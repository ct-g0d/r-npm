//! Pack Store for rnpm (Milestone M4).
//!
//! Per fifty-mark.md Section 4.4 & 5:
//! Location: `%LOCALAPPDATA%\rnpm\store-v1` (or `<cache_dir>/store-v1`),
//! on the fastest local volume (defaulting to LocalAppData / C: NVMe).
//!
//! Format:
//! ```text
//! store-v1/
//!   packs/<sha512-prefix>/<integrity>.pack    # all file contents, each 4 KiB-aligned
//!   packs/<sha512-prefix>/<integrity>.idx     # path, mode, size, offset per file
//! ```
//!
//! Adding a package to the store creates exactly 2 files (.pack + .idx),
//! minimizing Windows Defender scanning overhead and enabling direct memory-mapped
//! materialization without opening per-file sources.

use crate::error::CacheError;
pub use crate::error::PackError;
use data_encoding::HEXLOWER;
use flate2::read::GzDecoder;
use memmap2::Mmap;
use path_clean::clean;
use rnpm_core::{Algorithm, Integrity};
use rnpm_fs::writer::ParallelWriterConfig;
use rnpm_fs::{
    clone_or_write_pack_file, is_block_cloning_supported, is_refs_volume, is_same_volume,
    ExtractionSummary, RawFileHandle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::sleep;
use std::time::Duration;
use tracing::warn;

/// 4 KiB byte alignment for every file payload inside a `.pack` file.
pub const PACK_ALIGNMENT: usize = 4096;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(1);
pub static TIME_GZ_PARSE: AtomicU64 = AtomicU64::new(0);
pub static TIME_CAS_WRITE: AtomicU64 = AtomicU64::new(0);
pub static TIME_PACK_WRITE: AtomicU64 = AtomicU64::new(0);
pub static TIME_EXTRACT_DIRS: AtomicU64 = AtomicU64::new(0);
pub static TIME_EXTRACT_CAS_WRITE: AtomicU64 = AtomicU64::new(0);
pub static TIME_EXTRACT_LINK: AtomicU64 = AtomicU64::new(0);
pub static COUNT_LINK_OK: AtomicU64 = AtomicU64::new(0);
pub static COUNT_LINK_FAIL: AtomicU64 = AtomicU64::new(0);

/// Decoded in-memory package files and directories ready for global parallel materialization.
#[derive(Debug, Default)]
pub struct DecodedPackage {
    pub files: Vec<rnpm_fs::MaterializeFile>,
    pub dirs: Vec<PathBuf>,
    pub symlinks: Vec<(PathBuf, PathBuf)>,
}

/// Extracts the modified timestamp (nanoseconds since UNIX epoch) from file metadata.
pub fn mtime_to_timestamp(meta: &fs::Metadata) -> Option<u64> {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
}

/// A single file entry inside the `.idx` pack index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackFileEntry {
    /// Relative path within the package (e.g. "package.json", "lib/index.js").
    pub path: String,
    /// POSIX file mode/permissions (e.g. 0o644 or 0o755).
    pub mode: u32,
    /// Size of the uncompressed file payload in bytes.
    pub size: u64,
    /// Byte offset in the .pack file where file payload begins (guaranteed 4 KiB aligned).
    pub offset: u64,
    /// Explicit 4 KiB aligned offset.
    #[serde(default)]
    pub aligned_offset: u64,
    /// SHA-256 digest hex of the file payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Content-addressed storage path on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cas_path: Option<PathBuf>,
    #[serde(skip)]
    pub cas_verified: bool,
    /// Modified time (nanoseconds since UNIX epoch) of the CAS blob when verified/written.
    #[serde(alias = "checked_at", default, skip_serializing_if = "Option::is_none")]
    pub cas_mtime: Option<u64>,
}

impl PartialEq for PackFileEntry {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.mode == other.mode
            && self.size == other.size
            && self.offset == other.offset
            && self.aligned_offset == other.aligned_offset
            && self.sha256 == other.sha256
            && self.cas_path == other.cas_path
            && self.cas_mtime == other.cas_mtime
    }
}

impl Eq for PackFileEntry {}

impl PackFileEntry {
    /// Check whether the file payload offset satisfies 4 KiB alignment.
    pub fn is_4k_aligned(&self) -> bool {
        self.offset.is_multiple_of(PACK_ALIGNMENT as u64)
    }

    /// Return the aligned byte offset.
    pub fn aligned_offset(&self) -> u64 {
        self.aligned_offset
    }
}

/// The index representation of a package stored in `.idx`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackIndex {
    /// Original package integrity hash string (e.g. `sha512-...`).
    pub integrity: String,
    /// 128-char lowercase SHA-512 hex digest of the package.
    pub sha512_hex: String,
    /// Total byte size of the `.pack` payload (including padding).
    pub total_pack_size: u64,
    /// Whole-pack SHA-256 checksum hex digest of the `.pack` payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_checksum: Option<String>,
    /// List of file entries in the pack.
    pub files: Vec<PackFileEntry>,
    /// Optional symlinks inside the package (target_rel, symlink_dest).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symlinks: Vec<(String, String)>,
}

impl PackIndex {
    /// Create a new pack index.
    pub fn new(
        integrity: String,
        sha512_hex: String,
        total_pack_size: u64,
        files: Vec<PackFileEntry>,
    ) -> Self {
        Self {
            integrity,
            sha512_hex,
            total_pack_size,
            pack_checksum: None,
            files,
            symlinks: Vec::new(),
        }
    }

    /// Create a new pack index with a whole-pack checksum.
    pub fn with_checksum(
        integrity: String,
        sha512_hex: String,
        total_pack_size: u64,
        pack_checksum: impl Into<String>,
        files: Vec<PackFileEntry>,
    ) -> Self {
        Self {
            integrity,
            sha512_hex,
            total_pack_size,
            pack_checksum: Some(pack_checksum.into()),
            files,
            symlinks: Vec::new(),
        }
    }

    /// Serialize index to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    /// Deserialize index from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Find a file entry by relative path.
    pub fn get_file(&self, path: &str) -> Option<&PackFileEntry> {
        let norm = path.replace('\\', "/");
        let clean = norm.trim_start_matches("./").trim_start_matches('/');
        self.files
            .iter()
            .find(|f| {
                let f_norm = f.path.replace('\\', "/");
                let f_clean = f_norm.trim_start_matches("./").trim_start_matches('/');
                f_clean == clean
            })
            .or_else(|| {
                self.files.iter().find(|f| {
                    let f_norm = f.path.replace('\\', "/");
                    let f_clean = f_norm.trim_start_matches("./").trim_start_matches('/');
                    f_clean.eq_ignore_ascii_case(clean)
                })
            })
    }
}

/// File payload input to `put_package_pack`.
#[derive(Debug, Clone)]
pub struct PackInputFile<'a> {
    pub path: String,
    pub mode: u32,
    pub data: &'a [u8],
}

impl<'a> PackInputFile<'a> {
    pub fn new(path: impl Into<String>, mode: u32, data: &'a [u8]) -> Self {
        Self {
            path: path.into(),
            mode,
            data,
        }
    }
}

/// Memory-mapped file buffer or buffered bytes fallback.
#[derive(Debug)]
enum PackBuffer {
    #[allow(dead_code)]
    Mmap(Arc<Mmap>),
    Bytes(Arc<Vec<u8>>),
    Empty,
}

impl PackBuffer {
    fn data(&self) -> &[u8] {
        match self {
            Self::Mmap(m) => &m[..],
            Self::Bytes(b) => &b[..],
            Self::Empty => &[],
        }
    }
}

/// A loaded package pack with open memory mapping and index metadata.
#[derive(Debug, Clone)]
pub struct PackagePack {
    pub index: PackIndex,
    buffer: Arc<PackBuffer>,
    pub pack_path: PathBuf,
    pub idx_path: PathBuf,
}

/// A CAS file write job referencing a slice of an in-memory pack buffer.
#[derive(Debug, Clone)]
pub struct CasWriteJob {
    pub cas_path: PathBuf,
    pub pack_buf: Arc<Vec<u8>>,
    pub start: usize,
    pub end: usize,
}

impl PackagePack {
    /// Return the raw byte slice of the entire memory-mapped pack.
    pub fn data(&self) -> &[u8] {
        self.buffer.data()
    }

    /// Returns all CAS write jobs for this package pack, zero-copy sharing the pack buffer.
    pub fn cas_write_jobs(&self) -> Vec<CasWriteJob> {
        let bytes_arc = match self.buffer.as_ref() {
            PackBuffer::Bytes(b) => Arc::clone(b),
            _ => Arc::new(self.buffer.data().to_vec()),
        };
        let mut jobs = Vec::with_capacity(self.index.files.len());
        for entry in &self.index.files {
            if let Some(ref cas_path) = entry.cas_path {
                let start = entry.offset as usize;
                let end = start.saturating_add(entry.size as usize);
                if end <= bytes_arc.len() {
                    jobs.push(CasWriteJob {
                        cas_path: cas_path.clone(),
                        pack_buf: Arc::clone(&bytes_arc),
                        start,
                        end,
                    });
                }
            }
        }
        jobs
    }

    /// Simultaneously extracts package files to target_dir and populates the CAS store,
    /// hardlinking target files to their CAS counterparts with zero duplicated file writes.
    pub fn extract_and_populate_cas(&self, target_dir: &Path) -> std::io::Result<()> {
        let pack_data = self.data();
        let mut parents = std::collections::HashSet::new();
        parents.insert(target_dir.to_path_buf());
        for entry in &self.index.files {
            let full_path = target_dir.join(&entry.path);
            if let Some(parent) = full_path.parent() {
                parents.insert(parent.to_path_buf());
            }
        }
        for (link_rel, _) in &self.index.symlinks {
            let full_path = target_dir.join(link_rel);
            if let Some(parent) = full_path.parent() {
                parents.insert(parent.to_path_buf());
            }
        }
        let t_dirs = std::time::Instant::now();
        for dir in &parents {
            let _ = fs::create_dir_all(dir);
        }
        TIME_EXTRACT_DIRS.fetch_add(t_dirs.elapsed().as_nanos() as u64, Ordering::Relaxed);

        for entry in &self.index.files {
            let full_path = target_dir.join(&entry.path);
            let start = entry.offset as usize;
            let end = start + entry.size as usize;
            if end <= pack_data.len() {
                let slice = &pack_data[start..end];
                let t_cw = std::time::Instant::now();
                let _ = rnpm_fs::writer::write_file_fast(&full_path, slice, entry.mode, 65536);
                TIME_EXTRACT_CAS_WRITE.fetch_add(t_cw.elapsed().as_nanos() as u64, Ordering::Relaxed);
                rnpm_fs::record_file_created(entry.size);
            }
        }

        for (link_rel, target_rel) in &self.index.symlinks {
            let link_path = target_dir.join(link_rel);
            let target_path = target_dir.join(target_rel);
            let _ = rnpm_fs::create_link_or_copy(&link_path, &target_path);
        }

        Ok(())
    }

    /// Verify the pack's whole-pack content hash (SHA-256) against the checksum stored in `.idx`.
    /// Also detects zero-filled corrupted pack files.
    pub fn verify_checksum(&self) -> Result<(), CacheError> {
        let pack_data = self.data();
        if let Some(ref expected) = self.index.pack_checksum {
            let actual = HEXLOWER.encode(&Sha256::digest(pack_data));
            if &actual != expected {
                return Err(CacheError::CorruptedPack(format!(
                    "Pack content hash mismatch for '{}': expected {}, got {}",
                    self.pack_path.display(),
                    expected,
                    actual
                )));
            }
        } else if !pack_data.is_empty()
            && !self.index.files.is_empty()
            && pack_data.iter().all(|&b| b == 0)
        {
            return Err(CacheError::CorruptedPack(format!(
                "Pack file '{}' is zero-filled",
                self.pack_path.display()
            )));
        }
        Ok(())
    }

    /// Retrieve a direct slice for a specific file path within the memory-mapped pack.
    pub fn get_file_slice(&self, path: &str) -> Option<&[u8]> {
        let entry = self.index.get_file(path)?;
        let start = entry.offset as usize;
        let end = start + entry.size as usize;
        let data = self.data();
        if end <= data.len() {
            Some(&data[start..end])
        } else {
            None
        }
    }

    /// Materialize all files directly from the memory-mapped pack into `target_dir`
    /// using `rnpm-fs` writer primitives.
    pub fn materialize_to(
        &self,
        target_dir: &Path,
        writer_config: Option<&ParallelWriterConfig>,
    ) -> Result<ExtractionSummary, CacheError> {
        self.materialize_to_with_hint(target_dir, writer_config, None)
    }

    /// Materialize all files directly from the memory-mapped pack into `target_dir`,
    /// optionally using a pre-cached block-clone eligibility decision.
    pub fn materialize_to_with_hint(
        &self,
        target_dir: &Path,
        writer_config: Option<&ParallelWriterConfig>,
        can_block_clone_hint: Option<bool>,
    ) -> Result<ExtractionSummary, CacheError> {
        self.materialize_to_opt(target_dir, writer_config, can_block_clone_hint, false)
    }

    /// Fast materialization option with precreated directories support.
    pub fn materialize_to_opt(
        &self,
        target_dir: &Path,
        writer_config: Option<&ParallelWriterConfig>,
        can_block_clone_hint: Option<bool>,
        dirs_precreated: bool,
    ) -> Result<ExtractionSummary, CacheError> {
        let start_time = std::time::Instant::now();
        let pack_data = self.data();

        if !dirs_precreated {
            let clean_target_dir = clean(target_dir);
            // Security check: re-validate every entry path and ensure strict containment within target_dir
            for entry in &self.index.files {
                let p = Path::new(&entry.path);
                rnpm_fs::validate_entry_path(p).map_err(CacheError::Fs)?;
                let full_path = clean(target_dir.join(&entry.path));
                if !full_path.starts_with(&clean_target_dir) {
                    return Err(CacheError::Fs(rnpm_fs::FsError::PathTraversal {
                        path: PathBuf::from(&entry.path),
                    }));
                }
            }
            for (link_rel, target_rel) in &self.index.symlinks {
                let p_link = Path::new(link_rel);
                let p_target = Path::new(target_rel);
                rnpm_fs::validate_entry_path(p_link).map_err(CacheError::Fs)?;
                rnpm_fs::validate_entry_path(p_target).map_err(CacheError::Fs)?;
                let full_link = clean(target_dir.join(link_rel));
                let full_target = clean(target_dir.join(target_rel));
                if !full_link.starts_with(&clean_target_dir)
                    || !full_target.starts_with(&clean_target_dir)
                {
                    return Err(CacheError::Fs(rnpm_fs::FsError::PathTraversal {
                        path: PathBuf::from(link_rel),
                    }));
                }
            }

            // 1. Directories first: collect all unique parent directory paths for the package entries
            // and create them all up-front in one batch using std::fs::create_dir_all
            let mut parent_dirs = std::collections::HashSet::new();
            parent_dirs.insert(target_dir.to_path_buf());
            for entry in &self.index.files {
                let full_path = target_dir.join(&entry.path);
                if let Some(parent) = full_path.parent() {
                    parent_dirs.insert(parent.to_path_buf());
                }
            }
            for (link_rel, _) in &self.index.symlinks {
                let full_path = target_dir.join(link_rel);
                if let Some(parent) = full_path.parent() {
                    parent_dirs.insert(parent.to_path_buf());
                }
            }
            for dir in &parent_dirs {
                std::fs::create_dir_all(dir)?;
            }
        }

        let default_cfg = ParallelWriterConfig::default();
        let cfg = writer_config.unwrap_or(&default_cfg);
        let prealloc_thresh = cfg.preallocate_threshold;

        let mut total_uncompressed_bytes = 0u64;
        for entry in &self.index.files {
            total_uncompressed_bytes += entry.size;
        }

        // Check if pack file and destination are on the same ReFS volume (Dev Drive block cloning)
        let can_block_clone = can_block_clone_hint.unwrap_or_else(|| {
            is_same_volume(&self.pack_path, target_dir)
                && (is_block_cloning_supported(target_dir) || is_refs_volume(target_dir))
        });

        #[cfg(windows)]
        let pack_file = if can_block_clone {
            std::fs::File::open(&self.pack_path).ok()
        } else {
            None
        };

        #[cfg(windows)]
        let raw_pack_handle = pack_file.as_ref().map(|f| {
            use std::os::windows::io::AsRawHandle;
            f.as_raw_handle() as usize
        });

        #[cfg(not(windows))]
        let raw_pack_handle: Option<usize> = None;
        let _ = can_block_clone;

        // 2. Direct materialization straight from memory mapping (or ReFS block cloning).
        // Since packages are already parallelized across CPU cores at the installer level,
        // sequentially writing package files avoids OS thread churn, context switching,
        // and mutex contention across thousands of files.
        for entry in &self.index.files {
            let full_path = target_dir.join(&entry.path);
            let start = entry.offset as usize;
            let end = start + entry.size as usize;
            if end > pack_data.len() {
                return Err(CacheError::InvalidPack(format!(
                    "Pack entry '{}' exceeds pack size (offset {} + size {} > total {})",
                    entry.path,
                    entry.offset,
                    entry.size,
                    pack_data.len()
                )));
            }
            let slice = &pack_data[start..end];

            #[cfg(windows)]
            let src_h = raw_pack_handle.map(|h| h as RawFileHandle);
            #[cfg(not(windows))]
            let src_h = None;

            let mut copied = false;
            if !can_block_clone {
                if let Some(ref cas_path) = entry.cas_path {
                    let cas_valid = entry.cas_verified
                        && cas_path
                            .metadata()
                            .map(|metadata| {
                                metadata.len() == entry.size
                                    && entry
                                        .cas_mtime
                                        .is_none_or(|m| mtime_to_timestamp(&metadata) == Some(m))
                            })
                            .unwrap_or(false);
                    if cas_valid && rnpm_fs::copy_file_fast(cas_path, &full_path).is_ok() {
                        copied = true;
                        rnpm_fs::record_file_created(entry.size);
                    } else {
                        // Stale or corrupted CAS entry on disk: rebuild safely via temp file + atomic rename
                        let _ = PackStore::write_cas_file_safe(cas_path, slice);
                        if rnpm_fs::copy_file_fast(cas_path, &full_path).is_ok() {
                            copied = true;
                            rnpm_fs::record_file_created(entry.size);
                        }
                    }
                }
            }
            if !copied {
                clone_or_write_pack_file(
                    src_h,
                    &full_path,
                    slice,
                    entry.offset,
                    entry.size,
                    entry.mode,
                    prealloc_thresh,
                )
                .map_err(CacheError::Io)?;
            }
        }

        // 3. Recreate symlinks if any
        for (link_rel, target_rel) in &self.index.symlinks {
            let link_path = target_dir.join(link_rel);
            let target_path = target_dir.join(target_rel);
            let _ = rnpm_fs::create_link_or_copy(&link_path, &target_path);
        }

        let elapsed = start_time.elapsed();
        Ok(ExtractionSummary {
            entries_extracted: self.index.files.len(),
            total_uncompressed_bytes,
            inflate_duration: Duration::ZERO,
            materialize_duration: elapsed,
        })
    }
}

/// Serialized .pack and .idx payloads ready for deferred writing.
#[derive(Debug, Clone)]
pub struct DeferredPackPayloads {
    pub pack: (PathBuf, Arc<Vec<u8>>),
    pub idx: (PathBuf, Arc<Vec<u8>>),
}

/// The Pack Store manager.
///
/// Stores packages as 4 KiB-aligned `.pack` blobs and `.idx` indices under
/// `store-v1/packs/<sha512-prefix>/`.
#[derive(Debug, Clone)]
pub struct PackStore {
    root: PathBuf,
    mmap_cache: Arc<Mutex<HashMap<String, PackagePack>>>,
    block_clone_cache: Arc<RwLock<HashMap<PathBuf, bool>>>,
    cas_stamp_cache: Arc<RwLock<HashMap<PathBuf, (u64, u64)>>>,
    has_cas_files: Arc<std::sync::atomic::AtomicBool>,
}

impl PackStore {
    /// Initialize a PackStore rooted at `root` directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        let packs_dir = root.join("packs");
        fs::create_dir_all(&packs_dir)?;
        fs::create_dir_all(root.join("tmp"))?;
        let cas_dir = root.join("cas");
        fs::create_dir_all(&cas_dir)?;
        let mut has_cas = false;
        for b in 0..=255u8 {
            let hex_sub = format!("{:02x}", b);
            let sub = cas_dir.join(&hex_sub);
            if fs::create_dir(&sub).is_err() && !has_cas {
                if let Ok(mut it) = fs::read_dir(&sub) {
                    if it.next().is_some() {
                        has_cas = true;
                    }
                }
            }
        }
        Ok(Self {
            root,
            mmap_cache: Arc::new(Mutex::new(HashMap::new())),
            block_clone_cache: Arc::new(RwLock::new(HashMap::new())),
            cas_stamp_cache: Arc::new(RwLock::new(HashMap::new())),
            has_cas_files: Arc::new(std::sync::atomic::AtomicBool::new(has_cas)),
        })
    }

    /// Returns the cached (size, mtime) stamp for a CAS blob if recorded.
    pub fn get_cas_stamp(&self, path: &Path) -> Option<(u64, u64)> {
        self.cas_stamp_cache.read().ok()?.get(path).copied()
    }

    /// Records the (size, mtime) stamp for a CAS blob.
    pub fn set_cas_stamp(&self, path: &Path, size: u64, mtime: u64) {
        if let Ok(mut cache) = self.cas_stamp_cache.write() {
            cache.insert(path.to_path_buf(), (size, mtime));
        }
    }

    /// Determines default store directory:
    /// 1. `RNPM_STORE_DIR` environment variable
    /// 2. If `custom_cache_dir` is provided, `<custom_cache_dir>/store-v1`
    /// 3. `%LOCALAPPDATA%\rnpm\store-v1` (fastest NVMe volume on Windows)
    /// 4. Fallback `<temp_dir>/.rnpm-store-v1`
    pub fn default_location(custom_cache_dir: Option<&Path>) -> PathBuf {
        if let Ok(store_env) = std::env::var("RNPM_STORE_DIR") {
            if !store_env.trim().is_empty() {
                return PathBuf::from(store_env);
            }
        }
        if let Some(custom) = custom_cache_dir {
            return custom.join("store-v1");
        }
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            if !local_app_data.trim().is_empty() {
                return PathBuf::from(local_app_data).join("rnpm").join("store-v1");
            }
        }
        std::env::temp_dir().join(".rnpm-store-v1")
    }

    /// Open or create the pack store at default location or custom cache path.
    pub fn open_or_default(custom_cache_dir: Option<&Path>) -> Result<Self, CacheError> {
        let loc = Self::default_location(custom_cache_dir);
        Self::new(loc)
    }

    /// Root directory of the pack store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory storing packs: `<root>/packs`.
    pub fn packs_dir(&self) -> PathBuf {
        self.root.join("packs")
    }

    /// Directory for atomic write temporary files: `<root>/tmp`.
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Directory storing extracted Content-Addressed files: `<root>/cas`.
    pub fn cas_dir(&self) -> PathBuf {
        self.root.join("cas")
    }

    /// Returns the CAS file path for a given SHA-256 hex digest: `<root>/cas/<sha256[0..2]>/<sha256>`.
    pub fn cas_file_path(&self, sha256_hex: &str) -> PathBuf {
        let prefix = if sha256_hex.len() >= 2 {
            &sha256_hex[0..2]
        } else {
            "00"
        };
        self.cas_dir().join(prefix).join(sha256_hex)
    }

    /// Atomically writes file data into CAS safely using a temp file and atomic rename.
    /// Atomically writes file data into CAS safely using a temp file and atomic rename.
    pub fn write_cas_file(&self, cas_path: &Path, data: &[u8]) -> std::io::Result<()> {
        Self::write_cas_file_safe(cas_path, data)
    }

    /// Atomically writes file data into CAS safely using a temp file and atomic rename.
    pub fn write_cas_file_safe(cas_path: &Path, data: &[u8]) -> std::io::Result<()> {
        if let Ok(meta) = cas_path.metadata() {
            if meta.len() == data.len() as u64 {
                if let Ok(existing) = fs::read(cas_path) {
                    if existing == data {
                        return Ok(());
                    }
                }
            }
        }
        if let Some(parent) = cas_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let count = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let tmp_path = cas_path.with_extension(format!("tmp_{pid}_{count}"));

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(data)?;
            f.flush()?;
        }

        match fs::rename(&tmp_path, cas_path) {
            Ok(()) => Ok(()),
            Err(_) => {
                let _ = fs::remove_file(cas_path);
                let res = fs::rename(&tmp_path, cas_path);
                let _ = fs::remove_file(&tmp_path);
                res
            }
        }
    }

    /// Helper for direct CAS write delegating to write_cas_file_safe.
    pub fn write_cas_file_direct(cas_path: &Path, data: &[u8]) -> std::io::Result<()> {
        Self::write_cas_file_safe(cas_path, data)
    }

    /// Helper for CAS write create new delegating to write_cas_file_safe.
    pub fn write_cas_file_create_new(cas_path: &Path, data: &[u8]) -> std::io::Result<()> {
        Self::write_cas_file_safe(cas_path, data)
    }

    /// Fills the CAS by writing all uncompressed file payloads across 16 parallel threads.
    pub fn populate_cas_global(&self, files: &[(&Path, &[u8])]) {
        if files.is_empty() {
            return;
        }
        let mut unique_map = std::collections::HashMap::with_capacity(files.len());
        for (cas_path, data) in files {
            unique_map.entry(*cas_path).or_insert(*data);
        }
        let unique_files: Vec<(&Path, &[u8])> = unique_map.into_iter().collect();

        let num_threads = 16.min(unique_files.len());
        let chunk_size = unique_files.len().div_ceil(num_threads);

        std::thread::scope(|s| {
            for chunk in unique_files.chunks(chunk_size) {
                s.spawn(move || {
                    for (cas_path, data) in chunk {
                        if !cas_path.exists() {
                            let _ = std::fs::write(cas_path, data);
                        }
                    }
                });
            }
        });
    }

    /// Fills the CAS by copying already-installed files from node_modules into CAS
    /// across 16 parallel threads using fast native OS copy primitives.
    ///
    /// Copies to a unique temporary file in the CAS directory and atomically renames
    /// into the final destination to prevent data races and partial reads.
    pub fn populate_cas_from_installed(&self, files: &[(PathBuf, PathBuf)]) {
        if files.is_empty() {
            return;
        }
        let mut parents = std::collections::HashSet::new();
        for (_, cas_path) in files {
            if let Some(parent) = cas_path.parent() {
                parents.insert(parent.to_path_buf());
            }
        }
        for parent in parents {
            let _ = fs::create_dir_all(&parent);
        }

        let next = std::sync::atomic::AtomicUsize::new(0);
        let num_workers = 32.min(files.len());
        std::thread::scope(|scope| {
            for _ in 0..num_workers {
                scope.spawn(|| loop {
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    if idx >= files.len() {
                        break;
                    }
                    let (src, dst) = &files[idx];
                    let _ = rnpm_fs::copy_file_fast(src, dst);
                });
            }
        });
        self.has_cas_files.store(true, Ordering::Relaxed);
    }

    /// Returns the (pack_path, idx_path) tuple for an integrity hash.
    pub fn pack_paths(&self, integrity: &str) -> (PathBuf, PathBuf) {
        let (prefix, safe_stem, _) = Self::integrity_key_parts(integrity);
        let prefix_dir = self.packs_dir().join(&prefix);
        let pack_path = prefix_dir.join(format!("{safe_stem}.pack"));
        let idx_path = prefix_dir.join(format!("{safe_stem}.idx"));
        (pack_path, idx_path)
    }

    /// Returns the `.pack` file path for an integrity hash.
    pub fn pack_path(&self, integrity: &str) -> PathBuf {
        self.pack_paths(integrity).0
    }

    /// Returns the `.idx` index file path for an integrity hash.
    pub fn idx_path(&self, integrity: &str) -> PathBuf {
        self.pack_paths(integrity).1
    }

    /// Purge a package pack and its index from disk and in-memory cache.
    pub fn purge(&self, integrity: &str) -> Result<(), CacheError> {
        let (prefix, safe_stem, sha512_hex) = Self::integrity_key_parts(integrity);

        // 1. Remove from in-memory cache
        {
            let mut guard = self.mmap_cache.lock().unwrap();
            guard.remove(integrity);
            guard.remove(integrity.trim());
            guard.remove(&safe_stem);
            guard.remove(&sha512_hex);
            if let Ok(parsed) = integrity.trim().parse::<Integrity>() {
                if let Some(entry) = parsed
                    .entries
                    .iter()
                    .find(|e| e.algorithm == Algorithm::Sha512)
                {
                    let canon = format!("sha512-{}", data_encoding::BASE64.encode(&entry.digest));
                    guard.remove(&canon);
                }
            }
        }

        // 2. Remove files on disk
        let (pack_path, idx_path) = self.pack_paths(integrity);
        let _ = fs::remove_file(&pack_path);
        let _ = fs::remove_file(&idx_path);

        let prefix_dir = self.packs_dir().join(&prefix);
        let alt_pack = prefix_dir.join(format!("{sha512_hex}.pack"));
        let alt_idx = prefix_dir.join(format!("{sha512_hex}.idx"));
        let _ = fs::remove_file(&alt_pack);
        let _ = fs::remove_file(&alt_idx);

        Ok(())
    }

    /// Checks if a complete package pack (.pack and .idx) exists in the store.
    pub fn has_package_pack(&self, integrity: &str) -> bool {
        // Fast path: check open memory map cache
        {
            let guard = self.mmap_cache.lock().unwrap();
            if guard.contains_key(integrity) {
                return true;
            }
            let (_, safe_stem, sha512_hex) = Self::integrity_key_parts(integrity);
            if guard.contains_key(&safe_stem) || guard.contains_key(&sha512_hex) {
                return true;
            }
            if let Ok(parsed) = integrity.trim().parse::<Integrity>() {
                if let Some(entry) = parsed
                    .entries
                    .iter()
                    .find(|e| e.algorithm == Algorithm::Sha512)
                {
                    let canon = format!("sha512-{}", data_encoding::BASE64.encode(&entry.digest));
                    if guard.contains_key(&canon) {
                        return true;
                    }
                }
            }
        }

        let (pack_path, idx_path) = self.pack_paths(integrity);
        if pack_path.is_file() && idx_path.is_file() {
            if let Ok(meta) = pack_path.metadata() {
                if meta.len() > 0 {
                    return true;
                }
            }
        }

        // Secondary check by sha512_hex filename
        let (prefix, _, sha512_hex) = Self::integrity_key_parts(integrity);
        let alt_pack = self
            .packs_dir()
            .join(&prefix)
            .join(format!("{sha512_hex}.pack"));
        let alt_idx = self
            .packs_dir()
            .join(&prefix)
            .join(format!("{sha512_hex}.idx"));
        if alt_pack.is_file() && alt_idx.is_file() {
            if let Ok(meta) = alt_pack.metadata() {
                if meta.len() > 0 {
                    return true;
                }
            }
        }
        false
    }

    /// Retrieve and memory-map a package pack by integrity.
    ///
    /// Caches open memory maps across process lifetime for fast reuse.
    pub fn get_package_pack(&self, integrity: &str) -> Result<Option<PackagePack>, CacheError> {
        let (prefix, safe_stem, sha512_hex) = Self::integrity_key_parts(integrity);

        // 1. Check in-memory mmap cache
        {
            let guard = self.mmap_cache.lock().unwrap();
            if let Some(pack) = guard.get(integrity) {
                return Ok(Some(pack.clone()));
            }
            if let Some(pack) = guard.get(&safe_stem) {
                return Ok(Some(pack.clone()));
            }
            if let Some(pack) = guard.get(&sha512_hex) {
                return Ok(Some(pack.clone()));
            }
        }

        // 2. Locate on disk
        let (mut pack_path, mut idx_path) = self.pack_paths(integrity);
        if !pack_path.is_file() || !idx_path.is_file() {
            let alt_pack = self
                .packs_dir()
                .join(&prefix)
                .join(format!("{sha512_hex}.pack"));
            let alt_idx = self
                .packs_dir()
                .join(&prefix)
                .join(format!("{sha512_hex}.idx"));
            if alt_pack.is_file() && alt_idx.is_file() {
                pack_path = alt_pack;
                idx_path = alt_idx;
            } else {
                return Ok(None);
            }
        }

        // 3. Read and parse index
        let idx_bytes = match fs::read(&idx_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(CacheError::Io(e)),
        };
        let index: PackIndex = match PackIndex::from_bytes(&idx_bytes) {
            Ok(idx) => idx,
            Err(e) => {
                warn!(
                    "Corrupted pack index at '{}': {e}. Purging.",
                    idx_path.display()
                );
                let _ = self.purge(integrity);
                return Ok(None);
            }
        };

        // Re-validate every entry path in index before loading/materializing to prevent tampering
        for entry in &index.files {
            let p = Path::new(&entry.path);
            if let Err(e) = rnpm_fs::validate_entry_path(p) {
                warn!(
                    "Malicious or invalid entry path '{}' in index at '{}': {e}. Purging.",
                    entry.path,
                    idx_path.display()
                );
                let _ = self.purge(integrity);
                return Ok(None);
            }
            let expected_padded = if index.total_pack_size > 0 {
                (index.total_pack_size + (PACK_ALIGNMENT as u64 - 1)) & !(PACK_ALIGNMENT as u64 - 1)
            } else {
                0
            };
            if entry.offset.saturating_add(entry.size) > expected_padded.max(index.total_pack_size)
            {
                warn!(
                    "Pack entry '{}' bounds exceed total_pack_size in index at '{}'. Purging.",
                    entry.path,
                    idx_path.display()
                );
                let _ = self.purge(integrity);
                return Ok(None);
            }
        }
        for (link_rel, target_rel) in &index.symlinks {
            if let Err(e) = rnpm_fs::validate_entry_path(Path::new(link_rel)) {
                warn!(
                    "Malicious symlink link_rel '{}' in index at '{}': {e}. Purging.",
                    link_rel,
                    idx_path.display()
                );
                let _ = self.purge(integrity);
                return Ok(None);
            }
            if let Err(e) = rnpm_fs::validate_entry_path(Path::new(target_rel)) {
                warn!(
                    "Malicious symlink target_rel '{}' in index at '{}': {e}. Purging.",
                    target_rel,
                    idx_path.display()
                );
                let _ = self.purge(integrity);
                return Ok(None);
            }
        }

        // 4. Memory-map the pack file and verify file length matches index.total_pack_size (accounting for 4 KiB padding)
        let file = OpenOptions::new().read(true).open(&pack_path)?;
        let meta = file.metadata()?;
        let pack_len = meta.len();

        let expected_padded = if index.total_pack_size > 0 {
            (index.total_pack_size + (PACK_ALIGNMENT as u64 - 1)) & !(PACK_ALIGNMENT as u64 - 1)
        } else {
            0
        };

        if (pack_len != index.total_pack_size && pack_len != expected_padded)
            || (pack_len == 0 && !index.files.is_empty())
        {
            warn!(
                "Pack file length mismatch for '{}': disk pack_len={}, index total_pack_size={} (expected padded {}). Purging.",
                pack_path.display(),
                pack_len,
                index.total_pack_size,
                expected_padded
            );
            let _ = self.purge(integrity);
            return Ok(None);
        }

        let buffer = if pack_len == 0 {
            Arc::new(PackBuffer::Empty)
        } else {
            let file = std::fs::File::open(&pack_path)?;
            match unsafe { memmap2::Mmap::map(&file) } {
                Ok(mmap) => Arc::new(PackBuffer::Mmap(Arc::new(mmap))),
                Err(_) => {
                    let bytes = fs::read(&pack_path)?;
                    Arc::new(PackBuffer::Bytes(Arc::new(bytes)))
                }
            }
        };

        let pack = PackagePack {
            index: index.clone(),
            buffer,
            pack_path,
            idx_path: idx_path.clone(),
        };

        // Verify checksum once upon loading into memory BEFORE touching CAS
        if let Err(e) = pack.verify_checksum() {
            let _ = self.purge(integrity);
            return Err(e);
        }

        let mut index = index;
        let buf_data = pack.data();
        let mut index_updated = false;

        for entry in &mut index.files {
            let sha = match entry.sha256 {
                Some(ref s) => s.clone(),
                None => {
                    let start = entry.offset as usize;
                    let end = start + entry.size as usize;
                    if end <= buf_data.len() {
                        let h = HEXLOWER.encode(&Sha256::digest(&buf_data[start..end]));
                        entry.sha256 = Some(h.clone());
                        index_updated = true;
                        h
                    } else {
                        continue;
                    }
                }
            };
            let cas_file = self.cas_file_path(&sha);
            entry.cas_path = Some(cas_file.clone());

            if !self.has_cas_files.load(Ordering::Relaxed) {
                entry.cas_verified = false;
                continue;
            }

            let start = entry.offset as usize;
            let end = start.saturating_add(entry.size as usize);
            let slice = if end <= buf_data.len() {
                Some(&buf_data[start..end])
            } else {
                None
            };

            let cas_meta = cas_file.metadata().ok();
            match cas_meta {
                Some(meta) => {
                    let current_size = meta.len();
                    let current_mtime = mtime_to_timestamp(&meta);
                    let recorded_mtime = entry
                        .cas_mtime
                        .or_else(|| self.get_cas_stamp(&cas_file).map(|(_s, m)| m));
                    let stamp_match = current_size == entry.size
                        && recorded_mtime.is_some()
                        && current_mtime == recorded_mtime;

                    if stamp_match {
                        entry.cas_verified = true;
                    } else {
                        // Size or mtime changed, or verification stamp missing: rehash blob
                        let hash_valid = if current_size == entry.size {
                            if let Ok(bytes) = fs::read(&cas_file) {
                                HEXLOWER.encode(&Sha256::digest(&bytes)) == sha
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        if hash_valid {
                            entry.cas_mtime = current_mtime;
                            entry.cas_verified = true;
                            index_updated = true;
                            if let Some(m) = current_mtime {
                                self.set_cas_stamp(&cas_file, current_size, m);
                            }
                        } else if let Some(slice) = slice {
                            // Checksum mismatch or unreadable: repair from pack slice
                            let _ = PackStore::write_cas_file_safe(&cas_file, slice);
                            if let Ok(new_meta) = cas_file.metadata() {
                                let new_mtime = mtime_to_timestamp(&new_meta);
                                entry.cas_mtime = new_mtime;
                                if let Some(m) = new_mtime {
                                    self.set_cas_stamp(&cas_file, new_meta.len(), m);
                                }
                            }
                            entry.cas_verified = true;
                            index_updated = true;
                        } else {
                            entry.cas_verified = false;
                        }
                    }
                }
                None => {
                    entry.cas_verified = false;
                }
            }
        }

        if index_updated {
            let pid = std::process::id();
            let count = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
            let tmp_idx = self.tmp_dir().join(format!("idx_upd_{pid}_{count}.tmp"));
            if let Ok(updated_idx_bytes) = index.to_bytes() {
                if fs::write(&tmp_idx, &updated_idx_bytes).is_ok() {
                    let _ = rename_atomic(&tmp_idx, &idx_path);
                }
            }
        }

        let pack = PackagePack {
            index,
            buffer: pack.buffer,
            pack_path: pack.pack_path,
            idx_path: pack.idx_path,
        };

        // 5. Store in cache across process lifetime
        {
            let mut guard = self.mmap_cache.lock().unwrap();
            guard.insert(integrity.to_string(), pack.clone());
            guard.insert(safe_stem, pack.clone());
            guard.insert(sha512_hex, pack.clone());
            if let Ok(parsed) = integrity.trim().parse::<Integrity>() {
                if let Some(entry) = parsed
                    .entries
                    .iter()
                    .find(|e| e.algorithm == Algorithm::Sha512)
                {
                    let canon = format!("sha512-{}", data_encoding::BASE64.encode(&entry.digest));
                    guard.insert(canon, pack.clone());
                }
            }
        }

        Ok(Some(pack))
    }

    /// Atomically write a `.pack` and `.idx` pair for a package.
    ///
    /// - Aligns each file payload to 4096 bytes (4 KiB alignment).
    /// - Writes `.pack` and `.idx` atomically via temporary files.
    /// - Creates exactly 2 files (pack + idx) in `packs/<sha512-prefix>/`.
    pub fn put_package_pack(
        &self,
        integrity: &str,
        files: &[PackInputFile<'_>],
    ) -> Result<PackIndex, CacheError> {
        self.put_package_pack_with_cas(integrity, files, true)
            .map(|p| p.index)
    }

    /// Builds a pack/index without synchronously creating one CAS file per entry.
    /// The pack is immediately usable for direct materialization; callers can populate CAS
    /// asynchronously when the install path must not wait on thousands of small writes.
    pub fn put_package_pack_deferred(
        &self,
        integrity: &str,
        files: &[PackInputFile<'_>],
    ) -> Result<PackIndex, CacheError> {
        self.put_package_pack_with_cas(integrity, files, false)
            .map(|p| p.index)
    }

    /// Builds a pack/index directly from already decoded in-memory files without re-decoding gzip.
    pub fn put_package_pack_from_decoded(
        &self,
        integrity: &str,
        pkg_target: &Path,
        files: &[rnpm_fs::MaterializeFile],
        populate_cas: bool,
    ) -> Result<PackIndex, CacheError> {
        let input_files: Vec<PackInputFile<'_>> = files
            .iter()
            .filter_map(|f| {
                let rel = f.path.strip_prefix(pkg_target).ok()?;
                let clean = rel.to_string_lossy().replace('\\', "/");
                Some(PackInputFile {
                    path: clean,
                    mode: f.mode,
                    data: f.data.as_slice(),
                })
            })
            .collect();

        self.put_package_pack_with_cas(integrity, &input_files, populate_cas)
            .map(|p| p.index)
    }

    /// Builds a pack/index from decoded in-memory files and returns the serialized .pack and .idx
    /// payloads so disk writes can be offloaded asynchronously to the background file writer.
    pub fn put_package_pack_from_decoded_deferred(
        &self,
        integrity: &str,
        pkg_target: &Path,
        files: &[rnpm_fs::MaterializeFile],
        populate_cas: bool,
    ) -> Result<(PackIndex, DeferredPackPayloads), CacheError> {
        let input_files: Vec<PackInputFile<'_>> = files
            .iter()
            .filter_map(|f| {
                let rel = f.path.strip_prefix(pkg_target).ok()?;
                let clean = rel.to_string_lossy().replace('\\', "/");
                Some(PackInputFile {
                    path: clean,
                    mode: f.mode,
                    data: f.data.as_slice(),
                })
            })
            .collect();

        self.put_package_pack_with_cas_inner(integrity, &input_files, populate_cas, false)
            .map(|(p, payloads)| (p.index, payloads))
    }

    fn put_package_pack_with_cas(
        &self,
        integrity: &str,
        files: &[PackInputFile<'_>],
        populate_cas: bool,
    ) -> Result<PackagePack, CacheError> {
        self.put_package_pack_with_cas_inner(integrity, files, populate_cas, true)
            .map(|(p, _)| p)
    }

    fn put_package_pack_with_cas_inner(
        &self,
        integrity: &str,
        files: &[PackInputFile<'_>],
        populate_cas: bool,
        write_files: bool,
    ) -> Result<(PackagePack, DeferredPackPayloads), CacheError> {
        let (prefix, safe_stem, sha512_hex) = Self::integrity_key_parts(integrity);

        let limits = rnpm_fs::TarLimits::default();
        if files.len() > limits.max_entries {
            return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                limit_type: "entry count".to_string(),
                detail: format!(
                    "Pack exceeds maximum allowed entries: {}",
                    limits.max_entries
                ),
            }));
        }

        // Deduplicate input files by lowercased path, ensuring LAST entry wins
        let mut deduped_map: HashMap<String, PackInputFile<'_>> = HashMap::new();
        let mut deduped_order: Vec<String> = Vec::new();

        for file in files {
            let p = Path::new(&file.path);
            rnpm_fs::validate_entry_path(p).map_err(CacheError::Fs)?;

            let clean_path = file.path.replace('\\', "/");
            let norm_path = clean_path
                .trim_start_matches("./")
                .trim_start_matches('/')
                .to_string();
            if norm_path.is_empty() {
                return Err(CacheError::InvalidPack(
                    "Pack entry path cannot be empty".to_string(),
                ));
            }
            rnpm_fs::validate_entry_path(Path::new(&norm_path)).map_err(CacheError::Fs)?;

            let lower_key = norm_path.to_lowercase();
            if !deduped_map.contains_key(&lower_key) {
                deduped_order.push(lower_key.clone());
            }
            deduped_map.insert(
                lower_key,
                PackInputFile {
                    path: norm_path,
                    mode: file.mode,
                    data: file.data,
                },
            );
        }

        let deduped_files: Vec<PackInputFile<'_>> = deduped_order
            .into_iter()
            .filter_map(|k| deduped_map.remove(&k))
            .collect();

        // 1. Pack construction with 4 KiB alignment
        let mut pack_bytes = Vec::new();
        let mut index_files = Vec::with_capacity(deduped_files.len());

        for file in deduped_files {
            if file.data.len() as u64 > limits.max_single_entry_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "entry size".to_string(),
                    detail: format!("File payload '{}' exceeds single file limit", file.path),
                }));
            }

            let curr_offset = pack_bytes.len();
            let remainder = curr_offset % PACK_ALIGNMENT;
            let aligned_offset = if remainder == 0 {
                curr_offset
            } else {
                let padding = PACK_ALIGNMENT - remainder;
                pack_bytes.resize(curr_offset + padding, 0u8);
                curr_offset + padding
            };

            pack_bytes.extend_from_slice(file.data);
            if pack_bytes.len() as u64 > limits.max_uncompressed_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "uncompressed size".to_string(),
                    detail: format!(
                        "Total pack size {} exceeded maximum allowed {}",
                        pack_bytes.len(),
                        limits.max_uncompressed_size
                    ),
                }));
            }

            let (sha256, cas_path) = if populate_cas {
                let h = HEXLOWER.encode(&Sha256::digest(file.data));
                let p = self.cas_file_path(&h);
                (Some(h), Some(p))
            } else {
                (None, None)
            };
            index_files.push(PackFileEntry {
                path: file.path,
                mode: file.mode,
                size: file.data.len() as u64,
                offset: aligned_offset as u64,
                aligned_offset: aligned_offset as u64,
                sha256,
                cas_path,
                cas_verified: populate_cas,
                cas_mtime: None,
            });
        }

        // Pad the end of the .pack file with zeroes up to a 4096-byte cluster boundary
        // ((total_pack_size + 4095) & !4095). This ensures that FSCTL_DUPLICATE_EXTENTS_TO_FILE
        // for the last file in the pack does not extend past the end of the source .pack file,
        // which causes Windows to fail extent duplication.
        let unpadded_len = pack_bytes.len();
        let padded_len = if unpadded_len > 0 {
            (unpadded_len + (PACK_ALIGNMENT - 1)) & !(PACK_ALIGNMENT - 1)
        } else {
            0
        };
        if padded_len > unpadded_len {
            pack_bytes.resize(padded_len, 0u8);
        }

        if populate_cas && !index_files.is_empty() {
            let t_cas = std::time::Instant::now();
            self.populate_cas_parallel(&mut index_files, &pack_bytes);
            TIME_CAS_WRITE.fetch_add(t_cas.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }

        let pack_checksum = HEXLOWER.encode(&Sha256::digest(&pack_bytes));
        let index = PackIndex::with_checksum(
            integrity.to_string(),
            sha512_hex.clone(),
            pack_bytes.len() as u64,
            pack_checksum,
            index_files,
        );
        let idx_bytes = index.to_bytes().map_err(CacheError::Json)?;

        // 2. Direct write to packs directory (skip temp files and rename retry loops)
        let prefix_dir = self.packs_dir().join(&prefix);

        let final_pack = prefix_dir.join(format!("{safe_stem}.pack"));
        let final_idx = prefix_dir.join(format!("{safe_stem}.idx"));

        if write_files {
            let t_p = std::time::Instant::now();
            let _ = Self::write_cas_file_direct(&final_pack, &pack_bytes);
            let _ = Self::write_cas_file_direct(&final_idx, &idx_bytes);
            TIME_PACK_WRITE.fetch_add(t_p.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }

        let pack_bytes_arc = Arc::new(pack_bytes);
        let idx_bytes_arc = Arc::new(idx_bytes);

        // 4. Update memory-map cache
        let buffer = if pack_bytes_arc.is_empty() {
            Arc::new(PackBuffer::Empty)
        } else {
            Arc::new(PackBuffer::Bytes(Arc::clone(&pack_bytes_arc)))
        };

        let pack = PackagePack {
            index: index.clone(),
            buffer,
            pack_path: final_pack.clone(),
            idx_path: final_idx.clone(),
        };

        {
            let mut guard = self.mmap_cache.lock().unwrap();
            guard.insert(integrity.to_string(), pack.clone());
            guard.insert(safe_stem, pack.clone());
            guard.insert(sha512_hex, pack.clone());
            if let Ok(parsed) = integrity.trim().parse::<Integrity>() {
                if let Some(entry) = parsed
                    .entries
                    .iter()
                    .find(|e| e.algorithm == Algorithm::Sha512)
                {
                    let canon = format!("sha512-{}", data_encoding::BASE64.encode(&entry.digest));
                    guard.insert(canon, pack.clone());
                }
            }
        }

        Ok((
            pack,
            DeferredPackPayloads {
                pack: (final_pack, pack_bytes_arc),
                idx: (final_idx, idx_bytes_arc),
            },
        ))
    }

    fn populate_cas_parallel(&self, entries: &mut [PackFileEntry], pack_bytes: &[u8]) {
        for entry in entries.iter_mut() {
            let start = entry.offset as usize;
            let end = start.saturating_add(entry.size as usize);
            if end <= pack_bytes.len() {
                if let Some(ref cas_path) = entry.cas_path {
                    let _ = Self::write_cas_file_create_new(cas_path, &pack_bytes[start..end]);
                    entry.cas_verified = true;
                }
            }
        }
        self.has_cas_files.store(true, Ordering::Relaxed);
    }

    /// Extract a tarball into the pack store atomically.
    pub fn put_package_from_tarball(
        &self,
        integrity: &str,
        tarball_bytes: &[u8],
    ) -> Result<PackIndex, CacheError> {
        self.put_package_from_tarball_internal(integrity, tarball_bytes, true, true, None)
            .map(|p| p.index)
    }

    /// Cold-install variant that defers per-file CAS writes.
    pub fn put_package_from_tarball_deferred(
        &self,
        integrity: &str,
        tarball_bytes: &[u8],
    ) -> Result<PackIndex, CacheError> {
        self.put_package_from_tarball_internal(integrity, tarball_bytes, false, true, None)
            .map(|p| p.index)
    }

    /// Cold-install variant: takes already-verified tarball bytes, defers per-file CAS writes,
    /// skips redundant SHA-512 re-hashing, and returns the constructed `PackagePack`.
    pub fn put_package_from_verified_tarball_deferred(
        &self,
        integrity: &str,
        tarball_bytes: &[u8],
    ) -> Result<PackagePack, CacheError> {
        self.put_package_from_tarball_internal(integrity, tarball_bytes, false, false, None)
    }

    pub fn put_package_from_verified_tarball_deferred_and_extract(
        &self,
        integrity: &str,
        tarball_bytes: &[u8],
        target_dir: Option<&Path>,
    ) -> Result<PackagePack, CacheError> {
        self.put_package_from_tarball_internal(integrity, tarball_bytes, false, false, target_dir)
    }

    /// Takes already-verified tarball bytes, populates per-file CAS writes,
    /// skips redundant SHA-512 re-hashing, and returns the constructed `PackagePack`.
    pub fn put_package_from_verified_tarball(
        &self,
        integrity: &str,
        tarball_bytes: &[u8],
    ) -> Result<PackagePack, CacheError> {
        self.put_package_from_tarball_internal(integrity, tarball_bytes, true, false, None)
    }

    pub fn put_package_from_verified_tarball_and_extract(
        &self,
        integrity: &str,
        tarball_bytes: &[u8],
        target_dir: Option<&Path>,
    ) -> Result<PackagePack, CacheError> {
        self.put_package_from_tarball_internal(integrity, tarball_bytes, true, false, target_dir)
    }

    fn put_package_from_tarball_internal(
        &self,
        integrity: &str,
        tarball_bytes: &[u8],
        populate_cas: bool,
        verify_integrity: bool,
        target_dir: Option<&Path>,
    ) -> Result<PackagePack, CacheError> {
        let trimmed = integrity.trim();
        if verify_integrity && !trimmed.is_empty() {
            match trimmed.parse::<Integrity>() {
                Ok(expected_integ) => {
                    if let Err(e) = expected_integ.verify(tarball_bytes) {
                        return Err(CacheError::IntegrityMismatch {
                            key: integrity.to_string(),
                            expected: integrity.to_string(),
                            actual: e.to_string(),
                        });
                    }
                }
                Err(_) => {
                    if trimmed.len() == 128 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                        let mut hasher = Sha512::new();
                        hasher.update(tarball_bytes);
                        let actual_hex = HEXLOWER.encode(&hasher.finalize());
                        if actual_hex != trimmed.to_ascii_lowercase() {
                            return Err(CacheError::IntegrityMismatch {
                                key: integrity.to_string(),
                                expected: trimmed.to_string(),
                                actual: actual_hex,
                            });
                        }
                    } else {
                        return Err(CacheError::InvalidKey(format!(
                            "Invalid integrity string '{integrity}'"
                        )));
                    }
                }
            }
        }

        let t_gz = std::time::Instant::now();
        let reader: Box<dyn Read> = if tarball_bytes.starts_with(&[0x1f, 0x8b]) {
            Box::new(GzDecoder::new(tarball_bytes))
        } else {
            Box::new(tarball_bytes)
        };
        let mut archive = tar::Archive::new(reader);

        let limits = rnpm_fs::TarLimits::default();
        let mut file_payloads_map: HashMap<String, (String, u32, Vec<u8>)> = HashMap::new();
        let mut file_payloads_order = Vec::new();
        let entries = archive.entries().map_err(CacheError::Io)?;
        let mut entry_count = 0usize;
        let mut total_uncompressed = 0u64;

        let mut created_dirs = if let Some(target) = target_dir {
            let mut set = std::collections::HashSet::new();
            set.insert(target.to_path_buf());
            Some(set)
        } else {
            None
        };

        for entry_res in entries {
            let mut entry = entry_res.map_err(CacheError::Io)?;
            let entry_type = entry.header().entry_type();
            if entry_type == tar::EntryType::XGlobalHeader || entry_type.as_byte() == b'g' {
                continue;
            }
            if entry_type.is_block_special()
                || entry_type.is_character_special()
                || entry_type.is_fifo()
            {
                let raw_path = entry.path().map_err(CacheError::Io)?.to_path_buf();
                return Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenSpecialEntry {
                    path: raw_path,
                }));
            }
            if !entry_type.is_file() {
                continue;
            }

            entry_count += 1;
            if entry_count > limits.max_entries {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "entry count".to_string(),
                    detail: format!(
                        "Tarball exceeded maximum allowed entries: {}",
                        limits.max_entries
                    ),
                }));
            }

            let raw_path = entry.path().map_err(CacheError::Io)?.to_path_buf();
            let relative_path = match rnpm_fs::strip_package_prefix(&raw_path) {
                Some(p) => p,
                None => continue,
            };

            rnpm_fs::validate_entry_path(&relative_path).map_err(CacheError::Fs)?;

            let path_depth = relative_path
                .components()
                .filter(|c| matches!(c, std::path::Component::Normal(_)))
                .count();
            if path_depth > limits.max_path_depth {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "path depth".to_string(),
                    detail: format!(
                        "Path depth {} exceeded maximum allowed path depth of {}: '{}'",
                        path_depth,
                        limits.max_path_depth,
                        relative_path.display()
                    ),
                }));
            }

            let entry_size = entry.header().size().unwrap_or(0);
            if entry_size > limits.max_single_entry_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "entry size".to_string(),
                    detail: format!(
                        "Entry size {} exceeded single file limit of {} bytes",
                        entry_size, limits.max_single_entry_size
                    ),
                }));
            }

            let clean_path = relative_path.to_string_lossy().replace('\\', "/");
            let norm_path = clean_path
                .trim_start_matches("./")
                .trim_start_matches('/')
                .to_string();
            if norm_path.is_empty() {
                continue;
            }
            let mode = entry
                .header()
                .mode()
                .unwrap_or(rnpm_fs::NPM_DEFAULT_FILE_MODE);
            let mut data = Vec::with_capacity((entry_size as usize).min(1024 * 1024));
            let mut take_reader = (&mut entry).take(limits.max_single_entry_size + 1);
            take_reader.read_to_end(&mut data).map_err(CacheError::Io)?;
            if data.len() as u64 > limits.max_single_entry_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "entry size".to_string(),
                    detail: format!("Entry '{}' exceeded single file limit", norm_path),
                }));
            }

            total_uncompressed = total_uncompressed.saturating_add(data.len() as u64);
            if total_uncompressed > limits.max_uncompressed_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "uncompressed size".to_string(),
                    detail: format!(
                        "Total uncompressed bytes {} exceeded limit {}",
                        total_uncompressed, limits.max_uncompressed_size
                    ),
                }));
            }

            if let (Some(target), Some(ref mut dirs)) = (target_dir, &mut created_dirs) {
                let clean_p = if cfg!(windows) && norm_path.contains('/') {
                    norm_path.replace('/', "\\")
                } else {
                    norm_path.clone()
                };
                let full = target.join(clean_p);
                if let Some(parent) = full.parent() {
                    if !dirs.contains(parent) {
                        let _ = std::fs::create_dir_all(parent);
                        let mut curr = parent;
                        while curr != target && dirs.insert(curr.to_path_buf()) {
                            if let Some(p) = curr.parent() {
                                curr = p;
                            } else {
                                break;
                            }
                        }
                    }
                }
                let _ = rnpm_fs::write_file_fast(&full, &data, mode, 64 * 1024);
            }

            if populate_cas || target_dir.is_none() {
                // Deduplicate by lowercased path, ensuring LAST entry wins
                let lower_key = norm_path.to_lowercase();
                if !file_payloads_map.contains_key(&lower_key) {
                    file_payloads_order.push(lower_key.clone());
                }
                file_payloads_map.insert(lower_key, (norm_path, mode, data));
            }
        }

        if total_uncompressed > 50_000 && !tarball_bytes.is_empty() {
            let ratio = total_uncompressed as f64 / tarball_bytes.len() as f64;
            if ratio > limits.max_compression_ratio {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "compression ratio".to_string(),
                    detail: format!(
                        "Compression ratio {:.1}:1 exceeded limit of {:.1}:1",
                        ratio, limits.max_compression_ratio
                    ),
                }));
            }
        }

        let gz_dur = t_gz.elapsed();
        TIME_GZ_PARSE.fetch_add(gz_dur.as_nanos() as u64, Ordering::Relaxed);

        if target_dir.is_some() && !populate_cas {
            let (_prefix, _safe_stem, sha512_hex) = Self::integrity_key_parts(integrity);
            let dummy_index = PackIndex {
                integrity: integrity.to_string(),
                sha512_hex,
                total_pack_size: 0,
                pack_checksum: None,
                files: Vec::new(),
                symlinks: Vec::new(),
            };
            return Ok(PackagePack {
                index: dummy_index,
                buffer: Arc::new(PackBuffer::Empty),
                pack_path: PathBuf::new(),
                idx_path: PathBuf::new(),
            });
        }

        let file_payloads: Vec<(String, u32, Vec<u8>)> = file_payloads_order
            .into_iter()
            .filter_map(|k| file_payloads_map.remove(&k))
            .collect();

        let input_files: Vec<PackInputFile<'_>> = file_payloads
            .iter()
            .map(|(p, m, d)| PackInputFile {
                path: p.clone(),
                mode: *m,
                data: d.as_slice(),
            })
            .collect();

        self.put_package_pack_with_cas(integrity, &input_files, populate_cas)
    }

    /// Decodes a package tarball directly in memory without writing to disk,
    /// returning files, directories, and symlinks ready for parallel materialization.
    pub fn decode_package_tarball(
        tarball_bytes: &[u8],
        target_dir: &Path,
        pkg_key: &str,
    ) -> Result<DecodedPackage, CacheError> {
        let reader: Box<dyn Read> = if tarball_bytes.starts_with(&[0x1f, 0x8b]) {
            Box::new(GzDecoder::new(tarball_bytes))
        } else {
            Box::new(tarball_bytes)
        };
        let mut archive = tar::Archive::new(reader);
        let limits = rnpm_fs::TarLimits::default();
        let mut files = Vec::new();
        let mut file_indices: HashMap<PathBuf, usize> = HashMap::new();
        let mut dirs = vec![target_dir.to_path_buf()];
        let mut symlinks = Vec::new();
        let mut entry_count = 0usize;
        let mut total_uncompressed = 0u64;

        for entry_res in archive.entries().map_err(CacheError::Io)? {
            let mut entry = entry_res.map_err(CacheError::Io)?;
            let entry_type = entry.header().entry_type();
            if entry_type == tar::EntryType::XGlobalHeader || entry_type.as_byte() == b'g' {
                continue;
            }
            if entry_type.is_block_special()
                || entry_type.is_character_special()
                || entry_type.is_fifo()
            {
                let raw_path = entry.path().map_err(CacheError::Io)?.to_path_buf();
                return Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenSpecialEntry {
                    path: raw_path,
                }));
            }

            let raw_path = entry.path().map_err(CacheError::Io)?.to_path_buf();
            let relative_path = match rnpm_fs::strip_package_prefix(&raw_path) {
                Some(p) => p,
                None => continue,
            };

            rnpm_fs::validate_entry_path(&relative_path).map_err(CacheError::Fs)?;

            let clean_path = relative_path.to_string_lossy().replace('\\', "/");
            let norm_path = clean_path
                .trim_start_matches("./")
                .trim_start_matches('/')
                .to_string();
            if norm_path.is_empty() {
                continue;
            }

            let clean_rel = if cfg!(windows) && norm_path.contains('/') {
                norm_path.replace('/', "\\")
            } else {
                norm_path.clone()
            };
            let full_path = target_dir.join(clean_rel);
            if let Some(parent) = full_path.parent() {
                if parent != target_dir {
                    dirs.push(parent.to_path_buf());
                }
            }

            if entry_type.is_symlink() {
                if let Some(target) = entry.link_name().map_err(CacheError::Io)? {
                    let norm_target =
                        rnpm_fs::strip_package_prefix(&target).unwrap_or_else(|| target.to_path_buf());
                    symlinks.push((full_path, target_dir.join(norm_target)));
                }
                continue;
            }

            if !entry_type.is_file() {
                continue;
            }

            entry_count += 1;
            if entry_count > limits.max_entries {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "entry count".to_string(),
                    detail: format!(
                        "Tarball exceeded maximum allowed entries: {}",
                        limits.max_entries
                    ),
                }));
            }

            let entry_size = entry.header().size().unwrap_or(0);
            if entry_size > limits.max_single_entry_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "entry size".to_string(),
                    detail: format!(
                        "Entry size {} exceeded single file limit of {} bytes",
                        entry_size, limits.max_single_entry_size
                    ),
                }));
            }

            let mode = entry
                .header()
                .mode()
                .unwrap_or(rnpm_fs::NPM_DEFAULT_FILE_MODE);
            let mut data = Vec::with_capacity((entry_size as usize).min(1024 * 1024));
            let mut take_reader = (&mut entry).take(limits.max_single_entry_size + 1);
            take_reader.read_to_end(&mut data).map_err(CacheError::Io)?;
            if data.len() as u64 > limits.max_single_entry_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "entry size".to_string(),
                    detail: format!("Entry '{}' exceeded single file limit", norm_path),
                }));
            }

            total_uncompressed = total_uncompressed.saturating_add(data.len() as u64);
            if total_uncompressed > limits.max_uncompressed_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "uncompressed size".to_string(),
                    detail: format!(
                        "Total uncompressed bytes {} exceeded limit {}",
                        total_uncompressed, limits.max_uncompressed_size
                    ),
                }));
            }

            let mat_file = rnpm_fs::MaterializeFile {
                path: full_path.clone(),
                data,
                mode,
                package_id: Some(pkg_key.to_string()),
            };
            if let Some(&idx) = file_indices.get(&full_path) {
                files[idx] = mat_file;
            } else {
                file_indices.insert(full_path, files.len());
                files.push(mat_file);
            }
        }

        Ok(DecodedPackage { files, dirs, symlinks })
    }

    /// Checks whether block cloning from this store into `target_dir` is supported,
    /// avoiding redundant Win32 volume detection queries across thousands of packages
    /// by caching results keyed by destination directory / volume root in a thread-safe cache.
    pub fn is_block_cloning_eligible(&self, target_dir: &Path) -> bool {
        let key = volume_root_key(target_dir);
        {
            let cache = self.block_clone_cache.read().unwrap();
            if let Some(&eligible) = cache.get(&key) {
                return eligible;
            }
        }

        let eligible = is_same_volume(&self.root, target_dir)
            && (is_block_cloning_supported(target_dir) || is_refs_volume(target_dir));

        let mut cache = self.block_clone_cache.write().unwrap();
        cache.insert(key, eligible);
        eligible
    }

    /// Alias for `is_block_cloning_eligible`.
    pub fn can_block_clone_to(&self, target_dir: &Path) -> bool {
        self.is_block_cloning_eligible(target_dir)
    }

    /// Clear cached volume block-clone eligibility states.
    pub fn clear_block_clone_cache(&self) {
        self.block_clone_cache.write().unwrap().clear();
    }

    /// Materialize a package from its memory-mapped pack directly into `target_dir`.
    pub fn materialize_pack(
        &self,
        integrity: &str,
        target_dir: &Path,
        writer_config: Option<&ParallelWriterConfig>,
    ) -> Result<ExtractionSummary, CacheError> {
        self.materialize_pack_opt(integrity, target_dir, writer_config, false)
    }

    /// Fast materialization option with precreated directories support.
    pub fn materialize_pack_opt(
        &self,
        integrity: &str,
        target_dir: &Path,
        writer_config: Option<&ParallelWriterConfig>,
        dirs_precreated: bool,
    ) -> Result<ExtractionSummary, CacheError> {
        let pack = self
            .get_package_pack(integrity)?
            .ok_or_else(|| CacheError::PackNotFound(integrity.to_string()))?;
        let can_block_clone = self.is_block_cloning_eligible(target_dir);
        match pack.materialize_to_opt(
            target_dir,
            writer_config,
            Some(can_block_clone),
            dirs_precreated,
        ) {
            Ok(summary) => Ok(summary),
            Err(e) => {
                if e.is_pack_corruption() {
                    let _ = self.purge(integrity);
                }
                Err(e)
            }
        }
    }

    /// Clear in-memory cached memory maps.
    pub fn clear_mmap_cache(&self) {
        self.mmap_cache.lock().unwrap().clear();
    }

    /// Derives (prefix, safe_stem, sha512_hex) for an integrity string.
    pub fn integrity_key_parts(integrity: &str) -> (String, String, String) {
        let trimmed = integrity.trim();

        // 1. Try parsing as SSRI Integrity
        if let Ok(parsed) = trimmed.parse::<Integrity>() {
            if let Some(entry) = parsed
                .entries
                .iter()
                .find(|e| e.algorithm == Algorithm::Sha512)
            {
                let sha512_hex = HEXLOWER.encode(&entry.digest);
                let prefix = sha512_hex[0..2].to_string();
                let canonical_integrity =
                    format!("sha512-{}", data_encoding::BASE64.encode(&entry.digest));
                let safe_stem = sanitize_filename(&canonical_integrity);
                return (prefix, safe_stem, sha512_hex);
            }
            if let Some(strongest) = parsed.strongest_algorithm() {
                if let Some(entry) = parsed.entries.iter().find(|e| e.algorithm == strongest) {
                    let mut hasher = Sha512::new();
                    hasher.update(&entry.digest);
                    let sha512_hex = HEXLOWER.encode(&hasher.finalize());
                    let prefix = sha512_hex[0..2].to_string();
                    let canonical_integrity = format!(
                        "{}-{}",
                        entry.algorithm,
                        data_encoding::BASE64.encode(&entry.digest)
                    );
                    let safe_stem = sanitize_filename(&canonical_integrity);
                    return (prefix, safe_stem, sha512_hex);
                }
            }
        }

        // 2. Pure 128-char hex string
        if trimmed.len() == 128 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let sha512_hex = trimmed.to_ascii_lowercase();
            let prefix = sha512_hex[0..2].to_string();
            let safe_stem = sha512_hex.clone();
            return (prefix, safe_stem, sha512_hex);
        }

        // 3. Fallback: hash the string itself to produce a deterministic SHA-512 hex
        let mut hasher = Sha512::new();
        hasher.update(trimmed.as_bytes());
        let sha512_hex = HEXLOWER.encode(&hasher.finalize());
        let prefix = sha512_hex[0..2].to_string();
        let safe_stem = sanitize_filename(trimmed);
        (prefix, safe_stem, sha512_hex)
    }
}

/// Make filename safe across Windows and Unix by replacing invalid characters.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}

/// Helper to extract the volume root key for volume capability caching.
/// On Windows, extracts the drive root (e.g. `C:\` or `D:\`) or UNC share root.
/// On other platforms, extracts the root directory component or directory itself.
pub fn volume_root_key(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let abs = if path.is_relative() {
            std::env::current_dir()
                .map(|c| c.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        } else {
            path.to_path_buf()
        };
        let s = abs.to_string_lossy();
        let bytes = s.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            let drive = (bytes[0] as char).to_ascii_uppercase();
            return PathBuf::from(format!(r"{drive}:\"));
        }
        if s.starts_with(r"\\?\") && bytes.len() >= 6 && bytes[5] == b':' {
            let drive = (bytes[4] as char).to_ascii_uppercase();
            return PathBuf::from(format!(r"{drive}:\"));
        }
    }
    path.to_path_buf()
}

/// Check if a destination file in the pack store already exists and is valid.
fn is_destination_valid(to: &Path) -> bool {
    if !to.is_file() {
        return false;
    }
    let Ok(meta) = to.metadata() else {
        return false;
    };
    if meta.len() == 0 {
        return false;
    }
    if to.extension().and_then(|ext| ext.to_str()) == Some("idx") {
        if let Ok(bytes) = fs::read(to) {
            if let Ok(index) = PackIndex::from_bytes(&bytes) {
                let pack_path = to.with_extension("pack");
                if pack_path.is_file() {
                    if let Ok(pack_meta) = pack_path.metadata() {
                        let expected_padded = (index.total_pack_size + (PACK_ALIGNMENT as u64 - 1))
                            & !(PACK_ALIGNMENT as u64 - 1);
                        return pack_meta.len() == index.total_pack_size
                            || pack_meta.len() == expected_padded;
                    }
                }
            }
        }
        false
    } else if to.extension().and_then(|ext| ext.to_str()) == Some("pack") {
        let idx_path = to.with_extension("idx");
        if idx_path.is_file() {
            if let Ok(bytes) = fs::read(&idx_path) {
                if let Ok(index) = PackIndex::from_bytes(&bytes) {
                    let expected_padded = (index.total_pack_size + (PACK_ALIGNMENT as u64 - 1))
                        & !(PACK_ALIGNMENT as u64 - 1);
                    return meta.len() == index.total_pack_size || meta.len() == expected_padded;
                }
            }
        }
        meta.len() > 0
    } else {
        if let Some(name) = to.file_name().and_then(|n| n.to_str()) {
            if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(bytes) = fs::read(to) {
                    let actual = HEXLOWER.encode(&Sha256::digest(&bytes));
                    return actual.eq_ignore_ascii_case(name);
                }
                return false;
            }
        }
        meta.len() > 0
    }
}

/// Helper to reliably rename a temporary file with retries on Windows transient file locks.
/// If another process or thread concurrently packs the same package integrity and has
/// mapped the file or holds a lock, and the destination files already exist and are valid,
/// treat it as success rather than failing the install.
fn rename_atomic(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut attempts = 0;
    let mut delay = Duration::from_millis(5);
    loop {
        attempts += 1;
        if let Some(parent) = to.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                // If destination already exists and is valid, another thread/process completed the pack
                if is_destination_valid(to) {
                    let _ = fs::remove_file(from);
                    return Ok(());
                }

                if attempts >= 10 {
                    if is_destination_valid(to) {
                        let _ = fs::remove_file(from);
                        return Ok(());
                    }
                    return Err(e);
                }

                // Only attempt removing destination if it exists but is invalid/corrupted
                if attempts > 1 && to.exists() && !is_destination_valid(to) {
                    let _ = fs::remove_file(to);
                }
                let jitter = (attempts as u64 * 3) % 7;
                sleep(delay + Duration::from_millis(jitter));
                delay = delay.saturating_mul(2).min(Duration::from_millis(200));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tempfile::tempdir;

    #[test]
    fn test_4k_alignment_and_index_serialization() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let large_data = vec![0xAA; 9000];
        let files = [
            PackInputFile::new(
                "package.json",
                0o644,
                b"{\"name\": \"test-pkg\", \"version\": \"1.0.0\"}",
            ),
            PackInputFile::new("index.js", 0o644, b"console.log('hello world');"),
            PackInputFile::new(
                "bin/cli.js",
                0o755,
                b"#!/usr/bin/env node\nprocess.exit(0);",
            ),
            PackInputFile::new("large.dat", 0o644, &large_data),
        ];

        let integrity = "sha512-testalign1234567890abcdef";
        let index = store.put_package_pack(integrity, &files).unwrap();

        // Check index fields
        assert_eq!(index.files.len(), 4);
        assert_eq!(index.integrity, integrity);

        // Verify every file is 4 KiB aligned
        for entry in &index.files {
            assert!(
                entry.is_4k_aligned(),
                "Offset {} must be 4 KiB aligned for {}",
                entry.offset,
                entry.path
            );
            assert_eq!(entry.offset % 4096, 0);
            assert_eq!(entry.aligned_offset, entry.offset);
        }

        // Verify serialization roundtrip
        let bytes = index.to_bytes().unwrap();
        let parsed = PackIndex::from_bytes(&bytes).unwrap();
        assert_eq!(index, parsed);
    }

    #[test]
    fn test_put_and_get_pack_slice_verification() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-u1234567890abcdef54321==";
        let files = [
            PackInputFile::new("package.json", 0o644, b"{\"name\": \"demo\"}"),
            PackInputFile::new("src/main.js", 0o644, b"export default 42;"),
            PackInputFile::new("assets/logo.svg", 0o644, b"<svg></svg>"),
        ];

        store.put_package_pack(integrity, &files).unwrap();

        // Exactly 2 files created under packs/<prefix>/
        let (pack_path, idx_path) = store.pack_paths(integrity);
        assert!(
            pack_path.is_file(),
            "Pack file must exist: {}",
            pack_path.display()
        );
        assert!(
            idx_path.is_file(),
            "Index file must exist: {}",
            idx_path.display()
        );

        let prefix_dir = pack_path.parent().unwrap();
        let entries_count = fs::read_dir(prefix_dir).unwrap().count();
        assert_eq!(
            entries_count, 2,
            "Only exactly 2 files (pack + idx) should exist in store prefix dir"
        );

        // has_package_pack check
        assert!(store.has_package_pack(integrity));

        // Get pack and verify memory-mapped slices
        let pack = store
            .get_package_pack(integrity)
            .unwrap()
            .expect("Pack must exist");
        assert_eq!(
            pack.get_file_slice("package.json").unwrap(),
            b"{\"name\": \"demo\"}"
        );
        assert_eq!(
            pack.get_file_slice("src/main.js").unwrap(),
            b"export default 42;"
        );
        assert_eq!(
            pack.get_file_slice("assets/logo.svg").unwrap(),
            b"<svg></svg>"
        );
        assert!(pack.get_file_slice("nonexistent.txt").is_none());
    }

    #[test]
    fn test_materialize_pack_direct() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-matpack12345==";
        let files = [
            PackInputFile::new("package.json", 0o644, b"{\"name\": \"mat-pkg\"}"),
            PackInputFile::new("nested/deep/file.js", 0o755, b"module.exports = true;"),
        ];

        store.put_package_pack(integrity, &files).unwrap();

        let target_dir = tempdir().unwrap();
        let summary = store
            .materialize_pack(integrity, target_dir.path(), None)
            .unwrap();

        assert_eq!(summary.entries_extracted, 2);
        assert_eq!(
            summary.total_uncompressed_bytes,
            b"{\"name\": \"mat-pkg\"}".len() as u64 + b"module.exports = true;".len() as u64
        );
        assert_eq!(summary.inflate_duration, Duration::ZERO);

        let pkg_json = fs::read_to_string(target_dir.path().join("package.json")).unwrap();
        assert_eq!(pkg_json, "{\"name\": \"mat-pkg\"}");

        let file_js = fs::read_to_string(target_dir.path().join("nested/deep/file.js")).unwrap();
        assert_eq!(file_js, "module.exports = true;");
    }

    #[test]
    fn test_corrupted_cas_blob_auto_repair() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();
        let integrity = "sha512-casrepair1234567890==";
        let files = [PackInputFile::new("index.js", 0o644, b"original content")];
        let index = store.put_package_pack(integrity, &files).unwrap();
        let cas_path = index.files[0].cas_path.clone().unwrap();
        fs::write(&cas_path, b"CORRUPTED").unwrap();

        let target = tempdir().unwrap();
        store
            .materialize_pack(integrity, target.path(), None)
            .unwrap();

        assert_eq!(
            fs::read(target.path().join("index.js")).unwrap(),
            b"original content"
        );
        assert_eq!(fs::read(cas_path).unwrap(), b"original content");
    }

    #[test]
    fn test_put_package_from_tarball() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        // Create an in-memory tarball
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);

            let mut header1 = tar::Header::new_gnu();
            header1.set_size(b"{\"name\": \"tar-pkg\"}".len() as u64);
            header1.set_mode(0o644);
            header1.set_cksum();
            tar.append_data(
                &mut header1,
                "package/package.json",
                &b"{\"name\": \"tar-pkg\"}"[..],
            )
            .unwrap();

            let mut header2 = tar::Header::new_gnu();
            header2.set_size(b"console.log('from tar');".len() as u64);
            header2.set_mode(0o644);
            header2.set_cksum();
            tar.append_data(
                &mut header2,
                "package/lib/index.js",
                &b"console.log('from tar');"[..],
            )
            .unwrap();

            tar.finish().unwrap();
        }
        let tarball_bytes = enc.finish().unwrap();

        let integrity =
            rnpm_core::Integrity::from_bytes(&tarball_bytes, rnpm_core::Algorithm::Sha512)
                .to_string();
        let index = store
            .put_package_from_tarball(&integrity, &tarball_bytes)
            .unwrap();
        assert_eq!(index.files.len(), 2);

        let pack = store
            .get_package_pack(&integrity)
            .unwrap()
            .expect("Pack must exist");
        assert_eq!(
            pack.get_file_slice("package.json").unwrap(),
            b"{\"name\": \"tar-pkg\"}"
        );
        assert_eq!(
            pack.get_file_slice("lib/index.js").unwrap(),
            b"console.log('from tar');"
        );

        // Test materializing tar-extracted pack
        let target = tempdir().unwrap();
        store
            .materialize_pack(&integrity, target.path(), None)
            .unwrap();
        assert_eq!(
            fs::read_to_string(target.path().join("package.json")).unwrap(),
            "{\"name\": \"tar-pkg\"}"
        );
        assert_eq!(
            fs::read_to_string(target.path().join("lib/index.js")).unwrap(),
            "console.log('from tar');"
        );
    }

    #[test]
    fn test_tarball_entry_path_traversal_rejected() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);
            let mut header = tar::Header::new_gnu();
            let payload = b"malicious content";
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            let path_bytes = b"package/../escape.txt";
            header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
            header.set_cksum();
            tar.append(&header, &payload[..]).unwrap();
            tar.finish().unwrap();
        }
        let tarball_bytes = enc.finish().unwrap();
        let integrity =
            rnpm_core::Integrity::from_bytes(&tarball_bytes, rnpm_core::Algorithm::Sha512)
                .to_string();

        let err = store
            .put_package_from_tarball(&integrity, &tarball_bytes)
            .unwrap_err();
        match err {
            CacheError::Fs(rnpm_fs::FsError::PathTraversal { path }) => {
                assert!(
                    path.to_string_lossy().contains("escape.txt")
                        || path.to_string_lossy().contains("..")
                );
            }
            other => panic!("Expected FsError::PathTraversal, got: {other:?}"),
        }
    }

    #[test]
    fn test_put_package_pack_path_traversal_rejected() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let files = [PackInputFile::new("../escape.txt", 0o644, b"malicious")];
        let integrity = "sha512-testtraversal1234==";
        let err = store.put_package_pack(integrity, &files).unwrap_err();
        match err {
            CacheError::Fs(rnpm_fs::FsError::PathTraversal { .. }) => {}
            other => panic!("Expected FsError::PathTraversal, got: {other:?}"),
        }
    }

    #[test]
    fn test_tampered_index_path_traversal_purged() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-validentry1234567890==";
        let files = [PackInputFile::new("index.js", 0o644, b"console.log('hi');")];
        store.put_package_pack(integrity, &files).unwrap();

        let (_, idx_path) = store.pack_paths(integrity);
        assert!(idx_path.is_file());

        // Tamper with the index to include a traversal path
        let mut idx: PackIndex = PackIndex::from_bytes(&fs::read(&idx_path).unwrap()).unwrap();
        idx.files[0].path = "../evil.js".to_string();
        fs::write(&idx_path, idx.to_bytes().unwrap()).unwrap();

        // Clear in-memory cache to force reading from disk
        store.clear_mmap_cache();

        // get_package_pack must detect the tampered path, purge the pack/idx, and return None
        let loaded = store.get_package_pack(integrity).unwrap();
        assert!(loaded.is_none());
        assert!(!idx_path.exists());
    }

    #[test]
    fn test_corrupted_pack_file_length_mismatch_purged() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-lenmismatch1234567890==";
        let files = [PackInputFile::new("index.js", 0o644, b"important payload")];
        store.put_package_pack(integrity, &files).unwrap();

        let (pack_path, idx_path) = store.pack_paths(integrity);
        assert!(pack_path.is_file());

        // Clear mmap cache before modifying file on disk (Windows user-mapped section requirement)
        store.clear_mmap_cache();

        // Truncate pack file on disk
        fs::write(&pack_path, b"short").unwrap();

        // get_package_pack must detect length mismatch, purge files, and return None
        let loaded = store.get_package_pack(integrity).unwrap();
        assert!(loaded.is_none());
        assert!(!pack_path.exists());
        assert!(!idx_path.exists());
    }

    #[test]
    fn test_put_package_from_tarball_integrity_mismatch_fails() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);
            let mut header = tar::Header::new_gnu();
            header.set_size(10);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "package/index.js", &b"0123456789"[..])
                .unwrap();
            tar.finish().unwrap();
        }
        let tarball_bytes = enc.finish().unwrap();

        let bogus_integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
        let err = store
            .put_package_from_tarball(bogus_integrity, &tarball_bytes)
            .unwrap_err();
        match err {
            CacheError::IntegrityMismatch { .. } => {}
            other => panic!("Expected CacheError::IntegrityMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn test_purge_pack_removes_files_and_cache() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-purgetest1234567890==";
        let files = [PackInputFile::new("index.js", 0o644, b"test")];
        store.put_package_pack(integrity, &files).unwrap();

        let (pack_path, idx_path) = store.pack_paths(integrity);
        assert!(pack_path.is_file());
        assert!(idx_path.is_file());
        assert!(store.has_package_pack(integrity));

        store.purge(integrity).unwrap();
        assert!(!pack_path.exists());
        assert!(!idx_path.exists());
        assert!(!store.has_package_pack(integrity));
    }

    #[test]
    fn test_mmap_cache_and_dual_lookup() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-v4zDualLookupIntegrityKey==";
        let files = [PackInputFile::new("index.js", 0o644, b"test content")];

        let index = store.put_package_pack(integrity, &files).unwrap();
        let sha512_hex = index.sha512_hex.clone();

        // Lookup by SRI string
        assert!(store.has_package_pack(integrity));
        let pack1 = store.get_package_pack(integrity).unwrap().unwrap();

        // Lookup by sha512_hex
        assert!(store.has_package_pack(&sha512_hex));
        let pack2 = store.get_package_pack(&sha512_hex).unwrap().unwrap();

        assert_eq!(pack1.data(), pack2.data());

        // Clear cache and verify on-disk reload works
        store.clear_mmap_cache();
        assert!(store.has_package_pack(integrity));
        let pack3 = store.get_package_pack(integrity).unwrap().unwrap();
        assert_eq!(pack3.get_file_slice("index.js").unwrap(), b"test content");
    }

    #[test]
    fn test_pack_checksum_verification_and_corruption_purged() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-checksumtest1234567890==";
        let files = [PackInputFile::new(
            "index.js",
            0o644,
            b"console.log('original checksum payload');",
        )];

        let index = store.put_package_pack(integrity, &files).unwrap();
        assert!(
            index.pack_checksum.is_some(),
            "Pack index must store pack_checksum"
        );

        let (pack_path, idx_path) = store.pack_paths(integrity);
        assert!(pack_path.is_file());
        assert!(idx_path.is_file());

        // Corrupt a byte in the pack file without changing its length
        store.clear_mmap_cache();
        let mut pack_bytes = fs::read(&pack_path).unwrap();
        pack_bytes[0] ^= 0xFF; // Bit flip
        fs::write(&pack_path, &pack_bytes).unwrap();

        // Attempting to materialize should detect hash mismatch, return CorruptedPack, and purge files
        let target = tempdir().unwrap();
        let err = store
            .materialize_pack(integrity, target.path(), None)
            .unwrap_err();
        match err {
            PackError::CorruptedPack(msg) => {
                assert!(msg.contains("hash mismatch") || msg.contains("mismatch"));
            }
            other => panic!("Expected PackError::CorruptedPack, got: {other:?}"),
        }

        // Pack files must have been purged
        assert!(!pack_path.exists(), "Corrupted pack file must be purged");
        assert!(!idx_path.exists(), "Corrupted pack index must be purged");
        assert!(!store.has_package_pack(integrity));
    }

    #[test]
    fn test_zero_filled_pack_detected_and_purged() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-zerofilltest1234567890==";
        let files = [PackInputFile::new(
            "index.js",
            0o644,
            b"non zero payload content",
        )];

        let index = store.put_package_pack(integrity, &files).unwrap();
        let (pack_path, idx_path) = store.pack_paths(integrity);

        // Zero-fill the pack file to the exact same size
        store.clear_mmap_cache();
        let zero_bytes = vec![0u8; index.total_pack_size as usize];
        fs::write(&pack_path, &zero_bytes).unwrap();

        // Materialize should detect zero-filled corruption and purge
        let target = tempdir().unwrap();
        let err = store
            .materialize_pack(integrity, target.path(), None)
            .unwrap_err();
        match err {
            PackError::CorruptedPack(_) => {}
            other => panic!("Expected PackError::CorruptedPack, got: {other:?}"),
        }

        assert!(!pack_path.exists(), "Zero-filled pack file must be purged");
        assert!(!idx_path.exists(), "Pack index must be purged");
    }

    #[test]
    fn test_put_package_pack_deduplicates_entries_last_wins() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-deduptest1234567890==";
        let files = [
            PackInputFile::new("foo.js", 0o644, b"first foo"),
            PackInputFile::new("bar.js", 0o644, b"bar content"),
            PackInputFile::new("FOO.JS", 0o755, b"second foo (last wins)"),
        ];

        let index = store.put_package_pack(integrity, &files).unwrap();
        // Only 2 unique files: foo.js (deduped) and bar.js
        assert_eq!(index.files.len(), 2);

        let pack = store.get_package_pack(integrity).unwrap().unwrap();
        assert_eq!(
            pack.get_file_slice("foo.js").unwrap(),
            b"second foo (last wins)"
        );
        assert_eq!(pack.get_file_slice("bar.js").unwrap(), b"bar content");

        // Materialize and verify file on disk
        let target = tempdir().unwrap();
        let summary = store
            .materialize_pack(integrity, target.path(), None)
            .unwrap();
        assert_eq!(summary.entries_extracted, 2);
        let extracted_foo = fs::read_to_string(target.path().join("FOO.JS")).unwrap();
        assert_eq!(extracted_foo, "second foo (last wins)");
    }

    #[test]
    fn test_put_package_from_tarball_deduplicates_entries_last_wins() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);

            let mut header1 = tar::Header::new_gnu();
            header1.set_size(b"initial value".len() as u64);
            header1.set_mode(0o644);
            header1.set_cksum();
            tar.append_data(&mut header1, "package/lib/app.js", &b"initial value"[..])
                .unwrap();

            let mut header2 = tar::Header::new_gnu();
            header2.set_size(b"updated value (last wins)".len() as u64);
            header2.set_mode(0o755);
            header2.set_cksum();
            tar.append_data(
                &mut header2,
                "package/LIB/APP.JS",
                &b"updated value (last wins)"[..],
            )
            .unwrap();

            tar.finish().unwrap();
        }
        let tarball_bytes = enc.finish().unwrap();
        let integrity =
            rnpm_core::Integrity::from_bytes(&tarball_bytes, rnpm_core::Algorithm::Sha512)
                .to_string();

        let index = store
            .put_package_from_tarball(&integrity, &tarball_bytes)
            .unwrap();
        assert_eq!(
            index.files.len(),
            1,
            "Duplicate entry in tarball must be deduplicated to 1 entry"
        );

        let target = tempdir().unwrap();
        store
            .materialize_pack(&integrity, target.path(), None)
            .unwrap();
        let content = fs::read_to_string(target.path().join("LIB/APP.JS")).unwrap();
        assert_eq!(content, "updated value (last wins)");
    }

    #[test]
    fn test_rename_atomic_race_dest_valid_treated_as_success() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-renameracetest12345==";
        let files = [PackInputFile::new("index.js", 0o644, b"test content")];

        // 1. First pack creation succeeds
        store.put_package_pack(integrity, &files).unwrap();
        let (pack_path, idx_path) = store.pack_paths(integrity);
        assert!(pack_path.is_file());
        assert!(idx_path.is_file());

        // 2. Create another temp file and rename to the already existing valid destination
        let tmp_file = store.tmp_dir().join("another_tmp.tmp");
        fs::write(&tmp_file, b"concurrent duplicate payload").unwrap();

        // rename_atomic to existing valid pack file should succeed without error
        let res = rename_atomic(&tmp_file, &pack_path);
        assert!(
            res.is_ok(),
            "rename_atomic must succeed when destination already exists and is valid"
        );
        assert!(
            !tmp_file.exists(),
            "temp file must be cleaned up on successful race resolution"
        );
    }

    #[test]
    fn test_materialize_pack_io_error_does_not_purge_pack() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        let integrity = "sha512-nooverpurge1234567890==";
        let files = [PackInputFile::new("sub/file.js", 0o644, b"good content")];
        store.put_package_pack(integrity, &files).unwrap();

        let (pack_path, idx_path) = store.pack_paths(integrity);
        assert!(pack_path.is_file());
        assert!(idx_path.is_file());

        // Create a target destination where 'sub' is a regular file, causing mkdir to fail with Io error
        let target_dir = tempdir().unwrap();
        let sub_file = target_dir.path().join("sub");
        fs::write(&sub_file, b"blocking file").unwrap();

        let err = store
            .materialize_pack(integrity, target_dir.path(), None)
            .unwrap_err();
        match err {
            CacheError::Io(_) => {}
            other => panic!("Expected CacheError::Io, got: {other:?}"),
        }

        // The pack must NOT be purged because this was an environmental/IO error!
        assert!(pack_path.is_file(), "Pack must NOT be purged on I/O error");
        assert!(idx_path.is_file(), "Index must NOT be purged on I/O error");
        assert!(store.has_package_pack(integrity));
    }

    #[test]
    fn test_pack_padding_4k_cluster_aligned() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();

        // Total payload is only 123 bytes - far below 4096 bytes
        let small_payload = vec![0x42; 123];
        let files = [PackInputFile::new("index.js", 0o644, &small_payload)];
        let integrity = "sha512-padtest1234567890abcdef==";

        let index = store.put_package_pack(integrity, &files).unwrap();
        let (pack_path, idx_path) = store.pack_paths(integrity);
        assert!(idx_path.is_file());

        let pack_len = fs::metadata(&pack_path).unwrap().len();
        assert_eq!(
            pack_len % 4096,
            0,
            "Pack file on disk must be 4096-byte cluster aligned"
        );
        assert_eq!(
            pack_len, 4096,
            "123-byte payload must be padded up to 4096 bytes"
        );
        assert_eq!(
            index.total_pack_size, 4096,
            "Index total_pack_size must reflect the padded pack length"
        );

        // Verify trailing bytes are zero-padded
        let raw_bytes = fs::read(&pack_path).unwrap();
        assert_eq!(raw_bytes.len(), 4096);
        assert_eq!(&raw_bytes[0..123], &small_payload[..]);
        assert!(
            raw_bytes[123..].iter().all(|&b| b == 0),
            "Padding bytes must be zeroes"
        );

        // Reload and verify
        let pack = store
            .get_package_pack(integrity)
            .unwrap()
            .expect("Pack must load");
        assert_eq!(pack.get_file_slice("index.js").unwrap(), &small_payload[..]);

        // Also test tarball creation pads to 4 KiB
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);
            let mut header = tar::Header::new_gnu();
            header.set_size(50);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "package/test.txt", &vec![0x33; 50][..])
                .unwrap();
            tar.finish().unwrap();
        }
        let tarball_bytes = enc.finish().unwrap();
        let tarball_integ =
            rnpm_core::Integrity::from_bytes(&tarball_bytes, rnpm_core::Algorithm::Sha512)
                .to_string();
        let tar_index = store
            .put_package_from_tarball(&tarball_integ, &tarball_bytes)
            .unwrap();
        let (tar_pack_path, _) = store.pack_paths(&tarball_integ);
        let tar_pack_len = fs::metadata(&tar_pack_path).unwrap().len();
        assert_eq!(tar_pack_len % 4096, 0, "Tarball pack must be 4 KiB padded");
        assert_eq!(tar_pack_len, 4096);
        assert_eq!(tar_index.total_pack_size, 4096);

        // Materialize should succeed
        let target = tempdir().unwrap();
        let summary = store
            .materialize_pack(&tarball_integ, target.path(), None)
            .unwrap();
        assert_eq!(summary.entries_extracted, 1);
        assert_eq!(summary.total_uncompressed_bytes, 50);
    }

    #[test]
    fn test_pack_store_cache_volume_block_clone_eligibility() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();
        let target_dir = tempdir().unwrap();

        // Cache initially empty
        {
            let cache = store.block_clone_cache.read().unwrap();
            assert!(cache.is_empty());
        }

        // First check populates cache
        let eligible = store.is_block_cloning_eligible(target_dir.path());
        let expected_key = volume_root_key(target_dir.path());
        {
            let cache = store.block_clone_cache.read().unwrap();
            assert_eq!(cache.get(&expected_key), Some(&eligible));
        }

        // Subsequent check uses cache
        let cached_eligible = store.can_block_clone_to(target_dir.path());
        assert_eq!(eligible, cached_eligible);

        // Concurrent access from multiple threads
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let st = &store;
                let tp = target_dir.path();
                scope.spawn(move || {
                    let el = st.is_block_cloning_eligible(tp);
                    assert_eq!(el, eligible);
                });
            }
        });

        // Clearing cache works
        store.clear_block_clone_cache();
        {
            let cache = store.block_clone_cache.read().unwrap();
            assert!(cache.is_empty());
        }
    }

    #[test]
    fn test_same_size_cas_blob_corruption_detected_and_repaired() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();
        let integrity = "sha512-samesizecorruption98765==";
        let original_data = b"export const version = '1.0.0';\nconsole.log('clean');";
        let files = [PackInputFile::new("index.js", 0o644, original_data)];

        let index = store.put_package_pack(integrity, &files).unwrap();
        let cas_path = index.files[0].cas_path.clone().unwrap();
        let expected_sha256 = index.files[0].sha256.clone().unwrap();

        assert!(cas_path.is_file(), "CAS blob must be written to disk");
        assert_eq!(fs::read(&cas_path).unwrap(), original_data);

        // Sleep briefly to ensure filesystem mtime changes on subsequent modification
        sleep(Duration::from_millis(25));

        // Corrupt exactly 1 byte in place, keeping the file size identical
        let mut corrupted_data = original_data.to_vec();
        corrupted_data[7] ^= 0x55;
        assert_eq!(corrupted_data.len(), original_data.len());
        fs::write(&cas_path, &corrupted_data).unwrap();
        assert_eq!(fs::read(&cas_path).unwrap(), corrupted_data);
        assert_ne!(fs::read(&cas_path).unwrap(), original_data);

        // Clear in-memory mmap cache to simulate warm verification in a fresh process
        store.clear_mmap_cache();

        // get_package_pack must detect the corruption, rehash, repair from pack slice,
        // and match the correct SHA-256
        let pack = store
            .get_package_pack(integrity)
            .unwrap()
            .expect("Package pack must load successfully");

        // Verify that the corrupted CAS blob on disk was repaired
        let repaired_disk_bytes = fs::read(&cas_path).unwrap();
        assert_eq!(
            repaired_disk_bytes, original_data,
            "CAS blob on disk must be repaired to original content"
        );
        let repaired_sha = HEXLOWER.encode(&Sha256::digest(&repaired_disk_bytes));
        assert_eq!(
            repaired_sha, expected_sha256,
            "Repaired CAS blob must match expected SHA-256"
        );

        // Verify pack slice matches original data
        assert_eq!(pack.get_file_slice("index.js").unwrap(), original_data);

        // Verify materialization uses the repaired CAS blob cleanly
        let target = tempdir().unwrap();
        let summary = store
            .materialize_pack(integrity, target.path(), None)
            .unwrap();
        assert_eq!(summary.entries_extracted, 1);
        assert_eq!(
            fs::read(target.path().join("index.js")).unwrap(),
            original_data
        );
    }

    #[test]
    fn test_decode_package_tarball_duplicate_entries_differing_content_later_wins() {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);

            let mut header1 = tar::Header::new_gnu();
            header1.set_size(b"first version of file".len() as u64);
            header1.set_mode(0o644);
            header1.set_cksum();
            tar.append_data(&mut header1, "package/lib/index.js", &b"first version of file"[..])
                .unwrap();

            let mut header2 = tar::Header::new_gnu();
            header2.set_size(b"second version of file (later wins)".len() as u64);
            header2.set_mode(0o755);
            header2.set_cksum();
            tar.append_data(
                &mut header2,
                "package/./lib/index.js",
                &b"second version of file (later wins)"[..],
            )
            .unwrap();

            tar.finish().unwrap();
        }
        let tarball_bytes = enc.finish().unwrap();
        let target_dir = tempdir().unwrap();
        let decoded = PackStore::decode_package_tarball(
            &tarball_bytes,
            target_dir.path(),
            "test-dup-pkg",
        )
        .expect("decode_package_tarball must succeed with duplicate entries");

        // Must be deduplicated to exactly 1 file entry, with the later content and mode winning
        assert_eq!(decoded.files.len(), 1);
        assert_eq!(decoded.files[0].data, b"second version of file (later wins)");
        assert_eq!(decoded.files[0].mode, 0o755);
    }
}
