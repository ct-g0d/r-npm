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
use tracing::{debug, warn};

/// 4 KiB byte alignment for every file payload inside a `.pack` file.
pub const PACK_ALIGNMENT: usize = 4096;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A single file entry inside the `.idx` pack index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

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

impl PackagePack {
    /// Return the raw byte slice of the entire memory-mapped pack.
    pub fn data(&self) -> &[u8] {
        self.buffer.data()
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
        let start_time = std::time::Instant::now();
        let pack_data = self.data();
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

        // 3. Recreate symlinks if any
        for (link_rel, target_rel) in &self.index.symlinks {
            let link_path = target_dir.join(link_rel);
            let target_path = target_dir.join(target_rel);
            let _ = rnpm_fs::junction::create_junction(&link_path, &target_path);
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

/// The Pack Store manager.
///
/// Stores packages as 4 KiB-aligned `.pack` blobs and `.idx` indices under
/// `store-v1/packs/<sha512-prefix>/`.
#[derive(Debug, Clone)]
pub struct PackStore {
    root: PathBuf,
    mmap_cache: Arc<Mutex<HashMap<String, PackagePack>>>,
    block_clone_cache: Arc<RwLock<HashMap<PathBuf, bool>>>,
}

impl PackStore {
    /// Initialize a PackStore rooted at `root` directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("packs"))?;
        fs::create_dir_all(root.join("tmp"))?;
        Ok(Self {
            root,
            mmap_cache: Arc::new(Mutex::new(HashMap::new())),
            block_clone_cache: Arc::new(RwLock::new(HashMap::new())),
        })
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
            match unsafe { Mmap::map(&file) } {
                Ok(mmap) => Arc::new(PackBuffer::Mmap(Arc::new(mmap))),
                Err(e) => {
                    debug!(
                        "mmap failed for '{}': {e}, falling back to buffered read",
                        pack_path.display()
                    );
                    let bytes = fs::read(&pack_path)?;
                    Arc::new(PackBuffer::Bytes(Arc::new(bytes)))
                }
            }
        };

        let pack = PackagePack {
            index,
            buffer,
            pack_path,
            idx_path,
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

            index_files.push(PackFileEntry {
                path: file.path,
                mode: file.mode,
                size: file.data.len() as u64,
                offset: aligned_offset as u64,
                aligned_offset: aligned_offset as u64,
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

        let pack_checksum = HEXLOWER.encode(&Sha256::digest(&pack_bytes));
        let index = PackIndex::with_checksum(
            integrity.to_string(),
            sha512_hex.clone(),
            pack_bytes.len() as u64,
            pack_checksum,
            index_files,
        );
        let idx_bytes = index.to_bytes().map_err(CacheError::Json)?;

        // 2. Atomic write via temp directory on same filesystem
        let tmp_dir = self.tmp_dir();
        let count = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let tmp_pack = tmp_dir.join(format!("pack_{pid}_{count}.tmp"));
        let tmp_idx = tmp_dir.join(format!("idx_{pid}_{count}.tmp"));

        {
            let mut f_pack = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_pack)?;
            f_pack.write_all(&pack_bytes)?;
            f_pack.flush()?;
        }

        {
            let mut f_idx = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_idx)?;
            f_idx.write_all(&idx_bytes)?;
            f_idx.flush()?;
        }

        // 3. Move into place
        let prefix_dir = self.packs_dir().join(&prefix);
        let _ = fs::create_dir_all(&prefix_dir);

        let final_pack = prefix_dir.join(format!("{safe_stem}.pack"));
        let final_idx = prefix_dir.join(format!("{safe_stem}.idx"));

        rename_atomic(&tmp_pack, &final_pack)?;
        rename_atomic(&tmp_idx, &final_idx)?;

        // 4. Update memory-map cache
        let buffer = if pack_bytes.is_empty() {
            Arc::new(PackBuffer::Empty)
        } else if let Ok(file) = OpenOptions::new().read(true).open(&final_pack) {
            match unsafe { Mmap::map(&file) } {
                Ok(mmap) => Arc::new(PackBuffer::Mmap(Arc::new(mmap))),
                Err(_) => Arc::new(PackBuffer::Bytes(Arc::new(pack_bytes))),
            }
        } else {
            Arc::new(PackBuffer::Bytes(Arc::new(pack_bytes)))
        };

        let pack = PackagePack {
            index: index.clone(),
            buffer,
            pack_path: final_pack,
            idx_path: final_idx,
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
                    guard.insert(canon, pack);
                }
            }
        }

        Ok(index)
    }

    /// Extract a tarball into the pack store atomically.
    pub fn put_package_from_tarball(
        &self,
        integrity: &str,
        tarball_bytes: &[u8],
    ) -> Result<PackIndex, CacheError> {
        let trimmed = integrity.trim();
        if !trimmed.is_empty() {
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

            if let Ok(entry_size) = entry.header().size() {
                if entry_size > limits.max_single_entry_size {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "entry size".to_string(),
                        detail: format!(
                            "Entry size {} exceeded single file limit of {} bytes",
                            entry_size, limits.max_single_entry_size
                        ),
                    }));
                }
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
            let mut data = Vec::new();
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

            // Deduplicate by lowercased path, ensuring LAST entry wins
            let lower_key = norm_path.to_lowercase();
            if !file_payloads_map.contains_key(&lower_key) {
                file_payloads_order.push(lower_key.clone());
            }
            file_payloads_map.insert(lower_key, (norm_path, mode, data));
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

        self.put_package_pack(integrity, &input_files)
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
        let pack = self
            .get_package_pack(integrity)?
            .ok_or_else(|| CacheError::PackNotFound(integrity.to_string()))?;
        let can_block_clone = self.is_block_cloning_eligible(target_dir);
        match pack.materialize_to_with_hint(target_dir, writer_config, Some(can_block_clone)) {
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
}
