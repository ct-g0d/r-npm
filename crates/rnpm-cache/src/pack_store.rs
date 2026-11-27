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
use crate::index::encode_hex_lower;
use data_encoding::{BASE64, HEXLOWER};
use flate2::bufread::GzDecoder;
use memmap2::Mmap;
use path_clean::clean;
use rnpm_core::{Algorithm, Integrity};
use rnpm_fs::writer::ParallelWriterConfig;
#[cfg(windows)]
use rnpm_fs::RawFileHandle;
use rnpm_fs::{
    clone_or_write_pack_file, is_block_cloning_supported, is_refs_volume, is_same_volume,
    ExtractionSummary,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{sleep, yield_now};
use std::time::Duration;
use tracing::warn;

#[inline]
fn sha256_hex_string(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut hex_buf = [0u8; 64];
    encode_hex_lower(&digest, &mut hex_buf).to_string()
}

#[inline]
fn is_ascii_reserved_stem(base: &str) -> bool {
    let b = base.as_bytes();
    match b.len() {
        3 => {
            base.eq_ignore_ascii_case("CON")
                || base.eq_ignore_ascii_case("PRN")
                || base.eq_ignore_ascii_case("AUX")
                || base.eq_ignore_ascii_case("NUL")
        }
        4 => {
            ((b[0] | 0x20) == b'c' && (b[1] | 0x20) == b'o' && (b[2] | 0x20) == b'm' && b[3].is_ascii_digit())
                || ((b[0] | 0x20) == b'l' && (b[1] | 0x20) == b'p' && (b[2] | 0x20) == b't' && b[3].is_ascii_digit())
        }
        6 => base.eq_ignore_ascii_case("CLOCK$") || base.eq_ignore_ascii_case("CONIN$"),
        7 => base.eq_ignore_ascii_case("CONOUT$"),
        _ => false,
    }
}

/// Zero-allocation entry path validation matching `rnpm_fs::validate_entry_path` for ASCII paths,
/// delegating to `rnpm_fs::validate_entry_path` for non-ASCII or backslash edge cases.
fn fast_validate_entry_path(path_str: &str) -> Result<(), rnpm_fs::FsError> {
    if path_str.is_empty() {
        return Ok(());
    }
    if !path_str.is_ascii() || path_str.contains('\\') {
        return rnpm_fs::validate_entry_path(Path::new(path_str));
    }

    let bytes = path_str.as_bytes();
    if bytes.contains(&0) {
        return Err(rnpm_fs::FsError::PathTraversal {
            path: PathBuf::from(path_str),
        });
    }
    if bytes[0] == b'/' || (bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()) {
        return Err(rnpm_fs::FsError::AbsolutePath {
            path: PathBuf::from(path_str),
        });
    }

    for seg in path_str.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(rnpm_fs::FsError::PathTraversal {
                path: PathBuf::from(path_str),
            });
        }
        for &ch in seg.as_bytes() {
            if ch < 0x20 || matches!(ch, b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|') {
                return Err(rnpm_fs::FsError::PathTraversal {
                    path: PathBuf::from(path_str),
                });
            }
        }
        let stem = seg.split('.').next().unwrap_or(seg).trim_matches([' ', '.']);
        if !stem.is_empty() && is_ascii_reserved_stem(stem) {
            return Err(rnpm_fs::FsError::WindowsReservedDeviceName {
                name: seg.to_string(),
                path: PathBuf::from(path_str),
            });
        }
        if seg.ends_with('.') || seg.ends_with(' ') {
            return Err(rnpm_fs::FsError::TrailingDotOrSpace {
                name: seg.to_string(),
                path: PathBuf::from(path_str),
            });
        }
    }
    Ok(())
}

struct CountingSlice<'a> {
    rem: &'a [u8],
    read_bytes: Arc<AtomicU64>,
}

impl<'a> Read for CountingSlice<'a> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.rem.len().min(buf.len());
        if n > 0 {
            buf[..n].copy_from_slice(&self.rem[..n]);
            self.rem = &self.rem[n..];
            self.read_bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok(n)
    }
}

impl<'a> std::io::BufRead for CountingSlice<'a> {
    #[inline]
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        Ok(self.rem)
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        let n = amt.min(self.rem.len());
        self.rem = &self.rem[n..];
        self.read_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Enum reader avoiding Box<dyn Read> and double-buffering over &[u8] via flate2::bufread::GzDecoder.
enum TarStreamReader<'a> {
    Gz(Box<BufReader<GzDecoder<CountingSlice<'a>>>>),
    Raw(CountingSlice<'a>),
}

impl<'a> TarStreamReader<'a> {
    #[inline]
    fn new(tarball_bytes: &'a [u8], read_bytes: Arc<AtomicU64>) -> Self {
        let slice = CountingSlice {
            rem: tarball_bytes,
            read_bytes,
        };
        if tarball_bytes.starts_with(&[0x1f, 0x8b]) {
            Self::Gz(Box::new(BufReader::with_capacity(
                16 * 1024,
                GzDecoder::new(slice),
            )))
        } else {
            Self::Raw(slice)
        }
    }
}

impl<'a> Read for TarStreamReader<'a> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Gz(r) => r.read(buf),
            Self::Raw(r) => r.read(buf),
        }
    }
}

/// Fast ASCII prefix stripping matching `rnpm_fs::strip_package_prefix` + normalization for simple paths.
/// Returns `None` if entry has no relative path after stripping root component,
/// or `Some(None)` if caller should fall back to full `Path` logic (`..`, `\`, `./` internal segments, non-ASCII, etc.).
#[inline]
fn try_fast_strip_ascii_tar_path(bytes: &[u8]) -> Option<Option<&str>> {
    if bytes.is_empty() || !bytes.is_ascii() {
        return Some(None);
    }
    let Ok(mut s) = std::str::from_utf8(bytes) else {
        return Some(None);
    };
    if s.contains('\\') || s.contains('\0') || s.contains("..") {
        return Some(None);
    }
    // Trim leading "./" segments
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    if s.is_empty()
        || s.starts_with('/')
        || (s.len() >= 2 && s.as_bytes()[1] == b':' && s.as_bytes()[0].is_ascii_alphabetic())
    {
        return Some(None);
    }
    // Strip first normal component (package root like "package/")
    let Some(slash) = s.find('/') else {
        // Only the root component (e.g. "package") -> nothing to extract
        return None;
    };
    let mut rest = &s[slash + 1..];
    loop {
        if let Some(r) = rest.strip_prefix("./") {
            rest = r;
        } else if let Some(r) = rest.strip_prefix('/') {
            rest = r;
        } else {
            break;
        }
    }
    // Trim trailing slashes; empty or "." yields no payload
    if rest.is_empty() || rest == "." {
        return None;
    }
    // Fallback if internal "/./" or "//" segments need component collapsing
    if rest.contains("/./") || rest.contains("//") || rest.ends_with("/.") {
        return Some(None);
    }
    Some(Some(rest))
}

fn fallback_normalize_tar_path(
    entry: &tar::Entry<'_, TarStreamReader<'_>>,
    limits: &rnpm_fs::TarLimits,
    saw_npmignores: &mut HashSet<String>,
) -> Result<Option<String>, CacheError> {
    let raw_path = entry.path().map_err(CacheError::Io)?.to_path_buf();
    let mut relative_path = match rnpm_fs::strip_package_prefix(&raw_path) {
        Some(p) => {
            let cleaned: PathBuf = p
                .components()
                .filter(|c| !matches!(c, std::path::Component::CurDir))
                .collect();
            if cleaned.as_os_str().is_empty() {
                return Ok(None);
            }
            cleaned
        }
        None => return Ok(None),
    };
    if relative_path.file_name() == Some(std::ffi::OsStr::new(".npmignore")) {
        let s = relative_path.to_string_lossy().replace('\\', "/");
        saw_npmignores.insert(s);
    } else if relative_path.file_name() == Some(std::ffi::OsStr::new(".gitignore")) {
        let ni = relative_path.with_file_name(".npmignore");
        let ni_str = ni.to_string_lossy().replace('\\', "/");
        if saw_npmignores.contains(&ni_str) {
            return Ok(None);
        }
        relative_path = ni;
    }
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
    let clean_path = relative_path.to_string_lossy().replace('\\', "/");
    let np = clean_path
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string();
    if np.is_empty() {
        Ok(None)
    } else {
        Ok(Some(np))
    }
}

#[inline]
fn ascii_depth(path: &str) -> usize {
    path.split('/').filter(|s| !s.is_empty() && *s != ".").count()
}

fn check_case_dir_collision(
    norm_lower: &str,
    is_dir: bool,
    seen_dirs_lower: &mut HashSet<String>,
    seen_files_lower: &mut HashSet<String>,
    rel_for_err: &dyn Fn() -> PathBuf,
) -> Result<(), CacheError> {
    if is_dir {
        if seen_files_lower.contains(norm_lower) {
            return Err(CacheError::Fs(rnpm_fs::FsError::CaseCollision {
                path: rel_for_err(),
            }));
        }
        if !seen_dirs_lower.contains(norm_lower) {
            seen_dirs_lower.insert(norm_lower.to_string());
        }
        let mut search_from = 0;
        while let Some(rel_idx) = norm_lower[search_from..].find('/') {
            let end = search_from + rel_idx;
            if end > 0 {
                let prefix = &norm_lower[..end];
                if seen_files_lower.contains(prefix) {
                    return Err(CacheError::Fs(rnpm_fs::FsError::CaseCollision {
                        path: rel_for_err(),
                    }));
                }
                if !seen_dirs_lower.contains(prefix) {
                    seen_dirs_lower.insert(prefix.to_string());
                }
            }
            search_from = end + 1;
        }
    } else {
        if seen_dirs_lower.contains(norm_lower) {
            return Err(CacheError::Fs(rnpm_fs::FsError::CaseCollision {
                path: rel_for_err(),
            }));
        }
        if !seen_files_lower.contains(norm_lower) {
            seen_files_lower.insert(norm_lower.to_string());
        }
        let mut search_from = 0;
        while let Some(rel_idx) = norm_lower[search_from..].find('/') {
            let end = search_from + rel_idx;
            if end > 0 {
                let prefix = &norm_lower[..end];
                if seen_files_lower.contains(prefix) {
                    return Err(CacheError::Fs(rnpm_fs::FsError::CaseCollision {
                        path: rel_for_err(),
                    }));
                }
                if !seen_dirs_lower.contains(prefix) {
                    seen_dirs_lower.insert(prefix.to_string());
                }
            }
            search_from = end + 1;
        }
    }
    Ok(())
}

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

/// Fast single-syscall metadata query returning `(file_size, mtime_nanos)` for a regular file.
#[cfg(windows)]
#[inline]
fn fast_size_and_mtime_wide(wide_null: &[u16]) -> Option<(u64, Option<u64>)> {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct FILETIME {
        dwLowDateTime: u32,
        dwHighDateTime: u32,
    }
    #[repr(C)]
    #[allow(non_snake_case)]
    struct WIN32_FILE_ATTRIBUTE_DATA {
        dwFileAttributes: u32,
        ftCreationTime: FILETIME,
        ftLastAccessTime: FILETIME,
        ftLastWriteTime: FILETIME,
        nFileSizeHigh: u32,
        nFileSizeLow: u32,
    }
    extern "system" {
        fn GetFileAttributesExW(
            lpFileName: *const u16,
            fInfoLevelId: i32,
            lpFileInformation: *mut std::ffi::c_void,
        ) -> i32;
    }
    const GET_FILE_EX_INFO_STANDARD: i32 = 0;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const WINDOWS_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

    let mut data = std::mem::MaybeUninit::<WIN32_FILE_ATTRIBUTE_DATA>::uninit();
    let ok = unsafe {
        GetFileAttributesExW(
            wide_null.as_ptr(),
            GET_FILE_EX_INFO_STANDARD,
            data.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    if ok == 0 {
        return None;
    }
    let info = unsafe { data.assume_init() };
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return None;
    }
    let size = ((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64);
    let ft = ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
        | (info.ftLastWriteTime.dwLowDateTime as u64);
    let mtime = ft.checked_sub(WINDOWS_EPOCH_OFFSET).map(|t| t * 100);
    Some((size, mtime))
}

#[inline]
fn fast_size_and_mtime(path: &Path) -> Option<(u64, Option<u64>)> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let v = rnpm_fs::path::to_verbatim_path(path);
        let mut wide = Vec::with_capacity(v.as_os_str().len() + 1);
        wide.extend(v.as_os_str().encode_wide());
        wide.push(0);
        fast_size_and_mtime_wide(&wide)
    }
    #[cfg(not(windows))]
    {
        let meta = fs::metadata(path).ok()?;
        if meta.is_dir() {
            return None;
        }
        Some((meta.len(), mtime_to_timestamp(&meta)))
    }
}

#[inline]
fn is_clean_rel_ascii_path(p: &str) -> bool {
    p.is_ascii()
        && !p.is_empty()
        && !p.starts_with('/')
        && !p.starts_with("./")
        && !p.contains('\\')
        && !p.contains("..")
        && !p.contains("/./")
        && !p.contains("//")
        && !p.ends_with("/.")
        && p != "."
}

#[cfg(windows)]
#[inline]
fn encode_verbatim_prefix_wide(dir: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let v = rnpm_fs::path::to_verbatim_path(dir);
    let mut wide = Vec::with_capacity(v.as_os_str().len() + 2);
    wide.extend(v.as_os_str().encode_wide());
    if wide.last().copied() != Some(b'\\' as u16) {
        wide.push(b'\\' as u16);
    }
    wide
}

#[cfg(windows)]
#[inline]
fn append_ascii_rel_wide(buf: &mut Vec<u16>, prefix: &[u16], rel: &str) {
    buf.clear();
    buf.extend_from_slice(prefix);
    buf.reserve(rel.len() + 1);
    for &b in rel.as_bytes() {
        buf.push(if b == b'/' { b'\\' as u16 } else { b as u16 });
    }
    buf.push(0);
}

#[cfg(windows)]
fn win_create_dir_all_wide(prefix: &[u16], rel_dir: &str, wide_buf: &mut Vec<u16>) -> std::io::Result<()> {
    extern "system" {
        fn CreateDirectoryW(lpPathName: *const u16, lpSecurityAttributes: *mut std::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
    }
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ALREADY_EXISTS: u32 = 183;

    if rel_dir.is_empty() {
        return Ok(());
    }
    append_ascii_rel_wide(wide_buf, prefix, rel_dir);
    let ok = unsafe { CreateDirectoryW(wide_buf.as_ptr(), std::ptr::null_mut()) };
    if ok != 0 {
        return Ok(());
    }
    let err = unsafe { GetLastError() };
    if err == ERROR_ALREADY_EXISTS {
        return Ok(());
    }
    if err != ERROR_PATH_NOT_FOUND {
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }

    // Create ancestor segments from prefix onward without extra string allocations.
    let start_idx = prefix.len();
    let end_idx = wide_buf.len().saturating_sub(1);
    let mut i = start_idx;
    while i < end_idx {
        if wide_buf[i] == b'\\' as u16 && i > start_idx {
            let saved = wide_buf[i];
            wide_buf[i] = 0;
            let r = unsafe { CreateDirectoryW(wide_buf.as_ptr(), std::ptr::null_mut()) };
            wide_buf[i] = saved;
            if r == 0 {
                let e = unsafe { GetLastError() };
                if e != ERROR_ALREADY_EXISTS && e != ERROR_PATH_NOT_FOUND {
                    return Err(std::io::Error::from_raw_os_error(e as i32));
                }
            }
        }
        i += 1;
    }
    let final_ok = unsafe { CreateDirectoryW(wide_buf.as_ptr(), std::ptr::null_mut()) };
    if final_ok != 0 {
        return Ok(());
    }
    let final_err = unsafe { GetLastError() };
    if final_err == ERROR_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(final_err as i32))
    }
}

#[inline]
fn hex2_byte(s: &str) -> Option<u8> {
    let b = s.as_bytes();
    if b.len() < 2 {
        return None;
    }
    let hi = match b[0] {
        b'0'..=b'9' => b[0] - b'0',
        b'a'..=b'f' => b[0] - b'a' + 10,
        b'A'..=b'F' => b[0] - b'A' + 10,
        _ => return None,
    };
    let lo = match b[1] {
        b'0'..=b'9' => b[1] - b'0',
        b'a'..=b'f' => b[1] - b'a' + 10,
        b'A'..=b'F' => b[1] - b'A' + 10,
        _ => return None,
    };
    Some((hi << 4) | lo)
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
    /// Modified time (nanoseconds since UNIX epoch) of the `.pack` blob when verified/written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_mtime: Option<u64>,
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
            pack_mtime: None,
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
            pack_mtime: None,
            files,
            symlinks: Vec::new(),
        }
    }

    /// Serialize index to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
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

fn verify_pack_slice_checksum(
    pack_data: &[u8],
    index: &PackIndex,
    pack_path: &Path,
) -> Result<(), CacheError> {
    if let Some(ref expected) = index.pack_checksum {
        let digest = Sha256::digest(pack_data);
        let mut hex_buf = [0u8; 64];
        let actual = encode_hex_lower(&digest, &mut hex_buf);
        if actual != expected {
            return Err(CacheError::CorruptedPack(format!(
                "Pack content hash mismatch for '{}': expected {}, got {}",
                pack_path.display(),
                expected,
                actual
            )));
        }
    } else if !pack_data.is_empty()
        && !index.files.is_empty()
        && pack_data.iter().all(|&b| b == 0)
    {
        return Err(CacheError::CorruptedPack(format!(
            "Pack file '{}' is zero-filled",
            pack_path.display()
        )));
    }
    Ok(())
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

    /// Extracts independent package files into target_dir.
    pub fn extract_and_populate_cas(&self, target_dir: &Path) -> std::io::Result<()> {
        let pack_data = self.data();
        fs::create_dir_all(target_dir)?;
        let mut created_dirs: std::collections::HashSet<PathBuf> =
            std::collections::HashSet::new();
        created_dirs.insert(target_dir.to_path_buf());

        let mut parents = std::collections::HashSet::new();
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

        let mut sorted_parents: Vec<PathBuf> = parents.into_iter().collect();
        sorted_parents.sort_by_key(|a| std::cmp::Reverse(a.components().count()));

        let t_dirs = std::time::Instant::now();
        for dir in &sorted_parents {
            if created_dirs.contains(dir) {
                continue;
            }
            let _ = fs::create_dir_all(dir);
            let mut curr = dir.as_path();
            while curr != target_dir && created_dirs.insert(curr.to_path_buf()) {
                if let Some(p) = curr.parent() {
                    curr = p;
                } else {
                    break;
                }
            }
        }
        TIME_EXTRACT_DIRS.fetch_add(t_dirs.elapsed().as_nanos() as u64, Ordering::Relaxed);

        for entry in &self.index.files {
            let full_path = target_dir.join(&entry.path);
            let start = entry.offset as usize;
            let end = start + entry.size as usize;
            if end <= pack_data.len() {
                let slice = &pack_data[start..end];
                let t_cw = std::time::Instant::now();
                rnpm_fs::writer::write_file_fast(&full_path, slice, entry.mode, 65536)?;
                TIME_EXTRACT_CAS_WRITE
                    .fetch_add(t_cw.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
        }

        for (link_rel, target_rel) in &self.index.symlinks {
            let link_path = target_dir.join(link_rel);
            let target_path = target_dir.join(target_rel);
            rnpm_fs::create_link_or_copy(&link_path, &target_path)
                .map_err(std::io::Error::other)?;
        }

        Ok(())
    }

    /// Verify the pack's whole-pack content hash (SHA-256) against the checksum stored in `.idx`.
    /// Also detects zero-filled corrupted pack files.
    pub fn verify_checksum(&self) -> Result<(), CacheError> {
        verify_pack_slice_checksum(self.data(), &self.index, &self.pack_path)
    }

    /// Retrieve a direct slice for a specific file path within the memory-mapped pack.
    pub fn get_file_slice(&self, path: &str) -> Option<&[u8]> {
        let entry = self.index.get_file(path)?;
        self.get_entry_slice(entry)
    }

    /// Read an entry already obtained from this pack's index without searching
    /// the index again. Bulk materialization must stay linear in file count.
    pub fn get_entry_slice(&self, entry: &PackFileEntry) -> Option<&[u8]> {
        let start = usize::try_from(entry.offset).ok()?;
        let size = usize::try_from(entry.size).ok()?;
        let end = start.checked_add(size)?;
        self.data().get(start..end)
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

        #[cfg(windows)]
        let verbatim_prefix_wide = encode_verbatim_prefix_wide(target_dir);

        if !dirs_precreated {
            let mut clean_target_dir: Option<PathBuf> = None;
            // Security check: re-validate every entry path and ensure strict containment within target_dir
            for entry in &self.index.files {
                fast_validate_entry_path(&entry.path).map_err(CacheError::Fs)?;
                if entry.path.contains("..") || entry.path.contains('\\') || !entry.path.is_ascii() {
                    let clean_td = clean_target_dir.get_or_insert_with(|| clean(target_dir));
                    let full_path = clean(target_dir.join(&entry.path));
                    if !full_path.starts_with(&*clean_td) {
                        return Err(CacheError::Fs(rnpm_fs::FsError::PathTraversal {
                            path: PathBuf::from(&entry.path),
                        }));
                    }
                }
            }
            for (link_rel, target_rel) in &self.index.symlinks {
                fast_validate_entry_path(link_rel).map_err(CacheError::Fs)?;
                fast_validate_entry_path(target_rel).map_err(CacheError::Fs)?;
                let clean_td = clean_target_dir.get_or_insert_with(|| clean(target_dir));
                let full_link = clean(target_dir.join(link_rel));
                let full_target = clean(target_dir.join(target_rel));
                if !full_link.starts_with(&*clean_td) || !full_target.starts_with(&*clean_td) {
                    return Err(CacheError::Fs(rnpm_fs::FsError::PathTraversal {
                        path: PathBuf::from(link_rel),
                    }));
                }
            }

            // 1. Directories first: deduplicate relative directories before issuing Win32/FS calls.
            std::fs::create_dir_all(target_dir)?;
            let mut created_rel_dirs: HashSet<&str> =
                HashSet::with_capacity(self.index.files.len() / 2 + 4);
            #[cfg(windows)]
            let mut dir_wide_buf: Vec<u16> = Vec::with_capacity(260);

            for entry in &self.index.files {
                if !is_clean_rel_ascii_path(&entry.path) {
                    let full_path = target_dir.join(&entry.path);
                    if let Some(parent) = full_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    continue;
                }
                if let Some(slash) = entry.path.rfind('/') {
                    let rel_dir = &entry.path[..slash];
                    if !rel_dir.is_empty() && !created_rel_dirs.contains(rel_dir) {
                        #[cfg(windows)]
                        win_create_dir_all_wide(&verbatim_prefix_wide, rel_dir, &mut dir_wide_buf)?;
                        #[cfg(not(windows))]
                        std::fs::create_dir_all(target_dir.join(rel_dir))?;
                        let mut cur = rel_dir;
                        while !cur.is_empty() && created_rel_dirs.insert(cur) {
                            match cur.rfind('/') {
                                Some(p) => cur = &cur[..p],
                                None => break,
                            }
                        }
                    }
                }
            }
            for (link_rel, _) in &self.index.symlinks {
                let full_path = target_dir.join(link_rel);
                if let Some(parent) = full_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
            }
        }

        let default_cfg = ParallelWriterConfig::default();
        let cfg = writer_config.unwrap_or(&default_cfg);
        let prealloc_thresh = cfg.preallocate_threshold;

        let mut total_uncompressed_bytes = 0u64;
        for entry in &self.index.files {
            total_uncompressed_bytes += entry.size;
            let start = entry.offset as usize;
            let end = start.checked_add(entry.size as usize);
            if end.is_none_or(|e| e > pack_data.len()) {
                return Err(CacheError::InvalidPack(format!(
                    "Pack entry '{}' exceeds pack size (offset {} + size {} > total {})",
                    entry.path,
                    entry.offset,
                    entry.size,
                    pack_data.len()
                )));
            }
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

        // 2. Direct materialization straight from memory mapping (or ReFS block cloning).
        let files = &self.index.files;
        if !can_block_clone && files.len() >= 8 {
            let num_threads = 24.min(files.len() / 2).max(2).min(files.len());
            let next_idx = AtomicUsize::new(0);
            let has_err = AtomicBool::new(false);
            let first_err: Mutex<Option<CacheError>> = Mutex::new(None);
            #[cfg(windows)]
            let prefix_ref = &verbatim_prefix_wide;
            rnpm_fs::run_parallel(num_threads, &|| {
                #[cfg(windows)]
                let mut wide_buf: Vec<u16> = Vec::with_capacity(260);
                let mut local_files = 0u64;
                let mut local_bytes = 0u64;
                loop {
                    if has_err.load(Ordering::Relaxed) {
                        break;
                    }
                    let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                    if idx >= files.len() {
                        break;
                    }
                    let entry = &files[idx];
                    let start = entry.offset as usize;
                    let end = start + entry.size as usize;
                    let slice = &pack_data[start..end];

                    if entry.cas_verified {
                        if let Some(ref cas_path) = entry.cas_path {
                            let is_corrupted_or_missing = fast_size_and_mtime(cas_path)
                                .map(|(sz, mt)| {
                                    sz != entry.size
                                        || (entry.cas_mtime.is_some() && mt != entry.cas_mtime)
                                })
                                .unwrap_or(true);
                            if is_corrupted_or_missing {
                                let _ = PackStore::write_cas_file_safe(cas_path, slice);
                            }
                        }
                    }

                    let write_res: std::io::Result<bool> = {
                        #[cfg(windows)]
                        {
                            if is_clean_rel_ascii_path(&entry.path) {
                                append_ascii_rel_wide(&mut wide_buf, prefix_ref, &entry.path);
                                match rnpm_fs::writer::write_file_fast_wide_raw(
                                    &wide_buf,
                                    target_dir,
                                    slice,
                                    entry.mode,
                                    prealloc_thresh,
                                    false,
                                ) {
                                    Ok(()) => Ok(true),
                                    Err(_) => clone_or_write_pack_file(
                                        None,
                                        &target_dir.join(&entry.path),
                                        slice,
                                        entry.offset,
                                        entry.size,
                                        entry.mode,
                                        prealloc_thresh,
                                    )
                                    .map(|_| false),
                                }
                            } else {
                                clone_or_write_pack_file(
                                    None,
                                    &target_dir.join(&entry.path),
                                    slice,
                                    entry.offset,
                                    entry.size,
                                    entry.mode,
                                    prealloc_thresh,
                                )
                                .map(|_| false)
                            }
                        }
                        #[cfg(not(windows))]
                        {
                            clone_or_write_pack_file(
                                None,
                                &target_dir.join(&entry.path),
                                slice,
                                entry.offset,
                                entry.size,
                                entry.mode,
                                prealloc_thresh,
                            )
                            .map(|_| false)
                        }
                    };
                    match write_res {
                        Err(e) => {
                            if local_files > 0 {
                                rnpm_fs::record_files_created_batch(local_files, local_bytes);
                            }
                            has_err.store(true, Ordering::Relaxed);
                            let mut guard = first_err.lock().unwrap();
                            if guard.is_none() {
                                *guard = Some(CacheError::Io(e));
                            }
                            return;
                        }
                        Ok(true) => {
                            local_files += 1;
                            local_bytes += slice.len() as u64;
                        }
                        Ok(false) => {}
                    }
                }
                if local_files > 0 {
                    rnpm_fs::record_files_created_batch(local_files, local_bytes);
                }
            });
            if let Some(err) = first_err.into_inner().unwrap() {
                return Err(err);
            }
        } else {
            #[cfg(windows)]
            let mut wide_buf: Vec<u16> = if !can_block_clone {
                Vec::with_capacity(260)
            } else {
                Vec::new()
            };
            for entry in files {
                let start = entry.offset as usize;
                let end = start + entry.size as usize;
                let slice = &pack_data[start..end];

                #[cfg(windows)]
                let src_h = raw_pack_handle.map(|h| h as RawFileHandle);
                #[cfg(not(windows))]
                let src_h = None;

                if entry.cas_verified {
                    if let Some(ref cas_path) = entry.cas_path {
                        let is_corrupted_or_missing = fast_size_and_mtime(cas_path)
                            .map(|(sz, mt)| {
                                sz != entry.size
                                    || (entry.cas_mtime.is_some() && mt != entry.cas_mtime)
                            })
                            .unwrap_or(true);
                        if is_corrupted_or_missing {
                            let _ = PackStore::write_cas_file_safe(cas_path, slice);
                        }
                    }
                }

                #[cfg(windows)]
                if !can_block_clone && is_clean_rel_ascii_path(&entry.path) {
                    append_ascii_rel_wide(&mut wide_buf, &verbatim_prefix_wide, &entry.path);
                    if rnpm_fs::writer::write_file_fast_wide_raw(
                        &wide_buf,
                        target_dir,
                        slice,
                        entry.mode,
                        prealloc_thresh,
                        true,
                    )
                    .is_ok()
                    {
                        continue;
                    }
                }

                let full_path = target_dir.join(&entry.path);
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
            rnpm_fs::create_link_or_copy(&link_path, &target_path).map_err(CacheError::Fs)?;
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
    mmap_cache: Arc<RwLock<HashMap<String, PackagePack>>>,
    block_clone_cache: Arc<RwLock<HashMap<PathBuf, bool>>>,
    #[cfg(windows)]
    block_clone_drive_cache: Arc<[AtomicU8; 26]>,
    cas_stamp_cache: Arc<RwLock<HashMap<PathBuf, (u64, u64)>>>,
    has_cas_files: Arc<AtomicBool>,
    created_prefixes: Arc<RwLock<std::collections::HashSet<String>>>,
    cas_prefix_dirs: Arc<[AtomicU64; 4]>,
}

impl PackStore {
    /// Initialize a PackStore rooted at `root` directory.
    /// Uses lazy on-demand creation for pack and CAS prefix directories instead of eager 256-dir loops.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        let packs_dir = root.join("packs");
        fs::create_dir_all(&packs_dir)?;
        fs::create_dir_all(root.join("tmp"))?;
        let cas_dir = root.join("cas");
        fs::create_dir_all(&cas_dir)?;

        let has_cas = if let Ok(mut it) = fs::read_dir(&cas_dir) {
            it.next().is_some()
        } else {
            false
        };

        Ok(Self {
            root,
            mmap_cache: Arc::new(RwLock::new(HashMap::new())),
            block_clone_cache: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(windows)]
            block_clone_drive_cache: Arc::new([const { AtomicU8::new(0) }; 26]),
            cas_stamp_cache: Arc::new(RwLock::new(HashMap::new())),
            has_cas_files: Arc::new(AtomicBool::new(has_cas)),
            created_prefixes: Arc::new(RwLock::new(std::collections::HashSet::new())),
            cas_prefix_dirs: Arc::new([const { AtomicU64::new(0) }; 4]),
        })
    }

    /// Ensures that the prefix directory under `packs/<prefix>` exists, using memoized in-memory check.
    pub fn ensure_pack_prefix_dir(&self, prefix: &str) -> std::io::Result<PathBuf> {
        let prefix_dir = self.packs_dir().join(prefix);
        {
            if let Ok(guard) = self.created_prefixes.read() {
                if guard.contains(prefix) {
                    return Ok(prefix_dir);
                }
            }
        }
        let mut guard = self.created_prefixes.write().unwrap();
        if !guard.contains(prefix) {
            fs::create_dir_all(&prefix_dir)?;
            guard.insert(prefix.to_string());
        }
        Ok(prefix_dir)
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

    /// Remove reusable package content without following linked dependencies
    /// outside the store or deleting unrelated files in a custom directory.
    pub fn clean_at(root: &Path) -> Result<(), CacheError> {
        for name in ["packs", "cas", "tmp", "linked"] {
            rnpm_fs::remove_dir_all_safe(&root.join(name))?;
        }
        match fs::remove_dir(root) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
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
        Self::write_cas_file_with_mtime(cas_path, data, false).map(|_| ())
    }

    fn write_cas_file_with_mtime(
        cas_path: &Path,
        data: &[u8],
        parent_created: bool,
    ) -> std::io::Result<Option<u64>> {
        Self::write_cas_file_with_mtime_opt(cas_path, data, parent_created, true)
    }

    fn write_cas_file_with_mtime_opt(
        cas_path: &Path,
        data: &[u8],
        parent_created: bool,
        cas_may_exist: bool,
    ) -> std::io::Result<Option<u64>> {
        #[cfg(windows)]
        {
            let mut wide_cas = Vec::with_capacity(260);
            crate::storage::encode_verbatim_wide_into(cas_path, &mut wide_cas);
            if cas_may_exist {
                if let Some((sz, mt)) = fast_size_and_mtime_wide(&wide_cas) {
                    if sz == data.len() as u64 && fs::read(cas_path).is_ok_and(|e| e == data) {
                        return Ok(mt);
                    }
                }
            }

            if !parent_created {
                if let Some(parent) = cas_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            let count = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let mut wide_tmp = Vec::with_capacity(wide_cas.len() + 32);
            wide_tmp.extend_from_slice(&wide_cas[..wide_cas.len().saturating_sub(1)]);
            let suffix = format!(".tmp_{pid}_{count}");
            wide_tmp.extend(suffix.encode_utf16());
            wide_tmp.push(0);

            if crate::storage::write_and_rename_atomic_wide(
                &wide_tmp,
                &wide_cas,
                cas_path,
                cas_path,
                data,
            )
            .is_ok()
            {
                return Ok(fast_size_and_mtime_wide(&wide_cas).and_then(|(_, mt)| mt));
            }
            if let Some((sz, mt)) = fast_size_and_mtime_wide(&wide_cas) {
                if sz == data.len() as u64 && fs::read(cas_path).is_ok_and(|e| e == data) {
                    return Ok(mt);
                }
            }
            let tmp_path = cas_path.with_extension(format!("tmp_{pid}_{count}"));
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            if let Err(e) = f.write_all(data) {
                drop(f);
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
            drop(f);
            if let Err(e) = fs::rename(&tmp_path, cas_path) {
                if let Ok(meta) = fs::symlink_metadata(cas_path) {
                    let mut perms = meta.permissions();
                    if perms.readonly() {
                        perms.set_readonly(false);
                        let _ = fs::set_permissions(cas_path, perms);
                    }
                }
                let _ = fs::remove_file(cas_path);
                if let Err(e2) = fs::rename(&tmp_path, cas_path) {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(if e2.kind() != std::io::ErrorKind::NotFound {
                        e2
                    } else {
                        e
                    });
                }
            }
            Ok(fast_size_and_mtime_wide(&wide_cas).and_then(|(_, mt)| mt))
        }

        #[cfg(not(windows))]
        {
            if cas_may_exist {
                if let Some((sz, mt)) = fast_size_and_mtime(cas_path) {
                    if sz == data.len() as u64 {
                        if let Ok(existing) = fs::read(cas_path) {
                            if existing == data {
                                return Ok(mt);
                            }
                        }
                    }
                }
            }
            if !parent_created {
                if let Some(parent) = cas_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            let count = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let tmp_path = cas_path.with_extension(format!("tmp_{pid}_{count}"));
            crate::storage::write_and_rename_atomic(&tmp_path, cas_path, data)?;
            Ok(fast_size_and_mtime(cas_path).and_then(|(_, mt)| mt))
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
                    let expected_len = match src.metadata() {
                        Ok(m) => m.len(),
                        Err(_) => continue,
                    };
                    let dst_valid = dst
                        .metadata()
                        .ok()
                        .map(|d_meta| d_meta.len() == expected_len)
                        .unwrap_or(false);
                    if !dst_valid {
                        let count = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
                        let pid = std::process::id();
                        let tmp_path = dst.with_extension(format!("tmp_{pid}_{count}"));
                        if rnpm_fs::copy_file_fast(src, &tmp_path).is_ok() {
                            if rename_atomic_cas(&tmp_path, dst, expected_len).is_err() {
                                let _ = fs::remove_file(&tmp_path);
                            }
                        } else {
                            let _ = fs::remove_file(&tmp_path);
                        }
                    }
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
        let (prefix, safe_stem, sha512_hex, canon) = Self::integrity_key_parts_with_canon(integrity);

        // 1. Remove from in-memory cache
        {
            let mut guard = self.mmap_cache.write().unwrap();
            guard.remove(integrity);
            guard.remove(integrity.trim());
            guard.remove(&safe_stem);
            guard.remove(&sha512_hex);
            if let Some(ref canon_key) = canon {
                guard.remove(canon_key);
            }
        }

        // 2. Remove files on disk (clearing readonly on Windows if set)
        let prefix_dir = self.packs_dir().join(&prefix);
        let pack_path = prefix_dir.join(format!("{safe_stem}.pack"));
        let idx_path = prefix_dir.join(format!("{safe_stem}.idx"));
        remove_file_clearing_readonly(&pack_path);
        remove_file_clearing_readonly(&idx_path);

        if safe_stem != sha512_hex {
            let alt_pack = prefix_dir.join(format!("{sha512_hex}.pack"));
            let alt_idx = prefix_dir.join(format!("{sha512_hex}.idx"));
            remove_file_clearing_readonly(&alt_pack);
            remove_file_clearing_readonly(&alt_idx);
        }

        Ok(())
    }

    /// Checks if a complete package pack (.pack and .idx) exists in the store.
    pub fn has_package_pack(&self, integrity: &str) -> bool {
        // Fast path: check raw key before parsing integrity
        {
            let guard = self.mmap_cache.read().unwrap();
            if guard.contains_key(integrity) {
                return true;
            }
        }

        let (prefix, safe_stem, sha512_hex, canon) =
            Self::integrity_key_parts_with_canon(integrity);

        {
            let guard = self.mmap_cache.read().unwrap();
            if guard.contains_key(&safe_stem)
                || guard.contains_key(&sha512_hex)
                || canon.as_deref().is_some_and(|c| guard.contains_key(c))
            {
                return true;
            }
        }

        let prefix_dir = self.packs_dir().join(&prefix);
        let pack_path = prefix_dir.join(format!("{safe_stem}.pack"));
        if let Ok(meta) = pack_path.metadata() {
            if meta.is_file() && meta.len() > 0 {
                let idx_path = prefix_dir.join(format!("{safe_stem}.idx"));
                if idx_path.metadata().is_ok_and(|m| m.is_file()) {
                    return true;
                }
            }
        }

        if safe_stem != sha512_hex {
            let alt_pack = prefix_dir.join(format!("{sha512_hex}.pack"));
            if let Ok(meta) = alt_pack.metadata() {
                if meta.is_file() && meta.len() > 0 {
                    let alt_idx = prefix_dir.join(format!("{sha512_hex}.idx"));
                    if alt_idx.metadata().is_ok_and(|m| m.is_file()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Retrieve and memory-map a package pack by integrity.
    ///
    /// Caches open memory maps across process lifetime for fast reuse.
    pub fn get_package_pack(&self, integrity: &str) -> Result<Option<PackagePack>, CacheError> {
        // 1. Check in-memory cache by exact string before parsing integrity
        {
            let guard = self.mmap_cache.read().unwrap();
            if let Some(pack) = guard.get(integrity) {
                return Ok(Some(pack.clone()));
            }
        }

        let (prefix, safe_stem, sha512_hex, canon) =
            Self::integrity_key_parts_with_canon(integrity);

        {
            let guard = self.mmap_cache.read().unwrap();
            if let Some(pack) = guard
                .get(&safe_stem)
                .or_else(|| guard.get(&sha512_hex))
                .or_else(|| canon.as_deref().and_then(|c| guard.get(c)))
            {
                return Ok(Some(pack.clone()));
            }
        }

        // 2. Locate on disk and read index: read directly to avoid redundant stat syscalls
        let prefix_dir = self.packs_dir().join(&prefix);
        let mut pack_path = prefix_dir.join(format!("{safe_stem}.pack"));
        let mut idx_path = prefix_dir.join(format!("{safe_stem}.idx"));
        let idx_bytes = match fs::read(&idx_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if safe_stem == sha512_hex {
                    return Ok(None);
                }
                let alt_pack = prefix_dir.join(format!("{sha512_hex}.pack"));
                let alt_idx = prefix_dir.join(format!("{sha512_hex}.idx"));
                match fs::read(&alt_idx) {
                    Ok(b) => {
                        pack_path = alt_pack;
                        idx_path = alt_idx;
                        b
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(CacheError::Io(e)),
                }
            }
            Err(e) => return Err(CacheError::Io(e)),
        };
        let mut index: PackIndex = match PackIndex::from_bytes(&idx_bytes) {
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

        let expected_padded = if index.total_pack_size > 0 {
            (index.total_pack_size + (PACK_ALIGNMENT as u64 - 1)) & !(PACK_ALIGNMENT as u64 - 1)
        } else {
            0
        };
        let max_pack_bound = expected_padded.max(index.total_pack_size);

        // Re-validate every entry path in index before loading/materializing to prevent tampering
        for entry in &index.files {
            if let Err(e) = fast_validate_entry_path(&entry.path) {
                warn!(
                    "Malicious or invalid entry path '{}' in index at '{}': {e}. Purging.",
                    entry.path,
                    idx_path.display()
                );
                let _ = self.purge(integrity);
                return Ok(None);
            }
            if entry.offset.saturating_add(entry.size) > max_pack_bound {
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
            if let Err(e) = fast_validate_entry_path(link_rel) {
                warn!(
                    "Malicious symlink link_rel '{}' in index at '{}': {e}. Purging.",
                    link_rel,
                    idx_path.display()
                );
                let _ = self.purge(integrity);
                return Ok(None);
            }
            if let Err(e) = fast_validate_entry_path(target_rel) {
                warn!(
                    "Malicious symlink target_rel '{}' in index at '{}': {e}. Purging.",
                    target_rel,
                    idx_path.display()
                );
                let _ = self.purge(integrity);
                return Ok(None);
            }
        }

        // 4. Open pack once; read small packs directly into memory and mmap larger packs
        let mut file = match OpenOptions::new().read(true).open(&pack_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(CacheError::Io(e)),
        };
        let meta = file.metadata()?;
        let pack_len = meta.len();

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

        const DIRECT_READ_THRESHOLD: u64 = 128 * 1024;
        let buffer = if pack_len == 0 {
            Arc::new(PackBuffer::Empty)
        } else if pack_len <= DIRECT_READ_THRESHOLD {
            let mut bytes = Vec::with_capacity(pack_len as usize);
            file.read_to_end(&mut bytes)?;
            Arc::new(PackBuffer::Bytes(Arc::new(bytes)))
        } else {
            match unsafe { memmap2::Mmap::map(&file) } {
                Ok(mmap) => Arc::new(PackBuffer::Mmap(Arc::new(mmap))),
                Err(_) => {
                    let mut bytes = Vec::with_capacity(pack_len as usize);
                    file.read_to_end(&mut bytes)?;
                    Arc::new(PackBuffer::Bytes(Arc::new(bytes)))
                }
            }
        };

        let mut index_updated = false;

        // Fast pack verification: if pack_mtime matches current disk mtime, skip full SHA256 digest.
        let current_pack_mtime = mtime_to_timestamp(&meta);
        let pack_verified = index.pack_mtime.is_some()
            && current_pack_mtime.is_some()
            && index.pack_mtime == current_pack_mtime;

        if !pack_verified {
            if let Err(e) = verify_pack_slice_checksum(buffer.data(), &index, &pack_path) {
                let _ = self.purge(integrity);
                return Err(e);
            }
            if let Some(m) = current_pack_mtime {
                index.pack_mtime = Some(m);
                index_updated = true;
            }
        }

        let buf_data = buffer.data();
        let has_cas = self.has_cas_files.load(Ordering::Relaxed);
        let cas_dir = if has_cas { Some(self.cas_dir()) } else { None };

        // Ensure valid SHA-256 digests and derived CAS paths first.
        for entry in &mut index.files {
            let valid_sha = entry.sha256.as_deref().is_some_and(|s| {
                s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
            });
            if !valid_sha {
                let start = entry.offset as usize;
                let end = start + entry.size as usize;
                if end <= buf_data.len() {
                    entry.sha256 = Some(sha256_hex_string(&buf_data[start..end]));
                    index_updated = true;
                } else {
                    continue;
                }
            }

            let Some(ref sha) = entry.sha256 else {
                continue;
            };
            // Always derive CAS path from this store's cas_dir + validated SHA-256;
            // never trust arbitrary deserialized paths from `.idx`.
            let cas_file = match cas_dir.as_ref() {
                Some(d) => d.join(&sha[0..2]).join(sha),
                None => self.cas_file_path(sha),
            };
            if entry.cas_path.as_ref() != Some(&cas_file) && (entry.cas_path.is_some() || has_cas) {
                entry.cas_path = Some(cas_file);
            }

            if !has_cas {
                entry.cas_verified = false;
            }
        }

        if has_cas {
            let verify_cas_entry =
                |entry: &mut PackFileEntry, cas_wide_buf: &mut Vec<u16>| -> bool {
                    let Some(ref sha) = entry.sha256 else {
                        return false;
                    };
                    let cas_file = match entry.cas_path.as_ref() {
                        Some(p) => p,
                        None => return false,
                    };

                    let start = entry.offset as usize;
                    let end = start.saturating_add(entry.size as usize);
                    let slice = if end <= buf_data.len() {
                        Some(&buf_data[start..end])
                    } else {
                        None
                    };

                    #[cfg(windows)]
                    let stat_opt = {
                        crate::storage::encode_verbatim_wide_into(cas_file, cas_wide_buf);
                        fast_size_and_mtime_wide(cas_wide_buf)
                    };
                    #[cfg(not(windows))]
                    let stat_opt = {
                        let _ = cas_wide_buf;
                        fast_size_and_mtime(cas_file)
                    };

                    if let Some((current_size, current_mtime)) = stat_opt {
                        let recorded_mtime = entry
                            .cas_mtime
                            .or_else(|| self.get_cas_stamp(cas_file).map(|(_s, m)| m));
                        let stamp_match = current_size == entry.size
                            && recorded_mtime.is_some()
                            && current_mtime == recorded_mtime;

                        if stamp_match {
                            entry.cas_verified = true;
                            false
                        } else {
                            let hash_valid = if current_size == entry.size {
                                if let Ok(bytes) = fs::read(cas_file) {
                                    let digest = Sha256::digest(&bytes);
                                    let mut hex_buf = [0u8; 64];
                                    encode_hex_lower(&digest, &mut hex_buf).eq_ignore_ascii_case(sha)
                                } else {
                                    false
                                }
                            } else {
                                false
                            };

                            if hash_valid {
                                entry.cas_mtime = current_mtime;
                                entry.cas_verified = true;
                                if let Some(m) = current_mtime {
                                    self.set_cas_stamp(cas_file, current_size, m);
                                }
                                true
                            } else if let Some(slice) = slice {
                                match Self::write_cas_file_with_mtime(cas_file, slice, false) {
                                    Ok(new_mt) => {
                                        if let Some(m) = new_mt {
                                            entry.cas_mtime = Some(m);
                                            self.set_cas_stamp(cas_file, slice.len() as u64, m);
                                        }
                                        entry.cas_verified = true;
                                        true
                                    }
                                    Err(_) => {
                                        entry.cas_verified = false;
                                        false
                                    }
                                }
                            } else {
                                entry.cas_verified = false;
                                false
                            }
                        }
                    } else {
                        entry.cas_verified = false;
                        false
                    }
                };

            if index.files.len() >= 12 {
                struct EntrySlot(std::cell::UnsafeCell<PackFileEntry>);
                // SAFETY: Each slot index is claimed once by `next_idx.fetch_add(1)` and joined before unwrapping.
                unsafe impl Sync for EntrySlot {}

                let slots: Vec<EntrySlot> = std::mem::take(&mut index.files)
                    .into_iter()
                    .map(|e| EntrySlot(std::cell::UnsafeCell::new(e)))
                    .collect();
                let next_idx = AtomicUsize::new(0);
                let par_updated = AtomicBool::new(false);
                let workers = 12.min(slots.len());
                rnpm_fs::run_parallel(workers, &|| {
                    let mut local_updated = false;
                    let mut cas_wide_buf = Vec::with_capacity(260);
                    loop {
                        let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                        if idx >= slots.len() {
                            break;
                        }
                        // SAFETY: `fetch_add` assigns each `idx < slots.len()` to at most one worker.
                        let entry = unsafe { &mut *slots[idx].0.get() };
                        if verify_cas_entry(entry, &mut cas_wide_buf) {
                            local_updated = true;
                        }
                    }
                    if local_updated {
                        par_updated.store(true, Ordering::Relaxed);
                    }
                });
                if par_updated.load(Ordering::Relaxed) {
                    index_updated = true;
                }
                index.files = slots.into_iter().map(|s| s.0.into_inner()).collect();
            } else {
                let mut cas_wide_buf = Vec::with_capacity(260);
                for entry in &mut index.files {
                    if verify_cas_entry(entry, &mut cas_wide_buf) {
                        index_updated = true;
                    }
                }
            }
        }

        if index_updated {
            let pid = std::process::id();
            let count = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tmp_idx = self.tmp_dir().join(format!("idx_upd_{pid}_{count}.tmp"));
            if let Ok(updated_idx_bytes) = index.to_bytes() {
                if fs::write(&tmp_idx, &updated_idx_bytes).is_ok() {
                    let _ = rename_atomic(&tmp_idx, &idx_path);
                }
            }
        }

        let pack = PackagePack {
            index,
            buffer,
            pack_path,
            idx_path,
        };

        // 5. Store in cache across process lifetime
        {
            let mut guard = self.mmap_cache.write().unwrap();
            guard.insert(integrity.to_string(), pack.clone());
            guard.insert(safe_stem, pack.clone());
            guard.insert(sha512_hex, pack.clone());
            if let Some(canon_key) = canon {
                guard.insert(canon_key, pack.clone());
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

    /// Persist both regular payloads and validated link metadata from one decode.
    pub fn put_decoded_package(
        &self,
        integrity: &str,
        pkg_target: &Path,
        decoded: &DecodedPackage,
        populate_cas: bool,
    ) -> Result<PackIndex, CacheError> {
        let base = rnpm_fs::to_verbatim_path(pkg_target);
        let mut input_files = Vec::with_capacity(decoded.files.len());
        for file in &decoded.files {
            let relative = file.path.strip_prefix(&base).map_err(|_| {
                CacheError::InvalidPack(format!("File escapes package: {}", file.path.display()))
            })?;
            input_files.push(PackInputFile {
                path: relative.to_string_lossy().replace('\\', "/"),
                mode: file.mode,
                data: file.data.as_slice(),
            });
        }
        let mut links = Vec::with_capacity(decoded.symlinks.len());
        for (link, target) in &decoded.symlinks {
            let relative_link = link
                .strip_prefix(&base)
                .map_err(|_| CacheError::InvalidPack("Link escapes package".into()))?;
            let relative_target = target
                .strip_prefix(&base)
                .map_err(|_| CacheError::InvalidPack("Link target escapes package".into()))?;
            rnpm_fs::validate_entry_path(relative_link).map_err(CacheError::Fs)?;
            rnpm_fs::validate_entry_path(relative_target).map_err(CacheError::Fs)?;
            links.push((
                relative_link.to_string_lossy().replace('\\', "/"),
                relative_target.to_string_lossy().replace('\\', "/"),
            ));
        }
        self.put_package_pack_with_cas_inner(integrity, &input_files, populate_cas, true, &links)
            .map(|(pack, _)| pack.index)
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

        self.put_package_pack_with_cas_inner(integrity, &input_files, populate_cas, false, &[])
            .map(|(p, payloads)| (p.index, payloads))
    }

    fn put_package_pack_with_cas(
        &self,
        integrity: &str,
        files: &[PackInputFile<'_>],
        populate_cas: bool,
    ) -> Result<PackagePack, CacheError> {
        self.put_package_pack_with_cas_inner(integrity, files, populate_cas, true, &[])
            .map(|(p, _)| p)
    }

    fn put_package_pack_with_cas_inner(
        &self,
        integrity: &str,
        files: &[PackInputFile<'_>],
        populate_cas: bool,
        write_files: bool,
        links: &[(String, String)],
    ) -> Result<(PackagePack, DeferredPackPayloads), CacheError> {
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
        let mut seen_lower: HashMap<String, usize> = HashMap::with_capacity(files.len());
        let mut deduped_files: Vec<(String, u32, &[u8])> = Vec::with_capacity(files.len());
        let mut total_size: usize = 0;

        for file in files {
            fast_validate_entry_path(&file.path).map_err(CacheError::Fs)?;

            let norm_path: String = if file.path.contains('\\')
                || file.path.starts_with("./")
                || file.path.starts_with('/')
            {
                let clean_path = file.path.replace('\\', "/");
                clean_path
                    .trim_start_matches("./")
                    .trim_start_matches('/')
                    .to_string()
            } else {
                file.path.clone()
            };
            if norm_path.is_empty() {
                return Err(CacheError::InvalidPack(
                    "Pack entry path cannot be empty".to_string(),
                ));
            }
            if norm_path != file.path {
                fast_validate_entry_path(&norm_path).map_err(CacheError::Fs)?;
            }

            let needs_lower = norm_path.bytes().any(|b| b.is_ascii_uppercase() || !b.is_ascii());
            let prev_idx = if needs_lower {
                let lk = norm_path.to_lowercase();
                if let Some(&idx) = seen_lower.get(&lk) {
                    Some((idx, Some(lk)))
                } else {
                    None
                }
            } else if let Some(&idx) = seen_lower.get(norm_path.as_str()) {
                Some((idx, None))
            } else {
                None
            };

            if let Some((idx, _)) = prev_idx {
                deduped_files[idx] = (norm_path, file.mode, file.data);
            } else {
                total_size += file.data.len() + PACK_ALIGNMENT;
                let owned_key = if needs_lower {
                    norm_path.to_lowercase()
                } else {
                    norm_path.clone()
                };
                let idx = deduped_files.len();
                deduped_files.push((norm_path, file.mode, file.data));
                seen_lower.insert(owned_key, idx);
            }
        }

        // 1. Pack construction with 4 KiB alignment
        let mut pack_bytes = Vec::with_capacity(total_size);
        let mut index_files = Vec::with_capacity(deduped_files.len());
        let cas_dir = populate_cas.then(|| self.cas_dir());

        for (path, mode, data) in deduped_files {
            if data.len() as u64 > limits.max_single_entry_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "entry size".to_string(),
                    detail: format!("File payload '{}' exceeds single file limit", path),
                }));
            }

            let curr_offset = pack_bytes.len();
            let rem = curr_offset & (PACK_ALIGNMENT - 1);
            let aligned_offset = if rem == 0 {
                curr_offset
            } else {
                let padded = curr_offset + (PACK_ALIGNMENT - rem);
                pack_bytes.resize(padded, 0u8);
                padded
            };

            pack_bytes.extend_from_slice(data);
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

            let sha = sha256_hex_string(data);
            let cas_path = cas_dir.as_ref().map(|d| {
                let p = if sha.len() >= 2 { &sha[0..2] } else { "00" };
                d.join(p).join(&sha)
            });
            index_files.push(PackFileEntry {
                path,
                mode,
                size: data.len() as u64,
                offset: aligned_offset as u64,
                aligned_offset: aligned_offset as u64,
                sha256: Some(sha),
                cas_path,
                cas_verified: false,
                cas_mtime: None,
            });
        }

        self.finalize_pack_and_write(
            integrity,
            pack_bytes,
            index_files,
            links.to_vec(),
            populate_cas,
            write_files,
        )
    }

    fn finalize_pack_and_write(
        &self,
        integrity: &str,
        mut pack_bytes: Vec<u8>,
        mut index_files: Vec<PackFileEntry>,
        links: Vec<(String, String)>,
        populate_cas: bool,
        write_files: bool,
    ) -> Result<(PackagePack, DeferredPackPayloads), CacheError> {
        let (prefix, safe_stem, sha512_hex, canon) =
            Self::integrity_key_parts_with_canon(integrity);

        // Pad the end of the .pack file with zeroes up to a 4096-byte cluster boundary
        // ((total_pack_size + 4095) & !4095). This ensures that FSCTL_DUPLICATE_EXTENTS_TO_FILE
        // for the last file in the pack does not extend past the end of the source .pack file.
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

        let pack_checksum = sha256_hex_string(&pack_bytes);

        let mut index = PackIndex::with_checksum(
            integrity.to_string(),
            sha512_hex.clone(),
            pack_bytes.len() as u64,
            pack_checksum,
            index_files,
        );
        index.symlinks = links;

        let prefix_dir = self.ensure_pack_prefix_dir(&prefix).map_err(|e| {
            CacheError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to create pack prefix directory '{}': {e}",
                    self.packs_dir().join(&prefix).display()
                ),
            ))
        })?;

        let final_pack = prefix_dir.join(format!("{safe_stem}.pack"));
        let final_idx = prefix_dir.join(format!("{safe_stem}.idx"));

        let idx_bytes = if write_files {
            let tmp_dir = self.tmp_dir();
            let count = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let tmp_pack = tmp_dir.join(format!("pack_{pid}_{count}.tmp"));
            let tmp_idx = tmp_dir.join(format!("idx_{pid}_{count}.tmp"));

            crate::storage::write_and_rename_atomic(&tmp_pack, &final_pack, &pack_bytes)?;
            // Windows can move the write time when the handle closes, so read it from
            // the final closed file so subsequent loads match `meta` mtime cleanly.
            index.pack_mtime = fast_size_and_mtime(&final_pack).and_then(|(_, mt)| mt);
            let serialized = index.to_bytes().map_err(CacheError::Json)?;
            crate::storage::write_and_rename_atomic(&tmp_idx, &final_idx, &serialized)?;
            serialized
        } else {
            index.to_bytes().map_err(CacheError::Json)?
        };

        let pack_bytes_arc = Arc::new(pack_bytes);
        let idx_bytes_arc = Arc::new(idx_bytes);

        // 4. Update memory-map cache
        let buffer = if pack_bytes_arc.is_empty() {
            Arc::new(PackBuffer::Empty)
        } else {
            Arc::new(PackBuffer::Bytes(Arc::clone(&pack_bytes_arc)))
        };

        let pack = PackagePack {
            index,
            buffer,
            pack_path: final_pack.clone(),
            idx_path: final_idx.clone(),
        };

        {
            let mut guard = self.mmap_cache.write().unwrap();
            guard.insert(integrity.to_string(), pack.clone());
            guard.insert(safe_stem, pack.clone());
            guard.insert(sha512_hex, pack.clone());
            if let Some(canon_key) = canon {
                guard.insert(canon_key, pack.clone());
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
        if entries.is_empty() {
            return;
        }
        let mut prefix_dirs: Vec<(Option<u8>, PathBuf)> = Vec::new();
        let mut seen_prefix_mask = [0u64; 4];
        let mut unique_jobs: Vec<(PathBuf, &[u8])> = Vec::with_capacity(entries.len());
        let mut seen_cas: HashMap<&Path, usize> = HashMap::with_capacity(entries.len());
        let mut entry_job_idx: Vec<Option<usize>> = Vec::with_capacity(entries.len());

        for entry in entries.iter() {
            let start = entry.offset as usize;
            let end = start.saturating_add(entry.size as usize);
            if end <= pack_bytes.len() {
                if let Some(ref cas_path) = entry.cas_path {
                    if let Some(&idx) = seen_cas.get(cas_path.as_path()) {
                        entry_job_idx.push(Some(idx));
                    } else {
                        if let Some(parent) = cas_path.parent() {
                            let prefix_byte = entry.sha256.as_deref().and_then(hex2_byte);
                            let need_dir = match prefix_byte {
                                Some(b) => {
                                    let w = (b >> 6) as usize;
                                    let m = 1u64 << (b & 63);
                                    let already_global =
                                        (self.cas_prefix_dirs[w].load(Ordering::Relaxed) & m) != 0;
                                    let already_local = (seen_prefix_mask[w] & m) != 0;
                                    if !already_global && !already_local {
                                        seen_prefix_mask[w] |= m;
                                        true
                                    } else {
                                        false
                                    }
                                }
                                None => !prefix_dirs.iter().any(|(_, p)| p == parent),
                            };
                            if need_dir {
                                prefix_dirs.push((prefix_byte, parent.to_path_buf()));
                            }
                        }
                        let idx = unique_jobs.len();
                        seen_cas.insert(cas_path.as_path(), idx);
                        unique_jobs.push((cas_path.clone(), &pack_bytes[start..end]));
                        entry_job_idx.push(Some(idx));
                    }
                    continue;
                }
            }
            entry_job_idx.push(None);
        }

        if unique_jobs.is_empty() {
            return;
        }
        if !prefix_dirs.is_empty() {
            if prefix_dirs.len() >= 8 {
                let dir_idx = AtomicUsize::new(0);
                rnpm_fs::run_parallel(8.min(prefix_dirs.len()), &|| loop {
                    let idx = dir_idx.fetch_add(1, Ordering::Relaxed);
                    if idx >= prefix_dirs.len() {
                        break;
                    }
                    let (pb_opt, ref parent) = prefix_dirs[idx];
                    if fs::create_dir_all(parent).is_ok() {
                        if let Some(b) = pb_opt {
                            let w = (b >> 6) as usize;
                            let m = 1u64 << (b & 63);
                            self.cas_prefix_dirs[w].fetch_or(m, Ordering::Relaxed);
                        }
                    }
                });
            } else {
                for (pb_opt, parent) in &prefix_dirs {
                    if fs::create_dir_all(parent).is_ok() {
                        if let Some(b) = *pb_opt {
                            let w = (b >> 6) as usize;
                            let m = 1u64 << (b & 63);
                            self.cas_prefix_dirs[w].fetch_or(m, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        let cas_may_exist = self.has_cas_files.load(Ordering::Relaxed);
        let mtimes: Vec<AtomicU64> = (0..unique_jobs.len()).map(|_| AtomicU64::new(0)).collect();
        let ok_flags: Vec<AtomicBool> = (0..unique_jobs.len())
            .map(|_| AtomicBool::new(false))
            .collect();
        let next_idx = AtomicUsize::new(0);
        let num_workers = 32.min(unique_jobs.len());
        rnpm_fs::run_parallel(num_workers, &|| loop {
            let idx = next_idx.fetch_add(1, Ordering::Relaxed);
            if idx >= unique_jobs.len() {
                break;
            }
            let (ref cas_path, slice) = unique_jobs[idx];
            if let Ok(mt_opt) =
                Self::write_cas_file_with_mtime_opt(cas_path, slice, true, cas_may_exist)
            {
                ok_flags[idx].store(true, Ordering::Relaxed);
                if let Some(mt) = mt_opt {
                    mtimes[idx].store(mt, Ordering::Relaxed);
                }
            }
        });

        let mut any_ok = false;
        for (entry, job_opt) in entries.iter_mut().zip(entry_job_idx) {
            if let Some(idx) = job_opt {
                if ok_flags[idx].load(Ordering::Relaxed) {
                    any_ok = true;
                    entry.cas_verified = true;
                    let mt = mtimes[idx].load(Ordering::Relaxed);
                    if mt != 0 {
                        entry.cas_mtime = Some(mt);
                    }
                } else {
                    entry.cas_verified = false;
                }
            } else {
                entry.cas_verified = false;
            }
        }
        if any_ok {
            self.has_cas_files.store(true, Ordering::Relaxed);
        }
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
            let mut verified_fast = false;
            if let Some(b64) = trimmed.strip_prefix("sha512-") {
                if b64.len() == 88 && !b64.as_bytes().iter().any(|b| b.is_ascii_whitespace()) {
                    let mut expected_bytes = [0u8; 66];
                    if let Ok(64) = BASE64.decode_mut(b64.as_bytes(), &mut expected_bytes) {
                        let actual: [u8; 64] = Sha512::digest(tarball_bytes).into();
                        let mut diff = 0u8;
                        for i in 0..64 {
                            diff |= actual[i] ^ expected_bytes[i];
                        }
                        if diff != 0 {
                            return Err(CacheError::IntegrityMismatch {
                                key: integrity.to_string(),
                                expected: integrity.to_string(),
                                actual: format!("sha512-{}", BASE64.encode(&actual)),
                            });
                        }
                        verified_fast = true;
                    }
                }
            }
            if !verified_fast {
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
                        if trimmed.len() == 128 && trimmed.bytes().all(|c| c.is_ascii_hexdigit()) {
                            let digest: [u8; 64] = Sha512::digest(tarball_bytes).into();
                            let mut hex_buf = [0u8; 128];
                            let actual_hex = encode_hex_lower(&digest, &mut hex_buf);
                            if !actual_hex.eq_ignore_ascii_case(trimmed) {
                                return Err(CacheError::IntegrityMismatch {
                                    key: integrity.to_string(),
                                    expected: trimmed.to_string(),
                                    actual: actual_hex.to_string(),
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
        }

        let t_gz = std::time::Instant::now();
        let compressed_read = Arc::new(AtomicU64::new(0));
        let mut archive = tar::Archive::new(TarStreamReader::new(tarball_bytes, compressed_read));

        let limits = rnpm_fs::TarLimits::default();
        let build_pack = populate_cas || target_dir.is_none();
        let cas_dir = populate_cas.then(|| self.cas_dir());

        let mut pack_bytes = if build_pack {
            Vec::with_capacity((tarball_bytes.len() * 4).max(16 * 1024))
        } else {
            Vec::new()
        };
        let mut index_files: Vec<PackFileEntry> = if build_pack {
            Vec::with_capacity(32)
        } else {
            Vec::new()
        };
        let mut seen_lower: HashMap<String, usize> = if build_pack {
            HashMap::with_capacity(32)
        } else {
            HashMap::new()
        };
        let mut had_duplicates = false;
        let mut scratch: Vec<u8> = Vec::new();
        let mut saw_npmignores: HashSet<String> = HashSet::new();

        let mut created_dirs = if let Some(target) = target_dir {
            std::fs::create_dir_all(target).map_err(CacheError::Io)?;
            let mut set = HashSet::new();
            set.insert(target.to_path_buf());
            Some(set)
        } else {
            None
        };

        let entries = archive.entries().map_err(CacheError::Io)?;
        let mut entry_count = 0usize;
        let mut total_uncompressed = 0u64;

        for entry_res in entries {
            let mut entry = entry_res.map_err(CacheError::Io)?;
            let entry_type = entry.header().entry_type();
            if entry_type == tar::EntryType::XGlobalHeader || entry_type.as_byte() == b'g' {
                continue;
            }
            let mode = entry.header().mode().unwrap_or(0);
            if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
                return Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenModeBits {
                    mode,
                    path: entry.path().unwrap_or_default().to_path_buf(),
                }));
            }
            let path_check_bytes = entry.path_bytes();
            if path_check_bytes.contains(&0) {
                return Err(CacheError::Fs(rnpm_fs::FsError::PathTraversal {
                    path: PathBuf::from(String::from_utf8_lossy(&path_check_bytes).into_owned()),
                }));
            }
            if std::str::from_utf8(&path_check_bytes).is_err() {
                return Err(CacheError::Fs(rnpm_fs::FsError::InvalidUtf8Path {
                    path: PathBuf::from(String::from_utf8_lossy(&path_check_bytes).into_owned()),
                }));
            }
            let is_sparse = entry_type.as_byte() == b'S' || entry_type.is_gnu_sparse();
            let has_pax_sparse = if let Ok(Some(extensions)) = entry.pax_extensions() {
                extensions.filter_map(|e| e.ok()).any(|ext| {
                    ext.key()
                        .map(|k| k.starts_with("GNU.sparse."))
                        .unwrap_or(false)
                        || ext.key_bytes().starts_with(b"GNU.sparse.")
                })
            } else {
                false
            };
            if is_sparse || has_pax_sparse {
                return Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenSparseFile {
                    path: entry.path().unwrap_or_default().to_path_buf(),
                }));
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

            let norm_path: String = {
                let raw_bytes = entry.path_bytes();
                let fast_res = try_fast_strip_ascii_tar_path(raw_bytes.as_ref());
                match fast_res {
                    None => continue,
                    Some(Some(rel_str)) => {
                        let rel_trimmed = rel_str.trim_end_matches('/');
                        if rel_trimmed.is_empty() || rel_trimmed == "." || rel_str.ends_with('/') {
                            match fallback_normalize_tar_path(&entry, &limits, &mut saw_npmignores)? {
                                Some(np) => np,
                                None => continue,
                            }
                        } else {
                            let is_ni = rel_trimmed == ".npmignore"
                                || rel_trimmed.ends_with("/.npmignore");
                            let is_gi = !is_ni
                                && (rel_trimmed == ".gitignore"
                                    || rel_trimmed.ends_with("/.gitignore"));
                            let candidate: String = if is_ni {
                                if !saw_npmignores.contains(rel_trimmed) {
                                    saw_npmignores.insert(rel_trimmed.to_string());
                                }
                                rel_trimmed.to_string()
                            } else if is_gi {
                                let prefix_len = rel_trimmed.len() - ".gitignore".len();
                                let mut ni = String::with_capacity(prefix_len + 10);
                                ni.push_str(&rel_trimmed[..prefix_len]);
                                ni.push_str(".npmignore");
                                if saw_npmignores.contains(&ni) {
                                    continue;
                                }
                                ni
                            } else {
                                rel_trimmed.to_string()
                            };

                            fast_validate_entry_path(&candidate).map_err(CacheError::Fs)?;
                            let path_depth = ascii_depth(&candidate);
                            if path_depth > limits.max_path_depth {
                                return Err(CacheError::Fs(
                                    rnpm_fs::FsError::TarBombLimitExceeded {
                                        limit_type: "path depth".to_string(),
                                        detail: format!(
                                            "Path depth {} exceeded maximum allowed path depth of {}: '{}'",
                                            path_depth, limits.max_path_depth, candidate
                                        ),
                                    },
                                ));
                            }
                            candidate
                        }
                    }
                    Some(None) => {
                        match fallback_normalize_tar_path(&entry, &limits, &mut saw_npmignores)? {
                            Some(np) => np,
                            None => continue,
                        }
                    }
                }
            };

            let entry_size = entry.size();
            if entry_size > limits.max_single_entry_size {
                return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                    limit_type: "entry size".to_string(),
                    detail: format!(
                        "Entry size {} exceeded single file limit of {} bytes",
                        entry_size, limits.max_single_entry_size
                    ),
                }));
            }

            let file_mode = if mode != 0 {
                mode
            } else {
                entry
                    .header()
                    .mode()
                    .unwrap_or(rnpm_fs::NPM_DEFAULT_FILE_MODE)
            };

            if build_pack {
                let curr_offset = pack_bytes.len();
                let rem = curr_offset & (PACK_ALIGNMENT - 1);
                let aligned_offset = if rem == 0 {
                    curr_offset
                } else {
                    let padded = curr_offset + (PACK_ALIGNMENT - rem);
                    pack_bytes.resize(padded, 0u8);
                    padded
                };
                if entry_size > limits.max_single_entry_size {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "entry size".to_string(),
                        detail: format!("Entry '{}' exceeded single file limit", norm_path),
                    }));
                }
                if entry_size <= 4 * 1024 * 1024 {
                    let sz = entry_size as usize;
                    if sz > 0 {
                        pack_bytes.resize(aligned_offset + sz, 0u8);
                        entry
                            .read_exact(&mut pack_bytes[aligned_offset..aligned_offset + sz])
                            .map_err(CacheError::Io)?;
                    }
                } else {
                    let mut take_reader = (&mut entry).take(limits.max_single_entry_size + 1);
                    take_reader.read_to_end(&mut pack_bytes).map_err(CacheError::Io)?;
                }
                let data_len = pack_bytes.len() - aligned_offset;
                if data_len as u64 > limits.max_single_entry_size {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "entry size".to_string(),
                        detail: format!("Entry '{}' exceeded single file limit", norm_path),
                    }));
                }

                total_uncompressed = total_uncompressed.saturating_add(data_len as u64);
                if total_uncompressed > limits.max_uncompressed_size {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "uncompressed size".to_string(),
                        detail: format!(
                            "Total uncompressed bytes {} exceeded limit {}",
                            total_uncompressed, limits.max_uncompressed_size
                        ),
                    }));
                }

                let slice = &pack_bytes[aligned_offset..];
                if let (Some(target), Some(ref mut dirs)) = (target_dir, &mut created_dirs) {
                    let full = if cfg!(windows) && norm_path.contains('/') {
                        target.join(norm_path.replace('/', "\\"))
                    } else {
                        target.join(&norm_path)
                    };
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
                    let _ = rnpm_fs::write_file_fast(&full, slice, file_mode, 64 * 1024);
                }

                let new_entry = PackFileEntry {
                    path: norm_path.clone(),
                    mode: file_mode,
                    size: data_len as u64,
                    offset: aligned_offset as u64,
                    aligned_offset: aligned_offset as u64,
                    sha256: None,
                    cas_path: None,
                    cas_verified: false,
                    cas_mtime: None,
                };
                let lower_key = norm_path.to_lowercase();
                if let Some(&prev_idx) = seen_lower.get(&lower_key) {
                    had_duplicates = true;
                    index_files[prev_idx] = new_entry;
                } else {
                    let idx = index_files.len();
                    seen_lower.insert(lower_key, idx);
                    index_files.push(new_entry);
                }
            } else {
                if entry_size > limits.max_single_entry_size {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "entry size".to_string(),
                        detail: format!("Entry '{}' exceeded single file limit", norm_path),
                    }));
                }
                scratch.clear();
                if entry_size > 0 && entry_size <= 4 * 1024 * 1024 {
                    let sz = entry_size as usize;
                    scratch.resize(sz, 0u8);
                    entry.read_exact(&mut scratch).map_err(CacheError::Io)?;
                } else {
                    let mut take_reader = (&mut entry).take(limits.max_single_entry_size + 1);
                    take_reader.read_to_end(&mut scratch).map_err(CacheError::Io)?;
                }
                if scratch.len() as u64 > limits.max_single_entry_size {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "entry size".to_string(),
                        detail: format!("Entry '{}' exceeded single file limit", norm_path),
                    }));
                }
                total_uncompressed = total_uncompressed.saturating_add(scratch.len() as u64);
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
                    let full = if cfg!(windows) && norm_path.contains('/') {
                        target.join(norm_path.replace('/', "\\"))
                    } else {
                        target.join(&norm_path)
                    };
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
                    let _ = rnpm_fs::write_file_fast(&full, &scratch, file_mode, 64 * 1024);
                }
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
                pack_mtime: None,
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

        if had_duplicates {
            // Allocate only the space needed for retained live entries + 4 KiB alignment,
            // freeing any oversized pre-compaction buffer immediately.
            let retained_size: usize = index_files
                .iter()
                .map(|entry| {
                    let s = entry.size as usize;
                    if s == 0 {
                        0
                    } else {
                        (s + PACK_ALIGNMENT - 1) & !(PACK_ALIGNMENT - 1)
                    }
                })
                .sum();
            let mut compacted = Vec::with_capacity(retained_size);
            for entry in &mut index_files {
                let start = entry.offset as usize;
                let end = start + entry.size as usize;
                let curr_offset = compacted.len();
                let rem = curr_offset & (PACK_ALIGNMENT - 1);
                let aligned_offset = if rem == 0 {
                    curr_offset
                } else {
                    let padded = curr_offset + (PACK_ALIGNMENT - rem);
                    compacted.resize(padded, 0u8);
                    padded
                };
                compacted.extend_from_slice(&pack_bytes[start..end]);
                entry.offset = aligned_offset as u64;
                entry.aligned_offset = aligned_offset as u64;
            }
            pack_bytes = compacted;
        }

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

        // Compute per-file SHA-256 digests and derived CAS paths after dedup/compaction
        // (in parallel for large packages).
        if index_files.len() >= 32 {
            struct HashSlot(std::cell::UnsafeCell<PackFileEntry>);
            // SAFETY: Each index is claimed at most once via `next_hash_idx.fetch_add(1)`.
            unsafe impl Sync for HashSlot {}
            let slots: Vec<HashSlot> = std::mem::take(&mut index_files)
                .into_iter()
                .map(|e| HashSlot(std::cell::UnsafeCell::new(e)))
                .collect();
            let next_hash_idx = AtomicUsize::new(0);
            let workers = 16.min(slots.len());
            let pack_slice = &pack_bytes[..];
            let cas_dir_ref = cas_dir.as_ref();
            rnpm_fs::run_parallel(workers, &|| loop {
                let idx = next_hash_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= slots.len() {
                    break;
                }
                let entry = unsafe { &mut *slots[idx].0.get() };
                let start = entry.offset as usize;
                let end = start + entry.size as usize;
                let sha = sha256_hex_string(&pack_slice[start..end]);
                entry.cas_path = cas_dir_ref.map(|d| {
                    let p = if sha.len() >= 2 { &sha[0..2] } else { "00" };
                    d.join(p).join(&sha)
                });
                entry.sha256 = Some(sha);
            });
            index_files = slots.into_iter().map(|s| s.0.into_inner()).collect();
        } else {
            for entry in &mut index_files {
                let start = entry.offset as usize;
                let end = start + entry.size as usize;
                let sha = sha256_hex_string(&pack_bytes[start..end]);
                entry.cas_path = cas_dir.as_ref().map(|d| {
                    let p = if sha.len() >= 2 { &sha[0..2] } else { "00" };
                    d.join(p).join(&sha)
                });
                entry.sha256 = Some(sha);
            }
        }

        self.finalize_pack_and_write(
            integrity,
            pack_bytes,
            index_files,
            Vec::new(),
            populate_cas,
            true,
        )
        .map(|(p, _)| p)
    }

    /// Decodes a package tarball directly in memory without writing to disk,
    /// returning files, directories, and symlinks ready for parallel materialization.
    pub fn decode_package_tarball(
        tarball_bytes: &[u8],
        target_dir: &Path,
        pkg_key: &str,
    ) -> Result<DecodedPackage, CacheError> {
        let limits = rnpm_fs::TarLimits::default();
        let verbatim_dest = rnpm_fs::to_verbatim_path(target_dir);
        let clean_dest = clean(&verbatim_dest);
        let dest_exists = verbatim_dest.symlink_metadata().is_ok();

        let compressed_counter = Arc::new(AtomicU64::new(0));
        let mut archive = tar::Archive::new(TarStreamReader::new(
            tarball_bytes,
            Arc::clone(&compressed_counter),
        ));

        let mut entry_count = 0usize;
        let mut total_uncompressed = 0u64;
        let mut directory_count = 0usize;
        let mut symlink_count = 0usize;

        let mut seen_paths: HashMap<String, String> = HashMap::with_capacity(32);
        let mut seen_dirs_lower: HashSet<String> = HashSet::with_capacity(16);
        let mut seen_files_lower: HashSet<String> = HashSet::with_capacity(32);
        let mut symlink_paths: HashSet<PathBuf> = HashSet::new();
        let mut extracted_regular_files: HashSet<PathBuf> = HashSet::with_capacity(32);
        let mut hardlink_targets: HashMap<PathBuf, PathBuf> = HashMap::new();
        let mut safe_ancestors: HashSet<PathBuf> = HashSet::new();

        let mut directories: Vec<PathBuf> = Vec::with_capacity(16);
        let mut files: Vec<Option<rnpm_fs::MaterializeFile>> = Vec::with_capacity(32);
        let mut file_indices: HashMap<String, usize> = HashMap::with_capacity(32);
        let mut symlinks: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut hardlinks: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut saw_npmignores: HashSet<String> = HashSet::new();

        let pkg_id = Some(pkg_key.to_string());
        let entries = archive.entries().map_err(CacheError::Io)?;
        for entry_res in entries {
            let mut entry = entry_res.map_err(CacheError::Io)?;
            let entry_type = entry.header().entry_type();

            if entry_type == tar::EntryType::XGlobalHeader || entry_type.as_byte() == b'g' {
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

            let mode = entry.header().mode().unwrap_or(0);
            if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
                return Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenModeBits {
                    mode,
                    path: entry.path().unwrap_or_default().to_path_buf(),
                }));
            }

            let (fast_ok, raw_err_path, raw_str_owned): (bool, Option<PathBuf>, Option<String>) = {
                let path_bytes = entry.path_bytes();
                if path_bytes.contains(&0) {
                    return Err(CacheError::Fs(rnpm_fs::FsError::PathTraversal {
                        path: PathBuf::from(String::from_utf8_lossy(&path_bytes).into_owned()),
                    }));
                }
                let s = std::str::from_utf8(&path_bytes).map_err(|_| {
                    CacheError::Fs(rnpm_fs::FsError::InvalidUtf8Path {
                        path: PathBuf::from(String::from_utf8_lossy(&path_bytes).into_owned()),
                    })
                })?;
                let fast_ok = s.is_ascii()
                    && !s.contains('\\')
                    && !s.contains("..")
                    && !s.starts_with('/')
                    && !s.contains("/./")
                    && !s.contains("//")
                    && !s.ends_with("/.");
                if fast_ok {
                    (true, None, Some(s.to_string()))
                } else {
                    (false, Some(PathBuf::from(s)), None)
                }
            };

            let is_sparse = entry_type.as_byte() == b'S' || entry_type.is_gnu_sparse();
            let has_pax_sparse = if let Ok(Some(extensions)) = entry.pax_extensions() {
                extensions.filter_map(|e| e.ok()).any(|ext| {
                    ext.key()
                        .map(|k| k.starts_with("GNU.sparse."))
                        .unwrap_or(false)
                        || ext.key_bytes().starts_with(b"GNU.sparse.")
                })
            } else {
                false
            };
            if is_sparse || has_pax_sparse {
                let p = match raw_err_path.or_else(|| raw_str_owned.map(PathBuf::from)) {
                    Some(p) => p,
                    None => entry.path().unwrap_or_default().to_path_buf(),
                };
                return Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenSparseFile {
                    path: p,
                }));
            }

            let fast_rel_or_fallback: Option<Result<String, ()>> = if fast_ok {
                let s = raw_str_owned.as_deref().unwrap();
                fast_validate_entry_path(s).map_err(CacheError::Fs)?;
                match try_fast_strip_ascii_tar_path(s.as_bytes()) {
                    None => None,
                    Some(None) => Some(Err(())),
                    Some(Some(stripped)) => {
                        let trimmed = stripped.trim_end_matches('/');
                        if trimmed.is_empty() || trimmed == "." {
                            None
                        } else if entry_type.is_file() {
                            if trimmed == ".npmignore" || trimmed.ends_with("/.npmignore") {
                                if !saw_npmignores.contains(trimmed) {
                                    saw_npmignores.insert(trimmed.to_string());
                                }
                                Some(Ok(trimmed.to_string()))
                            } else if trimmed == ".gitignore" || trimmed.ends_with("/.gitignore") {
                                let prefix_len = trimmed.len() - ".gitignore".len();
                                let mut ni = String::with_capacity(prefix_len + 10);
                                ni.push_str(&trimmed[..prefix_len]);
                                ni.push_str(".npmignore");
                                if saw_npmignores.contains(&ni) {
                                    None
                                } else {
                                    Some(Ok(ni))
                                }
                            } else {
                                Some(Ok(trimmed.to_string()))
                            }
                        } else {
                            Some(Ok(trimmed.to_string()))
                        }
                    }
                }
            } else {
                Some(Err(()))
            };

            let Some(fast_or_fb) = fast_rel_or_fallback else {
                continue;
            };

            let (relative_path, target_path, norm_exact, is_ascii_clean) = match fast_or_fb {
                Ok(norm_exact) => {
                    let path_depth = ascii_depth(&norm_exact);
                    if path_depth > limits.max_path_depth {
                        return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                            limit_type: "path depth".to_string(),
                            detail: format!(
                                "Path depth {} exceeded maximum allowed path depth of {}: '{}'",
                                path_depth, limits.max_path_depth, norm_exact
                            ),
                        }));
                    }

                    if entry_type.is_dir() {
                        directory_count += 1;
                        if directory_count > limits.max_directories {
                            return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                                limit_type: "directory count".to_string(),
                                detail: format!(
                                    "Tarball exceeded maximum allowed directories: {}",
                                    limits.max_directories
                                ),
                            }));
                        }
                    }
                    if entry_type.is_block_special()
                        || entry_type.is_character_special()
                        || entry_type.is_fifo()
                    {
                        return Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenSpecialEntry {
                            path: entry.path().unwrap_or_default().to_path_buf(),
                        }));
                    }

                    let rel_pb = PathBuf::from(&norm_exact);
                    let target_path = if cfg!(windows) && norm_exact.contains('/') {
                        verbatim_dest.join(norm_exact.replace('/', "\\"))
                    } else {
                        verbatim_dest.join(&norm_exact)
                    };

                    if !symlink_paths.is_empty() || dest_exists {
                        rnpm_fs::tarball::ensure_no_symlink_ancestors_with_cache(
                            &target_path,
                            &verbatim_dest,
                            &symlink_paths,
                            &rel_pb,
                            Some(&mut safe_ancestors),
                        )
                        .map_err(CacheError::Fs)?;
                    }

                    (rel_pb, target_path, norm_exact, true)
                }
                Err(()) => {
                    let raw_path = entry.path().map_err(CacheError::Io)?.to_path_buf();
                    rnpm_fs::validate_entry_path(&raw_path).map_err(CacheError::Fs)?;
                    let mut relative_path = match rnpm_fs::strip_package_prefix(&raw_path) {
                        Some(p) => {
                            let cleaned: PathBuf = p
                                .components()
                                .filter(|c| !matches!(c, std::path::Component::CurDir))
                                .collect();
                            if cleaned.as_os_str().is_empty() {
                                continue;
                            }
                            cleaned
                        }
                        None => continue,
                    };
                    if entry_type.is_file() {
                        if relative_path.file_name() == Some(std::ffi::OsStr::new(".npmignore")) {
                            let s = relative_path.to_string_lossy().replace('\\', "/");
                            saw_npmignores.insert(s);
                        } else if relative_path.file_name()
                            == Some(std::ffi::OsStr::new(".gitignore"))
                        {
                            let ni = relative_path.with_file_name(".npmignore");
                            let ni_str = ni.to_string_lossy().replace('\\', "/");
                            if saw_npmignores.contains(&ni_str) {
                                continue;
                            }
                            relative_path = ni;
                        }
                    }
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

                    if entry_type.is_dir() {
                        directory_count += 1;
                        if directory_count > limits.max_directories {
                            return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                                limit_type: "directory count".to_string(),
                                detail: format!(
                                    "Tarball exceeded maximum allowed directories: {}",
                                    limits.max_directories
                                ),
                            }));
                        }
                    }
                    if entry_type.is_block_special()
                        || entry_type.is_character_special()
                        || entry_type.is_fifo()
                    {
                        return Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenSpecialEntry {
                            path: raw_path,
                        }));
                    }

                    let target_path = clean(verbatim_dest.join(&relative_path));
                    if !target_path.starts_with(&clean_dest) {
                        return Err(CacheError::Fs(rnpm_fs::FsError::PathTraversal {
                            path: relative_path,
                        }));
                    }
                    if target_path == clean_dest && !entry_type.is_dir() {
                        return Err(CacheError::Fs(rnpm_fs::FsError::PathTraversal {
                            path: relative_path,
                        }));
                    }

                    if !symlink_paths.is_empty() || dest_exists {
                        rnpm_fs::tarball::ensure_no_symlink_ancestors_with_cache(
                            &target_path,
                            &verbatim_dest,
                            &symlink_paths,
                            &relative_path,
                            Some(&mut safe_ancestors),
                        )
                        .map_err(CacheError::Fs)?;
                    }

                    let norm_exact = relative_path
                        .components()
                        .filter_map(|c| match c {
                            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("/");
                    if norm_exact.is_empty() {
                        continue;
                    }
                    (relative_path, target_path, norm_exact, false)
                }
            };

            let norm_lower = if norm_exact.bytes().any(|b| b.is_ascii_uppercase()) {
                norm_exact.to_ascii_lowercase()
            } else {
                norm_exact.clone()
            };

            if let Some(existing_exact) = seen_paths.get(&norm_lower) {
                if existing_exact != &norm_exact {
                    return Err(CacheError::Fs(rnpm_fs::FsError::CaseCollision {
                        path: relative_path,
                    }));
                }
            }
            check_case_dir_collision(
                &norm_lower,
                entry_type.is_dir(),
                &mut seen_dirs_lower,
                &mut seen_files_lower,
                &|| relative_path.clone(),
            )?;
            seen_paths.insert(norm_lower, norm_exact.clone());

            if entry_type.is_symlink() || entry_type.is_hard_link() {
                symlink_count += 1;
                if symlink_count > limits.max_symlinks {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "symlink count".to_string(),
                        detail: format!(
                            "Tarball exceeded maximum allowed symlinks/hardlinks: {}",
                            limits.max_symlinks
                        ),
                    }));
                }

                if let Some(link_bytes) = entry.link_name_bytes() {
                    if link_bytes.contains(&0) {
                        return Err(CacheError::Fs(rnpm_fs::FsError::PathTraversal {
                            path: PathBuf::from(String::from_utf8_lossy(&link_bytes).into_owned()),
                        }));
                    }
                    if std::str::from_utf8(&link_bytes).is_err() {
                        return Err(CacheError::Fs(rnpm_fs::FsError::InvalidUtf8Path {
                            path: PathBuf::from(String::from_utf8_lossy(&link_bytes).into_owned()),
                        }));
                    }
                }

                if let Some(link_target) = entry.link_name().map_err(CacheError::Io)? {
                    let normalized_target = if entry_type.is_hard_link() {
                        rnpm_fs::strip_package_prefix(&link_target)
                            .unwrap_or_else(|| link_target.to_path_buf())
                    } else {
                        link_target.to_path_buf()
                    };

                    if entry_type.is_symlink() {
                        let cleaned_rel = rnpm_fs::tarball::validate_link_target(
                            &relative_path,
                            &normalized_target,
                            target_dir,
                        )
                        .map_err(CacheError::Fs)?;
                        let norm_rel = if norm_exact.contains('\\') {
                            PathBuf::from(norm_exact.replace('\\', "/"))
                        } else {
                            PathBuf::from(&norm_exact)
                        };
                        extracted_regular_files.remove(&relative_path);
                        extracted_regular_files.remove(&norm_rel);
                        symlink_paths.insert(relative_path);
                        symlink_paths.insert(norm_rel);
                        if let Some(idx) = file_indices.remove(&norm_exact) {
                            files[idx] = None;
                        }
                        symlinks.retain(|(p, _)| p != &target_path);
                        hardlinks.retain(|(p, _)| p != &target_path);
                        symlinks.push((target_path, cleaned_rel));
                    } else if entry_type.is_hard_link() {
                        if normalized_target.is_absolute() || normalized_target.has_root() {
                            return Err(CacheError::Fs(rnpm_fs::FsError::AbsolutePath {
                                path: normalized_target,
                            }));
                        }
                        let cleaned_target = clean(&normalized_target);
                        if cleaned_target.starts_with("..")
                            || cleaned_target.is_absolute()
                            || cleaned_target.has_root()
                        {
                            return Err(CacheError::Fs(rnpm_fs::FsError::EscapingSymlink {
                                link: relative_path,
                                target: normalized_target,
                            }));
                        }
                        rnpm_fs::validate_entry_path(&cleaned_target).map_err(CacheError::Fs)?;

                        let clean_source = clean(verbatim_dest.join(&cleaned_target));
                        if !clean_source.starts_with(&clean_dest) {
                            return Err(CacheError::Fs(rnpm_fs::FsError::EscapingSymlink {
                                link: relative_path,
                                target: normalized_target,
                            }));
                        }

                        let norm_cleaned =
                            PathBuf::from(cleaned_target.to_string_lossy().replace('\\', "/"));
                        if cleaned_target == relative_path {
                            return Err(CacheError::Fs(rnpm_fs::FsError::CircularHardlink {
                                link: relative_path,
                                target: normalized_target,
                            }));
                        }
                        let mut curr = cleaned_target.clone();
                        let mut visited = HashSet::new();
                        visited.insert(relative_path.clone());
                        while let Some(next) = hardlink_targets.get(&curr) {
                            if !visited.insert(curr.clone()) || curr == relative_path {
                                return Err(CacheError::Fs(rnpm_fs::FsError::CircularHardlink {
                                    link: relative_path,
                                    target: normalized_target,
                                }));
                            }
                            curr = next.clone();
                        }

                        if !extracted_regular_files.contains(&cleaned_target)
                            && !extracted_regular_files.contains(&norm_cleaned)
                        {
                            return Err(CacheError::Fs(rnpm_fs::FsError::DanglingHardlink {
                                link: relative_path,
                                target: normalized_target,
                            }));
                        }

                        let norm_rel = PathBuf::from(
                            relative_path.to_string_lossy().replace('\\', "/"),
                        );
                        hardlink_targets.insert(relative_path.clone(), cleaned_target);
                        extracted_regular_files.insert(relative_path);
                        extracted_regular_files.insert(norm_rel);
                        if let Some(idx) = file_indices.remove(&norm_exact) {
                            files[idx] = None;
                        }
                        symlinks.retain(|(p, _)| p != &target_path);
                        hardlinks.retain(|(p, _)| p != &target_path);
                        hardlinks.push((target_path, clean_source));
                    }
                }
                continue;
            }

            if entry_type.is_dir() {
                directories.push(target_path);
            } else if entry_type.is_file() {
                let entry_size = entry.size();
                if entry_size > limits.max_single_entry_size {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "entry size".to_string(),
                        detail: format!(
                            "Entry size {} exceeded single file limit of {} bytes",
                            entry_size, limits.max_single_entry_size
                        ),
                    }));
                }
                if total_uncompressed.saturating_add(entry_size) > limits.max_uncompressed_size {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "uncompressed size".to_string(),
                        detail: format!(
                            "Projected uncompressed size exceeds limit of {} bytes",
                            limits.max_uncompressed_size
                        ),
                    }));
                }

                let file_mode = entry
                    .header()
                    .mode()
                    .unwrap_or(rnpm_fs::NPM_DEFAULT_FILE_MODE);
                let mut file_buf = Vec::with_capacity((entry_size as usize).min(4 * 1024 * 1024));
                entry.read_to_end(&mut file_buf).map_err(CacheError::Io)?;

                total_uncompressed = total_uncompressed.saturating_add(file_buf.len() as u64);
                if total_uncompressed > limits.max_uncompressed_size {
                    return Err(CacheError::Fs(rnpm_fs::FsError::TarBombLimitExceeded {
                        limit_type: "uncompressed size".to_string(),
                        detail: format!(
                            "Uncompressed size {} exceeded limit of {} bytes",
                            total_uncompressed, limits.max_uncompressed_size
                        ),
                    }));
                }

                if total_uncompressed > 50_000 {
                    let compressed_so_far = compressed_counter.load(Ordering::Relaxed);
                    let ratio = if compressed_so_far == 0 {
                        f64::INFINITY
                    } else {
                        total_uncompressed as f64 / compressed_so_far as f64
                    };
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

                if !symlink_paths.is_empty() {
                    let norm_rel = PathBuf::from(&norm_exact);
                    symlink_paths.remove(&relative_path);
                    symlink_paths.remove(&norm_rel);
                }
                extracted_regular_files.insert(relative_path);
                if norm_exact.contains('\\') || !is_ascii_clean {
                    extracted_regular_files.insert(PathBuf::from(norm_exact.replace('\\', "/")));
                }

                if !symlinks.is_empty() {
                    symlinks.retain(|(p, _)| p != &target_path);
                }
                if !hardlinks.is_empty() {
                    hardlinks.retain(|(p, _)| p != &target_path);
                }

                let mat_file = rnpm_fs::MaterializeFile {
                    path: target_path,
                    data: Arc::new(file_buf),
                    mode: file_mode,
                    package_id: pkg_id.clone(),
                };

                if let Some(&idx) = file_indices.get(&norm_exact) {
                    files[idx] = Some(mat_file);
                } else {
                    let idx = files.len();
                    file_indices.insert(norm_exact, idx);
                    files.push(Some(mat_file));
                }
            }
        }
        let compressed_bytes = compressed_counter.load(Ordering::Relaxed);
        if total_uncompressed > 50_000 {
            let ratio = if compressed_bytes == 0 {
                f64::INFINITY
            } else {
                total_uncompressed as f64 / compressed_bytes as f64
            };
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

        let mut files: Vec<rnpm_fs::MaterializeFile> = files.into_iter().flatten().collect();

        if !hardlinks.is_empty() {
            let mut positions: HashMap<PathBuf, usize> = files
                .iter()
                .enumerate()
                .map(|(i, file)| (file.path.clone(), i))
                .collect();
            for (link, target) in hardlinks {
                let source = positions.get(&target).copied().ok_or_else(|| {
                    CacheError::InvalidPack(format!(
                        "Hardlink target missing: {}",
                        target.display()
                    ))
                })?;
                let mut file = files[source].clone();
                file.path = link.clone();
                positions.insert(link, files.len());
                files.push(file);
            }
        }

        directories.reserve(files.len() / 2 + symlinks.len() + 1);
        directories.push(verbatim_dest.clone());
        for file in &files {
            if let Some(parent) = file.path.parent() {
                directories.push(parent.to_path_buf());
            }
        }
        let resolved_symlinks: Vec<_> = if symlinks.is_empty() {
            Vec::new()
        } else {
            symlinks
                .into_iter()
                .map(|(link, target)| {
                    if let Some(parent) = link.parent() {
                        directories.push(parent.to_path_buf());
                    }
                    (link, verbatim_dest.join(target))
                })
                .collect()
        };
        directories.sort_unstable();
        directories.dedup();

        Ok(DecodedPackage {
            files,
            dirs: directories,
            symlinks: resolved_symlinks,
        })
    }

    /// Checks whether block cloning from this store into `target_dir` is supported,
    /// avoiding redundant Win32 volume detection queries across thousands of packages
    /// by caching results keyed by destination directory / volume root in a thread-safe cache.
    pub fn is_block_cloning_eligible(&self, target_dir: &Path) -> bool {
        #[cfg(windows)]
        {
            let b = target_dir.as_os_str().as_encoded_bytes();
            let drive_byte = if b.len() >= 3 && b[1] == b':' && b[2] == b'\\' && b[0].is_ascii_alphabetic() {
                Some(b[0])
            } else if b.len() >= 7
                && b.starts_with(br"\\?\")
                && b[5] == b':'
                && b[6] == b'\\'
                && b[4].is_ascii_alphabetic()
            {
                Some(b[4])
            } else {
                None
            };
            if let Some(d) = drive_byte {
                let idx = (d.to_ascii_uppercase() - b'A') as usize;
                let cached = self.block_clone_drive_cache[idx].load(Ordering::Relaxed);
                if cached != 0 {
                    return cached == 2;
                }
                let eligible = is_same_volume(&self.root, target_dir)
                    && (is_block_cloning_supported(target_dir) || is_refs_volume(target_dir));
                {
                    let mut cache = self.block_clone_cache.write().unwrap();
                    cache.insert(volume_root_key(target_dir), eligible);
                }
                self.block_clone_drive_cache[idx].store(if eligible { 2 } else { 1 }, Ordering::Relaxed);
                return eligible;
            }
        }

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
        #[cfg(windows)]
        for slot in self.block_clone_drive_cache.iter() {
            slot.store(0, Ordering::Relaxed);
        }
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
        self.mmap_cache.write().unwrap().clear();
    }

    /// Derives (prefix, safe_stem, sha512_hex) for an integrity string.
    pub fn integrity_key_parts(integrity: &str) -> (String, String, String) {
        let (prefix, safe_stem, sha512_hex, _) = Self::integrity_key_parts_with_canon(integrity);
        (prefix, safe_stem, sha512_hex)
    }

    /// Derives `(prefix, safe_stem, sha512_hex, canonical_sha512_sri)` in one pass.
    fn integrity_key_parts_with_canon(
        integrity: &str,
    ) -> (String, String, String, Option<String>) {
        let trimmed = integrity.trim();

        // Fast path for single canonical "sha512-<88-char base64>" SRI string
        if let Some(b64) = trimmed.strip_prefix("sha512-") {
            if b64.len() == 88 && !b64.as_bytes().iter().any(|b| b.is_ascii_whitespace()) {
                let mut decoded = [0u8; 66];
                if let Ok(64) = BASE64.decode_mut(b64.as_bytes(), &mut decoded) {
                    let mut hex_buf = [0u8; 128];
                    let sha512_hex = encode_hex_lower(&decoded[..64], &mut hex_buf).to_string();
                    let prefix = sha512_hex[0..2].to_string();
                    let safe_stem = sanitize_filename(trimmed);
                    return (prefix, safe_stem, sha512_hex, Some(trimmed.to_string()));
                }
            }
        }

        // 1. Try parsing as SSRI Integrity
        if let Ok(parsed) = trimmed.parse::<Integrity>() {
            if let Some(entry) = parsed
                .entries
                .iter()
                .find(|e| e.algorithm == Algorithm::Sha512)
            {
                let mut hex_buf = [0u8; 128];
                let sha512_hex = if entry.digest.len() == 64 {
                    encode_hex_lower(&entry.digest, &mut hex_buf).to_string()
                } else {
                    HEXLOWER.encode(&entry.digest)
                };
                let prefix = sha512_hex[0..2].to_string();
                let canonical_integrity = format!("sha512-{}", BASE64.encode(&entry.digest));
                let safe_stem = sanitize_filename(&canonical_integrity);
                return (prefix, safe_stem, sha512_hex, Some(canonical_integrity));
            }
            if let Some(strongest) = parsed.strongest_algorithm() {
                if let Some(entry) = parsed.entries.iter().find(|e| e.algorithm == strongest) {
                    let digest = Sha512::digest(&entry.digest);
                    let mut hex_buf = [0u8; 128];
                    let sha512_hex = encode_hex_lower(&digest, &mut hex_buf).to_string();
                    let prefix = sha512_hex[0..2].to_string();
                    let canonical_integrity =
                        format!("{}-{}", entry.algorithm, BASE64.encode(&entry.digest));
                    let safe_stem = sanitize_filename(&canonical_integrity);
                    return (prefix, safe_stem, sha512_hex, None);
                }
            }
        }

        // 2. Pure 128-char hex string
        if trimmed.len() == 128 && trimmed.bytes().all(|c| c.is_ascii_hexdigit()) {
            let sha512_hex = trimmed.to_ascii_lowercase();
            let prefix = sha512_hex[0..2].to_string();
            let safe_stem = sha512_hex.clone();
            return (prefix, safe_stem, sha512_hex, None);
        }

        // 3. Fallback: hash the string itself to produce a deterministic SHA-512 hex
        let digest = Sha512::digest(trimmed.as_bytes());
        let mut hex_buf = [0u8; 128];
        let sha512_hex = encode_hex_lower(&digest, &mut hex_buf).to_string();
        let prefix = sha512_hex[0..2].to_string();
        let safe_stem = sanitize_filename(trimmed);
        (prefix, safe_stem, sha512_hex, None)
    }
}

/// Make filename safe across Windows and Unix by replacing invalid characters.
fn sanitize_filename(name: &str) -> String {
    if !name
        .bytes()
        .any(|b| matches!(b, b'/' | b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'))
    {
        return name.to_string();
    }
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        out.push(match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        });
    }
    out
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
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
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
                if attempts <= 2 {
                    yield_now();
                } else {
                    let jitter = (attempts as u64 * 173) % 400;
                    sleep(delay + Duration::from_micros(jitter));
                    delay = delay.saturating_mul(2).min(Duration::from_millis(100));
                }
            }
        }
    }
}

/// Helper to reliably remove a file, clearing readonly attributes if set.
fn remove_file_clearing_readonly(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
    let _ = fs::remove_file(path);
}

/// Atomically renames a temporary file into a CAS destination with Windows retry support.
///
/// If `to` already exists and has the expected length, another thread concurrently wrote it;
/// this is treated as a success, and `from` is cleaned up.
/// If `to` exists but does not match `expected_len` (e.g. truncated or corrupted), `to` is
/// replaced cleanly clearing any readonly attributes.
/// On failure or exhaustion of retries, `from` is cleaned up to prevent leftover temp files.
fn rename_atomic_cas(from: &Path, to: &Path, expected_len: u64) -> std::io::Result<()> {
    if let Ok(m) = to.metadata() {
        if m.len() == expected_len {
            let _ = fs::remove_file(from);
            return Ok(());
        }
    }
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    let mut attempts = 0;
    let mut delay = Duration::from_millis(5);
    loop {
        attempts += 1;
        if let Some(parent) = to.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(m) = to.metadata() {
            if m.len() == expected_len {
                let _ = fs::remove_file(from);
                return Ok(());
            } else {
                remove_file_clearing_readonly(to);
            }
        }
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if let Ok(m) = to.metadata() {
                    if m.len() == expected_len {
                        let _ = fs::remove_file(from);
                        return Ok(());
                    }
                }

                if attempts >= 10 {
                    if let Ok(m) = to.metadata() {
                        if m.len() == expected_len {
                            let _ = fs::remove_file(from);
                            return Ok(());
                        }
                    }
                    let _ = fs::remove_file(from);
                    return Err(e);
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
    fn test_rename_atomic_cas_cases() {
        let dir = tempdir().unwrap();
        let from = dir.path().join("temp.dat");
        let to = dir.path().join("final.dat");

        // 1. Rename into non-existing destination
        fs::write(&from, b"content-1234").unwrap();
        rename_atomic_cas(&from, &to, 12).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"content-1234");
        assert!(!from.exists());

        // 2. Destination exists with matching expected length: treated as concurrent success
        fs::write(&from, b"content-5678").unwrap();
        rename_atomic_cas(&from, &to, 12).unwrap();
        // Destination preserved, from cleaned up
        assert_eq!(fs::read(&to).unwrap(), b"content-1234");
        assert!(!from.exists());

        // 3. Destination exists with mismatched length (e.g. truncated/corrupted):
        // Atomically replaced with new content
        fs::write(&from, b"new-longer-content").unwrap();
        rename_atomic_cas(&from, &to, 18).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"new-longer-content");
        assert!(!from.exists());
    }

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
        for entry in &pack.index.files {
            assert_eq!(
                pack.get_entry_slice(entry),
                pack.get_file_slice(&entry.path)
            );
        }
        let mut invalid = pack.index.files[0].clone();
        invalid.offset = pack.data().len() as u64;
        invalid.size = 1;
        assert!(pack.get_entry_slice(&invalid).is_none());
        invalid.offset = u64::MAX;
        assert!(pack.get_entry_slice(&invalid).is_none());
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
        // Same-tick writes keep the mtime, which would hit the verified-mtime
        // shortcut; real corruption is detected once the mtime differs.
        fs::File::options()
            .write(true)
            .open(&pack_path)
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();

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
        // Same-tick writes keep the mtime, which would hit the verified-mtime
        // shortcut; real corruption is detected once the mtime differs.
        fs::File::options()
            .write(true)
            .open(&pack_path)
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();

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
            tar.append_data(
                &mut header1,
                "package/lib/index.js",
                &b"first version of file"[..],
            )
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
        let decoded =
            PackStore::decode_package_tarball(&tarball_bytes, target_dir.path(), "test-dup-pkg")
                .expect("decode_package_tarball must succeed with duplicate entries");

        // Must be deduplicated to exactly 1 file entry, with the later content and mode winning
        assert_eq!(decoded.files.len(), 1);
        assert_eq!(
            decoded.files[0].data.as_slice(),
            b"second version of file (later wins)"
        );
        assert_eq!(decoded.files[0].mode, 0o755);
    }

    #[test]
    fn test_pack_store_startup_cost_lazy_vs_eager() {
        let dir1 = tempdir().unwrap();
        let t_lazy_start = std::time::Instant::now();
        let store_lazy = PackStore::new(dir1.path()).unwrap();
        let lazy_dur = t_lazy_start.elapsed();

        // Verify lazy startup does not create prefix directories up front
        let packs_dir = store_lazy.packs_dir();
        assert!(packs_dir.is_dir());
        let initial_prefix_count = fs::read_dir(&packs_dir).unwrap().count();
        assert_eq!(
            initial_prefix_count, 0,
            "Lazy pack store must not eagerly create prefix dirs"
        );

        // Verify ensure_pack_prefix_dir creates prefix dir on demand and memoizes
        let p1 = store_lazy.ensure_pack_prefix_dir("ab").unwrap();
        assert!(p1.is_dir());
        assert_eq!(fs::read_dir(&packs_dir).unwrap().count(), 1);
        let p2 = store_lazy.ensure_pack_prefix_dir("ab").unwrap();
        assert_eq!(p1, p2);
        assert_eq!(fs::read_dir(&packs_dir).unwrap().count(), 1);

        let dir2 = tempdir().unwrap();
        let t_eager_start = std::time::Instant::now();
        let packs = dir2.path().join("packs");
        let cas = dir2.path().join("cas");
        fs::create_dir_all(&packs).unwrap();
        fs::create_dir_all(&cas).unwrap();
        for b in 0..=255u8 {
            let hex = format!("{b:02x}");
            let _ = fs::create_dir(packs.join(&hex));
            let _ = fs::create_dir(cas.join(&hex));
        }
        let eager_dur = t_eager_start.elapsed();

        eprintln!(
            "[STARTUP_BENCH] PackStore::new (lazy memoized): {:.2} ms",
            lazy_dur.as_secs_f64() * 1000.0
        );
        eprintln!(
            "[STARTUP_BENCH] PackStore::new (eager 256 dirs): {:.2} ms",
            eager_dur.as_secs_f64() * 1000.0
        );
    }

    #[test]
    fn decoded_pack_preserves_relative_symlinks_and_hardlink_payloads_on_disk() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(7);
        header.set_cksum();
        tar.append_data(&mut header, "package/lib/data.js", &b"payload"[..])
            .unwrap();
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        tar.append_link(&mut link, "package/lib/link.js", "data.js")
            .unwrap();
        let mut hardlink = tar::Header::new_gnu();
        hardlink.set_entry_type(tar::EntryType::Link);
        hardlink.set_size(0);
        hardlink.set_mode(0o644);
        tar.append_link(&mut hardlink, "package/hard.js", "package/lib/data.js")
            .unwrap();
        let bytes = tar.into_inner().unwrap();
        let target = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let decoded = PackStore::decode_package_tarball(&bytes, target.path(), "links").unwrap();
        assert_eq!(decoded.files.len(), 2);
        let store = PackStore::new(store_root.path()).unwrap();
        store
            .put_decoded_package("sha512-links", target.path(), &decoded, false)
            .unwrap();
        drop(store);
        let store = PackStore::new(store_root.path()).unwrap();
        let pack = store.get_package_pack("sha512-links").unwrap().unwrap();
        assert_eq!(
            pack.index.symlinks,
            vec![("lib/link.js".to_string(), "lib/data.js".to_string())]
        );
        let warm = tempdir().unwrap();
        store
            .materialize_pack("sha512-links", warm.path(), None)
            .unwrap();
        assert_eq!(
            fs::read(warm.path().join("lib/link.js")).unwrap(),
            b"payload"
        );
        assert_eq!(fs::read(warm.path().join("hard.js")).unwrap(), b"payload");
    }

    #[test]
    fn decoded_pack_rejects_escaping_symlink() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        tar.append_link(&mut link, "package/link", "../../outside")
            .unwrap();
        let bytes = tar.into_inner().unwrap();
        let target = tempdir().unwrap();
        assert!(PackStore::decode_package_tarball(&bytes, target.path(), "escape").is_err());
    }

    #[test]
    fn clean_store_removes_content_and_preserves_link_targets() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("store");
        let external = temp.path().join("external");
        fs::create_dir_all(&external).unwrap();
        fs::write(external.join("keep.txt"), "keep").unwrap();
        let store = PackStore::new(&root).unwrap();
        fs::write(store.cas_dir().join("cached"), "private content").unwrap();
        fs::create_dir_all(root.join("linked")).unwrap();
        rnpm_fs::create_junction(&root.join("linked/dep"), &external).unwrap();
        drop(store);
        PackStore::clean_at(&root).unwrap();
        assert!(!root.exists());
        assert_eq!(
            fs::read_to_string(external.join("keep.txt")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn test_ntfs_warm_materialize_skips_cas_disk_indirection_and_double_write() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();
        let integrity = "sha512-skipcasdoublewrite12345==";

        let files = [
            PackInputFile::new("index.js", 0o644, b"console.log('hello world');"),
            PackInputFile::new(
                "package.json",
                0o644,
                b"{\"name\": \"test-pkg\", \"version\": \"1.0.0\"}",
            ),
            PackInputFile::new(
                "lib/util.js",
                0o644,
                b"module.exports = { add: (a, b) => a + b };",
            ),
        ];

        // Create pack using deferred CAS mode (simulating cold install where CAS writes are deferred)
        let index = store.put_package_pack_deferred(integrity, &files).unwrap();
        assert_eq!(index.files.len(), 3);

        // Verify that store-v1/cas is completely empty (no CAS blobs on disk)
        let cas_dir = store.cas_dir();
        let cas_entries: Vec<_> = fs::read_dir(&cas_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            cas_entries.is_empty(),
            "CAS directory must be empty initially"
        );

        // Clear in-memory cache to force loading from disk on warm materialize
        store.clear_mmap_cache();

        // Warm materialize into target destination
        let target = tempdir().unwrap();
        let summary = store
            .materialize_pack(integrity, target.path(), None)
            .unwrap();

        assert_eq!(summary.entries_extracted, 3);
        assert_eq!(
            fs::read(target.path().join("index.js")).unwrap(),
            b"console.log('hello world');"
        );
        assert_eq!(
            fs::read(target.path().join("package.json")).unwrap(),
            b"{\"name\": \"test-pkg\", \"version\": \"1.0.0\"}"
        );
        assert_eq!(
            fs::read(target.path().join("lib/util.js")).unwrap(),
            b"module.exports = { add: (a, b) => a + b };"
        );

        // Verify that warm materialize did NOT redundantly create CAS blobs on disk!
        // Materialization should write directly from the in-memory pack buffer without CAS indirection.
        let cas_entries_after: Vec<_> = fs::read_dir(&cas_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            cas_entries_after.is_empty(),
            "CAS directory must remain empty: warm materialize must NOT double-write into CAS!"
        );
    }

    #[test]
    fn test_warm_materialize_repairs_corrupted_cas_blob_and_materializes_pristine_files() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();
        let integrity = "sha512-casrepairmtimeandsize777==";

        let original_data1 = b"export const alpha = 1;";
        let original_data2 = b"export const beta = 2;";
        let files = [
            PackInputFile::new("file1.js", 0o644, original_data1),
            PackInputFile::new("file2.js", 0o644, original_data2),
        ];

        // Create pack with CAS files populated
        let index = store.put_package_pack(integrity, &files).unwrap();
        let cas_path1 = index.files[0].cas_path.clone().unwrap();
        let cas_path2 = index.files[1].cas_path.clone().unwrap();

        assert!(cas_path1.is_file());
        assert!(cas_path2.is_file());

        // Corrupt file1 with size mismatch
        fs::write(&cas_path1, b"corrupted-size").unwrap();

        // Corrupt file2 with same size but altered content & mtime
        sleep(Duration::from_millis(25));
        let mut corrupted_data2 = original_data2.to_vec();
        corrupted_data2[0] ^= 0x42;
        fs::write(&cas_path2, &corrupted_data2).unwrap();

        // Clear in-memory mmap cache to simulate warm verification in a fresh process
        store.clear_mmap_cache();

        let target = tempdir().unwrap();
        let summary = store
            .materialize_pack(integrity, target.path(), None)
            .unwrap();

        assert_eq!(summary.entries_extracted, 2);

        // Verify target files are pristine directly from pack
        assert_eq!(
            fs::read(target.path().join("file1.js")).unwrap(),
            original_data1
        );
        assert_eq!(
            fs::read(target.path().join("file2.js")).unwrap(),
            original_data2
        );

        // Verify corrupted CAS blobs on disk were repaired
        assert_eq!(
            fs::read(&cas_path1).unwrap(),
            original_data1,
            "Corrupted size CAS blob must be repaired"
        );
        assert_eq!(
            fs::read(&cas_path2).unwrap(),
            original_data2,
            "Corrupted mtime CAS blob must be repaired"
        );
    }

    #[test]
    fn test_ntfs_materialize_speed_fast_path_vs_cas_indirection() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path()).unwrap();
        let integrity = "sha512-benchmaterialize999==";

        // Generate 100 files of 4 KiB each
        let file_data = vec![0xABu8; 4096];
        let mut files = Vec::new();
        let mut file_names = Vec::new();
        for i in 0..100 {
            file_names.push(format!("sub/file_{i}.dat"));
        }
        for name in &file_names {
            files.push(PackInputFile::new(name, 0o644, &file_data));
        }

        store.put_package_pack_deferred(integrity, &files).unwrap();

        let target_direct = tempdir().unwrap();
        let t_start_direct = std::time::Instant::now();
        let sum_direct = store
            .materialize_pack(integrity, target_direct.path(), None)
            .unwrap();
        let duration_direct = t_start_direct.elapsed();
        assert_eq!(sum_direct.entries_extracted, 100);

        for name in &file_names {
            assert_eq!(
                fs::read(target_direct.path().join(name)).unwrap(),
                file_data
            );
        }

        // Verify zero CAS files created during direct materialization
        let cas_entries: Vec<_> = fs::read_dir(store.cas_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            cas_entries.is_empty(),
            "Zero CAS files should be created during direct materialize"
        );

        // For comparison, measure how long writing CAS + CopyFileExW would take for 100 files
        let cas_sim_dir = tempdir().unwrap();
        let target_cas = tempdir().unwrap();
        let t_start_cas = std::time::Instant::now();
        for name in &file_names {
            let cas_file = cas_sim_dir.path().join(format!("cas_{name}.tmp"));
            PackStore::write_cas_file_safe(&cas_file, &file_data).unwrap();
            let dst = target_cas.path().join(name);
            if let Some(p) = dst.parent() {
                let _ = fs::create_dir_all(p);
            }
            rnpm_fs::copy_file_fast(&cas_file, &dst).unwrap();
        }
        let duration_cas = t_start_cas.elapsed();

        eprintln!(
            "Benchmark timing: Direct materialize = {:?}, CAS double-write indirection = {:?}",
            duration_direct, duration_cas
        );
    }

    #[test]
    fn test_populate_cas_from_installed_overwrites_zero_byte_or_truncated_file() {
        let temp = tempdir().unwrap();
        let store = PackStore::new(temp.path().join("store")).unwrap();
        let source_dir = temp.path().join("node_modules/pkg");
        fs::create_dir_all(&source_dir).unwrap();

        let src_file = source_dir.join("index.js");
        let content = b"console.log('repaired');";
        fs::write(&src_file, content).unwrap();

        let cas_dst = store.cas_dir().join("ab").join("abcdef123456");
        if let Some(p) = cas_dst.parent() {
            fs::create_dir_all(p).unwrap();
        }
        // Create a truncated 0-byte CAS file
        fs::write(&cas_dst, b"").unwrap();
        assert_eq!(fs::metadata(&cas_dst).unwrap().len(), 0);

        // Run populate_cas_from_installed: 0-byte CAS file must be repaired/overwritten
        store.populate_cas_from_installed(&[(src_file.clone(), cas_dst.clone())]);

        // Verify the 0-byte CAS file was overwritten with valid content
        assert_eq!(fs::read(&cas_dst).unwrap(), content);

        // Running it again with matching size should succeed idempotently
        store.populate_cas_from_installed(&[(src_file, cas_dst.clone())]);
        assert_eq!(fs::read(&cas_dst).unwrap(), content);
    }

    #[test]
    fn test_populate_cas_from_installed_atomic_no_leftover_temp_and_repairs_truncated() {
        let temp = tempdir().unwrap();
        let store = PackStore::new(temp.path().join("store")).unwrap();
        let source_dir = temp.path().join("node_modules/my-pkg");
        fs::create_dir_all(&source_dir).unwrap();

        let src_file = source_dir.join("main.js");
        let full_content = b"const msg = 'hello world from complete file payload!';\nexport default msg;\n";
        fs::write(&src_file, full_content).unwrap();

        let cas_dst = store.cas_file_path("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        let cas_parent = cas_dst.parent().unwrap();
        fs::create_dir_all(cas_parent).unwrap();

        // 1. Partial/truncated write: simulate a truncated CAS file (e.g. 10 bytes)
        fs::write(&cas_dst, &full_content[..10]).unwrap();
        assert_eq!(fs::metadata(&cas_dst).unwrap().len(), 10);

        // 2. Run populate_cas_from_installed: must atomically repair the truncated file
        store.populate_cas_from_installed(&[(src_file.clone(), cas_dst.clone())]);

        // 3. Verify destination has the complete valid content
        assert_eq!(fs::read(&cas_dst).unwrap(), full_content);

        // 4. Verify no leftover temp files exist in cas directory
        let mut temp_files = Vec::new();
        for entry in fs::read_dir(cas_parent).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains("tmp") {
                temp_files.push(name);
            }
        }
        assert!(
            temp_files.is_empty(),
            "Found leftover temporary files in CAS dir: {:?}",
            temp_files
        );

        // 5. Concurrent / multi-threaded run on multiple files
        let mut batch = Vec::new();
        for i in 0..20 {
            let src = source_dir.join(format!("file_{i}.js"));
            let content = format!("console.log('file payload {i}');");
            fs::write(&src, content.as_bytes()).unwrap();
            let dst = store.cas_dir().join(format!("c{i}")).join(format!("{i:064x}"));
            batch.push((src, dst));
        }
        store.populate_cas_from_installed(&batch);

        for (src, dst) in &batch {
            assert_eq!(fs::read(dst).unwrap(), fs::read(src).unwrap());
            let parent = dst.parent().unwrap();
            for entry in fs::read_dir(parent).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().to_string();
                assert!(!name.contains("tmp"), "Leftover temp file: {name}");
            }
        }
    }

    #[test]
    fn test_pack_materialization_directory_dedup() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path().join("cache")).unwrap();

        let integrity = "sha512-nested-dirs-test-dedup==";
        let files = [
            PackInputFile::new("a/b/c/d/deep1.js", 0o644, b"console.log('deep1');"),
            PackInputFile::new("a/b/c/d/deep2.js", 0o644, b"console.log('deep2');"),
            PackInputFile::new("a/b/c/sibling.js", 0o644, b"console.log('sibling');"),
            PackInputFile::new("a/b/other/file.js", 0o644, b"console.log('other');"),
            PackInputFile::new("package.json", 0o644, b"{\"name\":\"nested\"}"),
        ];

        store.put_package_pack(integrity, &files).unwrap();

        let target_dir = tempdir().unwrap();
        let summary = store
            .materialize_pack(integrity, target_dir.path(), None)
            .unwrap();

        assert_eq!(summary.entries_extracted, 5);
        assert_eq!(
            fs::read(target_dir.path().join("a/b/c/d/deep1.js")).unwrap(),
            b"console.log('deep1');"
        );
        assert_eq!(
            fs::read(target_dir.path().join("a/b/c/d/deep2.js")).unwrap(),
            b"console.log('deep2');"
        );
        assert_eq!(
            fs::read(target_dir.path().join("a/b/c/sibling.js")).unwrap(),
            b"console.log('sibling');"
        );
        assert_eq!(
            fs::read(target_dir.path().join("a/b/other/file.js")).unwrap(),
            b"console.log('other');"
        );
        assert_eq!(
            fs::read(target_dir.path().join("package.json")).unwrap(),
            b"{\"name\":\"nested\"}"
        );
    }

    #[test]
    fn test_materialize_and_extract_root_only_files_into_nonexistent_target_dir() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path().join("cache")).unwrap();

        let integrity = "sha512-root-only-nonexistent-target==";
        let files = [
            PackInputFile::new("package.json", 0o644, b"{\"name\":\"root-only\"}"),
            PackInputFile::new("index.js", 0o644, b"module.exports = 42;"),
        ];
        store.put_package_pack(integrity, &files).unwrap();

        // 1. materialize_pack into a nonexistent target directory
        let missing_target = dir.path().join("nested").join("node_modules").join("root-only");
        assert!(!missing_target.exists());
        let summary = store
            .materialize_pack(integrity, &missing_target, None)
            .unwrap();
        assert_eq!(summary.entries_extracted, 2);
        assert_eq!(
            fs::read(missing_target.join("package.json")).unwrap(),
            b"{\"name\":\"root-only\"}"
        );
        assert_eq!(
            fs::read(missing_target.join("index.js")).unwrap(),
            b"module.exports = 42;"
        );

        // 2. extract_and_populate_cas into a nonexistent target directory
        let pack = store.get_package_pack(integrity).unwrap().unwrap();
        let missing_cas_target = dir.path().join("cas_out").join("root-only");
        assert!(!missing_cas_target.exists());
        pack.extract_and_populate_cas(&missing_cas_target).unwrap();
        assert_eq!(
            fs::read(missing_cas_target.join("package.json")).unwrap(),
            b"{\"name\":\"root-only\"}"
        );
        assert_eq!(
            fs::read(missing_cas_target.join("index.js")).unwrap(),
            b"module.exports = 42;"
        );
    }

    #[test]
    fn test_tampered_idx_cas_path_ignored_and_confined_to_store() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path().join("store")).unwrap();
        let outside_victim = dir.path().join("outside_victim.txt");
        fs::write(&outside_victim, b"DO_NOT_OVERWRITE_SECRET").unwrap();

        let payload = b"legit-cas-file-payload-bytes";
        let integrity = "sha512-tampered-cas-path-test==";
        store
            .put_package_pack(
                integrity,
                &[PackInputFile::new("index.js", 0o644, payload)],
            )
            .unwrap();

        // Tamper .idx on disk so entry.cas_path points outside cas_dir
        let idx_path = store.idx_path(integrity);
        let mut idx = PackIndex::from_bytes(&fs::read(&idx_path).unwrap()).unwrap();
        idx.files[0].cas_path = Some(outside_victim.clone());
        idx.files[0].cas_mtime = Some(1); // force stamp mismatch -> repair path
        fs::write(&idx_path, idx.to_bytes().unwrap()).unwrap();

        store.clear_mmap_cache();
        let loaded = store.get_package_pack(integrity).unwrap().unwrap();

        assert_eq!(
            fs::read(&outside_victim).unwrap(),
            b"DO_NOT_OVERWRITE_SECRET",
            "Tampered entry.cas_path in .idx must NEVER cause reads/writes outside store.cas_dir()"
        );
        let resolved_cas = loaded.index.files[0].cas_path.as_ref().unwrap();
        assert!(resolved_cas.starts_with(store.cas_dir()));
    }

    #[test]
    fn test_put_package_pack_normalizes_and_deduplicates_mixed_prefixes() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path().join("store")).unwrap();
        let integrity = "sha512-norm-dedup-mixed-prefixes==";
        #[cfg(windows)]
        let files = [
            PackInputFile::new("foo/bar.js", 0o644, b"first"),
            PackInputFile::new("./foo/bar.js", 0o644, b"second"),
            PackInputFile::new("././foo/bar.js", 0o644, b"third"),
            PackInputFile::new("foo\\bar.js", 0o644, b"winner"),
        ];
        #[cfg(not(windows))]
        let files = [
            PackInputFile::new("foo/bar.js", 0o644, b"first"),
            PackInputFile::new("./foo/bar.js", 0o644, b"second"),
            PackInputFile::new("././foo/bar.js", 0o644, b"winner"),
        ];
        let idx = store.put_package_pack_deferred(integrity, &files).unwrap();
        assert_eq!(idx.files.len(), 1);
        assert_eq!(idx.files[0].path, "foo/bar.js");

        // On POSIX, backslashes are rejected as potential cross-platform path traversal.
        #[cfg(not(windows))]
        {
            let bs_err = store
                .put_package_pack_deferred(
                    integrity,
                    &[PackInputFile::new("foo\\bar.js", 0o644, b"bad")],
                )
                .unwrap_err();
            assert!(matches!(
                bs_err,
                CacheError::Fs(rnpm_fs::FsError::PathTraversal { .. })
            ));
        }

        // Leading '/' must still be rejected as an absolute path.
        let abs_err = store
            .put_package_pack_deferred(integrity, &[PackInputFile::new("/foo/bar.js", 0o644, b"bad")])
            .unwrap_err();
        assert!(matches!(abs_err, CacheError::Fs(rnpm_fs::FsError::AbsolutePath { .. })));

        store.clear_mmap_cache();
        let pack = store.get_package_pack(integrity).unwrap().unwrap();
        assert_eq!(pack.get_file_slice("foo/bar.js").unwrap(), b"winner");
    }

    #[test]
    fn test_put_package_from_tarball_duplicate_compaction_bounded_size() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path().join("store")).unwrap();

        let big_old = vec![b'A'; 128 * 1024];
        let small_new = b"tiny-final-content";
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        {
            let mut tar = tar::Builder::new(&mut gz);
            for path in ["package/sub/data.bin", "package/sub/./data.bin"] {
                let mut h = tar::Header::new_gnu();
                h.set_size(big_old.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                tar.append_data(&mut h, path, &big_old[..]).unwrap();
            }
            let mut h_final = tar::Header::new_gnu();
            h_final.set_size(small_new.len() as u64);
            h_final.set_mode(0o644);
            h_final.set_cksum();
            tar.append_data(&mut h_final, "package//./sub/data.bin", &small_new[..])
                .unwrap();
            tar.finish().unwrap();
        }
        let tgz = gz.finish().unwrap();
        let integrity = rnpm_core::Integrity::from_bytes(&tgz, Algorithm::Sha512).to_string();

        let idx = store.put_package_from_tarball(&integrity, &tgz).unwrap();
        assert_eq!(idx.files.len(), 1);
        assert_eq!(idx.files[0].path, "sub/data.bin");
        assert!(
            idx.total_pack_size <= PACK_ALIGNMENT as u64,
            "Compacted pack size {} must match retained live entry (<= 4096), not 256KB+ discarded duplicates",
            idx.total_pack_size
        );
        let pack_disk_len = fs::metadata(store.pack_path(&integrity)).unwrap().len();
        assert_eq!(pack_disk_len, PACK_ALIGNMENT as u64);

        store.clear_mmap_cache();
        let pack = store.get_package_pack(&integrity).unwrap().unwrap();
        assert_eq!(pack.get_file_slice("sub/data.bin").unwrap(), small_new);
    }

    #[test]
    fn test_decode_package_tarball_subdirectory_hardlink_and_gitignore_curdir() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        {
            let mut tar = tar::Builder::new(&mut gz);
            let target_bytes = b"export const ok = true;\n";
            let mut h1 = tar::Header::new_gnu();
            h1.set_size(target_bytes.len() as u64);
            h1.set_mode(0o644);
            h1.set_cksum();
            tar.append_data(&mut h1, "package/lib/src/target.js", &target_bytes[..])
                .unwrap();

            let mut hl = tar::Header::new_gnu();
            hl.set_entry_type(tar::EntryType::Link);
            hl.set_size(0);
            hl.set_mode(0o644);
            hl.set_cksum();
            tar.append_link(&mut hl, "package/lib/src/alias.js", "package/lib/src/target.js")
                .unwrap();

            let ni = b"ignore-me\n";
            let mut h_ni = tar::Header::new_gnu();
            h_ni.set_size(ni.len() as u64);
            h_ni.set_mode(0o644);
            h_ni.set_cksum();
            tar.append_data(&mut h_ni, "package/sub/./.npmignore", &ni[..])
                .unwrap();

            let gi = b"git-ignore-should-not-win\n";
            let mut h_gi = tar::Header::new_gnu();
            h_gi.set_size(gi.len() as u64);
            h_gi.set_mode(0o644);
            h_gi.set_cksum();
            tar.append_data(&mut h_gi, "package/sub/.gitignore", &gi[..])
                .unwrap();

            tar.finish().unwrap();
        }
        let tgz = gz.finish().unwrap();

        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("pkg");
        let decoded = PackStore::decode_package_tarball(&tgz, &target_dir, "pkg").unwrap();

        let alias_file = decoded
            .files
            .iter()
            .find(|f| f.path.ends_with("alias.js"))
            .expect("subdirectory hardlink must resolve across platforms");
        assert_eq!(alias_file.data.as_slice(), b"export const ok = true;\n");

        let npmignore_file = decoded
            .files
            .iter()
            .find(|f| f.path.ends_with(".npmignore"))
            .expect(".npmignore must be retained");
        assert_eq!(npmignore_file.data.as_slice(), b"ignore-me\n");

        // Verify put_package_from_tarball_deferred also preserves sub/.npmignore over sub/.gitignore
        let store = PackStore::new(dir.path().join("store")).unwrap();
        let integ = rnpm_core::Integrity::from_bytes(&tgz, Algorithm::Sha512).to_string();
        store.put_package_from_tarball_deferred(&integ, &tgz).unwrap();
        let pack = store.get_package_pack(&integ).unwrap().unwrap();
        assert_eq!(pack.get_file_slice("sub/.npmignore").unwrap(), b"ignore-me\n");
    }

    #[test]
    fn test_materialize_unnormalized_dots_and_double_slashes() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path().join("store")).unwrap();
        let files = vec![
            PackInputFile::new("./nested/./a.js", 0o644, b"export const a = 1;\n"),
            PackInputFile::new("nested//b.js", 0o644, b"export const b = 2;\n"),
        ];
        let integ = "sha512-unnormalizedtest0000000000000000000000000000000000000000000000000000000000000000000000000000";
        store.put_package_pack(integ, &files).unwrap();
        let pack = store.get_package_pack(integ).unwrap().unwrap();
        let out = dir.path().join("out");
        pack.materialize_to(&out, None).unwrap();
        assert_eq!(
            std::fs::read(out.join("nested").join("a.js")).unwrap(),
            b"export const a = 1;\n"
        );
        assert_eq!(
            std::fs::read(out.join("nested").join("b.js")).unwrap(),
            b"export const b = 2;\n"
        );
    }

    #[test]
    fn test_put_package_from_tarball_hardens_suid_sparse_invalid_utf8_and_tampered_idx() {
        let dir = tempdir().unwrap();
        let store = PackStore::new(dir.path().join("store")).unwrap();

        // 1. SUID on directory entry must fail ForbiddenModeBits
        let tgz_suid = {
            let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
            {
                let mut tar = tar::Builder::new(&mut gz);
                let mut hd = tar::Header::new_gnu();
                hd.set_entry_type(tar::EntryType::Directory);
                hd.set_size(0);
                hd.set_mode(0o4755);
                hd.set_cksum();
                tar.append_data(&mut hd, "package/bin/", &[][..]).unwrap();
                tar.finish().unwrap();
            }
            gz.finish().unwrap()
        };
        let integ_suid =
            rnpm_core::Integrity::from_bytes(&tgz_suid, Algorithm::Sha512).to_string();
        let res_suid = store.put_package_from_tarball(&integ_suid, &tgz_suid);
        assert!(
            matches!(
                res_suid,
                Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenModeBits { .. }))
            ),
            "Expected ForbiddenModeBits, got: {res_suid:?}"
        );

        // 2. Sparse entry with invalid UTF-8 path must report InvalidUtf8Path before ForbiddenSparseFile
        let tgz_sparse_invalid = {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::GNUSparse);
            header.set_size(0);
            header.set_mode(0o644);
            header.as_gnu_mut().unwrap().set_real_size(0);
            let bad = [b'p', b'a', b'c', b'k', b'a', b'g', b'e', b'/', 0xfe, b'b', b'i', b'n'];
            header.as_mut_bytes()[..bad.len()].copy_from_slice(&bad);
            header.set_cksum();
            let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
            {
                let mut builder = tar::Builder::new(&mut gz);
                builder.append(&header, std::io::Cursor::new(&[])).unwrap();
                builder.finish().unwrap();
            }
            gz.finish().unwrap()
        };
        let integ_sp = rnpm_core::Integrity::from_bytes(&tgz_sparse_invalid, Algorithm::Sha512)
            .to_string();
        let res_sp = store.put_package_from_tarball(&integ_sp, &tgz_sparse_invalid);
        assert!(
            matches!(
                res_sp,
                Err(CacheError::Fs(rnpm_fs::FsError::InvalidUtf8Path { .. }))
            ),
            "Expected InvalidUtf8Path, got: {res_sp:?}"
        );

        // 2b. Sparse entry with valid UTF-8 path must report ForbiddenSparseFile
        let tgz_sparse_ok = {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::GNUSparse);
            header.set_size(0);
            header.set_mode(0o644);
            header.as_gnu_mut().unwrap().set_real_size(0);
            let name = b"package/sparse.bin";
            header.as_mut_bytes()[..name.len()].copy_from_slice(name);
            header.set_cksum();
            let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
            {
                let mut builder = tar::Builder::new(&mut gz);
                builder.append(&header, std::io::Cursor::new(&[])).unwrap();
                builder.finish().unwrap();
            }
            gz.finish().unwrap()
        };
        let integ_sp_ok =
            rnpm_core::Integrity::from_bytes(&tgz_sparse_ok, Algorithm::Sha512).to_string();
        assert!(matches!(
            store.put_package_from_tarball(&integ_sp_ok, &tgz_sparse_ok),
            Err(CacheError::Fs(rnpm_fs::FsError::ForbiddenSparseFile { .. }))
        ));

        // 3. Tampered .idx cas_path is ignored & derived inside store cas_dir; tampered entry path purges pack
        let integ_ok = "sha512-tampertest000000000000000000000000000000000000000000000000000000000000000000000000000000==";
        let files = [PackInputFile::new("index.js", 0o644, b"console.log(1);")];
        store.put_package_pack(integ_ok, &files).unwrap();
        store.clear_mmap_cache();

        let idx_path = store.idx_path(integ_ok);
        let idx_raw = fs::read_to_string(&idx_path).unwrap();
        let mut parsed: PackIndex = serde_json::from_str(&idx_raw).unwrap();
        let rogue_cas = dir.path().join("outside_cas_target");
        parsed.files[0].cas_path = Some(rogue_cas.clone());
        fs::write(&idx_path, parsed.to_bytes().unwrap()).unwrap();

        let loaded = store.get_package_pack(integ_ok).unwrap().unwrap();
        assert!(!rogue_cas.exists());
        assert_ne!(loaded.index.files[0].cas_path.as_deref(), Some(rogue_cas.as_path()));

        // Now tamper entry.path to traversal path -> get_package_pack must purge and return Ok(None)
        store.clear_mmap_cache();
        parsed.files[0].path = "../escape.js".to_string();
        fs::write(&idx_path, parsed.to_bytes().unwrap()).unwrap();
        assert!(store.get_package_pack(integ_ok).unwrap().is_none());
        assert!(!idx_path.exists());
    }
}
