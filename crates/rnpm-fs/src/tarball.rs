use crate::error::FsError;
use crate::fast_hash::{fx_map, fx_set, FxHashMap, FxHashSet};
use flate2::read::GzDecoder;
use path_clean::clean;
use rnpm_core::integrity::{Algorithm, Integrity};
use rnpm_core::manifest::Manifest;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::{Archive, Builder, Header};

/// Normalized POSIX timestamp for tarball reproducibility:
/// 1985-10-26 08:15:00 UTC (499162500 seconds) - standard npm pack epoch.
pub const NPM_PACK_EPOCH_MTIME: u64 = 499162500;

/// Default file permission mode: rw-r--r-- (0o644)
pub const NPM_DEFAULT_FILE_MODE: u32 = 0o644;
/// Executable file permission mode: rwxr-xr-x (0o755)
pub const NPM_EXECUTABLE_FILE_MODE: u32 = 0o755;

#[derive(Debug, Clone, Copy)]
pub struct TarLimits {
    pub max_entries: usize,
    pub max_uncompressed_size: u64,
    pub max_compression_ratio: f64,
    pub max_single_entry_size: u64,
    pub max_symlinks: usize,
    pub max_path_depth: usize,
    pub max_directories: usize,
}

impl Default for TarLimits {
    fn default() -> Self {
        Self {
            max_entries: 50_000,
            max_uncompressed_size: 512 * 1024 * 1024, // 512 MB
            max_compression_ratio: 100.0,
            max_single_entry_size: 256 * 1024 * 1024, // 256 MB
            max_symlinks: 5_000,
            max_path_depth: 32,
            max_directories: 10_000,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExtractionSummary {
    pub entries_extracted: usize,
    pub total_uncompressed_bytes: u64,
    pub inflate_duration: std::time::Duration,
    pub materialize_duration: std::time::Duration,
}

static FILES_CREATED: AtomicU64 = AtomicU64::new(0);
static BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// Record a batch of files created and bytes written.
pub fn record_files_created_batch(count: u64, bytes: u64) {
    FILES_CREATED.fetch_add(count, Ordering::Relaxed);
    BYTES_WRITTEN.fetch_add(bytes, Ordering::Relaxed);
}

/// Record a single file created and bytes written.
pub fn record_file_created(bytes: u64) {
    FILES_CREATED.fetch_add(1, Ordering::Relaxed);
    BYTES_WRITTEN.fetch_add(bytes, Ordering::Relaxed);
}

/// Returns the total count of files created.
pub fn files_created() -> u64 {
    FILES_CREATED.load(Ordering::Relaxed)
}

/// Returns the total bytes written to disk.
pub fn bytes_written() -> u64 {
    BYTES_WRITTEN.load(Ordering::Relaxed)
}

/// Reset all filesystem counters (files created, bytes written, junctions created, block clones).
pub fn reset_fs_counters() {
    FILES_CREATED.store(0, Ordering::Relaxed);
    BYTES_WRITTEN.store(0, Ordering::Relaxed);
    crate::junction::reset_junctions_created();
    crate::block_clone::reset_block_clones();
}

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct CountingReader<R> {
    inner: R,
    bytes_read: Arc<AtomicU64>,
}

impl<R: Read> CountingReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_counter(inner: R, bytes_read: Arc<AtomicU64>) -> Self {
        Self { inner, bytes_read }
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    pub fn counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.bytes_read)
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Fast zero-allocation validation and first-component stripping for clean ASCII tar paths.
/// Returns:
/// - `Ok(None)` if the entry is just the root component (e.g. `"package/"` or `"."`)
/// - `Ok(Some((rel_str, depth)))` if valid and clean ASCII without escapes/traversal
/// - `Err(())` if caller should fall back to full `Path`-based validation/normalization
#[inline]
pub(crate) fn fast_validate_and_strip_ascii(s: &str) -> Result<Option<(&str, usize)>, ()> {
    if !s.is_ascii()
        || s.contains('\\')
        || s.contains("..")
        || s.contains(':')
        || s.starts_with('/')
        || s.contains("/./")
        || s.contains("//")
        || s.ends_with("/.")
    {
        return Err(());
    }

    let mut trimmed = s;
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }
    if trimmed.is_empty() || trimmed == "." {
        return Ok(None);
    }

    let Some(slash) = trimmed.find('/') else {
        // Validate single root component in case it contains reserved/invalid chars
        let root_seg = trimmed;
        if !is_clean_ascii_segment(root_seg) {
            return Err(());
        }
        return Ok(None);
    };

    let root_seg = &trimmed[..slash];
    if !is_clean_ascii_segment(root_seg) {
        return Err(());
    }

    let mut rel = &trimmed[slash + 1..];
    while let Some(r) = rel.strip_prefix("./") {
        rel = r;
    }
    rel = rel.trim_end_matches('/');
    if rel.is_empty() || rel == "." {
        return Ok(None);
    }

    let mut depth = 0usize;
    for seg in rel.split('/') {
        if seg.is_empty() || !is_clean_ascii_segment(seg) {
            return Err(());
        }
        depth += 1;
    }

    Ok(Some((rel, depth)))
}

#[inline]
fn is_clean_ascii_segment(seg: &str) -> bool {
    if seg.ends_with('.') || seg.ends_with(' ') {
        return false;
    }
    for &b in seg.as_bytes() {
        if b < 0x20 || matches!(b, b':' | b'\\' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|') {
            return false;
        }
    }
    !is_windows_reserved_name(seg)
}

/// Joins `base` (already a clean verbatim path) with a clean slash-separated relative path `rel`
/// using native separators in a single `PathBuf` allocation.
#[inline]
pub(crate) fn join_clean_rel(base: &Path, rel: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let mut out = std::ffi::OsString::with_capacity(base.as_os_str().len() + 1 + rel.len());
        out.push(base.as_os_str());
        if !base.as_os_str().as_encoded_bytes().ends_with(b"\\") {
            out.push("\\");
        }
        if !rel.contains('/') {
            out.push(rel);
        } else {
            let mut buf = [0u8; 256];
            let bytes = rel.as_bytes();
            if bytes.len() <= buf.len() {
                for (i, &b) in bytes.iter().enumerate() {
                    buf[i] = if b == b'/' { b'\\' } else { b };
                }
                debug_assert!(std::str::from_utf8(&buf[..bytes.len()]).is_ok());
                // SAFETY: `rel` is valid UTF-8 and replacing single-byte ASCII `/` with `\` preserves UTF-8.
                let s = unsafe { std::str::from_utf8_unchecked(&buf[..bytes.len()]) };
                out.push(s);
            } else {
                out.push(rel.replace('/', "\\"));
            }
        }
        PathBuf::from(out)
    }
    #[cfg(not(windows))]
    {
        base.join(rel)
    }
}

/// Helper that creates `dir` and registers it and all intermediate ancestors down to `root`
/// in both `created_dirs` and `safe_cache` so that directory creation and ancestor symlink
/// checks are performed at most once per unique directory hierarchy.
fn ensure_dir_created(
    dir: &Path,
    root: &Path,
    created_dirs: &mut FxHashSet<PathBuf>,
    safe_cache: &mut HashSet<PathBuf>,
    track_safe_cache: bool,
) -> Result<(), FsError> {
    if created_dirs.contains(dir) {
        return Ok(());
    }

    #[cfg(windows)]
    let fast_ok = {
        let mut missing: Vec<&Path> = Vec::with_capacity(8);
        let mut cur = Some(dir);
        while let Some(p) = cur {
            if created_dirs.contains(p) || !p.starts_with(root) {
                break;
            }
            missing.push(p);
            cur = p.parent();
        }
        let mut ok = true;
        for &p in missing.iter().rev() {
            let res = crate::path::with_verbatim_wide(p, |wide| {
                extern "system" {
                    fn CreateDirectoryW(
                        lpPathName: *const u16,
                        lpSecurityAttributes: *mut std::ffi::c_void,
                    ) -> i32;
                    fn GetLastError() -> u32;
                }
                const ERROR_ALREADY_EXISTS: u32 = 183;
                let r = unsafe { CreateDirectoryW(wide.as_ptr(), std::ptr::null_mut()) };
                if r == 0 {
                    let err = unsafe { GetLastError() };
                    if err != ERROR_ALREADY_EXISTS {
                        return Err(err);
                    }
                }
                Ok(())
            });
            if res.is_err() {
                ok = false;
                break;
            }
        }
        ok
    };

    #[cfg(not(windows))]
    let fast_ok = false;

    if !fast_ok {
        if let Err(e) = fs::create_dir_all(dir) {
            #[cfg(unix)]
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                if let Some(parent) = dir.parent() {
                    if let Ok(meta) = fs::metadata(parent) {
                        use std::os::unix::fs::PermissionsExt;
                        let mut perms = meta.permissions();
                        if perms.mode() & 0o200 == 0 {
                            perms.set_mode(perms.mode() | 0o700);
                            let _ = fs::set_permissions(parent, perms);
                        }
                    }
                }
            }
            #[cfg(windows)]
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                if let Some(parent) = dir.parent() {
                    if let Ok(meta) = fs::metadata(parent) {
                        let mut perms = meta.permissions();
                        if perms.readonly() {
                            perms.set_readonly(false);
                            let _ = fs::set_permissions(parent, perms);
                        }
                    }
                }
            }
            fs::create_dir_all(dir)?;
        }
    }

    let mut curr = Some(dir);
    while let Some(p) = curr {
        if !p.starts_with(root) {
            break;
        }
        let inserted = created_dirs.insert(p.to_path_buf());
        if track_safe_cache {
            safe_cache.insert(p.to_path_buf());
        }
        if !inserted {
            break;
        }
        curr = p.parent();
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrackedKind {
    Dir,
    File,
    Symlink,
}

pub(crate) struct TrackedEntry {
    pub(crate) kind: TrackedKind,
    pub(crate) exact_upper: Option<String>,
    pub(crate) file_idx: Option<usize>,
}

pub(crate) enum TrackReject {
    CaseCollision,
    SymlinkAncestor(String),
}

pub(crate) struct PathCollisionTracker {
    pub(crate) map: FxHashMap<String, TrackedEntry>,
    pub(crate) has_symlinks: bool,
}

impl PathCollisionTracker {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            map: fx_map(cap),
            has_symlinks: false,
        }
    }

    #[inline]
    pub(crate) fn lower_cow(s: &str) -> std::borrow::Cow<'_, str> {
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            std::borrow::Cow::Owned(s.to_ascii_lowercase())
        } else {
            std::borrow::Cow::Borrowed(s)
        }
    }

    pub(crate) fn record(
        &mut self,
        norm_exact: &str,
        kind: TrackedKind,
    ) -> Result<(bool, Option<usize>), TrackReject> {
        let has_upper = norm_exact.bytes().any(|b| b.is_ascii_uppercase());
        let norm_lower: std::borrow::Cow<'_, str> = if has_upper {
            std::borrow::Cow::Owned(norm_exact.to_ascii_lowercase())
        } else {
            std::borrow::Cow::Borrowed(norm_exact)
        };
        let is_dir = kind == TrackedKind::Dir;

        // Check ancestors first if symlink ancestors or file-vs-dir collisions could exist
        let mut end = norm_lower.len();
        while let Some(pos) = norm_lower[..end].rfind('/') {
            let prefix = &norm_lower[..pos];
            if let Some(anc) = self.map.get(prefix) {
                match anc.kind {
                    TrackedKind::Symlink => {
                        return Err(TrackReject::SymlinkAncestor(norm_exact[..pos].to_string()));
                    }
                    TrackedKind::File => return Err(TrackReject::CaseCollision),
                    TrackedKind::Dir => break,
                }
            }
            end = pos;
        }

        if let Some(existing) = self.map.get_mut(norm_lower.as_ref()) {
            let exact_matches = match &existing.exact_upper {
                Some(u) => u == norm_exact,
                None => !has_upper && norm_lower.as_ref() == norm_exact,
            };
            if !exact_matches {
                return Err(TrackReject::CaseCollision);
            }
            if (is_dir && existing.kind != TrackedKind::Dir)
                || (!is_dir && existing.kind == TrackedKind::Dir)
            {
                return Err(TrackReject::CaseCollision);
            }
            let prev_file_idx = existing.file_idx;
            if kind == TrackedKind::Symlink {
                self.has_symlinks = true;
                existing.file_idx = None;
            }
            existing.kind = kind;
            return Ok((true, prev_file_idx));
        }

        // Insert missing ancestor directories
        let mut end = norm_lower.len();
        while let Some(pos) = norm_lower[..end].rfind('/') {
            let prefix = &norm_lower[..pos];
            if self.map.contains_key(prefix) {
                break;
            }
            let prefix_exact = &norm_exact[..pos];
            let anc_upper = prefix_exact
                .bytes()
                .any(|b| b.is_ascii_uppercase())
                .then(|| prefix_exact.to_string());
            self.map.insert(
                prefix.to_string(),
                TrackedEntry {
                    kind: TrackedKind::Dir,
                    exact_upper: anc_upper,
                    file_idx: None,
                },
            );
            end = pos;
        }

        if kind == TrackedKind::Symlink {
            self.has_symlinks = true;
        }
        self.map.insert(
            norm_lower.into_owned(),
            TrackedEntry {
                kind,
                exact_upper: if has_upper {
                    Some(norm_exact.to_string())
                } else {
                    None
                },
                file_idx: None,
            },
        );
        Ok((false, None))
    }

    #[inline]
    pub(crate) fn set_file_idx(&mut self, norm_exact: &str, idx: usize) {
        let lower = Self::lower_cow(norm_exact);
        if let Some(entry) = self.map.get_mut(lower.as_ref()) {
            entry.file_idx = Some(idx);
        }
    }

    #[inline]
    pub(crate) fn is_regular_file(&self, rel: &str) -> bool {
        let lower = Self::lower_cow(rel);
        self.map
            .get(lower.as_ref())
            .is_some_and(|e| e.kind == TrackedKind::File)
    }

    #[inline]
    pub(crate) fn has_symlink_ancestor(&self, rel: &str) -> Option<String> {
        if !self.has_symlinks {
            return None;
        }
        let lower = Self::lower_cow(rel);
        if let Some(e) = self.map.get(lower.as_ref()) {
            if e.kind == TrackedKind::Symlink {
                return Some(rel.to_string());
            }
        }
        let mut end = lower.len();
        while let Some(pos) = lower[..end].rfind('/') {
            let prefix = &lower[..pos];
            if let Some(e) = self.map.get(prefix) {
                if e.kind == TrackedKind::Symlink {
                    return Some(rel[..pos].to_string());
                }
            }
            end = pos;
        }
        None
    }
}

/// Extract a .tar.gz stream into destination, stripping the archive's first root component
/// and enforcing all security and tar-bomb defenses.
pub fn extract_tar_gz<R: Read>(
    reader: R,
    destination: &Path,
    limits: Option<TarLimits>,
) -> Result<ExtractionSummary, FsError> {
    struct PendingTarFile {
        path: PathBuf,
        start: usize,
        len: usize,
        mode: u32,
    }

    let start_extract = std::time::Instant::now();
    let mut inflate_nanos = 0u64;
    let limits = limits.unwrap_or_default();
    let verbatim_dest = crate::path::to_verbatim_path(destination);

    // Fast-path detection: if `create_dir` creates `verbatim_dest`, it is guaranteed fresh/empty
    // without issuing a `read_dir` syscall.
    let is_fresh_dest = match fs::create_dir(&verbatim_dest) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match fs::read_dir(&verbatim_dest) {
            Ok(mut it) => it.next().is_none(),
            Err(_) => true,
        },
        Err(_) => {
            fs::create_dir_all(&verbatim_dest)?;
            match fs::read_dir(&verbatim_dest) {
                Ok(mut it) => it.next().is_none(),
                Err(_) => true,
            }
        }
    };
    let clean_dest = clean(&verbatim_dest);

    let mut created_dirs: FxHashSet<PathBuf> = fx_set(16);
    created_dirs.insert(clean_dest.clone());
    created_dirs.insert(verbatim_dest.clone());

    let mut verified_safe_ancestors: HashSet<PathBuf> = if is_fresh_dest {
        HashSet::new()
    } else {
        let mut s = HashSet::new();
        s.insert(clean_dest.clone());
        s.insert(verbatim_dest.clone());
        s
    };

    let compressed_counter = Arc::new(AtomicU64::new(0));
    let buf_reader = io::BufReader::with_capacity(64 * 1024, reader);
    let counting_reader = CountingReader::with_counter(buf_reader, Arc::clone(&compressed_counter));
    let gz = GzDecoder::new(counting_reader);
    let buffered_gz = io::BufReader::with_capacity(64 * 1024, gz);
    let mut archive = Archive::new(buffered_gz);

    let mut entry_count = 0;
    let mut directory_count = 0usize;
    let mut symlink_count = 0;
    let mut total_uncompressed = 0u64;
    let mut tracker = PathCollisionTracker::with_capacity(32);
    let mut saw_npmignores: FxHashSet<String> = fx_set(4);
    let mut hardlink_targets: FxHashMap<PathBuf, PathBuf> = fx_map(0);
    let mut copy_buf: Vec<u8> = Vec::new();
    let mut scratch_buf: Vec<u8> = Vec::new();
    let mut wide_buf: Vec<u16> = Vec::with_capacity(260);
    let mut pending_files: Vec<PendingTarFile> = Vec::with_capacity(64);
    let mut pending_arena: Vec<u8> = Vec::with_capacity(128 * 1024);
    let mut recorded_files: u64 = 0;
    let mut recorded_bytes: u64 = 0;
    const PENDING_FLUSH_BYTES: usize = 4 * 1024 * 1024;
    let cached_cfg = crate::writer::determine_writer_config(&verbatim_dest, None);

    let flush_pending = |pending_files: &mut Vec<PendingTarFile>,
                         pending_arena: &mut Vec<u8>,
                         created_dirs: &mut FxHashSet<PathBuf>,
                         verified_safe_ancestors: &mut HashSet<PathBuf>,
                         recorded_files: &mut u64,
                         recorded_bytes: &mut u64,
                         wide_buf: &mut Vec<u16>|
     -> Result<(), FsError> {
        if pending_files.is_empty() {
            return Ok(());
        }
        let batch_len = pending_files.len() as u64;
        let batch_bytes = pending_arena.len() as u64;

        let mut unique_dirs: FxHashSet<&Path> = fx_set(pending_files.len() / 2 + 1);
        for f in pending_files.iter() {
            if let Some(p) = f.path.parent() {
                if !created_dirs.contains(p) {
                    unique_dirs.insert(p);
                }
            }
        }
        if !unique_dirs.is_empty() {
            let dir_refs: Vec<&Path> = unique_dirs.iter().copied().collect();
            crate::writer::precreate_directories(dir_refs).map_err(FsError::Io)?;
            for dir in unique_dirs {
                let mut curr = Some(dir);
                while let Some(p) = curr {
                    if !p.starts_with(&verbatim_dest) {
                        break;
                    }
                    let inserted = created_dirs.insert(p.to_path_buf());
                    if !is_fresh_dest {
                        verified_safe_ancestors.insert(p.to_path_buf());
                    }
                    if !inserted {
                        break;
                    }
                    curr = p.parent();
                }
            }
        }

        if pending_files.len() < 4 {
            for item in pending_files.iter() {
                crate::writer::write_file_fast_buf(
                    &item.path,
                    &pending_arena[item.start..item.start + item.len],
                    item.mode,
                    cached_cfg.preallocate_threshold,
                    wide_buf,
                    true,
                )?;
            }
            pending_files.clear();
        } else {
            let arena_slice = &pending_arena[..];
            let mut refs = Vec::with_capacity(pending_files.len());
            for item in pending_files.drain(..) {
                refs.push(crate::writer::MaterializeFileRef {
                    path: item.path,
                    data: &arena_slice[item.start..item.start + item.len],
                    mode: item.mode,
                    package_id: None,
                    source_path: None,
                    expected_sha256: None,
                    source_verified: false,
                });
            }
            crate::writer::materialize_files_parallel_refs(refs, &cached_cfg)?;
        }
        pending_arena.clear();
        *recorded_files += batch_len;
        *recorded_bytes += batch_bytes;
        Ok(())
    };
    let _ = &flush_pending;

    let entries = archive.entries().map_err(FsError::Io)?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(FsError::Io)?;

        let entry_type = entry.header().entry_type();

        // Skip EntryType::XGlobalHeader without failing validation
        if entry_type == tar::EntryType::XGlobalHeader || entry_type.as_byte() == b'g' {
            continue;
        }

        entry_count += 1;
        if entry_count > limits.max_entries {
            return Err(FsError::TarBombLimitExceeded {
                limit_type: "entry count".to_string(),
                detail: format!(
                    "Tarball exceeded maximum allowed entries: {}",
                    limits.max_entries
                ),
            });
        }

        // Security check: SUID / SGID mode bits
        let mode = entry.header().mode().unwrap_or(0);
        if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
            return Err(FsError::ForbiddenModeBits {
                mode,
                path: entry.path().unwrap_or_default().to_path_buf(),
            });
        }

        // Check non-UTF-8 path bytes or embedded null bytes before sparse/root checks.
        let path_ascii_result: Result<Option<(String, usize)>, ()> = {
            let path_bytes = entry.path_bytes();
            if path_bytes.contains(&0) {
                return Err(FsError::PathTraversal {
                    path: PathBuf::from(String::from_utf8_lossy(&path_bytes).into_owned()),
                });
            }
            let s = std::str::from_utf8(&path_bytes).map_err(|_| FsError::InvalidUtf8Path {
                path: PathBuf::from(String::from_utf8_lossy(&path_bytes).into_owned()),
            })?;
            match fast_validate_and_strip_ascii(s) {
                Ok(None) => Ok(None),
                Ok(Some((rel, depth))) => Ok(Some((rel.to_string(), depth))),
                Err(()) => Err(()),
            }
        };

        // Reject sparse entries before skipping archive roots.
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
            let err_path = match path_ascii_result {
                Ok(Some((s, _))) => PathBuf::from(s),
                _ => entry.path().unwrap_or_default().to_path_buf(),
            };
            return Err(FsError::ForbiddenSparseFile { path: err_path });
        }

        let fast_ascii: Option<(String, usize)> = match path_ascii_result {
            Ok(None) => continue,
            Ok(Some((rel, depth))) => {
                if entry_type.is_file() {
                    if rel == ".npmignore" || rel.ends_with("/.npmignore") {
                        if !saw_npmignores.contains(&rel) {
                            saw_npmignores.insert(rel.clone());
                        }
                        Some((rel, depth))
                    } else if rel == ".gitignore" || rel.ends_with("/.gitignore") {
                        let rewritten = if rel.len() == ".gitignore".len() {
                            ".npmignore".to_string()
                        } else {
                            format!("{}/.npmignore", &rel[..rel.len() - "/.gitignore".len()])
                        };
                        if saw_npmignores.contains(&rewritten) {
                            continue;
                        }
                        Some((rewritten, depth))
                    } else {
                        Some((rel, depth))
                    }
                } else {
                    Some((rel, depth))
                }
            }
            Err(()) => None,
        };

        let (mut relative_path_opt, target_path, norm_exact, path_depth) =
            if let Some((rel_str, depth)) = fast_ascii {
                let target_path = join_clean_rel(&clean_dest, &rel_str);
                (None, target_path, rel_str, depth)
            } else {
                let path_bytes = entry.path_bytes();
                let raw_path = match entry.path() {
                    Ok(p) => p.to_path_buf(),
                    Err(_) if std::str::from_utf8(&path_bytes).is_err() => {
                        return Err(FsError::InvalidUtf8Path {
                            path: PathBuf::from(String::from_utf8_lossy(&path_bytes).into_owned()),
                        });
                    }
                    Err(e) => return Err(FsError::Io(e)),
                };

                validate_entry_path(&raw_path)?;

                let mut relative_path = match strip_package_prefix(&raw_path) {
                    Some(p) => {
                        let cleaned: PathBuf = p
                            .components()
                            .filter(|c| !matches!(c, Component::CurDir))
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
                    } else if relative_path.file_name() == Some(std::ffi::OsStr::new(".gitignore"))
                    {
                        let ni = relative_path.with_file_name(".npmignore");
                        let ni_str = ni.to_string_lossy().replace('\\', "/");
                        if saw_npmignores.contains(&ni_str) {
                            continue;
                        }
                        relative_path = ni;
                    }
                }

                validate_entry_path(&relative_path)?;

                let mut path_depth = 0usize;
                let mut target_path = PathBuf::with_capacity(
                    clean_dest.as_os_str().len() + relative_path.as_os_str().len() + 2,
                );
                target_path.push(&clean_dest);
                let mut norm_exact = String::with_capacity(relative_path.as_os_str().len());
                for c in relative_path.components() {
                    if let Component::Normal(s) = c {
                        path_depth += 1;
                        target_path.push(s);
                        if !norm_exact.is_empty() {
                            norm_exact.push('/');
                        }
                        norm_exact.push_str(&s.to_string_lossy());
                    }
                }
                (Some(relative_path), target_path, norm_exact, path_depth)
            };

        let get_rel_path = |opt: &mut Option<PathBuf>, norm: &str| -> PathBuf {
            opt.get_or_insert_with(|| PathBuf::from(norm)).clone()
        };

        // Check path depth: count components; if deeper than limits.max_path_depth
        if path_depth > limits.max_path_depth {
            return Err(FsError::TarBombLimitExceeded {
                limit_type: "path depth".to_string(),
                detail: format!(
                    "Path depth {} exceeded maximum allowed path depth of {}: '{}'",
                    path_depth,
                    limits.max_path_depth,
                    get_rel_path(&mut relative_path_opt, &norm_exact).display()
                ),
            });
        }

        // Track directory count: if directories exceed limits.max_directories
        if entry_type.is_dir() {
            directory_count += 1;
            if directory_count > limits.max_directories {
                return Err(FsError::TarBombLimitExceeded {
                    limit_type: "directory count".to_string(),
                    detail: format!(
                        "Tarball exceeded maximum allowed directories: {}",
                        limits.max_directories
                    ),
                });
            }
        }

        // Check special entry types: FIFOs, block/character devices
        if entry_type.is_block_special()
            || entry_type.is_character_special()
            || entry_type.is_fifo()
        {
            return Err(FsError::ForbiddenSpecialEntry {
                path: entry.path().unwrap_or_default().to_path_buf(),
            });
        }

        // Verify strict canonical path containment
        if !target_path.starts_with(&clean_dest) {
            return Err(FsError::PathTraversal {
                path: get_rel_path(&mut relative_path_opt, &norm_exact),
            });
        }
        if target_path == clean_dest && !entry_type.is_dir() {
            return Err(FsError::PathTraversal {
                path: get_rel_path(&mut relative_path_opt, &norm_exact),
            });
        }

        if norm_exact.is_empty() {
            continue;
        }

        if !is_fresh_dest {
            let rel_for_check = get_rel_path(&mut relative_path_opt, &norm_exact);
            let empty_set = HashSet::new();
            ensure_no_symlink_ancestors_with_cache(
                &target_path,
                &verbatim_dest,
                &empty_set,
                &rel_for_check,
                Some(&mut verified_safe_ancestors),
            )?;
        }

        let tracked_kind = if entry_type.is_dir() {
            TrackedKind::Dir
        } else if entry_type.is_symlink() {
            TrackedKind::Symlink
        } else {
            TrackedKind::File
        };
        let was_seen = match tracker.record(&norm_exact, tracked_kind) {
            Ok((seen, _)) => seen,
            Err(TrackReject::CaseCollision) => {
                return Err(FsError::CaseCollision {
                    path: get_rel_path(&mut relative_path_opt, &norm_exact),
                });
            }
            Err(TrackReject::SymlinkAncestor(anc)) => {
                return Err(FsError::EscapingSymlink {
                    link: verbatim_dest.join(anc),
                    target: target_path,
                });
            }
        };

        // Security check: escaping symlinks/hardlinks
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            if !pending_files.is_empty() {
                flush_pending(
                    &mut pending_files,
                    &mut pending_arena,
                    &mut created_dirs,
                    &mut verified_safe_ancestors,
                    &mut recorded_files,
                    &mut recorded_bytes,
                    &mut wide_buf,
                )?;
            }
            let relative_path = get_rel_path(&mut relative_path_opt, &norm_exact);
            symlink_count += 1;
            if symlink_count > limits.max_symlinks {
                return Err(FsError::TarBombLimitExceeded {
                    limit_type: "symlink count".to_string(),
                    detail: format!(
                        "Tarball exceeded maximum allowed symlinks/hardlinks: {}",
                        limits.max_symlinks
                    ),
                });
            }

            if let Some(link_bytes) = entry.link_name_bytes() {
                if link_bytes.contains(&0) {
                    return Err(FsError::PathTraversal {
                        path: PathBuf::from(String::from_utf8_lossy(&link_bytes).into_owned()),
                    });
                }
                if std::str::from_utf8(&link_bytes).is_err() {
                    return Err(FsError::InvalidUtf8Path {
                        path: PathBuf::from(String::from_utf8_lossy(&link_bytes).into_owned()),
                    });
                }
            }

            if let Some(link_target) = entry.link_name().map_err(FsError::Io)? {
                if entry_type.is_symlink() {
                    let cleaned_rel =
                        validate_link_target(&relative_path, &link_target, destination)?;

                    if let Some(parent) = target_path.parent() {
                        ensure_dir_created(
                            parent,
                            &verbatim_dest,
                            &mut created_dirs,
                            &mut verified_safe_ancestors,
                            !is_fresh_dest,
                        )?;
                    }

                    // If target_path exists, safely unlink it (handling Windows junctions) before creating link
                    unlink_target_path(&target_path);

                    #[cfg(unix)]
                    {
                        let _ = &cleaned_rel;
                        let _ = std::os::unix::fs::symlink(&link_target, &target_path);
                    }
                    #[cfg(windows)]
                    {
                        let target_full = verbatim_dest.join(&cleaned_rel);
                        if target_full.is_dir() {
                            let _ = crate::junction::create_junction(&target_path, &target_full);
                        } else if target_full.is_file() {
                            let _ = fs::copy(&target_full, &target_path);
                        }
                    }
                } else if entry_type.is_hard_link() {
                    // For hardlinks, the target is often archived as package/...
                    let normalized_target =
                        strip_package_prefix(&link_target).unwrap_or_else(|| link_target.to_path_buf());
                    // Hardlinks in tar are relative to archive root (destination), NOT relative to link_dir!
                    if normalized_target.is_absolute() || normalized_target.has_root() {
                        return Err(FsError::AbsolutePath {
                            path: normalized_target,
                        });
                    }

                    let target_str = normalized_target.to_string_lossy();
                    if target_str.starts_with('/')
                        || target_str.starts_with('\\')
                        || target_str.starts_with(r"\\?\")
                        || target_str.starts_with(r"\??\")
                        || target_str.starts_with("//?/")
                        || target_str.starts_with(r"\\.\")
                        || target_str.starts_with("//./")
                    {
                        return Err(FsError::AbsolutePath {
                            path: normalized_target,
                        });
                    }

                    let bytes = target_str.as_bytes();
                    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
                        return Err(FsError::AbsolutePath {
                            path: normalized_target,
                        });
                    }

                    for comp in normalized_target.components() {
                        if matches!(comp, Component::Prefix(_) | Component::RootDir) {
                            return Err(FsError::AbsolutePath {
                                path: normalized_target,
                            });
                        }
                    }

                    let cleaned_target = clean(&normalized_target);

                    // If cleaned target starts with '..' or is root/absolute, it escapes destination
                    if cleaned_target.starts_with("..")
                        || cleaned_target.is_absolute()
                        || cleaned_target.has_root()
                    {
                        return Err(FsError::EscapingSymlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }

                    validate_entry_path(&cleaned_target)?;

                    let source_full = verbatim_dest.join(&cleaned_target);
                    let clean_source = clean(&source_full);
                    if !clean_source.starts_with(&clean_dest) {
                        return Err(FsError::EscapingSymlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }

                    #[cfg(windows)]
                    let is_symlink_or_junction = source_full.is_symlink()
                        || crate::junction::is_junction(&source_full).unwrap_or(false);
                    #[cfg(not(windows))]
                    let is_symlink_or_junction = source_full.is_symlink();

                    let norm_cleaned_str = cleaned_target
                        .to_string_lossy()
                        .replace('\\', "/");
                    let norm_cleaned_trimmed = norm_cleaned_str
                        .trim_start_matches("./")
                        .trim_start_matches('/');
                    let mut has_symlink_ancestor =
                        is_symlink_or_junction || tracker.has_symlink_ancestor(norm_cleaned_trimmed).is_some();

                    if !has_symlink_ancestor {
                        let mut curr_p = source_full.parent();
                        while let Some(p) = curr_p {
                            if p == verbatim_dest || p.as_os_str().is_empty() {
                                break;
                            }
                            if !p.starts_with(&verbatim_dest) {
                                break;
                            }
                            if let Ok(meta) = fs::symlink_metadata(p) {
                                if meta.file_type().is_symlink() {
                                    has_symlink_ancestor = true;
                                    break;
                                }
                                #[cfg(windows)]
                                {
                                    use std::os::windows::fs::MetadataExt;
                                    if (meta.file_attributes() & 0x400) != 0 {
                                        has_symlink_ancestor = true;
                                        break;
                                    }
                                }
                            }
                            curr_p = p.parent();
                        }
                    }

                    if has_symlink_ancestor {
                        return Err(FsError::EscapingSymlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }

                    // Check for circular hardlink
                    if cleaned_target == relative_path {
                        return Err(FsError::CircularHardlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }
                    let mut curr = cleaned_target.clone();
                    let mut visited = HashSet::new();
                    visited.insert(relative_path.clone());
                    while let Some(next) = hardlink_targets.get(&curr) {
                        if !visited.insert(curr.clone()) || curr == relative_path {
                            return Err(FsError::CircularHardlink {
                                link: relative_path.clone(),
                                target: normalized_target,
                            });
                        }
                        curr = next.clone();
                    }

                    // Reject dangling hardlinks: hardlinks can only point to previously extracted regular files
                    if !tracker.is_regular_file(norm_cleaned_trimmed)
                        || !source_full.exists()
                        || !source_full.is_file()
                    {
                        return Err(FsError::DanglingHardlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }

                    if let Some(parent) = target_path.parent() {
                        ensure_dir_created(
                            parent,
                            &verbatim_dest,
                            &mut created_dirs,
                            &mut verified_safe_ancestors,
                            !is_fresh_dest,
                        )?;
                    }

                    unlink_target_path(&target_path);

                    if fs::hard_link(&source_full, &target_path).is_err() && source_full.is_file() {
                        let _ = fs::copy(&source_full, &target_path);
                    }

                    hardlink_targets.insert(relative_path, cleaned_target);
                }
            }
            continue;
        }

        // Unpack entry with size and ratio checks
        if entry_type.is_dir() {
            if was_seen && !pending_files.is_empty() {
                flush_pending(
                    &mut pending_files,
                    &mut pending_arena,
                    &mut created_dirs,
                    &mut verified_safe_ancestors,
                    &mut recorded_files,
                    &mut recorded_bytes,
                    &mut wide_buf,
                )?;
            }
            if !created_dirs.contains(&target_path) {
                let should_unlink = if is_fresh_dest { was_seen } else { true };
                if should_unlink {
                    unlink_target_path(&target_path);
                }
                ensure_dir_created(
                    &target_path,
                    &verbatim_dest,
                    &mut created_dirs,
                    &mut verified_safe_ancestors,
                    !is_fresh_dest,
                )?;
            }
        } else if entry_type.is_file() {
            // Use PAX-aware entry size so PAX `size` overrides are never truncated.
            let entry_size = entry.size();
            if entry_size > limits.max_single_entry_size {
                return Err(FsError::TarBombLimitExceeded {
                    limit_type: "entry size".to_string(),
                    detail: format!(
                        "Entry size {} exceeded single file limit of {} bytes",
                        entry_size, limits.max_single_entry_size
                    ),
                });
            }
            if total_uncompressed.saturating_add(entry_size) > limits.max_uncompressed_size {
                return Err(FsError::TarBombLimitExceeded {
                    limit_type: "uncompressed size".to_string(),
                    detail: format!(
                        "Projected uncompressed size exceeds limit of {} bytes",
                        limits.max_uncompressed_size
                    ),
                });
            }

            // Fast parallel batching path for <=256KB files on a fresh destination without
            // duplicate paths or prior symlinks.
            if entry_size <= 256 * 1024
                && is_fresh_dest
                && !was_seen
                && !tracker.has_symlinks
                && !created_dirs.contains(&target_path)
            {
                let sz = entry_size as usize;
                let start = pending_arena.len();
                let t_read = std::time::Instant::now();
                if sz > 0 {
                    pending_arena.resize(start + sz, 0);
                    entry
                        .read_exact(&mut pending_arena[start..start + sz])
                        .map_err(FsError::Io)?;
                }
                inflate_nanos += t_read.elapsed().as_nanos() as u64;

                total_uncompressed += sz as u64;
                if total_uncompressed > limits.max_uncompressed_size {
                    return Err(FsError::TarBombLimitExceeded {
                        limit_type: "uncompressed size".to_string(),
                        detail: format!(
                            "Uncompressed size {} exceeded limit of {} bytes",
                            total_uncompressed, limits.max_uncompressed_size
                        ),
                    });
                }
                if total_uncompressed > 50_000 {
                    let compressed_so_far = compressed_counter.load(Ordering::Relaxed);
                    let ratio = if compressed_so_far == 0 {
                        f64::INFINITY
                    } else {
                        total_uncompressed as f64 / compressed_so_far as f64
                    };
                    if ratio > limits.max_compression_ratio {
                        return Err(FsError::TarBombLimitExceeded {
                            limit_type: "compression ratio".to_string(),
                            detail: format!(
                                "Compression ratio {:.1}:1 exceeded limit of {:.1}:1",
                                ratio, limits.max_compression_ratio
                            ),
                        });
                    }
                }

                pending_files.push(PendingTarFile {
                    path: target_path,
                    start,
                    len: sz,
                    mode,
                });

                if pending_arena.len() >= PENDING_FLUSH_BYTES {
                    flush_pending(
                        &mut pending_files,
                        &mut pending_arena,
                        &mut created_dirs,
                        &mut verified_safe_ancestors,
                        &mut recorded_files,
                        &mut recorded_bytes,
                        &mut wide_buf,
                    )?;
                }
                continue;
            }

            if !pending_files.is_empty() {
                flush_pending(
                    &mut pending_files,
                    &mut pending_arena,
                    &mut created_dirs,
                    &mut verified_safe_ancestors,
                    &mut recorded_files,
                    &mut recorded_bytes,
                    &mut wide_buf,
                )?;
            }

            // Ensure parent directory exists using deduplicated directory cache
            if let Some(parent) = target_path.parent() {
                ensure_dir_created(
                    parent,
                    &verbatim_dest,
                    &mut created_dirs,
                    &mut verified_safe_ancestors,
                    !is_fresh_dest,
                )?;
            }

            if entry_size <= 256 * 1024 {
                let sz = entry_size as usize;
                scratch_buf.resize(sz, 0);
                let t_read = std::time::Instant::now();
                if sz > 0 {
                    entry.read_exact(&mut scratch_buf).map_err(FsError::Io)?;
                }
                inflate_nanos += t_read.elapsed().as_nanos() as u64;

                total_uncompressed += scratch_buf.len() as u64;
                if total_uncompressed > limits.max_uncompressed_size {
                    return Err(FsError::TarBombLimitExceeded {
                        limit_type: "uncompressed size".to_string(),
                        detail: format!(
                            "Uncompressed size {} exceeded limit of {} bytes",
                            total_uncompressed, limits.max_uncompressed_size
                        ),
                    });
                }
                if total_uncompressed > 50_000 {
                    let compressed_so_far = compressed_counter.load(Ordering::Relaxed);
                    let ratio = if compressed_so_far == 0 {
                        f64::INFINITY
                    } else {
                        total_uncompressed as f64 / compressed_so_far as f64
                    };
                    if ratio > limits.max_compression_ratio {
                        return Err(FsError::TarBombLimitExceeded {
                            limit_type: "compression ratio".to_string(),
                            detail: format!(
                                "Compression ratio {:.1}:1 exceeded limit of {:.1}:1",
                                ratio, limits.max_compression_ratio
                            ),
                        });
                    }
                }

                if let Err(err) = crate::writer::write_file_fast_buf(
                    &target_path,
                    &scratch_buf,
                    mode,
                    64 * 1024,
                    &mut wide_buf,
                    false,
                ) {
                    if err.kind() == std::io::ErrorKind::PermissionDenied {
                        unlink_target_path(&target_path);
                        #[cfg(windows)]
                        {
                            if let Some(parent) = target_path.parent() {
                                if let Ok(meta) = fs::metadata(parent) {
                                    let mut perms = meta.permissions();
                                    if perms.readonly() {
                                        perms.set_readonly(false);
                                        let _ = fs::set_permissions(parent, perms);
                                    }
                                }
                            }
                            if let Ok(meta) = fs::metadata(&target_path) {
                                let mut perms = meta.permissions();
                                if perms.readonly() {
                                    perms.set_readonly(false);
                                    let _ = fs::set_permissions(&target_path, perms);
                                }
                            }
                        }
                        #[cfg(unix)]
                        {
                            if let Some(parent) = target_path.parent() {
                                if let Ok(meta) = fs::metadata(parent) {
                                    use std::os::unix::fs::PermissionsExt;
                                    let mut perms = meta.permissions();
                                    if perms.mode() & 0o200 == 0 {
                                        perms.set_mode(perms.mode() | 0o700);
                                        let _ = fs::set_permissions(parent, perms);
                                    }
                                }
                            }
                            if let Ok(meta) = fs::metadata(&target_path) {
                                use std::os::unix::fs::PermissionsExt;
                                let mut perms = meta.permissions();
                                perms.set_mode(perms.mode() | 0o600);
                                let _ = fs::set_permissions(&target_path, perms);
                            }
                        }
                        crate::writer::write_file_fast_buf(
                            &target_path,
                            &scratch_buf,
                            mode,
                            64 * 1024,
                            &mut wide_buf,
                            false,
                        )?;
                    } else {
                        return Err(err.into());
                    }
                }
                continue;
            }

            // Replace the directory entry before opening it: truncating an existing
            // symlink or hardlink would modify the linked file, possibly outside dest.
            let should_unlink = if is_fresh_dest {
                was_seen || created_dirs.contains(&target_path)
            } else {
                true
            };
            if should_unlink {
                unlink_target_path(&target_path);
            }

            let mut raw_file = match File::create(&target_path) {
                Ok(f) => f,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    if let Some(parent) = target_path.parent() {
                        ensure_dir_created(
                            parent,
                            &verbatim_dest,
                            &mut created_dirs,
                            &mut verified_safe_ancestors,
                            !is_fresh_dest,
                        )?;
                    }
                    File::create(&target_path)?
                }
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    unlink_target_path(&target_path);
                    #[cfg(windows)]
                    {
                        if let Some(parent) = target_path.parent() {
                            if let Ok(meta) = fs::metadata(parent) {
                                let mut perms = meta.permissions();
                                if perms.readonly() {
                                    perms.set_readonly(false);
                                    let _ = fs::set_permissions(parent, perms);
                                }
                            }
                        }
                        if let Ok(meta) = fs::metadata(&target_path) {
                            let mut perms = meta.permissions();
                            if perms.readonly() {
                                perms.set_readonly(false);
                                let _ = fs::set_permissions(&target_path, perms);
                            }
                        }
                    }
                    #[cfg(unix)]
                    {
                        if let Some(parent) = target_path.parent() {
                            if let Ok(meta) = fs::metadata(parent) {
                                use std::os::unix::fs::PermissionsExt;
                                let mut perms = meta.permissions();
                                if perms.mode() & 0o200 == 0 {
                                    perms.set_mode(perms.mode() | 0o700);
                                    let _ = fs::set_permissions(parent, perms);
                                }
                            }
                        }
                        if let Ok(meta) = fs::metadata(&target_path) {
                            use std::os::unix::fs::PermissionsExt;
                            let mut perms = meta.permissions();
                            perms.set_mode(perms.mode() | 0o600);
                            let _ = fs::set_permissions(&target_path, perms);
                        }
                    }
                    File::create(&target_path)?
                }
                Err(err) => return Err(err.into()),
            };
            if copy_buf.is_empty() {
                copy_buf.resize(128 * 1024, 0);
            }
            loop {
                let t_read = std::time::Instant::now();
                let n = entry.read(&mut copy_buf).map_err(FsError::Io)?;
                inflate_nanos += t_read.elapsed().as_nanos() as u64;
                if n == 0 {
                    break;
                }
                io::Write::write_all(&mut raw_file, &copy_buf[..n])?;
                total_uncompressed += n as u64;

                // Check max uncompressed size
                if total_uncompressed > limits.max_uncompressed_size {
                    return Err(FsError::TarBombLimitExceeded {
                        limit_type: "uncompressed size".to_string(),
                        detail: format!(
                            "Uncompressed size {} exceeded limit of {} bytes",
                            total_uncompressed, limits.max_uncompressed_size
                        ),
                    });
                }

                // Real-time check for high-ratio tar bombs in-flight (threshold 50KB)
                if total_uncompressed > 50_000 {
                    let compressed_so_far = compressed_counter.load(Ordering::Relaxed);
                    let ratio = if compressed_so_far == 0 {
                        f64::INFINITY
                    } else {
                        total_uncompressed as f64 / compressed_so_far as f64
                    };
                    if ratio > limits.max_compression_ratio {
                        return Err(FsError::TarBombLimitExceeded {
                            limit_type: "compression ratio".to_string(),
                            detail: format!(
                                "Compression ratio {:.1}:1 exceeded limit of {:.1}:1",
                                ratio, limits.max_compression_ratio
                            ),
                        });
                    }
                }
            }
            #[cfg(unix)]
            if mode & 0o111 != 0 {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = raw_file.metadata() {
                    let mut perms = meta.permissions();
                    perms.set_mode(perms.mode() | (mode & 0o111));
                    let _ = raw_file.set_permissions(perms);
                }
            }
            drop(raw_file);
        }
    }

    if !pending_files.is_empty() {
        flush_pending(
            &mut pending_files,
            &mut pending_arena,
            &mut created_dirs,
            &mut verified_safe_ancestors,
            &mut recorded_files,
            &mut recorded_bytes,
            &mut wide_buf,
        )?;
    }

    // Final check for compression ratio after extraction
    let compressed_bytes = compressed_counter.load(Ordering::Relaxed);
    if total_uncompressed > 50_000 {
        let ratio = if compressed_bytes == 0 {
            f64::INFINITY
        } else {
            total_uncompressed as f64 / compressed_bytes as f64
        };
        if ratio > limits.max_compression_ratio {
            return Err(FsError::TarBombLimitExceeded {
                limit_type: "compression ratio".to_string(),
                detail: format!(
                    "Compression ratio {:.1}:1 exceeded limit of {:.1}:1",
                    ratio, limits.max_compression_ratio
                ),
            });
        }
    }

    let rem_files = (entry_count as u64).saturating_sub(recorded_files);
    let rem_bytes = total_uncompressed.saturating_sub(recorded_bytes);
    if rem_files > 0 || rem_bytes > 0 {
        record_files_created_batch(rem_files, rem_bytes);
    }
    let total_elapsed = start_extract.elapsed();
    let inflate_duration = std::time::Duration::from_nanos(inflate_nanos);
    let materialize_duration = total_elapsed.saturating_sub(inflate_duration);

    Ok(ExtractionSummary {
        entries_extracted: entry_count,
        total_uncompressed_bytes: total_uncompressed,
        inflate_duration,
        materialize_duration,
    })
}

#[cfg(windows)]
pub(crate) fn unlink_target_path_wide(wide: &[u16], path_hint: &Path) {
    extern "system" {
        fn GetFileAttributesW(lpFileName: *const u16) -> u32;
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
        fn DeleteFileW(lpFileName: *const u16) -> i32;
        fn RemoveDirectoryW(lpPathName: *const u16) -> i32;
    }
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return;
    }
    if (attrs & FILE_ATTRIBUTE_READONLY) != 0 {
        unsafe {
            SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
        }
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
        let removed = unsafe { RemoveDirectoryW(wide.as_ptr()) };
        if removed == 0 && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            use std::os::windows::ffi::OsStringExt;
            let _ = path_hint;
            let actual = std::ffi::OsString::from_wide(&wide[..wide.len().saturating_sub(1)]);
            let _ = crate::junction::remove_junction(Path::new(&actual));
        }
    } else {
        unsafe {
            DeleteFileW(wide.as_ptr());
        }
    }
}

/// Safely unlinks a pre-existing target path before creating a new entry.
/// On Windows, directory junctions are safely unlinked using `RemoveDirectoryW` / `remove_junction`
/// to prevent `fs::remove_file` failures and avoid deleting target contents.
pub(crate) fn unlink_target_path(path: &Path) {
    #[cfg(windows)]
    {
        crate::path::with_verbatim_wide(path, |wide| unlink_target_path_wide(wide, path));
    }
    #[cfg(not(windows))]
    {
        let path_v = crate::path::to_verbatim_path(path);
        if let Ok(meta) = fs::symlink_metadata(&path_v) {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                let _ = fs::remove_file(&path_v);
            } else {
                let _ = fs::remove_dir(&path_v);
            }
        }
    }
}

pub(crate) fn normalize_rel_path(path: &Path) -> PathBuf {
    PathBuf::from(path.to_string_lossy().replace('\\', "/"))
}

#[allow(dead_code)]
fn is_link_pointing_outside(link: &Path, destination: &Path) -> bool {
    let verbatim_dest = crate::path::to_verbatim_path(destination);

    if let Ok(target) = fs::read_link(link) {
        let resolved = if target.is_absolute() {
            target
        } else {
            link.parent().unwrap_or(destination).join(target)
        };
        let cleaned = crate::path::to_verbatim_path(&resolved);
        if !cleaned.starts_with(&verbatim_dest) {
            return true;
        }
    }

    if let Ok(canonical) = fs::canonicalize(link) {
        let canonical_target = crate::path::to_verbatim_path(&canonical);
        let canonical_dest = fs::canonicalize(destination)
            .map(|d| crate::path::to_verbatim_path(&d))
            .unwrap_or_else(|_| verbatim_dest);
        if !canonical_target.starts_with(&canonical_dest) {
            return true;
        }
    }

    false
}

/// Security helper ensuring neither target nor any intermediate ancestor directory
/// between destination and target is a symlink or junction pointing outside destination
/// or created by an earlier tarball entry.
pub fn ensure_no_symlink_ancestors(
    target: &Path,
    destination: &Path,
    symlink_paths: &HashSet<PathBuf>,
    relative_path: &Path,
) -> Result<(), FsError> {
    ensure_no_symlink_ancestors_with_cache(target, destination, symlink_paths, relative_path, None)
}

pub fn ensure_no_symlink_ancestors_with_cache(
    target: &Path,
    destination: &Path,
    symlink_paths: &HashSet<PathBuf>,
    relative_path: &Path,
    mut safe_cache: Option<&mut HashSet<PathBuf>>,
) -> Result<(), FsError> {
    // 1 & 2. Check earlier symlink entries only when symlink entries exist in archive
    if !symlink_paths.is_empty() {
        let norm_rel = normalize_rel_path(relative_path);
        for ancestor in norm_rel.ancestors() {
            if !ancestor.as_os_str().is_empty()
                && ancestor != norm_rel
                && symlink_paths.contains(ancestor)
            {
                return Err(FsError::EscapingSymlink {
                    link: destination.join(ancestor),
                    target: target.to_path_buf(),
                });
            }
        }
        if symlink_paths.contains(&norm_rel) {
            return Err(FsError::EscapingSymlink {
                link: target.to_path_buf(),
                target: target.to_path_buf(),
            });
        }
    }

    // Fast path: if parent is destination or already cached as safe, skip Vec alloc & syscalls
    let Some(first_parent) = target.parent() else {
        return Ok(());
    };
    if first_parent == destination || first_parent.as_os_str().is_empty() {
        return Ok(());
    }
    if let Some(ref cache) = safe_cache {
        if cache.contains(first_parent) {
            return Ok(());
        }
    }

    // 3. Check all intermediate ancestors between destination and target on disk
    let mut current = Some(first_parent);
    let mut newly_verified = Vec::with_capacity(8);
    while let Some(parent) = current {
        if parent == destination || parent.as_os_str().is_empty() {
            break;
        }
        if !parent.starts_with(destination) {
            break;
        }
        if let Some(ref cache) = safe_cache {
            if cache.contains(parent) {
                break;
            }
        }
        if let Ok(meta) = fs::symlink_metadata(parent) {
            if meta.file_type().is_symlink() {
                return Err(FsError::EscapingSymlink {
                    link: parent.to_path_buf(),
                    target: target.to_path_buf(),
                });
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if (meta.file_attributes() & 0x400) != 0 {
                    return Err(FsError::EscapingSymlink {
                        link: parent.to_path_buf(),
                        target: target.to_path_buf(),
                    });
                }
            }
        }
        newly_verified.push(parent.to_path_buf());
        current = parent.parent();
    }
    if let Some(ref mut cache) = safe_cache {
        for p in newly_verified {
            cache.insert(p);
        }
    }
    Ok(())
}

/// Strips the first archive-root component from a tar entry path.
///
/// npm packages are normally packed below `package/`, but published tarballs
/// also use generated roots such as `mscdex-busboy-<sha>/`. npm strips one
/// component regardless of its name, so extraction must do the same. Leading
/// `./` components are ignored; a path consisting only of the root component
/// returns `None` because it has no extracted payload.
pub fn strip_package_prefix(path: &Path) -> Option<PathBuf> {
    let mut components = path.components().peekable();
    while let Some(Component::CurDir) = components.peek() {
        components.next();
    }

    let first = components.next()?;
    if matches!(first, Component::Normal(_)) {
        while let Some(Component::CurDir) = components.peek() {
            components.next();
        }
        let remainder: PathBuf = components.collect();
        if remainder.as_os_str().is_empty() {
            return None;
        }
        return Some(remainder);
    }

    // Preserve paths beginning with a parent/prefix component. They are
    // validated by the caller and must not be normalized before validation.
    Some(path.to_path_buf())
}

/// Validates that path contains no traversal, absolute prefixes, Windows device names, trailing dots/spaces, or non-UTF-8 components.
pub fn validate_entry_path(path: &Path) -> Result<(), FsError> {
    let path_str = match path.to_str() {
        Some(s) => s,
        None => {
            return Err(FsError::InvalidUtf8Path {
                path: path.to_path_buf(),
            });
        }
    };

    if path_str.is_empty() {
        return Ok(());
    }

    if path_str.contains('\0') {
        return Err(FsError::PathTraversal {
            path: path.to_path_buf(),
        });
    }

    // Reject absolute paths, UNC paths, verbatim paths across all platforms
    if path.is_absolute()
        || path_str.starts_with('/')
        || path_str.starts_with('\\')
        || path_str.starts_with(r"\\?\")
        || path_str.starts_with(r"\??\")
        || path_str.starts_with("//?/")
        || path_str.starts_with(r"\\.\")
        || path_str.starts_with("//./")
    {
        return Err(FsError::AbsolutePath {
            path: path.to_path_buf(),
        });
    }

    // Reject Windows drive letters: "C:foo", "c:/...", "D:\...", etc.
    let bytes = path_str.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(FsError::AbsolutePath {
            path: path.to_path_buf(),
        });
    }

    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                return Err(FsError::AbsolutePath {
                    path: path.to_path_buf(),
                });
            }
            Component::ParentDir => {
                return Err(FsError::PathTraversal {
                    path: path.to_path_buf(),
                });
            }
            Component::CurDir => continue,
            Component::Normal(os_str) => {
                let name = match os_str.to_str() {
                    Some(s) => s,
                    None => {
                        return Err(FsError::InvalidUtf8Path {
                            path: path.to_path_buf(),
                        });
                    }
                };

                // Reject null bytes, colons, backslashes, ASCII control chars (< 0x20),
                // and Windows invalid chars (*, ?, ", <, >, |) in a single byte scan.
                if name.bytes().any(|b| {
                    b < 0x20
                        || matches!(
                            b,
                            b':' | b'\\' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'
                        )
                }) {
                    return Err(FsError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }

                // Reject Windows reserved device names: CON, PRN, AUX, NUL, COM0-9, LPT0-9, CLOCK$, CONIN$, CONOUT$, etc.
                // including with extensions (aux.js, com1.json) or embedded/trailing spaces/dots (aux .js, nul.)
                if is_windows_reserved_name(name) {
                    return Err(FsError::WindowsReservedDeviceName {
                        name: name.to_string(),
                        path: path.to_path_buf(),
                    });
                }

                // Reject trailing dot or trailing space in component
                if name.ends_with('.') || name.ends_with(' ') {
                    return Err(FsError::TrailingDotOrSpace {
                        name: name.to_string(),
                        path: path.to_path_buf(),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Returns true if name is a Windows reserved device name (CON, PRN, AUX, NUL, COM0-9, LPT0-9, CLOCK$, CONIN$, CONOUT$),
/// superscripts (COM¹..³, LPT¹..³), reserved names with any extension (nul.txt, com1.json, aux.js),
/// trailing dots/spaces or embedded whitespace (aux .js, nul.), or NTFS Alternate Data Streams (file:stream, foo:$DATA).
pub fn is_windows_reserved_name(name: &str) -> bool {
    // 1. NTFS Alternate Data Streams (e.g. file:stream, foo:$DATA, nul:stream)
    if name.contains(':') {
        return true;
    }

    // 2. Extract base stem before any extension: split on '.'
    // Trim trailing spaces and dots from the base stem (e.g. "aux .js", "nul.", "com1  .json")
    let stem = match name.find('.') {
        Some(pos) => &name[..pos],
        None => name,
    };
    let base = stem.trim_matches(|c: char| c == ' ' || c == '.');

    if base.len() < 3 || base.len() > 7 {
        return false;
    }

    if base.eq_ignore_ascii_case("CON")
        || base.eq_ignore_ascii_case("PRN")
        || base.eq_ignore_ascii_case("AUX")
        || base.eq_ignore_ascii_case("NUL")
        || base.eq_ignore_ascii_case("CLOCK$")
        || base.eq_ignore_ascii_case("CONIN$")
        || base.eq_ignore_ascii_case("CONOUT$")
    {
        return true;
    }

    let bytes = base.as_bytes();
    if bytes.len() == 4
        && (bytes[..3].eq_ignore_ascii_case(b"COM") || bytes[..3].eq_ignore_ascii_case(b"LPT"))
        && bytes[3].is_ascii_digit()
    {
        return true;
    }

    if bytes.len() == 5
        && (bytes[..3].eq_ignore_ascii_case(b"COM") || bytes[..3].eq_ignore_ascii_case(b"LPT"))
        && (base[3..].eq("\u{00B9}") || base[3..].eq("\u{00B2}") || base[3..].eq("\u{00B3}"))
    {
        return true;
    }

    false
}

pub fn validate_link_target(
    link_path: &Path,
    target: &Path,
    destination: &Path,
) -> Result<PathBuf, FsError> {
    let target_str = match target.to_str() {
        Some(s) => s,
        None => {
            return Err(FsError::InvalidUtf8Path {
                path: target.to_path_buf(),
            });
        }
    };

    if target_str.contains('\0') {
        return Err(FsError::PathTraversal {
            path: target.to_path_buf(),
        });
    }

    if target.is_absolute()
        || target.has_root()
        || target_str.starts_with('/')
        || target_str.starts_with('\\')
        || target_str.starts_with(r"\\?\")
        || target_str.starts_with(r"\??\")
        || target_str.starts_with("//?/")
        || target_str.starts_with(r"\\.\")
        || target_str.starts_with("//./")
    {
        return Err(FsError::AbsolutePath {
            path: target.to_path_buf(),
        });
    }

    let bytes = target_str.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(FsError::AbsolutePath {
            path: target.to_path_buf(),
        });
    }

    for comp in target.components() {
        if matches!(comp, Component::Prefix(_) | Component::RootDir) {
            return Err(FsError::AbsolutePath {
                path: target.to_path_buf(),
            });
        }
    }

    // Resolve target relative to link parent
    let normalized_target_str = target_str.replace('\\', "/");
    let norm_target = Path::new(&normalized_target_str);
    let link_dir = link_path.parent().unwrap_or_else(|| Path::new(""));
    let combined = link_dir.join(norm_target);
    let cleaned = clean(&combined);

    // If cleaned path starts with '..' or is root/absolute, it escapes destination
    if cleaned.starts_with("..") || cleaned.is_absolute() || cleaned.has_root() {
        return Err(FsError::EscapingSymlink {
            link: link_path.to_path_buf(),
            target: target.to_path_buf(),
        });
    }

    // Verify containment against destination
    let verbatim_dest = crate::path::to_verbatim_path(destination);
    let full_target = verbatim_dest.join(&cleaned);
    let clean_full = clean(&full_target);
    let clean_dest = clean(&verbatim_dest);

    if !clean_full.starts_with(&clean_dest) {
        return Err(FsError::EscapingSymlink {
            link: link_path.to_path_buf(),
            target: target.to_path_buf(),
        });
    }

    // Also validate the cleaned destination-relative path against traversal and reserved names
    validate_entry_path(&cleaned)?;

    Ok(cleaned)
}

// ============================================================================
// Packaging (rnpm pack) support
// ============================================================================

/// Metadata and content for an entry to be packed into the tarball.
#[derive(Debug, Clone)]
pub struct PackedFileEntry {
    /// Relative path inside the package, e.g. "package.json" or "lib/index.js"
    pub path: String,
    /// Uncompressed size in bytes
    pub size: u64,
    /// Normalized POSIX file permissions mode, e.g. 0o644 or 0o755
    pub mode: u32,
}

/// Summary report returned upon successful tarball creation.
#[derive(Debug, Clone)]
pub struct PackSummary {
    pub name: String,
    pub version: String,
    pub filename: String,
    /// Compressed .tgz size in bytes
    pub package_size: u64,
    /// Total uncompressed size of all contained files
    pub unpacked_size: u64,
    /// Hex-encoded SHA-1 hash of the compressed .tgz archive
    pub shasum: String,
    /// Full SSRI integrity string: `sha512-...`
    pub integrity: String,
    /// List of bundled files
    pub files: Vec<PackedFileEntry>,
    pub entry_count: usize,
    pub bundled: Vec<String>,
}

/// Compute canonical tarball filename for a package:
/// `@scope/pkg` @ `1.0.0` -> `scope-pkg-1.0.0.tgz`
/// `pkg` @ `1.0.0` -> `pkg-1.0.0.tgz`
pub fn compute_tarball_filename(name: &str, version: &str) -> String {
    let clean_name = name.replace('@', "").replace('/', "-");
    format!("{clean_name}-{version}.tgz")
}

/// Collect files to pack according to npm pack rules:
/// 1. If `files` array is defined in package.json, only include matching files + strictly required files.
/// 2. If `.npmignore` exists, use its patterns to exclude files; else if `.gitignore` exists, use it.
/// 3. Always include `package.json`, `README*`, `LICENSE*`, `LICENCE*`, `COPYING*`, `main`, and `bin`.
/// 4. Always exclude `.git*`, `node_modules/`, `.npmrc`, `package-lock.json`, and lockfiles.
pub fn collect_pack_files(
    package_dir: &Path,
    manifest: &Manifest,
) -> Result<Vec<(String, PathBuf)>, FsError> {
    let mut files_to_pack = Vec::new();

    // Check for ignore file
    let npmignore_path = package_dir.join(".npmignore");
    let gitignore_path = package_dir.join(".gitignore");

    let ignore_patterns = if manifest.files.is_some() {
        // npm-packlist's package.json rules disable both root ignore files.
        Vec::new()
    } else if npmignore_path.is_file() {
        parse_ignore_patterns(&npmignore_path)?
    } else if gitignore_path.is_file() {
        parse_ignore_patterns(&gitignore_path)?
    } else {
        Vec::new()
    };

    let files_filter: Option<Vec<String>> = manifest.files.clone();

    // Walk package_dir recursively
    walk_dir_collect(
        package_dir,
        package_dir,
        &files_filter,
        &[(String::new(), ignore_patterns)],
        manifest,
        &mut files_to_pack,
    )?;

    // Ensure strictly required files exist in files_to_pack if present on disk
    let required_rel_paths = collect_strictly_required_files(package_dir, manifest);
    let mut existing_set: HashSet<String> = files_to_pack.iter().map(|(r, _)| r.clone()).collect();

    for rel_path in required_rel_paths {
        if !existing_set.contains(&rel_path) {
            let full = package_dir.join(&rel_path);
            if full.is_file() {
                existing_set.insert(rel_path.clone());
                files_to_pack.push((rel_path, full));
            }
        }
    }

    // Include bundled dependency files from node_modules/<bundled_pkg>
    for bundled_name in manifest.bundled_package_names() {
        let bundled_dir = package_dir.join("node_modules").join(&bundled_name);
        if bundled_dir.is_dir() {
            walk_bundled_dependency_dir(
                &bundled_dir,
                package_dir,
                &mut files_to_pack,
                &mut existing_set,
            )?;
        }
    }

    // Sort files according to npm order:
    // uppercase initial files first sorted alphabetically, then others sorted alphabetically
    files_to_pack.sort_by(|a, b| sort_pack_file_paths(&a.0, &b.0));

    Ok(files_to_pack)
}

fn walk_bundled_dependency_dir(
    dir: &Path,
    root_dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
    existing: &mut HashSet<String>,
) -> Result<(), FsError> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let rel_path_buf = match path.strip_prefix(root_dir) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let rel_path = rel_path_buf
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");

        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if filename == ".git" || filename == ".gitignore" || filename == ".DS_Store" {
            continue;
        }

        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        if file_type.is_dir() {
            walk_bundled_dependency_dir(&path, root_dir, out, existing)?;
        } else if file_type.is_file() && !existing.contains(&rel_path) {
            existing.insert(rel_path.clone());
            out.push((rel_path, path));
        }
    }

    Ok(())
}

fn collect_strictly_required_files(package_dir: &Path, manifest: &Manifest) -> Vec<String> {
    let mut required = Vec::new();

    // package.json is always required
    required.push("package.json".to_string());

    // main script
    if let Some(main) = &manifest.main {
        let clean_main = main.trim_start_matches("./").trim_start_matches('/');
        required.push(clean_main.to_string());
    }

    // bins
    for (_, bin_path) in manifest.bin_entries() {
        let clean_bin = bin_path.trim_start_matches("./").trim_start_matches('/');
        required.push(clean_bin.to_string());
    }

    // npm-packlist promotes literal files entries to strict requirements. These
    // survive even an ignore file in their parent directory; directory/glob
    // entries remain subject to nested ignore rules.
    if let Some(files) = &manifest.files {
        for file in files {
            let clean = file
                .strip_prefix("./")
                .unwrap_or(file)
                .trim_start_matches('/');
            if package_dir.join(clean).is_file() && !is_strictly_excluded(clean, false) {
                required.push(clean.to_string());
            }
        }
    }

    // Look for README*, LICENSE*, LICENCE*, COPYING* in root
    if let Ok(entries) = fs::read_dir(package_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let upper = name.to_ascii_uppercase();
            if (upper.starts_with("README")
                || upper.starts_with("LICENSE")
                || upper.starts_with("LICENCE")
                || upper.starts_with("COPYING"))
                && entry.path().is_file()
            {
                required.push(name);
            }
        }
    }

    required
}

fn walk_dir_collect(
    current_dir: &Path,
    root_dir: &Path,
    files_filter: &Option<Vec<String>>,
    inherited_ignores: &[(String, Vec<String>)],
    manifest: &Manifest,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), FsError> {
    let mut ignore_scopes = inherited_ignores.to_vec();
    if current_dir != root_dir {
        let local = if current_dir.join(".npmignore").is_file() {
            current_dir.join(".npmignore")
        } else {
            current_dir.join(".gitignore")
        };
        let Ok(rel_dir) = current_dir.strip_prefix(root_dir) else {
            return Ok(());
        };
        let prefix = rel_dir.to_string_lossy().replace('\\', "/");
        ignore_scopes.push((format!("{prefix}/"), parse_ignore_patterns(&local)?));
    }
    let entries = match fs::read_dir(current_dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let rel_path_buf = match path.strip_prefix(root_dir) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let rel_path = rel_path_buf
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");

        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        // Check strictly excluded names
        if is_strictly_excluded(&rel_path, file_type.is_dir()) {
            continue;
        }

        if file_type.is_dir() {
            // Check if directory itself is ignored
            if is_path_ignored(&rel_path, &ignore_scopes) {
                continue;
            }
            walk_dir_collect(&path, root_dir, files_filter, &ignore_scopes, manifest, out)?;
        } else if file_type.is_file() {
            // Check if file is included
            if should_include_file(&rel_path, files_filter, &ignore_scopes, manifest) {
                out.push((rel_path, path));
            }
        }
    }

    Ok(())
}

fn is_strictly_excluded(rel_path: &str, is_dir: bool) -> bool {
    let filename = rel_path.split('/').next_back().unwrap_or(rel_path);

    // Hard exclusions matching npm
    if rel_path == ".git"
        || rel_path.starts_with(".git/")
        || filename == ".git"
        || filename == ".gitignore"
        || filename == ".npmignore"
        || filename == ".npmrc"
        || filename == ".rnpm_checkout_done"
        || rel_path == "node_modules"
        || rel_path.starts_with("node_modules/")
        || filename == "package-lock.json"
        || filename == "yarn.lock"
        || filename == "pnpm-lock.yaml"
        || filename == "bun.lockb"
        || filename == "npm-debug.log"
        || filename == ".DS_Store"
    {
        return true;
    }

    if is_dir && (filename == ".svn" || filename == ".hg" || filename == "CVS") {
        return true;
    }

    false
}

fn should_include_file(
    rel_path: &str,
    files_filter: &Option<Vec<String>>,
    ignore_patterns: &[(String, Vec<String>)],
    manifest: &Manifest,
) -> bool {
    // 1. If it's an always-included root file
    if is_always_included_file(rel_path, manifest) {
        return true;
    }

    // 2. If `files` array is present in package.json
    if let Some(patterns) = files_filter {
        let matched = patterns.iter().any(|pattern| {
            let clean = pattern.trim_start_matches("./").trim_start_matches('/');
            let clean_no_slash = clean.trim_end_matches('/');

            // Exact match
            if rel_path == clean_no_slash {
                return true;
            }
            // Directory match
            if rel_path.starts_with(&format!("{clean_no_slash}/")) {
                return true;
            }
            // Glob match against the file or a directory containing it
            match_glob_or_parent(clean_no_slash, rel_path)
        });

        if !matched {
            return false;
        }

        // Only directory-local ignore rules remain when files is present.
        if is_path_ignored(rel_path, ignore_patterns) {
            return false;
        }

        return true;
    }

    // 3. Without `files` array, check ignore patterns
    !is_path_ignored(rel_path, ignore_patterns)
}

fn is_always_included_file(rel_path: &str, manifest: &Manifest) -> bool {
    if rel_path == "package.json" {
        return true;
    }

    if let Some(main) = &manifest.main {
        let clean = main.trim_start_matches("./").trim_start_matches('/');
        if rel_path == clean {
            return true;
        }
    }

    for (_, bin_path) in manifest.bin_entries() {
        let clean = bin_path.trim_start_matches("./").trim_start_matches('/');
        if rel_path == clean {
            return true;
        }
    }

    // Root README, LICENSE, LICENCE, COPYING
    if !rel_path.contains('/') {
        let upper = rel_path.to_ascii_uppercase();
        if upper.starts_with("README")
            || upper.starts_with("LICENSE")
            || upper.starts_with("LICENCE")
            || upper.starts_with("COPYING")
        {
            return true;
        }
    }

    false
}

fn parse_ignore_patterns(path: &Path) -> Result<Vec<String>, FsError> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let mut patterns = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        patterns.push(trimmed.to_string());
    }

    Ok(patterns)
}

fn is_path_ignored(rel_path: &str, scopes: &[(String, Vec<String>)]) -> bool {
    let mut ignored = false;
    for (prefix, patterns) in scopes {
        let Some(local_path) = rel_path.strip_prefix(prefix) else {
            continue;
        };
        for pattern in patterns {
            let (rule, is_negated) = if let Some(rule) = pattern.strip_prefix('!') {
                (rule.trim(), true)
            } else {
                (pattern.as_str(), false)
            };
            if match_ignore_rule(rule, local_path) {
                ignored = !is_negated;
            }
        }
    }

    ignored
}

fn match_ignore_rule(pattern: &str, path: &str) -> bool {
    let clean_pat = pattern.trim_start_matches('/');
    let target_path = path.trim_start_matches('/');

    // If pattern ends with '/', it only matches directories or contents
    if clean_pat.ends_with('/') {
        let dir_prefix = clean_pat;
        if target_path.starts_with(dir_prefix) || format!("{target_path}/").starts_with(dir_prefix)
        {
            return true;
        }
    }

    if clean_pat.trim_end_matches('/').contains('/') {
        if match_glob_or_parent(clean_pat.trim_end_matches('/'), target_path) {
            return true;
        }
    } else {
        // Pattern matches basename or any segment
        let basename = target_path.split('/').next_back().unwrap_or(target_path);
        if match_glob(clean_pat, basename) {
            return true;
        }
        for segment in target_path.split('/') {
            if match_glob(clean_pat, segment) {
                return true;
            }
        }
    }

    false
}

/// minimatch-style path glob: `*` and `?` stay within a segment, `**`
/// spans any number of segments (including none), `[...]` is a class and
/// `{a,b}` alternatives are expanded.
fn match_glob(pattern: &str, text: &str) -> bool {
    expand_braces(pattern).iter().any(|p| {
        let pat: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
        let txt: Vec<&str> = text.split('/').filter(|s| !s.is_empty()).collect();
        match_segments(&pat, &txt)
    })
}

/// True when the glob matches `text` or any directory containing it, which is
/// how ignore-walk treats a matched directory.
fn match_glob_or_parent(pattern: &str, text: &str) -> bool {
    let segments: Vec<&str> = text.split('/').filter(|s| !s.is_empty()).collect();
    (1..=segments.len()).any(|n| match_glob(pattern, &segments[..n].join("/")))
}

fn expand_braces(pattern: &str) -> Vec<String> {
    const MAX_BRACE_EXPANSIONS: usize = 1024;
    let mut results = vec![pattern.to_string()];
    let mut i = 0;
    while i < results.len() {
        let current = results[i].clone();
        let Some(open) = current.find('{') else {
            i += 1;
            continue;
        };
        let mut depth = 0usize;
        let mut close = None;
        for (idx, c) in current[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + idx);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            i += 1;
            continue;
        };
        let inner = &current[open + 1..close];
        let mut parts = Vec::new();
        let (mut d, mut start) = (0usize, 0usize);
        for (idx, c) in inner.char_indices() {
            match c {
                '{' => d += 1,
                '}' => d -= 1,
                ',' if d == 0 => {
                    parts.push(&inner[start..idx]);
                    start = idx + 1;
                }
                _ => {}
            }
        }
        parts.push(&inner[start..]);
        if parts.len() < 2 {
            i += 1;
            continue;
        }
        let (head, tail) = (&current[..open], &current[close + 1..]);
        if results.len() - 1 + parts.len() > MAX_BRACE_EXPANSIONS {
            i += 1;
            continue;
        }
        results.remove(i);
        for (offset, part) in parts.into_iter().enumerate() {
            results.insert(i + offset, format!("{head}{part}{tail}"));
        }
    }
    results
}

fn match_segments(pat: &[&str], txt: &[&str]) -> bool {
    match pat.first() {
        None => txt.is_empty(),
        Some(&"**") => {
            // `**` never matches dot-entries, mirroring minimatch's default.
            match_segments(&pat[1..], txt)
                || (!txt.is_empty() && !txt[0].starts_with('.') && match_segments(pat, &txt[1..]))
        }
        Some(seg) => {
            !txt.is_empty() && match_segment(seg, txt[0]) && match_segments(&pat[1..], &txt[1..])
        }
    }
}

fn match_segment(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // A leading wildcard does not match a leading dot (minimatch `dot: false`).
    if t.first() == Some(&'.') && matches!(p.first(), Some('*') | Some('?') | Some('[')) {
        return false;
    }

    enum PatTok {
        Star,
        Any,
        Lit(char),
        Class { negate: bool, ranges: Vec<(char, char)> },
    }

    let mut tokens = Vec::with_capacity(p.len());
    let mut pi = 0usize;
    while pi < p.len() {
        match p[pi] {
            '*' => {
                if !matches!(tokens.last(), Some(PatTok::Star)) {
                    tokens.push(PatTok::Star);
                }
                pi += 1;
            }
            '?' => {
                tokens.push(PatTok::Any);
                pi += 1;
            }
            '[' => {
                if let Some(end_rel) = p[pi + 1..].iter().position(|&c| c == ']') {
                    let end = pi + 1 + end_rel;
                    let mut class = &p[pi + 1..end];
                    let negate = matches!(class.first(), Some('!') | Some('^'));
                    if negate {
                        class = &class[1..];
                    }
                    let mut ranges = Vec::new();
                    let mut ci = 0usize;
                    while ci < class.len() {
                        if ci + 2 < class.len() && class[ci + 1] == '-' {
                            ranges.push((class[ci], class[ci + 2]));
                            ci += 3;
                        } else {
                            ranges.push((class[ci], class[ci]));
                            ci += 1;
                        }
                    }
                    tokens.push(PatTok::Class { negate, ranges });
                    pi = end + 1;
                } else {
                    tokens.push(PatTok::Lit('['));
                    pi += 1;
                }
            }
            '\\' if pi + 1 < p.len() => {
                tokens.push(PatTok::Lit(p[pi + 1]));
                pi += 2;
            }
            c => {
                tokens.push(PatTok::Lit(c));
                pi += 1;
            }
        }
    }

    let n = t.len();
    let mut dp = vec![false; n + 1];
    let mut next = vec![false; n + 1];
    dp[0] = true;

    for tok in &tokens {
        next.fill(false);
        match tok {
            PatTok::Star => {
                let mut seen = false;
                for j in 0..=n {
                    if dp[j] {
                        seen = true;
                    }
                    next[j] = seen;
                }
            }
            PatTok::Any => {
                for j in 0..n {
                    if dp[j] {
                        next[j + 1] = true;
                    }
                }
            }
            PatTok::Lit(expected) => {
                for j in 0..n {
                    if dp[j] && t[j] == *expected {
                        next[j + 1] = true;
                    }
                }
            }
            PatTok::Class { negate, ranges } => {
                for j in 0..n {
                    if dp[j] {
                        let c = t[j];
                        let hit = ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi);
                        if hit != *negate {
                            next[j + 1] = true;
                        }
                    }
                }
            }
        }
        std::mem::swap(&mut dp, &mut next);
    }

    dp[n]
}

/// Sort helper for npm pack files:
/// Files starting with uppercase letter come first (alphabetical),
/// followed by others (alphabetical).
fn sort_pack_file_paths(a: &str, b: &str) -> std::cmp::Ordering {
    let a_first_char = a.chars().next().unwrap_or('\0');
    let b_first_char = b.chars().next().unwrap_or('\0');

    // npm's tar.js: `ch === ch.toUpperCase()`, so digits and punctuation
    // sort with the uppercase group.
    let a_is_upper = !a_first_char.is_lowercase();
    let b_is_upper = !b_first_char.is_lowercase();

    match (a_is_upper, b_is_upper) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.cmp(b),
    }
}

/// Summarize an existing .tgz the way npm's `getContents` does, returning
/// the summary and the parsed `package/package.json`.
pub fn summarize_tarball(bytes: &[u8]) -> Result<(PackSummary, serde_json::Value), FsError> {
    let gz = GzDecoder::new(bytes);
    let buffered = io::BufReader::with_capacity(64 * 1024, gz);
    let mut archive = Archive::new(buffered);
    let mut files = Vec::new();
    let mut bundled: Vec<String> = Vec::new();
    let mut unpacked_size = 0u64;
    let mut entry_count = 0usize;
    let mut manifest: Option<serde_json::Value> = None;
    for entry in archive.entries().map_err(FsError::Io)? {
        let mut entry = entry.map_err(FsError::Io)?;
        let raw = entry
            .path()
            .map_err(FsError::Io)?
            .to_string_lossy()
            .replace('\\', "/");
        let size = entry.header().size().map_err(FsError::Io)?;
        let mode = entry.header().mode().map_err(FsError::Io)?;
        entry_count += 1;
        unpacked_size += size;
        if let Some(rest) = raw
            .strip_prefix("package/node_modules/")
            .filter(|r| !r.is_empty())
        {
            let mut parts = rest.split('/');
            let first = parts.next().unwrap_or("");
            let name = if first.starts_with('@') {
                format!("{first}/{}", parts.next().unwrap_or(""))
            } else {
                first.to_string()
            };
            if !bundled.contains(&name) {
                bundled.push(name);
            }
        }
        let path = raw.strip_prefix("package/").unwrap_or(&raw).to_string();
        if path == "package.json" {
            let mut text = String::new();
            entry.read_to_string(&mut text).map_err(FsError::Io)?;
            manifest = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok();
        }
        files.push(PackedFileEntry { path, size, mode });
    }
    let manifest = manifest.ok_or_else(|| {
        FsError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "package.json not found in tarball",
        ))
    })?;
    files.sort_by(|a, b| sort_pack_file_paths(&a.path, &b.path));
    let name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let summary = PackSummary {
        filename: compute_tarball_filename(&name, &version),
        name,
        version,
        package_size: bytes.len() as u64,
        unpacked_size,
        shasum: data_encoding::HEXLOWER.encode(&Algorithm::Sha1.compute_digest(bytes)),
        integrity: Integrity::from_bytes(bytes, Algorithm::Sha512).to_string(),
        files,
        entry_count,
        bundled,
    };
    Ok((summary, manifest))
}

/// Text of one `package/<path>` entry in a .tgz, if present.
pub fn read_tarball_text(bytes: &[u8], inner_path: &str) -> Option<String> {
    let gz = GzDecoder::new(bytes);
    let buffered = io::BufReader::with_capacity(64 * 1024, gz);
    let mut archive = Archive::new(buffered);
    for entry in archive.entries().ok()? {
        let mut entry = entry.ok()?;
        let raw = entry.path().ok()?.to_string_lossy().replace('\\', "/");
        if raw.strip_prefix("package/").unwrap_or(&raw) == inner_path {
            let mut text = String::new();
            entry.read_to_string(&mut text).ok()?;
            return Some(text);
        }
    }
    None
}

/// Create a tar.gz package archive for the project directory.
/// All file paths inside the archive are prefixed with `package/`.
/// All entries are created with POSIX normalized mode (0o644 or 0o755) and mtime (499162500).
pub fn pack_directory(
    package_dir: &Path,
    dest_tarball_path: Option<&Path>,
) -> Result<(PackSummary, Vec<u8>), FsError> {
    let manifest_path = package_dir.join("package.json");
    if !manifest_path.is_file() {
        return Err(FsError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("package.json not found in {}", package_dir.display()),
        )));
    }

    let manifest = Manifest::from_file(&manifest_path)
        .map_err(|e| FsError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))?;

    let name = manifest
        .name
        .clone()
        .unwrap_or_else(|| "package".to_string());
    let version = manifest
        .version
        .clone()
        .unwrap_or_else(|| "1.0.0".to_string());
    let filename = compute_tarball_filename(&name, &version);

    let files_to_pack = collect_pack_files(package_dir, &manifest)?;
    // npm-packlist sorts archive entries by extension, basename, then path for
    // compressibility. The public file list keeps its separate display order.
    let mut archive_files: Vec<_> = files_to_pack.iter().collect();
    archive_files.sort_by_key(|(path, _)| {
        let file = Path::new(path);
        (
            file.extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase(),
            file.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase(),
            path.to_lowercase(),
        )
    });

    // Build tar archive in memory
    let mut file_meta_cache: HashMap<&str, (u64, u32)> = HashMap::with_capacity(files_to_pack.len());
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);

        for (rel_path, full_path) in archive_files {
            let file_data = fs::read(full_path)?;
            let mut header = Header::new_ustar();
            header.set_size(file_data.len() as u64);

            // Normalized mtime
            header.set_mtime(NPM_PACK_EPOCH_MTIME);
            header.set_uid(0);
            header.set_gid(0);

            // Normalized mode
            let is_executable = is_file_executable(full_path);
            let mode = if is_executable {
                NPM_EXECUTABLE_FILE_MODE
            } else {
                NPM_DEFAULT_FILE_MODE
            };
            file_meta_cache.insert(rel_path.as_str(), (file_data.len() as u64, mode));
            header.set_mode(mode);
            let entry_path = format!("package/{rel_path}");
            header.set_path(entry_path).map_err(FsError::Io)?;
            header.set_entry_type(tar::EntryType::Regular);
            // node-tar's portable USTAR encoder leaves uid/gid unset, and uses
            // octal digits followed by space + NUL (including checksum).
            let bytes = header.as_mut_bytes();
            bytes[108..124].fill(0);
            for (start, end, value) in [
                (100, 108, mode as u64),
                (124, 136, file_data.len() as u64),
                (136, 148, NPM_PACK_EPOCH_MTIME),
                (329, 337, 0),
                (337, 345, 0),
            ] {
                let encoded = format!("{:0width$o} \0", value, width = end - start - 2);
                bytes[start..end].copy_from_slice(encoded.as_bytes());
            }
            bytes[148..156].fill(b' ');
            let sum: u64 = bytes.iter().map(|b| *b as u64).sum();
            bytes[148..156].copy_from_slice(format!("{sum:06o} \0").as_bytes());
            builder
                .append(&header, &file_data[..])
                .map_err(FsError::Io)?;
        }

        builder.finish().map_err(FsError::Io)?;
    }

    // Compress with gzip level 9
    let compressed_bytes = npm_gzip(&tar_bytes)?;

    // Compute SHA-1 and SHA-512 hashes
    let sha1_digest = Algorithm::Sha1.compute_digest(&compressed_bytes);
    let shasum = data_encoding::HEXLOWER.encode(&sha1_digest);

    let integrity_obj = Integrity::from_bytes(&compressed_bytes, Algorithm::Sha512);
    let integrity_str = integrity_obj.to_string();

    let mut unpacked_size = 0u64;
    let mut summary_files = Vec::with_capacity(files_to_pack.len());

    for (rel_path, full_path) in &files_to_pack {
        let (size, mode) = match file_meta_cache.get(rel_path.as_str()) {
            Some(&pair) => pair,
            None => {
                let meta = fs::metadata(full_path)?;
                let mode = if is_file_executable(full_path) {
                    NPM_EXECUTABLE_FILE_MODE
                } else {
                    NPM_DEFAULT_FILE_MODE
                };
                (meta.len(), mode)
            }
        };
        unpacked_size += size;
        summary_files.push(PackedFileEntry {
            path: rel_path.clone(),
            size,
            mode,
        });
    }

    let entry_count = summary_files.len();

    let summary = PackSummary {
        name,
        version,
        filename: filename.clone(),
        package_size: compressed_bytes.len() as u64,
        unpacked_size,
        shasum,
        integrity: integrity_str,
        files: summary_files,
        entry_count,
        bundled: manifest.bundled_package_names(),
    };

    // If destination path is provided, write out the compressed tarball
    if let Some(dest_path) = dest_tarball_path {
        let mut out = File::create(dest_path)?;
        out.write_all(&compressed_bytes)?;
    }

    Ok((summary, compressed_bytes))
}

/// npm's digests depend on the Node runtime's zlib byte stream. Different
/// compliant DEFLATE implementations produce different digests. Use only the
/// built-in zlib module, without requiring an npm installation.
fn npm_gzip(input: &[u8]) -> Result<Vec<u8>, FsError> {
    use std::process::{Command, Stdio};
    const SCRIPT: &str = "const {pipeline,Transform}=require('node:stream');let first=true;pipeline(process.stdin,require('node:zlib').createGzip({level:9}),new Transform({transform(b,e,cb){if(first){b[9]=255;first=false;}cb(null,b);}}),process.stdout,e=>{if(e){console.error(e.message);process.exitCode=1;}});";
    let mut command = Command::new("node");
    command
        .args(["-e", SCRIPT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return pure_rust_gzip(input);
        }
        Err(err) => return Err(FsError::Io(err)),
    };
    let mut stdin = child.stdin.take().expect("piped child stdin");
    let (output, written) = std::thread::scope(|scope| {
        // Drain stdout while feeding stdin so large archives cannot deadlock
        // when both OS pipes fill. Always reap the child, including EPIPE.
        let writer = scope.spawn(move || stdin.write_all(input));
        let output = child.wait_with_output();
        (output, writer.join())
    });
    let output = output.map_err(FsError::Io)?;
    if !output.status.success() {
        return Err(FsError::Io(std::io::Error::other(format!(
            "Node gzip failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))));
    }
    written
        .map_err(|_| FsError::Io(std::io::Error::other("gzip input writer panicked")))?
        .map_err(FsError::Io)?;
    Ok(output.stdout)
}

/// Pure-Rust gzip fallback when `node` is unavailable.
/// Uses `flate2::write::GzEncoder` at compression level 9 with OS header byte (byte 9)
/// set to 255 (0xFF), matching npm's gzip header formatting.
pub fn pure_rust_gzip(input: &[u8]) -> Result<Vec<u8>, FsError> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let initial_cap = (input.len() / 2).max(1024);
    let mut encoder = GzEncoder::new(Vec::with_capacity(initial_cap), Compression::new(9));
    encoder.write_all(input).map_err(FsError::Io)?;
    let mut output = encoder.finish().map_err(FsError::Io)?;
    if output.len() >= 10 {
        output[9] = 255;
    }
    Ok(output)
}

/// Pure-Rust gzip helper alias for `pure_rust_gzip`.
pub fn rust_gzip(input: &[u8]) -> Result<Vec<u8>, FsError> {
    pure_rust_gzip(input)
}

fn is_file_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            return meta.permissions().mode() & 0o111 != 0;
        }
    }

    #[cfg(windows)]
    {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_ascii_lowercase();
            if ext_lower == "cmd" || ext_lower == "bat" || ext_lower == "ps1" || ext_lower == "exe"
            {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod glob_tests {
    use super::{match_glob, match_glob_or_parent};

    #[test]
    fn globstar_matches_any_depth_including_none() {
        assert!(match_glob("secrets/**/*.pem", "secrets/prod/key.pem"));
        assert!(match_glob("secrets/**/*.pem", "secrets/key.pem"));
        assert!(match_glob("dist/**/*.js", "dist/sub/deep/index.js"));
        assert!(!match_glob("dist/**/*.js", "dist/sub/index.ts"));
        assert!(!match_glob("dist/*.js", "dist/sub/index.js"));
    }

    #[test]
    fn classes_braces_and_question_marks() {
        assert!(match_glob("lib/*.{js,cjs}", "lib/a.cjs"));
        assert!(!match_glob("lib/*.{js,cjs}", "lib/a.ts"));
        assert!(match_glob("file?.txt", "file1.txt"));
        assert!(match_glob("v[0-9].js", "v7.js"));
        assert!(!match_glob("v[!0-9].js", "v7.js"));
    }

    #[test]
    fn wildcards_skip_dotfiles_like_minimatch() {
        assert!(!match_glob("*", ".env"));
        assert!(!match_glob("**/*.js", ".hidden/a.js"));
    }

    #[test]
    fn matched_directories_cover_their_contents() {
        assert!(match_glob_or_parent("secrets/prod", "secrets/prod/key.pem"));
        assert!(!match_glob_or_parent(
            "secrets/prod",
            "secrets/production/key.pem"
        ));
    }
}

#[cfg(test)]
mod gzip_tests {
    use super::{pure_rust_gzip, rust_gzip};
    use flate2::read::GzDecoder;
    use std::io::Read;

    #[test]
    fn test_pure_rust_gzip_os_byte_and_roundtrip() {
        let test_inputs: Vec<&[u8]> = vec![
            b"",
            b"hello world",
            b"The quick brown fox jumps over the lazy dog",
            &[0u8; 10000],
            b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
        ];

        for input in test_inputs {
            let compressed = pure_rust_gzip(input).expect("pure_rust_gzip should succeed");

            // Verify valid gzip header
            assert!(
                compressed.len() >= 10,
                "gzip output must have header of at least 10 bytes"
            );
            assert_eq!(compressed[0], 0x1f, "gzip magic byte 1");
            assert_eq!(compressed[1], 0x8b, "gzip magic byte 2");
            assert_eq!(compressed[2], 0x08, "gzip compression method (deflate)");

            // Verify OS byte (byte 9) is 255 (0xFF)
            assert_eq!(
                compressed[9], 255,
                "gzip header byte 9 (OS flag) must be 255 (0xFF)"
            );

            // Verify round-trip decompression
            let mut decoder = GzDecoder::new(&compressed[..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .expect("decompression must succeed");
            assert_eq!(
                decompressed, input,
                "round-trip decompressed bytes must match original input"
            );

            // Also test rust_gzip alias
            let compressed_alias = rust_gzip(input).expect("rust_gzip alias should succeed");
            assert_eq!(compressed_alias[9], 255);
            let mut decoder2 = GzDecoder::new(&compressed_alias[..]);
            let mut decompressed2 = Vec::new();
            decoder2
                .read_to_end(&mut decompressed2)
                .expect("decompression must succeed");
            assert_eq!(decompressed2, input);
        }
    }

    #[test]
    fn test_glob_match_segment_no_exponential_backtracking_and_brace_cap() {
        let start = std::time::Instant::now();
        let pattern = "a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let text = "a".repeat(64);
        assert!(!super::match_segment(pattern, &text));
        assert!(super::match_segment("a*a*b", "aaaaab"));
        assert!(
            start.elapsed() < std::time::Duration::from_millis(200),
            "multi-star glob took too long: {:?}",
            start.elapsed()
        );

        let nested_braces = "{a,b}".repeat(12); // 2^12 = 4096 uncapped
        let expanded = super::expand_braces(&nested_braces);
        assert!(
            expanded.len() <= 1024,
            "brace expansion must be capped at 1024, got {}",
            expanded.len()
        );
    }
}
