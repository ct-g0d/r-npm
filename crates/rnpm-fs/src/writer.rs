use crate::error::FsError;
use crate::tarball::{
    fast_validate_and_strip_ascii, join_clean_rel, normalize_rel_path, strip_package_prefix,
    unlink_target_path, validate_entry_path, validate_link_target, CountingReader,
    ExtractionSummary, TarLimits,
};
use data_encoding::HEXLOWER;
use flate2::read::GzDecoder;
use path_clean::clean;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tar::Archive;

#[cfg(windows)]
static DRIVE_SEEK_CACHE: [AtomicU8; 26] = [const { AtomicU8::new(0) }; 26];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveType {
    Ssd,
    Hdd,
    Unknown,
}

pub fn wait_all_handles_closed() {}

/// Detects whether the storage volume hosting `path` has a seek penalty (HDD) or not (SSD/NVMe).
///
/// On Windows, queries `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceSeekPenaltyProperty`.
/// If no seek penalty is reported, returns `Some(false)` (SSD/NVMe).
/// If seek penalty is reported, returns `Some(true)` (HDD).
/// If the query fails or on non-Windows platforms, returns `None`.
pub fn detect_seek_penalty(path: &Path) -> Option<bool> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::path::Component;

        let abs_path = if path.is_relative() {
            std::env::current_dir().ok()?.join(path)
        } else {
            path.to_path_buf()
        };

        let clean_str = crate::path::strip_verbatim_prefix(&abs_path);
        let clean_lossy = clean_str.to_string_lossy();

        let drive_char = if clean_lossy.len() >= 2 && clean_lossy.as_bytes()[1] == b':' {
            (clean_lossy.as_bytes()[0] as char).to_ascii_uppercase()
        } else {
            let mut found = None;
            for c in abs_path.components() {
                if let Component::Prefix(prefix) = c {
                    match prefix.kind() {
                        std::path::Prefix::Disk(d) | std::path::Prefix::VerbatimDisk(d) => {
                            found = Some((d as char).to_ascii_uppercase());
                            break;
                        }
                        _ => {}
                    }
                }
            }
            found?
        };

        let drive_idx = if drive_char.is_ascii_uppercase() {
            Some((drive_char as u8 - b'A') as usize)
        } else {
            None
        };
        if let Some(idx) = drive_idx {
            match DRIVE_SEEK_CACHE[idx].load(Ordering::Relaxed) {
                1 => return Some(false),
                2 => return Some(true),
                3 => return None,
                _ => {}
            }
        }

        let device_name = format!(r"\\.\{drive_char}:");
        let device_wide: Vec<u16> = std::ffi::OsStr::new(&device_name)
            .encode_wide()
            .chain(Some(0))
            .collect();

        extern "system" {
            fn CreateFileW(
                lpFileName: *const u16,
                dwDesiredAccess: u32,
                dwShareMode: u32,
                lpSecurityAttributes: *mut std::ffi::c_void,
                dwCreationDisposition: u32,
                dwFlagsAndAttributes: u32,
                hTemplateFile: *mut std::ffi::c_void,
            ) -> *mut std::ffi::c_void;

            fn DeviceIoControl(
                hDevice: *mut std::ffi::c_void,
                dwIoControlCode: u32,
                lpInBuffer: *const std::ffi::c_void,
                nInBufferSize: u32,
                lpOutBuffer: *mut std::ffi::c_void,
                nOutBufferSize: u32,
                lpBytesReturned: *mut u32,
                lpOverlapped: *mut std::ffi::c_void,
            ) -> i32;

            fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        }

        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;
        const FILE_SHARE_DELETE: u32 = 4;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;
        const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;

        #[repr(C)]
        #[allow(non_snake_case)]
        struct STORAGE_PROPERTY_QUERY {
            PropertyId: u32,
            QueryType: u32,
            AdditionalParameters: [u8; 1],
        }

        #[repr(C)]
        #[allow(non_snake_case)]
        struct DEVICE_SEEK_PENALTY_DESCRIPTOR {
            Version: u32,
            Size: u32,
            IncursSeekPenalty: u8,
        }

        // dwDesiredAccess = 0 allows querying device attributes without requiring admin privileges
        let handle = unsafe {
            CreateFileW(
                device_wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            if let Some(idx) = drive_idx {
                DRIVE_SEEK_CACHE[idx].store(3, Ordering::Relaxed);
            }
            return None;
        }

        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: 7, // StorageDeviceSeekPenaltyProperty
            QueryType: 0,  // PropertyStandardQuery
            AdditionalParameters: [0],
        };

        let mut desc = DEVICE_SEEK_PENALTY_DESCRIPTOR {
            Version: 0,
            Size: 0,
            IncursSeekPenalty: 0,
        };
        let mut bytes_returned = 0u32;

        let res = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &query as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                &mut desc as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        unsafe {
            CloseHandle(handle);
        }

        if res != 0 {
            let has_penalty = desc.IncursSeekPenalty != 0;
            if let Some(idx) = drive_idx {
                DRIVE_SEEK_CACHE[idx].store(if has_penalty { 2 } else { 1 }, Ordering::Relaxed);
            }
            Some(has_penalty)
        } else {
            if let Some(idx) = drive_idx {
                DRIVE_SEEK_CACHE[idx].store(3, Ordering::Relaxed);
            }
            None
        }
    }

    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

/// Configuration for parallel file materialization.
#[derive(Debug, Clone)]
pub struct ParallelWriterConfig {
    pub worker_threads: usize,
    pub is_hdd: bool,
    pub preallocate_threshold: usize,
    pub skip_existing_matching: bool,
}

impl Default for ParallelWriterConfig {
    fn default() -> Self {
        Self {
            worker_threads: 0,
            is_hdd: false,
            preallocate_threshold: 64 * 1024, // 64 KiB
            skip_existing_matching: false,
        }
    }
}

/// Automatically determines optimal worker thread count and disk type for `path`.
///
/// Rules per design spec:
/// - SSD (no seek penalty): 24-32 worker threads
/// - HDD (seek penalty): 4 worker threads, grouping writes by package
/// - Fallback (non-Windows or query failure): 16-24 worker threads
pub fn determine_writer_config(
    path: &Path,
    user_concurrency: Option<usize>,
) -> ParallelWriterConfig {
    let seek_penalty = detect_seek_penalty(path);

    let (threads, is_hdd) = if let Some(c) = user_concurrency {
        if c > 0 {
            (c, seek_penalty.unwrap_or(false))
        } else {
            select_default_concurrency(seek_penalty)
        }
    } else {
        select_default_concurrency(seek_penalty)
    };

    ParallelWriterConfig {
        worker_threads: threads,
        is_hdd,
        preallocate_threshold: 64 * 1024,
        skip_existing_matching: false,
    }
}

fn select_default_concurrency(seek_penalty: Option<bool>) -> (usize, bool) {
    match seek_penalty {
        Some(false) => {
            // SSD: 24 to 32 worker threads
            let threads = std::thread::available_parallelism()
                .map(|n| (n.get() * 4).clamp(24, 32))
                .unwrap_or(24);
            (threads, false)
        }
        Some(true) => {
            // HDD: 4 worker threads, grouping writes by package
            (4, true)
        }
        None => {
            // Fallback: 16 to 24 worker threads
            let threads = std::thread::available_parallelism()
                .map(|n| (n.get() * 2).clamp(16, 24))
                .unwrap_or(16);
            (threads, false)
        }
    }
}

#[cfg(windows)]
#[inline]
fn dir_exists_wide(wide_null_term: &[u16]) -> bool {
    extern "system" {
        fn GetFileAttributesW(lpFileName: *const u16) -> u32;
    }
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    debug_assert_eq!(wide_null_term.last().copied(), Some(0));
    // SAFETY: `wide_null_term` is NUL-terminated UTF-16 passed read-only to Win32 `GetFileAttributesW`.
    let attrs = unsafe { GetFileAttributesW(wide_null_term.as_ptr()) };
    attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0
}

#[cfg(windows)]
#[inline]
fn create_dir_wide_or_fallback(wide: &[u16]) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStringExt;
    extern "system" {
        fn CreateDirectoryW(
            lpPathName: *const u16,
            lpSecurityAttributes: *mut std::ffi::c_void,
        ) -> i32;
        fn GetLastError() -> u32;
    }
    const ERROR_ALREADY_EXISTS: u32 = 183;

    debug_assert_eq!(wide.last().copied(), Some(0));
    // SAFETY: `wide` is NUL-terminated UTF-16 passed read-only with a null security descriptor pointer.
    let ret = unsafe { CreateDirectoryW(wide.as_ptr(), std::ptr::null_mut()) };
    if ret == 0 {
        let err = unsafe { GetLastError() };
        if !(err == ERROR_ALREADY_EXISTS && dir_exists_wide(wide)) {
            let dir_path = std::ffi::OsString::from_wide(&wide[..wide.len().saturating_sub(1)]);
            std::fs::create_dir_all(&dir_path)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
#[inline]
fn create_dir_bytes_wide_buf(dir_bytes: &[u8], wide_buf: &mut Vec<u16>) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    wide_buf.clear();
    debug_assert!(!dir_bytes.is_empty());
    // SAFETY: `dir_bytes` comes exclusively from `Path::as_os_str().as_encoded_bytes()` sliced
    // immediately before an ASCII `b'\\'` (`0x5C`) separator (or at full slice length). Because `0x5C`
    // is ASCII `< 0x80`, it can never fall inside a multi-byte UTF-8/WTF-8 code unit sequence nor split
    // a surrogate pair across both halves, so every prefix cut before `b'\\'` preserves valid WTF-8.
    let os = unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(dir_bytes) };
    wide_buf.extend(os.encode_wide());
    wide_buf.push(0);
    create_dir_wide_or_fallback(wide_buf)
}

/// Pre-creates a collection of directories in breadth-first order (by path depth),
/// eliminating redundant `exists()` calls in the subsequent file write loop.
///
/// Paths are converted to verbatim `\\?\` format on Windows.
pub fn precreate_directories<'a, I>(dirs: I) -> std::io::Result<()>
where
    I: IntoIterator<Item = &'a Path>,
{
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        let iter = dirs.into_iter();
        let (lower, _) = iter.size_hint();
        let mut raw_seen: HashSet<&std::ffi::OsStr> = HashSet::with_capacity(lower);
        let mut unique_paths: Vec<PathBuf> = Vec::with_capacity(lower);
        let mut verb_seen: HashSet<PathBuf> = HashSet::with_capacity(lower);

        for d in iter {
            let os = d.as_os_str();
            if os.is_empty() || !raw_seen.insert(os) {
                continue;
            }
            let verbatim = crate::path::to_verbatim_path(d);
            if verb_seen.insert(verbatim.clone()) {
                unique_paths.push(verbatim);
            }
        }

        if unique_paths.is_empty() {
            return Ok(());
        }

        // Compute longest common directory prefix on clean verbatim paths so we
        // ensure the shared root exists once and never touch drive roots (C:\).
        let common_prefix: Option<PathBuf> = {
            let mut prefix = unique_paths[0].as_os_str().as_encoded_bytes();
            for p in &unique_paths[1..] {
                let b = p.as_os_str().as_encoded_bytes();
                let min_len = prefix.len().min(b.len());
                let mut i = 0;
                while i < min_len && prefix[i] == b[i] {
                    i += 1;
                }
                let boundary_ok = (i == prefix.len() && (i == b.len() || b[i] == b'\\'))
                    || (i == b.len() && prefix[i] == b'\\')
                    || (i < prefix.len() && i < b.len() && prefix[i] == b'\\' && b[i] == b'\\');
                if !boundary_ok {
                    while i > 0 && prefix[i - 1] != b'\\' {
                        i -= 1;
                    }
                    i = i.saturating_sub(1);
                }
                prefix = &prefix[..i];
                if prefix.len() <= 6 {
                    break;
                }
            }
            // Must include at least one subdirectory below drive root (\\?\X:\sub) or UNC share (\\?\UNC\server\share\sub)
            if prefix.len() > 7 && prefix.starts_with(br"\\?\") {
                let valid = if prefix.starts_with(br"\\?\UNC\") {
                    prefix[8..].iter().filter(|&&b| b == b'\\').count() >= 2
                } else {
                    prefix[5] == b':' && prefix[6] == b'\\'
                };
                if valid {
                    // SAFETY: `prefix` is a non-empty prefix of `unique_paths[0]`'s valid WTF-8 bytes,
                    // guaranteed by `boundary_ok` / the rewind loop to match either the full path or end
                    // immediately before an ASCII `b'\\'` (`0x5C`), preserving valid WTF-8 encoding.
                    let os_prefix =
                        unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(prefix) };
                    Some(PathBuf::from(os_prefix))
                } else {
                    None
                }
            } else {
                None
            }
        };

        let mut known_existing_bytes: HashSet<&[u8]> = HashSet::new();
        let mut scratch_wide = Vec::with_capacity(260);
        if let Some(ref prefix) = common_prefix {
            scratch_wide.extend(prefix.as_os_str().encode_wide());
            scratch_wide.push(0);
            if !dir_exists_wide(&scratch_wide) {
                std::fs::create_dir_all(prefix)?;
            }
            known_existing_bytes.insert(prefix.as_os_str().as_encoded_bytes());
        }

        let mut pending_seen: HashSet<&[u8]> = HashSet::with_capacity(unique_paths.len() * 2);
        let mut by_depth: Vec<(usize, &[u8])> = Vec::with_capacity(unique_paths.len() * 2);
        let mut min_depth = usize::MAX;
        let mut max_depth = 0usize;

        for dir in &unique_paths {
            let full_bytes = dir.as_os_str().as_encoded_bytes();
            let mut end = full_bytes.len();
            let mut depth = full_bytes.iter().filter(|&&b| b == b'\\').count();
            let min_root = if full_bytes.starts_with(br"\\?\UNC\") {
                let mut slashes = 0;
                let mut idx = 8;
                while idx < full_bytes.len() {
                    if full_bytes[idx] == b'\\' {
                        slashes += 1;
                        if slashes == 2 {
                            break;
                        }
                    }
                    idx += 1;
                }
                if slashes >= 2 {
                    idx + 1
                } else {
                    full_bytes.len()
                }
            } else if full_bytes.starts_with(br"\\?\")
                && full_bytes.len() >= 7
                && full_bytes[5] == b':'
            {
                7
            } else {
                4
            };
            while end > min_root {
                debug_assert!(end == full_bytes.len() || full_bytes[end] == b'\\');
                let slice = &full_bytes[..end];
                if known_existing_bytes.contains(slice) || !pending_seen.insert(slice) {
                    break;
                }
                if common_prefix.is_none() {
                    scratch_wide.clear();
                    // SAFETY: `slice` is either the full valid WTF-8 path or cut right before ASCII `b'\\'`.
                    let slice_os =
                        unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(slice) };
                    scratch_wide.extend(slice_os.encode_wide());
                    scratch_wide.push(0);
                    if dir_exists_wide(&scratch_wide) {
                        known_existing_bytes.insert(slice);
                        break;
                    }
                }

                min_depth = min_depth.min(depth);
                max_depth = max_depth.max(depth);
                by_depth.push((depth, slice));

                // Step back to parent component boundary
                let mut p_end = end;
                while p_end > min_root && full_bytes[p_end - 1] != b'\\' {
                    p_end -= 1;
                }
                if p_end <= min_root {
                    break;
                }
                end = p_end - 1;
                depth -= 1;
            }
        }

        let total_to_create = by_depth.len();
        if total_to_create == 0 {
            return Ok(());
        }

        let num_levels = max_depth - min_depth + 1;
        let mut levels: Vec<Vec<&[u8]>> = (0..num_levels).map(|_| Vec::new()).collect();
        for (depth, slice) in by_depth {
            levels[depth - min_depth].push(slice);
        }
        levels.retain(|l| !l.is_empty());

        if total_to_create <= 32 {
            for level in &levels {
                for &slice in level {
                    create_dir_bytes_wide_buf(slice, &mut scratch_wide)?;
                }
            }
            return Ok(());
        }

        // Peel shallow low-fanout levels sequentially so workers can create independent
        // package subtrees top-down with zero barrier synchronization.
        let mut split_idx = 0usize;
        while split_idx + 1 < levels.len() && levels[split_idx].len() < 24 {
            for &slice in &levels[split_idx] {
                create_dir_bytes_wide_buf(slice, &mut scratch_wide)?;
            }
            split_idx += 1;
        }

        if split_idx + 1 >= levels.len() {
            let level = &levels[split_idx];
            let num_threads = 16.min(level.len());
            let cursor = AtomicUsize::new(0);
            let chunk = (level.len() / (num_threads * 2)).clamp(1, 8);
            let has_err = AtomicBool::new(false);
            let first_err: Mutex<Option<std::io::Error>> = Mutex::new(None);
            crate::pool::run_parallel(num_threads, &|| {
                let mut wide_buf = Vec::with_capacity(260);
                loop {
                    if has_err.load(Ordering::Relaxed) {
                        break;
                    }
                    let start = cursor.fetch_add(chunk, Ordering::Relaxed);
                    if start >= level.len() {
                        break;
                    }
                    let end = (start + chunk).min(level.len());
                    for &slice in &level[start..end] {
                        if let Err(e) = create_dir_bytes_wide_buf(slice, &mut wide_buf) {
                            has_err.store(true, Ordering::Relaxed);
                            let mut guard = first_err.lock().unwrap();
                            if guard.is_none() {
                                *guard = Some(e);
                            }
                            return;
                        }
                    }
                }
            });
            if let Some(err) = first_err.into_inner().unwrap() {
                return Err(err);
            }
            return Ok(());
        }

        // Promote a small number of high-fanout scope roots (e.g. `@scope`) so every
        // package gets its own balanced bucket without per-level barriers.
        let mut promoted: HashSet<&[u8]> = HashSet::new();
        {
            let mut child_counts: HashMap<&[u8], usize> =
                HashMap::with_capacity(levels[split_idx].len());
            for &s in &levels[split_idx] {
                child_counts.insert(s, 0);
            }
            for &child in &levels[split_idx + 1] {
                if let Some(pos) = child.iter().rposition(|&c| c == b'\\') {
                    if let Some(cnt) = child_counts.get_mut(&child[..pos]) {
                        *cnt += 1;
                    }
                }
            }
            let high_fanout_count = child_counts.values().filter(|&&c| c >= 16).count();
            if high_fanout_count > 0 && high_fanout_count < 16 {
                for &s in &levels[split_idx] {
                    if child_counts.get(s).copied().unwrap_or(0) >= 16 {
                        create_dir_bytes_wide_buf(s, &mut scratch_wide)?;
                        promoted.insert(s);
                    }
                }
            }
        }

        let mut bucket_map: HashMap<&[u8], usize> = HashMap::with_capacity(total_to_create);
        let mut buckets: Vec<Vec<&[u8]>> = Vec::with_capacity(levels[split_idx].len() * 2);

        for &s in &levels[split_idx] {
            if promoted.contains(s) {
                continue;
            }
            let id = buckets.len();
            bucket_map.insert(s, id);
            buckets.push(vec![s]);
        }

        for lvl in &levels[split_idx + 1..] {
            for &s in lvl {
                let mut cur = s;
                let mut found = None;
                while let Some(pos) = cur.iter().rposition(|&c| c == b'\\') {
                    let parent = &cur[..pos];
                    if let Some(&id) = bucket_map.get(parent) {
                        found = Some(id);
                        break;
                    }
                    cur = parent;
                }
                if let Some(id) = found {
                    bucket_map.insert(s, id);
                    buckets[id].push(s);
                } else {
                    let id = buckets.len();
                    bucket_map.insert(s, id);
                    buckets.push(vec![s]);
                }
            }
        }

        if !buckets.is_empty() {
            let num_threads = 16.min(buckets.len());
            let cursor = AtomicUsize::new(0);
            let chunk = (buckets.len() / (num_threads * 4)).clamp(1, 8);
            let has_err = AtomicBool::new(false);
            let first_err: Mutex<Option<std::io::Error>> = Mutex::new(None);
            crate::pool::run_parallel(num_threads, &|| {
                let mut wide_buf = Vec::with_capacity(260);
                loop {
                    if has_err.load(Ordering::Relaxed) {
                        break;
                    }
                    let start = cursor.fetch_add(chunk, Ordering::Relaxed);
                    if start >= buckets.len() {
                        break;
                    }
                    let end = (start + chunk).min(buckets.len());
                    for bucket in &buckets[start..end] {
                        for &slice in bucket {
                            if let Err(e) = create_dir_bytes_wide_buf(slice, &mut wide_buf) {
                                has_err.store(true, Ordering::Relaxed);
                                let mut guard = first_err.lock().unwrap();
                                if guard.is_none() {
                                    *guard = Some(e);
                                }
                                return;
                            }
                        }
                    }
                }
            });
            if let Some(err) = first_err.into_inner().unwrap() {
                return Err(err);
            }
        }

        Ok(())
    }

    #[cfg(not(windows))]
    {
        let iter = dirs.into_iter();
        let (lower, _) = iter.size_hint();
        let mut raw_seen: HashSet<&std::ffi::OsStr> = HashSet::with_capacity(lower);
        let mut unique_paths: Vec<PathBuf> = Vec::with_capacity(lower);

        for d in iter {
            if !d.as_os_str().is_empty() && raw_seen.insert(d.as_os_str()) {
                unique_paths.push(d.to_path_buf());
            }
        }
        if unique_paths.is_empty() {
            return Ok(());
        }

        let mut common = unique_paths[0].clone();
        for p in &unique_paths[1..] {
            while !p.starts_with(&common) {
                if !common.pop() {
                    break;
                }
            }
            if common.as_os_str().is_empty() {
                break;
            }
        }

        let mut known_existing: HashSet<PathBuf> = HashSet::new();
        if !common.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(&common);
            known_existing.insert(common);
        }

        let mut pending_seen: HashSet<PathBuf> = HashSet::with_capacity(unique_paths.len() * 2);
        let mut by_depth: Vec<(usize, PathBuf)> = Vec::with_capacity(unique_paths.len() * 2);
        let mut min_depth = usize::MAX;
        let mut max_depth = 0usize;

        for dir in &unique_paths {
            let mut curr = dir.as_path();
            loop {
                if known_existing.contains(curr) || !pending_seen.insert(curr.to_path_buf()) {
                    break;
                }
                if curr.is_dir() {
                    known_existing.insert(curr.to_path_buf());
                    break;
                }
                let depth = curr.components().count();
                min_depth = min_depth.min(depth);
                max_depth = max_depth.max(depth);
                by_depth.push((depth, curr.to_path_buf()));
                match curr.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() && parent != curr => {
                        curr = parent;
                    }
                    _ => break,
                }
            }
        }

        let total = by_depth.len();
        if total == 0 {
            return Ok(());
        }

        let num_levels = max_depth - min_depth + 1;
        let mut levels: Vec<Vec<PathBuf>> = (0..num_levels).map(|_| Vec::new()).collect();
        for (depth, path) in by_depth {
            levels[depth - min_depth].push(path);
        }
        levels.retain(|l| !l.is_empty());

        if total <= 32 {
            for level in &levels {
                for p in level {
                    if let Err(e) = std::fs::create_dir(p) {
                        if e.kind() != std::io::ErrorKind::AlreadyExists {
                            let _ = std::fs::create_dir_all(p);
                        }
                    }
                }
            }
            return Ok(());
        }

        let max_level_len = levels.iter().map(|l| l.len()).max().unwrap_or(1);
        let num_threads = 16.min(max_level_len.max(2)).min(total);
        let cursors: Vec<std::sync::atomic::AtomicUsize> = levels
            .iter()
            .map(|_| std::sync::atomic::AtomicUsize::new(0))
            .collect();
        let barrier = std::sync::Barrier::new(num_threads);

        std::thread::scope(|scope| {
            for _ in 0..num_threads {
                scope.spawn(|| {
                    for (idx, level) in levels.iter().enumerate() {
                        let len = level.len();
                        let cursor = &cursors[idx];
                        let chunk = (len / (num_threads * 2)).clamp(1, 8);
                        loop {
                            let start = cursor.fetch_add(chunk, Ordering::Relaxed);
                            if start >= len {
                                break;
                            }
                            let end = (start + chunk).min(len);
                            for p in &level[start..end] {
                                if let Err(e) = std::fs::create_dir(p) {
                                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                                        let _ = std::fs::create_dir_all(p);
                                    }
                                }
                            }
                        }
                        if idx + 1 < levels.len() {
                            barrier.wait();
                        }
                    }
                });
            }
        });

        Ok(())
    }
}

/// Writes a file directly using a caller-supplied null-terminated Windows verbatim UTF-16 path.
#[cfg(windows)]
#[inline]
pub fn write_file_fast_wide_raw(
    path_wide: &[u16],
    path_hint: &Path,
    data: &[u8],
    mode: u32,
    prealloc_threshold: usize,
    record_stats: bool,
) -> std::io::Result<()> {
    if path_wide.last() != Some(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path_wide must be NUL-terminated",
        ));
    }
    write_file_fast_wide(path_wide, path_hint, data, mode, prealloc_threshold, record_stats)
}

#[cfg(windows)]
pub(crate) fn write_file_fast_wide(
    path_wide: &[u16],
    path_hint: &Path,
    data: &[u8],
    _mode: u32,
    _prealloc_threshold: usize,
    record_stats: bool,
) -> std::io::Result<()> {
    debug_assert_eq!(path_wide.last().copied(), Some(0));
    extern "system" {
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut std::ffi::c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;

        fn WriteFile(
            hFile: *mut std::ffi::c_void,
            lpBuffer: *const std::ffi::c_void,
            nNumberOfBytesToWrite: u32,
            lpNumberOfBytesWritten: *mut u32,
            lpOverlapped: *mut std::ffi::c_void,
        ) -> i32;

        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
    }

    const GENERIC_WRITE: u32 = 0x40000000;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_FILE_EXISTS: u32 = 80;
    const ERROR_ALREADY_EXISTS: u32 = 183;

    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_SHARE_DELETE: u32 = 4;
    const FILE_SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // Fast path: exclusive creation avoids truncating an existing hardlink or
    // following a symlink without paying a pre-stat syscall on fresh installs.
    let mut handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_ALL,
            std::ptr::null_mut(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        if err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS || err == ERROR_ACCESS_DENIED {
            crate::tarball::unlink_target_path_wide(path_wide, path_hint);
            handle = unsafe {
                CreateFileW(
                    path_wide.as_ptr(),
                    GENERIC_WRITE,
                    FILE_SHARE_ALL,
                    std::ptr::null_mut(),
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
        } else if err == ERROR_PATH_NOT_FOUND {
            use std::os::windows::ffi::OsStringExt;
            let trimmed = &path_wide[..path_wide.len().saturating_sub(1)];
            if let Some(sep) = trimmed.iter().rposition(|&c| c == b'\\' as u16) {
                let parent_os = std::ffi::OsString::from_wide(&trimmed[..sep]);
                let _ = std::fs::create_dir_all(&parent_os);
            } else if let Some(parent) = path_hint.parent() {
                let parent_v = crate::path::to_verbatim_path(parent);
                let _ = std::fs::create_dir_all(&parent_v);
            }
            handle = unsafe {
                CreateFileW(
                    path_wide.as_ptr(),
                    GENERIC_WRITE,
                    FILE_SHARE_ALL,
                    std::ptr::null_mut(),
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
        }
        if handle == INVALID_HANDLE_VALUE {
            let final_err = unsafe { GetLastError() };
            return Err(std::io::Error::from_raw_os_error(final_err as i32));
        }
    }

    let data_len = data.len();

    if data_len > 0 {
        let mut offset = 0usize;
        while offset < data_len {
            let chunk_len = ((data_len - offset).min(u32::MAX as usize)) as u32;
            let mut written = 0u32;
            let ok = unsafe {
                WriteFile(
                    handle,
                    data[offset..].as_ptr() as *const std::ffi::c_void,
                    chunk_len,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                unsafe {
                    CloseHandle(handle);
                }
                return Err(std::io::Error::from_raw_os_error(err as i32));
            }
            if written == 0 {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "WriteFile returned 0 bytes written",
                ));
            }
            offset += written as usize;
        }
    }

    unsafe {
        CloseHandle(handle);
    }

    if record_stats {
        crate::tarball::record_file_created(data_len as u64);
    }
    Ok(())
}

/// Writes a file reusing a caller-provided wide-string buffer on Windows.
#[inline]
pub(crate) fn write_file_fast_buf(
    path: &Path,
    data: &[u8],
    mode: u32,
    prealloc_threshold: usize,
    wide_buf: &mut Vec<u16>,
    record_stats: bool,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        crate::path::encode_verbatim_wide(path, wide_buf);
        write_file_fast_wide(
            wide_buf,
            path,
            data,
            mode,
            prealloc_threshold,
            record_stats,
        )
    }

    #[cfg(not(windows))]
    {
        let _ = wide_buf;
        write_file_fast_impl(path, data, mode, prealloc_threshold, record_stats)
    }
}

#[cfg(not(windows))]
fn write_file_fast_impl(
    path: &Path,
    data: &[u8],
    mode: u32,
    prealloc_threshold: usize,
    record_stats: bool,
) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            unlink_target_path(path);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?
        }
        Err(e) => return Err(e),
    };

    if data.len() >= prealloc_threshold {
        let _ = file.set_len(data.len() as u64);
    }

    if !data.is_empty() {
        file.write_all(data)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if mode & 0o111 != 0 {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }
    }

    if record_stats {
        crate::tarball::record_file_created(data.len() as u64);
    }
    Ok(())
}

/// Writes a single file using native OS primitives:
/// - Verbatim `\\?\` path formatting on Windows to bypass MAX_PATH limit
/// - Exclusive creation (`CREATE_NEW` / `O_EXCL`) fast path with unlink-and-recreate on collision
/// - Optional length preallocation (`set_len`) on non-Windows targets
/// - Single cheap write straight from memory without per-file `fsync`
pub fn write_file_fast(
    path: &Path,
    data: &[u8],
    mode: u32,
    prealloc_threshold: usize,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        crate::path::with_verbatim_wide(path, |path_wide| {
            write_file_fast_wide(path_wide, path, data, mode, prealloc_threshold, true)
        })
    }

    #[cfg(not(windows))]
    {
        write_file_fast_impl(path, data, mode, prealloc_threshold, true)
    }
}

#[cfg(windows)]
fn path_to_wide_buf(path: &Path, buf: &mut Vec<u16>) {
    crate::path::encode_verbatim_wide(path, buf);
}

#[cfg(windows)]
#[allow(dead_code)]
fn path_to_wide(path: &Path) -> Vec<u16> {
    let mut wide = Vec::with_capacity(path.as_os_str().len() + 8);
    path_to_wide_buf(path, &mut wide);
    wide
}

/// Copies a file using native OS primitives reusing caller wide-string buffers.
#[cfg(windows)]
pub fn copy_file_fast_buf(
    source: &Path,
    destination: &Path,
    src_buf: &mut Vec<u16>,
    dst_buf: &mut Vec<u16>,
) -> std::io::Result<()> {
    extern "system" {
        fn CopyFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            lpProgressRoutine: *mut std::ffi::c_void,
            lpData: *mut std::ffi::c_void,
            pbCancel: *mut i32,
            dwCopyFlags: u32,
        ) -> i32;
        fn GetLastError() -> u32;
    }

    const COPY_FILE_FAIL_IF_EXISTS: u32 = 0x00000001;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_FILE_EXISTS: u32 = 80;
    const ERROR_ALREADY_EXISTS: u32 = 183;

    path_to_wide_buf(source, src_buf);
    path_to_wide_buf(destination, dst_buf);

    let mut ret = unsafe {
        CopyFileExW(
            src_buf.as_ptr(),
            dst_buf.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            COPY_FILE_FAIL_IF_EXISTS,
        )
    };

    if ret == 0 {
        let mut err = unsafe { GetLastError() };
        if err == ERROR_PATH_NOT_FOUND {
            if let Some(parent) = destination.parent() {
                let parent_v = crate::path::to_verbatim_path(parent);
                let _ = std::fs::create_dir_all(&parent_v);
            }
            ret = unsafe {
                CopyFileExW(
                    src_buf.as_ptr(),
                    dst_buf.as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    COPY_FILE_FAIL_IF_EXISTS,
                )
            };
            if ret == 0 {
                err = unsafe { GetLastError() };
            }
        }
        if ret == 0
            && (err == ERROR_FILE_EXISTS
                || err == ERROR_ALREADY_EXISTS
                || err == ERROR_ACCESS_DENIED)
        {
            crate::tarball::unlink_target_path_wide(dst_buf, destination);
            ret = unsafe {
                CopyFileExW(
                    src_buf.as_ptr(),
                    dst_buf.as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    COPY_FILE_FAIL_IF_EXISTS,
                )
            };
        }
        if ret == 0 {
            let final_err = unsafe { GetLastError() };
            return Err(std::io::Error::from_raw_os_error(final_err as i32));
        }
    }
    Ok(())
}

/// Copies a file using native OS primitives (`CopyFileExW` on Windows).
pub fn copy_file_fast(source: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut src_buf = Vec::with_capacity(260);
        let mut dst_buf = Vec::with_capacity(260);
        copy_file_fast_buf(source, destination, &mut src_buf, &mut dst_buf)
    }

    #[cfg(not(windows))]
    {
        let mut src = std::fs::File::open(source)?;
        let mut dst = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                unlink_target_path(destination);
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(destination)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = destination.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(destination)?
            }
            Err(e) => return Err(e),
        };
        std::io::copy(&mut src, &mut dst).map(|_| ())
    }
}

/// A file to be materialized into place.
#[derive(Debug, Clone)]
pub struct MaterializeFile {
    pub path: PathBuf,
    pub data: Arc<Vec<u8>>,
    pub mode: u32,
    pub package_id: Option<String>,
}

/// Computes the priority of a file for Longest-Processing-Time first (LPT) scheduling.
///
/// Files >= 64 KiB or ending with `.node`, `.wasm`, `.exe`, `.dll` receive top priority
/// to ensure heavy files and native binaries start writing and scanning first.
#[allow(dead_code)]
fn file_lpt_priority(file: &MaterializeFile) -> u64 {
    let size = file.data.len() as u64;
    let path_str = file.path.to_string_lossy();
    let is_heavy = size >= 64 * 1024
        || path_str.ends_with(".node")
        || path_str.ends_with(".wasm")
        || path_str.ends_with(".exe")
        || path_str.ends_with(".dll");

    if is_heavy {
        (1u64 << 62) | size
    } else {
        size
    }
}

/// A borrowed reference to a file to be materialized into place.
#[derive(Debug, Clone)]
pub struct MaterializeFileRef<'a> {
    pub path: PathBuf,
    pub data: &'a [u8],
    pub mode: u32,
    pub package_id: Option<&'a str>,
    pub source_path: Option<&'a Path>,
    /// Expected SHA-256 for a source CAS file, when available.
    pub expected_sha256: Option<&'a str>,
    /// Set when the owning pack store verified the CAS blob before dispatch.
    pub source_verified: bool,
}

static CAS_REPAIR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn cas_file_is_valid(
    path: &Path,
    data_len: usize,
    expected_sha256: Option<&str>,
    source_verified: bool,
) -> bool {
    if source_verified {
        return true;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() != data_len as u64 {
        return false;
    }
    if let Some(expected) = expected_sha256 {
        if let Ok(bytes) = std::fs::read(path) {
            let actual = HEXLOWER.encode(&Sha256::digest(&bytes));
            return actual.eq_ignore_ascii_case(expected);
        }
        return false;
    }
    true
}

pub fn repair_cas_file(path: &Path, data: &[u8], mode: u32, prealloc_threshold: usize) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let count = CAS_REPAIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let tmp_path = path.with_extension(format!("tmp_{pid}_{count}"));
    if write_file_fast(&tmp_path, data, mode, prealloc_threshold).is_ok()
        && std::fs::rename(&tmp_path, path).is_err()
    {
        // Check if another concurrent thread already placed a valid file
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() == data.len() as u64 {
                let _ = std::fs::remove_file(&tmp_path);
                return;
            }
        }
        #[cfg(windows)]
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
        let _ = std::fs::remove_file(path);
        let _ = std::fs::rename(&tmp_path, path);
        let _ = std::fs::remove_file(&tmp_path);
    }
}

trait MatItem: Sync {
    fn item_path(&self) -> &Path;
    fn item_data(&self) -> &[u8];
    fn item_mode(&self) -> u32;
    fn item_package_id(&self) -> Option<&str>;
    fn item_source_path(&self) -> Option<&Path>;
    fn item_expected_sha256(&self) -> Option<&str>;
    fn item_source_verified(&self) -> bool;
}

impl MatItem for MaterializeFile {
    #[inline]
    fn item_path(&self) -> &Path {
        &self.path
    }
    #[inline]
    fn item_data(&self) -> &[u8] {
        &self.data
    }
    #[inline]
    fn item_mode(&self) -> u32 {
        self.mode
    }
    #[inline]
    fn item_package_id(&self) -> Option<&str> {
        self.package_id.as_deref()
    }
    #[inline]
    fn item_source_path(&self) -> Option<&Path> {
        None
    }
    #[inline]
    fn item_expected_sha256(&self) -> Option<&str> {
        None
    }
    #[inline]
    fn item_source_verified(&self) -> bool {
        false
    }
}

impl MatItem for MaterializeFileRef<'_> {
    #[inline]
    fn item_path(&self) -> &Path {
        &self.path
    }
    #[inline]
    fn item_data(&self) -> &[u8] {
        self.data
    }
    #[inline]
    fn item_mode(&self) -> u32 {
        self.mode
    }
    #[inline]
    fn item_package_id(&self) -> Option<&str> {
        self.package_id
    }
    #[inline]
    fn item_source_path(&self) -> Option<&Path> {
        self.source_path
    }
    #[inline]
    fn item_expected_sha256(&self) -> Option<&str> {
        self.expected_sha256
    }
    #[inline]
    fn item_source_verified(&self) -> bool {
        self.source_verified
    }
}

#[inline]
fn is_heavy_item<T: MatItem>(item: &T) -> bool {
    let data = item.item_data();
    if data.len() >= 64 * 1024 {
        return true;
    }
    let bytes = item.item_path().as_os_str().as_encoded_bytes();
    bytes.ends_with(b".node")
        || bytes.ends_with(b".wasm")
        || bytes.ends_with(b".exe")
        || bytes.ends_with(b".dll")
}

#[inline]
fn item_lpt_priority<T: MatItem>(item: &T) -> u64 {
    let size = item.item_data().len() as u64;
    if is_heavy_item(item) {
        (1u64 << 62) | size
    } else {
        size
    }
}

#[cfg(windows)]
#[inline]
fn file_size_if_exists_wide(wide: &[u16]) -> Option<u64> {
    #[repr(C)]
    #[allow(non_snake_case, clippy::upper_case_acronyms)]
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
            fInfoLevelId: u32,
            lpFileInformation: *mut WIN32_FILE_ATTRIBUTE_DATA,
        ) -> i32;
    }
    let mut info: WIN32_FILE_ATTRIBUTE_DATA = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileAttributesExW(wide.as_ptr(), 0, &mut info) };
    if ok != 0 && (info.dwFileAttributes & 0x10) == 0 {
        Some(((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64))
    } else {
        None
    }
}

#[inline]
fn materialize_one_item<T: MatItem>(
    item: &T,
    skip_existing_matching: bool,
    prealloc_thresh: usize,
    _src_buf: &mut Vec<u16>,
    dst_buf: &mut Vec<u16>,
) -> Result<(), FsError> {
    let path = item.item_path();
    let data = item.item_data();
    let mode = item.item_mode();

    if skip_existing_matching {
        #[cfg(windows)]
        {
            crate::path::encode_verbatim_wide(path, dst_buf);
            if file_size_if_exists_wide(dst_buf) == Some(data.len() as u64) {
                return Ok(());
            }
        }
        #[cfg(not(windows))]
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() == data.len() as u64 {
                return Ok(());
            }
        }
    }

    if let Some(src) = item.item_source_path() {
        let verified = item.item_source_verified();
        let mut cas_valid = cas_file_is_valid(src, data.len(), item.item_expected_sha256(), verified);
        if !cas_valid {
            repair_cas_file(src, data, mode, prealloc_thresh);
            cas_valid = cas_file_is_valid(src, data.len(), item.item_expected_sha256(), true);
        }
        if cas_valid {
            // When the file payload is already mapped in memory, writing directly
            // avoids opening and reading a separate CAS file on disk.
            if !data.is_empty() {
                return write_file_fast_buf(path, data, mode, prealloc_thresh, dst_buf, true)
                    .map_err(FsError::Io);
            }
            #[cfg(windows)]
            let copy_ok = copy_file_fast_buf(src, path, _src_buf, dst_buf).is_ok();
            #[cfg(not(windows))]
            let copy_ok = copy_file_fast(src, path).is_ok();
            if copy_ok {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if mode & 0o111 != 0 {
                        let _ = std::fs::set_permissions(
                            path,
                            std::fs::Permissions::from_mode(mode),
                        );
                    }
                }
                crate::tarball::record_file_created(data.len() as u64);
                return Ok(());
            }
        }
    }

    write_file_fast_buf(path, data, mode, prealloc_thresh, dst_buf, true).map_err(FsError::Io)
}

fn materialize_items_slice<T: MatItem>(
    mut items: Vec<T>,
    config: &ParallelWriterConfig,
) -> Result<(), FsError> {
    if items.is_empty() {
        return Ok(());
    }

    let prealloc_thresh = config.preallocate_threshold;
    let num_threads = if config.is_hdd {
        config.worker_threads.clamp(1, 4)
    } else {
        config.worker_threads.clamp(1, 32)
    }
    .min(items.len());

    if !config.is_hdd {
        let total_files = items.len();
        if total_files == 1 || num_threads <= 1 {
            let mut src_buf = Vec::with_capacity(260);
            let mut dst_buf = Vec::with_capacity(260);
            for item in &items {
                materialize_one_item(
                    item,
                    config.skip_existing_matching,
                    prealloc_thresh,
                    &mut src_buf,
                    &mut dst_buf,
                )?;
            }
            return Ok(());
        }

        // Partition heavy binaries / >= 64 KiB payloads to the front in O(N) so
        // large writes and AV scans start immediately without sorting small files.
        if total_files >= 32 {
            let mut heavy_end = 0usize;
            for i in 0..total_files {
                if is_heavy_item(&items[i]) {
                    items.swap(i, heavy_end);
                    heavy_end += 1;
                }
            }
            if heavy_end > 1 {
                items[..heavy_end].sort_unstable_by_key(|a| std::cmp::Reverse(a.item_data().len()));
            }
        }

        let chunk_size = (total_files / (num_threads * 4)).clamp(1, 16);
        let next_file = AtomicUsize::new(0);
        let has_err = AtomicBool::new(false);
        let first_err: Mutex<Option<FsError>> = Mutex::new(None);
        let items_slice = &items[..];

        crate::pool::run_parallel(num_threads, &|| {
            let mut src_buf = Vec::with_capacity(260);
            let mut dst_buf = Vec::with_capacity(260);

            loop {
                if has_err.load(Ordering::Relaxed) {
                    break;
                }
                let start = next_file.fetch_add(chunk_size, Ordering::Relaxed);
                if start >= total_files {
                    break;
                }
                let end = (start + chunk_size).min(total_files);
                for item in &items_slice[start..end] {
                    if let Err(e) = materialize_one_item(
                        item,
                        config.skip_existing_matching,
                        prealloc_thresh,
                        &mut src_buf,
                        &mut dst_buf,
                    ) {
                        has_err.store(true, Ordering::Relaxed);
                        let mut guard = first_err.lock().unwrap_or_else(|p| p.into_inner());
                        if guard.is_none() {
                            *guard = Some(e);
                        }
                        return;
                    }
                }
            }
        });

        if let Some(e) = first_err.into_inner().unwrap_or_else(|p| p.into_inner()) {
            return Err(e);
        }
        Ok(())
    } else {
        // Group files by package to maintain directory locality on HDD
        let mut package_groups: BTreeMap<String, Vec<T>> = BTreeMap::new();
        let mut ungrouped: Vec<T> = Vec::new();

        for item in items {
            if let Some(pkg) = item.item_package_id() {
                package_groups
                    .entry(pkg.to_string())
                    .or_default()
                    .push(item);
            } else {
                ungrouped.push(item);
            }
        }

        for group in package_groups.values_mut() {
            group.sort_by_key(|a| std::cmp::Reverse(item_lpt_priority(a)));
        }

        let mut batches: Vec<Vec<T>> = package_groups.into_values().collect();
        batches.sort_by_key(|b| {
            std::cmp::Reverse(b.iter().map(|f| f.item_data().len() as u64).sum::<u64>())
        });

        if !ungrouped.is_empty() {
            ungrouped.sort_by_key(|a| std::cmp::Reverse(item_lpt_priority(a)));
            batches.push(ungrouped);
        }

        let total_batches = batches.len();
        let next_pkg = AtomicUsize::new(0);
        let has_err = AtomicBool::new(false);
        let first_err: Mutex<Option<FsError>> = Mutex::new(None);
        let batches_slice = &batches[..];

        crate::pool::run_parallel(num_threads, &|| {
            let mut src_buf = Vec::with_capacity(260);
            let mut dst_buf = Vec::with_capacity(260);
            loop {
                if has_err.load(Ordering::Relaxed) {
                    break;
                }
                let idx = next_pkg.fetch_add(1, Ordering::Relaxed);
                if idx >= total_batches {
                    break;
                }
                for item in &batches_slice[idx] {
                    if let Err(e) = materialize_one_item(
                        item,
                        config.skip_existing_matching,
                        prealloc_thresh,
                        &mut src_buf,
                        &mut dst_buf,
                    ) {
                        has_err.store(true, Ordering::Relaxed);
                        let mut guard = first_err.lock().unwrap_or_else(|p| p.into_inner());
                        if guard.is_none() {
                            *guard = Some(e);
                        }
                        return;
                    }
                }
            }
        });

        if let Some(e) = first_err.into_inner().unwrap_or_else(|p| p.into_inner()) {
            return Err(e);
        }
        Ok(())
    }
}

/// Writes a batch of borrowed file references in parallel according to the optimal disk policy:
/// - SSD: 24-48 threads, global LPT scheduling across all packages with lock-free atomic chunking.
/// - HDD: 4 threads, writes grouped by package to minimize mechanical seek head movement.
pub fn materialize_files_parallel_refs<'a>(
    files: Vec<MaterializeFileRef<'a>>,
    config: &ParallelWriterConfig,
) -> Result<(), FsError> {
    materialize_items_slice(files, config)
}

/// Writes a batch of files in parallel according to the optimal disk policy:
/// - SSD: 24-32 threads, global LPT scheduling across all packages.
/// - HDD: 4 threads, writes grouped by package to minimize mechanical seek head movement.
pub fn materialize_files_parallel(
    files: Vec<MaterializeFile>,
    config: &ParallelWriterConfig,
) -> Result<(), FsError> {
    materialize_items_slice(files, config)
}

/// A package tarball decoded in memory, ready for parallel materialization.
#[derive(Debug)]
pub struct DecodedTarball {
    pub directories: Vec<PathBuf>,
    pub files: Vec<MaterializeFile>,
    pub symlinks: Vec<(PathBuf, PathBuf)>,
    pub hardlinks: Vec<(PathBuf, PathBuf)>,
    pub entry_count: usize,
    pub total_uncompressed_bytes: u64,
    pub inflate_duration: std::time::Duration,
}

/// Decodes a tarball into structured files and directories while validating all security constraints:
/// path traversal, SUID/SGID bits, invalid UTF-8, reserved Windows device names, tar bombs,
/// and case collisions.
pub fn decode_tar_entries<R: Read>(
    reader: R,
    destination: &Path,
    limits: Option<TarLimits>,
    package_id: Option<String>,
) -> Result<DecodedTarball, FsError> {
    let limits = limits.unwrap_or_default();
    let verbatim_dest = crate::path::to_verbatim_path(destination);
    let clean_dest = clean(&verbatim_dest);

    let counting_reader = CountingReader::new(reader);
    let compressed_counter = counting_reader.counter();
    let mut buffered = std::io::BufReader::with_capacity(64 * 1024, counting_reader);
    let gzipped = std::io::BufRead::fill_buf(&mut buffered)
        .map_err(FsError::Io)?
        .starts_with(&[0x1f, 0x8b]);
    let payload: Box<dyn Read + '_> = if gzipped {
        Box::new(GzDecoder::new(buffered))
    } else {
        Box::new(buffered)
    };
    let mut archive = Archive::new(payload);

    let mut inflate_nanos = 0u64;
    let mut entry_count = 0usize;
    let mut total_uncompressed = 0u64;
    let mut directory_count = 0usize;
    let mut symlink_count = 0usize;

    let mut seen_paths: HashMap<String, String> = HashMap::new();
    let mut seen_dirs_lower: HashSet<String> = HashSet::new();
    let mut seen_files_lower: HashSet<String> = HashSet::new();
    let mut symlink_paths: HashSet<PathBuf> = HashSet::new();
    let mut extracted_regular_files: HashSet<PathBuf> = HashSet::new();
    let mut hardlink_targets: HashMap<PathBuf, PathBuf> = HashMap::new();
    let mut safe_ancestors = HashSet::new();

    let mut directories = Vec::new();
    let mut files: Vec<Option<MaterializeFile>> = Vec::new();
    let mut file_indices: HashMap<String, usize> = HashMap::new();
    let mut symlinks = Vec::new();
    let mut hardlinks = Vec::new();
    let mut saw_npmignores: HashSet<PathBuf> = HashSet::new();

    let entries = archive.entries().map_err(FsError::Io)?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(FsError::Io)?;
        let entry_type = entry.header().entry_type();

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

        let mode = entry.header().mode().unwrap_or(0);
        if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
            return Err(FsError::ForbiddenModeBits {
                mode,
                path: entry.path().unwrap_or_default().to_path_buf(),
            });
        }

        let fast_ascii: Option<(String, usize)> = {
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
                Ok(None) => continue,
                Ok(Some((rel, depth))) => {
                    if entry_type.is_file() {
                        if rel == ".npmignore" || rel.ends_with("/.npmignore") {
                            saw_npmignores.insert(PathBuf::from(rel));
                            Some((rel.to_string(), depth))
                        } else if rel == ".gitignore" || rel.ends_with("/.gitignore") {
                            let rewritten = if rel.len() == ".gitignore".len() {
                                ".npmignore".to_string()
                            } else {
                                format!("{}/.npmignore", &rel[..rel.len() - "/.gitignore".len()])
                            };
                            if saw_npmignores.contains(Path::new(&rewritten)) {
                                continue;
                            }
                            Some((rewritten, depth))
                        } else {
                            Some((rel.to_string(), depth))
                        }
                    } else {
                        Some((rel.to_string(), depth))
                    }
                }
                Err(()) => None,
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
            let err_path = match fast_ascii {
                Some((s, _)) => PathBuf::from(s),
                None => entry.path().unwrap_or_default().to_path_buf(),
            };
            return Err(FsError::ForbiddenSparseFile { path: err_path });
        }

        let (relative_path, target_path, norm_exact, path_depth, _is_ascii_clean) =
            if let Some((rel_str, depth)) = fast_ascii {
                let target_path = join_clean_rel(&clean_dest, &rel_str);
                let relative_path = PathBuf::from(&rel_str);
                (relative_path, target_path, rel_str, depth, true)
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
                            .filter(|c| !matches!(c, std::path::Component::CurDir))
                            .collect();
                        if cleaned.as_os_str().is_empty() {
                            continue;
                        }
                        cleaned
                    }
                    None => continue,
                };

                // Replicate pacote / npm pack behavior: treat .gitignore files like .npmignore
                // unless a .npmignore file is already present.
                if entry_type.is_file() {
                    if relative_path.file_name() == Some(std::ffi::OsStr::new(".npmignore")) {
                        saw_npmignores.insert(relative_path.clone());
                    } else if relative_path.file_name() == Some(std::ffi::OsStr::new(".gitignore"))
                    {
                        let ni = relative_path.with_file_name(".npmignore");
                        if saw_npmignores.contains(&ni) {
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
                    if let std::path::Component::Normal(s) = c {
                        path_depth += 1;
                        target_path.push(s);
                        if !norm_exact.is_empty() {
                            norm_exact.push('/');
                        }
                        norm_exact.push_str(&s.to_string_lossy());
                    }
                }
                (relative_path, target_path, norm_exact, path_depth, false)
            };

        if path_depth > limits.max_path_depth {
            return Err(FsError::TarBombLimitExceeded {
                limit_type: "path depth".to_string(),
                detail: format!(
                    "Path depth {} exceeded maximum allowed path depth of {}: '{}'",
                    path_depth,
                    limits.max_path_depth,
                    relative_path.display()
                ),
            });
        }

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

        if entry_type.is_block_special()
            || entry_type.is_character_special()
            || entry_type.is_fifo()
        {
            return Err(FsError::ForbiddenSpecialEntry { path: relative_path });
        }

        if !target_path.starts_with(&clean_dest) {
            return Err(FsError::PathTraversal {
                path: relative_path.clone(),
            });
        }
        if target_path == clean_dest && !entry_type.is_dir() {
            return Err(FsError::PathTraversal {
                path: relative_path.clone(),
            });
        }

        crate::tarball::ensure_no_symlink_ancestors_with_cache(
            &target_path,
            &verbatim_dest,
            &symlink_paths,
            &relative_path,
            Some(&mut safe_ancestors),
        )?;

        if norm_exact.is_empty() {
            continue;
        }
        let norm_lower = if norm_exact.bytes().any(|b| b.is_ascii_uppercase()) {
            norm_exact.to_ascii_lowercase()
        } else {
            norm_exact.clone()
        };

        if let Some(existing_exact) = seen_paths.get(&norm_lower) {
            if existing_exact != &norm_exact {
                return Err(FsError::CaseCollision {
                    path: relative_path.clone(),
                });
            }
        }

        if entry_type.is_dir() {
            if seen_files_lower.contains(&norm_lower) {
                return Err(FsError::CaseCollision {
                    path: relative_path.clone(),
                });
            }
            if seen_dirs_lower.insert(norm_lower.clone()) {
                let mut end = norm_lower.len();
                while let Some(pos) = norm_lower[..end].rfind('/') {
                    let prefix = &norm_lower[..pos];
                    if seen_files_lower.contains(prefix) {
                        return Err(FsError::CaseCollision {
                            path: relative_path.clone(),
                        });
                    }
                    if !seen_dirs_lower.insert(prefix.to_string()) {
                        break;
                    }
                    end = pos;
                }
            }
        } else {
            if seen_dirs_lower.contains(&norm_lower) {
                return Err(FsError::CaseCollision {
                    path: relative_path.clone(),
                });
            }
            seen_files_lower.insert(norm_lower.clone());
            let mut end = norm_lower.len();
            while let Some(pos) = norm_lower[..end].rfind('/') {
                let prefix = &norm_lower[..pos];
                if seen_files_lower.contains(prefix) {
                    return Err(FsError::CaseCollision {
                        path: relative_path.clone(),
                    });
                }
                if !seen_dirs_lower.insert(prefix.to_string()) {
                    break;
                }
                end = pos;
            }
        }

        let was_seen = seen_paths.insert(norm_lower, norm_exact.clone()).is_some();

        if entry_type.is_symlink() || entry_type.is_hard_link() {
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
                // Symlink targets are relative to the link's parent. Only tar
                // hardlink targets are relative to the archive root.
                let normalized_target = if entry_type.is_hard_link() {
                    strip_package_prefix(&link_target).unwrap_or_else(|| link_target.to_path_buf())
                } else {
                    link_target.to_path_buf()
                };

                if entry_type.is_symlink() {
                    let cleaned_rel =
                        validate_link_target(&relative_path, &normalized_target, destination)?;
                    extracted_regular_files.remove(&relative_path);
                    extracted_regular_files.remove(&normalize_rel_path(&relative_path));
                    symlink_paths.insert(relative_path.clone());
                    symlink_paths.insert(normalize_rel_path(&relative_path));
                    if let Some(prev_idx) = file_indices.remove(&norm_exact) {
                        files[prev_idx] = None;
                    }
                    if !symlinks.is_empty() {
                        symlinks.retain(|(p, _)| p != &target_path);
                    }
                    if !hardlinks.is_empty() {
                        hardlinks.retain(|(p, _)| p != &target_path);
                    }
                    symlinks.push((target_path, cleaned_rel));
                } else if entry_type.is_hard_link() {
                    if normalized_target.is_absolute() || normalized_target.has_root() {
                        return Err(FsError::AbsolutePath {
                            path: normalized_target,
                        });
                    }
                    let cleaned_target = clean(&normalized_target);
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

                    let norm_cleaned = normalize_rel_path(&cleaned_target);
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

                    if !extracted_regular_files.contains(&cleaned_target)
                        && !extracted_regular_files.contains(&norm_cleaned)
                    {
                        return Err(FsError::DanglingHardlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }

                    hardlink_targets.insert(relative_path.clone(), cleaned_target);
                    extracted_regular_files.insert(relative_path.clone());
                    extracted_regular_files.insert(normalize_rel_path(&relative_path));
                    if let Some(prev_idx) = file_indices.remove(&norm_exact) {
                        files[prev_idx] = None;
                    }
                    if !symlinks.is_empty() {
                        symlinks.retain(|(p, _)| p != &target_path);
                    }
                    if !hardlinks.is_empty() {
                        hardlinks.retain(|(p, _)| p != &target_path);
                    }
                    hardlinks.push((target_path, source_full));
                }
            }
            continue;
        }

        if entry_type.is_dir() {
            directories.push(target_path);
        } else if entry_type.is_file() {
            let header_size = entry.header().size().ok();
            if let Some(entry_size) = header_size {
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
            }

            let file_mode = entry
                .header()
                .mode()
                .unwrap_or(crate::tarball::NPM_DEFAULT_FILE_MODE);
            let t_read = std::time::Instant::now();
            let initial_cap = header_size.unwrap_or(0).min(4 * 1024 * 1024) as usize;
            let mut file_buf = Vec::with_capacity(initial_cap);
            entry.read_to_end(&mut file_buf).map_err(FsError::Io)?;
            inflate_nanos += t_read.elapsed().as_nanos() as u64;

            total_uncompressed += file_buf.len() as u64;
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

            if was_seen {
                if !symlink_paths.is_empty() {
                    symlink_paths.remove(&relative_path);
                    symlink_paths.remove(&normalize_rel_path(&relative_path));
                }
                if !symlinks.is_empty() {
                    symlinks.retain(|(p, _)| p != &target_path);
                }
                if !hardlinks.is_empty() {
                    hardlinks.retain(|(p, _)| p != &target_path);
                }
            }
            if !was_seen {
                if _is_ascii_clean || !cfg!(windows) {
                    extracted_regular_files.insert(relative_path);
                } else {
                    extracted_regular_files.insert(relative_path.clone());
                    extracted_regular_files.insert(normalize_rel_path(&relative_path));
                }
            } else {
                extracted_regular_files.insert(relative_path.clone());
                if cfg!(windows) && !_is_ascii_clean {
                    extracted_regular_files.insert(normalize_rel_path(&relative_path));
                }
            }

            let mat_file = MaterializeFile {
                path: target_path,
                data: Arc::new(file_buf),
                mode: file_mode,
                package_id: package_id.clone(),
            };

            // Deduplicate: later entry in tarball wins (keyed on case-preserved normalized path)
            match file_indices.entry(norm_exact) {
                std::collections::hash_map::Entry::Occupied(occ) => {
                    files[*occ.get()] = Some(mat_file);
                }
                std::collections::hash_map::Entry::Vacant(vac) => {
                    vac.insert(files.len());
                    files.push(Some(mat_file));
                }
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
            return Err(FsError::TarBombLimitExceeded {
                limit_type: "compression ratio".to_string(),
                detail: format!(
                    "Compression ratio {:.1}:1 exceeded limit of {:.1}:1",
                    ratio, limits.max_compression_ratio
                ),
            });
        }
    }

    let files: Vec<MaterializeFile> = files.into_iter().flatten().collect();

    Ok(DecodedTarball {
        directories,
        files,
        symlinks,
        hardlinks,
        entry_count,
        total_uncompressed_bytes: total_uncompressed,
        inflate_duration: std::time::Duration::from_nanos(inflate_nanos),
    })
}

/// Extracts a package tarball directly into place using the native Windows parallel writer:
/// 1. Decodes tarball in memory with full security and ratio validations
/// 2. Pre-creates all directories in breadth-first order (CreateDirectoryW), eliminating redundant exists() calls
/// 3. Materializes files concurrently via dedicated I/O thread pool sized for SSD (24-32 threads) or HDD (4 threads)
/// 4. Dispatches largest files first (LPT scheduling)
/// 5. Preallocates files >= 64 KiB with FileAllocationInfo
/// 6. Writes straight to final location without temporary staging dirs or renames
pub fn extract_tarball_direct<R: Read>(
    reader: R,
    destination: &Path,
    limits: Option<TarLimits>,
    config: Option<&ParallelWriterConfig>,
) -> Result<ExtractionSummary, FsError> {
    let pkg_id = destination
        .file_name()
        .map(|s| s.to_string_lossy().to_string());
    let decoded = decode_tar_entries(reader, destination, limits, pkg_id)?;
    let inflate_dur = decoded.inflate_duration;

    let default_cfg;
    let cfg = match config {
        Some(c) => c,
        None => {
            default_cfg = determine_writer_config(destination, None);
            &default_cfg
        }
    };

    let t_mat = std::time::Instant::now();

    // 1. Directory pre-creation with pre-deduplication to avoid redundant allocations and syscalls
    let mut unique_dirs: std::collections::HashSet<&Path> = std::collections::HashSet::new();
    unique_dirs.insert(destination);
    for d in &decoded.directories {
        unique_dirs.insert(d.as_path());
    }
    for f in &decoded.files {
        if let Some(p) = f.path.parent() {
            unique_dirs.insert(p);
        }
    }
    let dir_refs: Vec<&Path> = unique_dirs.into_iter().collect();
    precreate_directories(dir_refs).map_err(FsError::Io)?;

    // 2. Parallel file materialization
    materialize_files_parallel(decoded.files, cfg)?;

    // 3. Symlinks
    for (link_path, target_rel) in decoded.symlinks {
        unlink_target_path(&link_path);
        #[cfg(windows)]
        {
            let target_full = destination.join(&target_rel);
            if target_full.is_dir() {
                let _ = crate::junction::create_junction(&link_path, &target_full);
            } else if target_full.is_file() {
                let _ = std::fs::copy(&target_full, &link_path);
            }
        }
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&target_rel, &link_path);
        }
    }

    // 4. Hardlinks
    for (link_path, source_full) in decoded.hardlinks {
        unlink_target_path(&link_path);
        if std::fs::hard_link(&source_full, &link_path).is_err() && source_full.is_file() {
            let _ = std::fs::copy(&source_full, &link_path);
        }
    }

    let mat_dur = t_mat.elapsed();

    Ok(ExtractionSummary {
        entries_extracted: decoded.entry_count,
        total_uncompressed_bytes: decoded.total_uncompressed_bytes,
        inflate_duration: inflate_dur,
        materialize_duration: mat_dur,
    })
}

/// A single item for direct batch materialization.
pub struct BatchDirectItem<R> {
    pub reader: R,
    pub destination: PathBuf,
    pub package_id: String,
    pub limits: Option<TarLimits>,
}

/// Extracts multiple package tarballs concurrently into place using the native parallel materializer.
/// Slices across packages to precreate all directories in a single pass, then runs file writes
/// concurrently across the dedicated I/O pool.
pub fn extract_packages_direct_parallel<R: Read + Send>(
    items: Vec<BatchDirectItem<R>>,
    root_destination: &Path,
    config: Option<&ParallelWriterConfig>,
) -> Vec<Result<ExtractionSummary, FsError>> {
    let num_items = items.len();
    if num_items == 0 {
        return Vec::new();
    }

    let default_cfg;
    let cfg = match config {
        Some(c) => c,
        None => {
            default_cfg = determine_writer_config(root_destination, None);
            &default_cfg
        }
    };

    let mut decoded_results: Vec<Result<DecodedTarball, FsError>> = if num_items == 1 {
        items
            .into_iter()
            .map(|item| {
                decode_tar_entries(
                    item.reader,
                    &item.destination,
                    item.limits,
                    Some(item.package_id),
                )
            })
            .collect()
    } else {
        struct DisjointSlot<T>(std::cell::UnsafeCell<Option<T>>);
        // SAFETY: `T: Send`, and workers only access distinct indices claimed once via `next_idx.fetch_add(1)`.
        unsafe impl<T: Send> Sync for DisjointSlot<T> {}

        let decode_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(2, 16)
            .min(num_items);
        let inputs: Vec<DisjointSlot<BatchDirectItem<R>>> = items
            .into_iter()
            .map(|item| DisjointSlot(std::cell::UnsafeCell::new(Some(item))))
            .collect();
        let results: Vec<DisjointSlot<Result<DecodedTarball, FsError>>> = (0..num_items)
            .map(|_| DisjointSlot(std::cell::UnsafeCell::new(None)))
            .collect();
        let next_idx = AtomicUsize::new(0);

        crate::pool::run_parallel(decode_threads, &|| {
            loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= num_items {
                    break;
                }
                // SAFETY: `fetch_add` assigns each `idx < num_items` to at most one worker.
                let item = unsafe { (*inputs[idx].0.get()).take() };
                let Some(item) = item else { continue };
                let decoded = decode_tar_entries(
                    item.reader,
                    &item.destination,
                    item.limits,
                    Some(item.package_id),
                );
                // SAFETY: Each `idx < num_items` is claimed by at most one worker via `next_idx.fetch_add(1)`,
                // and `run_parallel` synchronizes all helpers before `results` is consumed.
                unsafe {
                    *results[idx].0.get() = Some(decoded);
                }
            }
        });

        results
            .into_iter()
            .map(|slot| {
                slot.0.into_inner().unwrap_or_else(|| {
                    Err(FsError::Io(std::io::Error::other(
                        "Tarball decode worker terminated unexpectedly",
                    )))
                })
            })
            .collect()
    };

    let mut total_files_count = 0usize;
    let mut total_dirs_count = 1usize;
    for decoded in decoded_results.iter().flatten() {
        total_files_count += decoded.files.len();
        total_dirs_count += decoded.directories.len() + decoded.files.len() / 2;
    }

    // Collect all unique directories and move decoded files without cloning payloads/paths
    let mut all_files = Vec::with_capacity(total_files_count);
    for decoded in decoded_results.iter_mut().flatten() {
        all_files.append(&mut decoded.files);
    }

    let mut unique_dirs: std::collections::HashSet<&Path> =
        std::collections::HashSet::with_capacity(total_dirs_count);
    unique_dirs.insert(root_destination);
    for decoded in decoded_results.iter().flatten() {
        for d in &decoded.directories {
            unique_dirs.insert(d.as_path());
        }
    }
    for f in &all_files {
        if let Some(p) = f.path.parent() {
            unique_dirs.insert(p);
        }
    }

    // Pre-create all directories in one pass
    let dir_refs: Vec<&Path> = unique_dirs.into_iter().collect();
    if let Err(e) = precreate_directories(dir_refs) {
        return (0..num_items)
            .map(|_| Err(FsError::Io(std::io::Error::new(e.kind(), e.to_string()))))
            .collect();
    }

    // Materialize all files concurrently across the dedicated I/O pool
    let t_mat = std::time::Instant::now();
    if let Err(e) = materialize_files_parallel(all_files, cfg) {
        let err_str = e.to_string();
        return (0..num_items)
            .map(|_| Err(FsError::Io(std::io::Error::other(err_str.clone()))))
            .collect();
    }
    let mat_dur = t_mat.elapsed();

    // Apply symlinks and hardlinks for each package
    decoded_results
        .into_iter()
        .map(|res| {
            res.map(|decoded| {
                for (link_path, target_rel) in &decoded.symlinks {
                    unlink_target_path(link_path);
                    #[cfg(windows)]
                    {
                        let target_full = link_path
                            .parent()
                            .unwrap_or(Path::new("."))
                            .join(target_rel);
                        if target_full.is_dir() {
                            let _ = crate::junction::create_junction(link_path, &target_full);
                        } else if target_full.is_file() {
                            let _ = std::fs::copy(&target_full, link_path);
                        }
                    }
                    #[cfg(unix)]
                    {
                        let _ = std::os::unix::fs::symlink(target_rel, link_path);
                    }
                }
                for (link_path, source_full) in &decoded.hardlinks {
                    unlink_target_path(link_path);
                    if std::fs::hard_link(source_full, link_path).is_err() && source_full.is_file()
                    {
                        let _ = std::fs::copy(source_full, link_path);
                    }
                }
                ExtractionSummary {
                    entries_extracted: decoded.entry_count,
                    total_uncompressed_bytes: decoded.total_uncompressed_bytes,
                    inflate_duration: decoded.inflate_duration,
                    materialize_duration: mat_dur,
                }
            })
        })
        .collect()
}

#[cfg(all(test, windows))]
mod write_wide_raw_tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    #[test]
    fn write_file_fast_wide_raw_rejects_missing_nul_terminator() {
        let dir = tempfile::tempdir().unwrap();
        let hint = dir.path().join("x.txt");

        let empty: &[u16] = &[];
        let err = write_file_fast_wide_raw(empty, &hint, b"hi", 0o644, 0, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        let unterminated: Vec<u16> = hint.as_os_str().encode_wide().collect();
        let err =
            write_file_fast_wide_raw(&unterminated, &hint, b"hi", 0o644, 0, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
