use crate::error::CacheError;
use crate::index::{
    encode_hex_lower, legacy_index_path_from_npm, npm_index_path_from_hash, sha256_hex_stack,
    IndexEntry,
};
use crate::lock::CacheLock;
use data_encoding::{BASE64, HEXLOWER};
use rnpm_core::{Algorithm, Integrity, IntegrityError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{sleep, yield_now};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(1);
static PROCESS_START_NANOS: OnceLock<u128> = OnceLock::new();
const LOCK_SHARD_COUNT: usize = 64;

#[inline]
fn process_start_nanos() -> u128 {
    *PROCESS_START_NANOS.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    })
}

#[inline]
fn prefix_index_and_mask(hex: &str) -> Option<(usize, u64)> {
    let b = hex.as_bytes();
    if b.len() < 4 {
        return None;
    }
    let idx16 = ((hex_nibble(b[0])? as usize) << 12)
        | ((hex_nibble(b[1])? as usize) << 8)
        | ((hex_nibble(b[2])? as usize) << 4)
        | (hex_nibble(b[3])? as usize);
    Some((idx16 >> 6, 1u64 << (idx16 & 63)))
}

#[inline]
fn prefix_bitset_has(bits: &[AtomicU64; 1024], hex: &str) -> bool {
    let Some((word, mask)) = prefix_index_and_mask(hex) else {
        return false;
    };
    (bits[word].load(Ordering::Relaxed) & mask) != 0
}

#[inline]
fn prefix_bitset_set(bits: &[AtomicU64; 1024], hex: &str) {
    if let Some((word, mask)) = prefix_index_and_mask(hex) {
        bits[word].fetch_or(mask, Ordering::Relaxed);
    }
}

fn clear_prefix_bitset(bits: &[AtomicU64; 1024]) {
    for slot in bits {
        slot.store(0, Ordering::Relaxed);
    }
}

#[inline]
fn shard_index_for_str(s: &str) -> usize {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in s.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash as usize) & (LOCK_SHARD_COUNT - 1)
}

#[inline]
fn is_path_not_found(err: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        // ERROR_PATH_NOT_FOUND (3): parent directory does not exist, so sibling files cannot exist either.
        err.raw_os_error() == Some(3)
    }
    #[cfg(not(windows))]
    {
        let _ = err;
        false
    }
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[inline]
fn decode_sha512_hex_stack(hex: &str) -> Option<[u8; 64]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
fn constant_time_eq_64(a: &[u8; 64], b: &[u8]) -> bool {
    if b.len() != 64 {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..64 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[inline]
fn sha512_matches_integrity(digest: &[u8; 64], expected: &Integrity) -> Option<bool> {
    if expected.strongest_algorithm() != Some(Algorithm::Sha512) {
        return None;
    }
    for entry in &expected.entries {
        if entry.algorithm == Algorithm::Sha512 && constant_time_eq_64(digest, &entry.digest) {
            return Some(true);
        }
    }
    Some(false)
}

#[inline]
fn retry_backoff(attempt: u32, delay: &mut Duration, max_delay: Duration) {
    if attempt <= 2 {
        yield_now();
    } else {
        let jitter = (attempt as u64 * 73) % 300;
        sleep(*delay + Duration::from_micros(jitter));
        *delay = delay.saturating_mul(2).min(max_delay);
    }
}

/// Clear readonly attribute on Windows or Unix.
fn make_writable(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path).or_else(|_| fs::metadata(path)) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
}

/// Recursively clear readonly attribute on all files and subdirectories without following symlinks or junctions.
fn clear_readonly_recursive(path: &Path) {
    make_writable(path);
    if let Ok(meta) = fs::symlink_metadata(path) {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if (meta.file_attributes() & 0x400) != 0 {
                return; // Reparse point / junction / symlink: do not traverse
            }
        }
        #[cfg(not(windows))]
        {
            if meta.file_type().is_symlink() {
                return;
            }
        }
        if meta.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    clear_readonly_recursive(&entry.path());
                }
            }
        }
    }
}

/// Helper to reliably remove a file, clearing Windows readonly attributes and retrying on transient locks.
fn remove_file_with_retries(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {}
    }

    make_writable(path);

    let mut attempts = 0u32;
    let mut delay = Duration::from_micros(500);
    loop {
        attempts += 1;
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                if attempts >= 10 {
                    return Err(e);
                }
                make_writable(path);
                retry_backoff(attempts, &mut delay, Duration::from_millis(100));
            }
        }
    }
}

/// Helper to reliably remove a directory tree, clearing Windows readonly attributes and retrying on transient locks.
/// Uses `rnpm_fs::remove_dir_all_safe` to ensure junctions/symlinks are never followed into external targets.
fn remove_dir_all_with_retries(dir: &Path) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    let mut attempts = 0;
    let mut delay = Duration::from_millis(5);
    loop {
        attempts += 1;
        match rnpm_fs::remove_dir_all_safe(dir) {
            Ok(()) => return Ok(()),
            Err(_) if !dir.exists() => return Ok(()),
            Err(e) => {
                if attempts >= 10 {
                    return Err(std::io::Error::other(e.to_string()));
                }
                clear_readonly_recursive(dir);
                let jitter = (attempts as u64 * 3) % 7;
                sleep(delay + Duration::from_millis(jitter));
                delay = delay.saturating_mul(2).min(Duration::from_millis(250));
            }
        }
    }
}

/// Recursively collect all files under a directory without extra stat syscalls.
pub(crate) fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                collect_files_recursive(&entry.path(), out);
            } else if ft.is_file() {
                out.push(entry.path());
            }
        }
    }
}

/// Detailed report returned by `Cache::verify`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Number of valid content-addressable blobs verified against their SHA-512 digests.
    pub verified_blobs: usize,
    /// Number of corrupted or unreadable blobs purged.
    pub corrupted_blobs: usize,
    /// Total byte size of verified content blobs.
    pub total_blob_bytes: u64,
    /// Number of valid index entries verified against existing blobs.
    pub verified_indices: usize,
    /// Number of corrupted or unreadable index entries purged.
    pub corrupted_indices: usize,
    /// Number of orphaned index entries purged (pointed to missing or corrupted blobs).
    pub orphaned_indices: usize,
    /// Number of stale temporary files cleaned up from `tmp`.
    pub stale_temp_files_cleaned: usize,
}

impl VerifyReport {
    /// Check whether the cache was completely healthy and required no purging.
    pub fn is_clean(&self) -> bool {
        self.corrupted_blobs == 0
            && self.corrupted_indices == 0
            && self.orphaned_indices == 0
            && self.stale_temp_files_cleaned == 0
    }

    /// Total number of purged items (corrupted blobs, corrupted indices, orphaned indices, and stale temp files).
    pub fn total_purged(&self) -> usize {
        self.corrupted_blobs
            + self.corrupted_indices
            + self.orphaned_indices
            + self.stale_temp_files_cleaned
    }

    /// Total number of verified valid items (blobs and index entries).
    pub fn total_verified(&self) -> usize {
        self.verified_blobs + self.verified_indices
    }
}

impl std::fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache Verify: {} blobs verified ({} bytes), {} corrupted blobs purged, {} index entries verified, {} corrupted indices purged, {} orphaned indices purged, {} stale temp files cleaned",
            self.verified_blobs,
            self.total_blob_bytes,
            self.corrupted_blobs,
            self.verified_indices,
            self.corrupted_indices,
            self.orphaned_indices,
            self.stale_temp_files_cleaned,
        )
    }
}

/// Helper to reliably rename a temporary file to its target path with retries on Windows transient locks.
fn rename_with_retries(from: &Path, to: &Path) -> std::io::Result<()> {
    match fs::rename(from, to) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = to.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if fs::rename(from, to).is_ok() {
                return Ok(());
            }
        }
        Err(_) => {}
    }

    let mut attempts = 0u32;
    let mut delay = Duration::from_micros(500);
    loop {
        attempts += 1;
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = to.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if attempts >= 10 {
                    return Err(e);
                }
                retry_backoff(attempts, &mut delay, Duration::from_millis(100));
            }
            Err(e) => {
                if attempts >= 10 {
                    return Err(e);
                }
                // If destination exists as a file, clear readonly and remove before retrying rename
                if to.is_file() {
                    let _ = remove_file_with_retries(to);
                }
                retry_backoff(attempts, &mut delay, Duration::from_millis(100));
            }
        }
    }
}

#[cfg(windows)]
#[inline]
pub(crate) fn encode_verbatim_wide_into(path: &Path, buf: &mut Vec<u16>) {
    use std::os::windows::ffi::OsStrExt;
    buf.clear();
    let os = path.as_os_str();
    let bytes = os.as_encoded_bytes();
    if bytes.starts_with(br"\\?\")
        && !bytes.contains(&b'/')
        && !bytes[4..].windows(2).any(|w| w == b"\\\\")
        && !bytes.windows(3).any(|w| w == b"\\.\\")
        && !bytes.windows(4).any(|w| w == b"\\..\\")
    {
        buf.extend(os.encode_wide());
        buf.push(0);
        return;
    }
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !bytes.contains(&b'/')
        && !bytes[3..].windows(2).any(|w| w == b"\\\\")
        && !bytes.windows(3).any(|w| w == b"\\.\\")
        && !bytes.windows(4).any(|w| w == b"\\..\\")
        && !bytes.ends_with(br"\.")
        && !bytes.ends_with(br"\..")
        && !bytes.ends_with(b"\\")
    {
        buf.extend_from_slice(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]);
        buf.extend(os.encode_wide());
        buf.push(0);
        return;
    }
    let verb = rnpm_fs::to_verbatim_path(path);
    buf.extend(verb.as_os_str().encode_wide());
    buf.push(0);
}

#[cfg(windows)]
fn rename_handle_win32(
    handle: *mut std::ffi::c_void,
    wide_target_null: &[u16],
    target_hint: &Path,
) -> std::io::Result<()> {
    extern "system" {
        fn SetFileInformationByHandle(
            hFile: *mut std::ffi::c_void,
            FileInformationClass: i32,
            lpFileInformation: *const std::ffi::c_void,
            dwBufferSize: u32,
        ) -> i32;
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
        fn GetLastError() -> u32;
    }
    const FILE_RENAME_INFO: i32 = 3;
    const FILE_RENAME_INFO_EX: i32 = 22;
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x01;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x02;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_NOT_SUPPORTED: u32 = 50;
    const ERROR_INVALID_PARAMETER: u32 = 87;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct FileRenameInfoRaw {
        Flags: u32,
        RootDirectory: *mut std::ffi::c_void,
        FileNameLength: u32,
        FileName: [u16; 1],
    }

    let target_chars = wide_target_null.len().saturating_sub(1);
    let name_bytes = (target_chars * 2) as u32;
    let header_offset = std::mem::offset_of!(FileRenameInfoRaw, FileName);
    let total_bytes = header_offset + (target_chars + 1) * 2;
    let total_u64s = total_bytes.div_ceil(8);

    let mut stack_buf = [0u64; 256];
    let mut heap_buf: Vec<u64>;
    let buf_ptr: *mut u8 = if total_u64s <= stack_buf.len() {
        stack_buf.as_mut_ptr() as *mut u8
    } else {
        heap_buf = vec![0u64; total_u64s];
        heap_buf.as_mut_ptr() as *mut u8
    };

    unsafe {
        let info = &mut *(buf_ptr as *mut FileRenameInfoRaw);
        info.Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
        info.RootDirectory = std::ptr::null_mut();
        info.FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            wide_target_null.as_ptr(),
            buf_ptr.add(header_offset) as *mut u16,
            target_chars,
        );
        *(buf_ptr.add(header_offset) as *mut u16).add(target_chars) = 0;
    }

    let struct_size = (header_offset + target_chars * 2)
        .max(std::mem::size_of::<FileRenameInfoRaw>()) as u32;

    let try_rename = |info_class: i32, flags: u32| -> Result<(), u32> {
        unsafe {
            (*(buf_ptr as *mut FileRenameInfoRaw)).Flags = flags;
            if SetFileInformationByHandle(handle, info_class, buf_ptr as *const _, struct_size) != 0
            {
                Ok(())
            } else {
                Err(GetLastError())
            }
        }
    };

    let mut created_parent = false;
    let mut cleared_ro = false;
    loop {
        let res = match try_rename(
            FILE_RENAME_INFO_EX,
            FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS,
        ) {
            Ok(()) => Ok(()),
            Err(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED) => try_rename(FILE_RENAME_INFO, 1),
            Err(e) => Err(e),
        };
        match res {
            Ok(()) => return Ok(()),
            Err(ERROR_PATH_NOT_FOUND) if !created_parent => {
                created_parent = true;
                if let Some(parent) = target_hint.parent() {
                    fs::create_dir_all(parent)?;
                }
            }
            Err(ERROR_ACCESS_DENIED) if !cleared_ro => {
                cleared_ro = true;
                unsafe {
                    SetFileAttributesW(wide_target_null.as_ptr(), FILE_ATTRIBUTE_NORMAL);
                }
            }
            Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32)),
        }
    }
}

#[cfg(windows)]
pub(crate) fn write_and_rename_atomic_wide(
    wide_tmp_null: &[u16],
    wide_target_null: &[u16],
    tmp_hint: &Path,
    target_hint: &Path,
    data: &[u8],
) -> std::io::Result<()> {
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
        fn SetFileInformationByHandle(
            hFile: *mut std::ffi::c_void,
            FileInformationClass: i32,
            lpFileInformation: *const std::ffi::c_void,
            dwBufferSize: u32,
        ) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
    }
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_SHARE_ALL: u32 = 1 | 2 | 4;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_DISPOSITION_INFO: i32 = 4;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

    let mut handle = unsafe {
        CreateFileW(
            wide_tmp_null.as_ptr(),
            GENERIC_WRITE | DELETE_ACCESS,
            FILE_SHARE_ALL,
            std::ptr::null_mut(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        if err == ERROR_PATH_NOT_FOUND {
            if let Some(parent) = tmp_hint.parent() {
                fs::create_dir_all(parent)?;
            }
            handle = unsafe {
                CreateFileW(
                    wide_tmp_null.as_ptr(),
                    GENERIC_WRITE | DELETE_ACCESS,
                    FILE_SHARE_ALL,
                    std::ptr::null_mut(),
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32));
        }
    }

    let cleanup_and_close = |h: *mut std::ffi::c_void| unsafe {
        let del: u8 = 1;
        SetFileInformationByHandle(h, FILE_DISPOSITION_INFO, &del as *const u8 as *const _, 1);
        CloseHandle(h);
    };

    let mut offset = 0usize;
    while offset < data.len() {
        let chunk = ((data.len() - offset).min(u32::MAX as usize)) as u32;
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                handle,
                data[offset..].as_ptr() as *const _,
                chunk,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            cleanup_and_close(handle);
            return Err(std::io::Error::from_raw_os_error(err as i32));
        }
        if written == 0 {
            cleanup_and_close(handle);
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "WriteFile returned 0 bytes written",
            ));
        }
        offset += written as usize;
    }

    if let Err(e) = rename_handle_win32(handle, wide_target_null, target_hint) {
        cleanup_and_close(handle);
        return Err(e);
    }

    unsafe {
        CloseHandle(handle);
    }
    Ok(())
}

pub(crate) fn write_and_rename_atomic(
    temp_path: &Path,
    target_path: &Path,
    data: &[u8],
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut wide_tmp = Vec::with_capacity(260);
        let mut wide_target = Vec::with_capacity(260);
        encode_verbatim_wide_into(temp_path, &mut wide_tmp);
        encode_verbatim_wide_into(target_path, &mut wide_target);
        write_and_rename_atomic_wide(&wide_tmp, &wide_target, temp_path, target_path, data)
    }
    #[cfg(not(windows))]
    {
        let mut file = match OpenOptions::new().write(true).create_new(true).open(temp_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = temp_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                OpenOptions::new().write(true).create_new(true).open(temp_path)?
            }
            Err(e) => return Err(e),
        };
        if let Err(e) = file.write_all(data) {
            drop(file);
            let _ = fs::remove_file(temp_path);
            return Err(e);
        }
        drop(file);
        match fs::rename(temp_path, target_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                match fs::rename(temp_path, target_path) {
                    Ok(()) => Ok(()),
                    Err(e2) => {
                        let _ = fs::remove_file(temp_path);
                        Err(e2)
                    }
                }
            }
            Err(e) => {
                let _ = fs::remove_file(temp_path);
                Err(e)
            }
        }
    }
}

/// Helper to reliably read a file with retries on Windows transient file sharing locks.
fn read_file_with_retries(path: &Path) -> std::io::Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => return Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }
    let mut attempts = 1u32;
    let mut delay = Duration::from_micros(500);
    loop {
        retry_backoff(attempts, &mut delay, Duration::from_millis(100));
        attempts += 1;
        match fs::read(path) {
            Ok(bytes) => return Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(e),
            Err(e) => {
                if attempts >= 10 {
                    return Err(e);
                }
            }
        }
    }
}

fn parse_metadata_bytes(metadata: Option<&[u8]>) -> Option<serde_json::Value> {
    metadata.map(|m| match serde_json::from_slice::<serde_json::Value>(m) {
        Ok(val) => val,
        Err(_) => match std::str::from_utf8(m) {
            Ok(s) => serde_json::Value::String(s.to_string()),
            Err(_) => serde_json::Value::String(HEXLOWER.encode(m)),
        },
    })
}

enum ParsedIntegrity {
    Sha512([u8; 64]),
    Full(Integrity),
}

#[inline]
fn fast_parse_sha512_sri(s: &str) -> Option<[u8; 64]> {
    let trimmed = s.trim();
    let b64 = trimmed.strip_prefix("sha512-")?;
    if b64.len() != 88 || b64.as_bytes().iter().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    let mut decoded = [0u8; 66];
    if BASE64.decode_mut(b64.as_bytes(), &mut decoded).ok()? != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&decoded[..64]);
    Some(out)
}

fn parse_index_integrity(entry: &mut IndexEntry) -> Option<ParsedIntegrity> {
    if let Some(digest) = fast_parse_sha512_sri(&entry.integrity) {
        if entry.sha512_hex.is_empty() {
            let mut hex_buf = [0u8; 128];
            entry.sha512_hex = encode_hex_lower(&digest, &mut hex_buf).to_string();
        }
        return Some(ParsedIntegrity::Sha512(digest));
    }
    let parsed = Integrity::parse(&entry.integrity).ok()?;
    if entry.sha512_hex.is_empty() {
        if let Some(sha512) = parsed
            .entries
            .iter()
            .find(|e| e.algorithm == Algorithm::Sha512)
        {
            let mut hex_buf = [0u8; 128];
            if sha512.digest.len() == 64 {
                entry.sha512_hex = encode_hex_lower(&sha512.digest, &mut hex_buf).to_string();
            } else {
                entry.sha512_hex = HEXLOWER.encode(&sha512.digest);
            }
        }
    }
    Some(ParsedIntegrity::Full(parsed))
}

fn parse_index_line(trimmed: &str, expected_key: Option<&str>) -> Option<(IndexEntry, ParsedIntegrity)> {
    let json_str = match trimmed.find('\t') {
        Some(tab_pos) => &trimmed[tab_pos + 1..],
        None => trimmed,
    };
    let mut entry = serde_json::from_str::<IndexEntry>(json_str).ok()?;
    if let Some(k) = expected_key {
        if entry.key != k {
            return None;
        }
    }
    let parsed = parse_index_integrity(&mut entry)?;
    Some((entry, parsed))
}

fn parse_index_entry_slice(
    content: &str,
    expected_key: Option<&str>,
    strict_all_lines: bool,
) -> Option<(IndexEntry, ParsedIntegrity)> {
    if strict_all_lines {
        let mut last: Option<(IndexEntry, ParsedIntegrity)> = None;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            last = Some(parse_index_line(trimmed, expected_key)?);
        }
        if last.is_some() {
            return last;
        }
    } else {
        for line in content.lines().rev() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            return parse_index_line(trimmed, expected_key);
        }
    }

    None
}

type VerifiedBlobResult = Option<(Vec<u8>, [u8; 64])>;

fn parse_index_content(
    content: &str,
    expected_key: Option<&str>,
    strict_all_lines: bool,
) -> Option<(IndexEntry, ParsedIntegrity)> {
    if let Some(pair) = parse_index_entry_slice(content, expected_key, strict_all_lines) {
        return Some(pair);
    }
    if content.trim_start().starts_with('{') {
        if let Ok(mut entry) = serde_json::from_str::<IndexEntry>(content) {
            if let Some(k) = expected_key {
                if entry.key != k {
                    return None;
                }
            }
            if let Some(parsed) = parse_index_integrity(&mut entry) {
                return Some((entry, parsed));
            }
        }
    }
    None
}

#[inline]
fn verify_sha512_and_integrity(
    data: &[u8],
    expected_integrity: &Integrity,
    key_for_err: &str,
) -> Result<[u8; 64], CacheError> {
    if expected_integrity.strongest_algorithm() == Some(Algorithm::Sha512) {
        let actual_digest: [u8; 64] = Sha512::digest(data).into();
        if sha512_matches_integrity(&actual_digest, expected_integrity) == Some(true) {
            return Ok(actual_digest);
        }
        let expected_b64 = expected_integrity
            .entries
            .iter()
            .find(|e| e.algorithm == Algorithm::Sha512)
            .map(|e| e.digest_base64.as_str())
            .unwrap_or_default();
        return Err(CacheError::IntegrityMismatch {
            key: key_for_err.to_string(),
            expected: format!("sha512-{expected_b64}"),
            actual: format!("sha512-{}", BASE64.encode(&actual_digest)),
        });
    }

    expected_integrity.verify(data).map_err(|e| match e {
        IntegrityError::Mismatch {
            expected, actual, ..
        } => CacheError::IntegrityMismatch {
            key: key_for_err.to_string(),
            expected,
            actual,
        },
        other => CacheError::Core(rnpm_core::CoreError::Integrity(other)),
    })?;
    Ok(Sha512::digest(data).into())
}

/// Content-addressable cache manager.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
    lock_timeout: Duration,
    stale_threshold: Duration,
    blob_prefix_dirs: Arc<[AtomicU64; 1024]>,
    index_prefix_dirs: Arc<[AtomicU64; 1024]>,
    lock_shards: Arc<[Mutex<()>; LOCK_SHARD_COUNT]>,
}

impl Cache {
    /// Initialize a cache instance at the given root directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("content-v2").join("sha512"))?;
        fs::create_dir_all(root.join("index-v5"))?;
        fs::create_dir_all(root.join("tmp"))?;
        fs::create_dir_all(root.join("locks"))?;
        Ok(Self {
            root,
            lock_timeout: CacheLock::DEFAULT_TIMEOUT,
            stale_threshold: CacheLock::DEFAULT_STALE_THRESHOLD,
            blob_prefix_dirs: Arc::new([const { AtomicU64::new(0) }; 1024]),
            index_prefix_dirs: Arc::new([const { AtomicU64::new(0) }; 1024]),
            lock_shards: Arc::new(std::array::from_fn(|_| Mutex::new(()))),
        })
    }

    /// Configure custom lock acquisition timeout.
    pub fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    /// Configure custom stale lock threshold.
    pub fn with_stale_threshold(mut self, threshold: Duration) -> Self {
        self.stale_threshold = threshold;
        self
    }

    /// Root directory of this cache.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Temp directory located on the SAME filesystem/volume for atomic renames.
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Compute storage path for a SHA-512 digest hex string.
    pub fn blob_path(&self, sha512_hex: &str) -> PathBuf {
        self.blob_path_for_algo(Algorithm::Sha512, sha512_hex)
    }

    fn npm_blob_path_for_algo(&self, algo: Algorithm, hex_str: &str) -> PathBuf {
        let mut stack_buf = [0u8; 128];
        let owned_hex;
        let hex: &str = if hex_str.is_ascii() && hex_str.len() <= 128 {
            for (i, &b) in hex_str.as_bytes().iter().enumerate() {
                stack_buf[i] = b.to_ascii_lowercase();
            }
            std::str::from_utf8(&stack_buf[..hex_str.len()]).unwrap_or(hex_str)
        } else {
            owned_hex = hex_str.to_ascii_lowercase();
            &owned_hex
        };

        let mut npm_style = PathBuf::with_capacity(self.root.as_os_str().len() + hex.len() + 32);
        npm_style.push(&self.root);
        npm_style.push("content-v2");
        npm_style.push(algo.as_str());
        if hex.is_ascii() {
            let p1 = if hex.len() >= 2 { &hex[0..2] } else { "xx" };
            let p2 = if hex.len() >= 4 { &hex[2..4] } else { "yy" };
            npm_style.push(p1);
            npm_style.push(p2);
            npm_style.push(if hex.len() >= 4 { &hex[4..] } else { hex });
        } else {
            let mut chars = hex.chars();
            let p1: String = chars.by_ref().take(2).collect();
            let p2: String = chars.by_ref().take(2).collect();
            let rest: String = chars.collect();
            npm_style.push(if p1.len() == 2 { &p1 } else { "xx" });
            npm_style.push(if p2.len() == 2 { &p2 } else { "yy" });
            npm_style.push(if rest.is_empty() { hex } else { &rest });
        }
        npm_style
    }

    fn legacy_blob_path_from_npm(npm_path: &Path, hex_str: &str) -> PathBuf {
        let mut legacy = npm_path.to_path_buf();
        if hex_str.bytes().any(|b| b.is_ascii_uppercase()) {
            legacy.set_file_name(hex_str.to_ascii_lowercase());
        } else {
            legacy.set_file_name(hex_str);
        }
        legacy
    }

    /// Compute storage path for a digest hex string under a specific algorithm (cacache content-v2/<algo> layout).
    pub fn blob_path_for_algo(&self, algo: Algorithm, hex_str: &str) -> PathBuf {
        let npm_style = self.npm_blob_path_for_algo(algo, hex_str);
        if npm_style.exists() {
            return npm_style;
        }
        let legacy_style = Self::legacy_blob_path_from_npm(&npm_style, hex_str);
        if legacy_style.exists() {
            legacy_style
        } else {
            npm_style
        }
    }

    /// Compute lock file path for a given resource name.
    pub fn lock_path(&self, name: &str) -> PathBuf {
        let mut path = PathBuf::with_capacity(self.root.as_os_str().len() + name.len() + 16);
        path.push(&self.root);
        path.push("locks");
        if name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            let mut file = String::with_capacity(name.len() + 5);
            file.push_str(name);
            file.push_str(".lock");
            path.push(file);
            return path;
        }
        let mut file = String::with_capacity(name.len() + 5);
        for c in name.chars() {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                file.push(c);
            } else {
                file.push('_');
            }
        }
        file.push_str(".lock");
        path.push(file);
        path
    }

    fn lock_key_by_hash_with_options(
        &self,
        hash: &str,
        timeout: Duration,
        stale_threshold: Duration,
    ) -> Result<CacheLock, CacheError> {
        let mut name = String::with_capacity(4 + hash.len());
        name.push_str("idx_");
        name.push_str(hash);
        let lock_path = self.lock_path(&name);
        CacheLock::acquire_exclusive_with_options(&lock_path, timeout, stale_threshold).map_err(
            |e| {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    CacheError::LockFailed(lock_path.display().to_string())
                } else {
                    CacheError::Io(e)
                }
            },
        )
    }

    /// Acquire an exclusive cross-process lock for a key with custom options.
    pub fn lock_key_with_options(
        &self,
        key: &str,
        timeout: Duration,
        stale_threshold: Duration,
    ) -> Result<CacheLock, CacheError> {
        let mut hex_buf = [0u8; 64];
        let hash = sha256_hex_stack(key.as_bytes(), &mut hex_buf);
        self.lock_key_by_hash_with_options(hash, timeout, stale_threshold)
    }

    /// Acquire an exclusive cross-process lock for a key.
    pub fn lock_key(&self, key: &str) -> Result<CacheLock, CacheError> {
        self.lock_key_with_options(key, self.lock_timeout, self.stale_threshold)
    }

    /// Acquire an exclusive cross-process lock for a blob digest with custom options.
    pub fn lock_blob_with_options(
        &self,
        sha512_hex: &str,
        timeout: Duration,
        stale_threshold: Duration,
    ) -> Result<CacheLock, CacheError> {
        let lock_path = self.lock_path(&format!("blob_{sha512_hex}"));
        CacheLock::acquire_exclusive_with_options(&lock_path, timeout, stale_threshold).map_err(
            |e| {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    CacheError::LockFailed(lock_path.display().to_string())
                } else {
                    CacheError::Io(e)
                }
            },
        )
    }

    /// Acquire an exclusive cross-process lock for a blob digest.
    pub fn lock_blob(&self, sha512_hex: &str) -> Result<CacheLock, CacheError> {
        self.lock_blob_with_options(sha512_hex, self.lock_timeout, self.stale_threshold)
    }

    /// Create a unique temporary file path within `<cache_root>/tmp` (guaranteed on same volume).
    fn create_temp_path(&self, prefix: &str) -> PathBuf {
        let count = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let now = process_start_nanos();
        let mut name = String::with_capacity(prefix.len() + 48);
        let _ = write!(&mut name, "{prefix}_{pid}_{now}_{count}.tmp");
        let mut path = PathBuf::with_capacity(self.root.as_os_str().len() + 8 + name.len());
        path.push(&self.root);
        path.push("tmp");
        path.push(&name);
        path
    }

    fn write_temp_file(&self, prefix: &str, data: &[u8]) -> Result<PathBuf, CacheError> {
        let temp_path = self.create_temp_path(prefix);
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(self.tmp_dir())?;
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_path)?
            }
            Err(e) => return Err(CacheError::Io(e)),
        };
        file.write_all(data)?;
        Ok(temp_path)
    }

    /// Atomically store raw bytes into content-addressable storage.
    ///
    /// Writes to a temporary file in `<cache_root>/tmp`, verifies the checksum,
    /// and then renames to the final content-addressable path.
    pub fn put_blob(
        &self,
        data: &[u8],
        expected_integrity: Option<&Integrity>,
    ) -> Result<String, CacheError> {
        let sha512_bytes: [u8; 64] = if let Some(expected) = expected_integrity {
            verify_sha512_and_integrity(data, expected, "blob")?
        } else {
            Sha512::digest(data).into()
        };
        let mut hex_buf = [0u8; 128];
        let sha512_hex = encode_hex_lower(&sha512_bytes, &mut hex_buf).to_string();

        self.put_blob_direct(data, &sha512_hex)?;
        Ok(sha512_hex)
    }

    /// Store a pre-verified blob atomically by its known SHA-512 hex digest.
    pub fn put_blob_direct(&self, data: &[u8], sha512_hex: &str) -> Result<(), CacheError> {
        let npm_path = self.npm_blob_path_for_algo(Algorithm::Sha512, sha512_hex);
        let mut npm_definitely_missing = false;
        match fs::File::open(&npm_path) {
            Ok(mut f) => {
                if let Ok(meta) = f.metadata() {
                    if meta.is_dir() {
                        return Err(CacheError::Io(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            format!("Blob path is a directory: {}", npm_path.display()),
                        )));
                    }
                    if meta.len() == data.len() as u64 {
                        let mut existing = Vec::with_capacity(data.len());
                        if f.read_to_end(&mut existing).is_ok() && existing.as_slice() == data {
                            return Ok(());
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                npm_definitely_missing = true;
                if !is_path_not_found(&e) {
                    let legacy_path = Self::legacy_blob_path_from_npm(&npm_path, sha512_hex);
                    if let Ok(meta) = fs::metadata(&legacy_path) {
                        if meta.is_dir() {
                            return Err(CacheError::Io(std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                format!("Blob path is a directory: {}", legacy_path.display()),
                            )));
                        }
                        if meta.len() == data.len() as u64 {
                            if let Ok(existing) = read_file_with_retries(&legacy_path) {
                                if existing.as_slice() == data {
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {
                if let Ok(meta) = fs::metadata(&npm_path) {
                    if meta.is_dir() {
                        return Err(CacheError::Io(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            format!("Blob path is a directory: {}", npm_path.display()),
                        )));
                    }
                    if meta.len() == data.len() as u64 {
                        if let Ok(existing) = read_file_with_retries(&npm_path) {
                            if existing.as_slice() == data {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }

        if npm_definitely_missing || fs::symlink_metadata(&npm_path).is_err() {
            if !prefix_bitset_has(&self.blob_prefix_dirs, sha512_hex) {
                if let Some(parent) = npm_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                prefix_bitset_set(&self.blob_prefix_dirs, sha512_hex);
            }
            let temp_path = self.create_temp_path("blob");
            match write_and_rename_atomic(&temp_path, &npm_path, data) {
                Ok(()) => {
                    prefix_bitset_set(&self.blob_prefix_dirs, sha512_hex);
                    debug!("Atomically stored blob {}", npm_path.display());
                    return Ok(());
                }
                Err(_) if npm_path.is_dir() => {
                    return Err(CacheError::Io(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("Blob path is a directory: {}", npm_path.display()),
                    )));
                }
                Err(_) => {}
            }
        }

        // Fallback staging step: Write to temporary file on the SAME filesystem/volume
        let temp_path = self.write_temp_file("blob", data)?;

        // Serialize in-process writers on the same shard before touching the lockfile.
        let _shard_guard = self.lock_shards[shard_index_for_str(sha512_hex)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _blob_lock = self.lock_blob(sha512_hex)?;
        if let Ok(meta) = fs::metadata(&npm_path) {
            if meta.is_dir() {
                let _ = remove_file_with_retries(&temp_path);
                return Err(CacheError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("Blob path is a directory: {}", npm_path.display()),
                )));
            }
            if meta.len() == data.len() as u64 {
                if let Ok(existing) = read_file_with_retries(&npm_path) {
                    if existing.as_slice() == data {
                        let _ = remove_file_with_retries(&temp_path);
                        return Ok(());
                    }
                }
            }
            let _ = remove_file_with_retries(&npm_path);
        } else {
            let legacy_path = Self::legacy_blob_path_from_npm(&npm_path, sha512_hex);
            if legacy_path.is_file() {
                let _ = remove_file_with_retries(&legacy_path);
            }
        }

        if let Err(err) = rename_with_retries(&temp_path, &npm_path) {
            let _ = remove_file_with_retries(&temp_path);
            return Err(CacheError::Io(err));
        }
        prefix_bitset_set(&self.blob_prefix_dirs, sha512_hex);
        debug!("Atomically stored blob {}", npm_path.display());

        Ok(())
    }

    fn read_and_verify_sha512(&self, sha512_hex: &str) -> Result<VerifiedBlobResult, CacheError> {
        let npm_path = self.npm_blob_path_for_algo(Algorithm::Sha512, sha512_hex);
        let (bytes, used_path) = match read_file_with_retries(&npm_path) {
            Ok(b) => (b, npm_path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if is_path_not_found(&e) {
                    return Ok(None);
                }
                let legacy_path = Self::legacy_blob_path_from_npm(&npm_path, sha512_hex);
                match read_file_with_retries(&legacy_path) {
                    Ok(b) => (b, legacy_path),
                    Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e2) => {
                        warn!(
                            "Unreadable or corrupt blob at {} ({e2}). Purging corrupted entry.",
                            legacy_path.display()
                        );
                        let _ = remove_file_with_retries(&legacy_path);
                        return Ok(None);
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Unreadable or corrupt blob at {} ({e}). Purging corrupted entry.",
                    npm_path.display()
                );
                let _ = remove_file_with_retries(&npm_path);
                return Ok(None);
            }
        };

        let actual_digest: [u8; 64] = Sha512::digest(&bytes).into();
        let matches = match decode_sha512_hex_stack(sha512_hex) {
            Some(expected) => actual_digest == expected,
            None => {
                let mut hex_buf = [0u8; 128];
                encode_hex_lower(&actual_digest, &mut hex_buf).eq_ignore_ascii_case(sha512_hex)
            }
        };

        if !matches {
            let mut hex_buf = [0u8; 128];
            let actual_hex = encode_hex_lower(&actual_digest, &mut hex_buf);
            warn!(
                "Cached blob {} is corrupted (expected {}, got {})! Purging corrupt entry and signaling cache miss.",
                used_path.display(),
                sha512_hex,
                actual_hex
            );
            let _ = remove_file_with_retries(&used_path);
            return Ok(None);
        }

        Ok(Some((bytes, actual_digest)))
    }

    /// Retrieve a blob by its SHA-512 hex digest.
    ///
    /// If the file on disk is corrupted (checksum mismatch or unreadable), it is automatically
    /// PURGED and `Ok(None)` is returned (signaling a cache miss for re-fetch).
    pub fn get_by_sha512(&self, sha512_hex: &str) -> Result<Option<Vec<u8>>, CacheError> {
        Ok(self.read_and_verify_sha512(sha512_hex)?.map(|(b, _)| b))
    }

    /// Retrieve an index entry by key.
    ///
    /// If the index file is corrupted (invalid JSON, non-UTF-8, or mismatched key),
    /// it is automatically PURGED and `Ok(None)` is returned.
    pub fn get_index_entry(&self, key: &str) -> Result<Option<IndexEntry>, CacheError> {
        Ok(self.get_index_entry_with_parsed(key)?.map(|(e, _)| e))
    }

    fn get_index_entry_with_parsed(
        &self,
        key: &str,
    ) -> Result<Option<(IndexEntry, ParsedIntegrity)>, CacheError> {
        // First try exact key
        if let Some(pair) = self.get_index_entry_internal(key)? {
            return Ok(Some(pair));
        }

        // Try npm cacache / pacote key aliases
        if key.starts_with("http://") || key.starts_with("https://") {
            let alias = format!("make-fetch-happen:request-cache:{key}");
            if let Some(pair) = self.get_index_entry_internal(&alias)? {
                return Ok(Some(pair));
            }
        } else if let Some(stripped) = key.strip_prefix("make-fetch-happen:request-cache:") {
            if let Some(pair) = self.get_index_entry_internal(stripped)? {
                return Ok(Some(pair));
            }
        } else if !key.contains(':') {
            let alias = format!("pacote:packument:{key}");
            if let Some(pair) = self.get_index_entry_internal(&alias)? {
                return Ok(Some(pair));
            }
        } else if let Some(stripped) = key.strip_prefix("pacote:packument:") {
            if let Some(pair) = self.get_index_entry_internal(stripped)? {
                return Ok(Some(pair));
            }
            if stripped.contains("://") {
                if let Some((protocol, rest)) = stripped.split_once("://") {
                    if let Some((host_part, name_part)) = rest.split_once(':') {
                        if host_part.ends_with('/') {
                            let trimmed_host = host_part.trim_end_matches('/');
                            let alt_key =
                                format!("pacote:packument:{protocol}://{trimmed_host}:{name_part}");
                            if let Some(pair) = self.get_index_entry_internal(&alt_key)? {
                                return Ok(Some(pair));
                            }
                        } else {
                            let alt_key =
                                format!("pacote:packument:{protocol}://{host_part}/:{name_part}");
                            if let Some(pair) = self.get_index_entry_internal(&alt_key)? {
                                return Ok(Some(pair));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn get_index_entry_internal(
        &self,
        key: &str,
    ) -> Result<Option<(IndexEntry, ParsedIntegrity)>, CacheError> {
        let mut hex_buf = [0u8; 64];
        let hash = sha256_hex_stack(key.as_bytes(), &mut hex_buf);
        let npm_path = npm_index_path_from_hash(&self.root, hash);
        let (bytes, index_path) = match read_file_with_retries(&npm_path) {
            Ok(b) => (b, npm_path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if is_path_not_found(&e) {
                    return Ok(None);
                }
                let legacy_path = legacy_index_path_from_npm(&npm_path, hash);
                match read_file_with_retries(&legacy_path) {
                    Ok(b) => (b, legacy_path),
                    Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e2) => {
                        warn!(
                            "Unreadable index entry at {} ({e2}). Purging corrupt index.",
                            legacy_path.display()
                        );
                        let _ = remove_file_with_retries(&legacy_path);
                        return Ok(None);
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Unreadable index entry at {} ({e}). Purging corrupt index.",
                    npm_path.display()
                );
                let _ = remove_file_with_retries(&npm_path);
                return Ok(None);
            }
        };

        let content = match std::str::from_utf8(&bytes) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Non-UTF8 index entry at {} ({e}). Purging corrupt index.",
                    index_path.display()
                );
                self.purge_key_index_files(key);
                return Ok(None);
            }
        };

        if let Some(pair) = parse_index_content(content, Some(key), false) {
            return Ok(Some(pair));
        }

        warn!(
            "Corrupt or mismatched index entry at {}. Purging corrupt index.",
            index_path.display()
        );
        self.purge_key_index_files(key);
        Ok(None)
    }

    fn write_index_entry(&self, key: &str, entry: &IndexEntry) -> Result<(), CacheError> {
        let mut hex_buf = [0u8; 64];
        let hash = sha256_hex_stack(key.as_bytes(), &mut hex_buf);
        let npm_path = npm_index_path_from_hash(&self.root, hash);

        let mut buf = Vec::with_capacity(256 + key.len());
        buf.resize(41, 0u8);
        serde_json::to_writer(&mut buf, entry)?;
        let sha1_digest = sha1::Sha1::digest(&buf[41..]);
        encode_hex_lower(&sha1_digest, &mut buf[..40]);
        buf[40] = b'\t';
        buf.push(b'\n');

        let temp_path = self.create_temp_path("index");

        let _shard_guard = self.lock_shards[shard_index_for_str(hash)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if !prefix_bitset_has(&self.index_prefix_dirs, hash) {
            if let Some(parent) = npm_path.parent() {
                fs::create_dir_all(parent)?;
            }
            prefix_bitset_set(&self.index_prefix_dirs, hash);
        }

        if write_and_rename_atomic(&temp_path, &npm_path, &buf).is_ok() {
            return Ok(());
        }

        let staged = self.write_temp_file("index", &buf)?;
        let _key_lock = self.lock_key_by_hash_with_options(
            hash,
            self.lock_timeout,
            self.stale_threshold,
        )?;
        if let Err(err) = rename_with_retries(&staged, &npm_path) {
            let _ = remove_file_with_retries(&staged);
            return Err(CacheError::Io(err));
        }
        Ok(())
    }

    /// Store an entry into the cache with key mapping and strict integrity verification.
    ///
    /// If `expected_integrity` is provided, verifies it BEFORE writing blob or index entry;
    /// if mismatch, returns `CacheError::IntegrityMismatch` immediately without touching cache files!
    pub fn put_with_integrity(
        &self,
        key: &str,
        data: &[u8],
        expected_integrity: Option<&Integrity>,
        metadata: Option<&[u8]>,
    ) -> Result<IndexEntry, CacheError> {
        let (sha512_bytes, integrity) = if let Some(expected) = expected_integrity {
            let bytes = verify_sha512_and_integrity(data, expected, key)?;
            (bytes, expected.to_string())
        } else {
            let bytes: [u8; 64] = Sha512::digest(data).into();
            let integ = format!("sha512-{}", BASE64.encode(&bytes));
            (bytes, integ)
        };

        let mut hex_buf = [0u8; 128];
        let sha512_hex = encode_hex_lower(&sha512_bytes, &mut hex_buf).to_string();
        self.put_blob_direct(data, &sha512_hex)?;

        let entry = IndexEntry::new(
            key.to_string(),
            integrity,
            sha512_hex,
            data.len() as u64,
            parse_metadata_bytes(metadata),
        );
        self.write_index_entry(key, &entry)?;
        Ok(entry)
    }

    /// Store an entry into the cache with key mapping.
    ///
    /// Stores the blob content, creates the index metadata, and writes both atomically.
    pub fn put(
        &self,
        key: &str,
        data: &[u8],
        metadata: Option<serde_json::Value>,
    ) -> Result<IndexEntry, CacheError> {
        let sha512_bytes: [u8; 64] = Sha512::digest(data).into();
        let mut hex_buf = [0u8; 128];
        let sha512_hex = encode_hex_lower(&sha512_bytes, &mut hex_buf).to_string();
        let integrity = format!("sha512-{}", BASE64.encode(&sha512_bytes));

        self.put_blob_direct(data, &sha512_hex)?;

        let entry = IndexEntry::new(
            key.to_string(),
            integrity,
            sha512_hex,
            data.len() as u64,
            metadata,
        );
        self.write_index_entry(key, &entry)?;
        Ok(entry)
    }

    fn purge_key_index_files(&self, key: &str) {
        let mut hex_buf = [0u8; 64];
        let hash = sha256_hex_stack(key.as_bytes(), &mut hex_buf);
        let npm_path = npm_index_path_from_hash(&self.root, hash);
        let legacy_path = legacy_index_path_from_npm(&npm_path, hash);
        let _ = remove_file_with_retries(&npm_path);
        let _ = remove_file_with_retries(&legacy_path);
    }

    fn purge_blob_files(&self, sha512_hex: &str) {
        if sha512_hex.is_empty() {
            return;
        }
        let npm_path = self.npm_blob_path_for_algo(Algorithm::Sha512, sha512_hex);
        let legacy_path = Self::legacy_blob_path_from_npm(&npm_path, sha512_hex);
        let _ = remove_file_with_retries(&npm_path);
        let _ = remove_file_with_retries(&legacy_path);
    }

    fn get_with_entry_and_parsed(
        &self,
        entry: IndexEntry,
        parsed_integrity: ParsedIntegrity,
    ) -> Result<Option<(IndexEntry, Vec<u8>)>, CacheError> {
        if !entry.sha512_hex.is_empty() {
            if let Some((bytes, actual_digest)) = self.read_and_verify_sha512(&entry.sha512_hex)? {
                let valid = match &parsed_integrity {
                    ParsedIntegrity::Sha512(expected_digest) => {
                        constant_time_eq_64(&actual_digest, expected_digest)
                    }
                    ParsedIntegrity::Full(parsed) => {
                        match sha512_matches_integrity(&actual_digest, parsed) {
                            Some(ok) => ok,
                            None => parsed.verify(&bytes).is_ok(),
                        }
                    }
                };
                if !valid {
                    warn!(
                        "SSRI integrity mismatch for key '{}'. Auto-purging corrupt entry and treating as cache miss.",
                        entry.key
                    );
                    self.purge_key_index_files(&entry.key);
                    self.purge_blob_files(&entry.sha512_hex);
                    return Ok(None);
                }
                return Ok(Some((entry, bytes)));
            }
        }

        let parsed = match parsed_integrity {
            ParsedIntegrity::Full(p) => p,
            ParsedIntegrity::Sha512(_) => match Integrity::parse(&entry.integrity) {
                Ok(p) => p,
                Err(_) => {
                    self.purge_key_index_files(&entry.key);
                    return Ok(None);
                }
            },
        };
        if let Some(bytes) = self.get_by_integrity(&parsed)? {
            return Ok(Some((entry, bytes)));
        }

        self.purge_key_index_files(&entry.key);
        warn!(
            "Blob for index key '{}' was corrupted or missing. Stale index purged.",
            entry.key
        );
        Ok(None)
    }

    /// Retrieve cached data and index metadata by key.
    ///
    /// If the blob is missing or corrupted, both the blob and index entry are purged,
    /// and `Ok(None)` is returned to signal a cache miss for re-fetching.
    pub fn get(&self, key: &str) -> Result<Option<(IndexEntry, Vec<u8>)>, CacheError> {
        let Some((entry, parsed_integrity)) = self.get_index_entry_with_parsed(key)? else {
            return Ok(None);
        };
        self.get_with_entry_and_parsed(entry, parsed_integrity)
    }

    fn get_exact(&self, key: &str) -> Result<Option<(IndexEntry, Vec<u8>)>, CacheError> {
        let Some((entry, parsed_integrity)) = self.get_index_entry_internal(key)? else {
            return Ok(None);
        };
        self.get_with_entry_and_parsed(entry, parsed_integrity)
    }

    /// Retrieve the local filesystem path to a cached blob without reading the contents into memory.
    /// This enables zero-copy streaming extraction and inspection.
    pub fn get_blob_path(&self, key: &str) -> Result<Option<(IndexEntry, PathBuf)>, CacheError> {
        let (entry, parsed_integrity) = match self.get_index_entry_with_parsed(key)? {
            Some(pair) => pair,
            None => return Ok(None),
        };

        if !entry.sha512_hex.is_empty() {
            let npm_path = self.npm_blob_path_for_algo(Algorithm::Sha512, &entry.sha512_hex);
            if npm_path.exists() {
                return Ok(Some((entry, npm_path)));
            }
            let legacy_path = Self::legacy_blob_path_from_npm(&npm_path, &entry.sha512_hex);
            if legacy_path.exists() {
                return Ok(Some((entry, legacy_path)));
            }
        }

        let mut sorted_entries = match parsed_integrity {
            ParsedIntegrity::Full(p) => p.entries,
            ParsedIntegrity::Sha512(_) => return Ok(None),
        };
        if sorted_entries.len() > 1 {
            sorted_entries.sort_by_key(|a| std::cmp::Reverse(a.algorithm));
        }

        for ssri in sorted_entries {
            let hex = HEXLOWER.encode(&ssri.digest);
            let npm_path = self.npm_blob_path_for_algo(ssri.algorithm, &hex);
            if npm_path.exists() {
                return Ok(Some((entry, npm_path)));
            }
            let legacy_path = Self::legacy_blob_path_from_npm(&npm_path, &hex);
            if legacy_path.exists() {
                return Ok(Some((entry, legacy_path)));
            }
        }

        Ok(None)
    }

    /// Store a local file into content-addressable storage with key mapping and strict integrity verification.
    /// Streams content from `source_path` in bounded chunks to avoid buffering the whole file in memory.
    pub fn put_file_with_integrity(
        &self,
        key: &str,
        source_path: &Path,
        expected_integrity: Option<&Integrity>,
        metadata: Option<&[u8]>,
    ) -> Result<IndexEntry, CacheError> {
        use std::io::Read;

        let mut src_file = fs::File::open(source_path).map_err(CacheError::Io)?;
        let temp_blob = self.create_temp_path("blob");
        let mut dst_file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_blob)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(self.tmp_dir())?;
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_blob)?
            }
            Err(e) => return Err(CacheError::Io(e)),
        };

        let mut hasher = Sha512::new();
        let mut buffer = [0u8; 131072];
        let mut total_size = 0u64;

        let read_res: Result<(), CacheError> = (|| {
            loop {
                let bytes_read = src_file.read(&mut buffer).map_err(CacheError::Io)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
                dst_file.write_all(&buffer[..bytes_read])?;
                total_size += bytes_read as u64;
            }
            Ok(())
        })();
        drop(dst_file);

        if let Err(err) = read_res {
            let _ = remove_file_with_retries(&temp_blob);
            return Err(err);
        }

        let sha512_bytes: [u8; 64] = hasher.finalize().into();
        let mut hex_buf = [0u8; 128];
        let sha512_hex = encode_hex_lower(&sha512_bytes, &mut hex_buf).to_string();

        if let Some(expected) = expected_integrity {
            let mut verified = false;
            if expected.strongest_algorithm() == Some(Algorithm::Sha512) {
                if sha512_matches_integrity(&sha512_bytes, expected) == Some(true) {
                    verified = true;
                } else {
                    let _ = remove_file_with_retries(&temp_blob);
                    let expected_str = expected
                        .entries
                        .iter()
                        .find(|e| e.algorithm == Algorithm::Sha512)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| expected.to_string());
                    return Err(CacheError::IntegrityMismatch {
                        key: key.to_string(),
                        expected: expected_str,
                        actual: format!("sha512-{}", BASE64.encode(&sha512_bytes)),
                    });
                }
            }
            if !verified {
                let staged_bytes = match fs::read(&temp_blob) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = remove_file_with_retries(&temp_blob);
                        return Err(CacheError::Io(e));
                    }
                };
                if let Err(e) = expected.verify(&staged_bytes) {
                    let _ = remove_file_with_retries(&temp_blob);
                    return Err(CacheError::IntegrityMismatch {
                        key: key.to_string(),
                        expected: expected.to_string(),
                        actual: e.to_string(),
                    });
                }
            }
        }

        let npm_path = self.npm_blob_path_for_algo(Algorithm::Sha512, &sha512_hex);
        let mut stored = false;
        if fs::symlink_metadata(&npm_path).is_err() {
            if !prefix_bitset_has(&self.blob_prefix_dirs, &sha512_hex) {
                if let Some(parent) = npm_path.parent() {
                    if let Err(dir_err) = fs::create_dir_all(parent) {
                        let _ = remove_file_with_retries(&temp_blob);
                        return Err(CacheError::Io(dir_err));
                    }
                }
                prefix_bitset_set(&self.blob_prefix_dirs, &sha512_hex);
            }
            match fs::rename(&temp_blob, &npm_path) {
                Ok(()) => stored = true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if let Some(parent) = npm_path.parent() {
                        if let Err(dir_err) = fs::create_dir_all(parent) {
                            let _ = remove_file_with_retries(&temp_blob);
                            return Err(CacheError::Io(dir_err));
                        }
                    }
                    if fs::rename(&temp_blob, &npm_path).is_ok() {
                        stored = true;
                    }
                }
                Err(e) if npm_path.is_dir() => {
                    let _ = remove_file_with_retries(&temp_blob);
                    return Err(CacheError::Io(e));
                }
                Err(_) => {}
            }
        }

        if !stored {
            let _shard_guard = self.lock_shards[shard_index_for_str(&sha512_hex)]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let _blob_lock = match self.lock_blob(&sha512_hex) {
                Ok(l) => l,
                Err(e) => {
                    let _ = remove_file_with_retries(&temp_blob);
                    return Err(e);
                }
            };
            let existing_valid = match fs::metadata(&npm_path) {
                Ok(meta) if meta.is_dir() => {
                    let _ = remove_file_with_retries(&temp_blob);
                    return Err(CacheError::Io(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("Blob path is a directory: {}", npm_path.display()),
                    )));
                }
                Ok(meta) => {
                    let ok = meta.len() == total_size
                        && read_file_with_retries(&npm_path)
                            .is_ok_and(|b| Sha512::digest(&b).as_slice() == sha512_bytes.as_slice());
                    if !ok {
                        let _ = remove_file_with_retries(&npm_path);
                    }
                    ok
                }
                Err(_) => false,
            };
            if existing_valid {
                let _ = remove_file_with_retries(&temp_blob);
            } else if let Err(err) = rename_with_retries(&temp_blob, &npm_path) {
                let _ = remove_file_with_retries(&temp_blob);
                return Err(CacheError::Io(err));
            }
        }

        let integrity = if let Some(expected) = expected_integrity {
            expected.to_string()
        } else {
            format!("sha512-{}", BASE64.encode(&sha512_bytes))
        };

        let entry = IndexEntry::new(
            key.to_string(),
            integrity,
            sha512_hex,
            total_size,
            parse_metadata_bytes(metadata),
        );
        self.write_index_entry(key, &entry)?;
        Ok(entry)
    }

    /// Retrieve a blob by its SSRI Integrity descriptor.
    /// If corrupted, auto-purges the corrupt blob, logs a diagnostic, and returns `Ok(None)` for clean re-fetching.
    pub fn get_by_integrity(&self, integrity: &Integrity) -> Result<Option<Vec<u8>>, CacheError> {
        if integrity.entries.len() == 1 {
            let entry = &integrity.entries[0];
            if entry.algorithm == Algorithm::Sha512 {
                let mut hex_buf = [0u8; 128];
                if entry.digest.len() == 64 {
                    let hex = encode_hex_lower(&entry.digest, &mut hex_buf);
                    return self.get_by_sha512(hex);
                }
            }
            let hex = HEXLOWER.encode(&entry.digest);
            let npm_path = self.npm_blob_path_for_algo(entry.algorithm, &hex);
            let (bytes, used_path) = match read_file_with_retries(&npm_path) {
                Ok(b) => (b, npm_path),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if is_path_not_found(&e) {
                        return Ok(None);
                    }
                    let legacy_path = Self::legacy_blob_path_from_npm(&npm_path, &hex);
                    match read_file_with_retries(&legacy_path) {
                        Ok(b) => (b, legacy_path),
                        Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                        Err(e2) => {
                            warn!(
                                "Unreadable or corrupt blob at {} ({e2}). Purging corrupted entry.",
                                legacy_path.display()
                            );
                            let _ = remove_file_with_retries(&legacy_path);
                            return Ok(None);
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Unreadable or corrupt blob at {} ({e}). Purging corrupted entry.",
                        npm_path.display()
                    );
                    let _ = remove_file_with_retries(&npm_path);
                    return Ok(None);
                }
            };
            if let Err(err) = integrity.verify(&bytes) {
                warn!("SSRI verification failed for blob {hex}: {err}. Auto-purging.");
                let _ = remove_file_with_retries(&used_path);
                return Ok(None);
            }
            return Ok(Some(bytes));
        }

        let mut sorted_entries = integrity.entries.clone();
        sorted_entries.sort_by_key(|a| std::cmp::Reverse(a.algorithm));

        for entry in sorted_entries {
            let hex = HEXLOWER.encode(&entry.digest);
            let npm_path = self.npm_blob_path_for_algo(entry.algorithm, &hex);
            let (bytes, used_path) = match read_file_with_retries(&npm_path) {
                Ok(b) => (b, npm_path),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if is_path_not_found(&e) {
                        continue;
                    }
                    let legacy_path = Self::legacy_blob_path_from_npm(&npm_path, &hex);
                    match read_file_with_retries(&legacy_path) {
                        Ok(b) => (b, legacy_path),
                        Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(e2) => {
                            warn!(
                                "Unreadable or corrupt blob at {} ({e2}). Purging corrupted entry.",
                                legacy_path.display()
                            );
                            let _ = remove_file_with_retries(&legacy_path);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Unreadable or corrupt blob at {} ({e}). Purging corrupted entry.",
                        npm_path.display()
                    );
                    let _ = remove_file_with_retries(&npm_path);
                    continue;
                }
            };
            if let Err(err) = integrity.verify(&bytes) {
                warn!("SSRI verification failed for blob {hex}: {err}. Auto-purging.");
                let _ = remove_file_with_retries(&used_path);
            } else {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    /// Purge a specific key and its blob from the cache.
    pub fn purge_key(&self, key: &str) -> Result<(), CacheError> {
        let _key_lock = self.lock_key(key);
        if let Some(entry) = self.get_index_entry(key)? {
            self.purge_blob_files(&entry.sha512_hex);
        }
        self.purge_key_index_files(key);
        Ok(())
    }

    /// Helper to construct a registry-scoped cache key for packument metadata.
    pub fn packument_key(registry: &str, name: &str, accept: Option<&str>) -> String {
        packument_key(registry, name, accept)
    }

    /// Retrieve packument metadata scoped by registry URL and optional accept header.
    ///
    /// Preserves isolation so cached metadata from a test registry or private registry
    /// is not served for registry.npmjs.org or other registries.
    pub fn get_packument(
        &self,
        registry: &str,
        name: &str,
    ) -> Result<Option<(IndexEntry, Vec<u8>)>, CacheError> {
        self.get_packument_with_accept(registry, name, None)
    }

    /// Retrieve packument metadata scoped by registry URL and specific accept header.
    pub fn get_packument_with_accept(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
    ) -> Result<Option<(IndexEntry, Vec<u8>)>, CacheError> {
        let accept = accept.filter(|a| !a.is_empty());
        let key = Self::packument_key(registry, name, accept);
        if let Some(res) = self.get_exact(&key)? {
            return Ok(Some(res));
        }

        // Try trailing slash alternative on registry URL
        let reg_with_slash = format!("{}/", registry.trim_end_matches('/'));
        let alt_key = match accept {
            Some(a) => format!("pacote:packument:{reg_with_slash}:{name}:{a}"),
            None => format!("pacote:packument:{reg_with_slash}:{name}"),
        };
        if alt_key != key {
            if let Some(res) = self.get_exact(&alt_key)? {
                return Ok(Some(res));
            }
        }

        // If an accept header was provided, also fallback to the key without accept header
        if accept.is_some() {
            let key_no_accept = Self::packument_key(registry, name, None);
            if let Some(res) = self.get_exact(&key_no_accept)? {
                return Ok(Some(res));
            }
            let alt_no_accept = format!("pacote:packument:{reg_with_slash}:{name}");
            if alt_no_accept != key_no_accept {
                if let Some(res) = self.get_exact(&alt_no_accept)? {
                    return Ok(Some(res));
                }
            }
        } else {
            let key_abbrev =
                Self::packument_key(registry, name, Some("application/vnd.npm.install-v1+json"));
            if let Some(res) = self.get_exact(&key_abbrev)? {
                return Ok(Some(res));
            }
            let alt_abbrev = format!(
                "pacote:packument:{reg_with_slash}:{name}:application/vnd.npm.install-v1+json"
            );
            if alt_abbrev != key_abbrev {
                if let Some(res) = self.get_exact(&alt_abbrev)? {
                    return Ok(Some(res));
                }
            }
        }

        Ok(None)
    }

    /// Store packument metadata scoped by registry URL.
    pub fn put_packument(
        &self,
        registry: &str,
        name: &str,
        data: &[u8],
        metadata: Option<serde_json::Value>,
    ) -> Result<IndexEntry, CacheError> {
        self.put_packument_with_accept(registry, name, None, data, metadata)
    }

    /// Store packument metadata scoped by registry URL and optional accept header.
    pub fn put_packument_with_accept(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
        data: &[u8],
        metadata: Option<serde_json::Value>,
    ) -> Result<IndexEntry, CacheError> {
        let key = Self::packument_key(registry, name, accept);
        self.put(&key, data, metadata)
    }

    /// Store packument metadata scoped by registry URL and optional accept header with strict integrity verification.
    pub fn put_packument_with_integrity(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
        data: &[u8],
        expected_integrity: Option<&Integrity>,
        metadata: Option<&[u8]>,
    ) -> Result<IndexEntry, CacheError> {
        let key = Self::packument_key(registry, name, accept);
        self.put_with_integrity(&key, data, expected_integrity, metadata)
    }

    /// Retrieve the local filesystem path to a cached packument blob without reading it into memory.
    pub fn get_packument_blob_path(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
    ) -> Result<Option<(IndexEntry, PathBuf)>, CacheError> {
        let accept = accept.filter(|a| !a.is_empty());
        let key = Self::packument_key(registry, name, accept);
        if let Some(res) = self.get_blob_path(&key)? {
            return Ok(Some(res));
        }

        let reg_with_slash = format!("{}/", registry.trim_end_matches('/'));
        let alt_key = match accept {
            Some(a) => format!("pacote:packument:{reg_with_slash}:{name}:{a}"),
            None => format!("pacote:packument:{reg_with_slash}:{name}"),
        };
        if alt_key != key {
            if let Some(res) = self.get_blob_path(&alt_key)? {
                return Ok(Some(res));
            }
        }

        if accept.is_some() {
            let key_no_accept = Self::packument_key(registry, name, None);
            if let Some(res) = self.get_blob_path(&key_no_accept)? {
                return Ok(Some(res));
            }
            let alt_no_accept = format!("pacote:packument:{reg_with_slash}:{name}");
            if alt_no_accept != key_no_accept {
                if let Some(res) = self.get_blob_path(&alt_no_accept)? {
                    return Ok(Some(res));
                }
            }
        } else {
            let key_abbrev =
                Self::packument_key(registry, name, Some("application/vnd.npm.install-v1+json"));
            if let Some(res) = self.get_blob_path(&key_abbrev)? {
                return Ok(Some(res));
            }
            let alt_abbrev = format!(
                "pacote:packument:{reg_with_slash}:{name}:application/vnd.npm.install-v1+json"
            );
            if alt_abbrev != key_abbrev {
                if let Some(res) = self.get_blob_path(&alt_abbrev)? {
                    return Ok(Some(res));
                }
            }
        }

        Ok(None)
    }

    /// Purge a scoped packument entry from the cache.
    pub fn purge_packument(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
    ) -> Result<(), CacheError> {
        let key = Self::packument_key(registry, name, accept);
        self.purge_key(&key)
    }

    /// Clean up any orphaned temporary files in `<cache_root>/tmp` older than `max_age`.
    pub fn clean_stale_temp_files(&self, max_age: Duration) -> Result<usize, CacheError> {
        let mut count = 0;
        let pid = std::process::id();
        let in_flight_blob = format!("blob_{pid}_");
        let in_flight_idx = format!("index_{pid}_");

        if let Ok(entries) = fs::read_dir(self.tmp_dir()) {
            let now = SystemTime::now();
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                let should_remove = if let Ok(meta) = fs::metadata(&path) {
                    let mtime = meta.modified().unwrap_or(now);
                    let age = now.duration_since(mtime).unwrap_or(Duration::ZERO);

                    if max_age.is_zero() {
                        // If file is an active in-flight temporary file created by the current process recently (< 5000ms),
                        // preserve it so concurrent threads are not interrupted under thread starvation.
                        !((file_name.starts_with(&in_flight_blob)
                            || file_name.starts_with(&in_flight_idx))
                            && age < Duration::from_millis(5000))
                    } else {
                        age >= max_age
                    }
                } else {
                    false
                };

                if should_remove {
                    if path.is_dir() {
                        if remove_dir_all_with_retries(&path).is_ok() {
                            count += 1;
                        }
                    } else if remove_file_with_retries(&path).is_ok() {
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Purge all cache contents (content, index, tmp, locks) cleanly handling Windows file attributes.
    pub fn clean(&self) -> Result<(), CacheError> {
        let targets = [
            self.root.join("content-v2"),
            self.root.join("index-v5"),
            self.root.join("tmp"),
            self.root.join("locks"),
            self.root.join("_fingerprints"),
        ];

        for dir in &targets {
            if dir.exists() {
                remove_dir_all_with_retries(dir)?;
            }
        }

        // Also clean any stray files or directories directly in self.root
        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let _ = remove_file_with_retries(&path);
                } else if path.is_dir() {
                    let _ = remove_dir_all_with_retries(&path);
                }
            }
        }

        // Recreate essential cache directory layout
        clear_prefix_bitset(&self.blob_prefix_dirs);
        clear_prefix_bitset(&self.index_prefix_dirs);
        fs::create_dir_all(self.root.join("content-v2").join("sha512"))?;
        fs::create_dir_all(self.root.join("index-v5"))?;
        fs::create_dir_all(self.root.join("tmp"))?;
        fs::create_dir_all(self.root.join("locks"))?;
        fs::create_dir_all(self.root.join("_fingerprints"))?;

        Ok(())
    }

    fn expected_blob_digest(path: &Path) -> Option<[u8; 64]> {
        let file_name = path.file_name()?.to_str()?;
        if file_name.len() == 128 {
            return decode_sha512_hex_stack(file_name);
        }
        if file_name.len() == 124 {
            let p2 = path.parent()?.file_name()?.to_str()?;
            let p1 = path.parent()?.parent()?.file_name()?.to_str()?;
            if p1.len() == 2 && p2.len() == 2 {
                let mut combined = [0u8; 128];
                combined[0..2].copy_from_slice(p1.as_bytes());
                combined[2..4].copy_from_slice(p2.as_bytes());
                combined[4..128].copy_from_slice(file_name.as_bytes());
                let s = std::str::from_utf8(&combined).ok()?;
                return decode_sha512_hex_stack(s);
            }
        }
        None
    }

    fn verify_single_blob(path: &Path) -> (usize, usize, u64, Option<[u8; 64]>) {
        let Some(expected) = Self::expected_blob_digest(path) else {
            warn!(
                "Invalid blob file name '{}' in content-v2. Purging.",
                path.display()
            );
            let _ = remove_file_with_retries(path);
            return (0, 1, 0, None);
        };

        match read_file_with_retries(path) {
            Ok(bytes) => {
                let actual: [u8; 64] = Sha512::digest(&bytes).into();
                if actual == expected {
                    (1, 0, bytes.len() as u64, Some(actual))
                } else {
                    let mut exp_buf = [0u8; 128];
                    let mut act_buf = [0u8; 128];
                    warn!(
                        "Corrupted blob detected at {} (expected {}, got {}). Purging.",
                        path.display(),
                        encode_hex_lower(&expected, &mut exp_buf),
                        encode_hex_lower(&actual, &mut act_buf)
                    );
                    let _ = remove_file_with_retries(path);
                    (0, 1, 0, None)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, 0, 0, None),
            Err(e) => {
                warn!("Unreadable blob at {} ({}). Purging.", path.display(), e);
                let _ = remove_file_with_retries(path);
                (0, 1, 0, None)
            }
        }
    }

    fn verify_single_index(
        &self,
        path: &Path,
        valid_blobs: &HashSet<[u8; 64]>,
    ) -> (usize, usize, usize, Option<[u8; 64]>) {
        let bytes = match read_file_with_retries(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, 0, 0, None),
            Err(e) => {
                warn!(
                    "Unreadable index file at {} ({}). Purging.",
                    path.display(),
                    e
                );
                let _ = remove_file_with_retries(path);
                return (0, 1, 0, None);
            }
        };

        let Ok(content) = std::str::from_utf8(&bytes) else {
            warn!(
                "Non-UTF8 index file at {}. Purging.",
                path.display()
            );
            let _ = remove_file_with_retries(path);
            return (0, 1, 0, None);
        };

        let parsed_entry = parse_index_content(content, None, true);
        let entry = match parsed_entry {
            Some((e, _)) if !e.key.is_empty() && !e.sha512_hex.is_empty() => e,
            _ => {
                warn!(
                    "Corrupted or malformed index entry at {}. Purging.",
                    path.display()
                );
                let _ = remove_file_with_retries(path);
                return (0, 1, 0, None);
            }
        };

        if let Some(digest) = decode_sha512_hex_stack(&entry.sha512_hex) {
            if valid_blobs.contains(&digest) {
                return (1, 0, 0, None);
            }
            let npm_path = self.npm_blob_path_for_algo(Algorithm::Sha512, &entry.sha512_hex);
            let bytes_res = match read_file_with_retries(&npm_path) {
                Ok(b) => Ok(b),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && !is_path_not_found(&e) => {
                    let legacy_path =
                        Self::legacy_blob_path_from_npm(&npm_path, &entry.sha512_hex);
                    read_file_with_retries(&legacy_path)
                }
                Err(e) => Err(e),
            };
            if let Ok(blob_bytes) = bytes_res {
                let actual: [u8; 64] = Sha512::digest(&blob_bytes).into();
                if actual == digest {
                    return (1, 0, 0, Some(digest));
                }
            }
        }

        warn!(
            "Orphaned index entry at {} points to missing blob {}. Purging.",
            path.display(),
            entry.sha512_hex
        );
        let _ = remove_file_with_retries(path);
        (0, 0, 1, None)
    }

    /// Verify all `content-v2` SHA-512 blobs against their digests, purge corrupted blobs,
    /// scan `index-v5` entries, purge corrupted indices or orphaned indices pointing to missing blobs,
    /// clean stale temporary files in `tmp`, and return a detailed `VerifyReport`.
    pub fn verify(&self) -> Result<VerifyReport, CacheError> {
        let mut report = VerifyReport::default();
        let mut valid_blobs: HashSet<[u8; 64]> = HashSet::new();

        // 1. Verify content-v2 blobs against their digests and purge corrupted ones
        let content_dir = self.root.join("content-v2").join("sha512");
        if content_dir.exists() {
            let mut blob_paths = Vec::new();
            collect_files_recursive(&content_dir, &mut blob_paths);
            valid_blobs.reserve(blob_paths.len());

            if blob_paths.len() >= 4 {
                let workers = std::thread::available_parallelism()
                    .map(|n| n.get().clamp(2, 16))
                    .unwrap_or(8)
                    .min(blob_paths.len());
                let next_idx = std::sync::atomic::AtomicUsize::new(0);
                let results = Mutex::new(Vec::with_capacity(workers));
                rnpm_fs::run_parallel(workers, &|| {
                    let mut v = 0usize;
                    let mut c = 0usize;
                    let mut b = 0u64;
                    let mut digests = Vec::new();
                    loop {
                        let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                        if idx >= blob_paths.len() {
                            break;
                        }
                        let (vi, ci, bi, dg) = Self::verify_single_blob(&blob_paths[idx]);
                        v += vi;
                        c += ci;
                        b += bi;
                        if let Some(d) = dg {
                            digests.push(d);
                        }
                    }
                    results.lock().unwrap().push((v, c, b, digests));
                });
                for (v, c, b, digests) in results.into_inner().unwrap() {
                    report.verified_blobs += v;
                    report.corrupted_blobs += c;
                    report.total_blob_bytes += b;
                    valid_blobs.extend(digests);
                }
            } else {
                for path in &blob_paths {
                    let (v, c, b, dg) = Self::verify_single_blob(path);
                    report.verified_blobs += v;
                    report.corrupted_blobs += c;
                    report.total_blob_bytes += b;
                    if let Some(d) = dg {
                        valid_blobs.insert(d);
                    }
                }
            }
        }

        // 2. Scan index-v5 entries, purge corrupted indices or orphaned indices pointing to missing blobs
        let index_dir = self.root.join("index-v5");
        if index_dir.exists() {
            let mut index_paths = Vec::new();
            collect_files_recursive(&index_dir, &mut index_paths);

            if index_paths.len() >= 4 {
                let workers = std::thread::available_parallelism()
                    .map(|n| n.get().clamp(2, 16))
                    .unwrap_or(8)
                    .min(index_paths.len());
                let next_idx = std::sync::atomic::AtomicUsize::new(0);
                let results = Mutex::new(Vec::with_capacity(workers));
                rnpm_fs::run_parallel(workers, &|| {
                    let mut v = 0usize;
                    let mut c = 0usize;
                    let mut o = 0usize;
                    loop {
                        let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                        if idx >= index_paths.len() {
                            break;
                        }
                        let (vi, ci, oi, _) =
                            self.verify_single_index(&index_paths[idx], &valid_blobs);
                        v += vi;
                        c += ci;
                        o += oi;
                    }
                    results.lock().unwrap().push((v, c, o));
                });
                for (v, c, o) in results.into_inner().unwrap() {
                    report.verified_indices += v;
                    report.corrupted_indices += c;
                    report.orphaned_indices += o;
                }
            } else {
                for path in &index_paths {
                    let (v, c, o, new_digest) = self.verify_single_index(path, &valid_blobs);
                    report.verified_indices += v;
                    report.corrupted_indices += c;
                    report.orphaned_indices += o;
                    if let Some(d) = new_digest {
                        valid_blobs.insert(d);
                    }
                }
            }
        }

        // 3. Clean stale temporary files in tmp
        report.stale_temp_files_cleaned = self.clean_stale_temp_files(Duration::from_secs(0))?;

        Ok(report)
    }

    /// Audit and purge all corrupted entries in the cache (blobs and index entries).
    /// Returns the number of purged corrupted files.
    pub fn purge_corrupted(&self) -> Result<usize, CacheError> {
        let mut purged = 0;

        // 1. Audit content blobs
        let content_dir = self.root.join("content-v2").join("sha512");
        if content_dir.exists() {
            purged += self.audit_and_purge_dir(&content_dir, true)?;
        }

        // 2. Audit index entries
        let index_dir = self.root.join("index-v5");
        if index_dir.exists() {
            purged += self.audit_and_purge_dir(&index_dir, false)?;
        }

        Ok(purged)
    }

    fn audit_and_purge_dir(&self, dir: &Path, is_blob: bool) -> Result<usize, CacheError> {
        let mut count = 0;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                let path = entry.path();
                if ft.is_dir() {
                    count += self.audit_and_purge_dir(&path, is_blob)?;
                } else if ft.is_file() {
                    if is_blob {
                        if let Some(expected) = Self::expected_blob_digest(&path) {
                            if let Ok(bytes) = fs::read(&path) {
                                let actual: [u8; 64] = Sha512::digest(&bytes).into();
                                if actual != expected {
                                    let _ = remove_file_with_retries(&path);
                                    count += 1;
                                }
                            } else {
                                let _ = remove_file_with_retries(&path);
                                count += 1;
                            }
                        } else {
                            let _ = remove_file_with_retries(&path);
                            count += 1;
                        }
                    } else if let Ok(content) = fs::read_to_string(&path) {
                        if parse_index_content(&content, None, true).is_none() {
                            let _ = remove_file_with_retries(&path);
                            count += 1;
                        }
                    } else {
                        let _ = remove_file_with_retries(&path);
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Compute storage path for a project fast-path fingerprint keyed by its canonical directory.
    pub fn fingerprint_path(&self, project_dir: &Path) -> PathBuf {
        let canonical = project_dir
            .canonicalize()
            .unwrap_or_else(|_| project_dir.to_path_buf());
        let path_str = canonical.to_string_lossy();
        let normalized = path_str.strip_prefix(r"\\?\").unwrap_or(&path_str);
        #[cfg(windows)]
        let normalized_str = normalized.to_ascii_lowercase().replace('\\', "/");
        #[cfg(not(windows))]
        let normalized_str = normalized.to_string();

        let mut hex_buf = [0u8; 64];
        let key = sha256_hex_stack(normalized_str.as_bytes(), &mut hex_buf);
        self.root
            .join("_fingerprints")
            .join(format!("{key}.json"))
    }

    /// Retrieve the cached project fingerprint for a project directory.
    pub fn get_project_fingerprint(
        &self,
        project_dir: &Path,
    ) -> Result<Option<String>, CacheError> {
        let path = self.fingerprint_path(project_dir);
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
        #[derive(Deserialize)]
        struct FingerprintRecord {
            fingerprint: String,
        }
        if let Ok(record) = serde_json::from_slice::<FingerprintRecord>(&data) {
            Ok(Some(record.fingerprint))
        } else {
            Ok(None)
        }
    }

    /// Store a project fingerprint in cache keyed by canonical project directory.
    pub fn set_project_fingerprint(
        &self,
        project_dir: &Path,
        fingerprint: &str,
    ) -> Result<(), CacheError> {
        let target_path = self.fingerprint_path(project_dir);
        let canonical = project_dir
            .canonicalize()
            .unwrap_or_else(|_| project_dir.to_path_buf());
        let record = serde_json::json!({
            "project_path": canonical.to_string_lossy(),
            "fingerprint": fingerprint,
            "updated_at": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        });
        let serialized = serde_json::to_vec_pretty(&record)?;
        let temp_path = self.write_temp_file("fingerprint", &serialized)?;

        if let Err(err) = rename_with_retries(&temp_path, &target_path) {
            let _ = remove_file_with_retries(&temp_path);
            return Err(CacheError::Io(err));
        }
        Ok(())
    }
}

/// Helper to construct a registry-scoped cache key for packument metadata.
/// Scopes the key by registry URL and optional accept header.
pub fn packument_key(registry: &str, name: &str, accept: Option<&str>) -> String {
    let reg = registry.trim_end_matches('/');
    match accept {
        Some(a) if !a.is_empty() => format!("pacote:packument:{reg}:{name}:{a}"),
        _ => format!("pacote:packument:{reg}:{name}"),
    }
}

#[cfg(test)]
mod atomic_win_tests {
    use super::*;

    #[test]
    fn write_and_rename_atomic_creates_and_replaces_while_reading() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("tmp1.tmp");
        let target = dir.path().join("sub").join("target.txt");
        write_and_rename_atomic(&tmp, &target, b"hello").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"hello");
        assert!(!tmp.exists());

        // Hold reader open while replacing target atomically
        let _reader = fs::File::open(&target).unwrap();
        let tmp2 = dir.path().join("tmp2.tmp");
        write_and_rename_atomic(&tmp2, &target, b"world").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"world");
        assert!(!tmp2.exists());
    }

    #[test]
    fn multi_hash_sri_and_corrupt_index_blob_auto_repair() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();
        let payload = b"multi-hash integrity test payload";
        let s512 = Integrity::from_bytes(payload, Algorithm::Sha512);
        let s256 = Integrity::from_bytes(payload, Algorithm::Sha256);
        let combined: Integrity = format!("{s256} {s512}").parse().unwrap();

        let key = "https://registry.npmjs.org/multi-sri/-/m-1.0.0.tgz";
        let entry = cache.put_with_integrity(key, payload, Some(&combined), None).unwrap();
        let (got_entry, got_bytes) = cache.get(key).unwrap().unwrap();
        assert_eq!(got_entry.sha512_hex, entry.sha512_hex);
        assert_eq!(got_bytes, payload);

        // Corrupt the blob -> cache.get must auto-purge and return Ok(None)
        let blob_path = cache.blob_path(&entry.sha512_hex);
        fs::write(&blob_path, b"corrupted payload bytes").unwrap();
        assert!(cache.get(key).unwrap().is_none());
        assert!(!blob_path.exists());

        // Re-put and corrupt the index file -> cache.get must purge and return Ok(None)
        cache.put_with_integrity(key, payload, Some(&combined), None).unwrap();
        let idx_path = IndexEntry::path_for_key(cache.root(), key);
        fs::write(&idx_path, [0xffu8, 0xfe, 0x00]).unwrap();
        assert!(cache.get(key).unwrap().is_none());
        assert!(!idx_path.exists());
    }
}
