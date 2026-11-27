use crate::error::FsError;
use path_clean::clean;
use std::fs;
use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static JUNCTIONS_CREATED: AtomicU64 = AtomicU64::new(0);

/// Record that a junction was created.
pub fn record_junction_created() {
    JUNCTIONS_CREATED.fetch_add(1, Ordering::Relaxed);
}

/// Returns the total number of junctions created.
pub fn junctions_created() -> u64 {
    JUNCTIONS_CREATED.load(Ordering::Relaxed)
}

/// Resets the junctions created counter.
pub fn reset_junctions_created() {
    JUNCTIONS_CREATED.store(0, Ordering::Relaxed);
}

#[cfg(not(windows))]
fn normalize_abs_with_existing_ancestor(path: &Path) -> std::path::PathBuf {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut clean = std::path::PathBuf::new();
    for comp in abs.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                clean.pop();
            }
            other => clean.push(other.as_os_str()),
        }
    }
    let mut existing = clean.as_path();
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canon) = fs::canonicalize(existing) {
            let mut resolved = canon;
            for part in suffix.into_iter().rev() {
                resolved.push(part);
            }
            return resolved;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                suffix.push(name.to_os_string());
                existing = parent;
            }
            _ => return clean,
        }
    }
}

#[cfg(not(windows))]
fn compute_relative_symlink_target(from_dir: &Path, target: &Path) -> Option<std::path::PathBuf> {
    let from_abs = normalize_abs_with_existing_ancestor(from_dir);
    let to_abs = normalize_abs_with_existing_ancestor(target);
    let from_comps: Vec<_> = from_abs.components().collect();
    let to_comps: Vec<_> = to_abs.components().collect();
    let mut common = 0;
    while common < from_comps.len()
        && common < to_comps.len()
        && from_comps[common] == to_comps[common]
    {
        common += 1;
    }
    if common == 0 {
        return None;
    }
    let mut rel = std::path::PathBuf::new();
    for _ in common..from_comps.len() {
        rel.push("..");
    }
    for comp in &to_comps[common..] {
        rel.push(comp.as_os_str());
    }
    if rel.as_os_str().is_empty() {
        rel.push(".");
    }
    Some(rel)
}

/// Create a non-admin directory junction on Windows, or a relative POSIX symlink on Unix
/// (matching npm's `@npmcli/arborist` `symlink(relative(dirname(link), target), link, 'junction')`).
pub fn create_junction(link: &Path, target: &Path) -> Result<(), FsError> {
    let res = {
        #[cfg(windows)]
        {
            create_windows_junction(link, target)
        }

        #[cfg(not(windows))]
        {
            if let Some(parent) = link.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let link_v = crate::path::to_verbatim_path(link);
            let target_v = crate::path::to_verbatim_path(target);
            if let Ok(meta) = fs::symlink_metadata(&link_v) {
                if meta.file_type().is_symlink() {
                    let _ = remove_junction_with_meta(&link_v, link, &meta);
                }
            }
            let link_target = link
                .parent()
                .and_then(|parent| compute_relative_symlink_target(parent, target))
                .unwrap_or_else(|| target_v.clone());
            std::os::unix::fs::symlink(&link_target, &link_v).map_err(FsError::Io)
        }
    };
    if res.is_ok() {
        record_junction_created();
    }
    res
}

/// Create a directory link even when its target has not been created yet.
pub fn create_directory_link(link: &Path, target: &Path) -> Result<(), FsError> {
    #[cfg(windows)]
    if !target.exists() {
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        create_junction_win32(link, &std::path::absolute(target)?)?;
        record_junction_created();
        return Ok(());
    }
    create_junction(link, target)
}

/// Create a directory junction (if target is a directory) or a file symlink/copy (if target is a file).
pub fn create_link_or_copy(link: &Path, target: &Path) -> Result<(), FsError> {
    if let Some(parent) = link.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let link_v = crate::path::to_verbatim_path(link);
    // If link already exists, safely remove it first without clobbering target contents
    if is_reparse_point_or_symlink(&link_v).unwrap_or(false) {
        let _ = remove_junction(&link_v);
    } else if let Ok(meta) = fs::symlink_metadata(&link_v) {
        #[cfg(windows)]
        {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(&link_v, perms);
            }
        }
        if meta.is_dir() {
            let _ = remove_dir_all_safe(&link_v);
        } else {
            let _ = fs::remove_file(&link_v);
        }
    }

    #[cfg(windows)]
    {
        if target.is_dir() {
            create_junction(link, target)
        } else if target.is_file() {
            // Target is a file: try symlink_file first, fall back to copy
            if std::os::windows::fs::symlink_file(target, link).is_err() {
                fs::copy(target, link).map_err(FsError::Io)?;
            }
            Ok(())
        } else {
            // Target does not exist yet: try junction first, then symlink_file
            if create_junction(link, target).is_err() {
                std::os::windows::fs::symlink_file(target, link).map_err(FsError::Io)?;
            }
            Ok(())
        }
    }

    #[cfg(not(windows))]
    {
        std::os::unix::fs::symlink(target, link).map_err(FsError::Io)
    }
}

fn remove_junction_with_meta(
    path_v: &Path,
    orig_path: &Path,
    meta: &fs::Metadata,
) -> Result<(), FsError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = fs::set_permissions(path_v, perms);
        }
        let is_dir = (meta.file_attributes() & 0x10) != 0;

        let mut attempts = 0;
        let mut delay = std::time::Duration::from_millis(5);
        loop {
            attempts += 1;
            let res = if is_dir {
                fs::remove_dir(path_v)
            } else {
                fs::remove_file(path_v)
            };
            match res {
                Ok(()) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    if is_dir && err.raw_os_error() == Some(267) && fs::remove_file(path_v).is_ok()
                    {
                        return Ok(());
                    }
                    if attempts >= 15 || !crate::atomic::is_retryable_error(&err) {
                        return Err(FsError::JunctionError {
                            path: orig_path.to_path_buf(),
                            detail: format!(
                                "Failed to remove junction after {attempts} attempts: {err}"
                            ),
                        });
                    }
                    let jitter_ms = (attempts as u64 * 3) % 7;
                    std::thread::sleep(delay + std::time::Duration::from_millis(jitter_ms));
                    delay = delay
                        .saturating_mul(2)
                        .min(std::time::Duration::from_millis(250));
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (path_v, meta);
        fs::remove_file(orig_path).map_err(FsError::Io)
    }
}

/// Safely remove a junction or symlink.
/// Ensures deleting the junction removes ONLY the reparse point, never target contents!
/// Returns an error if the path exists but is not a junction or symlink.
pub fn remove_junction(path: &Path) -> Result<(), FsError> {
    let path_v = crate::path::to_verbatim_path(path);
    let meta = match fs::symlink_metadata(&path_v) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(FsError::Io(err)),
    };

    #[cfg(windows)]
    let is_reparse = {
        use std::os::windows::fs::MetadataExt;
        (meta.file_attributes() & 0x400) != 0
    };
    #[cfg(not(windows))]
    let is_reparse = meta.file_type().is_symlink();

    if !is_reparse {
        return Err(FsError::JunctionError {
            path: path.to_path_buf(),
            detail: "Refusing to remove path: target exists but is not a junction or symlink"
                .to_string(),
        });
    }

    remove_junction_with_meta(&path_v, path, &meta)
}

/// Helper to unlink a single regular file, clearing read-only attributes and retrying on transient Windows locks.
fn remove_file_safe(
    path: &Path,
    meta: Option<&fs::Metadata>,
    repair_parent: bool,
) -> Result<(), FsError> {
    #[cfg(not(unix))]
    let _ = repair_parent;
    #[cfg(windows)]
    {
        let is_ro = meta.map(|m| m.permissions().readonly()).unwrap_or_else(|| {
            fs::symlink_metadata(path)
                .map(|m| m.permissions().readonly())
                .unwrap_or(false)
        });
        if is_ro {
            if let Ok(m) = fs::symlink_metadata(path) {
                let mut perms = m.permissions();
                perms.set_readonly(false);
                let _ = fs::set_permissions(path, perms);
            }
        }
    }
    #[cfg(not(windows))]
    let _ = meta;

    let mut attempts = 0;
    #[cfg(unix)]
    let mut retried_writable_parent = false;
    let mut delay = std::time::Duration::from_millis(5);
    loop {
        attempts += 1;
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                #[cfg(unix)]
                if repair_parent
                    && !retried_writable_parent
                    && err.kind() == std::io::ErrorKind::PermissionDenied
                {
                    use std::os::unix::fs::PermissionsExt;
                    retried_writable_parent = true;
                    if let Some(parent) = path.parent() {
                        if let Ok(m) = fs::symlink_metadata(parent) {
                            let mut perms = m.permissions();
                            if perms.mode() & 0o200 == 0 {
                                perms.set_mode(perms.mode() | 0o700);
                                let _ = fs::set_permissions(parent, perms);
                            }
                            continue;
                        }
                    }
                }
                if attempts >= 15 || !crate::atomic::is_retryable_error(&err) {
                    return Err(FsError::Io(err));
                }
                let jitter_ms = (attempts as u64 * 3) % 7;
                std::thread::sleep(delay + std::time::Duration::from_millis(jitter_ms));
                delay = delay
                    .saturating_mul(2)
                    .min(std::time::Duration::from_millis(250));
            }
        }
    }
}

/// Helper to remove an empty directory on non-Windows targets, retrying on transient errors.
#[cfg(not(windows))]
fn remove_dir_safe(path: &Path, repair_parent: bool) -> Result<(), FsError> {
    #[cfg(not(unix))]
    let _ = repair_parent;
    let mut attempts = 0;
    #[cfg(unix)]
    let mut retried_writable_parent = false;
    let mut delay = std::time::Duration::from_millis(5);
    loop {
        attempts += 1;
        match fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                #[cfg(unix)]
                if repair_parent
                    && !retried_writable_parent
                    && err.kind() == std::io::ErrorKind::PermissionDenied
                {
                    use std::os::unix::fs::PermissionsExt;
                    retried_writable_parent = true;
                    if let Some(parent) = path.parent() {
                        if let Ok(m) = fs::symlink_metadata(parent) {
                            let mut perms = m.permissions();
                            if perms.mode() & 0o200 == 0 {
                                perms.set_mode(perms.mode() | 0o700);
                                let _ = fs::set_permissions(parent, perms);
                            }
                            continue;
                        }
                    }
                }
                if attempts >= 15 || !crate::atomic::is_retryable_error(&err) {
                    return Err(FsError::Io(err));
                }
                let jitter_ms = (attempts as u64 * 3) % 7;
                std::thread::sleep(delay + std::time::Duration::from_millis(jitter_ms));
                delay = delay
                    .saturating_mul(2)
                    .min(std::time::Duration::from_millis(250));
            }
        }
    }
}

#[cfg(windows)]
mod win_rm {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::{Arc, Condvar, Mutex};

    const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;
    const FIND_EX_INFO_BASIC: u32 = 1;
    const FIND_EX_INFO_STANDARD: u32 = 0;
    const FIND_EX_SEARCH_NAME_MATCH: u32 = 0;
    const FIND_FIRST_EX_LARGE_FETCH: u32 = 2;
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_NO_MORE_FILES: u32 = 18;
    const ERROR_NOT_SUPPORTED: u32 = 50;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_DIRECTORY: u32 = 267;

    #[repr(C)]
    #[allow(non_snake_case, clippy::upper_case_acronyms)]
    struct FILETIME {
        dwLowDateTime: u32,
        dwHighDateTime: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct WIN32_FIND_DATAW {
        dwFileAttributes: u32,
        ftCreationTime: FILETIME,
        ftLastAccessTime: FILETIME,
        ftLastWriteTime: FILETIME,
        nFileSizeHigh: u32,
        nFileSizeLow: u32,
        dwReserved0: u32,
        dwReserved1: u32,
        cFileName: [u16; 260],
        cAlternateFileName: [u16; 14],
    }

    extern "system" {
        fn FindFirstFileExW(
            lpFileName: *const u16,
            fInfoLevelId: u32,
            lpFindFileData: *mut WIN32_FIND_DATAW,
            fSearchOp: u32,
            lpSearchFilter: *mut std::ffi::c_void,
            dwAdditionalFlags: u32,
        ) -> *mut std::ffi::c_void;
        fn FindNextFileW(
            hFindFile: *mut std::ffi::c_void,
            lpFindFileData: *mut WIN32_FIND_DATAW,
        ) -> i32;
        fn FindClose(hFindFile: *mut std::ffi::c_void) -> i32;
        fn DeleteFileW(lpFileName: *const u16) -> i32;
        fn RemoveDirectoryW(lpPathName: *const u16) -> i32;
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
        fn GetLastError() -> u32;
    }

    struct FindGuard(*mut std::ffi::c_void);
    impl Drop for FindGuard {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                unsafe {
                    FindClose(self.0);
                }
            }
        }
    }

    #[inline]
    fn remove_file_wide(wide: &[u16], is_ro: bool) -> Result<(), FsError> {
        if is_ro {
            unsafe {
                SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            }
        }
        if unsafe { DeleteFileW(wide.as_ptr()) } != 0 {
            return Ok(());
        }
        let mut attempts = 0;
        let mut delay = std::time::Duration::from_millis(5);
        loop {
            let err_code = unsafe { GetLastError() };
            if err_code == ERROR_FILE_NOT_FOUND || err_code == ERROR_PATH_NOT_FOUND {
                return Ok(());
            }
            if err_code == ERROR_ACCESS_DENIED && attempts == 0 {
                unsafe {
                    SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
                }
            }
            let err = std::io::Error::from_raw_os_error(err_code as i32);
            attempts += 1;
            if attempts >= 15 || !crate::atomic::is_retryable_error(&err) {
                return Err(FsError::Io(err));
            }
            let jitter_ms = (attempts as u64 * 3) % 7;
            std::thread::sleep(delay + std::time::Duration::from_millis(jitter_ms));
            delay = delay
                .saturating_mul(2)
                .min(std::time::Duration::from_millis(250));
            if unsafe { DeleteFileW(wide.as_ptr()) } != 0 {
                return Ok(());
            }
        }
    }

    #[inline]
    fn remove_dir_wide(wide: &[u16], is_ro: bool) -> Result<(), FsError> {
        if is_ro {
            unsafe {
                SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            }
        }
        if unsafe { RemoveDirectoryW(wide.as_ptr()) } != 0 {
            return Ok(());
        }
        let mut attempts = 0;
        let mut delay = std::time::Duration::from_millis(5);
        loop {
            let err_code = unsafe { GetLastError() };
            if err_code == ERROR_FILE_NOT_FOUND || err_code == ERROR_PATH_NOT_FOUND {
                return Ok(());
            }
            if err_code == ERROR_ACCESS_DENIED && attempts == 0 {
                unsafe {
                    SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
                }
            }
            let err = std::io::Error::from_raw_os_error(err_code as i32);
            attempts += 1;
            if attempts >= 15 || !crate::atomic::is_retryable_error(&err) {
                return Err(FsError::Io(err));
            }
            let jitter_ms = (attempts as u64 * 3) % 7;
            std::thread::sleep(delay + std::time::Duration::from_millis(jitter_ms));
            delay = delay
                .saturating_mul(2)
                .min(std::time::Duration::from_millis(250));
            if unsafe { RemoveDirectoryW(wide.as_ptr()) } != 0 {
                return Ok(());
            }
        }
    }

    #[inline]
    fn remove_reparse_wide(wide: &[u16], is_dir: bool, is_ro: bool) -> Result<(), FsError> {
        if is_ro {
            unsafe {
                SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            }
        }
        if is_dir {
            if unsafe { RemoveDirectoryW(wide.as_ptr()) } != 0 {
                return Ok(());
            }
            let err_code = unsafe { GetLastError() };
            if err_code == ERROR_DIRECTORY && unsafe { DeleteFileW(wide.as_ptr()) } != 0 {
                return Ok(());
            }
            if err_code == ERROR_FILE_NOT_FOUND || err_code == ERROR_PATH_NOT_FOUND {
                return Ok(());
            }
            remove_dir_wide(wide, true)
        } else {
            remove_file_wide(wide, is_ro)
        }
    }

    struct ParentDir {
        wide_null: Vec<u16>,
        remaining: AtomicUsize,
        parent: Option<Arc<ParentDir>>,
    }

    struct DirItem {
        wide_no_null: Vec<u16>,
        is_ro: bool,
        parent: Option<Arc<ParentDir>>,
    }

    #[inline]
    fn cascade_remove_parents(mut curr_parent: Option<Arc<ParentDir>>) -> Result<(), FsError> {
        while let Some(p) = curr_parent {
            if p.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
                remove_dir_wide(&p.wide_null, false)?;
                curr_parent = p.parent.as_ref().map(Arc::clone);
            } else {
                break;
            }
        }
        Ok(())
    }

    fn scan_and_unlink_dir(
        mut dir: DirItem,
        pattern_buf: &mut Vec<u16>,
        child_buf: &mut Vec<u16>,
        subdirs_out: &mut Vec<DirItem>,
        single_chain: &mut Vec<Vec<u16>>,
        raw_subdirs: &mut Vec<(Vec<u16>, bool)>,
    ) -> Result<(), FsError> {
        single_chain.clear();
        let top_parent = dir.parent.take();

        loop {
            if dir.is_ro {
                dir.wide_no_null.push(0);
                unsafe {
                    SetFileAttributesW(dir.wide_no_null.as_ptr(), FILE_ATTRIBUTE_NORMAL);
                }
                dir.wide_no_null.pop();
            }

            let needs_sep = !dir.wide_no_null.ends_with(&[b'\\' as u16]);
            pattern_buf.clear();
            pattern_buf.extend_from_slice(&dir.wide_no_null);
            if needs_sep {
                pattern_buf.push(b'\\' as u16);
            }
            pattern_buf.push(b'*' as u16);
            pattern_buf.push(0);

            let mut find_data = std::mem::MaybeUninit::<WIN32_FIND_DATAW>::uninit();
            let mut handle = unsafe {
                FindFirstFileExW(
                    pattern_buf.as_ptr(),
                    FIND_EX_INFO_BASIC,
                    find_data.as_mut_ptr(),
                    FIND_EX_SEARCH_NAME_MATCH,
                    std::ptr::null_mut(),
                    FIND_FIRST_EX_LARGE_FETCH,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                let err = unsafe { GetLastError() };
                if err == ERROR_INVALID_PARAMETER || err == ERROR_NOT_SUPPORTED {
                    handle = unsafe {
                        FindFirstFileExW(
                            pattern_buf.as_ptr(),
                            FIND_EX_INFO_STANDARD,
                            find_data.as_mut_ptr(),
                            FIND_EX_SEARCH_NAME_MATCH,
                            std::ptr::null_mut(),
                            0,
                        )
                    };
                }
            }
            if handle == INVALID_HANDLE_VALUE {
                let err = unsafe { GetLastError() };
                if err == ERROR_ACCESS_DENIED {
                    dir.wide_no_null.push(0);
                    unsafe {
                        SetFileAttributesW(dir.wide_no_null.as_ptr(), FILE_ATTRIBUTE_NORMAL);
                    }
                    dir.wide_no_null.pop();
                    handle = unsafe {
                        FindFirstFileExW(
                            pattern_buf.as_ptr(),
                            FIND_EX_INFO_BASIC,
                            find_data.as_mut_ptr(),
                            FIND_EX_SEARCH_NAME_MATCH,
                            std::ptr::null_mut(),
                            FIND_FIRST_EX_LARGE_FETCH,
                        )
                    };
                }
            }
            if handle == INVALID_HANDLE_VALUE {
                let err = unsafe { GetLastError() };
                if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
                    while let Some(mut anc_wide) = single_chain.pop() {
                        anc_wide.push(0);
                        remove_dir_wide(&anc_wide, false)?;
                    }
                    return cascade_remove_parents(top_parent);
                }
                return Err(FsError::Io(std::io::Error::from_raw_os_error(err as i32)));
            }

            raw_subdirs.clear();
            {
                let _guard = FindGuard(handle);
                loop {
                    let fd_ptr = find_data.as_ptr();
                    let c = unsafe { &(*fd_ptr).cFileName };
                    let is_dot = (c[0] == b'.' as u16 && c[1] == 0)
                        || (c[0] == b'.' as u16 && c[1] == b'.' as u16 && c[2] == 0);
                    if !is_dot {
                        let name_len = c.iter().position(|&ch| ch == 0).unwrap_or(c.len());
                        child_buf.clear();
                        child_buf.extend_from_slice(&dir.wide_no_null);
                        if needs_sep {
                            child_buf.push(b'\\' as u16);
                        }
                        child_buf.extend_from_slice(&c[..name_len]);

                        let attrs = unsafe { (*fd_ptr).dwFileAttributes };
                        let is_ro = (attrs & FILE_ATTRIBUTE_READONLY) != 0;
                        let is_reparse = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                        let is_dir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;

                        if is_reparse {
                            // Reparse points / junctions / symlinks: NEVER push to subdirs!
                            child_buf.push(0);
                            remove_reparse_wide(child_buf, is_dir, is_ro)?;
                        } else if is_dir {
                            raw_subdirs.push((child_buf.clone(), is_ro));
                        } else {
                            child_buf.push(0);
                            remove_file_wide(child_buf, is_ro)?;
                        }
                    }

                    if unsafe { FindNextFileW(handle, find_data.as_mut_ptr()) } == 0 {
                        let err = unsafe { GetLastError() };
                        if err == ERROR_NO_MORE_FILES {
                            break;
                        }
                        return Err(FsError::Io(std::io::Error::from_raw_os_error(err as i32)));
                    }
                }
            }

            if raw_subdirs.is_empty() {
                dir.wide_no_null.push(0);
                remove_dir_wide(&dir.wide_no_null, false)?;
                while let Some(mut anc_wide) = single_chain.pop() {
                    anc_wide.push(0);
                    remove_dir_wide(&anc_wide, false)?;
                }
                return cascade_remove_parents(top_parent);
            }

            if raw_subdirs.len() == 1 {
                // Single-child directory: descend immediately on this worker without
                // Arc allocation or global queue synchronization.
                single_chain.push(dir.wide_no_null);
                let (sub_wide, is_ro) = raw_subdirs.pop().unwrap();
                dir = DirItem {
                    wide_no_null: sub_wide,
                    is_ro,
                    parent: None,
                };
                continue;
            }

            let mut curr_parent = top_parent;
            for mut anc_wide in single_chain.drain(..) {
                anc_wide.push(0);
                curr_parent = Some(Arc::new(ParentDir {
                    wide_null: anc_wide,
                    remaining: AtomicUsize::new(1),
                    parent: curr_parent,
                }));
            }
            dir.wide_no_null.push(0);
            let parent_node = Arc::new(ParentDir {
                wide_null: dir.wide_no_null,
                remaining: AtomicUsize::new(raw_subdirs.len()),
                parent: curr_parent,
            });
            for (sub_wide, is_ro) in raw_subdirs.drain(..) {
                subdirs_out.push(DirItem {
                    wide_no_null: sub_wide,
                    is_ro,
                    parent: Some(Arc::clone(&parent_node)),
                });
            }
            return Ok(());
        }
    }

    struct QueueState {
        pending: VecDeque<DirItem>,
        active: usize,
        waiters: usize,
        error: Option<FsError>,
    }

    pub(super) fn remove_dir_tree_windows(path_v: &Path, is_ro: bool) -> Result<(), FsError> {
        use std::os::windows::ffi::OsStrExt;
        let root_wide: Vec<u16> = path_v.as_os_str().encode_wide().collect();
        let mut stack = vec![DirItem {
            wide_no_null: root_wide,
            is_ro,
            parent: None,
        }];
        let mut pattern_buf = Vec::with_capacity(300);
        let mut child_buf = Vec::with_capacity(300);
        let mut local_subdirs = Vec::with_capacity(16);
        let mut single_chain = Vec::with_capacity(8);
        let mut raw_subdirs = Vec::with_capacity(16);

        // Traverse sequentially until queue fans out (>= 2 subdirs), avoiding thread
        // dispatch overhead on tiny trees while scaling cleanly for nested node_modules.
        while stack.len() == 1 {
            let dir = stack.pop().unwrap();
            local_subdirs.clear();
            scan_and_unlink_dir(
                dir,
                &mut pattern_buf,
                &mut child_buf,
                &mut local_subdirs,
                &mut single_chain,
                &mut raw_subdirs,
            )?;
            stack.append(&mut local_subdirs);
        }

        if !stack.is_empty() {
            struct ActiveGuard<'a> {
                state: &'a Mutex<QueueState>,
                cvar: &'a Condvar,
                armed: bool,
            }
            impl Drop for ActiveGuard<'_> {
                fn drop(&mut self) {
                    if self.armed {
                        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                        guard.active = guard.active.saturating_sub(1);
                        if guard.error.is_none() {
                            guard.error = Some(FsError::Io(std::io::Error::other(
                                "Directory removal worker panicked",
                            )));
                        }
                        self.cvar.notify_all();
                    }
                }
            }

            let num_threads = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .clamp(2, 16)
                .min(stack.len().max(2));
            let state = Mutex::new(QueueState {
                pending: stack.into_iter().collect(),
                active: 0,
                waiters: 0,
                error: None,
            });
            let has_waiters = AtomicBool::new(false);
            let cvar = Condvar::new();

            crate::pool::run_parallel(num_threads, &|| {
                let mut p_buf = Vec::with_capacity(300);
                let mut c_buf = Vec::with_capacity(300);
                let mut local_subs = Vec::with_capacity(16);
                let mut local_single = Vec::with_capacity(8);
                let mut local_raw_subs = Vec::with_capacity(16);
                let mut local_stack: Vec<DirItem> = Vec::with_capacity(16);
                let mut active_guard = ActiveGuard {
                    state: &state,
                    cvar: &cvar,
                    armed: false,
                };

                loop {
                    if !local_stack.is_empty() && has_waiters.load(Ordering::Relaxed) && local_stack.len() > 1 {
                        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                        if guard.error.is_some() {
                            guard.active = guard.active.saturating_sub(1);
                            active_guard.armed = false;
                            break;
                        }
                        while local_stack.len() > 1 {
                            if let Some(extra) = local_stack.pop() {
                                guard.pending.push_back(extra);
                            }
                        }
                        cvar.notify_all();
                    }

                    let dir = if let Some(d) = local_stack.pop() {
                        d
                    } else {
                        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                        if active_guard.armed {
                            guard.active = guard.active.saturating_sub(1);
                            active_guard.armed = false;
                        }
                        let popped = loop {
                            if guard.error.is_some() {
                                break None;
                            }
                            if let Some(d) = guard.pending.pop_back() {
                                guard.active += 1;
                                active_guard.armed = true;
                                break Some(d);
                            }
                            if guard.active == 0 {
                                cvar.notify_all();
                                break None;
                            }
                            guard.waiters += 1;
                            has_waiters.store(true, Ordering::Relaxed);
                            guard = cvar.wait(guard).unwrap_or_else(|e| e.into_inner());
                            guard.waiters = guard.waiters.saturating_sub(1);
                            has_waiters.store(guard.waiters > 0, Ordering::Relaxed);
                        };
                        match popped {
                            Some(d) => d,
                            None => break,
                        }
                    };

                    local_subs.clear();
                    if let Err(e) = scan_and_unlink_dir(
                        dir,
                        &mut p_buf,
                        &mut c_buf,
                        &mut local_subs,
                        &mut local_single,
                        &mut local_raw_subs,
                    ) {
                        local_stack.clear();
                        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                        guard.active = guard.active.saturating_sub(1);
                        active_guard.armed = false;
                        if guard.error.is_none() {
                            guard.error = Some(e);
                        }
                        cvar.notify_all();
                        break;
                    }

                    if !local_subs.is_empty() {
                        if local_subs.len() > 1 && has_waiters.load(Ordering::Relaxed) {
                            local_stack.push(local_subs.pop().unwrap());
                            let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                            for sub in local_subs.drain(..) {
                                guard.pending.push_back(sub);
                            }
                            cvar.notify_all();
                        } else {
                            local_stack.append(&mut local_subs);
                        }
                    }
                }
            });

            let st = state.into_inner().unwrap_or_else(|e| e.into_inner());
            if let Some(err) = st.error {
                return Err(err);
            }
        }

        Ok(())
    }
}

/// Recursively removes a directory tree while guaranteeing that junctions and symlinks
/// are NEVER recursively traversed (only their reparse points are unlinked).
/// Uses parallel directory traversal, immediate leaf unlinking, and bottom-up parallel dir removal.
/// Also handles Windows read-only attributes and transient file locks with backoff retries.
pub fn remove_dir_all_safe(path: &Path) -> Result<(), FsError> {
    let path_v = crate::path::to_verbatim_path(path);

    // 1. Single symlink_metadata call: determines existence, reparse point, and file vs dir
    let meta = match fs::symlink_metadata(&path_v) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(FsError::Io(e)),
    };

    #[cfg(windows)]
    let is_reparse = {
        use std::os::windows::fs::MetadataExt;
        (meta.file_attributes() & 0x400) != 0
    };
    #[cfg(not(windows))]
    let is_reparse = meta.file_type().is_symlink();

    // 2. If it's a junction or symlink, remove ONLY the reparse point/link, never target contents!
    if is_reparse {
        return remove_junction_with_meta(&path_v, path, &meta);
    }

    // 3. Regular file: unlink directly
    if !meta.is_dir() {
        return remove_file_safe(&path_v, Some(&meta), false);
    }

    #[cfg(windows)]
    {
        let is_ro = meta.permissions().readonly();
        win_rm::remove_dir_tree_windows(&path_v, is_ro)
    }

    #[cfg(not(windows))]
    {
        // 4. Directory: traverse iteratively using DirEntry::file_type (zero lstat on Linux/macOS),
        // unlinking files/symlinks in parallel and removing directories bottom-up by depth.
        let mut dir_stack = vec![(path_v, 0usize)];
        let mut dirs_collected: Vec<(PathBuf, usize)> = Vec::new();
        let mut unlinks: Vec<PathBuf> = Vec::new();

        while let Some((current_dir, depth)) = dir_stack.pop() {
            let entries = match fs::read_dir(&current_dir) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                #[cfg(unix)]
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(m) = fs::symlink_metadata(&current_dir) {
                        let mut perms = m.permissions();
                        if perms.mode() & 0o200 == 0 {
                            perms.set_mode(perms.mode() | 0o700);
                            let _ = fs::set_permissions(&current_dir, perms);
                        }
                    }
                    match fs::read_dir(&current_dir) {
                        Ok(e) => e,
                        Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(e2) => return Err(FsError::Io(e2)),
                    }
                }
                Err(e) => return Err(FsError::Io(e)),
            };
            for entry_res in entries {
                let entry = match entry_res {
                    Ok(e) => e,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => return Err(FsError::Io(err)),
                };
                let entry_path = entry.path();
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => return Err(FsError::Io(err)),
                };

                if ft.is_symlink() {
                    unlinks.push(entry_path);
                } else if ft.is_dir() {
                    dir_stack.push((entry_path, depth + 1));
                } else {
                    unlinks.push(entry_path);
                }
            }
            dirs_collected.push((current_dir, depth));
        }

        let total_unlinks = unlinks.len();
        if total_unlinks < 32 {
            for p in unlinks {
                remove_file_safe(&p, None, true)?;
            }
        } else {
            let concurrency = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .clamp(2, 16)
                .min(total_unlinks);
            let chunk_size = total_unlinks.div_ceil(concurrency);
            let first_error = std::sync::Mutex::new(None);

            std::thread::scope(|scope| {
                for chunk in unlinks.chunks(chunk_size) {
                    let err_ref = &first_error;
                    scope.spawn(move || {
                        for p in chunk {
                            if let Err(e) = remove_file_safe(p, None, true) {
                                let mut guard = err_ref.lock().unwrap();
                                if guard.is_none() {
                                    *guard = Some(e);
                                }
                                break;
                            }
                        }
                    });
                }
            });

            if let Some(err) = first_error.into_inner().unwrap() {
                return Err(err);
            }
        }

        let max_depth = dirs_collected.iter().map(|(_, d)| *d).max().unwrap_or(0);
        let mut by_depth: Vec<Vec<PathBuf>> = (0..=max_depth).map(|_| Vec::new()).collect();
        for (dir, depth) in dirs_collected {
            by_depth[depth].push(dir);
        }
        for (depth, level) in by_depth.into_iter().enumerate().rev() {
            let repair_parent = depth > 0;
            for dir in level {
                remove_dir_safe(&dir, repair_parent)?;
            }
        }

        Ok(())
    }
}

/// Check if a path is a junction or symlink.
pub fn is_junction(path: &Path) -> Result<bool, FsError> {
    let path_v = crate::path::to_verbatim_path(path);
    is_reparse_point_or_symlink(&path_v)
}

/// Fast check for whether a `DirEntry` is a symlink or (on Windows) a reparse point / NTFS junction.
///
/// On Windows, `FileType::is_symlink()` returns `false` for directory junctions, whereas
/// `DirEntry::metadata()` exposes the `FILE_ATTRIBUTE_REPARSE_POINT` bit directly from
/// `WIN32_FIND_DATAW` without an extra syscall.
pub fn is_dir_entry_reparse_or_symlink(
    entry: &fs::DirEntry,
    file_type: &fs::FileType,
) -> bool {
    if file_type.is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if let Ok(meta) = entry.metadata() {
            return (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        }
        is_junction(&entry.path()).unwrap_or(false)
    }

    #[cfg(not(windows))]
    {
        let _ = entry;
        false
    }
}

fn is_reparse_point_or_symlink(path: &Path) -> Result<bool, FsError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(FsError::Io(err)),
    };

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT = 0x400
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let attrs = meta.file_attributes();
        Ok((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    }

    #[cfg(not(windows))]
    {
        Ok(meta.file_type().is_symlink())
    }
}

#[cfg(windows)]
fn create_windows_junction(link: &Path, target: &Path) -> Result<(), FsError> {
    extern "system" {
        fn GetFileAttributesW(lpFileName: *const u16) -> u32;
    }
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;

    let res = crate::path::with_verbatim_wide(target, |target_wide| {
        let attrs = unsafe { GetFileAttributesW(target_wide.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            return Err(FsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("junction target does not exist: {}", target.display()),
            )));
        }
        create_junction_win32_wide(link, target_wide)
    });

    match res {
        Ok(()) => return Ok(()),
        Err(FsError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("junction target does not exist: {}", target.display()),
            )));
        }
        Err(e) => {
            tracing::debug!("Direct Win32 junction creation failed ({e:?}), attempting fallback");
        }
    }

    let target_abs = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir().map_err(FsError::Io)?.join(target)
    };
    create_junction_cmd_fallback(link, &target_abs)
}

#[cfg(windows)]
fn create_junction_win32(link: &Path, target: &Path) -> Result<(), FsError> {
    crate::path::with_verbatim_wide(target, |target_wide| {
        create_junction_win32_wide(link, target_wide)
    })
}

#[cfg(windows)]
fn create_junction_win32_wide(link: &Path, target_wide_null: &[u16]) -> Result<(), FsError> {
    extern "system" {
        fn CreateDirectoryW(
            lpPathName: *const u16,
            lpSecurityAttributes: *mut std::ffi::c_void,
        ) -> i32;

        fn RemoveDirectoryW(lpPathName: *const u16) -> i32;

        fn GetFileAttributesW(lpFileName: *const u16) -> u32;

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
        fn GetLastError() -> u32;
    }

    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_SHARE_DELETE: u32 = 4;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
    const FSCTL_SET_REPARSE_POINT: u32 = 0x000900A4;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ALREADY_EXISTS: u32 = 183;

    let tw = target_wide_null
        .strip_suffix(&[0])
        .unwrap_or(target_wide_null);
    let unc_prefix: [u16; 8] = [
        b'\\' as u16,
        b'\\' as u16,
        b'?' as u16,
        b'\\' as u16,
        b'U' as u16,
        b'N' as u16,
        b'C' as u16,
        b'\\' as u16,
    ];
    let verb_prefix: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    let nt_prefix: [u16; 4] = [b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16];

    let (is_unc, has_verb_prefix) = if tw.starts_with(&unc_prefix) {
        (true, true)
    } else if tw.starts_with(&verb_prefix) || tw.starts_with(&nt_prefix) {
        (false, true)
    } else {
        (false, false)
    };

    let sub_len_u16 = if has_verb_prefix { tw.len() } else { tw.len() + 4 };
    let print_len_u16 = if is_unc {
        2 + (tw.len() - 8)
    } else if has_verb_prefix {
        tw.len() - 4
    } else {
        tw.len()
    };

    let sub_len_bytes = (sub_len_u16 * 2) as u16;
    let print_len_bytes = (print_len_u16 * 2) as u16;
    let reparse_data_len = 8 + sub_len_bytes + 2 + print_len_bytes + 2;
    let total_buffer_len = 8 + reparse_data_len as usize;

    let mut stack_buf = [0u8; 1024];
    let mut heap_buf: Vec<u8> = Vec::new();
    let buffer: &mut [u8] = if total_buffer_len <= stack_buf.len() {
        &mut stack_buf[..total_buffer_len]
    } else {
        heap_buf.resize(total_buffer_len, 0);
        &mut heap_buf[..total_buffer_len]
    };

    // IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
    let tag = 0xA0000003u32;
    buffer[0..4].copy_from_slice(&tag.to_le_bytes());
    buffer[4..6].copy_from_slice(&reparse_data_len.to_le_bytes());
    buffer[6..8].copy_from_slice(&0u16.to_le_bytes());

    buffer[8..10].copy_from_slice(&0u16.to_le_bytes());
    buffer[10..12].copy_from_slice(&sub_len_bytes.to_le_bytes());
    let print_offset = sub_len_bytes + 2;
    buffer[12..14].copy_from_slice(&print_offset.to_le_bytes());
    buffer[14..16].copy_from_slice(&print_len_bytes.to_le_bytes());

    let path_buf_start = 16usize;
    if has_verb_prefix {
        let tw_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(tw.as_ptr() as *const u8, tw.len() * 2) };
        buffer[path_buf_start..path_buf_start + tw_bytes.len()].copy_from_slice(tw_bytes);
        // Flip `\\?\` -> `\??\` at UTF-16 index 1
        buffer[path_buf_start + 2..path_buf_start + 4].copy_from_slice(&(b'?' as u16).to_le_bytes());
    } else {
        let nt_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(nt_prefix.as_ptr() as *const u8, 8) };
        buffer[path_buf_start..path_buf_start + 8].copy_from_slice(nt_bytes);
        let tw_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(tw.as_ptr() as *const u8, tw.len() * 2) };
        buffer[path_buf_start + 8..path_buf_start + 8 + tw_bytes.len()].copy_from_slice(tw_bytes);
    }

    let print_byte_start = path_buf_start + print_offset as usize;
    if is_unc {
        let double_slash: [u16; 2] = [b'\\' as u16, b'\\' as u16];
        let ds_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(double_slash.as_ptr() as *const u8, 4) };
        buffer[print_byte_start..print_byte_start + 4].copy_from_slice(ds_bytes);
        let tail = &tw[8..];
        let tail_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(tail.as_ptr() as *const u8, tail.len() * 2) };
        buffer[print_byte_start + 4..print_byte_start + 4 + tail_bytes.len()]
            .copy_from_slice(tail_bytes);
    } else {
        let tail = if has_verb_prefix { &tw[4..] } else { tw };
        let tail_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(tail.as_ptr() as *const u8, tail.len() * 2) };
        buffer[print_byte_start..print_byte_start + tail_bytes.len()].copy_from_slice(tail_bytes);
    }

    crate::path::with_verbatim_wide(link, |link_wide| {
        let mut created = unsafe { CreateDirectoryW(link_wide.as_ptr(), std::ptr::null_mut()) };
        if created == 0 {
            let mut err = unsafe { GetLastError() };
            if err == ERROR_PATH_NOT_FOUND {
                if let Some(parent) = link.parent() {
                    let parent_v = crate::path::to_verbatim_path(parent);
                    let _ = fs::create_dir_all(&parent_v);
                }
                created = unsafe { CreateDirectoryW(link_wide.as_ptr(), std::ptr::null_mut()) };
                if created == 0 {
                    err = unsafe { GetLastError() };
                }
            }
            if created == 0 {
                if err == ERROR_ALREADY_EXISTS {
                    let attrs = unsafe { GetFileAttributesW(link_wide.as_ptr()) };
                    if attrs != INVALID_FILE_ATTRIBUTES
                        && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                    {
                        let _ = remove_junction(link);
                        created =
                            unsafe { CreateDirectoryW(link_wide.as_ptr(), std::ptr::null_mut()) };
                        if created == 0 {
                            let err2 = unsafe { GetLastError() };
                            if err2 != ERROR_ALREADY_EXISTS {
                                return Err(FsError::Io(std::io::Error::from_raw_os_error(
                                    err2 as i32,
                                )));
                            }
                        }
                    } else {
                        let link_v = crate::path::to_verbatim_path(link);
                        if fs::read_dir(&link_v).map_err(FsError::Io)?.next().is_some() {
                            return Err(FsError::JunctionError {
                                path: link.to_path_buf(),
                                detail: "Destination directory already exists and is not empty"
                                    .to_string(),
                            });
                        }
                    }
                } else {
                    return Err(FsError::Io(std::io::Error::from_raw_os_error(err as i32)));
                }
            }
        }

        let handle = unsafe {
            CreateFileW(
                link_wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            unsafe {
                RemoveDirectoryW(link_wide.as_ptr());
            }
            return Err(FsError::JunctionError {
                path: link.to_path_buf(),
                detail: format!("CreateFileW failed with error code {err}"),
            });
        }

        let mut bytes_returned = 0u32;
        let success = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_SET_REPARSE_POINT,
                buffer.as_ptr() as *const std::ffi::c_void,
                total_buffer_len as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        unsafe { CloseHandle(handle) };

        if success == 0 {
            let err = unsafe { GetLastError() };
            unsafe {
                RemoveDirectoryW(link_wide.as_ptr());
            }
            return Err(FsError::JunctionError {
                path: link.to_path_buf(),
                detail: format!(
                    "DeviceIoControl(FSCTL_SET_REPARSE_POINT) failed with error code {err}"
                ),
            });
        }

        Ok(())
    })
}

#[cfg(windows)]
fn create_junction_cmd_fallback(link: &Path, target: &Path) -> Result<(), FsError> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let clean_link = crate::path::strip_verbatim_prefix(link)
        .to_string_lossy()
        .to_string();
    let clean_target = crate::path::strip_verbatim_prefix(target)
        .to_string_lossy()
        .to_string();

    let escaped_link = clean_link.replace('%', "%%");
    let escaped_target = clean_target.replace('%', "%%");

    let cmd_line = format!(r#"mklink /J "{}" "{}""#, escaped_link, escaped_target);

    let output = Command::new("cmd.exe")
        .raw_arg(format!(r#"/S /C "{}""#, cmd_line))
        .output()
        .map_err(|err| FsError::JunctionError {
            path: link.to_path_buf(),
            detail: format!("Failed to execute mklink /J fallback: {err}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(FsError::JunctionError {
            path: link.to_path_buf(),
            detail: format!(
                "mklink /J fallback failed: stdout='{}' stderr='{}'",
                stdout.trim(),
                stderr.trim()
            ),
        });
    }

    Ok(())
}

/// Reads the target path of a junction or symlink.
pub fn read_junction_target(path: &Path) -> Result<std::path::PathBuf, FsError> {
    let path_v = crate::path::to_verbatim_path(path);
    let target = fs::read_link(&path_v).map_err(FsError::Io)?;
    Ok(crate::path::strip_verbatim_prefix(&target))
}

/// Checks whether an existing junction points to the expected target.
/// Returns false if `link` is not a junction or does not point to `expected_target`.
pub fn junction_points_to(link: &Path, expected_target: &Path) -> bool {
    if !is_junction(link).unwrap_or(false) {
        return false;
    }
    let raw_actual = match read_junction_target(link) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let actual = if raw_actual.is_relative() {
        link.parent()
            .map_or_else(|| raw_actual.clone(), |p| p.join(&raw_actual))
    } else {
        raw_actual
    };
    let clean_expected = crate::path::strip_verbatim_prefix(expected_target);
    let norm_actual = clean(&actual);
    let norm_expected = clean(&clean_expected);

    #[cfg(windows)]
    if norm_actual
        .as_os_str()
        .to_string_lossy()
        .replace('/', "\\")
        .eq_ignore_ascii_case(&norm_expected.as_os_str().to_string_lossy().replace('/', "\\"))
    {
        return true;
    }
    #[cfg(not(windows))]
    if norm_actual == norm_expected {
        return true;
    }

    if let (Ok(canon_actual), Ok(canon_exp)) =
        (actual.canonicalize(), clean_expected.canonicalize())
    {
        let clean_ca = crate::path::strip_verbatim_prefix(&canon_actual);
        let clean_ce = crate::path::strip_verbatim_prefix(&canon_exp);
        #[cfg(windows)]
        return clean_ca
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&clean_ce.as_os_str().to_string_lossy());
        #[cfg(not(windows))]
        return clean_ca == clean_ce;
    }

    false
}

#[cfg(test)]
mod directory_link_tests {
    #[test]
    fn dangling_link_becomes_usable_when_target_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        super::create_directory_link(&link, &target).unwrap();
        assert!(!target.exists());
        assert!(std::fs::symlink_metadata(&link).is_ok());
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("value"), "kept").unwrap();
        assert_eq!(std::fs::read_to_string(link.join("value")).unwrap(), "kept");
        super::remove_junction(&link).unwrap();
        assert_eq!(
            std::fs::read_to_string(target.join("value")).unwrap(),
            "kept"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_junction_creates_relative_symlink_matching_arborist() {
        let dir = tempfile::tempdir().unwrap();
        let ws_target = dir.path().join("packages").join("w");
        std::fs::create_dir_all(&ws_target).unwrap();
        let ws_link = dir.path().join("node_modules").join("w");
        super::create_junction(&ws_link, &ws_target).unwrap();
        assert_eq!(
            std::fs::read_link(&ws_link).unwrap(),
            std::path::PathBuf::from("../packages/w")
        );
        assert!(super::junction_points_to(&ws_link, &ws_target));

        let self_link = dir.path().join("node_modules").join("self");
        super::create_junction(&self_link, dir.path()).unwrap();
        assert_eq!(
            std::fs::read_link(&self_link).unwrap(),
            std::path::PathBuf::from("..")
        );
        assert!(super::junction_points_to(&self_link, dir.path()));
    }
}
