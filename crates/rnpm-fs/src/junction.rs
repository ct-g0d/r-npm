use crate::error::FsError;
use path_clean::clean;
use std::fs;
use std::path::{Path, PathBuf};
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
    if let Some(parent) = link.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let link_v = crate::path::to_verbatim_path(link);
    let target_v = crate::path::to_verbatim_path(target);

    // If link already exists as a junction or symlink, safely remove the reparse point first
    // so replacing a junction/symlink succeeds without clobbering target contents!
    if is_reparse_point_or_symlink(&link_v).unwrap_or(false) {
        let _ = remove_junction(&link_v);
    }

    let res = {
        #[cfg(windows)]
        {
            create_windows_junction(&link_v, &target_v)
        }

        #[cfg(not(windows))]
        {
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

/// Safely remove a junction or symlink.
/// Ensures deleting the junction removes ONLY the reparse point, never target contents!
/// Returns an error if the path exists but is not a junction or symlink.
pub fn remove_junction(path: &Path) -> Result<(), FsError> {
    let path_v = crate::path::to_verbatim_path(path);
    if !path_v.exists() && !is_reparse_point_or_symlink(&path_v)? {
        return Ok(());
    }

    if !is_reparse_point_or_symlink(&path_v)? {
        return Err(FsError::JunctionError {
            path: path.to_path_buf(),
            detail: "Refusing to remove path: target exists but is not a junction or symlink"
                .to_string(),
        });
    }

    #[cfg(windows)]
    {
        // On Windows, remove_dir calls RemoveDirectoryW, which removes the reparse point
        // and does NOT touch any contents inside the target directory.
        // Clear readonly attribute if set before attempting removal
        if let Ok(meta) = fs::symlink_metadata(&path_v) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(&path_v, perms);
            }
        }

        let is_dir = fs::symlink_metadata(&path_v)
            .map(|m| {
                use std::os::windows::fs::MetadataExt;
                m.file_attributes() & 0x10 != 0
            })
            .unwrap_or(true);

        let mut attempts = 0;
        let mut delay = std::time::Duration::from_millis(5);
        loop {
            attempts += 1;
            let res = if is_dir {
                fs::remove_dir(&path_v)
            } else {
                fs::remove_file(&path_v)
            };
            match res {
                Ok(()) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    // If remove_dir failed because it's a file symlink, try remove_file
                    if is_dir && err.raw_os_error() == Some(267) && fs::remove_file(&path_v).is_ok() {
                        return Ok(());
                    }
                    if attempts >= 15 || !crate::atomic::is_retryable_error(&err) {
                        return Err(FsError::JunctionError {
                            path: path.to_path_buf(),
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
        // On Unix, symlinks are removed with unlink (remove_file)
        fs::remove_file(path).map_err(FsError::Io)
    }
}

/// Helper to unlink a single regular file, clearing read-only attributes and retrying on transient Windows locks.
fn remove_file_safe(path: &Path, meta: Option<&fs::Metadata>) -> Result<(), FsError> {
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let needs_chmod = meta
            .map(|m| m.permissions().mode() & 0o200 == 0)
            .unwrap_or_else(|| {
                fs::symlink_metadata(path)
                    .map(|m| m.permissions().mode() & 0o200 == 0)
                    .unwrap_or(false)
            });
        if needs_chmod {
            if let Ok(m) = fs::symlink_metadata(path) {
                let mut perms = m.permissions();
                perms.set_mode(perms.mode() | 0o600);
                let _ = fs::set_permissions(path, perms);
            }
        }
    }

    let mut attempts = 0;
    let mut delay = std::time::Duration::from_millis(5);
    loop {
        attempts += 1;
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
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

/// Helper to remove an empty directory, clearing read-only attributes on Windows and retrying on transient locks.
fn remove_dir_safe(path: &Path) -> Result<(), FsError> {
    #[cfg(windows)]
    {
        if let Ok(meta) = fs::symlink_metadata(path) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(path, perms);
            }
        }
    }

    let mut attempts = 0;
    let mut delay = std::time::Duration::from_millis(5);
    loop {
        attempts += 1;
        match fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
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

enum UnlinkKind {
    File,
    ReparsePoint,
}

struct UnlinkEntry {
    path: PathBuf,
    kind: UnlinkKind,
}

/// Recursively removes a directory tree while guaranteeing that junctions and symlinks
/// are NEVER recursively traversed (only their reparse points are unlinked).
/// Uses parallel file unlinking across worker threads for large trees.
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
        return remove_junction(&path_v);
    }

    // 3. Regular file: unlink directly
    if !meta.is_dir() {
        return remove_file_safe(&path_v, Some(&meta));
    }

    // 4. Directory: traverse iteratively, collecting files/links to unlink and directories to remove in post-order
    let mut dir_stack = vec![path_v];
    let mut dirs_collected = Vec::new();
    let mut unlinks = Vec::new();

    while let Some(current_dir) = dir_stack.pop() {
        // Ensure directory has write permissions so its child items can be read/deleted
        #[cfg(windows)]
        {
            if let Ok(m) = fs::symlink_metadata(&current_dir) {
                let mut perms = m.permissions();
                if perms.readonly() {
                    perms.set_readonly(false);
                    let _ = fs::set_permissions(&current_dir, perms);
                }
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(m) = fs::symlink_metadata(&current_dir) {
                let mut perms = m.permissions();
                if perms.mode() & 0o200 == 0 {
                    perms.set_mode(perms.mode() | 0o700);
                    let _ = fs::set_permissions(&current_dir, perms);
                }
            }
        }

        match fs::read_dir(&current_dir) {
            Ok(entries) => {
                for entry_res in entries {
                    let entry = match entry_res {
                        Ok(e) => e,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(err) => return Err(FsError::Io(err)),
                    };
                    let entry_path = entry.path();
                    let entry_meta = match fs::symlink_metadata(&entry_path) {
                        Ok(m) => m,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(err) => return Err(FsError::Io(err)),
                    };

                    #[cfg(windows)]
                    let entry_is_reparse = {
                        use std::os::windows::fs::MetadataExt;
                        (entry_meta.file_attributes() & 0x400) != 0
                    };
                    #[cfg(not(windows))]
                    let entry_is_reparse = entry_meta.file_type().is_symlink();

                    if entry_is_reparse {
                        // Reparse points / symlinks: add to unlinks, NEVER push to dir_stack!
                        unlinks.push(UnlinkEntry {
                            path: entry_path,
                            kind: UnlinkKind::ReparsePoint,
                        });
                    } else if entry_meta.is_dir() {
                        dir_stack.push(entry_path);
                    } else {
                        unlinks.push(UnlinkEntry {
                            path: entry_path,
                            kind: UnlinkKind::File,
                        });
                    }
                }
                dirs_collected.push(current_dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(FsError::Io(e)),
        }
    }

    // 5. Parallel file/reparse-point unlinking
    let total_unlinks = unlinks.len();
    if total_unlinks < 32 {
        for item in unlinks {
            match item.kind {
                UnlinkKind::ReparsePoint => remove_junction(&item.path)?,
                UnlinkKind::File => remove_file_safe(&item.path, None)?,
            }
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
                    for item in chunk {
                        let res = match item.kind {
                            UnlinkKind::ReparsePoint => remove_junction(&item.path),
                            UnlinkKind::File => remove_file_safe(&item.path, None),
                        };
                        if let Err(e) = res {
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

    // 6. Remove empty directories bottom-up: sort descending by depth (component count)
    // so leaf directories are strictly removed before their parents!
    dirs_collected.sort_by_key(|a| std::cmp::Reverse(a.components().count()));

    for dir in dirs_collected {
        remove_dir_safe(&dir)?;
    }

    Ok(())
}

/// Check if a path is a junction or symlink.
pub fn is_junction(path: &Path) -> Result<bool, FsError> {
    let path_v = crate::path::to_verbatim_path(path);
    is_reparse_point_or_symlink(&path_v)
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
    // Ensure parent directory of link exists
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }

    // Target must exist for a junction
    if !target.exists() {
        return Err(FsError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("junction target does not exist: {}", target.display()),
        )));
    }

    let target_abs = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir().map_err(FsError::Io)?.join(target)
    };

    // Primary: direct Win32 FSCTL_SET_REPARSE_POINT (immune to shell escaping & space/metacharacter issues)
    match create_junction_win32(link, &target_abs) {
        Ok(()) => return Ok(()),
        Err(e) => {
            tracing::debug!("Direct Win32 junction creation failed ({e:?}), attempting fallback");
        }
    }

    // Fallback: hardened cmd.exe mklink /J with safe quoting and escaping
    create_junction_cmd_fallback(link, &target_abs)
}

#[cfg(windows)]
fn create_junction_win32(link: &Path, target: &Path) -> Result<(), FsError> {
    use std::os::windows::ffi::OsStrExt;

    let clean_target = crate::path::strip_verbatim_prefix(target);
    let clean_str = clean_target.to_string_lossy();

    let substitute_name = if clean_str.starts_with(r"\\") {
        format!(r"\??\UNC\{}", &clean_str[2..])
    } else {
        format!(r"\??\{}", clean_str)
    };
    let print_name = clean_str.to_string();

    let sub_w: Vec<u16> = std::ffi::OsStr::new(&substitute_name)
        .encode_wide()
        .collect();
    let print_w: Vec<u16> = std::ffi::OsStr::new(&print_name).encode_wide().collect();

    let sub_len_bytes = (sub_w.len() * 2) as u16;
    let print_len_bytes = (print_w.len() * 2) as u16;

    let reparse_data_len = 8 + sub_len_bytes + 2 + print_len_bytes + 2;
    let total_buffer_len = 8 + reparse_data_len as usize;

    let mut buffer = vec![0u8; total_buffer_len];

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

    let path_buf_start = 16;
    let sub_byte_slice: &[u8] =
        unsafe { std::slice::from_raw_parts(sub_w.as_ptr() as *const u8, sub_len_bytes as usize) };
    buffer[path_buf_start..path_buf_start + sub_len_bytes as usize].copy_from_slice(sub_byte_slice);

    let print_byte_start = path_buf_start + print_offset as usize;
    let print_byte_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(print_w.as_ptr() as *const u8, print_len_bytes as usize)
    };
    buffer[print_byte_start..print_byte_start + print_len_bytes as usize]
        .copy_from_slice(print_byte_slice);

    let link_v = crate::path::to_verbatim_path(link);
    match fs::create_dir(&link_v) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if !is_reparse_point_or_symlink(&link_v)?
                && fs::read_dir(&link_v).map_err(FsError::Io)?.next().is_some()
            {
                return Err(FsError::JunctionError {
                    path: link.to_path_buf(),
                    detail: "Destination directory already exists and is not empty".to_string(),
                });
            }
        }
        Err(e) => return Err(FsError::Io(e)),
    }

    let link_wide: Vec<u16> = link_v.as_os_str().encode_wide().chain(Some(0)).collect();

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
        let _ = fs::remove_dir(&link_v);
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
            buffer.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    unsafe { CloseHandle(handle) };

    if success == 0 {
        let err = unsafe { GetLastError() };
        let _ = fs::remove_dir(&link_v);
        return Err(FsError::JunctionError {
            path: link.to_path_buf(),
            detail: format!(
                "DeviceIoControl(FSCTL_SET_REPARSE_POINT) failed with error code {err}"
            ),
        });
    }

    Ok(())
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
