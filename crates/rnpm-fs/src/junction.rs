use std::fs;
use std::path::Path;
use crate::error::FsError;

/// Create a non-admin directory junction on Windows, or a symlink on Unix.
pub fn create_junction(link: &Path, target: &Path) -> Result<(), FsError> {
    let link_v = crate::path::to_verbatim_path(link);
    let target_v = crate::path::to_verbatim_path(target);

    #[cfg(windows)]
    {
        create_windows_junction(&link_v, &target_v)
    }

    #[cfg(not(windows))]
    {
        std::os::unix::fs::symlink(&target_v, &link_v).map_err(FsError::Io)
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
            detail: "Refusing to remove path: target exists but is not a junction or symlink".to_string(),
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

        let mut attempts = 0;
        let mut delay = std::time::Duration::from_millis(5);
        loop {
            attempts += 1;
            match fs::remove_dir(&path_v) {
                Ok(()) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    if attempts >= 15 || !crate::atomic::is_retryable_error(&err) {
                        return Err(FsError::JunctionError {
                            path: path.to_path_buf(),
                            detail: format!("Failed to remove junction after {attempts} attempts: {err}"),
                        });
                    }
                    let jitter_ms = (attempts as u64 * 3) % 7;
                    std::thread::sleep(delay + std::time::Duration::from_millis(jitter_ms));
                    delay = delay.saturating_mul(2).min(std::time::Duration::from_millis(250));
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

/// Recursively removes a directory tree while guaranteeing that junctions and symlinks
/// are NEVER recursively traversed (only their reparse points are unlinked).
/// Also handles Windows read-only attributes and transient file locks with backoff retries.
pub fn remove_dir_all_safe(path: &Path) -> Result<(), FsError> {
    let path_v = crate::path::to_verbatim_path(path);
    if !path_v.exists() && !is_reparse_point_or_symlink(&path_v)? {
        return Ok(());
    }

    // 1. If it's a junction or symlink, remove ONLY the reparse point/link, never target contents!
    if is_reparse_point_or_symlink(&path_v)? {
        return remove_junction(&path_v);
    }

    // 2. Query metadata to determine file vs directory
    let meta = match fs::symlink_metadata(&path_v) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(FsError::Io(e)),
    };

    if meta.is_dir() {
        // Ensure directory has write permissions so its child items can be deleted
        #[cfg(windows)]
        {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(&path_v, perms);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = meta.permissions();
            if perms.mode() & 0o200 == 0 {
                perms.set_mode(perms.mode() | 0o700);
                let _ = fs::set_permissions(path, perms);
            }
        }

        // Read directory entries
        match fs::read_dir(&path_v) {
            Ok(entries) => {
                for entry_res in entries {
                    let entry = match entry_res {
                        Ok(e) => e,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(err) => return Err(FsError::Io(err)),
                    };
                    remove_dir_all_safe(&entry.path())?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(FsError::Io(e)),
        }

        // Now remove the empty directory itself
        #[cfg(windows)]
        {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(&path_v, perms);
            }
        }

        let mut attempts = 0;
        let mut delay = std::time::Duration::from_millis(5);
        loop {
            attempts += 1;
            match fs::remove_dir(&path_v) {
                Ok(()) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    if attempts >= 15 || !crate::atomic::is_retryable_error(&err) {
                        return Err(FsError::Io(err));
                    }
                    let jitter_ms = (attempts as u64 * 3) % 7;
                    std::thread::sleep(delay + std::time::Duration::from_millis(jitter_ms));
                    delay = delay.saturating_mul(2).min(std::time::Duration::from_millis(250));
                }
            }
        }
    } else {
        // Regular file
        #[cfg(windows)]
        {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(&path_v, perms);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = meta.permissions();
            if perms.mode() & 0o200 == 0 {
                perms.set_mode(perms.mode() | 0o600);
                let _ = fs::set_permissions(&path_v, perms);
            }
        }

        let mut attempts = 0;
        let mut delay = std::time::Duration::from_millis(5);
        loop {
            attempts += 1;
            match fs::remove_file(&path_v) {
                Ok(()) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    if attempts >= 15 || !crate::atomic::is_retryable_error(&err) {
                        return Err(FsError::Io(err));
                    }
                    let jitter_ms = (attempts as u64 * 3) % 7;
                    std::thread::sleep(delay + std::time::Duration::from_millis(jitter_ms));
                    delay = delay.saturating_mul(2).min(std::time::Duration::from_millis(250));
                }
            }
        }
    }
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
    let target_canonical = target.canonicalize().map_err(FsError::Io)?;

    // Primary: direct Win32 FSCTL_SET_REPARSE_POINT (immune to shell escaping & space/metacharacter issues)
    match create_junction_win32(link, &target_canonical) {
        Ok(()) => return Ok(()),
        Err(e) => {
            tracing::debug!("Direct Win32 junction creation failed ({e:?}), attempting fallback");
        }
    }

    // Fallback: hardened cmd.exe mklink /J with safe quoting and escaping
    create_junction_cmd_fallback(link, &target_canonical)
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

    let sub_w: Vec<u16> = std::ffi::OsStr::new(&substitute_name).encode_wide().collect();
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
    let sub_byte_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(sub_w.as_ptr() as *const u8, sub_len_bytes as usize)
    };
    buffer[path_buf_start..path_buf_start + sub_len_bytes as usize].copy_from_slice(sub_byte_slice);

    let print_byte_start = path_buf_start + print_offset as usize;
    let print_byte_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(print_w.as_ptr() as *const u8, print_len_bytes as usize)
    };
    buffer[print_byte_start..print_byte_start + print_len_bytes as usize].copy_from_slice(print_byte_slice);

    let link_v = crate::path::to_verbatim_path(link);
    match fs::create_dir(&link_v) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if !is_reparse_point_or_symlink(&link_v)?
                && fs::read_dir(&link_v).map_err(FsError::Io)?.next().is_some() {
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
            detail: format!("DeviceIoControl(FSCTL_SET_REPARSE_POINT) failed with error code {err}"),
        });
    }

    Ok(())
}

#[cfg(windows)]
fn create_junction_cmd_fallback(link: &Path, target: &Path) -> Result<(), FsError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    let clean_link = crate::path::strip_verbatim_prefix(link).to_string_lossy().to_string();
    let clean_target = crate::path::strip_verbatim_prefix(target).to_string_lossy().to_string();

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
            detail: format!("mklink /J fallback failed: stdout='{}' stderr='{}'", stdout.trim(), stderr.trim()),
        });
    }

    Ok(())
}
