use std::fs;
use std::path::Path;
use crate::error::FsError;

/// Create a non-admin directory junction on Windows, or a symlink on Unix.
pub fn create_junction(link: &Path, target: &Path) -> Result<(), FsError> {
    #[cfg(windows)]
    {
        create_windows_junction(link, target)
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
    if !path.exists() && !is_reparse_point_or_symlink(path)? {
        return Ok(());
    }

    if !is_reparse_point_or_symlink(path)? {
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
        if let Ok(meta) = fs::symlink_metadata(path) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(path, perms);
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
    if !path.exists() && !is_reparse_point_or_symlink(path)? {
        return Ok(());
    }

    // 1. If it's a junction or symlink, remove ONLY the reparse point/link, never target contents!
    if is_reparse_point_or_symlink(path)? {
        return remove_junction(path);
    }

    // 2. Query metadata to determine file vs directory
    let meta = match fs::symlink_metadata(path) {
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
                let _ = fs::set_permissions(path, perms);
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
        match fs::read_dir(path) {
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
                let _ = fs::set_permissions(path, perms);
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
                let _ = fs::set_permissions(path, perms);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = meta.permissions();
            if perms.mode() & 0o200 == 0 {
                perms.set_mode(perms.mode() | 0o600);
                let _ = fs::set_permissions(path, perms);
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
                    delay = delay.saturating_mul(2).min(std::time::Duration::from_millis(250));
                }
            }
        }
    }
}

/// Check if a path is a junction or symlink.
pub fn is_junction(path: &Path) -> Result<bool, FsError> {
    is_reparse_point_or_symlink(path)
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
    use std::process::Command;

    // Ensure parent directory of link exists
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }

    // Target must exist for a junction
    let target_canonical = target.canonicalize().map_err(FsError::Io)?;
    let target_str = target_canonical.to_string_lossy().replace('/', "\\");
    let clean_target = if let Some(stripped) = target_str.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", stripped)
    } else if let Some(stripped) = target_str.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        target_str.to_string()
    };

    let link_str = link.to_string_lossy().replace('/', "\\");
    let clean_link = if let Some(stripped) = link_str.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", stripped)
    } else if let Some(stripped) = link_str.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        link_str.to_string()
    };

    // cmd.exe /C mklink /J "<link>" "<target>"
    // mklink /J creates directory junctions without administrator privileges.
    let output = Command::new("cmd.exe")
        .args([
            "/C",
            "mklink",
            "/J",
            &clean_link,
            &clean_target,
        ])
        .output()
        .map_err(|err| FsError::JunctionError {
            path: link.to_path_buf(),
            detail: format!("Failed to execute mklink /J: {err}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(FsError::JunctionError {
            path: link.to_path_buf(),
            detail: format!("mklink /J failed: stdout='{}' stderr='{}'", stdout.trim(), stderr.trim()),
        });
    }

    Ok(())
}
