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
pub fn remove_junction(path: &Path) -> Result<(), FsError> {
    if !path.exists() && !is_reparse_point_or_symlink(path)? {
        return Ok(());
    }

    #[cfg(windows)]
    {
        // On Windows, remove_dir calls RemoveDirectoryW, which removes the reparse point
        // and does NOT touch any contents inside the target directory.
        fs::remove_dir(path).map_err(|err| FsError::JunctionError {
            path: path.to_path_buf(),
            detail: format!("Failed to remove junction: {err}"),
        })
    }

    #[cfg(not(windows))]
    {
        // On Unix, symlinks are removed with unlink (remove_file)
        fs::remove_file(path).map_err(FsError::Io)
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

    let link_str = link.to_string_lossy().replace('/', "\\");
    let target_str = target_canonical.to_string_lossy().replace('/', "\\");
    let clean_target = target_str.strip_prefix(r"\\?\").unwrap_or(&target_str);

    // cmd.exe /C mklink /J "<link>" "<target>"
    // mklink /J creates directory junctions without administrator privileges.
    let output = Command::new("cmd.exe")
        .args([
            "/C",
            "mklink",
            "/J",
            &link_str,
            clean_target,
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
