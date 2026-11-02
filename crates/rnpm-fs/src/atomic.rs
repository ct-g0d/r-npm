use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::error::FsError;
use crate::tarball::{extract_tar_gz, ExtractionSummary, TarLimits};

static TRASH_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a unique path for trash/staging in `parent` that does not exist on disk.
fn generate_unique_path(parent: &Path, prefix: &str) -> PathBuf {
    let pid = std::process::id();
    let counter = TRASH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    parent.join(format!("{prefix}-{pid}-{nanos}-{counter}"))
}

/// Extracts a tarball into a temporary staging directory on the same filesystem as `destination`,
/// then atomically replaces `destination` with exponential backoff retries for Windows file locking.
pub fn extract_and_replace<R: Read>(
    reader: R,
    destination: &Path,
    limits: Option<TarLimits>,
) -> Result<ExtractionSummary, FsError> {
    let parent = destination
        .parent()
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    // Create staging directory in the same parent directory (guarantees same filesystem)
    let staging_temp = tempfile::Builder::new()
        .prefix(".rnpm-staging-")
        .tempdir_in(parent)?;

    let staging_path = staging_temp.path();

    // Extract into staging directory.
    // If extraction fails or a tar-bomb limit is violated, staging_temp is dropped and cleaned up.
    let summary = extract_tar_gz(reader, staging_path, limits).map_err(|err| {
        // Explicitly clean up staging directory on error
        let _ = fs::remove_dir_all(staging_path);
        err
    })?;

    // Staging succeeded: replace destination with staging directory
    replace_dir_with_retries(staging_path, destination, 30)?;

    // Extraction and atomic rename succeeded; disable tempdir auto-deletion
    std::mem::forget(staging_temp);

    Ok(summary)
}

/// Replaces `destination` with `staging` using atomic directory rename with exponential backoff.
/// Handles Windows EBUSY / EPERM / AccessDenied retries.
pub fn replace_dir_with_retries(
    staging: &Path,
    destination: &Path,
    max_retries: usize,
) -> Result<(), FsError> {
    let parent = destination
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let mut attempt = 0;
    let mut delay = Duration::from_millis(10);
    let effective_retries = max_retries.max(1);

    loop {
        attempt += 1;

        let result = try_replace_dir(staging, destination, parent);
        match result {
            Ok(()) => return Ok(()),
            Err(err) => {
                if attempt >= effective_retries || !is_retryable_error(&err) {
                    return Err(FsError::AtomicReplacementFailed {
                        path: destination.to_path_buf(),
                        retries: attempt,
                        source: err,
                    });
                }
                let jitter_ms = (attempt as u64 * 13 + 7) % 29;
                sleep(delay + Duration::from_millis(jitter_ms));
                delay = delay.saturating_mul(2).min(Duration::from_millis(500));
            }
        }
    }
}

fn try_replace_dir(staging: &Path, destination: &Path, parent: &Path) -> std::io::Result<()> {
    let dest_is_reparse = crate::junction::is_junction(destination).unwrap_or(false);
    if !destination.exists() && !dest_is_reparse {
        // Fast-path: Direct atomic rename when destination does not exist
        return fs::rename(staging, destination);
    }

    // Opportunistically cleanup any abandoned .rnpm-trash directories in parent
    cleanup_stale_trash(parent);

    // If destination already exists:
    // Move existing destination to a unique trash path (that does NOT yet exist) on the same filesystem
    let trash_path = generate_unique_path(parent, ".rnpm-trash");

    #[cfg(windows)]
    if let Ok(meta) = fs::symlink_metadata(destination) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = fs::set_permissions(destination, perms);
        }
    }

    // Rename destination -> trash_path
    match fs::rename(destination, &trash_path) {
        Ok(()) => {
            // Rename staging -> destination
            if let Err(rename_err) = fs::rename(staging, destination) {
                // Attempt rollback if staging -> destination failed
                let _ = fs::rename(&trash_path, destination);
                return Err(rename_err);
            }

            // Successfully replaced; safely cleanup trash using non-recursive junction pruning
            let _ = crate::junction::remove_dir_all_safe(&trash_path);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Race condition: another concurrent thread just renamed or removed destination!
            // Directly rename staging -> destination
            fs::rename(staging, destination)
        }
        Err(e) => Err(e),
    }
}

/// Opportunistic cleanup of any leftover .rnpm-trash-* directories in parent.
fn cleanup_stale_trash(parent: &Path) {
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if name_str.starts_with(".rnpm-trash-") {
                let _ = crate::junction::remove_dir_all_safe(&entry.path());
            }
        }
    }
}

pub(crate) fn is_retryable_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::PermissionDenied
        | ErrorKind::WouldBlock
        | ErrorKind::Interrupted
        | ErrorKind::ResourceBusy
        | ErrorKind::NotFound
        | ErrorKind::AlreadyExists => true,
        _ => {
            // Check raw OS error codes for Windows:
            // ERROR_FILE_NOT_FOUND (2), ERROR_ACCESS_DENIED (5), ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION (33),
            // ERROR_DIR_NOT_EMPTY (145), ERROR_FILE_CHECKED_OUT (149),
            // ERROR_BUSY (170), ERROR_ALREADY_EXISTS (183), ERROR_USER_MAPPED_FILE (1224)
            #[cfg(windows)]
            if let Some(code) = err.raw_os_error() {
                return code == 2
                    || code == 5
                    || code == 32
                    || code == 33
                    || code == 145
                    || code == 149
                    || code == 170
                    || code == 183
                    || code == 1224;
            }
            #[cfg(windows)]
            {
                let kind_debug = format!("{:?}", err.kind());
                if kind_debug == "DirectoryNotEmpty" {
                    return true;
                }
            }
            false
        }
    }
}
