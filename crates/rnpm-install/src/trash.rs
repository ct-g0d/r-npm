//! Fast background trash deletion engine.
//!
//! When removing package directories or wiping `node_modules` in `ci`:
//! - Atomically renames the directory to `node_modules/.rnpm-trash-<uuid>`
//!   (or `.rnpm-trash-<uuid>` in parent directory). This is a single, instantaneous
//!   directory metadata move on NTFS/Windows.
//! - Spawns a background thread to asynchronously remove the directory off the
//!   critical path (~0ms critical path latency).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static TRASH_COUNTER: AtomicU64 = AtomicU64::new(1);
static ACTIVE_HANDLES: Mutex<Vec<std::thread::JoinHandle<()>>> = Mutex::new(Vec::new());

/// Generates a unique UUID-style identifier for trash directories.
pub fn generate_trash_id() -> String {
    let count = TRASH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let part1 = pid;
    let part2 = ((nanos >> 32) & 0xffff) as u16;
    let part3 = 0x4000 | ((count & 0x0fff) as u16); // UUID v4-ish version bits
    let part4 = 0x8000 | (((nanos >> 16) & 0x3fff) as u16); // UUID variant bits
    let part5 = (nanos & 0xffffffffffff) as u64;

    format!("{part1:08x}-{part2:04x}-{part3:04x}-{part4:04x}-{part5:012x}")
}

/// A handle to an active background trash deletion.
pub struct TrashHandle {
    pub trash_path: PathBuf,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl TrashHandle {
    /// Wait for the background deletion thread to finish.
    pub fn wait(&mut self) -> std::thread::Result<()> {
        if let Some(handle) = self.thread_handle.take() {
            handle.join()
        } else {
            Ok(())
        }
    }

    /// Check if background thread has finished.
    pub fn is_finished(&self) -> bool {
        self.thread_handle
            .as_ref()
            .map(|h| h.is_finished())
            .unwrap_or(true)
    }
}

/// Registers an active background trash deletion handle.
fn register_active_handle(handle: std::thread::JoinHandle<()>) {
    if let Ok(mut list) = ACTIVE_HANDLES.lock() {
        list.retain(|h| !h.is_finished());
        list.push(handle);
    }
}

/// Waits for all currently active background trash deletions to complete.
pub fn wait_all_trash_deletions() {
    let handles: Vec<_> = {
        if let Ok(mut list) = ACTIVE_HANDLES.lock() {
            std::mem::take(&mut *list)
        } else {
            Vec::new()
        }
    };

    for handle in handles {
        let _ = handle.join();
    }
}

/// Spawns a detached background child process to delete `trash_path` off the critical path.
///
/// On Windows, this creates a detached process with `DETACHED_PROCESS` and `CREATE_NEW_PROCESS_GROUP`,
/// allowing the deletion to outlive the calling `rnpm` process without blocking exit.
pub fn spawn_detached_worker(trash_path: &Path) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };

    let is_rnpm = exe
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("rnpm"))
        .unwrap_or(false);

    if !is_rnpm {
        return false;
    }

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__internal_clean_trash").arg(trash_path);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS (0x00000008) | CREATE_NEW_PROCESS_GROUP (0x00000200) | CREATE_NO_WINDOW (0x08000000)
        cmd.creation_flags(0x08000208);
    }

    cmd.spawn().is_ok()
}

/// Scans `project_dir` and `project_dir/node_modules` for any leftover `.rnpm-trash-*` directories
/// from previous runs and removes them.
pub fn cleanup_leftover_trash(project_dir: &Path) {
    clean_trash_in_dir(project_dir);
    let nm = project_dir.join("node_modules");
    if nm.is_dir() {
        clean_trash_in_dir(&nm);
    }
}

fn clean_trash_in_dir(parent: &Path) {
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if name_str.starts_with(".rnpm-trash") {
                let path = entry.path();
                let _ = rnpm_fs::remove_dir_all_safe(&path);
            } else if name_str.starts_with('@') && entry.path().is_dir() {
                if let Ok(scoped_entries) = std::fs::read_dir(entry.path()) {
                    for scoped_entry in scoped_entries.flatten() {
                        let s_name = scoped_entry.file_name();
                        if s_name.to_string_lossy().starts_with(".rnpm-trash") {
                            let _ = rnpm_fs::remove_dir_all_safe(&scoped_entry.path());
                        }
                    }
                }
            }
        }
    }
}

/// Atomically renames `target` to `.rnpm-trash-<uuid>` inside `trash_parent`
/// and spawns a background thread to remove the files off the critical path.
///
/// If `target` is a junction or symlink, it removes the link directly since
/// removing a reparse point does not recurse into target files and is already ~0ms.
pub fn fast_trash_delete(
    target: &Path,
    trash_parent: &Path,
) -> std::io::Result<Option<TrashHandle>> {
    if !target.exists() && !rnpm_fs::is_junction(target).unwrap_or(false) {
        return Ok(None);
    }

    if rnpm_fs::is_junction(target).unwrap_or(false) {
        let _ = rnpm_fs::remove_junction(target);
        return Ok(None);
    }

    let trash_name = format!(".rnpm-trash-{}", generate_trash_id());
    let trash_path = trash_parent.join(&trash_name);

    // Atomically rename target -> trash_path on the same volume with retry backoff
    let mut attempt = 0;
    let mut delay = std::time::Duration::from_millis(5);
    loop {
        attempt += 1;
        match std::fs::rename(target, &trash_path) {
            Ok(()) => break,
            Err(err) => {
                if attempt >= 10 {
                    // Fall back to safe removal if atomic rename failed
                    tracing::warn!(
                        "Fast rename failed for {} -> {}: {err}. Attempting safe removal fallback.",
                        target.display(),
                        trash_path.display()
                    );
                    let remove_res = rnpm_fs::remove_dir_all_safe(target);
                    if target.exists() || rnpm_fs::is_junction(target).unwrap_or(false) {
                        return Err(match remove_res {
                            Err(e) => std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                e.to_string(),
                            ),
                            Ok(()) => err,
                        });
                    }
                    return Ok(None);
                }
                std::thread::sleep(delay);
                delay = delay
                    .saturating_mul(2)
                    .min(std::time::Duration::from_millis(100));
            }
        }
    }

    // Try spawning detached child worker process so deletion survives parent process exit.
    // Only fall back to background deletion thread if detached worker spawn fails.
    if !spawn_detached_worker(&trash_path) {
        let trash_to_delete = trash_path.clone();
        let thread_handle = std::thread::spawn(move || {
            let _ = rnpm_fs::remove_dir_all_safe(&trash_to_delete);
        });

        register_active_handle(thread_handle);
    }

    Ok(Some(TrashHandle {
        trash_path,
        thread_handle: None,
    }))
}

/// Fast trash deletion with explicit handle returned (useful for tests to wait on thread).
pub fn fast_trash_delete_with_handle(
    target: &Path,
    trash_parent: &Path,
) -> std::io::Result<Option<TrashHandle>> {
    if !target.exists() && !rnpm_fs::is_junction(target).unwrap_or(false) {
        return Ok(None);
    }

    if rnpm_fs::is_junction(target).unwrap_or(false) {
        let _ = rnpm_fs::remove_junction(target);
        return Ok(None);
    }

    let trash_name = format!(".rnpm-trash-{}", generate_trash_id());
    let trash_path = trash_parent.join(&trash_name);

    std::fs::rename(target, &trash_path)?;

    let trash_to_delete = trash_path.clone();
    let thread_handle = std::thread::spawn(move || {
        let _ = rnpm_fs::remove_dir_all_safe(&trash_to_delete);
    });

    Ok(Some(TrashHandle {
        trash_path,
        thread_handle: Some(thread_handle),
    }))
}

/// Atomically renames a whole directory (e.g. `node_modules` during `ci`) to `.rnpm-trash-<uuid>`
/// in its parent directory and spawns a background thread to delete it.
///
/// This moves the directory wipe off the critical path, immediately freeing the original path.
pub fn fast_trash_wipe_dir(dir: &Path) -> std::io::Result<Option<TrashHandle>> {
    if !dir.exists() && !rnpm_fs::is_junction(dir).unwrap_or(false) {
        return Ok(None);
    }

    if rnpm_fs::is_junction(dir).unwrap_or(false) {
        let _ = rnpm_fs::remove_junction(dir);
        return Ok(None);
    }

    let parent = dir.parent().unwrap_or_else(|| Path::new("."));
    let trash_name = format!(".rnpm-trash-{}", generate_trash_id());
    let trash_path = parent.join(&trash_name);

    let mut attempt = 0;
    let mut delay = std::time::Duration::from_millis(5);
    loop {
        attempt += 1;
        match std::fs::rename(dir, &trash_path) {
            Ok(()) => break,
            Err(err) => {
                if attempt >= 10 {
                    tracing::warn!(
                        "Wipe rename failed for {} -> {}: {err}. Attempting safe removal fallback.",
                        dir.display(),
                        trash_path.display()
                    );
                    let remove_res = rnpm_fs::remove_dir_all_safe(dir);
                    if dir.exists() || rnpm_fs::is_junction(dir).unwrap_or(false) {
                        return Err(match remove_res {
                            Err(e) => std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                e.to_string(),
                            ),
                            Ok(()) => err,
                        });
                    }
                    return Ok(None);
                }
                std::thread::sleep(delay);
                delay = delay
                    .saturating_mul(2)
                    .min(std::time::Duration::from_millis(100));
            }
        }
    }

    // Try spawning detached child worker process so deletion survives parent process exit.
    // Only fall back to background deletion thread if detached worker spawn fails.
    if !spawn_detached_worker(&trash_path) {
        let trash_to_delete = trash_path.clone();
        let thread_handle = std::thread::spawn(move || {
            let _ = rnpm_fs::remove_dir_all_safe(&trash_to_delete);
        });

        register_active_handle(thread_handle);
    }

    Ok(Some(TrashHandle {
        trash_path,
        thread_handle: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_trash_id_is_unique() {
        let id1 = generate_trash_id();
        let id2 = generate_trash_id();
        assert_ne!(id1, id2);
        assert!(id1.contains('-'));
        assert_eq!(id1.len(), 36);
    }

    #[test]
    fn test_fast_trash_delete_moves_and_cleans_up() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        let pkg = nm.join("test-package");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("file.js"), b"console.log('hi')").unwrap();
        assert!(pkg.exists());

        // Fast trash delete with handle
        let mut handle = fast_trash_delete_with_handle(&pkg, &nm).unwrap().unwrap();

        // 1. Target directory must be gone immediately
        assert!(
            !pkg.exists(),
            "Original package directory must be gone immediately"
        );

        // 2. Trash directory path in nm has .rnpm-trash- prefix
        assert!(handle
            .trash_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(".rnpm-trash-"));

        // 3. Wait for background thread
        handle.wait().unwrap();

        // 4. Trash directory is now completely gone
        assert!(
            !handle.trash_path.exists(),
            "Trash directory must be cleaned up"
        );
    }

    #[test]
    fn test_fast_trash_wipe_dir_moves_and_cleans_up() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        // Create deep hierarchy with many files
        for i in 0..5 {
            let sub = nm.join(format!("pkg-{}", i));
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join("package.json"), r#"{"name": "test"}"#).unwrap();
            std::fs::write(sub.join("index.js"), b"export default 42;").unwrap();
        }
        assert!(nm.exists());

        let res = fast_trash_wipe_dir(&nm).unwrap();
        assert!(res.is_some());
        let trash_handle = res.unwrap();

        // 1. node_modules was immediately unlinked/renamed
        assert!(
            !nm.exists(),
            "node_modules must be immediately gone on critical path"
        );

        // 2. Trash directory path starts with .rnpm-trash-
        assert!(trash_handle
            .trash_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(".rnpm-trash-"));

        // 3. Wait for background deletions to complete
        wait_all_trash_deletions();

        // 4. Trash directory is gone
        assert!(
            !trash_handle.trash_path.exists(),
            "Wiped trash directory must be cleaned up"
        );
    }

    #[test]
    fn test_trash_delete_nonexistent_returns_none() {
        let tmp = tempdir().unwrap();
        let non_existent = tmp.path().join("does_not_exist");
        let res = fast_trash_delete(&non_existent, tmp.path()).unwrap();
        assert!(res.is_none());
    }

    #[test]
    #[cfg(windows)]
    fn test_fast_trash_wipe_dir_propagates_error_on_locked_file() {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let locked_file_path = nm.join("locked.node");
        std::fs::write(&locked_file_path, b"native addon binary").unwrap();

        // Open directory handle without FILE_SHARE_DELETE (using FILE_FLAG_BACKUP_SEMANTICS)
        // This locks the directory against atomic rename and deletion on Windows NTFS.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        let _locked_dir = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .share_mode(FILE_SHARE_READ)
            .open(&nm)
            .unwrap();

        // fast_trash_wipe_dir must fail and propagate the error rather than continuing
        let res = fast_trash_wipe_dir(&nm);
        assert!(
            res.is_err(),
            "Must return Err when locked directory prevents renaming or deletion"
        );
    }

    #[test]
    fn test_cleanup_leftover_trash_removes_stale_directories() {
        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let stale1 = project_dir.join(".rnpm-trash-1111-2222-3333");
        std::fs::create_dir_all(&stale1).unwrap();
        std::fs::write(stale1.join("leftover.txt"), b"stale data").unwrap();

        let nm = project_dir.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let stale2 = nm.join(".rnpm-trash-4444-5555-6666");
        std::fs::create_dir_all(&stale2).unwrap();
        std::fs::write(stale2.join("leftover2.txt"), b"stale data 2").unwrap();

        assert!(stale1.exists());
        assert!(stale2.exists());

        cleanup_leftover_trash(project_dir);

        assert!(
            !stale1.exists(),
            "Stale trash in project_dir should be removed"
        );
        assert!(
            !stale2.exists(),
            "Stale trash in node_modules should be removed"
        );
    }
}
