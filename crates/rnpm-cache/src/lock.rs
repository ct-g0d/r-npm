use fs4::fs_std::FileExt;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// Cross-process file lock guard that releases its lock automatically upon drop.
#[derive(Debug)]
pub struct CacheLock {
    path: PathBuf,
    file: Option<File>,
}

impl CacheLock {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
    pub const DEFAULT_STALE_THRESHOLD: Duration = Duration::from_secs(60);

    /// Acquire an exclusive cross-process lock on the specified file path, with retry backoff and default timeout.
    pub fn acquire_exclusive(path: &Path) -> Result<Self, std::io::Error> {
        Self::acquire_exclusive_with_options(
            path,
            Self::DEFAULT_TIMEOUT,
            Self::DEFAULT_STALE_THRESHOLD,
        )
    }

    /// Acquire an exclusive cross-process lock with a specific timeout duration.
    pub fn acquire_exclusive_timeout(
        path: &Path,
        timeout: Duration,
    ) -> Result<Self, std::io::Error> {
        Self::acquire_exclusive_with_options(path, timeout, Self::DEFAULT_STALE_THRESHOLD)
    }

    /// Acquire an exclusive cross-process lock with specific timeout duration and stale threshold.
    pub fn acquire_exclusive_with_options(
        path: &Path,
        timeout: Duration,
        stale_threshold: Duration,
    ) -> Result<Self, std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let start = Instant::now();
        let mut attempt = 0;
        let mut delay = Duration::from_millis(5);

        loop {
            attempt += 1;
            match Self::try_acquire_exclusive(path)? {
                Some(lock) => return Ok(lock),
                None => {
                    // Check if current lock owner process has died; if so, break and reclaim stale lock immediately
                    if let Some(pid) = Self::read_lock_pid(path) {
                        if !is_process_alive(pid) {
                            warn!(
                                "Lock owner process PID {pid} for {} no longer exists. Breaking and reclaiming stale lock.",
                                path.display()
                            );
                            if let Ok(Some(recovered)) = Self::force_recover_stale_lock(path) {
                                return Ok(recovered);
                            }
                        }
                    }

                    let elapsed = start.elapsed();
                    if elapsed >= timeout {
                        // Check if lock file can be recovered (e.g. stale lock recovery)
                        if Self::is_lock_stale(path, stale_threshold) {
                            warn!(
                                "Lock on {} appears stale (older than {:?}). Attempting recovery...",
                                path.display(),
                                stale_threshold
                            );
                            if let Ok(Some(recovered)) = Self::force_recover_stale_lock(path) {
                                return Ok(recovered);
                            }
                        }

                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "Timed out acquiring exclusive lock on {} after {:?} ({attempt} attempts)",
                                path.display(),
                                elapsed
                            ),
                        ));
                    }

                    let jitter_ms = (attempt as u64 * 3) % 11;
                    let remaining = timeout.saturating_sub(elapsed);
                    let sleep_dur = (delay + Duration::from_millis(jitter_ms)).min(remaining);
                    sleep(sleep_dur);
                    delay = delay.saturating_mul(2).min(Duration::from_millis(250));
                }
            }
        }
    }

    /// Try to acquire an exclusive cross-process lock without blocking.
    /// Returns `Ok(Some(lock))` if acquired, or `Ok(None)` if another process holds the lock.
    pub fn try_acquire_exclusive(path: &Path) -> Result<Option<Self>, std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // On Windows, if readonly attribute was set, clear it before opening
        #[cfg(windows)]
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(path, perms);
            }
        }

        let file_res = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path);

        let mut file = match file_res {
            Ok(f) => f,
            Err(e) if is_transient_lock_error(&e) => {
                debug!(
                    "Transient file lock / sharing violation opening {}",
                    path.display()
                );
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        match file.try_lock_exclusive() {
            Ok(()) => {
                debug!("Acquired non-blocking exclusive lock on {}", path.display());
                let pid = std::process::id();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _ = file.set_len(0);
                let _ = file.seek(SeekFrom::Start(0));
                let _ = writeln!(file, "pid={pid} time={now}");
                let _ = file.flush();

                Ok(Some(Self {
                    path: path.to_path_buf(),
                    file: Some(file),
                }))
            }
            Err(e) if is_would_block(&e) => {
                debug!(
                    "Lock on {} is already held by another process",
                    path.display()
                );
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Parse owner PID from the lock file if present (e.g. `pid=1234 time=...`).
    pub fn read_lock_pid(path: &Path) -> Option<u32> {
        let content = std::fs::read_to_string(path).ok()?;
        for token in content.split_whitespace() {
            if let Some(pid_str) = token.strip_prefix("pid=") {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return Some(pid);
                }
            }
        }
        None
    }

    /// Check whether a lock file exists and is older than the stale threshold or belongs to a dead process.
    pub fn is_lock_stale(path: &Path, threshold: Duration) -> bool {
        if let Some(pid) = Self::read_lock_pid(path) {
            if !is_process_alive(pid) {
                return true;
            }
        }
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(mtime) = meta.modified() {
                if let Ok(age) = SystemTime::now().duration_since(mtime) {
                    return age >= threshold;
                }
            }
        }
        false
    }

    /// Attempt to recover a stale lock by removing or truncating an abandoned lock file.
    pub fn force_recover_stale_lock(path: &Path) -> Result<Option<Self>, std::io::Error> {
        #[cfg(windows)]
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(path, perms);
            }
        }

        let _ = std::fs::remove_file(path);
        Self::try_acquire_exclusive(path)
    }

    /// Acquire a shared (read) cross-process lock on the specified file path.
    pub fn acquire_shared(path: &Path) -> Result<Self, std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        debug!("Acquiring shared lock on {}", path.display());
        file.lock_shared()?;
        debug!("Acquired shared lock on {}", path.display());

        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
        })
    }

    /// The path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn is_would_block(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    if let Some(code) = err.raw_os_error() {
        return code == 33; // ERROR_LOCK_VIOLATION
    }
    false
}

fn is_transient_lock_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::PermissionDenied
        | ErrorKind::WouldBlock
        | ErrorKind::Interrupted
        | ErrorKind::ResourceBusy => true,
        _ => {
            #[cfg(windows)]
            if let Some(code) = err.raw_os_error() {
                return code == 5      // ERROR_ACCESS_DENIED
                    || code == 32     // ERROR_SHARING_VIOLATION
                    || code == 33     // ERROR_LOCK_VIOLATION
                    || code == 170    // ERROR_BUSY
                    || code == 1224; // ERROR_USER_MAPPED_FILE
            }
            false
        }
    }
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            debug!("Releasing lock on {}", self.path.display());
            let _ = file.unlock();
        }
    }
}

/// Inspects whether a process with the given PID is alive.
#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    type HANDLE = *mut std::ffi::c_void;
    type BOOL = i32;
    type DWORD = u32;

    const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
    const STILL_ACTIVE: DWORD = 259;
    const ERROR_ACCESS_DENIED: DWORD = 5;

    extern "system" {
        fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
        fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut DWORD) -> BOOL;
        fn CloseHandle(hObject: HANDLE) -> BOOL;
        fn GetLastError() -> DWORD;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            let err = GetLastError();
            // Access denied implies process exists under another security context
            return err == ERROR_ACCESS_DENIED;
        }

        let mut exit_code: DWORD = 0;
        let success = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);

        if success != 0 {
            exit_code == STILL_ACTIVE
        } else {
            true
        }
    }
}

/// Inspects whether a process with the given PID is alive on Unix using kill(pid, 0).
#[cfg(not(windows))]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        let res = kill(pid as i32, 0);
        if res == 0 {
            true
        } else {
            let err = std::io::Error::last_os_error();
            // EPERM (code 1) means process exists but owned by someone else
            err.raw_os_error() == Some(1)
        }
    }
}
