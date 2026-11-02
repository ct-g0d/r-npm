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

    /// Acquire an exclusive cross-process lock on the specified file path, with retry backoff and timeout.
    pub fn acquire_exclusive(path: &Path) -> Result<Self, std::io::Error> {
        Self::acquire_exclusive_timeout(path, Self::DEFAULT_TIMEOUT)
    }

    /// Acquire an exclusive cross-process lock with a specific timeout duration.
    pub fn acquire_exclusive_timeout(path: &Path, timeout: Duration) -> Result<Self, std::io::Error> {
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
                    let elapsed = start.elapsed();
                    if elapsed >= timeout {
                        // Check if lock file can be recovered (e.g. stale lock recovery)
                        if Self::is_lock_stale(path, Self::DEFAULT_STALE_THRESHOLD) {
                            warn!(
                                "Lock on {} appears stale (older than {:?}). Attempting recovery...",
                                path.display(),
                                Self::DEFAULT_STALE_THRESHOLD
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
                debug!("Transient file lock / sharing violation opening {}", path.display());
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
                debug!("Lock on {} is already held by another process", path.display());
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Check whether a lock file exists and is older than the stale threshold.
    pub fn is_lock_stale(path: &Path, threshold: Duration) -> bool {
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
                    || code == 1224;  // ERROR_USER_MAPPED_FILE
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
