use fs4::fs_std::FileExt;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Cross-process file lock guard that releases its lock automatically upon drop.
#[derive(Debug)]
pub struct CacheLock {
    path: PathBuf,
    file: Option<File>,
}

impl CacheLock {
    /// Acquire an exclusive cross-process lock on the specified file path, blocking until acquired.
    pub fn acquire_exclusive(path: &Path) -> Result<Self, std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        debug!("Acquiring exclusive lock on {}", path.display());
        file.lock_exclusive()?;
        debug!("Acquired exclusive lock on {}", path.display());

        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
        })
    }

    /// Try to acquire an exclusive cross-process lock without blocking.
    /// Returns `Ok(Some(lock))` if acquired, or `Ok(None)` if another process holds the lock.
    pub fn try_acquire_exclusive(path: &Path) -> Result<Option<Self>, std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        match file.try_lock_exclusive() {
            Ok(()) => {
                debug!("Acquired non-blocking exclusive lock on {}", path.display());
                Ok(Some(Self {
                    path: path.to_path_buf(),
                    file: Some(file),
                }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                debug!("Lock on {} is already held by another process", path.display());
                Ok(None)
            }
            Err(e) => Err(e),
        }
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

impl Drop for CacheLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            debug!("Releasing lock on {}", self.path.display());
            let _ = file.unlock();
        }
    }
}
