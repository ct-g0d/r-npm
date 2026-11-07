use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Core error: {0}")]
    Core(#[from] rnpm_core::CoreError),

    #[error("Integrity verification failed for '{key}': expected {expected}, actual {actual}")]
    IntegrityMismatch {
        key: String,
        expected: String,
        actual: String,
    },

    #[error("Cache lock acquisition timed out or failed for '{0}'")]
    LockFailed(String),

    #[error("Corrupted cache entry purged: {0}")]
    CorruptedEntryPurged(String),

    #[error("Invalid cache key: {0}")]
    InvalidKey(String),

    #[error("Cache error: {0}")]
    Other(String),

    #[error("Fs error: {0}")]
    Fs(#[from] rnpm_fs::FsError),

    #[error("Pack not found for integrity: {0}")]
    PackNotFound(String),

    #[error("Corrupted pack: {0}")]
    CorruptedPack(String),

    #[error("Invalid pack: {0}")]
    InvalidPack(String),
}

/// Type alias for pack store errors.
pub type PackError = CacheError;

impl CacheError {
    /// Returns true if the error indicates a corrupted or invalid pack file/index
    /// (e.g. hash mismatch, invalid format, path traversal), which warrants purging
    /// the pack from the cache.
    ///
    /// Returns false for general system/environmental errors like disk full (ENOSPC),
    /// permission denied (EACCES/read-only filesystem), or broken pipes, where the pack
    /// itself is intact and purging it would be harmful.
    pub fn is_pack_corruption(&self) -> bool {
        match self {
            CacheError::CorruptedPack(_) => true,
            CacheError::InvalidPack(_) => true,
            CacheError::IntegrityMismatch { .. } => true,
            CacheError::CorruptedEntryPurged(_) => true,
            CacheError::PackNotFound(_) => true,
            CacheError::Json(_) => true,
            CacheError::Fs(fs_err) => !matches!(
                fs_err,
                rnpm_fs::FsError::Io(_) | rnpm_fs::FsError::AtomicReplacementFailed { .. }
            ),
            _ => false,
        }
    }
}
