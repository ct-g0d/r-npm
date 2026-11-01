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
}
