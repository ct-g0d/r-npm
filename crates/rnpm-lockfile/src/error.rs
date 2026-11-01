use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Unsupported lockfileVersion: {0}")]
    UnsupportedVersion(u32),

    #[error("Invalid lockfile structure: {0}")]
    InvalidStructure(String),

    #[error("Lockfile error: {0}")]
    Other(String),
}
