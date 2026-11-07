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

    #[error("Missing integrity hash for package '{0}'")]
    MissingIntegrity(String),

    #[error("Weak integrity algorithm for package '{package}': '{algorithm}' is below minimum required algorithm '{required}'")]
    WeakIntegrity {
        package: String,
        algorithm: String,
        required: String,
    },

    #[error("Insecure resolved URL for package '{package}': '{url}' (insecure HTTP disallowed)")]
    InsecureResolvedUrl { package: String, url: String },

    #[error("Suspicious resolution URL for package '{package}': {reason}")]
    SuspiciousResolution { package: String, reason: String },

    #[error("Poisoned dependency detected for package '{package}': {reason}")]
    PoisonedDependency { package: String, reason: String },

    #[error("Lockfile error: {0}")]
    Other(String),
}
