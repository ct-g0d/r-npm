use thiserror::Error;

#[derive(Debug, Error)]
pub enum SolverError {
    #[error("Unresolved dependency '{name}@{spec}': {message}")]
    UnresolvedDependency {
        name: String,
        spec: String,
        message: String,
    },

    #[error("ERESOLVE: Conflicting peer dependency '{peer}' required by '{parent}': {message}")]
    PeerConflict {
        parent: String,
        peer: String,
        required_by: Vec<String>,
        message: String,
    },

    #[error("Cycle detected during dependency resolution: {0}")]
    CycleDetected(String),

    #[error("Invalid override configuration: {0}")]
    InvalidOverride(String),

    #[error("Core error: {0}")]
    Core(#[from] rnpm_core::CoreError),

    #[error("Spec error: {0}")]
    Spec(#[from] rnpm_core::SpecError),

    #[error("Semver error: {0}")]
    Semver(#[from] rnpm_core::SemverError),

    #[error("Manifest error: {0}")]
    Manifest(#[from] rnpm_core::ManifestError),

    #[error("Lockfile error: {0}")]
    Lockfile(#[from] rnpm_lockfile::LockfileError),

    #[error("Package metadata error for '{0}': {1}")]
    PackageMetadata(String, String),
}
