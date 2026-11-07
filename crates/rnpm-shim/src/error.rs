use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShimError {
    #[error("I/O error at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Cannot compute relative path between incompatible paths: from '{from}', to '{to}'")]
    IncompatiblePaths { from: PathBuf, to: PathBuf },

    #[error("Target script does not exist: '{0}'")]
    TargetNotFound(PathBuf),

    #[error("Manifest error: {0}")]
    Manifest(#[from] rnpm_core::error::ManifestError),
}
