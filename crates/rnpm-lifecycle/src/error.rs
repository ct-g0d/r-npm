use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during lifecycle script execution.
#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("Lifecycle script '{script_name}' not found in package.json")]
    ScriptNotFound { script_name: String },

    #[error("Lifecycle script '{script_name}' failed with exit code {exit_code:?}.\nstdout:\n{stdout}\nstderr:\n{stderr}")]
    ExecutionFailed {
        script_name: String,
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
    },

    #[error("I/O error for path {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Manifest error: {0}")]
    Manifest(#[from] rnpm_core::error::ManifestError),

    #[error("Dependency cycle detected during topological lifecycle execution: {cycle:?}")]
    DependencyCycle { cycle: Vec<String> },

    #[error("{0}")]
    Other(String),
}
