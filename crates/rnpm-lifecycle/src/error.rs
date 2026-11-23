use thiserror::Error;

/// Errors that can occur during lifecycle script sandboxing and execution.
#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("Lifecycle scripts are disabled by policy")]
    ScriptsDisabled,

    #[error("Package '{0}' is denylisted from running lifecycle scripts")]
    PackageDenylisted(String),

    #[error("Package '{0}' is not in the script execution allowlist")]
    PackageNotAllowlisted(String),

    #[error(
        "Dangerous command pattern detected in script for '{package}': {reason} (command: '{cmd}')"
    )]
    DangerousCommandPattern {
        package: String,
        reason: String,
        cmd: String,
    },

    #[error("Process limit exceeded for package '{0}'")]
    ProcessLimitExceeded(String),

    #[error("Execution timeout for package '{package}' after {timeout:?}")]
    Timeout {
        package: String,
        timeout: std::time::Duration,
    },

    #[error(
        "node-gyp is required to build native add-on '{package}', but was not found. Cannot download node-gyp in offline mode. Please configure node-gyp via 'npm_config_node_gyp' or '.npmrc' ('node-gyp=<path>'), or run online once to cache it."
    )]
    NodeGypOfflineAbsent {
        package: String,
    },

    #[error("Script execution failed: {0}")]
    ExecutionFailed(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
