use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Semver error: {0}")]
    Semver(#[from] SemverError),

    #[error("Package spec error: {0}")]
    Spec(#[from] SpecError),

    #[error("SSRI integrity error: {0}")]
    Integrity(#[from] IntegrityError),

    #[error("Manifest error: {0}")]
    Manifest(#[from] ManifestError),

    #[error("Workspace error: {0}")]
    Workspace(#[from] WorkspaceError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SemverError {
    #[error("Invalid semver version: '{0}'")]
    InvalidVersion(String),

    #[error("Invalid semver range: '{0}'")]
    InvalidRange(String),

    #[error("Invalid comparator: '{0}'")]
    InvalidComparator(String),

    #[error("Invalid prerelease identifier: '{0}'")]
    InvalidPrerelease(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("Empty package specifier")]
    Empty,

    #[error("Invalid package name: '{0}'")]
    InvalidName(String),

    #[error("Invalid alias specifier: '{0}'")]
    InvalidAlias(String),

    #[error("Invalid specifier format: '{0}'")]
    InvalidFormat(String),

    #[error("Unsupported URL Type \"{protocol}\": {spec}")]
    UnsupportedProtocol { protocol: String, spec: String },

    #[error("Invalid semver in specifier: {0}")]
    Semver(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntegrityError {
    #[error("Invalid integrity string format: '{0}'")]
    InvalidFormat(String),

    #[error("Unsupported hash algorithm: '{0}'")]
    UnsupportedAlgorithm(String),

    #[error("Invalid base64 in integrity digest: '{0}'")]
    InvalidBase64(String),

    #[error("Integrity mismatch for {algorithm}: expected '{expected}', computed '{actual}'")]
    Mismatch {
        algorithm: String,
        expected: String,
        actual: String,
    },

    #[error("Integrity check failed: no valid digests provided")]
    Empty,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("IO error reading manifest at '{path}': {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Malformed JSON in manifest: {message} at line {line}, column {column}")]
    MalformedJson {
        message: String,
        line: usize,
        column: usize,
    },

    #[error("Invalid manifest field '{field}': {detail}")]
    InvalidField { field: String, detail: String },
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("Manifest error: {0}")]
    Manifest(#[from] ManifestError),

    #[error("IO error in workspace: {0}")]
    Io(#[from] std::io::Error),

    #[error("Workspace member missing name at '{0}'")]
    MissingName(std::path::PathBuf),

    #[error("Duplicate workspace package name '{name}' at '{first}' and '{second}'")]
    DuplicatePackage {
        name: String,
        first: std::path::PathBuf,
        second: std::path::PathBuf,
    },
}
