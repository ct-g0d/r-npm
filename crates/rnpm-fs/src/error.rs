use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FsError {
    #[error("Path traversal detected in tarball entry: '{path}'")]
    PathTraversal { path: PathBuf },

    #[error("Absolute path rejected in tarball entry: '{path}'")]
    AbsolutePath { path: PathBuf },

    #[error("Symlink target '{target}' escapes destination for link '{link}'")]
    EscapingSymlink { link: PathBuf, target: PathBuf },

    #[error("Case collision detected for path: '{path}'")]
    CaseCollision { path: PathBuf },

    #[error("Non-UTF-8 path detected in tarball entry: '{path}'")]
    InvalidUtf8Path { path: PathBuf },

    #[error("Forbidden sparse file in tarball entry: '{path}'")]
    ForbiddenSparseFile { path: PathBuf },

    #[error("Dangling hardlink '{link}' targets non-existent entry '{target}'")]
    DanglingHardlink { link: PathBuf, target: PathBuf },

    #[error("Circular hardlink detected: link '{link}' to target '{target}'")]
    CircularHardlink { link: PathBuf, target: PathBuf },

    #[error("Windows reserved device name rejected: '{name}' in path '{path}'")]
    WindowsReservedDeviceName { name: String, path: PathBuf },

    #[error("Trailing dot or space rejected in component '{name}' in path '{path}'")]
    TrailingDotOrSpace { name: String, path: PathBuf },

    #[error("SUID/SGID mode bits (0o{mode:o}) forbidden in path '{path}'")]
    ForbiddenModeBits { mode: u32, path: PathBuf },

    #[error("Forbidden special entry (block, character, or fifo) in path '{path}'")]
    ForbiddenSpecialEntry { path: PathBuf },

    #[error("Tar bomb resource limit exceeded ({limit_type}): {detail}")]
    TarBombLimitExceeded { limit_type: String, detail: String },

    #[error("Atomic replacement failed for '{path}' after {retries} retries: {source}")]
    AtomicReplacementFailed {
        path: PathBuf,
        retries: usize,
        #[source]
        source: std::io::Error,
    },

    #[error("Junction error for '{path}': {detail}")]
    JunctionError { path: PathBuf, detail: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
