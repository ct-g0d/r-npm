use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("IO error reading configuration at '{path}': {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid URL in configuration: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("Invalid .npmrc line '{0}'")]
    InvalidLine(String),
}
