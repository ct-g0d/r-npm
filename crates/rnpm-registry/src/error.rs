use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Package '{package}' not found in registry (HTTP {status})")]
    PackageNotFound { package: String, status: u16 },

    #[error("Version '{version}' for package '{package}' not found")]
    VersionNotFound { package: String, version: String },

    #[error("Authentication failed for {url} (HTTP {status}): {message}")]
    Unauthorized {
        url: String,
        status: u16,
        message: String,
    },

    #[error("Registry rate limit exceeded (HTTP 429)")]
    RateLimited { retry_after: Option<u64> },

    #[error("Too many redirects (exceeded limit of {0})")]
    TooManyRedirects(usize),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Server error (HTTP {status}): {body}")]
    ServerError { status: u16, body: String },

    #[error("Unexpected error: {0}")]
    Other(String),
}
