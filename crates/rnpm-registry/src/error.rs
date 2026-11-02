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

    #[error("Access forbidden for {url} (HTTP {status}): {message}")]
    Forbidden {
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

impl RegistryError {
    /// Returns the HTTP status code associated with this error, if applicable.
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::PackageNotFound { status, .. } => Some(*status),
            Self::Unauthorized { status, .. } => Some(*status),
            Self::Forbidden { status, .. } => Some(*status),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status, .. } => Some(*status),
            Self::Http(e) => e.status().map(|s| s.as_u16()),
            _ => None,
        }
    }

    /// Returns true if this error is an authentication error (HTTP 401).
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized { .. })
    }

    /// Returns true if this error is an access forbidden error (HTTP 403).
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Self::Forbidden { .. })
    }

    /// Returns true if this error is an authentication or authorization failure (HTTP 401 or 403).
    pub fn is_auth_error(&self) -> bool {
        self.is_unauthorized() || self.is_forbidden()
    }

    /// Returns true if this error is a package not found error (HTTP 404).
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::PackageNotFound { .. })
    }

    /// Returns true if this error indicates rate limiting (HTTP 429).
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Self::RateLimited { .. })
    }

    /// Returns the `Retry-After` duration in seconds if this was an HTTP 429 rate limit error.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::RateLimited { retry_after } => *retry_after,
            _ => None,
        }
    }
}
