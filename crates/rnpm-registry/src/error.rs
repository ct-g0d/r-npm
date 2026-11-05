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

    #[error("Cannot publish over existing package version for {url} (HTTP {status}): {message}")]
    PublishConflict {
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

    #[error("Circuit breaker is OPEN for host '{host}'; registry is temporarily failing fast")]
    CircuitBreakerOpen { host: String },

    #[error("Malformed package metadata: {0}")]
    MalformedMetadata(String),

    #[error("Size limit exceeded: {message} (limit: {limit} bytes, actual: {actual} bytes)")]
    SizeLimitExceeded {
        limit: u64,
        actual: u64,
        message: String,
    },

    #[error("Slowloris chunk idle timeout exceeded ({0:?})")]
    SlowlorisTimeout(std::time::Duration),

    #[error("Content-Length mismatch: expected {expected} bytes, got {actual} bytes")]
    ContentLengthMismatch {
        expected: u64,
        actual: u64,
    },

    #[error("Provenance verification failed: {0}")]
    ProvenanceVerificationFailed(String),

    #[error("Attestation digest mismatch for {algorithm}: expected {expected}, actual {actual}")]
    AttestationDigestMismatch {
        algorithm: String,
        expected: String,
        actual: String,
    },

    #[error("Untrusted source repository: expected '{expected}', found '{actual}'")]
    UntrustedSourceRepository {
        expected: String,
        actual: String,
    },

    #[error("Invalid Sigstore bundle: {0}")]
    InvalidSigstoreBundle(String),

    #[error("Invalid registry signature: {0}")]
    InvalidSignature(String),

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
            Self::PublishConflict { status, .. } => Some(*status),
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

    /// Returns true if this error is caused by an open circuit breaker.
    pub fn is_circuit_breaker_open(&self) -> bool {
        matches!(self, Self::CircuitBreakerOpen { .. })
    }

    /// Returns true if this error was caused by a connection or request timeout.
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::SlowlorisTimeout(_) => true,
            Self::Http(e) => e.is_timeout(),
            _ => false,
        }
    }

    /// Returns true if this error was caused by a slowloris chunk idle timeout.
    pub fn is_slowloris_timeout(&self) -> bool {
        matches!(self, Self::SlowlorisTimeout(_))
    }

    /// Returns true if this error was caused by malformed packument metadata.
    pub fn is_malformed_metadata(&self) -> bool {
        matches!(self, Self::MalformedMetadata(_))
    }

    /// Returns true if this error was caused by exceeding a payload or package size limit.
    pub fn is_size_limit_exceeded(&self) -> bool {
        matches!(self, Self::SizeLimitExceeded { .. })
    }

    /// Returns true if this error was caused by a Content-Length mismatch.
    pub fn is_content_length_mismatch(&self) -> bool {
        matches!(self, Self::ContentLengthMismatch { .. })
    }

    /// Returns true if this error was caused by a connection or DNS resolution failure.
    pub fn is_connect(&self) -> bool {
        match self {
            Self::Http(e) => e.is_connect(),
            _ => false,
        }
    }

    /// Returns true if this error was caused by a body/stream decoding or chunk corruption error.
    pub fn is_decode(&self) -> bool {
        match self {
            Self::Http(e) => e.is_decode() || e.is_body(),
            _ => false,
        }
    }

    /// Returns true if this error is transient and retryable (timeouts, connect errors, truncated body stream decode errors, 429/502/503/504).
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Http(e) => {
                if e.is_redirect() || e.is_builder() {
                    return false;
                }
                if e.is_timeout() || e.is_connect() || e.is_decode() || e.is_body() {
                    return true;
                }
                if let Some(status) = e.status() {
                    let code = status.as_u16();
                    if code == 429 || code == 502 || code == 503 || code == 504 {
                        return true;
                    }
                }
                let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
                while let Some(err) = source {
                    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                        match io_err.kind() {
                            std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::UnexpectedEof => return true,
                            _ => {}
                        }
                    }
                    source = err.source();
                }
                false
            }
            Self::RateLimited { .. } => true,
            Self::SlowlorisTimeout(_) => true,
            Self::ContentLengthMismatch { .. } => true,
            Self::ServerError { status, .. } => {
                *status == 429 || *status == 502 || *status == 503 || *status == 504
            }
            Self::SecurityViolation(_) => false,
            Self::TooManyRedirects(_) => false,
            Self::UrlParse(_) => false,
            Self::Json(_) => false,
            Self::MalformedMetadata(_) => false,
            Self::SizeLimitExceeded { .. } => false,
            Self::PackageNotFound { .. } => false,
            Self::VersionNotFound { .. } => false,
            Self::Unauthorized { .. } => false,
            Self::Forbidden { .. } => false,
            Self::PublishConflict { .. } => false,
            Self::CircuitBreakerOpen { .. } => false,
            Self::ProvenanceVerificationFailed(_) => false,
            Self::AttestationDigestMismatch { .. } => false,
            Self::UntrustedSourceRepository { .. } => false,
            Self::InvalidSigstoreBundle(_) => false,
            Self::InvalidSignature(_) => false,
            Self::Other(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_transient_rate_limited() {
        let err = RegistryError::RateLimited {
            retry_after: Some(5),
        };
        assert!(err.is_transient());
        assert!(err.is_rate_limited());
        assert_eq!(err.retry_after(), Some(5));
        assert_eq!(err.status_code(), Some(429));
    }

    #[test]
    fn test_is_transient_server_error_codes() {
        for transient_code in [429, 502, 503, 504] {
            let err = RegistryError::ServerError {
                status: transient_code,
                body: "Transient failure".into(),
            };
            assert!(
                err.is_transient(),
                "Status {transient_code} should be considered transient"
            );
            assert_eq!(err.status_code(), Some(transient_code));
        }

        for non_transient_code in [400, 401, 403, 404, 405, 500] {
            let err = RegistryError::ServerError {
                status: non_transient_code,
                body: "Permanent failure".into(),
            };
            assert!(
                !err.is_transient(),
                "Status {non_transient_code} should not be transient"
            );
        }
    }

    #[test]
    fn test_is_transient_non_retryable_variants() {
        let not_found = RegistryError::PackageNotFound {
            package: "foo".into(),
            status: 404,
        };
        assert!(!not_found.is_transient());
        assert!(not_found.is_not_found());
        assert_eq!(not_found.status_code(), Some(404));

        let unauth = RegistryError::Unauthorized {
            url: "https://registry.npmjs.org/pkg".into(),
            status: 401,
            message: "Unauthorized".into(),
        };
        assert!(!unauth.is_transient());
        assert!(unauth.is_unauthorized());
        assert!(unauth.is_auth_error());
        assert_eq!(unauth.status_code(), Some(401));

        let forbidden = RegistryError::Forbidden {
            url: "https://registry.npmjs.org/pkg".into(),
            status: 403,
            message: "Forbidden".into(),
        };
        assert!(!forbidden.is_transient());
        assert!(forbidden.is_forbidden());
        assert!(forbidden.is_auth_error());
        assert_eq!(forbidden.status_code(), Some(403));

        let redirects = RegistryError::TooManyRedirects(10);
        assert!(!redirects.is_transient());

        let sec_violation = RegistryError::SecurityViolation("evil redirect".into());
        assert!(!sec_violation.is_transient());

        let version_not_found = RegistryError::VersionNotFound {
            package: "foo".into(),
            version: "1.0.0".into(),
        };
        assert!(!version_not_found.is_transient());

        let cb_open = RegistryError::CircuitBreakerOpen {
            host: "registry.npmjs.org".into(),
        };
        assert!(!cb_open.is_transient());
        assert!(cb_open.is_circuit_breaker_open());

        let other = RegistryError::Other("custom error".into());
        assert!(!other.is_transient());

        let prov_err = RegistryError::ProvenanceVerificationFailed("bad provenance".into());
        assert!(!prov_err.is_transient());

        let digest_err = RegistryError::AttestationDigestMismatch {
            algorithm: "sha512".into(),
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(!digest_err.is_transient());

        let repo_err = RegistryError::UntrustedSourceRepository {
            expected: "org/repo".into(),
            actual: "bad/repo".into(),
        };
        assert!(!repo_err.is_transient());

        let bundle_err = RegistryError::InvalidSigstoreBundle("corrupt".into());
        assert!(!bundle_err.is_transient());

        let sig_err = RegistryError::InvalidSignature("bad sig".into());
        assert!(!sig_err.is_transient());

        let url_err = RegistryError::UrlParse(url::ParseError::EmptyHost);
        assert!(!url_err.is_transient());

        let malformed = RegistryError::MalformedMetadata("missing name".into());
        assert!(!malformed.is_transient());

        let size_err = RegistryError::SizeLimitExceeded {
            limit: 100,
            actual: 200,
            message: "Too large".into(),
        };
        assert!(!size_err.is_transient());
    }
}

