use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerState};
use crate::error::RegistryError;
use crate::metadata::AbbreviatedPackageMetadata;
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONNECTION, ETAG, IF_NONE_MATCH, LOCATION,
    RETRY_AFTER, USER_AGENT,
};
use reqwest::{Client, Method, Response, StatusCode};
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::OwnedSemaphorePermit;
use tracing::debug;
use url::Url;

/// Returns the default User-Agent header string.
pub fn default_user_agent() -> String {
    format!(
        "rnpm/{} ({}; {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// Abbreviated metadata MIME type for npm registry.
pub const NPM_INSTALL_V1_JSON: &str = "application/vnd.npm.install-v1+json";

/// Maximum number of HTTP redirects to follow before failing.
pub const MAX_REDIRECTS: usize = 10;

/// Default maximum concurrent requests allowed across the client.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 16;

/// Default maximum idle connections per host in the connection pool.
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 32;

/// Default TCP keep-alive interval.
pub const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 60;

/// Default pool idle connection timeout.
pub const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 90;

/// Default connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default maximum retry attempts for retryable errors (429, 503, transient errors).
pub const DEFAULT_MAX_RETRIES: usize = 3;

/// Default initial retry backoff duration in milliseconds.
pub const DEFAULT_INITIAL_RETRY_BACKOFF_MS: u64 = 100;

/// Default maximum retry backoff duration in seconds.
pub const DEFAULT_MAX_RETRY_BACKOFF_SECS: u64 = 5;

/// Encodes a package name according to npm registry rules:
/// Scoped packages `@scope/pkg` are encoded as `@scope%2fpkg`.
/// Unscoped packages `pkg` remain unchanged.
pub fn encode_package_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@') {
        if let Some((scope, pkg)) = rest.split_once('/') {
            return format!("@{scope}%2f{pkg}");
        }
    }
    name.to_string()
}

/// Result of a conditional metadata fetch (ETag / 304 Not Modified).
#[derive(Debug, Clone)]
pub enum MetadataFetchResult {
    /// Server returned fresh metadata (HTTP 200 OK) with optional ETag.
    Fresh {
        metadata: AbbreviatedPackageMetadata,
        etag: Option<String>,
    },
    /// Server returned HTTP 304 Not Modified; cached data is still valid.
    NotModified {
        etag: Option<String>,
    },
}

impl MetadataFetchResult {
    pub fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }

    pub fn is_not_modified(&self) -> bool {
        matches!(self, Self::NotModified { .. })
    }

    pub fn metadata(&self) -> Option<&AbbreviatedPackageMetadata> {
        match self {
            Self::Fresh { metadata, .. } => Some(metadata),
            Self::NotModified { .. } => None,
        }
    }

    pub fn into_metadata(self) -> Option<AbbreviatedPackageMetadata> {
        match self {
            Self::Fresh { metadata, .. } => Some(metadata),
            Self::NotModified { .. } => None,
        }
    }

    pub fn etag(&self) -> Option<&str> {
        match self {
            Self::Fresh { etag, .. } => etag.as_deref(),
            Self::NotModified { etag, .. } => etag.as_deref(),
        }
    }
}

/// Result of a conditional bytes fetch (ETag / 304 Not Modified).
#[derive(Debug, Clone)]
pub enum BytesFetchResult {
    /// Server returned fresh bytes (HTTP 200 OK) with optional ETag.
    Fresh {
        bytes: Vec<u8>,
        etag: Option<String>,
    },
    /// Server returned HTTP 304 Not Modified.
    NotModified {
        etag: Option<String>,
    },
}

impl BytesFetchResult {
    pub fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }

    pub fn is_not_modified(&self) -> bool {
        matches!(self, Self::NotModified { .. })
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Fresh { bytes, .. } => Some(bytes),
            Self::NotModified { .. } => None,
        }
    }

    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            Self::Fresh { bytes, .. } => Some(bytes),
            Self::NotModified { .. } => None,
        }
    }

    pub fn etag(&self) -> Option<&str> {
        match self {
            Self::Fresh { etag, .. } => etag.as_deref(),
            Self::NotModified { etag, .. } => etag.as_deref(),
        }
    }
}

/// Result of a conditional tarball response fetch.
#[derive(Debug)]
pub enum TarballFetchResult {
    /// Server returned fresh tarball response (HTTP 200 OK) with optional ETag.
    Modified {
        response: Response,
        etag: Option<String>,
    },
    /// Server returned HTTP 304 Not Modified.
    NotModified {
        etag: Option<String>,
    },
}

impl TarballFetchResult {
    pub fn is_modified(&self) -> bool {
        matches!(self, Self::Modified { .. })
    }

    pub fn is_not_modified(&self) -> bool {
        matches!(self, Self::NotModified { .. })
    }

    pub fn etag(&self) -> Option<&str> {
        match self {
            Self::Modified { etag, .. } => etag.as_deref(),
            Self::NotModified { etag, .. } => etag.as_deref(),
        }
    }
}

/// Registry client configuration.
#[derive(Debug, Clone)]
pub struct RegistryClientConfig {
    pub default_registry: Url,
    pub user_agent: String,
    pub auth_token: Option<String>,
    pub trusted_hosts: HashSet<String>,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub max_concurrent_requests: usize,
    pub pool_max_idle_per_host: usize,
    pub tcp_keepalive: Duration,
    pub pool_idle_timeout: Duration,
    pub max_retries: usize,
    pub initial_retry_backoff: Duration,
    pub max_retry_backoff: Duration,
    pub retry_on_status: HashSet<u16>,
    pub scoped_registries: std::collections::BTreeMap<String, Url>,
    pub auth_tokens: std::collections::BTreeMap<String, String>,
    pub circuit_breaker_enabled: bool,
    pub circuit_breaker_failure_threshold: usize,
    pub circuit_breaker_reset_timeout: Duration,
}

impl Default for RegistryClientConfig {
    fn default() -> Self {
        let registry_url = Url::parse("https://registry.npmjs.org/").unwrap();
        let mut trusted_hosts = HashSet::new();
        if let Some(h) = registry_url.host_str() {
            trusted_hosts.insert(h.to_ascii_lowercase());
        }

        let mut retry_on_status = HashSet::new();
        retry_on_status.insert(429);
        retry_on_status.insert(502);
        retry_on_status.insert(503);
        retry_on_status.insert(504);

        Self {
            default_registry: registry_url,
            user_agent: default_user_agent(),
            auth_token: None,
            trusted_hosts,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE_PER_HOST,
            tcp_keepalive: Duration::from_secs(DEFAULT_TCP_KEEPALIVE_SECS),
            pool_idle_timeout: Duration::from_secs(DEFAULT_POOL_IDLE_TIMEOUT_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            initial_retry_backoff: Duration::from_millis(DEFAULT_INITIAL_RETRY_BACKOFF_MS),
            max_retry_backoff: Duration::from_secs(DEFAULT_MAX_RETRY_BACKOFF_SECS),
            retry_on_status,
            scoped_registries: std::collections::BTreeMap::new(),
            auth_tokens: std::collections::BTreeMap::new(),
            circuit_breaker_enabled: false,
            circuit_breaker_failure_threshold: 5,
            circuit_breaker_reset_timeout: Duration::from_secs(30),
        }
    }
}

/// Client for interacting with npm package registries.
#[derive(Clone)]
pub struct RegistryClient {
    client: Client,
    config: RegistryClientConfig,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    circuit_breaker: CircuitBreaker,
}

impl RegistryClient {
    /// Create a new RegistryClient with default configuration.
    pub fn new() -> Result<Self, RegistryError> {
        Self::with_config(RegistryClientConfig::default())
    }

    /// Create a new RegistryClient with custom configuration.
    pub fn with_config(config: RegistryClientConfig) -> Result<Self, RegistryError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&config.user_agent)
                .map_err(|e| RegistryError::Other(e.to_string()))?,
        );
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );

        let max_idle = if config.pool_max_idle_per_host == 0 {
            DEFAULT_POOL_MAX_IDLE_PER_HOST
        } else {
            config.pool_max_idle_per_host
        };

        // We disable reqwest's automatic redirect following so that we can enforce
        // the strict security rule: NEVER forward auth headers across redirects to untrusted hostnames.
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .tcp_nodelay(true)
            .tcp_keepalive(Some(config.tcp_keepalive))
            .pool_idle_timeout(Some(config.pool_idle_timeout))
            .pool_max_idle_per_host(max_idle)
            .build()?;

        let max_concurrency = if config.max_concurrent_requests == 0 {
            DEFAULT_MAX_CONCURRENT_REQUESTS
        } else {
            config.max_concurrent_requests
        };
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrency));

        let failure_threshold = if config.circuit_breaker_enabled {
            config.circuit_breaker_failure_threshold
        } else {
            0
        };
        let circuit_breaker = CircuitBreaker::new(failure_threshold, config.circuit_breaker_reset_timeout);

        Ok(Self {
            client,
            config,
            semaphore,
            circuit_breaker,
        })
    }

    /// Access the client configuration.
    pub fn config(&self) -> &RegistryClientConfig {
        &self.config
    }

    /// Access the bounded concurrency semaphore.
    pub fn semaphore(&self) -> &std::sync::Arc<tokio::sync::Semaphore> {
        &self.semaphore
    }

    /// Check the current circuit breaker state for a host.
    pub async fn circuit_state(&self, host: &str) -> CircuitBreakerState {
        self.circuit_breaker.check_state(host).await
    }

    /// Explicitly reset the circuit breaker for a host.
    pub async fn reset_circuit(&self, host: &str) {
        self.circuit_breaker.reset(host).await;
    }

    /// Explicitly trip the circuit breaker for a host to Open state.
    pub async fn trip_circuit(&self, host: &str) {
        self.circuit_breaker.trip(host).await;
    }

    /// Determine the registry URL to use for a given package name.
    /// Scoped package definitions in `config.scoped_registries` take strict precedence over the default registry.
    pub fn registry_for_package(&self, package_name: &str) -> &Url {
        let pkg_trimmed = package_name.trim();
        if pkg_trimmed.starts_with('@') {
            let scope_part = if let Some(slash_idx) = pkg_trimmed.find('/') {
                &pkg_trimmed[..slash_idx]
            } else if let Some(enc_idx) = pkg_trimmed.to_ascii_lowercase().find("%2f") {
                &pkg_trimmed[..enc_idx]
            } else {
                pkg_trimmed
            };

            let scope_lower = scope_part.to_ascii_lowercase();
            if let Some(scoped_url) = self.config.scoped_registries.get(&scope_lower) {
                return scoped_url;
            }
        }
        &self.config.default_registry
    }

    /// Retrieve the auth token for a target URL if configured in `auth_tokens` or fallback to `auth_token`.
    pub fn auth_token_for_url(&self, url: &Url) -> Option<&str> {
        let host = url.host_str()?;
        let host_lower = host.to_ascii_lowercase();
        let port_part = if let Some(port) = url.port() {
            format!(":{port}")
        } else {
            String::new()
        };
        let path = url.path();
        let normalized_path = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{path}/")
        };

        let candidate1 = format!("//{host_lower}{port_part}{normalized_path}");
        if let Some(token) = self.config.auth_tokens.get(&candidate1) {
            return Some(token.as_str());
        }
        let candidate2 = format!("//{host_lower}{port_part}{path}");
        if let Some(token) = self.config.auth_tokens.get(&candidate2) {
            return Some(token.as_str());
        }
        let candidate3 = format!("//{host_lower}{port_part}/");
        if let Some(token) = self.config.auth_tokens.get(&candidate3) {
            return Some(token.as_str());
        }
        if !port_part.is_empty() {
            let candidate4 = format!("//{host_lower}/");
            if let Some(token) = self.config.auth_tokens.get(&candidate4) {
                return Some(token.as_str());
            }
        }
        self.config.auth_token.as_deref()
    }

    /// Acquire an owned permit from the bounded concurrency semaphore.
    /// Holding this permit ensures that total concurrent in-flight network requests
    /// and active socket streams remain strictly bounded by `max_concurrent_requests`.
    pub async fn acquire_permit(&self) -> Result<OwnedSemaphorePermit, RegistryError> {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| RegistryError::Other(e.to_string()))
    }

    /// Format the metadata URL for a package name using scoped registry routing.
    pub fn package_metadata_url(&self, package_name: &str) -> Result<Url, RegistryError> {
        let registry = self.registry_for_package(package_name);
        self.package_metadata_url_on(registry, package_name)
    }

    /// Format the metadata URL for a package name on a specific registry.
    pub fn package_metadata_url_on(
        &self,
        registry: &Url,
        package_name: &str,
    ) -> Result<Url, RegistryError> {
        let encoded = encode_package_name(package_name);
        let base_str = registry.as_str().trim_end_matches('/');
        let url_str = format!("{base_str}/{encoded}");
        Url::parse(&url_str).map_err(RegistryError::UrlParse)
    }

    /// Check if target URL is trusted to receive authorization headers.
    pub fn is_trusted_target(&self, initial_url: &Url, current_url: &Url) -> bool {
        let same_origin = initial_url.scheme() == current_url.scheme()
            && initial_url.host_str().map(|s| s.to_ascii_lowercase())
                == current_url.host_str().map(|s| s.to_ascii_lowercase())
            && initial_url.port_or_known_default() == current_url.port_or_known_default();

        if same_origin {
            return true;
        }

        if let Some(host) = current_url.host_str() {
            let host_lower = host.to_ascii_lowercase();
            if self.config.trusted_hosts.contains(&host_lower) {
                return true;
            }
            if let Some(port) = current_url.port_or_known_default() {
                if self.config.trusted_hosts.contains(&format!("{host_lower}:{port}")) {
                    return true;
                }
            }
            for scoped_reg in self.config.scoped_registries.values() {
                if let Some(shost) = scoped_reg.host_str() {
                    if shost.eq_ignore_ascii_case(host) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Execute a request under semaphore permit with redirect security and retry backoff.
    pub async fn execute_with_permit(
        &self,
        method: Method,
        initial_url: Url,
        accept_header: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<(Response, OwnedSemaphorePermit), RegistryError> {
        let permit = self.acquire_permit().await?;
        let resp = self
            .execute_request_loop(method, initial_url, accept_header, if_none_match)
            .await?;
        Ok((resp, permit))
    }

    /// Internal request dispatch loop with redirect security policy, circuit breaking, and retry backoff.
    async fn execute_request_loop(
        &self,
        method: Method,
        initial_url: Url,
        accept_header: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Response, RegistryError> {
        let host_key = if let Some(port) = initial_url.port() {
            format!("{}:{}", initial_url.host_str().unwrap_or_default(), port).to_ascii_lowercase()
        } else {
            initial_url.host_str().unwrap_or_default().to_ascii_lowercase()
        };

        if self.config.circuit_breaker_enabled {
            let state = self.circuit_breaker.check_state(&host_key).await;
            if state == CircuitBreakerState::Open {
                return Err(RegistryError::CircuitBreakerOpen {
                    host: host_key,
                });
            }
        }

        let mut attempt = 0;

        loop {
            let mut current_url = initial_url.clone();
            let mut redirect_count = 0;

            let response_result: Result<Response, RegistryError> = loop {
                let mut req = self.client.request(method.clone(), current_url.clone());

                if let Some(accept) = accept_header {
                    req = req.header(ACCEPT, accept);
                }

                if let Some(etag) = if_none_match {
                    req = req.header(IF_NONE_MATCH, etag);
                }

                // Security check: only send auth headers if the target is trusted (same origin or in trusted_hosts)
                let should_send_auth = self.is_trusted_target(&initial_url, &current_url);

                if should_send_auth {
                    if let Some(token) = self.auth_token_for_url(&current_url) {
                        req = req.header(AUTHORIZATION, format!("Bearer {token}"));
                    }
                } else {
                    debug!(
                        "Stripping Authorization header on redirect from '{}' to untrusted '{}'",
                        initial_url, current_url
                    );
                }

                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => break Err(RegistryError::Http(e)),
                };

                let status = resp.status();

                if status.is_redirection() && status != StatusCode::NOT_MODIFIED {
                    redirect_count += 1;
                    if redirect_count > MAX_REDIRECTS {
                        break Err(RegistryError::TooManyRedirects(MAX_REDIRECTS));
                    }

                    if let Some(location) = resp.headers().get(LOCATION) {
                        let loc_str = match location.to_str() {
                            Ok(s) => s,
                            Err(_) => {
                                break Err(RegistryError::SecurityViolation(
                                    "Invalid characters in redirect Location header".into(),
                                ))
                            }
                        };
                        let next_url = match current_url.join(loc_str) {
                            Ok(u) => u,
                            Err(e) => break Err(RegistryError::UrlParse(e)),
                        };
                        debug!("Following redirect {} -> {}", current_url, next_url);
                        current_url = next_url;
                        continue;
                    } else {
                        break Err(RegistryError::ServerError {
                            status: status.as_u16(),
                            body: "Redirect response missing Location header".into(),
                        });
                    }
                }

                break Ok(resp);
            };

            match response_result {
                Ok(resp) => {
                    let status = resp.status();

                    // Check for retryable HTTP status codes (429, 502, 503, 504)
                    let is_rate_limited = status == StatusCode::TOO_MANY_REQUESTS;
                    let is_retryable_server_error = self.config.retry_on_status.contains(&status.as_u16())
                        || status == StatusCode::SERVICE_UNAVAILABLE
                        || status == StatusCode::BAD_GATEWAY
                        || status == StatusCode::GATEWAY_TIMEOUT;

                    if is_rate_limited {
                        let retry_after_secs = resp
                            .headers()
                            .get(RETRY_AFTER)
                            .and_then(|h| h.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok());

                        let within_backoff_budget = if let Some(secs) = retry_after_secs {
                            Duration::from_secs(secs) <= self.config.max_retry_backoff
                        } else {
                            true
                        };

                        if within_backoff_budget && attempt < self.config.max_retries {
                            let delay = if let Some(secs) = retry_after_secs {
                                Duration::from_secs(secs)
                            } else {
                                (self.config.initial_retry_backoff * 2u32.saturating_pow(attempt as u32))
                                    .min(self.config.max_retry_backoff)
                            };
                            debug!(
                                "HTTP 429 Rate limited for {}, retrying in {:?} (attempt {}/{})",
                                initial_url, delay, attempt + 1, self.config.max_retries
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        } else {
                            if self.config.circuit_breaker_enabled {
                                self.circuit_breaker.record_failure(&host_key).await;
                            }
                            return Err(RegistryError::RateLimited { retry_after: retry_after_secs });
                        }
                    } else if is_retryable_server_error {
                        let retry_after_secs = resp
                            .headers()
                            .get(RETRY_AFTER)
                            .and_then(|h| h.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok());

                        let within_backoff_budget = if let Some(secs) = retry_after_secs {
                            Duration::from_secs(secs) <= self.config.max_retry_backoff
                        } else {
                            true
                        };

                        if within_backoff_budget && attempt < self.config.max_retries {
                            let delay = if let Some(secs) = retry_after_secs {
                                Duration::from_secs(secs)
                            } else {
                                (self.config.initial_retry_backoff * 2u32.saturating_pow(attempt as u32))
                                    .min(self.config.max_retry_backoff)
                            };
                            debug!(
                                "HTTP {} on {}, retrying in {:?} (attempt {}/{})",
                                status.as_u16(), initial_url, delay, attempt + 1, self.config.max_retries
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        } else {
                            if self.config.circuit_breaker_enabled {
                                self.circuit_breaker.record_failure(&host_key).await;
                            }
                            return Ok(resp);
                        }
                    }

                    if self.config.circuit_breaker_enabled {
                        self.circuit_breaker.record_success(&host_key).await;
                    }
                    return Ok(resp);
                }
                Err(err) => {
                    // Check if network error is transient and retryable
                    if err.is_transient() && attempt < self.config.max_retries {
                        let delay = (self.config.initial_retry_backoff * 2u32.saturating_pow(attempt as u32))
                            .min(self.config.max_retry_backoff);
                        debug!(
                            "Request error {:?} for {}, retrying in {:?} (attempt {}/{})",
                            err, initial_url, delay, attempt + 1, self.config.max_retries
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    } else {
                        if self.config.circuit_breaker_enabled {
                            self.circuit_breaker.record_failure(&host_key).await;
                        }
                        return Err(err);
                    }
                }
            }
        }
    }

    /// Execute a request following redirects manually and enforcing the security rule:
    /// Never forward auth headers across redirects to untrusted hostnames.
    pub async fn execute_with_security_policy(
        &self,
        method: Method,
        initial_url: Url,
        accept_header: Option<&str>,
    ) -> Result<Response, RegistryError> {
        let (resp, _permit) = self
            .execute_with_permit(method, initial_url, accept_header, None)
            .await?;
        Ok(resp)
    }

    /// Execute a request with optional ETag conditional header (`If-None-Match`).
    pub async fn execute_with_security_policy_conditional(
        &self,
        method: Method,
        initial_url: Url,
        accept_header: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Response, RegistryError> {
        let (resp, _permit) = self
            .execute_with_permit(method, initial_url, accept_header, if_none_match)
            .await?;
        Ok(resp)
    }

    /// Fetch abbreviated install metadata for a package from the default registry.
    pub async fn get_package_metadata(
        &self,
        package_name: &str,
    ) -> Result<AbbreviatedPackageMetadata, RegistryError> {
        let url = self.package_metadata_url(package_name)?;
        self.get_package_metadata_from_url(package_name, url).await
    }

    /// Fetch abbreviated install metadata conditionally using ETag (`If-None-Match`).
    pub async fn get_package_metadata_conditional(
        &self,
        package_name: &str,
        if_none_match: Option<&str>,
    ) -> Result<MetadataFetchResult, RegistryError> {
        let url = self.package_metadata_url(package_name)?;
        self.get_package_metadata_from_url_conditional(package_name, url, if_none_match)
            .await
    }

    /// Fetch abbreviated install metadata from an explicit URL.
    pub async fn get_package_metadata_from_url(
        &self,
        package_name: &str,
        url: Url,
    ) -> Result<AbbreviatedPackageMetadata, RegistryError> {
        match self
            .get_package_metadata_from_url_conditional(package_name, url, None)
            .await?
        {
            MetadataFetchResult::Fresh { metadata, .. } => Ok(metadata),
            MetadataFetchResult::NotModified { .. } => Err(RegistryError::Other(
                "Unexpected 304 Not Modified response for unconditional request".into(),
            )),
        }
    }

    /// Fetch abbreviated install metadata from an explicit URL with ETag conditional validation.
    pub async fn get_package_metadata_from_url_conditional(
        &self,
        package_name: &str,
        url: Url,
        if_none_match: Option<&str>,
    ) -> Result<MetadataFetchResult, RegistryError> {
        let mut attempt = 0;
        loop {
            let (resp, _permit) = self
                .execute_with_permit(
                    Method::GET,
                    url.clone(),
                    Some(NPM_INSTALL_V1_JSON),
                    if_none_match,
                )
                .await?;

            let status = resp.status();
            if status == StatusCode::NOT_MODIFIED {
                let etag = resp
                    .headers()
                    .get(ETAG)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
                    .or_else(|| if_none_match.map(|s| s.to_string()));
                return Ok(MetadataFetchResult::NotModified { etag });
            }

            if status == StatusCode::NOT_FOUND {
                return Err(RegistryError::PackageNotFound {
                    package: package_name.to_string(),
                    status: 404,
                });
            }

            if status == StatusCode::UNAUTHORIZED {
                let msg = resp.text().await.unwrap_or_default();
                return Err(RegistryError::Unauthorized {
                    url: url.to_string(),
                    status: 401,
                    message: msg,
                });
            }

            if status == StatusCode::FORBIDDEN {
                let msg = resp.text().await.unwrap_or_default();
                return Err(RegistryError::Forbidden {
                    url: url.to_string(),
                    status: 403,
                    message: msg,
                });
            }

            if status == StatusCode::TOO_MANY_REQUESTS {
                let retry_after = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                return Err(RegistryError::RateLimited { retry_after });
            }

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(RegistryError::ServerError {
                    status: status.as_u16(),
                    body,
                });
            }

            let etag = resp
                .headers()
                .get(ETAG)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    let reg_err = RegistryError::Http(e);
                    if reg_err.is_transient() && attempt < self.config.max_retries {
                        let delay = (self.config.initial_retry_backoff * 2u32.saturating_pow(attempt as u32))
                            .min(self.config.max_retry_backoff);
                        debug!(
                            "Metadata body truncated for {}, retrying in {:?} (attempt {}/{})",
                            url, delay, attempt + 1, self.config.max_retries
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(reg_err);
                }
            };

            let metadata: AbbreviatedPackageMetadata = serde_json::from_slice(&bytes)
                .map_err(RegistryError::Json)?;
            return Ok(MetadataFetchResult::Fresh { metadata, etag });
        }
    }

    /// Fetch abbreviated install metadata for multiple packages concurrently with bounded concurrency.
    pub async fn get_package_metadata_concurrent<S: AsRef<str>>(
        &self,
        packages: &[S],
    ) -> Vec<Result<AbbreviatedPackageMetadata, RegistryError>> {
        let mut join_set = tokio::task::JoinSet::new();
        for (idx, pkg) in packages.iter().enumerate() {
            let client = self.clone();
            let name = pkg.as_ref().to_string();
            join_set.spawn(async move {
                let res = client.get_package_metadata(&name).await;
                (idx, res)
            });
        }

        let mut results: Vec<Option<Result<AbbreviatedPackageMetadata, RegistryError>>> =
            (0..packages.len()).map(|_| None).collect();

        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, result)) = res {
                results[idx] = Some(result);
            }
        }

        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(RegistryError::Other("Task cancelled".into()))))
            .collect()
    }

    /// Download a tarball stream from URL, safely following redirects.
    pub async fn download_tarball(&self, tarball_url: &str) -> Result<Response, RegistryError> {
        let (resp, _permit) = self.download_tarball_stream(tarball_url).await?;
        Ok(resp)
    }

    /// Download a tarball stream while maintaining an owned concurrency permit.
    pub async fn download_tarball_stream(
        &self,
        tarball_url: &str,
    ) -> Result<(Response, OwnedSemaphorePermit), RegistryError> {
        let url = Url::parse(tarball_url)?;
        let (resp, permit) = self
            .execute_with_permit(Method::GET, url.clone(), None, None)
            .await?;

        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Err(RegistryError::PackageNotFound {
                package: tarball_url.to_string(),
                status: 404,
            });
        }

        if status == StatusCode::UNAUTHORIZED {
            let msg = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Unauthorized {
                url: url.to_string(),
                status: 401,
                message: msg,
            });
        }

        if status == StatusCode::FORBIDDEN {
            let msg = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Forbidden {
                url: url.to_string(),
                status: 403,
                message: msg,
            });
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = resp
                .headers()
                .get(RETRY_AFTER)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            return Err(RegistryError::RateLimited { retry_after });
        }

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RegistryError::ServerError {
                status: status.as_u16(),
                body,
            });
        }

        Ok((resp, permit))
    }

    /// Download a tarball response conditionally using ETag (`If-None-Match`).
    pub async fn download_tarball_conditional(
        &self,
        tarball_url: &str,
        if_none_match: Option<&str>,
    ) -> Result<TarballFetchResult, RegistryError> {
        let url = Url::parse(tarball_url)?;
        let (resp, _permit) = self
            .execute_with_permit(Method::GET, url.clone(), None, if_none_match)
            .await?;

        let status = resp.status();
        if status == StatusCode::NOT_MODIFIED {
            let etag = resp
                .headers()
                .get(ETAG)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .or_else(|| if_none_match.map(|s| s.to_string()));
            return Ok(TarballFetchResult::NotModified { etag });
        }

        if status == StatusCode::NOT_FOUND {
            return Err(RegistryError::PackageNotFound {
                package: tarball_url.to_string(),
                status: 404,
            });
        }

        if status == StatusCode::UNAUTHORIZED {
            let msg = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Unauthorized {
                url: url.to_string(),
                status: 401,
                message: msg,
            });
        }

        if status == StatusCode::FORBIDDEN {
            let msg = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Forbidden {
                url: url.to_string(),
                status: 403,
                message: msg,
            });
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = resp
                .headers()
                .get(RETRY_AFTER)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            return Err(RegistryError::RateLimited { retry_after });
        }

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RegistryError::ServerError {
                status: status.as_u16(),
                body,
            });
        }

        let etag = resp
            .headers()
            .get(ETAG)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        Ok(TarballFetchResult::Modified {
            response: resp,
            etag,
        })
    }

    /// Download tarball directly to memory bytes.
    pub async fn download_tarball_bytes(&self, tarball_url: &str) -> Result<Vec<u8>, RegistryError> {
        match self
            .download_tarball_bytes_conditional(tarball_url, None)
            .await?
        {
            BytesFetchResult::Fresh { bytes, .. } => Ok(bytes),
            BytesFetchResult::NotModified { .. } => Err(RegistryError::Other(
                "Unexpected 304 Not Modified response for unconditional tarball request".into(),
            )),
        }
    }

    /// Download tarball directly to memory bytes with ETag conditional validation.
    pub async fn download_tarball_bytes_conditional(
        &self,
        tarball_url: &str,
        if_none_match: Option<&str>,
    ) -> Result<BytesFetchResult, RegistryError> {
        let url = Url::parse(tarball_url)?;
        let mut attempt = 0;
        loop {
            let (resp, _permit) = self
                .execute_with_permit(Method::GET, url.clone(), None, if_none_match)
                .await?;

            let status = resp.status();
            if status == StatusCode::NOT_MODIFIED {
                let etag = resp
                    .headers()
                    .get(ETAG)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
                    .or_else(|| if_none_match.map(|s| s.to_string()));
                return Ok(BytesFetchResult::NotModified { etag });
            }

            if status == StatusCode::NOT_FOUND {
                return Err(RegistryError::PackageNotFound {
                    package: tarball_url.to_string(),
                    status: 404,
                });
            }

            if status == StatusCode::UNAUTHORIZED {
                let msg = resp.text().await.unwrap_or_default();
                return Err(RegistryError::Unauthorized {
                    url: url.to_string(),
                    status: 401,
                    message: msg,
                });
            }

            if status == StatusCode::FORBIDDEN {
                let msg = resp.text().await.unwrap_or_default();
                return Err(RegistryError::Forbidden {
                    url: url.to_string(),
                    status: 403,
                    message: msg,
                });
            }

            if status == StatusCode::TOO_MANY_REQUESTS {
                let retry_after = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                return Err(RegistryError::RateLimited { retry_after });
            }

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(RegistryError::ServerError {
                    status: status.as_u16(),
                    body,
                });
            }

            let etag = resp
                .headers()
                .get(ETAG)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    let reg_err = RegistryError::Http(e);
                    if reg_err.is_transient() && attempt < self.config.max_retries {
                        let delay = (self.config.initial_retry_backoff * 2u32.saturating_pow(attempt as u32))
                            .min(self.config.max_retry_backoff);
                        debug!(
                            "Tarball body truncated for {}, retrying in {:?} (attempt {}/{})",
                            tarball_url, delay, attempt + 1, self.config.max_retries
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(reg_err);
                }
            };

            return Ok(BytesFetchResult::Fresh {
                bytes: bytes.to_vec(),
                etag,
            });
        }
    }

    /// Download multiple tarballs concurrently with bounded concurrency.
    pub async fn download_tarballs_concurrent<S: AsRef<str>>(
        &self,
        tarball_urls: &[S],
    ) -> Vec<Result<Vec<u8>, RegistryError>> {
        let mut join_set = tokio::task::JoinSet::new();
        for (idx, url) in tarball_urls.iter().enumerate() {
            let client = self.clone();
            let url_str = url.as_ref().to_string();
            join_set.spawn(async move {
                let res = client.download_tarball_bytes(&url_str).await;
                (idx, res)
            });
        }

        let mut results: Vec<Option<Result<Vec<u8>, RegistryError>>> =
            (0..tarball_urls.len()).map(|_| None).collect();

        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, result)) = res {
                results[idx] = Some(result);
            }
        }

        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(RegistryError::Other("Task cancelled".into()))))
            .collect()
    }

    /// Download tarball stream directly to a destination file on disk.
    pub async fn download_tarball_to_file(
        &self,
        tarball_url: &str,
        dest_path: &Path,
    ) -> Result<u64, RegistryError> {
        let url = Url::parse(tarball_url)?;
        let mut attempt = 0;
        loop {
            let (mut resp, _permit) = self
                .execute_with_permit(Method::GET, url.clone(), None, None)
                .await?;

            let status = resp.status();
            if status == StatusCode::NOT_FOUND {
                return Err(RegistryError::PackageNotFound {
                    package: tarball_url.to_string(),
                    status: 404,
                });
            }

            if status == StatusCode::UNAUTHORIZED {
                let msg = resp.text().await.unwrap_or_default();
                return Err(RegistryError::Unauthorized {
                    url: url.to_string(),
                    status: 401,
                    message: msg,
                });
            }

            if status == StatusCode::FORBIDDEN {
                let msg = resp.text().await.unwrap_or_default();
                return Err(RegistryError::Forbidden {
                    url: url.to_string(),
                    status: 403,
                    message: msg,
                });
            }

            if status == StatusCode::TOO_MANY_REQUESTS {
                let retry_after = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                return Err(RegistryError::RateLimited { retry_after });
            }

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(RegistryError::ServerError {
                    status: status.as_u16(),
                    body,
                });
            }

            if let Some(parent) = dest_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    RegistryError::Other(format!("Failed to create directories for {}: {e}", dest_path.display()))
                })?;
            }

            let mut file = tokio::fs::File::create(dest_path).await.map_err(|e| {
                RegistryError::Other(format!("Failed to create {}: {e}", dest_path.display()))
            })?;

            let mut written: u64 = 0;
            let mut stream_err = None;
            loop {
                match resp.chunk().await {
                    Ok(Some(chunk)) => {
                        if let Err(e) = file.write_all(&chunk).await {
                            return Err(RegistryError::Other(format!("Failed to write chunk to {}: {e}", dest_path.display())));
                        }
                        written += chunk.len() as u64;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        stream_err = Some(RegistryError::Http(e));
                        break;
                    }
                }
            }

            if let Some(err) = stream_err {
                if err.is_transient() && attempt < self.config.max_retries {
                    let delay = (self.config.initial_retry_backoff * 2u32.saturating_pow(attempt as u32))
                        .min(self.config.max_retry_backoff);
                    debug!(
                        "Tarball stream dropped mid-download for {}, retrying in {:?} (attempt {}/{})",
                        tarball_url, delay, attempt + 1, self.config.max_retries
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Err(err);
            }

            file.flush().await.map_err(|e| {
                RegistryError::Other(format!("Failed to flush {}: {e}", dest_path.display()))
            })?;

            return Ok(written);
        }
    }

    /// Download multiple tarballs directly to disk destinations concurrently with bounded concurrency.
    pub async fn download_tarballs_to_files_concurrent(
        &self,
        downloads: &[(&str, &Path)],
    ) -> Vec<Result<u64, RegistryError>> {
        let mut join_set = tokio::task::JoinSet::new();
        for (idx, (url, dest)) in downloads.iter().enumerate() {
            let client = self.clone();
            let url_str = url.to_string();
            let dest_buf = dest.to_path_buf();
            join_set.spawn(async move {
                let res = client.download_tarball_to_file(&url_str, &dest_buf).await;
                (idx, res)
            });
        }

        let mut results: Vec<Option<Result<u64, RegistryError>>> =
            (0..downloads.len()).map(|_| None).collect();

        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, result)) = res {
                results[idx] = Some(result);
            }
        }

        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(RegistryError::Other("Task cancelled".into()))))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_package_name() {
        assert_eq!(encode_package_name("lodash"), "lodash");
        assert_eq!(encode_package_name("@scope/pkg"), "@scope%2fpkg");
        assert_eq!(encode_package_name("@npmcli/arborist"), "@npmcli%2farborist");
        assert_eq!(encode_package_name("my-package-123"), "my-package-123");
    }

    #[test]
    fn test_package_metadata_url() {
        let client = RegistryClient::new().unwrap();
        let url = client.package_metadata_url("lodash").unwrap();
        assert_eq!(url.as_str(), "https://registry.npmjs.org/lodash");

        let scoped_url = client.package_metadata_url("@scope/pkg").unwrap();
        assert_eq!(
            scoped_url.as_str(),
            "https://registry.npmjs.org/@scope%2fpkg"
        );
    }

    #[test]
    fn test_client_config_defaults_and_keepalive() {
        let config = RegistryClientConfig::default();
        assert_eq!(config.max_concurrent_requests, DEFAULT_MAX_CONCURRENT_REQUESTS);
        assert_eq!(config.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
        assert_eq!(config.tcp_keepalive, Duration::from_secs(DEFAULT_TCP_KEEPALIVE_SECS));
        assert_eq!(config.pool_idle_timeout, Duration::from_secs(DEFAULT_POOL_IDLE_TIMEOUT_SECS));
        assert_eq!(config.connect_timeout, Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS));
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
        assert!(config.retry_on_status.contains(&429));
        assert!(config.retry_on_status.contains(&503));
    }

    #[tokio::test]
    async fn test_client_retry_transient_503_recovers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    let resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else {
                    let body = r#"{"name":"pkg","dist-tags":{"latest":"1.0.0"},"versions":{}}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            }
        });

        let config = RegistryClientConfig {
            default_registry: Url::parse(&format!("http://{addr}/")).unwrap(),
            user_agent: "test-client".into(),
            max_retries: 2,
            initial_retry_backoff: Duration::from_millis(5),
            max_retry_backoff: Duration::from_millis(20),
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let client = RegistryClient::with_config(config).unwrap();
        let meta = client.get_package_metadata("pkg").await.unwrap();
        assert_eq!(meta.name, "pkg");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_client_no_retry_on_404_not_found() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                attempts_clone.fetch_add(1, Ordering::SeqCst);
                let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        let config = RegistryClientConfig {
            default_registry: Url::parse(&format!("http://{addr}/")).unwrap(),
            user_agent: "test-client".into(),
            max_retries: 3,
            initial_retry_backoff: Duration::from_millis(5),
            max_retry_backoff: Duration::from_millis(20),
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let client = RegistryClient::with_config(config).unwrap();
        let res = client.get_package_metadata("nonexistent-pkg").await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.is_not_found());
        assert!(!err.is_transient());
        // 404 should never be retried, exactly 1 attempt
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_client_retry_body_stream_drop_recovers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    // Send header with Content-Length 100, but only 10 bytes then close connection
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 100\r\n\r\n0123456789";
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.flush().await;
                    drop(stream);
                } else {
                    let payload = b"complete-tarball-stream-payload";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                        payload.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.write_all(payload).await;
                }
            }
        });

        let config = RegistryClientConfig {
            default_registry: Url::parse(&format!("http://{addr}/")).unwrap(),
            user_agent: "test-client".into(),
            max_retries: 2,
            initial_retry_backoff: Duration::from_millis(5),
            max_retry_backoff: Duration::from_millis(20),
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let client = RegistryClient::with_config(config).unwrap();
        let tarball_url = format!("http://{addr}/tarball.tgz");
        let bytes = client.download_tarball_bytes(&tarball_url).await.unwrap();
        assert_eq!(bytes, b"complete-tarball-stream-payload");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}
