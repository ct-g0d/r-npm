use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerState};
use crate::error::RegistryError;
use crate::metadata::AbbreviatedPackageMetadata;
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, ETAG, IF_NONE_MATCH,
    LOCATION, RETRY_AFTER, USER_AGENT,
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

/// Default maximum package size allowed for tarball downloads (512 MB).
pub const DEFAULT_MAX_PACKAGE_SIZE: u64 = 512 * 1024 * 1024;

/// Default maximum metadata size allowed for packument JSON (16 MB).
pub const DEFAULT_MAX_METADATA_SIZE: usize = 16 * 1024 * 1024;

/// Default chunk idle timeout for streaming sockets (10 seconds).
pub const DEFAULT_CHUNK_IDLE_TIMEOUT_SECS: u64 = 10;

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

/// Tarball download stream holding an owned concurrency semaphore permit.
///
/// Holding the permit tied to the stream guarantees that active streaming sockets
/// do not leak concurrency permits or bypass maximum concurrency limits.
#[derive(Debug)]
pub struct TarballStream {
    pub response: Response,
    pub permit: OwnedSemaphorePermit,
}

impl TarballStream {
    pub fn new(response: Response, permit: OwnedSemaphorePermit) -> Self {
        Self { response, permit }
    }

    pub fn response(&self) -> &Response {
        &self.response
    }

    pub fn response_mut(&mut self) -> &mut Response {
        &mut self.response
    }

    pub fn into_parts(self) -> (Response, OwnedSemaphorePermit) {
        (self.response, self.permit)
    }

    pub fn into_response(self) -> Response {
        self.response
    }

    pub async fn chunk(&mut self) -> Result<Option<bytes::Bytes>, reqwest::Error> {
        self.response.chunk().await
    }
}

impl std::ops::Deref for TarballStream {
    type Target = Response;
    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

impl std::ops::DerefMut for TarballStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.response
    }
}

/// Result of a conditional tarball response fetch.
#[derive(Debug)]
pub enum TarballFetchResult {
    /// Server returned fresh tarball response (HTTP 200 OK) with optional ETag and held permit.
    Modified {
        response: Response,
        etag: Option<String>,
        permit: OwnedSemaphorePermit,
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

    pub fn response(&self) -> Option<&Response> {
        match self {
            Self::Modified { response, .. } => Some(response),
            Self::NotModified { .. } => None,
        }
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
    pub max_package_size: u64,
    pub max_metadata_size: usize,
    pub chunk_idle_timeout: Duration,
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
            max_package_size: DEFAULT_MAX_PACKAGE_SIZE,
            max_metadata_size: DEFAULT_MAX_METADATA_SIZE,
            chunk_idle_timeout: Duration::from_secs(DEFAULT_CHUNK_IDLE_TIMEOUT_SECS),
        }
    }
}

/// Helper to convert year, month (1..=12), day (1..=31) to days since Unix epoch (1970-01-01).
pub fn days_from_civil(mut y: i64, m: u64, d: u64) -> i64 {
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Helper to convert days since Unix epoch to civil date (year, month, day).
pub fn civil_from_days(days: i64) -> (i64, u64, u64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

fn parse_month_name(token: &str) -> Option<u64> {
    match token.to_ascii_lowercase().as_str() {
        "jan" | "january" => Some(1),
        "feb" | "february" => Some(2),
        "mar" | "march" => Some(3),
        "apr" | "april" => Some(4),
        "may" => Some(5),
        "jun" | "june" => Some(6),
        "jul" | "july" => Some(7),
        "aug" | "august" => Some(8),
        "sep" | "september" => Some(9),
        "oct" | "october" => Some(10),
        "nov" | "november" => Some(11),
        "dec" | "december" => Some(12),
        _ => None,
    }
}

/// Formats a `SystemTime` as an HTTP-date string (IMF-fixdate format, e.g. "Sun, 06 Nov 1994 08:49:37 GMT").
pub fn format_http_date(st: std::time::SystemTime) -> String {
    let unix_secs = st
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = unix_secs.div_euclid(86400);
    let rem_secs = unix_secs.rem_euclid(86400);
    let hour = rem_secs / 3600;
    let min = (rem_secs % 3600) / 60;
    let sec = rem_secs % 60;

    let (y, m, d) = civil_from_days(days);
    let day_of_week = ((days + 4).rem_euclid(7)) as usize;
    let weekdays = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let wk = weekdays[day_of_week];
    let mon = months[(m.saturating_sub(1) as usize).min(11)];
    format!("{wk}, {:02} {mon} {y} {:02}:{:02}:{:02} GMT", d, hour, min, sec)
}

/// Parses an HTTP-date string (IMF-fixdate, RFC 850, or ANSI C asctime, and RFC 2822)
/// into a Unix timestamp (seconds since Unix epoch 1970-01-01 00:00:00 UTC).
pub fn parse_http_date_to_unix_timestamp(s: &str) -> Option<i64> {
    let cleaned: String = s
        .chars()
        .map(|c| if c == ',' || c == '-' { ' ' } else { c })
        .collect();
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    let mut month = None;
    let mut month_idx = None;
    for (i, tok) in tokens.iter().enumerate() {
        if let Some(m) = parse_month_name(tok) {
            month = Some(m);
            month_idx = Some(i);
            break;
        }
    }
    let month = month?;
    let month_idx = month_idx?;

    let mut time = None;
    let mut time_idx = None;
    for (i, tok) in tokens.iter().enumerate() {
        if tok.contains(':') && !tok.starts_with('+') && !tok.starts_with('-') {
            let parts: Vec<&str> = tok.split(':').collect();
            if parts.len() == 2 || parts.len() == 3 {
                if let (Ok(h), Ok(m)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>()) {
                    let s = if parts.len() == 3 {
                        parts[2].parse::<u64>().ok()?
                    } else {
                        0
                    };
                    if h < 24 && m < 60 && s <= 60 {
                        time = Some((h, m, s));
                        time_idx = Some(i);
                        break;
                    }
                }
            }
        }
    }
    let (hour, min, sec) = time?;
    let time_idx = time_idx?;

    let mut day: Option<u64> = None;
    let mut year: Option<i64> = None;

    if month_idx > 0 && tokens[month_idx - 1].chars().all(|c| c.is_ascii_digit()) {
        day = tokens[month_idx - 1].parse::<u64>().ok();
        for (i, tok) in tokens.iter().enumerate().skip(month_idx + 1) {
            if i != time_idx && tok.chars().all(|c| c.is_ascii_digit()) {
                year = tok.parse::<i64>().ok();
                break;
            }
        }
    } else {
        if month_idx + 1 < tokens.len() && tokens[month_idx + 1].chars().all(|c| c.is_ascii_digit()) {
            day = tokens[month_idx + 1].parse::<u64>().ok();
        }
        for tok in tokens.iter().skip(time_idx + 1) {
            if tok.chars().all(|c| c.is_ascii_digit()) {
                year = tok.parse::<i64>().ok();
                break;
            }
        }
    }

    let day = day?;
    let mut year = year?;
    if !(1..=31).contains(&day) {
        return None;
    }
    if year < 70 {
        year += 2000;
    } else if year < 100 {
        year += 1900;
    }

    let mut tz_offset_secs: i64 = 0;
    for tok in tokens.iter().skip(time_idx + 1) {
        let t = tok.trim();
        if t.eq_ignore_ascii_case("gmt") || t.eq_ignore_ascii_case("utc") || t == "Z" {
            tz_offset_secs = 0;
            break;
        }
        if t.starts_with('+') || t.starts_with('-') {
            let sign = if t.starts_with('-') { -1 } else { 1 };
            let num_str = &t[1..];
            let offset_parts: Vec<&str> = num_str.split(':').collect();
            if offset_parts.len() == 2 {
                if let (Ok(h), Ok(m)) = (offset_parts[0].parse::<i64>(), offset_parts[1].parse::<i64>()) {
                    tz_offset_secs = sign * (h * 3600 + m * 60);
                    break;
                }
            } else if num_str.len() == 4 {
                if let (Ok(h), Ok(m)) = (num_str[0..2].parse::<i64>(), num_str[2..4].parse::<i64>()) {
                    tz_offset_secs = sign * (h * 3600 + m * 60);
                    break;
                }
            }
        }
    }

    let days = days_from_civil(year, month, day);
    let total_secs = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64) - tz_offset_secs;
    Some(total_secs)
}

/// Parses an HTTP-date string into duration in seconds relative to current time.
pub fn parse_http_date_to_seconds_from_now(s: &str) -> Option<u64> {
    let unix_secs = parse_http_date_to_unix_timestamp(s)?;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let diff = unix_secs - now_secs;
    Some(if diff > 0 { diff as u64 } else { 0 })
}

/// Parses a `Retry-After` header value which may be either integer seconds (e.g. `120`)
/// or an HTTP-date string (e.g. `Wed, 21 Oct 2025 07:28:00 GMT`).
pub fn parse_retry_after(header: Option<&HeaderValue>) -> Option<u64> {
    let s = header?.to_str().ok()?.trim();
    parse_retry_after_str(s)
}

/// Parses a `Retry-After` string which may be either integer seconds or an HTTP-date.
pub fn parse_retry_after_str(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Some(secs);
    }
    parse_http_date_to_seconds_from_now(s)
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

    /// Check whether a host is trusted to receive registry authorization headers.
    /// A host is trusted if it matches the default registry, is listed in `trusted_hosts`,
    /// or matches one of the `scoped_registries`.
    pub fn is_trusted_host(&self, url: &Url) -> bool {
        let host = match url.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => return false,
        };

        if let Some(reg_host) = self.config.default_registry.host_str() {
            if reg_host.eq_ignore_ascii_case(&host)
                && self.config.default_registry.port_or_known_default() == url.port_or_known_default()
            {
                return true;
            }
        }

        if let Some(port) = url.port_or_known_default() {
            if self.config.trusted_hosts.contains(&format!("{host}:{port}")) {
                return true;
            }
        }
        if self.config.trusted_hosts.contains(&host) {
            return true;
        }

        for scoped_reg in self.config.scoped_registries.values() {
            if let Some(shost) = scoped_reg.host_str() {
                if shost.eq_ignore_ascii_case(&host)
                    && scoped_reg.port_or_known_default() == url.port_or_known_default()
                {
                    return true;
                }
            }
        }

        false
    }

    /// Retrieve the auth token for a target URL if configured in `auth_tokens` or fallback to `auth_token`.
    /// Never returns the fallback registry auth token to untrusted hosts.
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

        // Hardening: Fallback to self.config.auth_token ONLY if the host is trusted
        if self.is_trusted_host(url) {
            self.config.auth_token.as_deref()
        } else {
            None
        }
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
    /// When following redirects or downloading tarballs, never forward registry auth token
    /// to untrusted cross-origin hosts.
    pub fn is_trusted_target(&self, initial_url: &Url, current_url: &Url) -> bool {
        let host = match current_url.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => return false,
        };

        // If explicitly defined in auth_tokens map for this URL, that specific host token is allowed
        let has_explicit_token = {
            let port_part = if let Some(port) = current_url.port() {
                format!(":{port}")
            } else {
                String::new()
            };
            let path = current_url.path();
            let normalized_path = if path.ends_with('/') {
                path.to_string()
            } else {
                format!("{path}/")
            };
            self.config.auth_tokens.contains_key(&format!("//{host}{port_part}{normalized_path}"))
                || self.config.auth_tokens.contains_key(&format!("//{host}{port_part}{path}"))
                || self.config.auth_tokens.contains_key(&format!("//{host}{port_part}/"))
                || (!port_part.is_empty() && self.config.auth_tokens.contains_key(&format!("//{host}/")))
        };

        if has_explicit_token {
            return true;
        }

        // To receive the registry auth token, BOTH initial_url and current_url MUST be trusted hosts!
        if !self.is_trusted_host(initial_url) || !self.is_trusted_host(current_url) {
            return false;
        }

        let same_origin = initial_url.scheme() == current_url.scheme()
            && initial_url.host_str().map(|s| s.to_ascii_lowercase())
                == current_url.host_str().map(|s| s.to_ascii_lowercase())
            && initial_url.port_or_known_default() == current_url.port_or_known_default();

        if same_origin {
            return true;
        }

        self.is_trusted_host(current_url)
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
            let mut seen_redirect_urls: HashSet<Url> = HashSet::new();
            seen_redirect_urls.insert(current_url.clone());

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
                        if loc_str.contains('\r') || loc_str.contains('\n') {
                            break Err(RegistryError::SecurityViolation(
                                "Location header contains forbidden CR/LF characters".into(),
                            ));
                        }
                        let next_url = match current_url.join(loc_str) {
                            Ok(u) => u,
                            Err(e) => break Err(RegistryError::UrlParse(e)),
                        };
                        let next_scheme = next_url.scheme().to_ascii_lowercase();
                        if next_scheme != "http" && next_scheme != "https" {
                            break Err(RegistryError::SecurityViolation(format!(
                                "Redirect to unsupported scheme '{next_scheme}': only http and https are allowed"
                            )));
                        }
                        if !seen_redirect_urls.insert(next_url.clone()) {
                            break Err(RegistryError::SecurityViolation(format!(
                                "Redirect loop detected: '{next_url}' was visited more than once"
                            )));
                        }
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
                        || status.is_server_error();

                    if is_rate_limited {
                        let retry_after_secs = parse_retry_after(resp.headers().get(RETRY_AFTER));

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
                        let retry_after_secs = parse_retry_after(resp.headers().get(RETRY_AFTER));

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
                    if attempt < self.config.max_retries {
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
        let (mut resp, _permit) = self
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
            let retry_after = parse_retry_after(resp.headers().get(RETRY_AFTER));
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

        let expected_content_length = resp
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| resp.content_length());

        if let Some(content_length) = expected_content_length {
            if content_length > self.config.max_metadata_size as u64 {
                return Err(RegistryError::SizeLimitExceeded {
                    limit: self.config.max_metadata_size as u64,
                    actual: content_length,
                    message: format!("Metadata Content-Length for package '{package_name}' exceeds maximum metadata size"),
                });
            }
        }

        let mut bytes = Vec::new();
        loop {
            let chunk_res = tokio::time::timeout(
                self.config.chunk_idle_timeout,
                resp.chunk(),
            ).await;

            let chunk_opt = match chunk_res {
                Ok(Ok(chunk)) => chunk,
                Ok(Err(e)) => return Err(RegistryError::Http(e)),
                Err(_) => {
                    return Err(RegistryError::SlowlorisTimeout(self.config.chunk_idle_timeout));
                }
            };

            match chunk_opt {
                Some(chunk) => {
                    if bytes.len() + chunk.len() > self.config.max_metadata_size {
                        return Err(RegistryError::SizeLimitExceeded {
                            limit: self.config.max_metadata_size as u64,
                            actual: (bytes.len() + chunk.len()) as u64,
                            message: format!("Metadata payload for package '{package_name}' exceeds maximum metadata size"),
                        });
                    }
                    bytes.extend_from_slice(&chunk);
                }
                None => break,
            }
        }

        if let Some(content_length) = expected_content_length {
            if bytes.len() as u64 != content_length {
                return Err(RegistryError::ContentLengthMismatch {
                    expected: content_length,
                    actual: bytes.len() as u64,
                });
            }
        }

        let metadata: AbbreviatedPackageMetadata = serde_json::from_slice(&bytes)?;
        metadata.validate()?;
        Ok(MetadataFetchResult::Fresh { metadata, etag })
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
    pub async fn download_tarball(&self, tarball_url: &str) -> Result<TarballStream, RegistryError> {
        self.download_tarball_stream(tarball_url).await
    }

    /// Download a tarball stream while maintaining an owned concurrency permit.
    pub async fn download_tarball_stream(
        &self,
        tarball_url: &str,
    ) -> Result<TarballStream, RegistryError> {
        let url = Url::parse(tarball_url)?;
        let scheme = url.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(RegistryError::SecurityViolation(format!(
                "Invalid tarball URL scheme '{scheme}': only http and https are allowed"
            )));
        }

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
            let retry_after = parse_retry_after(resp.headers().get(RETRY_AFTER));
            return Err(RegistryError::RateLimited { retry_after });
        }

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RegistryError::ServerError {
                status: status.as_u16(),
                body,
            });
        }

        Ok(TarballStream { response: resp, permit })
    }

    /// Download a tarball response conditionally using ETag (`If-None-Match`).
    pub async fn download_tarball_conditional(
        &self,
        tarball_url: &str,
        if_none_match: Option<&str>,
    ) -> Result<TarballFetchResult, RegistryError> {
        let url = Url::parse(tarball_url)?;
        let scheme = url.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(RegistryError::SecurityViolation(format!(
                "Invalid tarball URL scheme '{scheme}': only http and https are allowed"
            )));
        }

        let (resp, permit) = self
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
            let retry_after = parse_retry_after(resp.headers().get(RETRY_AFTER));
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
            permit,
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
        let scheme = url.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(RegistryError::SecurityViolation(format!(
                "Invalid tarball URL scheme '{scheme}': only http and https are allowed"
            )));
        }

        let host_key = if let Some(port) = url.port() {
            format!("{}:{}", url.host_str().unwrap_or_default(), port).to_ascii_lowercase()
        } else {
            url.host_str().unwrap_or_default().to_ascii_lowercase()
        };

        let mut stream_attempt = 0;
        loop {
            let (mut resp, _permit) = self
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
                let retry_after = parse_retry_after(resp.headers().get(RETRY_AFTER));
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

            let expected_content_length = resp
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| resp.content_length());

            if let Some(content_length) = expected_content_length {
                if content_length > self.config.max_package_size {
                    return Err(RegistryError::SizeLimitExceeded {
                        limit: self.config.max_package_size,
                        actual: content_length,
                        message: format!("Tarball Content-Length for '{tarball_url}' exceeds maximum package size"),
                    });
                }
            }

            let mut bytes = Vec::new();
            let mut stream_err = None;

            loop {
                let chunk_res = tokio::time::timeout(
                    self.config.chunk_idle_timeout,
                    resp.chunk(),
                ).await;

                let chunk_opt = match chunk_res {
                    Ok(Ok(opt)) => opt,
                    Ok(Err(err)) => {
                        stream_err = Some(RegistryError::Http(err));
                        break;
                    }
                    Err(_) => {
                        stream_err = Some(RegistryError::SlowlorisTimeout(self.config.chunk_idle_timeout));
                        break;
                    }
                };

                match chunk_opt {
                    Some(chunk) => {
                        if (bytes.len() as u64) + (chunk.len() as u64) > self.config.max_package_size {
                            stream_err = Some(RegistryError::SizeLimitExceeded {
                                limit: self.config.max_package_size,
                                actual: (bytes.len() as u64) + (chunk.len() as u64),
                                message: format!("Tarball payload for '{tarball_url}' exceeds maximum package size"),
                            });
                            break;
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    None => break,
                }
            }

            if let Some(err) = stream_err {
                match err {
                    RegistryError::Http(err) => {
                        if stream_attempt < self.config.max_retries {
                            let delay = (self.config.initial_retry_backoff * 2u32.saturating_pow(stream_attempt as u32))
                                .min(self.config.max_retry_backoff);
                            debug!(
                                "Stream download error {:?} for {}, retrying stream in {:?} (attempt {}/{})",
                                err, url, delay, stream_attempt + 1, self.config.max_retries
                            );
                            tokio::time::sleep(delay).await;
                            stream_attempt += 1;
                            continue;
                        } else {
                            if self.config.circuit_breaker_enabled {
                                self.circuit_breaker.record_failure(&host_key).await;
                            }
                            return Err(RegistryError::Http(err));
                        }
                    }
                    non_retryable => return Err(non_retryable),
                }
            }

            if let Some(content_length) = expected_content_length {
                if bytes.len() as u64 != content_length {
                    return Err(RegistryError::ContentLengthMismatch {
                        expected: content_length,
                        actual: bytes.len() as u64,
                    });
                }
            }

            return Ok(BytesFetchResult::Fresh { bytes, etag });
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
        let scheme = url.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(RegistryError::SecurityViolation(format!(
                "Invalid tarball URL scheme '{scheme}': only http and https are allowed"
            )));
        }

        let host_key = if let Some(port) = url.port() {
            format!("{}:{}", url.host_str().unwrap_or_default(), port).to_ascii_lowercase()
        } else {
            url.host_str().unwrap_or_default().to_ascii_lowercase()
        };

        let parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            RegistryError::Other(format!("Failed to create directories for {}: {e}", dest_path.display()))
        })?;

        let temp_path = {
            let file_name = dest_path
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("download");
            parent.join(format!("{file_name}.part"))
        };

        let mut stream_attempt = 0;
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
                let retry_after = parse_retry_after(resp.headers().get(RETRY_AFTER));
                return Err(RegistryError::RateLimited { retry_after });
            }

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(RegistryError::ServerError {
                    status: status.as_u16(),
                    body,
                });
            }

            let expected_content_length = resp
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| resp.content_length());

            if let Some(content_length) = expected_content_length {
                if content_length > self.config.max_package_size {
                    return Err(RegistryError::SizeLimitExceeded {
                        limit: self.config.max_package_size,
                        actual: content_length,
                        message: format!("Tarball Content-Length for '{tarball_url}' exceeds maximum package size"),
                    });
                }
            }

            let mut file = tokio::fs::File::create(&temp_path).await.map_err(|e| {
                RegistryError::Other(format!("Failed to create {}: {e}", temp_path.display()))
            })?;

            let mut written: u64 = 0;
            let mut stream_err = None;

            loop {
                let chunk_res = tokio::time::timeout(
                    self.config.chunk_idle_timeout,
                    resp.chunk(),
                ).await;

                let chunk_opt = match chunk_res {
                    Ok(Ok(opt)) => opt,
                    Ok(Err(err)) => {
                        stream_err = Some(RegistryError::Http(err));
                        break;
                    }
                    Err(_) => {
                        stream_err = Some(RegistryError::SlowlorisTimeout(self.config.chunk_idle_timeout));
                        break;
                    }
                };

                match chunk_opt {
                    Some(chunk) => {
                        if written + (chunk.len() as u64) > self.config.max_package_size {
                            stream_err = Some(RegistryError::SizeLimitExceeded {
                                limit: self.config.max_package_size,
                                actual: written + (chunk.len() as u64),
                                message: format!("Tarball payload for '{tarball_url}' exceeds maximum package size"),
                            });
                            break;
                        }
                        if let Err(e) = file.write_all(&chunk).await {
                            stream_err = Some(RegistryError::Other(format!(
                                "Failed to write chunk to {}: {e}",
                                temp_path.display()
                            )));
                            break;
                        }
                        written += chunk.len() as u64;
                    }
                    None => break,
                }
            }

            if let Some(err) = stream_err {
                drop(file);
                let _ = tokio::fs::remove_file(&temp_path).await;

                match err {
                    RegistryError::Http(err) => {
                        if stream_attempt < self.config.max_retries {
                            let delay = (self.config.initial_retry_backoff * 2u32.saturating_pow(stream_attempt as u32))
                                .min(self.config.max_retry_backoff);
                            debug!(
                                "Stream download to file error {:?} for {}, retrying stream in {:?} (attempt {}/{})",
                                err, url, delay, stream_attempt + 1, self.config.max_retries
                            );
                            tokio::time::sleep(delay).await;
                            stream_attempt += 1;
                            continue;
                        } else {
                            if self.config.circuit_breaker_enabled {
                                self.circuit_breaker.record_failure(&host_key).await;
                            }
                            return Err(RegistryError::Http(err));
                        }
                    }
                    non_retryable => return Err(non_retryable),
                }
            }

            if let Some(content_length) = expected_content_length {
                if written != content_length {
                    drop(file);
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    return Err(RegistryError::ContentLengthMismatch {
                        expected: content_length,
                        actual: written,
                    });
                }
            }

            file.flush().await.map_err(|e| {
                RegistryError::Other(format!("Failed to flush {}: {e}", temp_path.display()))
            })?;
            drop(file);

            tokio::fs::rename(&temp_path, dest_path).await.map_err(|e| {
                RegistryError::Other(format!(
                    "Failed to rename {} to {}: {e}",
                    temp_path.display(),
                    dest_path.display()
                ))
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

    #[test]
    fn test_parse_retry_after_integer_seconds() {
        assert_eq!(parse_retry_after_str("120"), Some(120));
        assert_eq!(parse_retry_after_str("0"), Some(0));
        assert_eq!(parse_retry_after_str("  45  "), Some(45));
    }

    #[test]
    fn test_parse_retry_after_http_date_formats() {
        // Known historical timestamp: Sun, 06 Nov 1994 08:49:37 GMT -> 784111777
        assert_eq!(
            parse_http_date_to_unix_timestamp("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784111777)
        );
        // RFC 850 format
        assert_eq!(
            parse_http_date_to_unix_timestamp("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(784111777)
        );
        // ANSI C asctime format
        assert_eq!(
            parse_http_date_to_unix_timestamp("Sun Nov  6 08:49:37 1994"),
            Some(784111777)
        );

        // Historical dates in the past resolve to 0 seconds from now
        assert_eq!(
            parse_retry_after_str("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(0)
        );

        // Date in future relative to now
        let future_time = std::time::SystemTime::now() + Duration::from_secs(30);
        let http_date = format_http_date(future_time);
        let parsed_secs = parse_retry_after_str(&http_date).expect("should parse future HTTP-date");
        assert!(
            parsed_secs >= 28 && parsed_secs <= 31,
            "Expected ~30s, got {parsed_secs}"
        );
    }
}
