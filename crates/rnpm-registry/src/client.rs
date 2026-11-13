use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerState};
use crate::error::RegistryError;
use crate::metadata::AbbreviatedPackageMetadata;
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, ETAG,
    IF_NONE_MATCH, LOCATION, RETRY_AFTER, USER_AGENT,
};
use reqwest::{Client, Method, Response, StatusCode};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
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
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 64;

/// Default maximum idle connections per host in the connection pool.
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 128;

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

/// Default maximum metadata size allowed for packument JSON (64 MB).
///
/// Large real-world packuments such as Next.js exceed 16 MB. Keep a bounded
/// streaming limit for denial-of-service protection while matching npm's
/// ability to consume large registry metadata documents.
pub const DEFAULT_MAX_METADATA_SIZE: usize = 64 * 1024 * 1024;

/// Global atomic counter for HTTP requests dispatched by the registry client.
pub static HTTP_REQUEST_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Returns the total number of HTTP requests dispatched since process start or last reset.
pub fn http_request_count() -> usize {
    HTTP_REQUEST_COUNT.load(std::sync::atomic::Ordering::SeqCst)
}

/// Resets the global HTTP request counter to zero.
pub fn reset_http_request_count() {
    HTTP_REQUEST_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
}

fn track_http_request(method: &Method, url: &Url) {
    let count = HTTP_REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    if std::env::var("RNPM_COUNT_HTTP").is_ok() || std::env::var("RNPM_TIMING_DEBUG").is_ok() {
        eprintln!("[http-request #{count}] {method} {url}");
    }
}

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
    NotModified { etag: Option<String> },
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
    NotModified { etag: Option<String> },
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
    NotModified { etag: Option<String> },
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
    /// URI-scoped Basic credentials (base64 `user:password`).
    pub basic_auths: std::collections::BTreeMap<String, String>,
    pub circuit_breaker_enabled: bool,
    pub circuit_breaker_failure_threshold: usize,
    pub circuit_breaker_reset_timeout: Duration,
    pub max_package_size: u64,
    pub max_metadata_size: usize,
    pub chunk_idle_timeout: Duration,
    pub proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub http_proxy: Option<String>,
    pub no_proxy: Option<String>,
    pub ca: Option<String>,
    pub cafile: Option<PathBuf>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub strict_ssl: bool,
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
            basic_auths: std::collections::BTreeMap::new(),
            circuit_breaker_enabled: false,
            circuit_breaker_failure_threshold: 5,
            circuit_breaker_reset_timeout: Duration::from_secs(30),
            max_package_size: DEFAULT_MAX_PACKAGE_SIZE,
            max_metadata_size: DEFAULT_MAX_METADATA_SIZE,
            chunk_idle_timeout: Duration::from_secs(DEFAULT_CHUNK_IDLE_TIMEOUT_SECS),
            proxy: None,
            https_proxy: None,
            http_proxy: None,
            no_proxy: None,
            ca: None,
            cafile: None,
            cert: None,
            key: None,
            strict_ssl: true,
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
    format!(
        "{wk}, {:02} {mon} {y} {:02}:{:02}:{:02} GMT",
        d, hour, min, sec
    )
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
        if month_idx + 1 < tokens.len() && tokens[month_idx + 1].chars().all(|c| c.is_ascii_digit())
        {
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
                if let (Ok(h), Ok(m)) = (
                    offset_parts[0].parse::<i64>(),
                    offset_parts[1].parse::<i64>(),
                ) {
                    tz_offset_secs = sign * (h * 3600 + m * 60);
                    break;
                }
            } else if num_str.len() == 4 {
                if let (Ok(h), Ok(m)) = (num_str[0..2].parse::<i64>(), num_str[2..4].parse::<i64>())
                {
                    tz_offset_secs = sign * (h * 3600 + m * 60);
                    break;
                }
            }
        }
    }

    let days = days_from_civil(year, month, day);
    let total_secs =
        days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64) - tz_offset_secs;
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
    http_requests: std::sync::Arc<std::sync::atomic::AtomicU64>,
    http_304s: std::sync::Arc<std::sync::atomic::AtomicU64>,
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
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

        let max_idle = if config.pool_max_idle_per_host == 0 {
            DEFAULT_POOL_MAX_IDLE_PER_HOST
        } else {
            config.pool_max_idle_per_host
        };

        // We disable reqwest's automatic redirect following so that we can enforce
        // the strict security rule: NEVER forward auth headers across redirects to untrusted hostnames.
        let mut builder = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .tcp_nodelay(true)
            .tcp_keepalive(Some(config.tcp_keepalive))
            .pool_idle_timeout(Some(config.pool_idle_timeout))
            .pool_max_idle_per_host(max_idle);

        if !config.strict_ssl {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(https_proxy) = &config.https_proxy {
            let mut proxy = reqwest::Proxy::https(https_proxy).map_err(|err| {
                RegistryError::Other(format!("Invalid https_proxy '{https_proxy}': {err}"))
            })?;
            if let Some(no_proxy) = &config.no_proxy {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy));
            }
            builder = builder.proxy(proxy);
        }

        if let Some(http_proxy) = &config.http_proxy {
            let mut proxy = reqwest::Proxy::http(http_proxy).map_err(|err| {
                RegistryError::Other(format!("Invalid http_proxy '{http_proxy}': {err}"))
            })?;
            if let Some(no_proxy) = &config.no_proxy {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy));
            }
            builder = builder.proxy(proxy);
        }

        if let Some(general_proxy) = &config.proxy {
            if config.https_proxy.is_none() && config.http_proxy.is_none() {
                let mut proxy = reqwest::Proxy::all(general_proxy).map_err(|err| {
                    RegistryError::Other(format!("Invalid proxy '{general_proxy}': {err}"))
                })?;
                if let Some(no_proxy) = &config.no_proxy {
                    proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy));
                }
                builder = builder.proxy(proxy);
            } else if config.http_proxy.is_none() {
                let mut proxy = reqwest::Proxy::http(general_proxy).map_err(|err| {
                    RegistryError::Other(format!("Invalid proxy '{general_proxy}': {err}"))
                })?;
                if let Some(no_proxy) = &config.no_proxy {
                    proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy));
                }
                builder = builder.proxy(proxy);
            } else if config.https_proxy.is_none() {
                let mut proxy = reqwest::Proxy::https(general_proxy).map_err(|err| {
                    RegistryError::Other(format!("Invalid proxy '{general_proxy}': {err}"))
                })?;
                if let Some(no_proxy) = &config.no_proxy {
                    proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy));
                }
                builder = builder.proxy(proxy);
            }
        }

        if let Some(cafile_path) = &config.cafile {
            let pem_bytes = std::fs::read(cafile_path).map_err(|err| {
                RegistryError::Other(format!(
                    "Failed to read cafile at '{}': {err}",
                    cafile_path.display()
                ))
            })?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem_bytes).unwrap_or_default();
            if certs.is_empty() {
                return Err(RegistryError::Other(format!(
                    "No PEM certificates found in cafile '{}'",
                    cafile_path.display()
                )));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        if let Some(ca_content_or_path) = &config.ca {
            let pem_bytes = if Path::new(ca_content_or_path).exists() {
                std::fs::read(ca_content_or_path).map_err(|err| {
                    RegistryError::Other(format!(
                        "Failed to read CA path '{ca_content_or_path}': {err}"
                    ))
                })?
            } else {
                ca_content_or_path.as_bytes().to_vec()
            };
            let certs = reqwest::Certificate::from_pem_bundle(&pem_bytes).unwrap_or_default();
            if certs.is_empty() {
                return Err(RegistryError::Other(
                    "No PEM certificates found in ca configuration".to_string(),
                ));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        if let (Some(cert_str), Some(key_str)) = (&config.cert, &config.key) {
            let cert_content = if Path::new(cert_str).exists() {
                std::fs::read_to_string(cert_str).map_err(|err| {
                    RegistryError::Other(format!("Failed to read cert file '{cert_str}': {err}"))
                })?
            } else {
                cert_str.clone()
            };

            let key_content = if Path::new(key_str).exists() {
                std::fs::read_to_string(key_str).map_err(|err| {
                    RegistryError::Other(format!("Failed to read key file '{key_str}': {err}"))
                })?
            } else {
                key_str.clone()
            };

            let combined_pem = format!("{}\n{}", cert_content.trim(), key_content.trim());
            let identity = reqwest::Identity::from_pem(combined_pem.as_bytes()).map_err(|err| {
                RegistryError::Other(format!(
                    "Failed to parse client certificate and key into Identity: {err}"
                ))
            })?;
            builder = builder.identity(identity);
        }

        let client = builder.build()?;

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
        let circuit_breaker =
            CircuitBreaker::new(failure_threshold, config.circuit_breaker_reset_timeout);

        Ok(Self {
            client,
            config,
            semaphore,
            circuit_breaker,
            http_requests: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            http_304s: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Access the client configuration.
    pub fn config(&self) -> &RegistryClientConfig {
        &self.config
    }

    /// Returns the total number of HTTP requests issued by this client.
    pub fn http_requests(&self) -> u64 {
        self.http_requests.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns the total number of HTTP 304 (Not Modified) responses received.
    pub fn http_304s(&self) -> u64 {
        self.http_304s.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reset HTTP request and 304 counters.
    pub fn reset_http_metrics(&self) {
        self.http_requests.store(0, std::sync::atomic::Ordering::Relaxed);
        self.http_304s.store(0, std::sync::atomic::Ordering::Relaxed);
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
                && self.config.default_registry.port_or_known_default()
                    == url.port_or_known_default()
            {
                return true;
            }
        }

        if let Some(port) = url.port_or_known_default() {
            if self
                .config
                .trusted_hosts
                .contains(&format!("{host}:{port}"))
            {
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

    /// The `Authorization` value npm would send: a Bearer token when one is
    /// configured, otherwise URI-scoped Basic credentials.
    pub fn auth_header_for_url(&self, url: &Url) -> Option<String> {
        if let Some(token) = self.auth_token_for_url(url) {
            return Some(format!("Bearer {token}"));
        }
        let host = url.host_str()?.to_ascii_lowercase();
        let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let mut path = url.path().to_string();
        loop {
            let key = format!("//{host}{port}{}", if path.ends_with('/') { path.clone() } else { format!("{path}/") });
            if let Some(basic) = self.config.basic_auths.get(&key) {
                return Some(format!("Basic {basic}"));
            }
            if path == "/" || path.is_empty() {
                return None;
            }
            let trimmed = path.trim_end_matches('/');
            path = match trimmed.rfind('/') {
                Some(i) => trimmed[..=i].to_string(),
                None => "/".to_string(),
            };
        }
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
            self.config
                .auth_tokens
                .contains_key(&format!("//{host}{port_part}{normalized_path}"))
                || self
                    .config
                    .auth_tokens
                    .contains_key(&format!("//{host}{port_part}{path}"))
                || self
                    .config
                    .auth_tokens
                    .contains_key(&format!("//{host}{port_part}/"))
                || (!port_part.is_empty()
                    && self.config.auth_tokens.contains_key(&format!("//{host}/")))
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

    /// Execute a request with an explicit body, content-type, and optional OTP header under semaphore permit.
    pub async fn execute_with_body_permit(
        &self,
        method: Method,
        initial_url: Url,
        content_type: Option<&str>,
        accept_header: Option<&str>,
        otp: Option<&str>,
        body: Vec<u8>,
    ) -> Result<(Response, OwnedSemaphorePermit), RegistryError> {
        let permit = self.acquire_permit().await?;
        let resp = self
            .execute_request_loop_with_body(
                method,
                initial_url,
                content_type,
                accept_header,
                otp,
                body,
            )
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
            initial_url
                .host_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
        };

        if self.config.circuit_breaker_enabled {
            let state = self.circuit_breaker.check_state(&host_key).await;
            if state == CircuitBreakerState::Open {
                return Err(RegistryError::CircuitBreakerOpen { host: host_key });
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
                    if let Some(auth) = self.auth_header_for_url(&current_url) {
                        req = req.header(AUTHORIZATION, auth);
                    }
                } else {
                    debug!(
                        "Stripping Authorization header on redirect from '{}' to untrusted '{}'",
                        initial_url, current_url
                    );
                }

                track_http_request(&method, &current_url);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => break Err(RegistryError::Http(e)),
                };

                self.http_requests
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let status = resp.status();
                if status == StatusCode::NOT_MODIFIED {
                    self.http_304s
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }

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
                    let is_retryable_server_error =
                        self.config.retry_on_status.contains(&status.as_u16())
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
                                (self.config.initial_retry_backoff
                                    * 2u32.saturating_pow(attempt as u32))
                                .min(self.config.max_retry_backoff)
                            };
                            debug!(
                                "HTTP 429 Rate limited for {}, retrying in {:?} (attempt {}/{})",
                                initial_url,
                                delay,
                                attempt + 1,
                                self.config.max_retries
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        } else {
                            if self.config.circuit_breaker_enabled {
                                self.circuit_breaker.record_failure(&host_key).await;
                            }
                            return Err(RegistryError::RateLimited {
                                retry_after: retry_after_secs,
                            });
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
                                (self.config.initial_retry_backoff
                                    * 2u32.saturating_pow(attempt as u32))
                                .min(self.config.max_retry_backoff)
                            };
                            debug!(
                                "HTTP {} on {}, retrying in {:?} (attempt {}/{})",
                                status.as_u16(),
                                initial_url,
                                delay,
                                attempt + 1,
                                self.config.max_retries
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
                        let delay = (self.config.initial_retry_backoff
                            * 2u32.saturating_pow(attempt as u32))
                        .min(self.config.max_retry_backoff);
                        debug!(
                            "Request error {:?} for {}, retrying in {:?} (attempt {}/{})",
                            err,
                            initial_url,
                            delay,
                            attempt + 1,
                            self.config.max_retries
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    } else {
                        if self.config.circuit_breaker_enabled && err.is_transient() {
                            self.circuit_breaker.record_failure(&host_key).await;
                        }
                        return Err(err);
                    }
                }
            }
        }
    }

    /// Internal request dispatch loop with body, content-type, and optional OTP.
    async fn execute_request_loop_with_body(
        &self,
        method: Method,
        initial_url: Url,
        content_type: Option<&str>,
        accept_header: Option<&str>,
        otp: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Response, RegistryError> {
        let host_key = if let Some(port) = initial_url.port() {
            format!("{}:{}", initial_url.host_str().unwrap_or_default(), port).to_ascii_lowercase()
        } else {
            initial_url
                .host_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
        };

        if self.config.circuit_breaker_enabled {
            let state = self.circuit_breaker.check_state(&host_key).await;
            if state == CircuitBreakerState::Open {
                return Err(RegistryError::CircuitBreakerOpen { host: host_key });
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

                if let Some(ct) = content_type {
                    req = req.header(CONTENT_TYPE, ct);
                }

                if let Some(accept) = accept_header {
                    req = req.header(ACCEPT, accept);
                }

                if let Some(otp_code) = otp {
                    req = req.header("npm-otp", otp_code);
                }

                // Security check: only send auth headers if the target is trusted (same origin or in trusted_hosts)
                let should_send_auth = self.is_trusted_target(&initial_url, &current_url);

                if should_send_auth {
                    if let Some(auth) = self.auth_header_for_url(&current_url) {
                        req = req.header(AUTHORIZATION, auth);
                    }
                } else {
                    debug!(
                        "Stripping Authorization header on redirect from '{}' to untrusted '{}'",
                        initial_url, current_url
                    );
                }

                req = req.body(body.clone());

                track_http_request(&method, &current_url);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => break Err(RegistryError::Http(e)),
                };

                self.http_requests
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let status = resp.status();
                if status == StatusCode::NOT_MODIFIED {
                    self.http_304s
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }

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

                    let is_rate_limited = status == StatusCode::TOO_MANY_REQUESTS;
                    let is_retryable_server_error =
                        self.config.retry_on_status.contains(&status.as_u16())
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
                                (self.config.initial_retry_backoff
                                    * 2u32.saturating_pow(attempt as u32))
                                .min(self.config.max_retry_backoff)
                            };
                            debug!(
                                "HTTP 429 Rate limited for {}, retrying in {:?} (attempt {}/{})",
                                initial_url,
                                delay,
                                attempt + 1,
                                self.config.max_retries
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        } else {
                            if self.config.circuit_breaker_enabled {
                                self.circuit_breaker.record_failure(&host_key).await;
                            }
                            return Err(RegistryError::RateLimited {
                                retry_after: retry_after_secs,
                            });
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
                                (self.config.initial_retry_backoff
                                    * 2u32.saturating_pow(attempt as u32))
                                .min(self.config.max_retry_backoff)
                            };
                            debug!(
                                "HTTP {} on {}, retrying in {:?} (attempt {}/{})",
                                status.as_u16(),
                                initial_url,
                                delay,
                                attempt + 1,
                                self.config.max_retries
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
                    if err.is_transient() && attempt < self.config.max_retries {
                        let delay = (self.config.initial_retry_backoff
                            * 2u32.saturating_pow(attempt as u32))
                        .min(self.config.max_retry_backoff);
                        debug!(
                            "Request error {:?} for {}, retrying in {:?} (attempt {}/{})",
                            err,
                            initial_url,
                            delay,
                            attempt + 1,
                            self.config.max_retries
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    } else {
                        if self.config.circuit_breaker_enabled && err.is_transient() {
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
        self.get_package_metadata_from_url_conditional_with_accept(
            package_name,
            url,
            if_none_match,
            NPM_INSTALL_V1_JSON,
        )
        .await
    }

    /// Fetch the full npm packument when lockfile metadata omitted by the
    /// abbreviated install representation is required (license/libc/etc.).
    pub async fn get_package_metadata_full(
        &self,
        package_name: &str,
    ) -> Result<AbbreviatedPackageMetadata, RegistryError> {
        match self
            .get_package_metadata_full_conditional(package_name, None)
            .await?
        {
            MetadataFetchResult::Fresh { metadata, .. } => Ok(metadata),
            MetadataFetchResult::NotModified { .. } => Err(RegistryError::Other(
                "Unexpected 304 Not Modified response for full metadata request".into(),
            )),
        }
    }

    /// Arborist resolves manifests from full packuments, including lockfile
    /// fields absent from the abbreviated install representation.
    pub async fn get_package_metadata_full_conditional(
        &self,
        package_name: &str,
        if_none_match: Option<&str>,
    ) -> Result<MetadataFetchResult, RegistryError> {
        let url = self.package_metadata_url(package_name)?;
        self.get_package_metadata_from_url_conditional_with_accept(
            package_name,
            url,
            if_none_match,
            "application/json",
        )
        .await
    }

    async fn get_package_metadata_from_url_conditional_with_accept(
        &self,
        package_name: &str,
        url: Url,
        if_none_match: Option<&str>,
        accept_header: &str,
    ) -> Result<MetadataFetchResult, RegistryError> {
        let host_key = if let Some(port) = url.port() {
            format!("{}:{}", url.host_str().unwrap_or_default(), port).to_ascii_lowercase()
        } else {
            url.host_str().unwrap_or_default().to_ascii_lowercase()
        };

        let mut stream_attempt = 0;
        loop {
            let (mut resp, _permit) = self
                .execute_with_permit(Method::GET, url.clone(), Some(accept_header), if_none_match)
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
            let mut stream_err: Option<RegistryError> = None;
            loop {
                let chunk_res =
                    tokio::time::timeout(self.config.chunk_idle_timeout, resp.chunk()).await;

                let chunk_opt = match chunk_res {
                    Ok(Ok(chunk)) => chunk,
                    Ok(Err(e)) => {
                        stream_err = Some(RegistryError::Http(e));
                        break;
                    }
                    Err(_) => {
                        stream_err = Some(RegistryError::SlowlorisTimeout(
                            self.config.chunk_idle_timeout,
                        ));
                        break;
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

            if let Some(err) = stream_err {
                if err.is_transient() && stream_attempt < self.config.max_retries {
                    let delay = (self.config.initial_retry_backoff
                        * 2u32.saturating_pow(stream_attempt as u32))
                    .min(self.config.max_retry_backoff);
                    debug!(
                    "Stream metadata error {:?} for {}, retrying stream in {:?} (attempt {}/{})",
                    err, url, delay, stream_attempt + 1, self.config.max_retries
                );
                    tokio::time::sleep(delay).await;
                    stream_attempt += 1;
                    continue;
                } else {
                    if self.config.circuit_breaker_enabled && err.is_transient() {
                        self.circuit_breaker.record_failure(&host_key).await;
                    }
                    return Err(err);
                }
            }

            if let Some(content_length) = expected_content_length {
                if bytes.len() as u64 != content_length {
                    let mismatch_err = RegistryError::ContentLengthMismatch {
                        expected: content_length,
                        actual: bytes.len() as u64,
                    };
                    if mismatch_err.is_transient() && stream_attempt < self.config.max_retries {
                        let delay = (self.config.initial_retry_backoff
                            * 2u32.saturating_pow(stream_attempt as u32))
                        .min(self.config.max_retry_backoff);
                        tokio::time::sleep(delay).await;
                        stream_attempt += 1;
                        continue;
                    } else {
                        return Err(mismatch_err);
                    }
                }
            }

            let metadata: AbbreviatedPackageMetadata = serde_json::from_slice(&bytes)?;
            metadata.validate()?;
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

    /// Fetch abbreviated install metadata for multiple packages concurrently using conditional ETag revalidation.
    pub async fn get_package_metadata_conditional_concurrent<S: AsRef<str>>(
        &self,
        packages: &[(S, Option<String>)],
    ) -> Vec<Result<MetadataFetchResult, RegistryError>> {
        self.get_package_metadata_conditional_concurrent_with_accept(packages, NPM_INSTALL_V1_JSON)
            .await
    }

    pub async fn get_package_metadata_full_conditional_concurrent<S: AsRef<str>>(
        &self,
        packages: &[(S, Option<String>)],
    ) -> Vec<Result<MetadataFetchResult, RegistryError>> {
        self.get_package_metadata_conditional_concurrent_with_accept(packages, "application/json")
            .await
    }

    async fn get_package_metadata_conditional_concurrent_with_accept<S: AsRef<str>>(
        &self,
        packages: &[(S, Option<String>)],
        accept: &'static str,
    ) -> Vec<Result<MetadataFetchResult, RegistryError>> {
        let mut join_set = tokio::task::JoinSet::new();
        for (idx, (pkg, if_none_match)) in packages.iter().enumerate() {
            let client = self.clone();
            let name = pkg.as_ref().to_string();
            let etag = if_none_match.clone();
            join_set.spawn(async move {
                let res = match client.package_metadata_url(&name) {
                    Ok(url) => client
                        .get_package_metadata_from_url_conditional_with_accept(
                            &name, url, etag.as_deref(), accept,
                        )
                        .await,
                    Err(error) => Err(error),
                };
                (idx, res)
            });
        }

        let mut results: Vec<Option<Result<MetadataFetchResult, RegistryError>>> =
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
    pub async fn download_tarball(
        &self,
        tarball_url: &str,
    ) -> Result<TarballStream, RegistryError> {
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

        Ok(TarballStream {
            response: resp,
            permit,
        })
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
    pub async fn download_tarball_bytes(
        &self,
        tarball_url: &str,
    ) -> Result<Vec<u8>, RegistryError> {
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

            let mut bytes = if let Some(content_length) = expected_content_length {
                Vec::with_capacity(content_length as usize)
            } else {
                Vec::new()
            };
            let mut stream_err = None;

            loop {
                let chunk_res =
                    tokio::time::timeout(self.config.chunk_idle_timeout, resp.chunk()).await;

                let chunk_opt = match chunk_res {
                    Ok(Ok(opt)) => opt,
                    Ok(Err(err)) => {
                        stream_err = Some(RegistryError::Http(err));
                        break;
                    }
                    Err(_) => {
                        stream_err = Some(RegistryError::SlowlorisTimeout(
                            self.config.chunk_idle_timeout,
                        ));
                        break;
                    }
                };

                match chunk_opt {
                    Some(chunk) => {
                        if (bytes.len() as u64) + (chunk.len() as u64)
                            > self.config.max_package_size
                        {
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
                if err.is_transient() && stream_attempt < self.config.max_retries {
                    let delay = (self.config.initial_retry_backoff
                        * 2u32.saturating_pow(stream_attempt as u32))
                    .min(self.config.max_retry_backoff);
                    debug!(
                        "Stream download error {:?} for {}, retrying stream in {:?} (attempt {}/{})",
                        err, url, delay, stream_attempt + 1, self.config.max_retries
                    );
                    tokio::time::sleep(delay).await;
                    stream_attempt += 1;
                    continue;
                } else {
                    if self.config.circuit_breaker_enabled && err.is_transient() {
                        self.circuit_breaker.record_failure(&host_key).await;
                    }
                    return Err(err);
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
            RegistryError::Other(format!(
                "Failed to create directories for {}: {e}",
                dest_path.display()
            ))
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
                let chunk_res =
                    tokio::time::timeout(self.config.chunk_idle_timeout, resp.chunk()).await;

                let chunk_opt = match chunk_res {
                    Ok(Ok(opt)) => opt,
                    Ok(Err(err)) => {
                        stream_err = Some(RegistryError::Http(err));
                        break;
                    }
                    Err(_) => {
                        stream_err = Some(RegistryError::SlowlorisTimeout(
                            self.config.chunk_idle_timeout,
                        ));
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

                if err.is_transient() && stream_attempt < self.config.max_retries {
                    let delay = (self.config.initial_retry_backoff
                        * 2u32.saturating_pow(stream_attempt as u32))
                    .min(self.config.max_retry_backoff);
                    debug!(
                        "Stream download to file error {:?} for {}, retrying stream in {:?} (attempt {}/{})",
                        err, url, delay, stream_attempt + 1, self.config.max_retries
                    );
                    tokio::time::sleep(delay).await;
                    stream_attempt += 1;
                    continue;
                } else {
                    if self.config.circuit_breaker_enabled && err.is_transient() {
                        self.circuit_breaker.record_failure(&host_key).await;
                    }
                    return Err(err);
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

            tokio::fs::rename(&temp_path, dest_path)
                .await
                .map_err(|e| {
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

    /// Publish a package to its assigned registry (scoped or default).
    pub async fn publish(
        &self,
        package_name: &str,
        publish_payload: &serde_json::Value,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        let registry = self.registry_for_package(package_name);
        self.publish_to(registry, package_name, publish_payload, otp)
            .await
    }

    /// Publish a package to a specific registry URL.
    pub async fn publish_to(
        &self,
        registry: &Url,
        package_name: &str,
        publish_payload: &serde_json::Value,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        let encoded = encode_package_name(package_name);
        let base_str = registry.as_str().trim_end_matches('/');
        let target_url =
            Url::parse(&format!("{base_str}/{encoded}")).map_err(RegistryError::UrlParse)?;

        let body_bytes = serde_json::to_vec(publish_payload)?;

        let (resp, _permit) = self
            .execute_with_body_permit(
                Method::PUT,
                target_url.clone(),
                Some("application/json"),
                Some("application/json"),
                otp,
                body_bytes,
            )
            .await?;

        let status = resp.status();
        let retry_after = if status == StatusCode::TOO_MANY_REQUESTS {
            parse_retry_after(resp.headers().get(RETRY_AFTER))
        } else {
            None
        };

        if status.is_success() {
            return Ok(());
        }

        let body_text = resp.text().await.unwrap_or_default();

        if status == StatusCode::CONFLICT {
            return Err(RegistryError::PublishConflict {
                url: target_url.to_string(),
                status: 409,
                message: if body_text.is_empty() {
                    "Cannot publish over existing package version.".to_string()
                } else {
                    body_text
                },
            });
        }

        if status == StatusCode::UNAUTHORIZED {
            return Err(RegistryError::Unauthorized {
                url: target_url.to_string(),
                status: 401,
                message: if body_text.is_empty() {
                    format!(
                        "Authentication required to publish package to {}.",
                        registry
                    )
                } else {
                    body_text
                },
            });
        }

        if status == StatusCode::FORBIDDEN {
            return Err(RegistryError::Forbidden {
                url: target_url.to_string(),
                status: 403,
                message: if body_text.is_empty() {
                    format!("Access forbidden to publish package to {}.", registry)
                } else {
                    body_text
                },
            });
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(RegistryError::RateLimited { retry_after });
        }

        Err(RegistryError::ServerError {
            status: status.as_u16(),
            body: body_text,
        })
    }

    /// Check the logged-in username for a registry.
    pub async fn whoami(&self, registry: Option<&Url>) -> Result<String, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let base_str = reg_url.as_str().trim_end_matches('/');
        let target_url =
            Url::parse(&format!("{base_str}/-/whoami")).map_err(RegistryError::UrlParse)?;

        // Verify that we have an active auth token for this registry
        let token = self.auth_token_for_url(&target_url);
        if token.is_none() {
            return Err(RegistryError::Unauthorized {
                url: target_url.to_string(),
                status: 401,
                message: format!("This command requires you to be logged in to {}", reg_url),
            });
        }

        let (resp, _permit) = self
            .execute_with_permit(
                Method::GET,
                target_url.clone(),
                Some("application/json"),
                None,
            )
            .await?;

        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Unauthorized {
                url: target_url.to_string(),
                status: 401,
                message: if body_text.is_empty() {
                    format!("This command requires you to be logged in to {}", reg_url)
                } else {
                    body_text
                },
            });
        }

        if status == StatusCode::FORBIDDEN {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Forbidden {
                url: target_url.to_string(),
                status: 403,
                message: body_text,
            });
        }

        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(RegistryError::ServerError {
                status: status.as_u16(),
                body: body_text,
            });
        }

        let body_text = resp.text().await.unwrap_or_default();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body_text) {
            if let Some(username) = val.get("username").and_then(|u| u.as_str()) {
                return Ok(username.to_string());
            }
        }
        let trimmed = body_text.trim().trim_matches('"').to_string();
        if !trimmed.is_empty() {
            Ok(trimmed)
        } else {
            Err(RegistryError::MalformedMetadata(
                "Empty or invalid whoami response".into(),
            ))
        }
    }

    /// Ping a registry and report latency.
    pub async fn ping(&self, registry: Option<&Url>) -> Result<std::time::Duration, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let base_str = reg_url.as_str().trim_end_matches('/');
        let target_url =
            Url::parse(&format!("{base_str}/-/ping")).map_err(RegistryError::UrlParse)?;

        let start = std::time::Instant::now();
        let (resp, _permit) = self
            .execute_with_permit(
                Method::GET,
                target_url.clone(),
                Some("application/json"),
                None,
            )
            .await?;

        let elapsed = start.elapsed();
        let status = resp.status();
        if status.is_success() {
            Ok(elapsed)
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            Err(RegistryError::ServerError {
                status: status.as_u16(),
                body: body_text,
            })
        }
    }

    /// List active authentication tokens on the registry (GET /-/npm/v1/tokens).
    pub async fn token_list(
        &self,
        registry: Option<&Url>,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let base_str = reg_url.as_str().trim_end_matches('/');
        let target_url =
            Url::parse(&format!("{base_str}/-/npm/v1/tokens")).map_err(RegistryError::UrlParse)?;

        let token = self.auth_token_for_url(&target_url);
        if token.is_none() {
            return Err(RegistryError::Unauthorized {
                url: target_url.to_string(),
                status: 401,
                message: format!("This command requires you to be logged in to {}", reg_url),
            });
        }

        let (resp, _permit) = self
            .execute_with_permit(
                Method::GET,
                target_url.clone(),
                Some("application/json"),
                None,
            )
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(RegistryError::ServerError {
                status: status.as_u16(),
                body: body_text,
            });
        }

        let body_json = resp
            .json::<serde_json::Value>()
            .await
            .map_err(RegistryError::Http)?;
        Ok(body_json)
    }

    /// Delete/revoke an authentication token on the registry (DELETE /-/npm/v1/tokens/token/<key>).
    pub async fn token_revoke(
        &self,
        registry: Option<&Url>,
        token_id: &str,
    ) -> Result<(), RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let base_str = reg_url.as_str().trim_end_matches('/');
        let target_url = Url::parse(&format!("{base_str}/-/npm/v1/tokens/token/{token_id}"))
            .map_err(RegistryError::UrlParse)?;

        let token = self.auth_token_for_url(&target_url);
        if token.is_none() {
            return Err(RegistryError::Unauthorized {
                url: target_url.to_string(),
                status: 401,
                message: format!("This command requires you to be logged in to {}", reg_url),
            });
        }

        let (resp, _permit) = self
            .execute_with_permit(
                Method::DELETE,
                target_url.clone(),
                Some("application/json"),
                None,
            )
            .await?;

        let status = resp.status();
        if status.is_success() || status == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            Err(RegistryError::ServerError {
                status: status.as_u16(),
                body: body_text,
            })
        }
    }

    /// Perform npm's legacy/basic login exchange and return the registry response.
    pub async fn login_legacy(
        &self,
        registry: Option<&Url>,
        username: &str,
        password: &str,
        otp: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        validate_admin_token(username)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let target = Url::parse(&format!(
            "{}/-/user/org.couchdb.user:{}",
            reg_url.as_str().trim_end_matches('/'),
            username
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(
            Method::PUT,
            target,
            Some(serde_json::json!({
                "_id": format!("org.couchdb.user:{username}"),
                "name": username,
                "password": password,
                "type": "user",
                "roles": [],
            })),
            otp,
        )
        .await
    }

    /// List dist-tags for a package using npm's registry administration API.
    pub async fn dist_tags(
        &self,
        registry: Option<&Url>,
        package_name: &str,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let target = Url::parse(&format!(
            "{}/-/package/{}/dist-tags",
            reg_url.as_str().trim_end_matches('/'),
            encoded
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    /// Add or replace one dist-tag.
    pub async fn dist_tag_add(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        tag: &str,
        version: &str,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        validate_admin_token(tag)?;
        validate_admin_token(version)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let target = Url::parse(&format!(
            "{}/-/package/{}/dist-tags/{}",
            reg_url.as_str().trim_end_matches('/'),
            encoded,
            tag
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::PUT, target, Some(serde_json::json!(version)), otp)
            .await?;
        Ok(())
    }

    /// Remove one dist-tag.
    pub async fn dist_tag_remove(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        tag: &str,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        validate_admin_token(tag)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let target = Url::parse(&format!(
            "{}/-/package/{}/dist-tags/{}",
            reg_url.as_str().trim_end_matches('/'),
            encoded,
            tag
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::DELETE, target, None, otp)
            .await?;
        Ok(())
    }

    /// List package owners/collaborators.
    pub async fn package_owners(
        &self,
        registry: Option<&Url>,
        package_name: &str,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);

        if let Ok(pkg_url) = Url::parse(&format!(
            "{}/{}",
            reg_url.as_str().trim_end_matches('/'),
            encoded
        )) {
            if let Ok(val) = self.admin_json_request(Method::GET, pkg_url, None, None).await {
                if val.get("maintainers").is_some() {
                    return Ok(val);
                }
            }
        }

        let target = Url::parse(&format!(
            "{}/-/package/{}/collaborators?format=cli",
            reg_url.as_str().trim_end_matches('/'),
            encoded
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    /// Add a package owner/collaborator.
    pub async fn package_owner_add(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        user: &str,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        validate_admin_token(user)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let target = Url::parse(&format!(
            "{}/-/package/{}/collaborators/{}",
            reg_url.as_str().trim_end_matches('/'),
            encoded,
            user
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::PUT, target, Some(serde_json::json!({})), otp)
            .await?;
        Ok(())
    }

    /// Remove a package owner/collaborator.
    pub async fn package_owner_remove(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        user: &str,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        validate_admin_token(user)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let target = Url::parse(&format!(
            "{}/-/package/{}/collaborators/{}",
            reg_url.as_str().trim_end_matches('/'),
            encoded,
            user
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::DELETE, target, None, otp)
            .await?;
        Ok(())
    }

    /// Unpublish a package or one version.
    pub async fn unpublish(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        version: Option<&str>,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        if let Some(v) = version {
            validate_admin_token(v)?;
        }
        let base = format!("{}/{encoded}", reg_url.as_str().trim_end_matches('/'));
        let read_url = Url::parse(&format!("{base}?write=true"))?;
        let result: Result<(), RegistryError> = async {
            let mut document = self
                .admin_json_request(Method::GET, read_url.clone(), None, None)
                .await?;
            let versions = document.get("versions").and_then(|v| v.as_object());
            let count = versions.map_or(0, |v| v.len());
            let specific = version.filter(|v| *v != "*");
            let version_doc = specific.and_then(|version| versions?.get(version)).cloned();
            if specific.is_some() && version_doc.is_none() && count > 0 {
                return Ok(());
            }
            let revision = document
                .get("_rev")
                .and_then(|v| v.as_str())
                .unwrap_or("undefined");
            let write_url = Url::parse(&format!("{base}/-rev/{revision}"))?;
            if specific.is_none() || count <= 1 {
                self.admin_json_request(Method::DELETE, write_url, None, otp)
                    .await?;
                return Ok(());
            }
            let version = specific.unwrap();
            let tarball = version_doc
                .as_ref()
                .and_then(|v| v.get("dist"))
                .and_then(|v| v.get("tarball"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            if let Some(versions) = document.get_mut("versions").and_then(|v| v.as_object_mut()) {
                versions.remove(version);
            }
            let remaining_latest = document
                .get("versions")
                .and_then(|v| v.as_object())
                .into_iter()
                .flat_map(|v| v.keys())
                .filter_map(|v| rnpm_core::semver::Version::parse(v).ok())
                .max()
                .map(|v| v.to_string());
            if let Some(tags) = document
                .get_mut("dist-tags")
                .and_then(|v| v.as_object_mut())
            {
                let removed_latest = tags.get("latest").and_then(|v| v.as_str()) == Some(version);
                tags.retain(|_, value| value.as_str() != Some(version));
                if removed_latest {
                    if let Some(latest) = remaining_latest {
                        tags.insert("latest".into(), latest.into());
                    }
                }
            }
            if let Some(object) = document.as_object_mut() {
                object.remove("_revisions");
                object.remove("_attachments");
            }
            self.admin_json_request(Method::PUT, write_url, Some(document), otp)
                .await?;
            let refreshed = self
                .admin_json_request(Method::GET, read_url, None, None)
                .await?;
            let revision = refreshed
                .get("_rev")
                .and_then(|v| v.as_str())
                .unwrap_or("undefined");
            if let Some(tarball) = tarball {
                let url = Url::parse(&tarball)?;
                let relative_path = url
                    .path()
                    .strip_prefix(reg_url.path())
                    .unwrap_or(url.path().trim_start_matches('/'));
                let target = Url::parse(&format!(
                    "{}/{relative_path}/-rev/{revision}",
                    reg_url.as_str().trim_end_matches('/')
                ))?;
                self.admin_json_request(Method::DELETE, target, None, otp)
                    .await?;
            }
            Ok(())
        }
        .await;
        match result {
            Err(error) if error.status_code() == Some(404) => Ok(()),
            result => result,
        }
    }

    /// Set or clear a deprecation message on one version.
    pub async fn deprecate(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        version: &str,
        message: &str,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        validate_admin_token(version)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let package_url = Url::parse(&format!(
            "{}/{}",
            reg_url.as_str().trim_end_matches('/'),
            encoded
        ))
        .map_err(RegistryError::UrlParse)?;
        let mut document = self
            .admin_json_request(Method::GET, package_url.clone(), None, None)
            .await?;
        let versions = document
            .get_mut("versions")
            .and_then(|v| v.as_object_mut())
            .ok_or_else(|| {
                RegistryError::MalformedMetadata(
                    "registry package response has no versions object".into(),
                )
            })?;
        let version_doc = versions
            .get_mut(version)
            .ok_or_else(|| RegistryError::ServerError {
                status: 404,
                body: format!("version {version} not found"),
            })?;
        if let Some(obj) = version_doc.as_object_mut() {
            obj.insert(
                "deprecated".into(),
                serde_json::Value::String(message.into()),
            );
        }
        self.admin_json_request(Method::PUT, package_url, Some(document), otp)
            .await?;
        Ok(())
    }

    /// Read or change a package's access level.
    pub async fn package_access(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        access: Option<&str>,
        otp: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let target = Url::parse(&format!(
            "{}/-/package/{}/access",
            reg_url.as_str().trim_end_matches('/'),
            encoded
        ))
        .map_err(RegistryError::UrlParse)?;
        match access {
            Some(level) if level == "public" || level == "restricted" => {
                self.admin_json_request(
                    Method::PUT,
                    target,
                    Some(serde_json::json!({"access": level})),
                    otp,
                )
                .await
            }
            Some(_) => Err(RegistryError::MalformedMetadata(
                "access must be public or restricted".into(),
            )),
            None => {
                self.admin_json_request(Method::GET, target, None, None)
                    .await
            }
        }
    }

    /// Star a package for the authenticated user using npm's package document API.
    pub async fn star_package(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        self.update_package_star(registry, package_name, true, otp)
            .await
    }

    /// Remove a package star for the authenticated user.
    pub async fn unstar_package(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        self.update_package_star(registry, package_name, false, otp)
            .await
    }

    async fn update_package_star(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        starred: bool,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let package_url = Url::parse(&format!(
            "{}/{}",
            reg_url.as_str().trim_end_matches('/'),
            encoded
        ))
        .map_err(RegistryError::UrlParse)?;
        let username = self.whoami(Some(reg_url)).await?;
        let mut document = self
            .admin_json_request(Method::GET, package_url.clone(), None, None)
            .await?;
        let users = document
            .as_object_mut()
            .ok_or_else(|| {
                RegistryError::MalformedMetadata("package response is not an object".into())
            })?
            .entry("users")
            .or_insert_with(|| serde_json::json!({}));
        let users = users.as_object_mut().ok_or_else(|| {
            RegistryError::MalformedMetadata("package users field is not an object".into())
        })?;
        if starred {
            users.insert(username, serde_json::Value::Bool(true));
        } else {
            users.remove(&username);
        }
        // npm sends only the identity, revision, and users map for this update.
        if let Some(object) = document.as_object_mut() {
            object.retain(|key, _| matches!(key.as_str(), "_id" | "_rev" | "users"));
        }
        self.admin_json_request(Method::PUT, package_url, Some(document), otp)
            .await?;
        Ok(())
    }

    /// List packages starred by a user using npm's CouchDB starredByUser view.
    pub async fn starred_packages(
        &self,
        registry: Option<&Url>,
        user: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let username = match user {
            Some(user) => {
                validate_admin_token(user)?;
                user.to_string()
            }
            None => self.whoami(Some(reg_url)).await?,
        };
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("key", &format!("\"{username}\""));
        let target = Url::parse(&format!(
            "{}/-/_view/starredByUser?{}",
            reg_url.as_str().trim_end_matches('/'),
            query.finish()
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    /// Retrieve the authenticated user's npm profile.
    pub async fn profile_get(
        &self,
        registry: Option<&Url>,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let target = Url::parse(&format!(
            "{}/-/npm/v1/user",
            reg_url.as_str().trim_end_matches('/')
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    /// Update selected fields in the authenticated user's npm profile.
    pub async fn profile_set(
        &self,
        registry: Option<&Url>,
        profile: serde_json::Value,
        otp: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let target = Url::parse(&format!(
            "{}/-/npm/v1/user",
            reg_url.as_str().trim_end_matches('/')
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::POST, target, Some(profile), otp)
            .await
    }

    /// List organization members or change one member's role.
    pub async fn org_members(
        &self,
        registry: Option<&Url>,
        org: &str,
    ) -> Result<serde_json::Value, RegistryError> {
        let target = self.org_url(registry, org, "user")?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    pub async fn org_member_set(
        &self,
        registry: Option<&Url>,
        org: &str,
        user: &str,
        role: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        let target = self.org_url(registry, org, "user")?;
        self.admin_json_request(
            Method::PUT,
            target,
            Some(serde_json::json!({"user": user, "role": role})),
            None,
        )
        .await
    }

    pub async fn org_member_remove(
        &self,
        registry: Option<&Url>,
        org: &str,
        user: &str,
    ) -> Result<(), RegistryError> {
        let target = self.org_url(registry, org, "user")?;
        self.admin_json_request(
            Method::DELETE,
            target,
            Some(serde_json::json!({"user": user})),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn team_create(
        &self,
        registry: Option<&Url>,
        scope: &str,
        team: &str,
        description: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        let target = self.org_url(registry, scope, "team")?;
        self.admin_json_request(
            Method::PUT,
            target,
            Some(serde_json::json!({"name": team, "description": description})),
            None,
        )
        .await
    }

    pub async fn team_destroy(
        &self,
        registry: Option<&Url>,
        scope: &str,
        team: &str,
    ) -> Result<(), RegistryError> {
        let target = self.team_url(registry, scope, team, "")?;
        self.admin_json_request(Method::DELETE, target, None, None)
            .await?;
        Ok(())
    }

    pub async fn team_users(
        &self,
        registry: Option<&Url>,
        scope: &str,
        team: &str,
    ) -> Result<serde_json::Value, RegistryError> {
        let target = self.team_url(registry, scope, team, "user")?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    pub async fn teams(
        &self,
        registry: Option<&Url>,
        scope: &str,
    ) -> Result<serde_json::Value, RegistryError> {
        let target = self.org_url(registry, scope, "team")?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    pub async fn team_add_user(
        &self,
        registry: Option<&Url>,
        scope: &str,
        team: &str,
        user: &str,
    ) -> Result<serde_json::Value, RegistryError> {
        let target = self.team_url(registry, scope, team, "user")?;
        self.admin_json_request(
            Method::PUT,
            target,
            Some(serde_json::json!({"user": user})),
            None,
        )
        .await
    }

    pub async fn team_remove_user(
        &self,
        registry: Option<&Url>,
        scope: &str,
        team: &str,
        user: &str,
    ) -> Result<(), RegistryError> {
        let target = self.team_url(registry, scope, team, "user")?;
        self.admin_json_request(
            Method::DELETE,
            target,
            Some(serde_json::json!({"user": user})),
            None,
        )
        .await?;
        Ok(())
    }

    fn org_url(
        &self,
        registry: Option<&Url>,
        org: &str,
        resource: &str,
    ) -> Result<Url, RegistryError> {
        validate_admin_token(org)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        Url::parse(&format!(
            "{}/-/org/{}/{}",
            reg_url.as_str().trim_end_matches('/'),
            encode_path_segment(org.trim_start_matches('@')),
            resource
        ))
        .map_err(RegistryError::UrlParse)
    }

    fn team_url(
        &self,
        registry: Option<&Url>,
        scope: &str,
        team: &str,
        resource: &str,
    ) -> Result<Url, RegistryError> {
        validate_admin_token(scope)?;
        validate_admin_token(team)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let suffix = if resource.is_empty() {
            String::new()
        } else {
            format!("/{resource}")
        };
        Url::parse(&format!(
            "{}/-/team/{}/{}{}",
            reg_url.as_str().trim_end_matches('/'),
            encode_path_segment(scope.trim_start_matches('@')),
            encode_path_segment(team),
            suffix
        ))
        .map_err(RegistryError::UrlParse)
    }

    /// Search the registry using npm's search API.
    pub async fn search(
        &self,
        registry: Option<&Url>,
        text: &str,
        size: usize,
        from: usize,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("text", text);
        query.append_pair("size", &size.to_string());
        query.append_pair("from", &from.to_string());
        let target = Url::parse(&format!(
            "{}/-/v1/search?{}",
            reg_url.as_str().trim_end_matches('/'),
            query.finish()
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    /// List trusted publishing relationships for a package.
    pub async fn trust_list(
        &self,
        registry: Option<&Url>,
        package_name: &str,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let target = Url::parse(&format!(
            "{}/-/package/{}/trust",
            reg_url.as_str().trim_end_matches('/'),
            encoded
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    /// Create one trusted publishing relationship for a package. The payload
    /// is an array because npm's registry API accepts the same shape for
    /// provider-specific configurations and bulk automation.
    pub async fn trust_create(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        config: serde_json::Value,
        otp: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let target = Url::parse(&format!(
            "{}/-/package/{}/trust",
            reg_url.as_str().trim_end_matches('/'),
            encoded
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::POST, target, Some(config), otp)
            .await
    }

    /// Revoke one trusted publishing relationship by its registry id.
    pub async fn trust_revoke(
        &self,
        registry: Option<&Url>,
        package_name: &str,
        trust_id: &str,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        validate_admin_token(trust_id)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let encoded = encode_package_name(package_name);
        let target = Url::parse(&format!(
            "{}/-/package/{}/trust/{}",
            reg_url.as_str().trim_end_matches('/'),
            encoded,
            encode_path_segment(trust_id)
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::DELETE, target, None, otp)
            .await?;
        Ok(())
    }

    pub async fn stage_list(
        &self,
        registry: Option<&Url>,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let target = Url::parse(&format!(
            "{}/-/stage",
            reg_url.as_str().trim_end_matches('/')
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    /// One page of `GET /-/stage`, optionally filtered to one package.
    pub async fn stage_list_page(
        &self,
        registry: Option<&Url>,
        page: u64,
        per_page: u64,
        package: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let mut target = Url::parse(&format!(
            "{}/-/stage",
            reg_url.as_str().trim_end_matches('/')
        ))
        .map_err(RegistryError::UrlParse)?;
        {
            let mut query = target.query_pairs_mut();
            query.append_pair("page", &page.to_string());
            query.append_pair("perPage", &per_page.to_string());
            if let Some(package) = package {
                query.append_pair("package", package);
            }
        }
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    pub async fn stage_view(
        &self,
        registry: Option<&Url>,
        stage_id: &str,
    ) -> Result<serde_json::Value, RegistryError> {
        validate_admin_token(stage_id)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let target = Url::parse(&format!(
            "{}/-/stage/{}",
            reg_url.as_str().trim_end_matches('/'),
            encode_path_segment(stage_id)
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::GET, target, None, None)
            .await
    }

    pub async fn stage_approve(
        &self,
        registry: Option<&Url>,
        stage_id: &str,
        otp: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        validate_admin_token(stage_id)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let target = Url::parse(&format!(
            "{}/-/stage/{}/approve",
            reg_url.as_str().trim_end_matches('/'),
            encode_path_segment(stage_id)
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::POST, target, None, otp)
            .await
    }

    pub async fn stage_reject(
        &self,
        registry: Option<&Url>,
        stage_id: &str,
        otp: Option<&str>,
    ) -> Result<(), RegistryError> {
        validate_admin_token(stage_id)?;
        let reg_url = registry.unwrap_or(&self.config.default_registry);
        let target = Url::parse(&format!(
            "{}/-/stage/{}",
            reg_url.as_str().trim_end_matches('/'),
            encode_path_segment(stage_id)
        ))
        .map_err(RegistryError::UrlParse)?;
        self.admin_json_request(Method::DELETE, target, None, otp)
            .await?;
        Ok(())
    }

    async fn admin_json_request(
        &self,
        method: Method,
        target: Url,
        body: Option<serde_json::Value>,
        otp: Option<&str>,
    ) -> Result<serde_json::Value, RegistryError> {
        let result = if let Some(body) = body {
            self.execute_with_body_permit(
                method,
                target.clone(),
                Some("application/json"),
                Some("application/json"),
                otp,
                serde_json::to_vec(&body)?,
            )
            .await?
        } else if otp.is_some() {
            self.execute_with_body_permit(
                method,
                target.clone(),
                Some("application/json"),
                Some("application/json"),
                otp,
                Vec::new(),
            )
            .await?
        } else {
            self.execute_with_permit(method, target.clone(), Some("application/json"), None)
                .await?
        };
        let (response, _permit) = result;
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(match status {
                StatusCode::UNAUTHORIZED => RegistryError::Unauthorized {
                    url: target.to_string(),
                    status: 401,
                    message: body_text,
                },
                StatusCode::FORBIDDEN => RegistryError::Forbidden {
                    url: target.to_string(),
                    status: 403,
                    message: body_text,
                },
                _ => RegistryError::ServerError {
                    status: status.as_u16(),
                    body: body_text,
                },
            });
        }
        if body_text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&body_text).map_err(|e| {
            RegistryError::MalformedMetadata(format!("Invalid registry JSON response: {e}"))
        })
    }
}

fn validate_admin_token(value: &str) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.contains('\r')
        || value.contains('\n')
        || value.contains('/')
        || value.contains('\\')
    {
        return Err(RegistryError::SecurityViolation(
            "registry administration argument contains forbidden characters".into(),
        ));
    }
    Ok(())
}

fn encode_path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_package_name() {
        assert_eq!(encode_package_name("lodash"), "lodash");
        assert_eq!(encode_package_name("@scope/pkg"), "@scope%2fpkg");
        assert_eq!(
            encode_package_name("@npmcli/arborist"),
            "@npmcli%2farborist"
        );
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
        assert_eq!(
            config.max_concurrent_requests,
            DEFAULT_MAX_CONCURRENT_REQUESTS
        );
        assert_eq!(
            config.pool_max_idle_per_host,
            DEFAULT_POOL_MAX_IDLE_PER_HOST
        );
        assert_eq!(
            config.tcp_keepalive,
            Duration::from_secs(DEFAULT_TCP_KEEPALIVE_SECS)
        );
        assert_eq!(
            config.pool_idle_timeout,
            Duration::from_secs(DEFAULT_POOL_IDLE_TIMEOUT_SECS)
        );
        assert_eq!(
            config.connect_timeout,
            Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)
        );
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
            (28..=31).contains(&parsed_secs),
            "Expected ~30s, got {parsed_secs}"
        );
    }

    #[test]
    fn test_client_config_strict_ssl() {
        let config_insecure = RegistryClientConfig {
            strict_ssl: false,
            ..Default::default()
        };
        assert!(RegistryClient::with_config(config_insecure).is_ok());

        let config_secure = RegistryClientConfig {
            strict_ssl: true,
            ..Default::default()
        };
        assert!(RegistryClient::with_config(config_secure).is_ok());
    }

    #[test]
    fn test_client_config_proxy_and_no_proxy() {
        let config_proxy = RegistryClientConfig {
            proxy: Some("http://proxy.local:8080".into()),
            no_proxy: Some("localhost,127.0.0.1".into()),
            ..Default::default()
        };
        assert!(RegistryClient::with_config(config_proxy).is_ok());

        let config_split_proxy = RegistryClientConfig {
            https_proxy: Some("https://proxy.local:8443".into()),
            http_proxy: Some("http://proxy.local:8080".into()),
            no_proxy: Some(".corp.internal".into()),
            ..Default::default()
        };
        assert!(RegistryClient::with_config(config_split_proxy).is_ok());
    }

    #[test]
    fn test_client_config_invalid_proxy_rejected() {
        let config_bad_proxy = RegistryClientConfig {
            proxy: Some("invalid url with spaces".into()),
            ..Default::default()
        };
        let result = RegistryClient::with_config(config_bad_proxy);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_config_invalid_ca_rejected() {
        let config_bad_ca = RegistryClientConfig {
            ca: Some("not a valid pem certificate content".into()),
            ..Default::default()
        };
        let result = RegistryClient::with_config(config_bad_ca);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_config_cafile_missing_rejected() {
        let config_missing_ca = RegistryClientConfig {
            cafile: Some(PathBuf::from("nonexistent_ca_path_12345.pem")),
            ..Default::default()
        };
        let result = RegistryClient::with_config(config_missing_ca);
        assert!(result.is_err());
    }
}
