use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerState};
use crate::error::RegistryError;
use crate::metadata::{
    parse_packument_with_mode, AbbreviatedPackageMetadata, PackumentParseMode,
};
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT, AGE, AUTHORIZATION, CACHE_CONTROL, CONNECTION,
    CONTENT_LENGTH, CONTENT_TYPE, DATE, ETAG, IF_NONE_MATCH, LOCATION, RETRY_AFTER, USER_AGENT,
    VARY,
};
use reqwest::{Client, Method, Response, StatusCode};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{Notify, OwnedSemaphorePermit, SemaphorePermit};
use tracing::debug;
use url::Url;

static DEFAULT_USER_AGENT_STR: OnceLock<String> = OnceLock::new();
static DEFAULT_UA_HEADER: OnceLock<HeaderValue> = OnceLock::new();
static DEFAULT_REGISTRY_URL: OnceLock<Url> = OnceLock::new();

#[inline]
fn default_user_agent_str() -> &'static str {
    DEFAULT_USER_AGENT_STR.get_or_init(|| {
        format!(
            "rnpm/{} ({}; {})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })
}

#[inline]
fn default_ua_header() -> HeaderValue {
    DEFAULT_UA_HEADER
        .get_or_init(|| {
            HeaderValue::from_str(default_user_agent_str())
                .expect("default user-agent is valid HTTP header value")
        })
        .clone()
}

#[inline]
fn default_registry_url() -> Url {
    DEFAULT_REGISTRY_URL
        .get_or_init(|| Url::parse("https://registry.npmjs.org/").unwrap())
        .clone()
}

/// Returns the default User-Agent header string.
pub fn default_user_agent() -> String {
    default_user_agent_str().to_owned()
}

/// Abbreviated metadata MIME type for npm registry.
pub const NPM_INSTALL_V1_JSON: &str = "application/vnd.npm.install-v1+json";

/// Accept header for install-optimized packument requests prioritizing abbreviated metadata.
pub const NPM_INSTALL_ACCEPT: &str =
    "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8";

static CLI_REQUEST_CONTEXT: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

/// Install the CLI's canonical command and expanded npm user agent once per
/// invocation. Library callers retain their configured request identity.
pub fn set_cli_request_context(command: String, user_agent: String) {
    let _ = CLI_REQUEST_CONTEXT.set((command, user_agent));
}

fn packument_cache_metadata(headers: &HeaderMap) -> serde_json::Value {
    const HEADERS: [(&str, &HeaderName); 5] = [
        ("cache-control", &CACHE_CONTROL),
        ("date", &DATE),
        ("age", &AGE),
        ("content-type", &CONTENT_TYPE),
        ("vary", &VARY),
    ];
    let mut map: Option<serde_json::Map<String, serde_json::Value>> = None;
    for &(name, header_name) in &HEADERS {
        if let Some(val) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
            let m = map.get_or_insert_with(|| serde_json::Map::with_capacity(4));
            m.insert(name.into(), serde_json::Value::String(val.to_owned()));
        }
    }
    let mut outer = serde_json::Map::with_capacity(1);
    let mut resp_map = serde_json::Map::with_capacity(1);
    resp_map.insert(
        "headers".into(),
        serde_json::Value::Object(map.unwrap_or_default()),
    );
    outer.insert("response".into(), serde_json::Value::Object(resp_map));
    serde_json::Value::Object(outer)
}

/// Negotiated HTTP representation of an npm packument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PackumentRepresentation {
    /// Abbreviated install representation (`application/vnd.npm.install-v1+json`).
    #[default]
    Abbreviated,
    /// Full npm packument (`application/json`) containing `time`, `license`, `scripts`, etc.
    Full,
}

impl PackumentRepresentation {
    /// HTTP `Accept` header value for negotiating this representation with fallback support.
    #[inline]
    pub const fn accept_header(self) -> &'static str {
        match self {
            Self::Abbreviated => NPM_INSTALL_ACCEPT,
            Self::Full => "application/json",
        }
    }

    /// Strict HTTP `Accept` header (`application/vnd.npm.install-v1+json` or `application/json`).
    #[inline]
    pub const fn strict_accept_header(self) -> &'static str {
        match self {
            Self::Abbreviated => NPM_INSTALL_V1_JSON,
            Self::Full => "application/json",
        }
    }

    /// Representation-specific cache key suffix ensuring abbreviated and full entries never collide.
    #[inline]
    pub const fn cache_key_suffix(self) -> &'static str {
        match self {
            Self::Abbreviated => "abbrev",
            Self::Full => "full",
        }
    }

    /// Corresponding parser mode for this representation.
    #[inline]
    pub const fn parse_mode(self) -> PackumentParseMode {
        match self {
            Self::Abbreviated => PackumentParseMode::Install,
            Self::Full => PackumentParseMode::Full,
        }
    }

    /// Determine actual returned representation from response `Content-Type` header (or requested `Accept`).
    pub fn from_response_headers(requested_accept: &str, content_type: Option<&str>) -> Self {
        if let Some(ct) = content_type {
            let ct_lower = ct.to_ascii_lowercase();
            if ct_lower.contains("vnd.npm.install-v1") {
                return Self::Abbreviated;
            }
            if ct_lower.contains("application/json") {
                return Self::Full;
            }
        }
        if requested_accept.contains("install-v1") {
            Self::Abbreviated
        } else {
            Self::Full
        }
    }
}

/// Options governing negotiated packument fetches and full-packument fallback behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PackumentFetchOptions {
    /// Preferred representation to request (`Abbreviated` by default).
    pub representation: PackumentRepresentation,
    /// Require `time` publish timestamps (e.g., `--before` / release-age checks).
    /// Negotiates `Full` directly when set.
    pub require_publish_times: bool,
    /// Require full manifest fields that minimal abbreviated registries (such as
    /// `benchmarks/mock-registry/mock-server.js`) omit from `install-v1` responses.
    pub require_full_fields: bool,
}

impl PackumentFetchOptions {
    /// Options for abbreviated install resolution.
    #[inline]
    pub const fn abbreviated() -> Self {
        Self {
            representation: PackumentRepresentation::Abbreviated,
            require_publish_times: false,
            require_full_fields: false,
        }
    }

    /// Options for full packument resolution (e.g., `--before`, `license`, `time`, CLI inspection).
    #[inline]
    pub const fn full() -> Self {
        Self {
            representation: PackumentRepresentation::Full,
            require_publish_times: false,
            require_full_fields: true,
        }
    }

    #[inline]
    const fn effective_representation(self) -> PackumentRepresentation {
        if self.require_publish_times || self.require_full_fields {
            PackumentRepresentation::Full
        } else {
            self.representation
        }
    }
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct PackumentCacheKey {
    url: String,
    representation: PackumentRepresentation,
}

#[derive(Clone)]
struct CachedPackumentEntry {
    etag: Option<String>,
    metadata: Arc<AbbreviatedPackageMetadata>,
    cache_metadata: serde_json::Value,
}

#[derive(Clone, Copy)]
enum FastBodyKind<'a> {
    Metadata {
        max_size: usize,
        package_name: &'a str,
    },
    TarballBytes {
        max_size: usize,
        compute_sha512: bool,
        not_found_label: &'a str,
    },
    TarballFile {
        max_size: usize,
        disk_threshold: usize,
        temp_path: &'a Path,
        dest_path: &'a Path,
        not_found_label: &'a str,
    },
}

enum DirectOrResume {
    Success {
        etag: Option<String>,
        payload: crate::http1_pool::BodyPayload,
    },
    NotModified {
        etag: Option<String>,
        cache_metadata: serde_json::Value,
    },
    ResumeReqwest {
        current_url: Url,
        redirect_count: usize,
        seen_redirect_urls: Option<HashSet<Url>>,
        attempt: usize,
    },
}

struct LazyHttpClient {
    identity: Mutex<Option<reqwest::Identity>>,
    cell: OnceLock<Result<Client, String>>,
}

impl LazyHttpClient {
    fn new(identity: Option<reqwest::Identity>) -> Arc<Self> {
        Arc::new(Self {
            identity: Mutex::new(identity),
            cell: OnceLock::new(),
        })
    }

    #[inline]
    fn get_or_init(
        &self,
        config: &RegistryClientConfig,
        headers: &HeaderMap,
    ) -> Result<&Client, RegistryError> {
        let res = self.cell.get_or_init(|| {
            let id = self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            build_http_client(config, headers, id).map_err(|e| e.to_string())
        });
        match res {
            Ok(client) => Ok(client),
            Err(err) => Err(RegistryError::Other(err.clone())),
        }
    }
}

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

/// Default retry backoff multiplier factor.
pub const DEFAULT_RETRY_FACTOR: f64 = 2.0;

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

static LOG_HTTP_REQUESTS: OnceLock<bool> = OnceLock::new();

#[inline]
fn should_log_http_requests() -> bool {
    *LOG_HTTP_REQUESTS.get_or_init(|| {
        std::env::var_os("RNPM_COUNT_HTTP").is_some()
            || std::env::var_os("RNPM_TIMING_DEBUG").is_some()
    })
}

fn track_http_request(method: &Method, url: &Url) {
    let count = HTTP_REQUEST_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    if should_log_http_requests() {
        eprintln!("[http-request #{count}] {method} {url}");
    }
}

#[inline]
fn has_proxy_env_vars() -> bool {
    #[cfg(windows)]
    {
        const VARS: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "PROXY"];
        VARS.iter()
            .any(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
    }
    #[cfg(not(windows))]
    {
        std::env::vars_os().any(|(k, v)| {
            !v.is_empty()
                && k.to_str().is_some_and(|s| {
                    s.eq_ignore_ascii_case("http_proxy")
                        || s.eq_ignore_ascii_case("https_proxy")
                        || s.eq_ignore_ascii_case("proxy")
                })
        })
    }
}

/// Returns a lowercase `host[:port]` key, borrowing zero-copy when the URL has no explicit port
/// and its host is already lowercase ASCII (true for canonical `url::Url` DNS hosts).
#[inline]
fn url_host_key(url: &Url) -> Cow<'_, str> {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => Cow::Owned(format!("{host}:{port}").to_ascii_lowercase()),
        None if host.bytes().any(|b| b.is_ascii_uppercase()) => {
            Cow::Owned(host.to_ascii_lowercase())
        }
        None => Cow::Borrowed(host),
    }
}

/// Appends the npm-encoded package name (`@scope%2fpkg` or `pkg`) directly into `out`.
#[inline]
fn append_encoded_package_name(out: &mut String, name: &str) {
    if let Some(rest) = name.strip_prefix('@') {
        if let Some((scope, pkg)) = rest.split_once('/') {
            out.push('@');
            out.push_str(scope);
            out.push_str("%2f");
            out.push_str(pkg);
            return;
        }
    }
    out.push_str(name);
}

/// Polls the next body chunk while enforcing `idle_timeout` without allocating or resetting a Tokio
/// timer unless `resp.chunk()` actually returns `Poll::Pending`.
#[inline]
async fn next_chunk_with_idle_timeout(
    resp: &mut Response,
    idle_timeout: Duration,
    idle_sleep: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> Result<Option<bytes::Bytes>, RegistryError> {
    let mut deadline_set = false;
    let mut fut = std::pin::pin!(resp.chunk());
    std::future::poll_fn(|cx| match fut.as_mut().poll(cx) {
        Poll::Ready(Ok(opt)) => Poll::Ready(Ok(opt)),
        Poll::Ready(Err(err)) => Poll::Ready(Err(RegistryError::Http(err))),
        Poll::Pending => {
            let sleep = match idle_sleep {
                Some(s) => {
                    if !deadline_set {
                        s.as_mut()
                            .reset(tokio::time::Instant::now() + idle_timeout);
                        deadline_set = true;
                    }
                    s
                }
                None => {
                    deadline_set = true;
                    idle_sleep.insert(Box::pin(tokio::time::sleep(idle_timeout)))
                }
            };
            match sleep.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(RegistryError::SlowlorisTimeout(idle_timeout))),
                Poll::Pending => Poll::Pending,
            }
        }
    })
    .await
}

fn clone_clonable_registry_error(err: &RegistryError) -> Option<RegistryError> {
    Some(match err {
        RegistryError::Http(_) | RegistryError::Json(_) => return None,
        RegistryError::Transport(e) => RegistryError::Transport(e.clone()),
        RegistryError::UrlParse(e) => RegistryError::UrlParse(*e),
        RegistryError::PackageNotFound { package, status } => RegistryError::PackageNotFound {
            package: package.clone(),
            status: *status,
        },
        RegistryError::VersionNotFound { package, version } => RegistryError::VersionNotFound {
            package: package.clone(),
            version: version.clone(),
        },
        RegistryError::Unauthorized {
            url,
            status,
            message,
        } => RegistryError::Unauthorized {
            url: url.clone(),
            status: *status,
            message: message.clone(),
        },
        RegistryError::AuthChallenge {
            url,
            www_authenticate,
            body,
        } => RegistryError::AuthChallenge {
            url: url.clone(),
            www_authenticate: www_authenticate.clone(),
            body: body.clone(),
        },
        RegistryError::Forbidden {
            url,
            status,
            message,
        } => RegistryError::Forbidden {
            url: url.clone(),
            status: *status,
            message: message.clone(),
        },
        RegistryError::PublishConflict {
            url,
            status,
            message,
        } => RegistryError::PublishConflict {
            url: url.clone(),
            status: *status,
            message: message.clone(),
        },
        RegistryError::RateLimited { retry_after } => RegistryError::RateLimited {
            retry_after: *retry_after,
        },
        RegistryError::TooManyRedirects(n) => RegistryError::TooManyRedirects(*n),
        RegistryError::SecurityViolation(s) => RegistryError::SecurityViolation(s.clone()),
        RegistryError::ServerError { status, body } => RegistryError::ServerError {
            status: *status,
            body: body.clone(),
        },
        RegistryError::CircuitBreakerOpen { host } => {
            RegistryError::CircuitBreakerOpen { host: host.clone() }
        }
        RegistryError::MalformedMetadata(s) => RegistryError::MalformedMetadata(s.clone()),
        RegistryError::SizeLimitExceeded {
            limit,
            actual,
            message,
        } => RegistryError::SizeLimitExceeded {
            limit: *limit,
            actual: *actual,
            message: message.clone(),
        },
        RegistryError::SlowlorisTimeout(d) => RegistryError::SlowlorisTimeout(*d),
        RegistryError::ContentLengthMismatch { expected, actual } => {
            RegistryError::ContentLengthMismatch {
                expected: *expected,
                actual: *actual,
            }
        }
        RegistryError::ProvenanceVerificationFailed(s) => {
            RegistryError::ProvenanceVerificationFailed(s.clone())
        }
        RegistryError::AttestationDigestMismatch {
            algorithm,
            expected,
            actual,
        } => RegistryError::AttestationDigestMismatch {
            algorithm: algorithm.clone(),
            expected: expected.clone(),
            actual: actual.clone(),
        },
        RegistryError::UntrustedSourceRepository { expected, actual } => {
            RegistryError::UntrustedSourceRepository {
                expected: expected.clone(),
                actual: actual.clone(),
            }
        }
        RegistryError::InvalidSigstoreBundle(s) => RegistryError::InvalidSigstoreBundle(s.clone()),
        RegistryError::InvalidSignature(s) => RegistryError::InvalidSignature(s.clone()),
        RegistryError::Other(s) => RegistryError::Other(s.clone()),
    })
}

#[derive(Hash, PartialEq, Eq)]
struct MetadataInFlightKey {
    url: Url,
    accept: Cow<'static, str>,
    if_none_match: Option<String>,
    package_name: String,
}

#[derive(Hash, PartialEq, Eq)]
struct TarballInFlightKey {
    url: Url,
    if_none_match: Option<String>,
}

enum CoalescedResult<T> {
    Ok(T),
    Err(RegistryError),
    Fallback,
}

struct InFlightSlot<T> {
    has_waiters: AtomicBool,
    outcome: OnceLock<CoalescedResult<T>>,
    notify: Notify,
}

const IN_FLIGHT_SHARDS: usize = 16;

type InFlightShardMap<K, T> = Mutex<HashMap<Arc<K>, Arc<InFlightSlot<T>>>>;

struct InFlightGroup<K, T> {
    shards: [InFlightShardMap<K, T>; IN_FLIGHT_SHARDS],
}

#[inline]
fn shard_index<K: Hash>(key: &K) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) & (IN_FLIGHT_SHARDS - 1)
}

impl<K, T> InFlightGroup<K, T>
where
    K: Eq + Hash,
{
    fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    fn join_or_lead(
        self: &Arc<Self>,
        key: Arc<K>,
    ) -> Result<LeaderGuard<K, T>, Arc<InFlightSlot<T>>> {
        let idx = shard_index(&*key);
        let mut guard = self.shards[idx].lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = guard.get(&key) {
            existing.has_waiters.store(true, Ordering::Release);
            return Err(Arc::clone(existing));
        }
        let slot = Arc::new(InFlightSlot {
            has_waiters: AtomicBool::new(false),
            outcome: OnceLock::new(),
            notify: Notify::new(),
        });
        guard.insert(Arc::clone(&key), Arc::clone(&slot));
        Ok(LeaderGuard {
            group: Arc::clone(self),
            shard_idx: idx,
            key: Some(key),
            slot,
        })
    }
}

async fn wait_for_coalesced<T>(
    slot: &InFlightSlot<T>,
    clone_ok: impl Fn(&T) -> T,
) -> Option<Result<T, RegistryError>> {
    loop {
        let notified = slot.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(outcome) = slot.outcome.get() {
            return match outcome {
                CoalescedResult::Ok(val) => Some(Ok(clone_ok(val))),
                CoalescedResult::Err(err) => clone_clonable_registry_error(err).map(Err),
                CoalescedResult::Fallback => None,
            };
        }
        notified.await;
    }
}

struct LeaderGuard<K: Eq + Hash, T> {
    group: Arc<InFlightGroup<K, T>>,
    shard_idx: usize,
    key: Option<Arc<K>>,
    slot: Arc<InFlightSlot<T>>,
}

impl<K: Eq + Hash, T> LeaderGuard<K, T> {
    fn finish(mut self, res: &Result<T, RegistryError>, clone_ok: impl FnOnce(&T) -> T) {
        if let Some(key) = self.key.take() {
            {
                let mut guard = self.group.shards[self.shard_idx]
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(cur) = guard.get(&key) {
                    if Arc::ptr_eq(cur, &self.slot) {
                        guard.remove(&key);
                    }
                }
            }

            // Fast-path: if no concurrent caller joined while in flight, avoid cloning payload.
            if self.slot.has_waiters.load(Ordering::Acquire) {
                let outcome = match res {
                    Ok(val) => CoalescedResult::Ok(clone_ok(val)),
                    Err(err) => match clone_clonable_registry_error(err) {
                        Some(cloned) => CoalescedResult::Err(cloned),
                        None => CoalescedResult::Fallback,
                    },
                };
                let _ = self.slot.outcome.set(outcome);
                self.slot.notify.notify_waiters();
            }
        }
    }
}

impl<K: Eq + Hash, T> Drop for LeaderGuard<K, T> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            {
                let mut guard = self.group.shards[self.shard_idx]
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(cur) = guard.get(&key) {
                    if Arc::ptr_eq(cur, &self.slot) {
                        guard.remove(&key);
                    }
                }
            }
            if self.slot.has_waiters.load(Ordering::Acquire) {
                let _ = self.slot.outcome.set(CoalescedResult::Fallback);
                self.slot.notify.notify_waiters();
            }
        }
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
        cache_metadata: serde_json::Value,
    },
    /// Server returned HTTP 304 Not Modified; cached data is still valid.
    NotModified {
        etag: Option<String>,
        cache_metadata: serde_json::Value,
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

/// Scoped TLS identity configuration for a registry URI prefix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopedTlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
    pub certfile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
}

impl ScopedTlsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_files(certfile: impl Into<PathBuf>, keyfile: impl Into<PathBuf>) -> Self {
        Self {
            cert: None,
            key: None,
            certfile: Some(certfile.into()),
            keyfile: Some(keyfile.into()),
        }
    }

    pub fn from_pem(cert: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            cert: Some(cert.into()),
            key: Some(key.into()),
            certfile: None,
            keyfile: None,
        }
    }
}

/// Alias for `ScopedTlsConfig` representing a scoped TLS identity.
pub type ScopedTlsIdentity = ScopedTlsConfig;

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
    pub retry_factor: f64,
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
    pub certfile: Option<PathBuf>,
    pub key: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub scoped_tls: std::collections::BTreeMap<String, ScopedTlsConfig>,
    pub strict_ssl: bool,
    pub maxsockets: Option<usize>,
}

impl Default for RegistryClientConfig {
    fn default() -> Self {
        let registry_url = default_registry_url();
        let mut trusted_hosts = HashSet::with_capacity(2);
        if let Some(h) = registry_url.host_str() {
            trusted_hosts.insert(h.to_ascii_lowercase());
        }

        let mut retry_on_status = HashSet::with_capacity(4);
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
            retry_factor: DEFAULT_RETRY_FACTOR,
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
            certfile: None,
            key: None,
            keyfile: None,
            scoped_tls: std::collections::BTreeMap::new(),
            strict_ssl: true,
            maxsockets: None,
        }
    }
}

/// Computes the exponential retry backoff duration for a given attempt index (0-based)
/// honoring initial backoff, max backoff, and retry factor.
pub fn calculate_retry_backoff(
    initial: Duration,
    max: Duration,
    factor: f64,
    attempt: usize,
) -> Duration {
    let factor = if factor <= 0.0 || factor.is_nan() {
        DEFAULT_RETRY_FACTOR
    } else {
        factor
    };
    let multiplier = factor.powi(attempt as i32);
    if multiplier <= 0.0 || multiplier.is_nan() {
        return initial.min(max);
    }
    let delay_secs = initial.as_secs_f64() * multiplier;
    if delay_secs.is_nan() || delay_secs >= max.as_secs_f64() {
        max
    } else {
        Duration::from_secs_f64(delay_secs).min(max)
    }
}

impl RegistryClientConfig {
    /// Calculate backoff duration for a given retry attempt index (0-based).
    pub fn calculate_backoff(&self, attempt: usize) -> Duration {
        calculate_retry_backoff(
            self.initial_retry_backoff,
            self.max_retry_backoff,
            self.retry_factor,
            attempt,
        )
    }

    /// Add or update a scoped TLS configuration for a registry URI prefix.
    pub fn add_scoped_tls(&mut self, uri_prefix: impl Into<String>, tls: ScopedTlsConfig) {
        self.scoped_tls.insert(uri_prefix.into(), tls);
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
    if s.is_empty() {
        return None;
    }
    // Handle signed integer seconds (e.g. "-10" -> 0 seconds, retry immediately per RFC 7231 / 9110)
    if let Ok(signed) = s.parse::<i64>() {
        return Some(if signed < 0 { 0 } else { signed as u64 });
    }
    // Handle huge integer seconds that overflow u64 (exceeding budget cap)
    let is_numeric = (s.starts_with('+') && s[1..].chars().all(|c| c.is_ascii_digit()))
        || s.chars().all(|c| c.is_ascii_digit());
    if is_numeric {
        return Some(u64::MAX);
    }
    parse_http_date_to_seconds_from_now(s)
}

/// Helper to extract and join WWW-Authenticate challenges into a single comma-separated string.
fn extract_www_authenticate(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let challenges: Vec<&str> = headers
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if challenges.is_empty() {
        None
    } else {
        Some(challenges.join(", "))
    }
}

/// Helper to generate path prefixes for longest-prefix matching (e.g. `/a/b/c` -> `["/a/b/c/", "/a/b/c", "/a/b/", "/a/b", "/a/", "/a", "/", ""]`).
pub fn generate_path_prefixes(path: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        prefixes.push("/".to_string());
        prefixes.push(String::new());
        return prefixes;
    }

    let norm_path = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };

    let segments: Vec<&str> = norm_path.split('/').filter(|s| !s.is_empty()).collect();
    for i in (1..=segments.len()).rev() {
        let sub = segments[..i].join("/");
        prefixes.push(format!("/{sub}/"));
        prefixes.push(format!("/{sub}"));
    }
    prefixes.push("/".to_string());
    prefixes.push(String::new());
    prefixes
}

/// Helper to normalize a URI prefix into standard npm format (e.g. `//hostname/path/`).
pub fn normalize_uri_prefix(prefix: &str) -> String {
    let mut p = prefix.trim();
    if let Some(rest) = p.strip_prefix("https://") {
        p = rest;
    } else if let Some(rest) = p.strip_prefix("http://") {
        p = rest;
    } else if let Some(rest) = p.strip_prefix("//") {
        p = rest;
    }

    let (host_part, path_part) = if let Some(slash_idx) = p.find('/') {
        (&p[..slash_idx], &p[slash_idx..])
    } else {
        (p, "/")
    };

    let host_lower = host_part.to_ascii_lowercase();
    let mut normalized_path = path_part.to_string();
    if !normalized_path.ends_with('/') {
        normalized_path.push('/');
    }

    format!("//{host_lower}{normalized_path}")
}

fn is_empty_or_null_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let trimmed = s.trim();
    trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("null")
        || trimmed.eq_ignore_ascii_case("undefined")
}

fn clean_pem_str(s: Option<&str>) -> Option<&str> {
    s.map(|v| v.trim())
        .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("null") && !t.eq_ignore_ascii_case("undefined"))
}

/// Helper to load and parse an X.509 client certificate and private key into a reqwest Identity.
pub fn load_tls_identity(
    certfile: Option<&Path>,
    cert_str: Option<&str>,
    keyfile: Option<&Path>,
    key_str: Option<&str>,
) -> Result<Option<reqwest::Identity>, RegistryError> {
    let certfile = certfile.filter(|p| !is_empty_or_null_path(p));
    let keyfile = keyfile.filter(|p| !is_empty_or_null_path(p));
    let cert_str = clean_pem_str(cert_str);
    let key_str = clean_pem_str(key_str);

    let cert_content = if let Some(path) = certfile {
        Some(std::fs::read_to_string(path).map_err(|err| {
            RegistryError::Other(format!("Failed to read certfile at '{}': {err}", path.display()))
        })?)
    } else if let Some(c) = cert_str {
        if Path::new(c).exists() {
            Some(std::fs::read_to_string(c).map_err(|err| {
                RegistryError::Other(format!("Failed to read cert file '{c}': {err}"))
            })?)
        } else {
            Some(c.to_string())
        }
    } else {
        None
    };

    let key_content = if let Some(path) = keyfile {
        Some(std::fs::read_to_string(path).map_err(|err| {
            RegistryError::Other(format!("Failed to read keyfile at '{}': {err}", path.display()))
        })?)
    } else if let Some(k) = key_str {
        if Path::new(k).exists() {
            Some(std::fs::read_to_string(k).map_err(|err| {
                RegistryError::Other(format!("Failed to read key file '{k}': {err}"))
            })?)
        } else {
            Some(k.to_string())
        }
    } else {
        None
    };

    let cert_content = cert_content.filter(|s| {
        let t = s.trim();
        !t.is_empty() && !t.eq_ignore_ascii_case("null") && !t.eq_ignore_ascii_case("undefined")
    });
    let key_content = key_content.filter(|s| {
        let t = s.trim();
        !t.is_empty() && !t.eq_ignore_ascii_case("null") && !t.eq_ignore_ascii_case("undefined")
    });

    match (cert_content, key_content) {
        (Some(cert), Some(key)) => {
            let combined_pem = format!("{}\n{}", cert.trim(), key.trim());
            let identity = reqwest::Identity::from_pem(combined_pem.as_bytes()).map_err(|err| {
                RegistryError::Other(format!(
                    "Failed to parse client certificate and key into Identity: {err}"
                ))
            })?;
            Ok(Some(identity))
        }
        (Some(cert), None) => {
            if let Ok(identity) = reqwest::Identity::from_pem(cert.trim().as_bytes()) {
                Ok(Some(identity))
            } else {
                Err(RegistryError::Other(
                    "Client certificate configured without corresponding private key (both cert and key are required, or cert must contain a combined cert + private key PEM bundle)".to_string(),
                ))
            }
        }
        (None, Some(_)) => Err(RegistryError::Other(
            "Client private key configured without corresponding certificate (both cert and key are required)".to_string(),
        )),
        (None, None) => Ok(None),
    }
}

fn clean_pathbuf(p: Option<&PathBuf>) -> Option<PathBuf> {
    p.filter(|path| !is_empty_or_null_path(path)).cloned()
}

fn clean_string(s: Option<&String>) -> Option<String> {
    s.map(|v| v.trim())
        .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("null") && !t.eq_ignore_ascii_case("undefined"))
        .map(|t| t.to_string())
}

/// Helper to extract parent path prefixes for a normalized URI prefix (e.g. `/a/b/` -> `["/a/", "/"]`).
pub fn get_parent_path_prefixes(path: &str) -> Vec<String> {
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Vec::new();
    }
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    let mut parents = Vec::new();
    for i in (1..segments.len()).rev() {
        let sub = segments[..i].join("/");
        parents.push(format!("/{sub}/"));
    }
    parents.push("/".to_string());
    parents
}

/// Builds a reqwest Client configured per RegistryClientConfig, optionally with a client TLS Identity.
pub fn build_http_client(
    config: &RegistryClientConfig,
    headers: &HeaderMap,
    identity: Option<reqwest::Identity>,
) -> Result<Client, RegistryError> {
    let max_idle = if let Some(sockets) = config.maxsockets {
        if sockets == 0 {
            DEFAULT_POOL_MAX_IDLE_PER_HOST
        } else {
            sockets
        }
    } else if config.pool_max_idle_per_host == 0 {
        DEFAULT_POOL_MAX_IDLE_PER_HOST
    } else {
        config.pool_max_idle_per_host
    };

    // We disable reqwest's automatic redirect following so that we can enforce
    // the strict security rule: NEVER forward auth headers across redirects to untrusted hostnames.
    let mut builder = Client::builder()
        .default_headers(headers.clone())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(config.timeout)
        .connect_timeout(config.connect_timeout)
        .tcp_nodelay(true)
        .tcp_keepalive(Some(config.tcp_keepalive))
        .pool_idle_timeout(Some(config.pool_idle_timeout))
        .pool_max_idle_per_host(max_idle)
        .http2_adaptive_window(true)
        .http2_initial_stream_window_size(Some(2 * 1024 * 1024))
        .http2_initial_connection_window_size(Some(8 * 1024 * 1024));

    if !config.strict_ssl {
        builder = builder.danger_accept_invalid_certs(true);
    }

    // Proxies follow @npmcli/agent, not reqwest's system lookup: the
    // configured proxy, else HTTPS_PROXY for every URL (HTTP_PROXY and
    // PROXY only for http), bypassed only by the `noproxy` setting.
    builder = builder.no_proxy();
    let (env_https_proxy, env_http_proxy) =
        if config.https_proxy.is_none() && config.http_proxy.is_none() && config.proxy.is_none() {
            let env = |name: &str| {
                std::env::vars()
                    .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                    .last()
                    .map(|(_, v)| v)
                    .filter(|v| !v.is_empty())
            };
            let https = env("https_proxy");
            let http = env("http_proxy").or_else(|| env("proxy"));
            (https, http)
        } else {
            (None, None)
        };
    if env_https_proxy.is_some() || env_http_proxy.is_some() {
        // @npmcli/agent's isNoProxy: an entry matches when its dot
        // segments end the hostname's; `*` and ports mean nothing.
        let no_proxy: Vec<Vec<String>> = config
            .no_proxy
            .clone()
            .filter(|v| !v.is_empty())
            .or_else(|| {
                std::env::vars()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("no_proxy"))
                    .last()
                    .map(|(_, v)| v)
            })
            .unwrap_or_default()
            .split(',')
            .map(|entry| {
                entry
                    .trim()
                    .split('.')
                    .filter(|s| !s.is_empty())
                    .rev()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|segments| !segments.is_empty())
            .collect();
        let https = env_https_proxy.and_then(|u| reqwest::Url::parse(&u).ok());
        let http = env_http_proxy.and_then(|u| reqwest::Url::parse(&u).ok());
        let https_p = https.clone();
        let http_p = http.clone();
        let mut custom_proxy = reqwest::Proxy::custom(move |url| {
            let host_str = url.host_str()?;
            // Never proxy RFC 2606 / RFC 6761 special-use reserved test domains (.invalid, .test, .example, .localhost)
            if host_str.ends_with(".invalid")
                || host_str.ends_with(".test")
                || host_str.ends_with(".example")
                || host_str.ends_with(".localhost")
                || host_str.eq_ignore_ascii_case("localhost")
            {
                return None;
            }
            let proxy = if url.scheme() == "https" { https_p.as_ref() } else { http_p.as_ref() }?;
            let host: Vec<&str> = host_str.split('.').rev().collect();
            let bypass = no_proxy
                .iter()
                .any(|entry| entry.iter().enumerate().all(|(i, s)| host.get(i) == Some(&s.as_str())));
            (!bypass).then(|| proxy.clone())
        });
        if let Some(https_u) = &https {
            if let (Some(u), Some(p)) = (Some(https_u.username()), https_u.password()) {
                if !u.is_empty() {
                    custom_proxy = custom_proxy.basic_auth(u, p);
                }
            }
        } else if let Some(http_u) = &http {
            if let (Some(u), Some(p)) = (Some(http_u.username()), http_u.password()) {
                if !u.is_empty() {
                    custom_proxy = custom_proxy.basic_auth(u, p);
                }
            }
        }
        builder = builder.proxy(custom_proxy);
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

    if let Some(identity) = identity {
        builder = builder.identity(identity);
    }

    builder.build().map_err(RegistryError::from)
}

fn validate_proxy_and_ca_config(config: &RegistryClientConfig) -> Result<(), RegistryError> {
    if let Some(https_proxy) = &config.https_proxy {
        reqwest::Proxy::https(https_proxy).map_err(|err| {
            RegistryError::Other(format!("Invalid https_proxy '{https_proxy}': {err}"))
        })?;
    }
    if let Some(http_proxy) = &config.http_proxy {
        reqwest::Proxy::http(http_proxy).map_err(|err| {
            RegistryError::Other(format!("Invalid http_proxy '{http_proxy}': {err}"))
        })?;
    }
    if let Some(general_proxy) = &config.proxy {
        if config.https_proxy.is_none() && config.http_proxy.is_none() {
            reqwest::Proxy::all(general_proxy).map_err(|err| {
                RegistryError::Other(format!("Invalid proxy '{general_proxy}': {err}"))
            })?;
        } else if config.http_proxy.is_none() {
            reqwest::Proxy::http(general_proxy).map_err(|err| {
                RegistryError::Other(format!("Invalid proxy '{general_proxy}': {err}"))
            })?;
        } else if config.https_proxy.is_none() {
            reqwest::Proxy::https(general_proxy).map_err(|err| {
                RegistryError::Other(format!("Invalid proxy '{general_proxy}': {err}"))
            })?;
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
    }
    Ok(())
}

/// Client for interacting with npm package registries.
#[derive(Clone)]
pub struct RegistryClient {
    base_client: Arc<LazyHttpClient>,
    default_headers: Arc<HeaderMap>,
    config: Arc<RegistryClientConfig>,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    circuit_breaker: CircuitBreaker,
    http_requests: std::sync::Arc<std::sync::atomic::AtomicU64>,
    http_304s: std::sync::Arc<std::sync::atomic::AtomicU64>,
    scoped_clients: Arc<std::collections::BTreeMap<String, Arc<LazyHttpClient>>>,
    global_client: Option<Arc<LazyHttpClient>>,
    has_scoped_auth: bool,
    has_any_auth: bool,
    has_non_error_retry_status: bool,
    bearer_auth_header: Option<HeaderValue>,
    http1_pool: Arc<crate::http1_pool::Http1Pool>,
    http1_static_headers: Arc<[u8]>,
    http1_max_idle_per_host: usize,
    may_use_http_proxy: bool,
    in_flight_metadata: Arc<InFlightGroup<MetadataInFlightKey, MetadataFetchResult>>,
    in_flight_tarballs: Arc<InFlightGroup<TarballInFlightKey, BytesFetchResult>>,
    packument_cache: Arc<std::sync::RwLock<HashMap<PackumentCacheKey, CachedPackumentEntry>>>,
}

impl RegistryClient {
    /// Create a new RegistryClient with default configuration.
    pub fn new() -> Result<Self, RegistryError> {
        Self::with_config(RegistryClientConfig::default())
    }

    /// Create a new RegistryClient with custom configuration.
    /// Defers heavy `reqwest` / `rustls` / root CA initialization until the first network request.
    pub fn with_config(config: RegistryClientConfig) -> Result<Self, RegistryError> {
        let mut headers = HeaderMap::with_capacity(4);
        let cli_context = CLI_REQUEST_CONTEXT.get();
        let user_agent = if let Some((command, cli_ua)) =
            cli_context.filter(|_| config.user_agent == default_user_agent_str())
        {
            headers.insert(
                "npm-command",
                HeaderValue::from_str(command).map_err(|e| RegistryError::Other(e.to_string()))?,
            );
            HeaderValue::from_str(cli_ua).map_err(|e| RegistryError::Other(e.to_string()))?
        } else {
            if let Some((command, _)) = cli_context {
                headers.insert(
                    "npm-command",
                    HeaderValue::from_str(command)
                        .map_err(|e| RegistryError::Other(e.to_string()))?,
                );
            }
            if config.user_agent == default_user_agent_str() {
                default_ua_header()
            } else {
                HeaderValue::from_str(&config.user_agent)
                    .map_err(|e| RegistryError::Other(e.to_string()))?
            }
        };
        headers.insert(USER_AGENT, user_agent);
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

        // Only validate proxy / CA / TLS files eagerly when configured;
        // defer reqwest/rustls ClientBuilder construction until the first actual request.
        validate_proxy_and_ca_config(&config)?;

        let global_client = if config.certfile.is_some()
            || config.cert.is_some()
            || config.keyfile.is_some()
            || config.key.is_some()
        {
            load_tls_identity(
                config.certfile.as_deref(),
                config.cert.as_deref(),
                config.keyfile.as_deref(),
                config.key.as_deref(),
            )?
            .map(|id| LazyHttpClient::new(Some(id)))
        } else {
            None
        };

        let mut scoped_clients = std::collections::BTreeMap::new();
        if !config.scoped_tls.is_empty() {
            // Pre-normalize and clean scoped configs to enable parent-prefix inheritance on the same host
            let mut normalized_scoped: std::collections::BTreeMap<String, ScopedTlsConfig> =
                std::collections::BTreeMap::new();
            for (prefix, scoped_cfg) in &config.scoped_tls {
                let norm = normalize_uri_prefix(prefix);
                let cleaned = ScopedTlsConfig {
                    certfile: clean_pathbuf(scoped_cfg.certfile.as_ref()),
                    cert: clean_string(scoped_cfg.cert.as_ref()),
                    keyfile: clean_pathbuf(scoped_cfg.keyfile.as_ref()),
                    key: clean_string(scoped_cfg.key.as_ref()),
                };
                normalized_scoped.insert(norm, cleaned);
            }

            // Load and register scoped TLS clients lazily with parent-prefix inheritance within the same host
            for (prefix, scoped_cfg) in &config.scoped_tls {
                let norm = normalize_uri_prefix(prefix);
                let mut certfile = clean_pathbuf(scoped_cfg.certfile.as_ref());
                let mut cert = clean_string(scoped_cfg.cert.as_ref());
                let mut keyfile = clean_pathbuf(scoped_cfg.keyfile.as_ref());
                let mut key = clean_string(scoped_cfg.key.as_ref());

                let rest = norm.strip_prefix("//").unwrap_or(&norm);
                let (host_part, path_part) = match rest.find('/') {
                    Some(i) => (&rest[..i], &rest[i..]),
                    None => (rest, "/"),
                };

                let parent_paths = get_parent_path_prefixes(path_part);
                for parent_path in &parent_paths {
                    if (certfile.is_some() || cert.is_some())
                        && (keyfile.is_some() || key.is_some())
                    {
                        break;
                    }
                    let cand_parent = format!("//{host_part}{parent_path}");
                    if let Some(parent_cfg) = normalized_scoped.get(&cand_parent) {
                        if certfile.is_none() && cert.is_none() {
                            certfile = parent_cfg.certfile.clone();
                            cert = parent_cfg.cert.clone();
                        }
                        if keyfile.is_none() && key.is_none() {
                            keyfile = parent_cfg.keyfile.clone();
                            key = parent_cfg.key.clone();
                        }
                    }
                }

                if certfile.is_none() && cert.is_none() && keyfile.is_none() && key.is_none() {
                    continue;
                }

                let has_scoped_descendant = normalized_scoped
                    .keys()
                    .any(|other_norm| other_norm != &norm && other_norm.starts_with(&norm));

                match load_tls_identity(
                    certfile.as_deref(),
                    cert.as_deref(),
                    keyfile.as_deref(),
                    key.as_deref(),
                ) {
                    Ok(Some(id)) => {
                        let lazy_client = LazyHttpClient::new(Some(id));
                        scoped_clients.insert(norm.clone(), Arc::clone(&lazy_client));
                        if norm.ends_with('/') {
                            let no_slash = norm.trim_end_matches('/').to_string();
                            scoped_clients.insert(no_slash, Arc::clone(&lazy_client));
                        }
                        scoped_clients.insert(prefix.clone(), lazy_client);
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if has_scoped_descendant {
                            let has_cert = certfile.is_some() || cert.is_some();
                            let has_key = keyfile.is_some() || key.is_some();
                            if has_cert != has_key {
                                if let RegistryError::Other(ref msg) = err {
                                    if msg.contains("both cert and key are required") {
                                        continue;
                                    }
                                }
                            }
                        }
                        return Err(err);
                    }
                }
            }
        }

        let base_client = LazyHttpClient::new(None);
        let default_headers = Arc::new(headers);

        let max_concurrency = if let Some(sockets) = config.maxsockets {
            if sockets == 0 {
                DEFAULT_MAX_CONCURRENT_REQUESTS
            } else {
                sockets
            }
        } else if config.max_concurrent_requests == 0 {
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

        let has_scoped_auth = !config.auth_tokens.is_empty() || !config.basic_auths.is_empty();
        let has_any_auth = config.auth_token.is_some() || has_scoped_auth;
        let has_non_error_retry_status = config.retry_on_status.iter().any(|&s| s < 400);
        let bearer_auth_header = config
            .auth_token
            .as_deref()
            .and_then(|token| HeaderValue::from_str(&format!("Bearer {token}")).ok());

        let http1_static_headers: Arc<[u8]> =
            crate::http1_pool::format_static_headers(&default_headers).into();
        let http1_max_idle_per_host = if let Some(sockets) = config.maxsockets {
            if sockets == 0 {
                DEFAULT_POOL_MAX_IDLE_PER_HOST
            } else {
                sockets
            }
        } else if config.pool_max_idle_per_host == 0 {
            DEFAULT_POOL_MAX_IDLE_PER_HOST
        } else {
            config.pool_max_idle_per_host
        };
        let may_use_http_proxy = config.proxy.is_some()
            || config.http_proxy.is_some()
            || config.https_proxy.is_some()
            || has_proxy_env_vars();

        Ok(Self {
            base_client,
            default_headers,
            config: Arc::new(config),
            semaphore,
            circuit_breaker,
            http_requests: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            http_304s: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            scoped_clients: Arc::new(scoped_clients),
            global_client,
            has_scoped_auth,
            has_any_auth,
            has_non_error_retry_status,
            bearer_auth_header,
            http1_pool: Arc::new(crate::http1_pool::Http1Pool::new()),
            http1_static_headers,
            http1_max_idle_per_host,
            may_use_http_proxy,
            in_flight_metadata: Arc::new(InFlightGroup::new()),
            in_flight_tarballs: Arc::new(InFlightGroup::new()),
            packument_cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Calculate backoff duration for a given retry attempt index (0-based).
    pub fn calculate_backoff(&self, attempt: usize) -> Duration {
        self.config.calculate_backoff(attempt)
    }

    /// Access the client configuration.
    pub fn config(&self) -> &RegistryClientConfig {
        &self.config
    }

    /// Returns the total number of HTTP requests issued by this client.
    pub fn http_requests(&self) -> u64 {
        self.http_requests
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns the total number of HTTP 304 (Not Modified) responses received.
    pub fn http_304s(&self) -> u64 {
        self.http_304s.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reset HTTP request and 304 counters.
    pub fn reset_http_metrics(&self) {
        self.http_requests
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.http_304s
            .store(0, std::sync::atomic::Ordering::Relaxed);
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
        let Some(raw_host) = url.host_str() else {
            return false;
        };
        let port_or_default = url.port_or_known_default();

        if let Some(reg_host) = self.config.default_registry.host_str() {
            if reg_host.eq_ignore_ascii_case(raw_host)
                && self.config.default_registry.port_or_known_default() == port_or_default
            {
                return true;
            }
        }

        for scoped_reg in self.config.scoped_registries.values() {
            if let Some(shost) = scoped_reg.host_str() {
                if shost.eq_ignore_ascii_case(raw_host)
                    && scoped_reg.port_or_known_default() == port_or_default
                {
                    return true;
                }
            }
        }

        if self.config.trusted_hosts.is_empty() {
            return false;
        }

        let host: Cow<'_, str> = if raw_host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(raw_host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(raw_host)
        };

        if let Some(port) = port_or_default {
            use std::io::Write as _;
            let mut stack_buf = [0u8; 272];
            let mut cursor = std::io::Cursor::new(&mut stack_buf[..]);
            if write!(&mut cursor, "{host}:{port}").is_ok() {
                let len = cursor.position() as usize;
                if let Ok(key) = std::str::from_utf8(&stack_buf[..len]) {
                    if self.config.trusted_hosts.contains(key) {
                        return true;
                    }
                }
            } else if self
                .config
                .trusted_hosts
                .contains(&format!("{host}:{port}"))
            {
                return true;
            }
        }
        self.config.trusted_hosts.contains(host.as_ref())
    }

    /// The `Authorization` value npm would send: a Bearer token when one is
    /// configured, otherwise URI-scoped Basic credentials.
    pub fn auth_header_for_url(&self, url: &Url) -> Option<String> {
        if let Some(token) = self.auth_token_for_url(url) {
            return Some(format!("Bearer {token}"));
        }
        if self.config.basic_auths.is_empty() {
            return None;
        }
        let host = url.host_str()?.to_ascii_lowercase();
        let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let mut path = url.path().to_string();
        loop {
            let key = format!(
                "//{host}{port}{}",
                if path.ends_with('/') {
                    path.clone()
                } else {
                    format!("{path}/")
                }
            );
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
        if !self.config.auth_tokens.is_empty() {
            let host_lower: Cow<'_, str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
                Cow::Owned(host.to_ascii_lowercase())
            } else {
                Cow::Borrowed(host)
            };
            let port_part = if let Some(port) = url.port() {
                format!(":{port}")
            } else {
                String::new()
            };
            let path = url.path();
            let normalized_path: Cow<'_, str> = if path.ends_with('/') {
                Cow::Borrowed(path)
            } else {
                Cow::Owned(format!("{path}/"))
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
        }

        // Hardening: Fallback to self.config.auth_token ONLY if the host is trusted
        let token = self.config.auth_token.as_deref()?;
        if self.is_trusted_host(url) {
            Some(token)
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
        if package_name.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n') {
            return Err(RegistryError::SecurityViolation(
                "Package name contains forbidden CR/LF characters".into(),
            ));
        }
        let base_str = registry.as_str().trim_end_matches('/');
        let mut url_str = String::with_capacity(base_str.len() + package_name.len() + 4);
        url_str.push_str(base_str);
        url_str.push('/');
        append_encoded_package_name(&mut url_str, package_name);
        Url::parse(&url_str).map_err(RegistryError::UrlParse)
    }

    /// Check whether two URLs share the exact same origin (scheme, host, and port).
    #[inline]
    pub fn is_same_origin(&self, a: &Url, b: &Url) -> bool {
        if a.scheme() != b.scheme() || a.port_or_known_default() != b.port_or_known_default() {
            return false;
        }
        match (a.host_str(), b.host_str()) {
            (Some(ha), Some(hb)) => ha.eq_ignore_ascii_case(hb),
            _ => false,
        }
    }

    /// Check if target URL is trusted to receive authorization headers.
    /// When following redirects or downloading tarballs, never forward registry auth token
    /// to untrusted cross-origin hosts.
    pub fn is_trusted_target(&self, initial_url: &Url, current_url: &Url) -> bool {
        let Some(raw_host) = current_url.host_str() else {
            return false;
        };

        // Never forward authorization headers across an HTTPS -> HTTP downgrade!
        if initial_url.scheme() == "https" && current_url.scheme() == "http" {
            return false;
        }

        // If explicitly defined in auth_tokens or basic_auths map for this URL, that specific host token is allowed
        if self.has_scoped_auth {
            let host: Cow<'_, str> = if raw_host.bytes().any(|b| b.is_ascii_uppercase()) {
                Cow::Owned(raw_host.to_ascii_lowercase())
            } else {
                Cow::Borrowed(raw_host)
            };
            let port_part = if let Some(port) = current_url.port() {
                format!(":{port}")
            } else {
                String::new()
            };
            let default_port_part = if port_part.is_empty() {
                if let Some(port) = current_url.port_or_known_default() {
                    format!(":{port}")
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            let path = current_url.path();
            let normalized_path: Cow<'_, str> = if path.ends_with('/') {
                Cow::Borrowed(path)
            } else {
                Cow::Owned(format!("{path}/"))
            };
            let has_explicit_token = self
                .config
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
                || (!default_port_part.is_empty()
                    && (self.config.auth_tokens.contains_key(&format!(
                        "//{host}{default_port_part}{normalized_path}"
                    )) || self
                        .config
                        .auth_tokens
                        .contains_key(&format!("//{host}{default_port_part}/"))))
                || self
                    .config
                    .basic_auths
                    .contains_key(&format!("//{host}{port_part}{normalized_path}"))
                || self
                    .config
                    .basic_auths
                    .contains_key(&format!("//{host}{port_part}/"))
                || (!default_port_part.is_empty()
                    && self
                        .config
                        .basic_auths
                        .contains_key(&format!("//{host}{default_port_part}/")));

            if has_explicit_token {
                return true;
            }
        }

        // To receive the registry auth token, BOTH initial_url and current_url MUST be trusted hosts!
        if !self.is_trusted_host(initial_url) || !self.is_trusted_host(current_url) {
            return false;
        }

        if self.is_same_origin(initial_url, current_url) {
            return true;
        }

        if self.config.trusted_hosts.is_empty() {
            return false;
        }

        let host: Cow<'_, str> = if raw_host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(raw_host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(raw_host)
        };

        // For cross-origin redirects (different host, port, or scheme), only forward authorization
        // if current_url host and port are explicitly trusted in trusted_hosts
        if let Some(port) = current_url.port_or_known_default() {
            if self
                .config
                .trusted_hosts
                .contains(&format!("{host}:{port}"))
            {
                return true;
            }
        }
        if self.config.trusted_hosts.contains(host.as_ref())
            && initial_url.port_or_known_default() == current_url.port_or_known_default()
        {
            return true;
        }

        false
    }

    #[cfg(test)]
    #[inline]
    fn base_client(&self) -> &Client {
        self.base_client
            .get_or_init(&self.config, &self.default_headers)
            .expect("HTTP client initialization failed after config validation")
    }

    #[inline]
    fn try_client_for_url(&self, url: &Url) -> Result<&Client, RegistryError> {
        if url.scheme() != "https" {
            return self
                .base_client
                .get_or_init(&self.config, &self.default_headers);
        }

        if self.scoped_clients.is_empty() && self.global_client.is_none() {
            return self
                .base_client
                .get_or_init(&self.config, &self.default_headers);
        }

        if let Some(entry) = self.match_scoped_entry(url) {
            return entry.get_or_init(&self.config, &self.default_headers);
        }

        if let Some(ref entry) = self.global_client {
            if self.is_trusted_host(url) {
                return entry.get_or_init(&self.config, &self.default_headers);
            }
        }

        self.base_client
            .get_or_init(&self.config, &self.default_headers)
    }

    /// Returns the appropriate `reqwest::Client` for a target URL:
    /// - If the URL matches a configured scoped TLS identity (longest prefix first), the client
    ///   configured with that scoped identity is returned.
    /// - Otherwise, if a global TLS identity is configured and the host is trusted, the client
    ///   configured with the global identity is returned.
    /// - Otherwise, the unauthenticated client (no client certificate) is returned.
    pub fn client_for_url(&self, url: &Url) -> &Client {
        self.try_client_for_url(url)
            .expect("HTTP client initialization failed after config validation")
    }

    fn match_scoped_entry(&self, url: &Url) -> Option<&Arc<LazyHttpClient>> {
        if url.scheme() != "https" || self.scoped_clients.is_empty() {
            return None;
        }

        let host = url.host_str()?;
        let host_lower = host.to_ascii_lowercase();
        let port_part = if let Some(port) = url.port() {
            format!(":{port}")
        } else {
            String::new()
        };
        let default_port_part = if port_part.is_empty() {
            if let Some(port) = url.port_or_known_default() {
                format!(":{port}")
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let path = url.path();
        let prefixes = generate_path_prefixes(path);

        for prefix in &prefixes {
            if !port_part.is_empty() {
                let cand1 = format!("//{host_lower}{port_part}{prefix}");
                if let Some(client) = self.scoped_clients.get(&cand1) {
                    return Some(client);
                }
                if prefix.ends_with('/') {
                    let no_slash = &prefix[..prefix.len() - 1];
                    let cand1_no_slash = format!("//{host_lower}{port_part}{no_slash}");
                    if let Some(client) = self.scoped_clients.get(&cand1_no_slash) {
                        return Some(client);
                    }
                }
            }

            if !default_port_part.is_empty() {
                let cand_def = format!("//{host_lower}{default_port_part}{prefix}");
                if let Some(client) = self.scoped_clients.get(&cand_def) {
                    return Some(client);
                }
                if prefix.ends_with('/') {
                    let no_slash = &prefix[..prefix.len() - 1];
                    let cand_def_no_slash = format!("//{host_lower}{default_port_part}{no_slash}");
                    if let Some(client) = self.scoped_clients.get(&cand_def_no_slash) {
                        return Some(client);
                    }
                }
            }

            let cand2 = format!("//{host_lower}{prefix}");
            if let Some(client) = self.scoped_clients.get(&cand2) {
                return Some(client);
            }
            if prefix.ends_with('/') {
                let no_slash = &prefix[..prefix.len() - 1];
                let cand3 = format!("//{host_lower}{no_slash}");
                if let Some(client) = self.scoped_clients.get(&cand3) {
                    return Some(client);
                }
            }
        }

        None
    }

    /// Match a target URL against scoped TLS identities using longest-prefix-first precedence.
    pub fn match_scoped_client(&self, url: &Url) -> Option<&Client> {
        self.match_scoped_entry(url).map(|entry| {
            entry
                .get_or_init(&self.config, &self.default_headers)
                .expect("Scoped HTTP client initialization failed after config validation")
        })
    }

    /// Check whether a scoped TLS client matches the target URL without triggering client init.
    pub fn has_scoped_tls_for_url(&self, url: &Url) -> bool {
        self.match_scoped_entry(url).is_some()
    }

    /// Check whether a global TLS identity client is configured.
    pub fn has_global_tls(&self) -> bool {
        self.global_client.is_some()
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

    async fn execute_with_borrowed_permit(
        &self,
        method: Method,
        initial_url: Url,
        accept_header: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<(Response, SemaphorePermit<'_>), RegistryError> {
        let permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| RegistryError::Other(e.to_string()))?;
        let resp = self
            .execute_request_loop(method, initial_url, accept_header, if_none_match)
            .await?;
        Ok((resp, permit))
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_with_borrowed_permit_from(
        &self,
        method: Method,
        initial_url: Url,
        resume_url: Url,
        resume_redirect_count: usize,
        resume_seen_redirects: Option<HashSet<Url>>,
        start_attempt: usize,
        accept_header: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<(Response, SemaphorePermit<'_>), RegistryError> {
        let permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| RegistryError::Other(e.to_string()))?;
        let resp = self
            .execute_request_loop_state(
                method,
                initial_url,
                resume_url,
                resume_redirect_count,
                resume_seen_redirects,
                start_attempt,
                accept_header,
                if_none_match,
            )
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

    #[inline]
    fn can_use_http1_pool(&self, url: &Url) -> bool {
        !self.may_use_http_proxy && !self.has_non_error_retry_status && url.scheme() == "http"
    }

    async fn execute_http1_fast(
        &self,
        initial_url: &Url,
        accept_header: Option<&str>,
        accept_gzip: bool,
        if_none_match: Option<&str>,
        collect_cache_metadata: bool,
        kind: FastBodyKind<'_>,
    ) -> Result<DirectOrResume, RegistryError> {
        let host_key = if self.config.circuit_breaker_enabled {
            let hk = url_host_key(initial_url);
            if self.circuit_breaker.check_state(&hk).await == CircuitBreakerState::Open {
                return Err(RegistryError::CircuitBreakerOpen {
                    host: hk.into_owned(),
                });
            }
            Some(hk)
        } else {
            None
        };

        let auth_cow: Option<Cow<'_, str>> = if self.has_any_auth
            && if self.has_scoped_auth {
                self.is_trusted_target(initial_url, initial_url)
            } else {
                self.is_trusted_host(initial_url)
            } {
            if !self.has_scoped_auth {
                if let Some(ref hdr) = self.bearer_auth_header {
                    hdr.to_str().ok().map(Cow::Borrowed)
                } else {
                    self.auth_header_for_url(initial_url).map(Cow::Owned)
                }
            } else {
                self.auth_header_for_url(initial_url).map(Cow::Owned)
            }
        } else {
            None
        };

        let mut attempt = 0;
        loop {
            let permit = self
                .semaphore
                .acquire()
                .await
                .map_err(|e| RegistryError::Other(e.to_string()))?;

            track_http_request(&Method::GET, initial_url);
            self.http_requests
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            let target = match kind {
                FastBodyKind::Metadata { max_size, .. } => {
                    crate::http1_pool::BodyTarget::Metadata { max_size }
                }
                FastBodyKind::TarballBytes {
                    max_size,
                    compute_sha512,
                    ..
                } => crate::http1_pool::BodyTarget::TarballBytes {
                    max_size,
                    compute_sha512,
                },
                FastBodyKind::TarballFile {
                    max_size,
                    disk_threshold,
                    temp_path,
                    dest_path,
                    ..
                } => crate::http1_pool::BodyTarget::TarballFile {
                    max_size,
                    disk_threshold,
                    temp_path,
                    dest_path,
                },
            };

            let params = crate::http1_pool::Http1RequestParams {
                method: &Method::GET,
                url: initial_url,
                static_headers: &self.http1_static_headers,
                accept: accept_header,
                accept_gzip,
                if_none_match,
                auth_header: auth_cow.as_deref(),
                collect_cache_metadata,
                connect_timeout: self.config.connect_timeout,
                request_timeout: self.config.timeout,
                chunk_idle_timeout: self.config.chunk_idle_timeout,
                pool_idle_timeout: self.config.pool_idle_timeout,
                max_idle_per_host: self.http1_max_idle_per_host,
            };

            let hop_res = crate::http1_pool::execute_hop(&self.http1_pool, params, target).await;
            drop(permit);

            match hop_res {
                Ok(crate::http1_pool::HopOutcome::Success { etag, payload }) => {
                    if let Some(ref hk) = host_key {
                        self.circuit_breaker.record_success(hk).await;
                    }
                    return Ok(DirectOrResume::Success { etag, payload });
                }
                Ok(crate::http1_pool::HopOutcome::NotModified {
                    etag,
                    cache_metadata,
                }) => {
                    self.http_304s
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Some(ref hk) = host_key {
                        self.circuit_breaker.record_success(hk).await;
                    }
                    return Ok(DirectOrResume::NotModified {
                        etag,
                        cache_metadata,
                    });
                }
                Ok(crate::http1_pool::HopOutcome::FallbackToReqwest) => {
                    return Ok(DirectOrResume::ResumeReqwest {
                        current_url: initial_url.clone(),
                        redirect_count: 0,
                        seen_redirect_urls: None,
                        attempt,
                    });
                }
                Ok(crate::http1_pool::HopOutcome::Redirect { status, location }) => {
                    if 1 > MAX_REDIRECTS {
                        return Err(RegistryError::TooManyRedirects(MAX_REDIRECTS));
                    }
                    let Some(loc_res) = location else {
                        return Err(RegistryError::ServerError {
                            status: status.as_u16(),
                            body: "Redirect response missing Location header".into(),
                        });
                    };
                    let loc_str = match loc_res {
                        Ok(s) => s,
                        Err(()) => {
                            return Err(RegistryError::SecurityViolation(
                                "Invalid characters in redirect Location header".into(),
                            ))
                        }
                    };
                    if loc_str.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n') {
                        return Err(RegistryError::SecurityViolation(
                            "Location header contains forbidden CR/LF characters".into(),
                        ));
                    }
                    let next_url = initial_url.join(&loc_str).map_err(RegistryError::UrlParse)?;
                    let next_scheme = next_url.scheme();
                    if !next_scheme.eq_ignore_ascii_case("http")
                        && !next_scheme.eq_ignore_ascii_case("https")
                    {
                        return Err(RegistryError::SecurityViolation(format!(
                            "Redirect to unsupported scheme '{}': only http and https are allowed",
                            next_scheme.to_ascii_lowercase()
                        )));
                    }
                    let mut seen = HashSet::with_capacity(4);
                    seen.insert(initial_url.clone());
                    if !seen.insert(next_url.clone()) {
                        return Err(RegistryError::SecurityViolation(format!(
                            "Redirect loop detected: '{next_url}' was visited more than once"
                        )));
                    }
                    debug!("Following redirect {} -> {}", initial_url, next_url);
                    return Ok(DirectOrResume::ResumeReqwest {
                        current_url: next_url,
                        redirect_count: 1,
                        seen_redirect_urls: Some(seen),
                        attempt,
                    });
                }
                Ok(crate::http1_pool::HopOutcome::ErrorStatus {
                    status,
                    retry_after,
                    www_authenticate,
                    body,
                }) => {
                    let is_rate_limited = status == StatusCode::TOO_MANY_REQUESTS;
                    let is_retryable_server_error =
                        self.config.retry_on_status.contains(&status.as_u16())
                            || status.is_server_error();

                    if is_rate_limited || is_retryable_server_error {
                        let retry_after_secs = retry_after
                            .as_deref()
                            .and_then(parse_retry_after_str);
                        let within_backoff_budget = if let Some(secs) = retry_after_secs {
                            Duration::from_secs(secs) <= self.config.max_retry_backoff
                        } else {
                            true
                        };
                        if within_backoff_budget && attempt < self.config.max_retries {
                            let delay = if let Some(secs) = retry_after_secs {
                                Duration::from_secs(secs)
                            } else {
                                self.calculate_backoff(attempt)
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
                        }
                        if let Some(ref hk) = host_key {
                            self.circuit_breaker.record_failure(hk).await;
                        }
                        if is_rate_limited {
                            return Err(RegistryError::RateLimited {
                                retry_after: retry_after_secs,
                            });
                        }
                    } else if let Some(ref hk) = host_key {
                        self.circuit_breaker.record_success(hk).await;
                    }

                    if status == StatusCode::NOT_FOUND {
                        let label = match kind {
                            FastBodyKind::Metadata { package_name, .. } => {
                                crate::not_found::record(
                                    package_name,
                                    initial_url.as_str(),
                                    &body,
                                );
                                package_name.to_string()
                            }
                            FastBodyKind::TarballBytes {
                                not_found_label, ..
                            }
                            | FastBodyKind::TarballFile {
                                not_found_label, ..
                            } => not_found_label.to_string(),
                        };
                        return Err(RegistryError::PackageNotFound {
                            package: label,
                            status: 404,
                        });
                    }
                    if status == StatusCode::UNAUTHORIZED {
                        if let Some(www) = www_authenticate {
                            return Err(RegistryError::AuthChallenge {
                                url: initial_url.to_string(),
                                www_authenticate: www,
                                body,
                            });
                        }
                        return Err(RegistryError::Unauthorized {
                            url: initial_url.to_string(),
                            status: 401,
                            message: body,
                        });
                    }
                    if status == StatusCode::FORBIDDEN {
                        return Err(RegistryError::Forbidden {
                            url: initial_url.to_string(),
                            status: 403,
                            message: body,
                        });
                    }
                    return Err(RegistryError::ServerError {
                        status: status.as_u16(),
                        body,
                    });
                }
                Err(err) => {
                    if err.is_transient() && attempt < self.config.max_retries {
                        let delay = self.calculate_backoff(attempt);
                        debug!(
                            "HTTP/1.1 request error {:?} for {}, retrying in {:?} (attempt {}/{})",
                            err,
                            initial_url,
                            delay,
                            attempt + 1,
                            self.config.max_retries
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    if let Some(ref hk) = host_key {
                        if err.is_transient() {
                            self.circuit_breaker.record_failure(hk).await;
                        }
                    }
                    return Err(err);
                }
            }
        }
    }

    /// Internal request dispatch loop with redirect security policy, circuit breaking, and retry backoff.
    async fn execute_request_loop(
        &self,
        method: Method,
        initial_url: Url,
        accept_header: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Response, RegistryError> {
        self.execute_request_loop_state(
            method,
            initial_url.clone(),
            initial_url,
            0,
            None,
            0,
            accept_header,
            if_none_match,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_request_loop_state(
        &self,
        method: Method,
        initial_url: Url,
        resume_url: Url,
        resume_redirect_count: usize,
        resume_seen_redirects: Option<HashSet<Url>>,
        start_attempt: usize,
        accept_header: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Response, RegistryError> {
        let host_key = if self.config.circuit_breaker_enabled {
            let hk = url_host_key(&initial_url);
            let state = self.circuit_breaker.check_state(&hk).await;
            if state == CircuitBreakerState::Open {
                return Err(RegistryError::CircuitBreakerOpen {
                    host: hk.into_owned(),
                });
            }
            Some(hk)
        } else {
            None
        };

        let initial_auth = if self.has_any_auth
            && if self.has_scoped_auth {
                self.is_trusted_target(&initial_url, &initial_url)
            } else {
                self.is_trusted_host(&initial_url)
            }
        {
            if !self.has_scoped_auth {
                self.bearer_auth_header.clone().or_else(|| {
                    self.auth_header_for_url(&initial_url)
                        .and_then(|s| HeaderValue::from_str(&s).ok())
                })
            } else {
                self.auth_header_for_url(&initial_url)
                    .and_then(|s| HeaderValue::from_str(&s).ok())
            }
        } else {
            None
        };

        let mut attempt = start_attempt;
        let mut first_resume = Some((resume_url, resume_redirect_count, resume_seen_redirects));

        loop {
            let (mut current_url, mut redirect_count, mut seen_redirect_urls) = first_resume
                .take()
                .unwrap_or_else(|| (initial_url.clone(), 0, None));
            let mut current_method = method.clone();

            let response_result: Result<Response, RegistryError> = loop {
                let client = match self.try_client_for_url(&current_url) {
                    Ok(c) => c,
                    Err(e) => break Err(e),
                };
                let mut req = client.request(current_method.clone(), current_url.clone());

                if let Some(accept) = accept_header {
                    if accept == NPM_INSTALL_ACCEPT {
                        req = req.header(ACCEPT, HeaderValue::from_static(NPM_INSTALL_ACCEPT));
                    } else if accept == "application/json" {
                        req = req.header(ACCEPT, HeaderValue::from_static("application/json"));
                    } else if accept == NPM_INSTALL_V1_JSON {
                        req = req.header(ACCEPT, HeaderValue::from_static(NPM_INSTALL_V1_JSON));
                    } else {
                        req = req.header(ACCEPT, accept);
                    }
                }

                if let Some(etag) = if_none_match {
                    req = req.header(IF_NONE_MATCH, etag);
                }

                // Security check: only send auth headers if the target is trusted (same origin or in trusted_hosts)
                if self.has_any_auth {
                    if redirect_count == 0 {
                        if let Some(ref auth) = initial_auth {
                            req = req.header(AUTHORIZATION, auth.clone());
                        }
                    } else if self.is_trusted_target(&initial_url, &current_url) {
                        if !self.has_scoped_auth {
                            if let Some(ref bearer) = self.bearer_auth_header {
                                req = req.header(AUTHORIZATION, bearer.clone());
                            } else if let Some(auth) = self.auth_header_for_url(&current_url) {
                                req = req.header(AUTHORIZATION, auth);
                            }
                        } else if let Some(auth) = self.auth_header_for_url(&current_url) {
                            req = req.header(AUTHORIZATION, auth);
                        }
                    } else {
                        debug!(
                            "Stripping Authorization header on redirect from '{}' to untrusted '{}'",
                            initial_url, current_url
                        );
                    }
                }

                track_http_request(&current_method, &current_url);
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

                    if status == StatusCode::SEE_OTHER
                        || ((status == StatusCode::MOVED_PERMANENTLY || status == StatusCode::FOUND)
                            && current_method == Method::POST)
                    {
                        current_method = Method::GET;
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
                        if loc_str.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n') {
                            break Err(RegistryError::SecurityViolation(
                                "Location header contains forbidden CR/LF characters".into(),
                            ));
                        }
                        let next_url = match current_url.join(loc_str) {
                            Ok(u) => u,
                            Err(e) => break Err(RegistryError::UrlParse(e)),
                        };
                        let next_scheme = next_url.scheme();
                        if !next_scheme.eq_ignore_ascii_case("http")
                            && !next_scheme.eq_ignore_ascii_case("https")
                        {
                            break Err(RegistryError::SecurityViolation(format!(
                                "Redirect to unsupported scheme '{}': only http and https are allowed",
                                next_scheme.to_ascii_lowercase()
                            )));
                        }
                        let seen = seen_redirect_urls.get_or_insert_with(|| {
                            let mut set = HashSet::with_capacity(4);
                            set.insert(initial_url.clone());
                            set
                        });
                        if !seen.insert(next_url.clone()) {
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
                    if !self.has_non_error_retry_status
                        && (status.is_success() || status == StatusCode::NOT_MODIFIED)
                    {
                        if let Some(ref hk) = host_key {
                            self.circuit_breaker.record_success(hk).await;
                        }
                        return Ok(resp);
                    }

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
                                self.calculate_backoff(attempt)
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
                            if let Some(ref hk) = host_key {
                                self.circuit_breaker.record_failure(hk).await;
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
                                self.calculate_backoff(attempt)
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
                            if let Some(ref hk) = host_key {
                                self.circuit_breaker.record_failure(hk).await;
                            }
                            return Ok(resp);
                        }
                    }

                    if let Some(ref hk) = host_key {
                        self.circuit_breaker.record_success(hk).await;
                    }
                    return Ok(resp);
                }
                Err(err) => {
                    // Check if network error is transient and retryable
                    if err.is_transient() && attempt < self.config.max_retries {
                        let delay = self.calculate_backoff(attempt);
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
                        if let Some(ref hk) = host_key {
                            if err.is_transient() {
                                self.circuit_breaker.record_failure(hk).await;
                            }
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
        if let Some(otp_code) = otp {
            if otp_code.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n') {
                return Err(RegistryError::SecurityViolation(
                    "OTP code contains forbidden CR/LF characters".into(),
                ));
            }
        }

        let host_key = if self.config.circuit_breaker_enabled {
            let hk = url_host_key(&initial_url);
            let state = self.circuit_breaker.check_state(&hk).await;
            if state == CircuitBreakerState::Open {
                return Err(RegistryError::CircuitBreakerOpen {
                    host: hk.into_owned(),
                });
            }
            Some(hk)
        } else {
            None
        };

        let mut attempt = 0;

        loop {
            let mut current_url = initial_url.clone();
            let mut current_method = method.clone();
            let mut current_body = body.clone();
            let mut current_content_type = content_type;
            let mut redirect_count = 0;
            let mut seen_redirect_urls: Option<HashSet<Url>> = None;

            let response_result: Result<Response, RegistryError> = loop {
                let client = match self.try_client_for_url(&current_url) {
                    Ok(c) => c,
                    Err(e) => break Err(e),
                };
                let mut req = client.request(current_method.clone(), current_url.clone());

                if let Some(ct) = current_content_type {
                    req = req.header(CONTENT_TYPE, ct);
                }

                if let Some(accept) = accept_header {
                    req = req.header(ACCEPT, accept);
                }

                // Security check: only send auth headers if the target is trusted (same origin or in trusted_hosts),
                // and ONLY send npm-otp to the exact initial origin (an OTP belongs strictly to the origin it was issued for).
                if self.has_any_auth || otp.is_some() {
                    let should_send_auth = self.is_trusted_target(&initial_url, &current_url);
                    if should_send_auth {
                        if self.has_any_auth {
                            if !self.has_scoped_auth {
                                if let Some(ref bearer) = self.bearer_auth_header {
                                    req = req.header(AUTHORIZATION, bearer.clone());
                                } else if let Some(auth) = self.auth_header_for_url(&current_url) {
                                    req = req.header(AUTHORIZATION, auth);
                                }
                            } else if let Some(auth) = self.auth_header_for_url(&current_url) {
                                req = req.header(AUTHORIZATION, auth);
                            }
                        }
                        if let Some(otp_code) = otp {
                            if self.is_same_origin(&initial_url, &current_url) {
                                req = req.header("npm-otp", otp_code);
                            }
                        }
                    } else {
                        debug!(
                            "Stripping Authorization and OTP headers on redirect from '{}' to untrusted '{}'",
                            initial_url, current_url
                        );
                    }
                }

                if current_method != Method::GET && current_method != Method::HEAD {
                    req = req.body(current_body.clone());
                }

                track_http_request(&current_method, &current_url);
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

                    if status == StatusCode::SEE_OTHER
                        || ((status == StatusCode::MOVED_PERMANENTLY || status == StatusCode::FOUND)
                            && current_method == Method::POST)
                    {
                        current_method = Method::GET;
                        current_body = Vec::new();
                        current_content_type = None;
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
                        if loc_str.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n') {
                            break Err(RegistryError::SecurityViolation(
                                "Location header contains forbidden CR/LF characters".into(),
                            ));
                        }
                        let next_url = match current_url.join(loc_str) {
                            Ok(u) => u,
                            Err(e) => break Err(RegistryError::UrlParse(e)),
                        };
                        let next_scheme = next_url.scheme();
                        if !next_scheme.eq_ignore_ascii_case("http")
                            && !next_scheme.eq_ignore_ascii_case("https")
                        {
                            break Err(RegistryError::SecurityViolation(format!(
                                "Redirect to unsupported scheme '{}': only http and https are allowed",
                                next_scheme.to_ascii_lowercase()
                            )));
                        }
                        let seen = seen_redirect_urls.get_or_insert_with(|| {
                            let mut set = HashSet::with_capacity(4);
                            set.insert(initial_url.clone());
                            set
                        });
                        if !seen.insert(next_url.clone()) {
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
                                self.calculate_backoff(attempt)
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
                            if let Some(ref hk) = host_key {
                                self.circuit_breaker.record_failure(hk).await;
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
                                self.calculate_backoff(attempt)
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
                            if let Some(ref hk) = host_key {
                                self.circuit_breaker.record_failure(hk).await;
                            }
                            return Ok(resp);
                        }
                    }

                    if let Some(ref hk) = host_key {
                        self.circuit_breaker.record_success(hk).await;
                    }
                    return Ok(resp);
                }
                Err(err) => {
                    if err.is_transient() && attempt < self.config.max_retries {
                        let delay = self.calculate_backoff(attempt);
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
                        if let Some(ref hk) = host_key {
                            if err.is_transient() {
                                self.circuit_breaker.record_failure(hk).await;
                            }
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
        match self
            .get_package_metadata_from_url_conditional_with_accept(
                package_name,
                url.clone(),
                if_none_match,
                NPM_INSTALL_V1_JSON,
            )
            .await
        {
            // pacote treats a corgi 404 as "abbreviated documents unsupported"
            // and asks once more for the full packument before failing.
            // Strict private registries / proxies may return 406 Not Acceptable or 415 Unsupported Media Type.
            Err(RegistryError::PackageNotFound { .. })
            | Err(RegistryError::ServerError {
                status: 406 | 415, ..
            }) => {
                self.get_package_metadata_from_url_conditional_with_accept(
                    package_name,
                    url,
                    if_none_match,
                    "application/json",
                )
                .await
            }
            other => other,
        }
    }

    /// Fetch lean install metadata requesting `NPM_INSTALL_ACCEPT`.
    pub async fn get_package_metadata_install(
        &self,
        package_name: &str,
    ) -> Result<AbbreviatedPackageMetadata, RegistryError> {
        let url = self.package_metadata_url(package_name)?;
        self.get_package_metadata_install_from_url(package_name, url).await
    }

    /// Fetch lean install metadata conditionally using ETag (`If-None-Match`) requesting `NPM_INSTALL_ACCEPT`.
    pub async fn get_package_metadata_install_conditional(
        &self,
        package_name: &str,
        if_none_match: Option<&str>,
    ) -> Result<MetadataFetchResult, RegistryError> {
        let url = self.package_metadata_url(package_name)?;
        self.get_package_metadata_install_from_url_conditional(package_name, url, if_none_match)
            .await
    }

    /// Fetch lean install metadata from an explicit URL requesting `NPM_INSTALL_ACCEPT`.
    pub async fn get_package_metadata_install_from_url(
        &self,
        package_name: &str,
        url: Url,
    ) -> Result<AbbreviatedPackageMetadata, RegistryError> {
        match self
            .get_package_metadata_install_from_url_conditional(package_name, url, None)
            .await?
        {
            MetadataFetchResult::Fresh { metadata, .. } => Ok(metadata),
            MetadataFetchResult::NotModified { .. } => Err(RegistryError::Other(
                "Unexpected 304 Not Modified response for unconditional request".into(),
            )),
        }
    }

    /// Fetch lean install metadata from an explicit URL with ETag conditional validation requesting `NPM_INSTALL_ACCEPT`.
    pub async fn get_package_metadata_install_from_url_conditional(
        &self,
        package_name: &str,
        url: Url,
        if_none_match: Option<&str>,
    ) -> Result<MetadataFetchResult, RegistryError> {
        match self
            .get_package_metadata_from_url_conditional_with_accept(
                package_name,
                url.clone(),
                if_none_match,
                NPM_INSTALL_ACCEPT,
            )
            .await
        {
            // If abbreviated documents are unsupported or return 404, 406 Not Acceptable,
            // or 415 Unsupported Media Type, fall back once to full JSON
            Err(RegistryError::PackageNotFound { .. })
            | Err(RegistryError::ServerError {
                status: 406 | 415, ..
            }) => {
                self.get_package_metadata_from_url_conditional_with_accept(
                    package_name,
                    url,
                    if_none_match,
                    "application/json",
                )
                .await
            }
            other => other,
        }
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

    /// Canonical representation-specific cache key for a package (`{url}::abbrev` vs `{url}::full`).
    /// Keeps abbreviated (`application/vnd.npm.install-v1+json`) and full (`application/json`) entries
    /// and ETags strictly isolated.
    pub fn packument_cache_key(
        &self,
        package_name: &str,
        representation: PackumentRepresentation,
    ) -> Result<String, RegistryError> {
        let url = self.package_metadata_url(package_name)?;
        Ok(format!(
            "{}::{}",
            url.as_str(),
            representation.cache_key_suffix()
        ))
    }

    /// Return the cached ETag for `(package_name, representation)` if stored in memory.
    pub fn cached_packument_etag(
        &self,
        package_name: &str,
        representation: PackumentRepresentation,
    ) -> Option<String> {
        let url = self.package_metadata_url(package_name).ok()?;
        let key = PackumentCacheKey {
            url: url.as_str().to_owned(),
            representation,
        };
        let guard = self
            .packument_cache
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard.get(&key).and_then(|e| e.etag.clone())
    }

    /// Return the cached `(etag, metadata)` pair for `(package_name, representation)` if present.
    pub fn cached_packument(
        &self,
        package_name: &str,
        representation: PackumentRepresentation,
    ) -> Option<(Option<String>, AbbreviatedPackageMetadata)> {
        let url = self.package_metadata_url(package_name).ok()?;
        let key = PackumentCacheKey {
            url: url.as_str().to_owned(),
            representation,
        };
        let entry = {
            let guard = self
                .packument_cache
                .read()
                .unwrap_or_else(|e| e.into_inner());
            guard
                .get(&key)
                .map(|e| (e.etag.clone(), Arc::clone(&e.metadata)))
        };
        entry.map(|(etag, meta)| (etag, (*meta).clone()))
    }

    fn store_cached_packument(
        &self,
        url: &Url,
        representation: PackumentRepresentation,
        etag: Option<&str>,
        metadata: &AbbreviatedPackageMetadata,
        cache_metadata: &serde_json::Value,
    ) {
        const MAX_PACKUMENT_CACHE_ENTRIES: usize = 1024;
        let no_store = cache_metadata
            .pointer("/response/headers/cache-control")
            .and_then(|v| v.as_str())
            .is_some_and(|cc| {
                cc.split(',')
                    .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
            });
        if no_store {
            return;
        }
        let key = PackumentCacheKey {
            url: url.as_str().to_owned(),
            representation,
        };
        let metadata_arc = Arc::new(metadata.clone());
        let mut guard = self
            .packument_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if guard.len() >= MAX_PACKUMENT_CACHE_ENTRIES && !guard.contains_key(&key) {
            if let Some(evict_key) = guard.keys().next().cloned() {
                guard.remove(&evict_key);
            }
        }
        guard.insert(
            key,
            CachedPackumentEntry {
                etag: etag.map(str::to_owned),
                metadata: metadata_arc,
                cache_metadata: cache_metadata.clone(),
            },
        );
    }

    /// Clear all cached packument representations held in memory.
    pub fn clear_packument_cache(&self) {
        self.packument_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Negotiate packument metadata using representation-specific ETags and automatic fallback.
    ///
    /// - Requests `application/vnd.npm.install-v1+json` (`NPM_INSTALL_ACCEPT`) by default.
    /// - When `options.require_publish_times` (`--before`) or `options.require_full_fields` is set,
    ///   negotiates the full packument (`application/json`) cleanly under its separate cache key & ETag.
    /// - Revalidates against representation-specific cached ETag via `If-None-Match` and serves `304`
    ///   without re-parsing or overwriting the other representation's cache entry.
    pub async fn get_package_metadata_negotiated(
        &self,
        package_name: &str,
        options: PackumentFetchOptions,
    ) -> Result<AbbreviatedPackageMetadata, RegistryError> {
        let url = self.package_metadata_url(package_name)?;
        let target_repr = options.effective_representation();
        let cache_key = PackumentCacheKey {
            url: url.as_str().to_owned(),
            representation: target_repr,
        };
        let cached_etag = {
            let guard = self
                .packument_cache
                .read()
                .unwrap_or_else(|e| e.into_inner());
            guard.get(&cache_key).and_then(|c| c.etag.clone())
        };

        match self
            .get_package_metadata_negotiated_conditional_at_url(
                package_name,
                &url,
                cached_etag.as_deref(),
                options,
            )
            .await?
        {
            MetadataFetchResult::Fresh { metadata, .. } => Ok(metadata),
            MetadataFetchResult::NotModified { etag, cache_metadata } => {
                let cached_meta = {
                    let mut guard = self
                        .packument_cache
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    guard.get_mut(&cache_key).map(|entry| {
                        if etag.is_some() {
                            entry.etag = etag;
                        }
                        entry.cache_metadata = cache_metadata;
                        Arc::clone(&entry.metadata)
                    })
                };
                if let Some(metadata) = cached_meta {
                    Ok((*metadata).clone())
                } else {
                    match self
                        .get_package_metadata_negotiated_conditional_at_url(
                            package_name,
                            &url,
                            None,
                            options,
                        )
                        .await?
                    {
                        MetadataFetchResult::Fresh { metadata, .. } => Ok(metadata),
                        MetadataFetchResult::NotModified { .. } => Err(RegistryError::Other(
                            "Unexpected 304 Not Modified response for uncached request".into(),
                        )),
                    }
                }
            }
        }
    }

    /// Fetch negotiated metadata with caller-supplied conditional `If-None-Match` ETag and
    /// representation-isolated fallback to full JSON (`application/json`).
    pub async fn get_package_metadata_negotiated_conditional(
        &self,
        package_name: &str,
        if_none_match: Option<&str>,
        options: PackumentFetchOptions,
    ) -> Result<MetadataFetchResult, RegistryError> {
        let url = self.package_metadata_url(package_name)?;
        self.get_package_metadata_negotiated_conditional_at_url(
            package_name,
            &url,
            if_none_match,
            options,
        )
        .await
    }

    async fn get_package_metadata_negotiated_conditional_at_url(
        &self,
        package_name: &str,
        url: &Url,
        if_none_match: Option<&str>,
        options: PackumentFetchOptions,
    ) -> Result<MetadataFetchResult, RegistryError> {
        let target_repr = options.effective_representation();
        let accept = target_repr.accept_header();

        let res = self
            .get_package_metadata_from_url_conditional_with_accept(
                package_name,
                url.clone(),
                if_none_match,
                accept,
            )
            .await;

        let mut stored_repr = target_repr;
        let final_res = match res {
            // Never reuse an abbreviated ETag when falling back to Full!
            Err(RegistryError::PackageNotFound { .. })
            | Err(RegistryError::ServerError {
                status: 406 | 415, ..
            }) if target_repr == PackumentRepresentation::Abbreviated => {
                stored_repr = PackumentRepresentation::Full;
                // A full 304 would refer to a different document than the
                // caller's abbreviated cache entry.
                self.get_package_metadata_from_url_conditional_with_accept(
                    package_name,
                    url.clone(),
                    None,
                    "application/json",
                )
                .await?
            }
            other => other?,
        };

        if let MetadataFetchResult::Fresh {
            ref metadata,
            ref etag,
            ref cache_metadata,
        } = final_res
        {
            // Store under `stored_repr` (the representation/parse_mode actually produced),
            // so Install-parsed responses never poison the Full slot even if the server replied
            // with `Content-Type: application/json`.
            self.store_cached_packument(
                url,
                stored_repr,
                etag.as_deref(),
                metadata,
                cache_metadata,
            );
        }

        Ok(final_res)
    }

    /// Try abbreviated negotiation first and fall back to full packument whenever `needs_full` returns `true`
    /// (for example when abbreviated metadata omits `time` for `--before` or omits `license`/`scripts`).
    pub async fn get_package_metadata_with_full_fallback<F>(
        &self,
        package_name: &str,
        if_none_match: Option<&str>,
        needs_full: F,
    ) -> Result<MetadataFetchResult, RegistryError>
    where
        F: FnOnce(&AbbreviatedPackageMetadata) -> bool,
    {
        let url = self.package_metadata_url(package_name)?;
        let res = self
            .get_package_metadata_negotiated_conditional_at_url(
                package_name,
                &url,
                if_none_match,
                PackumentFetchOptions::abbreviated(),
            )
            .await?;

        if let MetadataFetchResult::Fresh { ref metadata, .. } = res {
            if needs_full(metadata) {
                let full_etag = {
                    let key = PackumentCacheKey {
                        url: url.as_str().to_owned(),
                        representation: PackumentRepresentation::Full,
                    };
                    self.packument_cache
                        .read()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&key)
                        .and_then(|c| c.etag.clone())
                };
                let fb_res = self
                    .get_package_metadata_negotiated_conditional_at_url(
                        package_name,
                        &url,
                        full_etag.as_deref(),
                        PackumentFetchOptions::full(),
                    )
                    .await?;
                if let MetadataFetchResult::NotModified {
                    etag,
                    cache_metadata,
                } = fb_res
                {
                    let key = PackumentCacheKey {
                        url: url.as_str().to_owned(),
                        representation: PackumentRepresentation::Full,
                    };
                    let cached_full = {
                        let mut guard = self
                            .packument_cache
                            .write()
                            .unwrap_or_else(|e| e.into_inner());
                        guard.get_mut(&key).map(|entry| {
                            if etag.is_some() {
                                entry.etag = etag.clone();
                            }
                            entry.cache_metadata = cache_metadata.clone();
                            (entry.etag.clone(), Arc::clone(&entry.metadata))
                        })
                    };
                    if let Some((cached_etag, cached_meta)) = cached_full {
                        return Ok(MetadataFetchResult::Fresh {
                            metadata: (*cached_meta).clone(),
                            etag: cached_etag,
                            cache_metadata,
                        });
                    }
                    return self
                        .get_package_metadata_negotiated_conditional_at_url(
                            package_name,
                            &url,
                            None,
                            PackumentFetchOptions::full(),
                        )
                        .await;
                }
                return Ok(fb_res);
            }
        }
        Ok(res)
    }

    /// Concurrently fetch negotiated packuments with representation-specific ETags and full fallback.
    pub async fn get_package_metadata_negotiated_concurrent<S: AsRef<str>>(
        &self,
        packages: &[(S, Option<String>)],
        options: PackumentFetchOptions,
    ) -> Vec<Result<MetadataFetchResult, RegistryError>> {
        let mut key_to_group: HashMap<(&str, Option<&str>), usize> =
            HashMap::with_capacity(packages.len());
        let mut groups: Vec<(usize, Vec<usize>)> = Vec::with_capacity(packages.len());
        for (idx, (pkg, if_none_match)) in packages.iter().enumerate() {
            let key = (pkg.as_ref(), if_none_match.as_deref());
            if let Some(&grp) = key_to_group.get(&key) {
                groups[grp].1.push(idx);
            } else {
                let grp = groups.len();
                key_to_group.insert(key, grp);
                groups.push((idx, Vec::new()));
            }
        }

        let mut join_set = tokio::task::JoinSet::new();
        for (first_idx, dup_indices) in groups {
            let client = self.clone();
            let (pkg, if_none_match) = &packages[first_idx];
            let name = pkg.as_ref().to_string();
            let etag = if_none_match.clone();
            join_set.spawn(async move {
                let res = client
                    .get_package_metadata_negotiated_conditional(&name, etag.as_deref(), options)
                    .await;
                if dup_indices.is_empty() {
                    return vec![(first_idx, res)];
                }
                let mut out = Vec::with_capacity(1 + dup_indices.len());
                match res {
                    Ok(val) => {
                        for dup_idx in dup_indices {
                            out.push((dup_idx, Ok(val.clone())));
                        }
                        out.push((first_idx, Ok(val)));
                    }
                    Err(err) => {
                        if clone_clonable_registry_error(&err).is_some() {
                            for dup_idx in dup_indices {
                                let c = clone_clonable_registry_error(&err).unwrap();
                                out.push((dup_idx, Err(c)));
                            }
                            out.push((first_idx, Err(err)));
                        } else {
                            for dup_idx in dup_indices {
                                out.push((
                                    dup_idx,
                                    client
                                        .get_package_metadata_negotiated_conditional(
                                            &name,
                                            etag.as_deref(),
                                            options,
                                        )
                                        .await,
                                ));
                            }
                            out.push((first_idx, Err(err)));
                        }
                    }
                }
                out
            });
        }

        let mut results: Vec<Option<Result<MetadataFetchResult, RegistryError>>> =
            (0..packages.len()).map(|_| None).collect();

        while let Some(res) = join_set.join_next().await {
            if let Ok(items) = res {
                for (idx, result) in items {
                    results[idx] = Some(result);
                }
            }
        }

        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(RegistryError::Other("Task cancelled".into()))))
            .collect()
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
        accept_header: &'static str,
    ) -> Result<MetadataFetchResult, RegistryError> {
        let key = Arc::new(MetadataInFlightKey {
            url,
            accept: Cow::Borrowed(accept_header),
            if_none_match: if_none_match.map(str::to_owned),
            package_name: package_name.to_owned(),
        });

        match self.in_flight_metadata.join_or_lead(Arc::clone(&key)) {
            Ok(leader) => {
                let res = self
                    .get_package_metadata_from_url_conditional_with_accept_inner(
                        package_name,
                        &key.url,
                        if_none_match,
                        accept_header,
                    )
                    .await;
                leader.finish(&res, Clone::clone);
                return res;
            }
            Err(slot) => {
                if let Some(coalesced) = wait_for_coalesced(&slot, Clone::clone).await {
                    return coalesced;
                }
            }
        }
        // Leader dropped before publishing or returned a non-clonable error: fall back cleanly.
        self.get_package_metadata_from_url_conditional_with_accept_inner(
            package_name,
            &key.url,
            if_none_match,
            accept_header,
        )
        .await
    }

    async fn get_package_metadata_from_url_conditional_with_accept_inner(
        &self,
        package_name: &str,
        url: &Url,
        if_none_match: Option<&str>,
        accept_header: &str,
    ) -> Result<MetadataFetchResult, RegistryError> {
        let _concurrent_fetch_guard = crate::metadata::ConcurrentMetadataFetchGuard::enter();

        let parse_mode =
            if accept_header.contains("install-v1") || accept_header == NPM_INSTALL_ACCEPT {
                PackumentParseMode::Install
            } else {
                PackumentParseMode::Full
            };

        let mut resume_state: Option<(Url, usize, Option<HashSet<Url>>, usize)> = None;
        if self.can_use_http1_pool(url) {
            match self
                .execute_http1_fast(
                    url,
                    Some(accept_header),
                    true,
                    if_none_match,
                    true,
                    FastBodyKind::Metadata {
                        max_size: self.config.max_metadata_size,
                        package_name,
                    },
                )
                .await?
            {
                DirectOrResume::NotModified {
                    etag,
                    cache_metadata,
                } => {
                    return Ok(MetadataFetchResult::NotModified {
                        etag: etag.or_else(|| if_none_match.map(str::to_owned)),
                        cache_metadata,
                    });
                }
                DirectOrResume::Success {
                    etag,
                    payload:
                        crate::http1_pool::BodyPayload::Bytes {
                            bytes,
                            cache_metadata,
                            ..
                        },
                } => {
                    let metadata = if bytes.len() > 512 * 1024 {
                        tokio::task::spawn_blocking(move || {
                            parse_packument_with_mode(&bytes, parse_mode)
                        })
                        .await
                        .map_err(|e| {
                            RegistryError::Other(format!(
                                "Failed to join packument parsing task: {e}"
                            ))
                        })??
                    } else {
                        parse_packument_with_mode(&bytes, parse_mode)?
                    };
                    return Ok(MetadataFetchResult::Fresh {
                        metadata,
                        etag,
                        cache_metadata,
                    });
                }
                DirectOrResume::Success { .. } => unreachable!(),
                DirectOrResume::ResumeReqwest {
                    current_url,
                    redirect_count,
                    seen_redirect_urls,
                    attempt,
                } => {
                    resume_state = Some((current_url, redirect_count, seen_redirect_urls, attempt));
                }
            }
        }

        let host_key = self
            .config
            .circuit_breaker_enabled
            .then(|| url_host_key(url));

        let mut stream_attempt = 0;
        let mut idle_sleep: Option<Pin<Box<tokio::time::Sleep>>> = None;
        loop {
            let (mut resp, permit) = if let Some((ru, rc, sr, att)) = resume_state.take() {
                self.execute_with_borrowed_permit_from(
                    Method::GET,
                    url.clone(),
                    ru,
                    rc,
                    sr,
                    att,
                    Some(accept_header),
                    if_none_match,
                )
                .await?
            } else {
                self.execute_with_borrowed_permit(
                    Method::GET,
                    url.clone(),
                    Some(accept_header),
                    if_none_match,
                )
                .await?
            };

            let status = resp.status();
            if status == StatusCode::NOT_MODIFIED {
                let cache_metadata = packument_cache_metadata(resp.headers());
                let etag = resp
                    .headers()
                    .get(ETAG)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
                    .or_else(|| if_none_match.map(|s| s.to_string()));
                return Ok(MetadataFetchResult::NotModified {
                    etag,
                    cache_metadata,
                });
            }

            if status == StatusCode::NOT_FOUND {
                let body = resp.text().await.unwrap_or_default();
                crate::not_found::record(package_name, url.as_str(), &body);
                return Err(RegistryError::PackageNotFound {
                    package: package_name.to_string(),
                    status: 404,
                });
            }

            if status == StatusCode::UNAUTHORIZED {
                let www = extract_www_authenticate(resp.headers());
                let msg = resp.text().await.unwrap_or_default();
                if let Some(www_authenticate) = www {
                    return Err(RegistryError::AuthChallenge {
                        url: url.to_string(),
                        www_authenticate,
                        body: msg,
                    });
                }
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

            let cache_metadata = packument_cache_metadata(resp.headers());

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
                        message: format!(
                            "Metadata Content-Length for package '{package_name}' exceeds maximum metadata size"
                        ),
                    });
                }
            }

            let initial_cap = expected_content_length
                .map(|n| (n as usize).min(4 * 1024 * 1024))
                .unwrap_or(0);
            let mut bytes = Vec::with_capacity(initial_cap);
            let mut stream_err: Option<RegistryError> = None;
            loop {
                let chunk_opt = match next_chunk_with_idle_timeout(
                    &mut resp,
                    self.config.chunk_idle_timeout,
                    &mut idle_sleep,
                )
                .await
                {
                    Ok(opt) => opt,
                    Err(e) => {
                        stream_err = Some(e);
                        break;
                    }
                };

                match chunk_opt {
                    Some(chunk) => {
                        if bytes.len() + chunk.len() > self.config.max_metadata_size {
                            return Err(RegistryError::SizeLimitExceeded {
                                limit: self.config.max_metadata_size as u64,
                                actual: (bytes.len() + chunk.len()) as u64,
                                message: format!(
                                    "Metadata payload for package '{package_name}' exceeds maximum metadata size"
                                ),
                            });
                        }
                        if bytes.is_empty() {
                            if Some(chunk.len() as u64) == expected_content_length {
                                bytes = Vec::from(chunk);
                                continue;
                            }
                            if let Some(content_length) = expected_content_length {
                                bytes.reserve(
                                    (content_length as usize).min(self.config.max_metadata_size),
                                );
                            }
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    None => break,
                }
            }

            // Release network concurrency slot now that socket reading finished (or errored)
            drop(permit);

            if let Some(err) = stream_err {
                if err.is_transient() && stream_attempt < self.config.max_retries {
                    let delay = self.calculate_backoff(stream_attempt);
                    debug!(
                        "Stream metadata error {:?} for {}, retrying stream in {:?} (attempt {}/{})",
                        err, url, delay, stream_attempt + 1, self.config.max_retries
                    );
                    tokio::time::sleep(delay).await;
                    stream_attempt += 1;
                    continue;
                } else {
                    if let Some(ref hk) = host_key {
                        if err.is_transient() {
                            self.circuit_breaker.record_failure(hk).await;
                        }
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
                        let delay = self.calculate_backoff(stream_attempt);
                        tokio::time::sleep(delay).await;
                        stream_attempt += 1;
                        continue;
                    } else {
                        return Err(mismatch_err);
                    }
                }
            }

            let parse_mode =
                if accept_header.contains("install-v1") || accept_header == NPM_INSTALL_ACCEPT {
                    PackumentParseMode::Install
                } else {
                    PackumentParseMode::Full
                };

            let metadata = if bytes.len() > 512 * 1024 {
                tokio::task::spawn_blocking(move || parse_packument_with_mode(&bytes, parse_mode))
                    .await
                    .map_err(|e| {
                        RegistryError::Other(format!("Failed to join packument parsing task: {e}"))
                    })??
            } else {
                parse_packument_with_mode(&bytes, parse_mode)?
            };
            return Ok(MetadataFetchResult::Fresh {
                metadata,
                etag,
                cache_metadata,
            });
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

    /// Fetch lean install metadata for multiple packages concurrently with bounded concurrency requesting `NPM_INSTALL_ACCEPT`.
    pub async fn get_package_metadata_install_concurrent<S: AsRef<str>>(
        &self,
        packages: &[S],
    ) -> Vec<Result<AbbreviatedPackageMetadata, RegistryError>> {
        let mut join_set = tokio::task::JoinSet::new();
        for (idx, pkg) in packages.iter().enumerate() {
            let client = self.clone();
            let name = pkg.as_ref().to_string();
            join_set.spawn(async move {
                let res = client.get_package_metadata_install(&name).await;
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

    /// Fetch lean install metadata for multiple packages concurrently using conditional ETag revalidation requesting `NPM_INSTALL_ACCEPT`.
    pub async fn get_package_metadata_install_conditional_concurrent<S: AsRef<str>>(
        &self,
        packages: &[(S, Option<String>)],
    ) -> Vec<Result<MetadataFetchResult, RegistryError>> {
        self.get_package_metadata_conditional_concurrent_with_accept(packages, NPM_INSTALL_ACCEPT)
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
        let mut key_to_group: HashMap<(&str, Option<&str>), usize> =
            HashMap::with_capacity(packages.len());
        let mut groups: Vec<(usize, Vec<usize>)> = Vec::with_capacity(packages.len());
        for (idx, (pkg, if_none_match)) in packages.iter().enumerate() {
            let key = (pkg.as_ref(), if_none_match.as_deref());
            if let Some(&grp) = key_to_group.get(&key) {
                groups[grp].1.push(idx);
            } else {
                let grp = groups.len();
                key_to_group.insert(key, grp);
                groups.push((idx, Vec::new()));
            }
        }

        let mut join_set = tokio::task::JoinSet::new();
        for (first_idx, dup_indices) in groups {
            let client = self.clone();
            let (pkg, if_none_match) = &packages[first_idx];
            let name = pkg.as_ref().to_string();
            let etag = if_none_match.clone();
            join_set.spawn(async move {
                let fetch_one = || async {
                    match client.package_metadata_url(&name) {
                        Ok(url) => {
                            match client
                                .get_package_metadata_from_url_conditional_with_accept(
                                    &name,
                                    url.clone(),
                                    etag.as_deref(),
                                    accept,
                                )
                                .await
                            {
                                Err(RegistryError::PackageNotFound { .. })
                                | Err(RegistryError::ServerError {
                                    status: 406 | 415, ..
                                }) if accept != "application/json" => {
                                    client
                                        .get_package_metadata_from_url_conditional_with_accept(
                                            &name,
                                            url,
                                            etag.as_deref(),
                                            "application/json",
                                        )
                                        .await
                                }
                                other => other,
                            }
                        }
                        Err(error) => Err(error),
                    }
                };
                let res = fetch_one().await;
                if dup_indices.is_empty() {
                    return vec![(first_idx, res)];
                }
                let mut out = Vec::with_capacity(1 + dup_indices.len());
                match res {
                    Ok(val) => {
                        let heavy_clone = matches!(
                            &val,
                            MetadataFetchResult::Fresh { metadata, .. }
                                if dup_indices.len() >= 2 && metadata.versions.len() >= 16
                        );
                        if heavy_clone {
                            let cloned_items = tokio::task::spawn_blocking(move || {
                                let mut cloned_vec = Vec::with_capacity(1 + dup_indices.len());
                                for dup_idx in dup_indices {
                                    cloned_vec.push((dup_idx, Ok(val.clone())));
                                }
                                cloned_vec.push((first_idx, Ok(val)));
                                cloned_vec
                            })
                            .await
                            .unwrap_or_default();
                            return cloned_items;
                        }
                        for dup_idx in dup_indices {
                            out.push((dup_idx, Ok(val.clone())));
                        }
                        out.push((first_idx, Ok(val)));
                    }
                    Err(err) => {
                        if let Some(cloned) = clone_clonable_registry_error(&err) {
                            drop(cloned);
                            for dup_idx in dup_indices {
                                let c = clone_clonable_registry_error(&err).unwrap();
                                out.push((dup_idx, Err(c)));
                            }
                        } else {
                            for dup_idx in dup_indices {
                                out.push((dup_idx, fetch_one().await));
                            }
                        }
                        out.push((first_idx, Err(err)));
                    }
                }
                out
            });
        }

        let mut results: Vec<Option<Result<MetadataFetchResult, RegistryError>>> =
            (0..packages.len()).map(|_| None).collect();

        while let Some(res) = join_set.join_next().await {
            if let Ok(items) = res {
                for (idx, result) in items {
                    results[idx] = Some(result);
                }
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
        let scheme = url.scheme();
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(RegistryError::SecurityViolation(format!(
                "Invalid tarball URL scheme '{}': only http and https are allowed",
                scheme.to_ascii_lowercase()
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
            let www = extract_www_authenticate(resp.headers());
            let msg = resp.text().await.unwrap_or_default();
            if let Some(www_authenticate) = www {
                return Err(RegistryError::AuthChallenge {
                    url: url.to_string(),
                    www_authenticate,
                    body: msg,
                });
            }
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
        let scheme = url.scheme();
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(RegistryError::SecurityViolation(format!(
                "Invalid tarball URL scheme '{}': only http and https are allowed",
                scheme.to_ascii_lowercase()
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
            let www = extract_www_authenticate(resp.headers());
            let msg = resp.text().await.unwrap_or_default();
            if let Some(www_authenticate) = www {
                return Err(RegistryError::AuthChallenge {
                    url: url.to_string(),
                    www_authenticate,
                    body: msg,
                });
            }
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
        let scheme = url.scheme();
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(RegistryError::SecurityViolation(format!(
                "Invalid tarball URL scheme '{}': only http and https are allowed",
                scheme.to_ascii_lowercase()
            )));
        }

        let key = Arc::new(TarballInFlightKey {
            url,
            if_none_match: if_none_match.map(str::to_owned),
        });

        match self.in_flight_tarballs.join_or_lead(Arc::clone(&key)) {
            Ok(leader) => {
                let res = self
                    .download_tarball_bytes_core(&key.url, tarball_url, if_none_match, false)
                    .await
                    .map(|(result, _)| result);
                leader.finish(&res, Clone::clone);
                return res;
            }
            Err(slot) => {
                if let Some(coalesced) = wait_for_coalesced(&slot, Clone::clone).await {
                    return coalesced;
                }
            }
        }

        self.download_tarball_bytes_core(&key.url, tarball_url, if_none_match, false)
            .await
            .map(|(result, _)| result)
    }

    /// Download tarball directly to memory while computing its `sha512-...` SRI digest in a single streaming pass.
    pub async fn download_tarball_bytes_with_sha512(
        &self,
        tarball_url: &str,
    ) -> Result<(Vec<u8>, String), RegistryError> {
        let url = Url::parse(tarball_url)?;
        let scheme = url.scheme();
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(RegistryError::SecurityViolation(format!(
                "Invalid tarball URL scheme '{}': only http and https are allowed",
                scheme.to_ascii_lowercase()
            )));
        }
        match self
            .download_tarball_bytes_core(&url, tarball_url, None, true)
            .await?
        {
            (BytesFetchResult::Fresh { bytes, .. }, Some(integrity)) => Ok((bytes, integrity)),
            _ => Err(RegistryError::Other(
                "Unexpected response state while streaming tarball integrity".into(),
            )),
        }
    }

    async fn download_tarball_bytes_core(
        &self,
        url: &Url,
        tarball_url: &str,
        if_none_match: Option<&str>,
        compute_sha512: bool,
    ) -> Result<(BytesFetchResult, Option<String>), RegistryError> {
        let mut resume_state: Option<(Url, usize, Option<HashSet<Url>>, usize)> = None;
        if self.can_use_http1_pool(url) {
            match self
                .execute_http1_fast(
                    url,
                    None,
                    false,
                    if_none_match,
                    false,
                    FastBodyKind::TarballBytes {
                        max_size: self.config.max_package_size.min(usize::MAX as u64) as usize,
                        compute_sha512,
                        not_found_label: tarball_url,
                    },
                )
                .await?
            {
                DirectOrResume::NotModified { etag, .. } => {
                    return Ok((
                        BytesFetchResult::NotModified {
                            etag: etag.or_else(|| if_none_match.map(str::to_owned)),
                        },
                        None,
                    ));
                }
                DirectOrResume::Success {
                    etag,
                    payload: crate::http1_pool::BodyPayload::Bytes { bytes, sha512, .. },
                } => {
                    return Ok((BytesFetchResult::Fresh { bytes, etag }, sha512));
                }
                DirectOrResume::Success { .. } => unreachable!(),
                DirectOrResume::ResumeReqwest {
                    current_url,
                    redirect_count,
                    seen_redirect_urls,
                    attempt,
                } => {
                    resume_state = Some((current_url, redirect_count, seen_redirect_urls, attempt));
                }
            }
        }

        let host_key = self
            .config
            .circuit_breaker_enabled
            .then(|| url_host_key(url));

        let mut stream_attempt = 0;
        let mut idle_sleep: Option<Pin<Box<tokio::time::Sleep>>> = None;
        loop {
            let (mut resp, _permit) = if let Some((ru, rc, sr, att)) = resume_state.take() {
                self.execute_with_borrowed_permit_from(
                    Method::GET,
                    url.clone(),
                    ru,
                    rc,
                    sr,
                    att,
                    None,
                    if_none_match,
                )
                .await?
            } else {
                self.execute_with_borrowed_permit(Method::GET, url.clone(), None, if_none_match)
                    .await?
            };

            let status = resp.status();
            if status == StatusCode::NOT_MODIFIED {
                let etag = resp
                    .headers()
                    .get(ETAG)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
                    .or_else(|| if_none_match.map(|s| s.to_string()));
                return Ok((BytesFetchResult::NotModified { etag }, None));
            }

            if status == StatusCode::NOT_FOUND {
                return Err(RegistryError::PackageNotFound {
                    package: tarball_url.to_string(),
                    status: 404,
                });
            }

            if status == StatusCode::UNAUTHORIZED {
                let www = extract_www_authenticate(resp.headers());
                let msg = resp.text().await.unwrap_or_default();
                if let Some(www_authenticate) = www {
                    return Err(RegistryError::AuthChallenge {
                        url: url.to_string(),
                        www_authenticate,
                        body: msg,
                    });
                }
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
                        message: format!(
                            "Tarball Content-Length for '{tarball_url}' exceeds maximum package size"
                        ),
                    });
                }
            }

            let initial_cap = expected_content_length
                .map(|n| (n as usize).min(4 * 1024 * 1024))
                .unwrap_or(0);
            let mut bytes = Vec::with_capacity(initial_cap);
            let mut hasher = compute_sha512.then(|| ring::digest::Context::new(&ring::digest::SHA512));
            let mut stream_err = None;

            loop {
                let chunk_opt = match next_chunk_with_idle_timeout(
                    &mut resp,
                    self.config.chunk_idle_timeout,
                    &mut idle_sleep,
                )
                .await
                {
                    Ok(opt) => opt,
                    Err(e) => {
                        stream_err = Some(e);
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
                                message: format!(
                                    "Tarball payload for '{tarball_url}' exceeds maximum package size"
                                ),
                            });
                            break;
                        }
                        if let Some(ref mut ctx) = hasher {
                            ctx.update(&chunk);
                        }
                        if bytes.is_empty() {
                            if Some(chunk.len() as u64) == expected_content_length {
                                bytes = Vec::from(chunk);
                                continue;
                            }
                            if let Some(content_length) = expected_content_length {
                                bytes.reserve(content_length as usize);
                            }
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    None => break,
                }
            }

            if let Some(err) = stream_err {
                if err.is_transient() && stream_attempt < self.config.max_retries {
                    let delay = self.calculate_backoff(stream_attempt);
                    debug!(
                        "Stream download error {:?} for {}, retrying stream in {:?} (attempt {}/{})",
                        err, url, delay, stream_attempt + 1, self.config.max_retries
                    );
                    tokio::time::sleep(delay).await;
                    stream_attempt += 1;
                    continue;
                } else {
                    if let Some(ref hk) = host_key {
                        if err.is_transient() {
                            self.circuit_breaker.record_failure(hk).await;
                        }
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

            let integrity = hasher.map(|ctx| {
                let digest = ctx.finish();
                format!("sha512-{}", data_encoding::BASE64.encode(digest.as_ref()))
            });

            return Ok((BytesFetchResult::Fresh { bytes, etag }, integrity));
        }
    }

    /// Download multiple tarballs concurrently with bounded concurrency.
    pub async fn download_tarballs_concurrent<S: AsRef<str>>(
        &self,
        tarball_urls: &[S],
    ) -> Vec<Result<Vec<u8>, RegistryError>> {
        let mut key_to_group: HashMap<&str, usize> = HashMap::with_capacity(tarball_urls.len());
        let mut groups: Vec<(usize, Vec<usize>)> = Vec::with_capacity(tarball_urls.len());
        for (idx, url) in tarball_urls.iter().enumerate() {
            let s = url.as_ref();
            if let Some(&grp) = key_to_group.get(s) {
                groups[grp].1.push(idx);
            } else {
                let grp = groups.len();
                key_to_group.insert(s, grp);
                groups.push((idx, Vec::new()));
            }
        }

        let mut join_set = tokio::task::JoinSet::new();
        for (first_idx, dup_indices) in groups {
            let client = self.clone();
            let url_str = tarball_urls[first_idx].as_ref().to_string();
            join_set.spawn(async move {
                let res = client.download_tarball_bytes(&url_str).await;
                let mut out = Vec::with_capacity(1 + dup_indices.len());
                if !dup_indices.is_empty() {
                    match &res {
                        Ok(bytes) => {
                            for dup_idx in dup_indices {
                                out.push((dup_idx, Ok(bytes.clone())));
                            }
                        }
                        Err(err) => {
                            if clone_clonable_registry_error(err).is_some() {
                                for dup_idx in dup_indices {
                                    let c = clone_clonable_registry_error(err).unwrap();
                                    out.push((dup_idx, Err(c)));
                                }
                            } else {
                                for dup_idx in dup_indices {
                                    out.push((dup_idx, client.download_tarball_bytes(&url_str).await));
                                }
                            }
                        }
                    }
                }
                out.push((first_idx, res));
                out
            });
        }

        let mut results: Vec<Option<Result<Vec<u8>, RegistryError>>> =
            (0..tarball_urls.len()).map(|_| None).collect();

        while let Some(res) = join_set.join_next().await {
            if let Ok(items) = res {
                for (idx, result) in items {
                    results[idx] = Some(result);
                }
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
        self.download_tarball_to_file_inner(tarball_url, dest_path, false)
            .await
    }

    async fn download_tarball_to_file_inner(
        &self,
        tarball_url: &str,
        dest_path: &Path,
        parent_verified: bool,
    ) -> Result<u64, RegistryError> {
        const DISK_BUFFER_THRESHOLD: usize = 4 * 1024 * 1024;

        let url = Url::parse(tarball_url)?;
        let scheme = url.scheme();
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(RegistryError::SecurityViolation(format!(
                "Invalid tarball URL scheme '{}': only http and https are allowed",
                scheme.to_ascii_lowercase()
            )));
        }

        let host_key = self
            .config
            .circuit_breaker_enabled
            .then(|| url_host_key(&url));

        let parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
        if !parent_verified && !parent.as_os_str().is_empty() && !parent.is_dir() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                RegistryError::Other(format!(
                    "Failed to create directories for {}: {e}",
                    dest_path.display()
                ))
            })?;
        }

        let temp_path = {
            let file_name = dest_path
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("download");
            parent.join(format!("{file_name}.part"))
        };

        let mut resume_state: Option<(Url, usize, Option<HashSet<Url>>, usize)> = None;
        if self.can_use_http1_pool(&url) {
            match self
                .execute_http1_fast(
                    &url,
                    None,
                    false,
                    None,
                    false,
                    FastBodyKind::TarballFile {
                        max_size: self.config.max_package_size.min(usize::MAX as u64) as usize,
                        disk_threshold: DISK_BUFFER_THRESHOLD,
                        temp_path: &temp_path,
                        dest_path,
                        not_found_label: tarball_url,
                    },
                )
                .await?
            {
                DirectOrResume::Success {
                    payload: crate::http1_pool::BodyPayload::File { written },
                    ..
                } => {
                    return Ok(written);
                }
                DirectOrResume::Success { .. } | DirectOrResume::NotModified { .. } => {
                    unreachable!()
                }
                DirectOrResume::ResumeReqwest {
                    current_url,
                    redirect_count,
                    seen_redirect_urls,
                    attempt,
                } => {
                    resume_state = Some((current_url, redirect_count, seen_redirect_urls, attempt));
                }
            }
        }

        let mut stream_attempt = 0;
        let mut idle_sleep: Option<Pin<Box<tokio::time::Sleep>>> = None;
        loop {
            let (mut resp, permit) = if let Some((ru, rc, sr, att)) = resume_state.take() {
                self.execute_with_borrowed_permit_from(
                    Method::GET,
                    url.clone(),
                    ru,
                    rc,
                    sr,
                    att,
                    None,
                    None,
                )
                .await?
            } else {
                self.execute_with_borrowed_permit(Method::GET, url.clone(), None, None)
                    .await?
            };

            let status = resp.status();
            if status == StatusCode::NOT_FOUND {
                return Err(RegistryError::PackageNotFound {
                    package: tarball_url.to_string(),
                    status: 404,
                });
            }

            if status == StatusCode::UNAUTHORIZED {
                let www = extract_www_authenticate(resp.headers());
                let msg = resp.text().await.unwrap_or_default();
                if let Some(www_authenticate) = www {
                    return Err(RegistryError::AuthChallenge {
                        url: url.to_string(),
                        www_authenticate,
                        body: msg,
                    });
                }
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
                        message: format!(
                            "Tarball Content-Length for '{tarball_url}' exceeds maximum package size"
                        ),
                    });
                }
            }

            let mut mem_buf: Option<Vec<u8>>;
            let mut file: Option<BufWriter<tokio::fs::File>>;
            if expected_content_length.is_some_and(|len| len > DISK_BUFFER_THRESHOLD as u64) {
                let raw_file = tokio::fs::File::create(&temp_path).await.map_err(|e| {
                    RegistryError::Other(format!("Failed to create {}: {e}", temp_path.display()))
                })?;
                mem_buf = None;
                file = Some(BufWriter::with_capacity(256 * 1024, raw_file));
            } else {
                mem_buf = Some(Vec::new());
                file = None;
            }

            let mut written: u64 = 0;
            let mut stream_err = None;

            loop {
                let chunk_opt = match next_chunk_with_idle_timeout(
                    &mut resp,
                    self.config.chunk_idle_timeout,
                    &mut idle_sleep,
                )
                .await
                {
                    Ok(opt) => opt,
                    Err(e) => {
                        stream_err = Some(e);
                        break;
                    }
                };

                match chunk_opt {
                    Some(chunk) => {
                        if written + (chunk.len() as u64) > self.config.max_package_size {
                            stream_err = Some(RegistryError::SizeLimitExceeded {
                                limit: self.config.max_package_size,
                                actual: written + (chunk.len() as u64),
                                message: format!(
                                    "Tarball payload for '{tarball_url}' exceeds maximum package size"
                                ),
                            });
                            break;
                        }
                        if let Some(mut buf) = mem_buf.take() {
                            if buf.len() + chunk.len() <= DISK_BUFFER_THRESHOLD {
                                if buf.is_empty() {
                                    if Some(chunk.len() as u64) == expected_content_length {
                                        buf = Vec::from(chunk);
                                        written = buf.len() as u64;
                                        mem_buf = Some(buf);
                                        continue;
                                    }
                                    if let Some(content_length) = expected_content_length {
                                        buf.reserve(content_length as usize);
                                    }
                                }
                                buf.extend_from_slice(&chunk);
                                written += chunk.len() as u64;
                                mem_buf = Some(buf);
                            } else {
                                let raw_file =
                                    match tokio::fs::File::create(&temp_path).await {
                                        Ok(f) => f,
                                        Err(e) => {
                                            stream_err = Some(RegistryError::Other(format!(
                                                "Failed to create {}: {e}",
                                                temp_path.display()
                                            )));
                                            break;
                                        }
                                    };
                                let mut bw = BufWriter::with_capacity(256 * 1024, raw_file);
                                if !buf.is_empty() {
                                    if let Err(e) = bw.write_all(&buf).await {
                                        file = Some(bw);
                                        stream_err = Some(RegistryError::Other(format!(
                                            "Failed to write chunk to {}: {e}",
                                            temp_path.display()
                                        )));
                                        break;
                                    }
                                }
                                if let Err(e) = bw.write_all(&chunk).await {
                                    file = Some(bw);
                                    stream_err = Some(RegistryError::Other(format!(
                                        "Failed to write chunk to {}: {e}",
                                        temp_path.display()
                                    )));
                                    break;
                                }
                                written += chunk.len() as u64;
                                file = Some(bw);
                            }
                        } else if let Some(ref mut bw) = file {
                            if let Err(e) = bw.write_all(&chunk).await {
                                stream_err = Some(RegistryError::Other(format!(
                                    "Failed to write chunk to {}: {e}",
                                    temp_path.display()
                                )));
                                break;
                            }
                            written += chunk.len() as u64;
                        }
                    }
                    None => break,
                }
            }

            drop(permit);

            if let Some(err) = stream_err {
                if let Some(bw) = file.take() {
                    drop(bw);
                    let _ = tokio::fs::remove_file(&temp_path).await;
                }

                if err.is_transient() && stream_attempt < self.config.max_retries {
                    let delay = self.calculate_backoff(stream_attempt);
                    debug!(
                        "Stream download to file error {:?} for {}, retrying stream in {:?} (attempt {}/{})",
                        err, url, delay, stream_attempt + 1, self.config.max_retries
                    );
                    tokio::time::sleep(delay).await;
                    stream_attempt += 1;
                    continue;
                } else {
                    if let Some(ref hk) = host_key {
                        if err.is_transient() {
                            self.circuit_breaker.record_failure(hk).await;
                        }
                    }
                    return Err(err);
                }
            }

            if let Some(content_length) = expected_content_length {
                if written != content_length {
                    if let Some(bw) = file.take() {
                        drop(bw);
                        let _ = tokio::fs::remove_file(&temp_path).await;
                    }
                    return Err(RegistryError::ContentLengthMismatch {
                        expected: content_length,
                        actual: written,
                    });
                }
            }

            if let Some(buf) = mem_buf {
                let tp = temp_path.clone();
                let dp = dest_path.to_path_buf();
                tokio::task::spawn_blocking(move || {
                    let mut f = std::fs::File::create(&tp).map_err(|e| {
                        RegistryError::Other(format!("Failed to create {}: {e}", tp.display()))
                    })?;
                    if let Err(e) = f.write_all(&buf) {
                        drop(f);
                        let _ = std::fs::remove_file(&tp);
                        return Err(RegistryError::Other(format!(
                            "Failed to write {}: {e}",
                            tp.display()
                        )));
                    }
                    drop(f);
                    if let Err(e) = std::fs::rename(&tp, &dp) {
                        let _ = std::fs::remove_file(&tp);
                        return Err(RegistryError::Other(format!(
                            "Failed to rename {} to {}: {e}",
                            tp.display(),
                            dp.display()
                        )));
                    }
                    Ok(())
                })
                .await
                .map_err(|e| {
                    RegistryError::Other(format!("Failed to join tarball write task: {e}"))
                })??;
            } else if let Some(mut bw) = file {
                if let Err(e) = bw.flush().await {
                    drop(bw);
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    return Err(RegistryError::Other(format!(
                        "Failed to flush {}: {e}",
                        temp_path.display()
                    )));
                }
                drop(bw);

                if let Err(e) = tokio::fs::rename(&temp_path, dest_path).await {
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    return Err(RegistryError::Other(format!(
                        "Failed to rename {} to {}: {e}",
                        temp_path.display(),
                        dest_path.display()
                    )));
                }
            }

            return Ok(written);
        }
    }

    /// Download multiple tarballs directly to disk destinations concurrently with bounded concurrency.
    pub async fn download_tarballs_to_files_concurrent(
        &self,
        downloads: &[(&str, &Path)],
    ) -> Vec<Result<u64, RegistryError>> {
        if downloads.is_empty() {
            return Vec::new();
        }
        let mut unique_parents: HashSet<&Path> = HashSet::with_capacity(8);
        let mut failed_parents: HashMap<&Path, String> = HashMap::new();
        for &(_, dest) in downloads {
            if let Some(p) = dest.parent() {
                if !p.as_os_str().is_empty() && unique_parents.insert(p) && !p.is_dir() {
                    if let Err(e) = std::fs::create_dir_all(p) {
                        failed_parents
                            .insert(p, format!("Failed to create directories for {}: {e}", p.display()));
                    }
                }
            }
        }

        let mut results: Vec<Option<Result<u64, RegistryError>>> =
            (0..downloads.len()).map(|_| None).collect();

        let mut join_set = tokio::task::JoinSet::new();
        for (idx, (url, dest)) in downloads.iter().enumerate() {
            if let Some(p) = dest.parent() {
                if let Some(msg) = failed_parents.get(p) {
                    results[idx] = Some(Err(RegistryError::Other(msg.clone())));
                    continue;
                }
            }
            let client = self.clone();
            let url_str = url.to_string();
            let dest_buf = dest.to_path_buf();
            join_set.spawn(async move {
                let res = client
                    .download_tarball_to_file_inner(&url_str, &dest_buf, true)
                    .await;
                (idx, res)
            });
        }

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

        let www_authenticate = extract_www_authenticate(resp.headers());
        let body_text = resp.text().await.unwrap_or_default();

        if status == StatusCode::UNAUTHORIZED {
            if let Some(www_authenticate) = www_authenticate {
                return Err(RegistryError::AuthChallenge {
                    url: target_url.to_string(),
                    www_authenticate,
                    body: body_text,
                });
            }
        }

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
            let www = extract_www_authenticate(resp.headers());
            let body_text = resp.text().await.unwrap_or_default();
            if let Some(www_authenticate) = www {
                return Err(RegistryError::AuthChallenge {
                    url: target_url.to_string(),
                    www_authenticate,
                    body: body_text,
                });
            }
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
            if let Ok(val) = self
                .admin_json_request(Method::GET, pkg_url, None, None)
                .await
            {
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
        let www = extract_www_authenticate(response.headers());
        let body_text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(match status {
                StatusCode::UNAUTHORIZED if www.is_some() => RegistryError::AuthChallenge {
                    url: target.to_string(),
                    www_authenticate: www.unwrap(),
                    body: body_text,
                },
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
        assert!((config.retry_factor - DEFAULT_RETRY_FACTOR).abs() < f64::EPSILON);
        assert_eq!(config.maxsockets, None);
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

    #[test]
    fn test_calculate_retry_backoff_progression() {
        let initial = Duration::from_millis(100);
        let max = Duration::from_secs(5);

        // Default factor (2.0)
        assert_eq!(
            calculate_retry_backoff(initial, max, 2.0, 0),
            Duration::from_millis(100)
        );
        assert_eq!(
            calculate_retry_backoff(initial, max, 2.0, 1),
            Duration::from_millis(200)
        );
        assert_eq!(
            calculate_retry_backoff(initial, max, 2.0, 2),
            Duration::from_millis(400)
        );
        assert_eq!(
            calculate_retry_backoff(initial, max, 2.0, 3),
            Duration::from_millis(800)
        );
        assert_eq!(
            calculate_retry_backoff(initial, max, 2.0, 10),
            Duration::from_secs(5)
        );

        // Custom npm retry factor (10.0) with custom mintimeout (10ms) and maxtimeout (1000ms)
        let custom_min = Duration::from_millis(10);
        let custom_max = Duration::from_millis(1000);
        assert_eq!(
            calculate_retry_backoff(custom_min, custom_max, 10.0, 0),
            Duration::from_millis(10)
        );
        assert_eq!(
            calculate_retry_backoff(custom_min, custom_max, 10.0, 1),
            Duration::from_millis(100)
        );
        assert_eq!(
            calculate_retry_backoff(custom_min, custom_max, 10.0, 2),
            Duration::from_millis(1000)
        );
        assert_eq!(
            calculate_retry_backoff(custom_min, custom_max, 10.0, 3),
            Duration::from_millis(1000) // capped at custom_max
        );

        // Non-positive or NaN factor falls back to DEFAULT_RETRY_FACTOR
        assert_eq!(
            calculate_retry_backoff(initial, max, 0.0, 1),
            Duration::from_millis(200)
        );
        assert_eq!(
            calculate_retry_backoff(initial, max, f64::NAN, 1),
            Duration::from_millis(200)
        );
    }

    #[test]
    fn test_registry_client_with_config_honors_maxsockets() {
        // When maxsockets is set, semaphore available permits must equal maxsockets
        let config = RegistryClientConfig {
            maxsockets: Some(15),
            ..Default::default()
        };
        let client = RegistryClient::with_config(config).unwrap();
        assert_eq!(client.semaphore().available_permits(), 15);

        // When maxsockets is set to a custom small value
        let config_small = RegistryClientConfig {
            maxsockets: Some(4),
            ..Default::default()
        };
        let client_small = RegistryClient::with_config(config_small).unwrap();
        assert_eq!(client_small.semaphore().available_permits(), 4);

        // When maxsockets is None, fallback to max_concurrent_requests
        let config_fallback = RegistryClientConfig {
            maxsockets: None,
            max_concurrent_requests: 32,
            ..Default::default()
        };
        let client_fallback = RegistryClient::with_config(config_fallback).unwrap();
        assert_eq!(client_fallback.semaphore().available_permits(), 32);
    }

    #[test]
    fn test_registry_client_custom_retry_configuration() {
        let config = RegistryClientConfig {
            max_retries: 5,
            retry_factor: 3.0,
            initial_retry_backoff: Duration::from_millis(50),
            max_retry_backoff: Duration::from_millis(2000),
            ..Default::default()
        };
        let client = RegistryClient::with_config(config).unwrap();

        assert_eq!(client.config().max_retries, 5);
        assert!((client.config().retry_factor - 3.0).abs() < f64::EPSILON);
        assert_eq!(client.calculate_backoff(0), Duration::from_millis(50));
        assert_eq!(client.calculate_backoff(1), Duration::from_millis(150));
        assert_eq!(client.calculate_backoff(2), Duration::from_millis(450));
        assert_eq!(client.calculate_backoff(3), Duration::from_millis(1350));
        assert_eq!(client.calculate_backoff(4), Duration::from_millis(2000)); // capped
    }

    #[test]
    fn test_package_metadata_url_rejects_crlf() {
        let client = RegistryClient::new().unwrap();
        let err = client.package_metadata_url("bad\r\npkg").unwrap_err();
        assert!(matches!(err, RegistryError::SecurityViolation(_)));
    }

    #[tokio::test]
    async fn test_auth_challenge_propagated_on_401() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: OTP realm=\"npm\"\r\nContent-Length: 18\r\n\r\n{\"error\":\"need otp\"}";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let client = RegistryClient::new().unwrap();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/test-pkg")).unwrap();
        let err = client
            .get_package_metadata_from_url_conditional_with_accept(
                "test-pkg",
                url,
                None,
                "application/json",
            )
            .await
            .unwrap_err();

        match err {
            RegistryError::AuthChallenge {
                www_authenticate,
                body,
                ..
            } => {
                assert_eq!(www_authenticate, "OTP realm=\"npm\"");
                assert!(body.contains("need otp"));
            }
            other => panic!("Expected AuthChallenge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_multiple_www_authenticate_challenges_joined() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"npm\"\r\nWWW-Authenticate: OTP realm=\"npm\"\r\nContent-Length: 18\r\n\r\n{\"error\":\"need otp\"}";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let client = RegistryClient::new().unwrap();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/test-pkg")).unwrap();
        let err = client
            .get_package_metadata_from_url_conditional_with_accept(
                "test-pkg",
                url,
                None,
                "application/json",
            )
            .await
            .unwrap_err();

        match err {
            RegistryError::AuthChallenge {
                www_authenticate,
                body,
                ..
            } => {
                assert_eq!(
                    www_authenticate,
                    "Bearer realm=\"npm\", OTP realm=\"npm\""
                );
                assert!(body.contains("need otp"));
            }
            other => panic!("Expected AuthChallenge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_otp_stripped_on_untrusted_redirect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener_target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener_target.local_addr().unwrap().port();

        let listener_src = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let src_port = listener_src.local_addr().unwrap().port();

        // Server 1 (source): redirects to server 2
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener_src.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target_port}/dest\r\nContent-Length: 0\r\n\r\n"
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        // Server 2 (target): receives redirect and verifies no npm-otp header
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener_target.accept().await {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_text = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = tx.send(req_text).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let client = RegistryClient::new().unwrap();
        let initial_url = Url::parse(&format!("http://127.0.0.1:{src_port}/initial")).unwrap();
        let res = client
            .execute_request_loop_with_body(
                Method::POST,
                initial_url,
                Some("application/json"),
                Some("application/json"),
                Some("123456"),
                b"{}".to_vec(),
            )
            .await;
        assert!(res.is_ok());

        let target_req = rx.recv().await.unwrap();
        // Method rewritten to GET on 302 POST
        assert!(target_req.starts_with("GET /dest"));
        // OTP must be stripped on redirect to different port/untrusted target
        assert!(!target_req.to_ascii_lowercase().contains("npm-otp"));
    }

    const TEST_CERT_PEM_1: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDEzCCAfugAwIBAgIUQgC/5PP3O/WJ6mrMKuoYAkZMlrowDQYJKoZIhvcNAQEL\n\
BQAwGTEXMBUGA1UEAwwOcmVnaXN0cnkxLnRlc3QwHhcNMjYxMTI0MTE0NDA1WhcN\n\
MjcxMTI0MTE0NDA1WjAZMRcwFQYDVQQDDA5yZWdpc3RyeTEudGVzdDCCASIwDQYJ\n\
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJVrlXj6Jmov7G53BUkWN6paLX4Lq7yh\n\
FUDiXo/YVyqPBF0yDQuqzBetd1XnUWhEHzYKfvdrEPvvEAJzKVkIMY2cGoC3v7dN\n\
oRAQ3QuaLa9NdclXw929J1qBxaoJkuTNO/lI2XtuSHmDX3ng3v7M/yPDgK+tW0s7\n\
rgn6FwlIRElfmW/pNicfycHJajc27tjTtFypJlQE/S05Ox4z8O+05LABZrpYF5DG\n\
c0ARjazoB1cD9iqXhKRz336ctqqqaVXGDLU8G7/3YITYVjPyCir8pZPcLt36BWha\n\
zgDvb/M+NarY8CI6IIrATA0cyzDkMxopVw8yLKb6WA5y3m5hZeuK67ECAwEAAaNT\n\
MFEwHQYDVR0OBBYEFAizmC3Yhf+GWuEXGBL456WoCzYBMB8GA1UdIwQYMBaAFAiz\n\
mC3Yhf+GWuEXGBL456WoCzYBMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n\
BQADggEBAFAD12y8iEUuV02v7PpkGjzOewPFzlhyDga/IT2QUbpYnNqOOhyGn1UJ\n\
qzFca6SUaXPC/C1HsftFPr0HwHMo/XWmp6zjgrRefPVuM9fbfLwOOSv3Vw98UBW6\n\
emVX+nFx65DjAJYDqWa32I5S/IBb1giDo5FU6RF5z7Fhzbq2HCnP58SkNqZxv2Za\n\
iE6xGS5IhEXOsUs78y8Cbf1uhBDqdVsGuzI5K1/ejj4hYdnjL1XAkW8X+zQgWl6w\n\
4nZoAl7lkSNnZBNf+aGcwucgxOkQ/VCvVmViY18UJAsBmuY93XKHMyMumVG7owz9\n\
JuHO29V5bQS8RfMxU87PjWqfy8gvcKk=\n\
-----END CERTIFICATE-----\n";

    const TEST_KEY_PEM_1: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCVa5V4+iZqL+xu\n\
dwVJFjeqWi1+C6u8oRVA4l6P2FcqjwRdMg0LqswXrXdV51FoRB82Cn73axD77xAC\n\
cylZCDGNnBqAt7+3TaEQEN0Lmi2vTXXJV8PdvSdagcWqCZLkzTv5SNl7bkh5g195\n\
4N7+zP8jw4CvrVtLO64J+hcJSERJX5lv6TYnH8nByWo3Nu7Y07RcqSZUBP0tOTse\n\
M/DvtOSwAWa6WBeQxnNAEY2s6AdXA/Yql4Skc99+nLaqqmlVxgy1PBu/92CE2FYz\n\
8goq/KWT3C7d+gVoWs4A72/zPjWq2PAiOiCKwEwNHMsw5DMaKVcPMiym+lgOct5u\n\
YWXriuuxAgMBAAECggEAGFcM44beRJx3Z3w4bnIx0ax8biSxDlpwJ6BodoavllVz\n\
SMorMVwagH3nq2Tx0CoOqoM1sRCuFNgZ08hWMzRgPBjygUbNcmrxIniYxXfRWtXj\n\
qs+C7sdOFpJ+tEb4eJCNJTvOf6qUoES8BBLTSI70veruNs/mx//aBzKH16F/zDLI\n\
VxJrbq6zmsYDnzug9qfvSq4TCQpg7D7lpMHhrnmIGSf7Kip7VkX+Gjy8/qyXgk5c\n\
6xQC/xaPLOrBATuQ/DDBI0QGozbO0o+qV4L436LyemwIsc/0VjvxqZMYGDUsFe8b\n\
/vbVl+u3bxgWPgeUL0SDoisiMpfdCGJ/x3u8A37DBQKBgQDTT22ij44lfVN/Lr9d\n\
42p3y8E+I2gEZo3s7zDXFFdgyGiwBjAdaCebh+lomIxnxhleePjiJ1vL9o19wrQr\n\
bEJk2kOdvT2Mwi0dNu7t1OOVnzyA9W6+UbzVaCG99Hnl7cAsa8mS+zdaWrJ2vimC\n\
kbzRZNQdqjcjE81pQUXEOrLVPQKBgQC1BVyQmSFf16Be1ibh2li4zrdqRTa0q8rY\n\
4kJFSxlZ/vBSRhMK/gHBYgOVGKLcvARJi7i8FZ7uXqR2CU9Ngr55yLrzceP59ol2\n\
MSRougZtbNO8d7j5I2Eks206Nb7hClYWhLQ+9iRiHJvBdmiN7Axdy4lpLNQAanfk\n\
gHd0morfhQKBgQCLgV3NO99JiuMMDU3T62cH7eIHZxKuDRLYANYKuOgzAjxzMbKk\n\
R3YWrXUAU+4mONfY0h7mF7v3/S9OfrO6E0AGGz8WrbAr9KoaJoE5TRpvVnB4ZxCU\n\
35u+fIACS5wKm5sK+KJcwjO6GDTIRiVbiWHSEDIl35GFO/aZ7bjkoygbtQKBgQCX\n\
MV044M2BUYX+7/sV1NsZsH59YkXo7TvFnmUfnzQTeN2cui6ZlcI9lPHNDACrQNaL\n\
3wly/tP54E6Yz/nOkY8qBMAxKUTyuDnj3/O7DPTlXGoVFiIG5Mf0cXCfl9hP+eQh\n\
dsFdfRSyZZaqJY36S9egV6nzkJ+ZoVN2JN6hI5suSQKBgQDHGzsN0Q06qDpvhf63\n\
YKnpA15ce2/TmSCx0B7MZPxV71eapUTHbq/6NSyxPKEq3+eB36Pbe/MXKXhfisWm\n\
mKvCKFIq7VLWb4r2VkeVPb+HAylIf9ajEpzmXrKrN+20mHbC5EyWhcPIb3bmuh3w\n\
AD1kT35hNx5FOcjfcnVOjyV9fA==\n\
-----END PRIVATE KEY-----\n";

    const TEST_CERT_PEM_2: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDEzCCAfugAwIBAgIUP5YU7kvsEybJhzpee+A3wZ+CdBwwDQYJKoZIhvcNAQEL\n\
BQAwGTEXMBUGA1UEAwwOcmVnaXN0cnkyLnRlc3QwHhcNMjYxMTI0MTE0NDExWhcN\n\
MjcxMTI0MTE0NDExWjAZMRcwFQYDVQQDDA5yZWdpc3RyeTIudGVzdDCCASIwDQYJ\n\
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALkDvL1bGGwd9SvjUGe+W/gCpmye8eGo\n\
mlu9QfHHiGfSO+pHEAJeX7wE4l1hfgEke1Z8QcD5NqpnmasciBq3GtmbjpYXGi39\n\
KJ/oXO/ADEUkgeyeQpAZZpPOx6dBKj0xrJLxFYS5PLR36NBE7S9/VCXUufZkwJtr\n\
br79POwadzjB1i+g8mNCp4hSWMjFL+kpPpsiLvXu6vtWR383EnIvQ6U1AybsNuRK\n\
taEdVUTy6jbXNx5NJqP1LjbE/G6qHZDOmVJ+7VVyqqbZraUYFwjRO900R6P2tp0I\n\
SuGJw2c2CkyuUARFiIXCnVZ2pLPRwjMsRBUtXHH93Tww3Rpe5x6SNj8CAwEAAaNT\n\
MFEwHQYDVR0OBBYEFGZSaURlakmy2Rg/LCGVviqXkTWiMB8GA1UdIwQYMBaAFGZS\n\
aURlakmy2Rg/LCGVviqXkTWiMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n\
BQADggEBAFSx4Df2KpQn6tujaA43G0dGT5xNkCUS4NatdW/4ZJHO7zgKU+VtBc56\n\
GcxBYATSCU1blp6SnNP/CiIVA+AToHLqOHBKodGmoW3CIMvhyxpwR8Zj95x34fL7\n\
aHejP1RXfyuEq96zGh8pFAJyKnv2ofGx4YjPO1ijZcIcbWRVKerbZ3ExJHDqF3a+\n\
+9AHmOdOy+cQsGtuCgv6JBtXMAr2ECHIXIdL983XS9nzsvd/8Hbz1P8iEx7AqL2d\n\
4Zefva868DK44w7qH0UNuRgD5g5y5s4GB7GzN3Ob+8W8IuwLG9DV9tSvc+JxCVB4\n\
xEH8MefZ9kceFJbS8SRtPgqKrGkk73A=\n\
-----END CERTIFICATE-----\n";

    const TEST_KEY_PEM_2: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5A7y9WxhsHfUr\n\
41Bnvlv4AqZsnvHhqJpbvUHxx4hn0jvqRxACXl+8BOJdYX4BJHtWfEHA+TaqZ5mr\n\
HIgatxrZm46WFxot/Sif6FzvwAxFJIHsnkKQGWaTzsenQSo9MayS8RWEuTy0d+jQ\n\
RO0vf1Ql1Ln2ZMCba26+/TzsGnc4wdYvoPJjQqeIUljIxS/pKT6bIi717ur7Vkd/\n\
NxJyL0OlNQMm7DbkSrWhHVVE8uo21zceTSaj9S42xPxuqh2QzplSfu1Vcqqm2a2l\n\
GBcI0TvdNEej9radCErhicNnNgpMrlAERYiFwp1WdqSz0cIzLEQVLVxx/d08MN0a\n\
XucekjY/AgMBAAECggEAMQhBBmv0gn7EAZAaOIxWAlntcj8Depr84ZA8QE/xohYw\n\
48tWflI1i/Y9aaMTSkk5WLfQk0xYxPt02cjTd0UMnBwiQzu3J/X+RLbHnpBmkBJ3\n\
Tla47EiXC1gTSIu4HoSiKEU1Pzn6URewPzXtKBfWHLqOWDLmaqojrQEfGrF+5C7i\n\
5IDkGFtRNmvI2XN6AECh0vCiJuwHCEPImccEVazKxy95iAPjmFAqZ4YehekhbCPK\n\
H9OZVYueM57iwomxOlF/pS2XFhvZX3g4akFOBqHbK4dUwEVgOED+fG00s/Vz8VUT\n\
Lb9NK/YS+feF8q49jStmGRg+5Tf27+f3/pkSpWsl1QKBgQDwCfVTFxodvKeKVbaU\n\
HMknObqjLIm+ZWPPLYi7H5N6iygI8fkqhr+3/99+2W4dhoh6vXFYCSPhLk58r03G\n\
KtTdnEOAb0LeOsYBZ64SEeBceKl/L69rc1NW5LooZVmClKk1WRsZsum4kpHnjnV1\n\
NcPh7hp2E1Abvbvkg5xqh4/gFQKBgQDFUSHrLAF8QuiNiLJsE46V3W3eK92yxKxs\n\
Xzekxmf8ITAr88QSi6py2VMIM54aIewrimfOYayFzE2TuG0zA5/ADMrwNXpV5+pQ\n\
4ssj2g+Zg+ot37+Ym9o3yiRGDgMAUbTmZA5gttbB4GoDWo1QHa4kBONlKllMFRgf\n\
Q5AF4we+AwKBgAhXADwL0G96D4Qh6D8LJP4E5nQm5v5DfY1EMrz1ouUeEp0E8zhE\n\
CEM3U6ePnGDQPMuu61I4txNqzXVNjfE1qcGtXTcIJpWcCycfWA/uqRHta04s9PZR\n\
wnKBbepbYxnDWoGs/+ELs00jYoheDbytyol+AVNa5mygUffljriwzxHlAoGAa7wD\n\
wArz+Kvzm6uid74p4QvYvDDJSJ1342gN0qr+Bbz9N1JOoS2e8DxWyKieT3hsIc3d\n\
JeNQtnE5fkl5XhxBcjPJ7mPUmukYl/dsoPOkBtbu2wNK8oFOIZ3+Nj3aR6dVFWJW\n\
M1pBYfQtDg24EKFT/piorAj2XsM5u4BBN+WgyY8CgYEArREl99NSOJqmCIz4xCOH\n\
ab8Zf9Di7tJEFp6itPl9I3rOpV+RqqONcapw/jPeZsbGbsbgStX50b52hMbllfS1\n\
nB99xJBcpcklOhB/x8L3Vb9kw8ZPzUvYKI7lj0+yjYJannulkI7H7LB4hxKnVKp5\n\
/zgIzR6sWiCxqCSZSdAKj4w=\n\
-----END PRIVATE KEY-----\n";

    #[tokio::test]
    async fn test_cross_origin_redirect_drops_otp_even_when_destination_trusted_and_has_token() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener_target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener_target.local_addr().unwrap().port();

        let listener_src = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let src_port = listener_src.local_addr().unwrap().port();

        // Server 1 (source): redirects to Server 2 (target)
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener_src.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{target_port}/dest\r\nContent-Length: 0\r\n\r\n"
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        // Server 2 (target): receives redirect
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener_target.accept().await {
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_text = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = tx.send(req_text).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        // Configure client where target host is explicitly trusted and has an explicit token
        let mut config = RegistryClientConfig::default();
        config.trusted_hosts.insert(format!("127.0.0.1:{target_port}"));
        config.auth_tokens.insert(format!("//127.0.0.1:{target_port}/"), "target-secret-token".into());

        let client = RegistryClient::with_config(config).unwrap();
        let initial_url = Url::parse(&format!("http://127.0.0.1:{src_port}/initial")).unwrap();
        let res = client
            .execute_request_loop_with_body(
                Method::POST,
                initial_url,
                Some("application/json"),
                Some("application/json"),
                Some("654321"),
                b"{}".to_vec(),
            )
            .await;
        assert!(res.is_ok());

        let target_req = rx.recv().await.unwrap();
        // Destination received authorization token because it has an explicit token configured
        assert!(target_req.contains("authorization: Bearer target-secret-token"));
        // BUT npm-otp MUST be strictly dropped on cross-origin redirect
        assert!(!target_req.to_ascii_lowercase().contains("npm-otp"), "OTP leaked across cross-origin redirect!");
    }

    #[tokio::test]
    async fn test_same_origin_redirect_keeps_otp() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            // First request: redirect to same-origin /second
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_text = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = tx.send(req_text).await;
                let response = format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{port}/second\r\nContent-Length: 0\r\n\r\n"
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }

            // Second request: received at /second
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_text = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = tx.send(req_text).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let mut config = RegistryClientConfig::default();
        config.trusted_hosts.insert(format!("127.0.0.1:{port}"));
        config.auth_tokens.insert(format!("//127.0.0.1:{port}/"), "my-same-origin-token".into());

        let client = RegistryClient::with_config(config).unwrap();
        let initial_url = Url::parse(&format!("http://127.0.0.1:{port}/first")).unwrap();
        let res = client
            .execute_request_loop_with_body(
                Method::POST,
                initial_url,
                Some("application/json"),
                Some("application/json"),
                Some("998877"),
                b"{}".to_vec(),
            )
            .await;
        assert!(res.is_ok());

        let first_req = rx.recv().await.unwrap();
        assert!(first_req.contains("npm-otp: 998877"));

        let second_req = rx.recv().await.unwrap();
        // Same-origin redirect MUST retain the OTP header!
        assert!(second_req.contains("npm-otp: 998877"));
        assert!(second_req.contains("authorization: Bearer my-same-origin-token"));
    }

    #[test]
    fn test_https_to_http_downgrade_strips_auth_and_otp_even_with_explicit_token() {
        let initial_url = Url::parse("https://registry.example.com/api").unwrap();
        let downgrade_url = Url::parse("http://registry.example.com/api").unwrap();
        let downgrade_untrusted_url = Url::parse("http://insecure.example.com/api").unwrap();

        let mut config = RegistryClientConfig::default();
        config.trusted_hosts.insert("registry.example.com".into());
        config.trusted_hosts.insert("insecure.example.com".into());
        config.auth_tokens.insert("//registry.example.com/".into(), "secret-token-1".into());
        config.auth_tokens.insert("//insecure.example.com/".into(), "secret-token-2".into());

        let client = RegistryClient::with_config(config).unwrap();

        // HTTPS -> HTTP downgrade MUST NEVER be trusted, even if destination has explicit token
        assert!(!client.is_trusted_target(&initial_url, &downgrade_url));
        assert!(!client.is_trusted_target(&initial_url, &downgrade_untrusted_url));

        // Same origin HTTPS -> HTTPS is trusted
        let same_origin_https = Url::parse("https://registry.example.com/api/v2").unwrap();
        assert!(client.is_trusted_target(&initial_url, &same_origin_https));
    }

    #[test]
    fn test_same_origin_edge_cases() {
        let url_default_port = Url::parse("https://registry.example.com/api").unwrap();
        let url_explicit_port = Url::parse("https://registry.example.com:443/api").unwrap();
        let url_upper = Url::parse("https://REGISTRY.EXAMPLE.COM/api").unwrap();
        let url_ipv6_1 = Url::parse("https://[::1]:8443/api").unwrap();
        let url_ipv6_2 = Url::parse("https://[::1]:8443/other").unwrap();
        let url_ipv6_diff_port = Url::parse("https://[::1]:8444/api").unwrap();

        let mut config = RegistryClientConfig::default();
        config.trusted_hosts.insert("registry.example.com".into());
        config.trusted_hosts.insert("[::1]:8443".into());
        let client = RegistryClient::with_config(config).unwrap();

        // Origin checks
        assert!(client.is_same_origin(&url_default_port, &url_explicit_port));
        assert!(client.is_same_origin(&url_explicit_port, &url_default_port));
        assert!(client.is_same_origin(&url_default_port, &url_upper));
        assert!(client.is_same_origin(&url_ipv6_1, &url_ipv6_2));
        assert!(!client.is_same_origin(&url_ipv6_1, &url_ipv6_diff_port));

        // Default port matching (443 implicit vs explicit)
        assert!(client.is_trusted_target(&url_default_port, &url_explicit_port));
        assert!(client.is_trusted_target(&url_explicit_port, &url_default_port));

        // Case-insensitive host
        assert!(client.is_trusted_target(&url_default_port, &url_upper));

        // IPv6 same origin
        assert!(client.is_trusted_target(&url_ipv6_1, &url_ipv6_2));

        // IPv6 different port (cross origin)
        assert!(!client.is_trusted_target(&url_ipv6_1, &url_ipv6_diff_port));
    }

    #[test]
    fn test_scoped_tls_longest_prefix_matching() {
        // Test prefix generation
        let prefixes = generate_path_prefixes("/npm/v1/packages/pkg");
        assert_eq!(
            prefixes,
            vec![
                "/npm/v1/packages/pkg/",
                "/npm/v1/packages/pkg",
                "/npm/v1/packages/",
                "/npm/v1/packages",
                "/npm/v1/",
                "/npm/v1",
                "/npm/",
                "/npm",
                "/",
                "",
            ]
        );

        // Test URI prefix normalization
        assert_eq!(
            normalize_uri_prefix("https://registry.example.com/npm"),
            "//registry.example.com/npm/"
        );
        assert_eq!(
            normalize_uri_prefix("//REGISTRY.EXAMPLE.COM"),
            "//registry.example.com/"
        );
        assert_eq!(
            normalize_uri_prefix("//registry.example.com:8443/custom"),
            "//registry.example.com:8443/custom/"
        );

        // Configure scoped TLS with longest-prefix precedence
        let mut config = RegistryClientConfig::default();
        config.scoped_tls.insert(
            "//registry.example.com/".into(),
            ScopedTlsConfig::from_pem(TEST_CERT_PEM_1, TEST_KEY_PEM_1),
        );
        config.scoped_tls.insert(
            "//registry.example.com/npm/".into(),
            ScopedTlsConfig::from_pem(TEST_CERT_PEM_2, TEST_KEY_PEM_2),
        );

        let client = RegistryClient::with_config(config).unwrap();

        // /npm/ subpath matches the more specific scoped config (longest prefix)
        let npm_url = Url::parse("https://registry.example.com/npm/packages/pkg").unwrap();
        assert!(client.has_scoped_tls_for_url(&npm_url));
        assert!(client.match_scoped_client(&npm_url).is_some());
        let npm_c = client.client_for_url(&npm_url);

        // /other subpath matches the root scoped config
        let other_url = Url::parse("https://registry.example.com/other/pkg").unwrap();
        assert!(client.has_scoped_tls_for_url(&other_url));
        assert!(client.match_scoped_client(&other_url).is_some());
        let other_c = client.client_for_url(&other_url);

        // /npm2/pkg has prefix /npm2/ which does not match /npm/, so it matches root /
        let npm2_url = Url::parse("https://registry.example.com/npm2/pkg").unwrap();
        assert!(client.has_scoped_tls_for_url(&npm2_url));
        assert!(client.match_scoped_client(&npm2_url).is_some());
        let npm2_c = client.client_for_url(&npm2_url);

        // Pointers must be distinct for different scoped clients, not base unauthenticated client
        assert!(!std::ptr::eq(npm_c, other_c));
        assert!(!std::ptr::eq(npm_c, client.base_client()));
        assert!(!std::ptr::eq(other_c, client.base_client()));

        // /npm2/pkg matches root scoped client, NOT /npm/ client
        assert!(std::ptr::eq(npm2_c, other_c));
        assert!(!std::ptr::eq(npm2_c, npm_c));

        // Different host does not match any scoped config and returns base client
        let diff_host = Url::parse("https://other-registry.com/npm/pkg").unwrap();
        assert!(!client.has_scoped_tls_for_url(&diff_host));
        assert!(client.match_scoped_client(&diff_host).is_none());
        assert!(std::ptr::eq(client.client_for_url(&diff_host), client.base_client()));
    }

    #[test]
    fn test_scoped_tls_fallback_to_global_and_no_leak() {
        let mut config = RegistryClientConfig {
            cert: Some(TEST_CERT_PEM_1.into()),
            key: Some(TEST_KEY_PEM_1.into()),
            ..Default::default()
        };
        config.trusted_hosts.insert("global-registry.example.com".into());
        config.scoped_tls.insert(
            "//scoped-registry.example.com/scoped_prefix/".into(),
            ScopedTlsConfig::from_pem(TEST_CERT_PEM_2, TEST_KEY_PEM_2),
        );

        let client = RegistryClient::with_config(config).unwrap();
        assert!(client.has_global_tls());

        let scoped_url = Url::parse("https://scoped-registry.example.com/scoped_prefix/pkg").unwrap();
        let unscoped_on_scoped_host = Url::parse("https://scoped-registry.example.com/other/pkg").unwrap();
        let global_url = Url::parse("https://global-registry.example.com/pkg").unwrap();
        let untrusted_url = Url::parse("https://untrusted-redirect.evil.com/pkg").unwrap();
        let other_reg_url = Url::parse("https://other-registry.org/pkg").unwrap();

        // 1. Scoped registry prefix gets its own client (neither base client nor global client)
        assert!(client.has_scoped_tls_for_url(&scoped_url));
        let scoped_c = client.client_for_url(&scoped_url);
        assert!(!std::ptr::eq(scoped_c, client.base_client()));

        // 2. Global registry falls back to global TLS client because host is trusted
        assert!(!client.has_scoped_tls_for_url(&global_url));
        let global_c = client.client_for_url(&global_url);
        assert!(!std::ptr::eq(global_c, client.base_client()));
        assert!(!std::ptr::eq(global_c, scoped_c));
        assert!(client.is_trusted_host(&global_url));

        // 3. Untrusted redirect NEVER receives scoped or global TLS client certificate!
        assert!(!client.has_scoped_tls_for_url(&untrusted_url));
        assert!(!client.is_trusted_host(&untrusted_url));
        let untrusted_c = client.client_for_url(&untrusted_url);
        assert!(std::ptr::eq(untrusted_c, client.base_client()));

        // 4. Other untrusted registry also never receives scoped cert
        let other_c = client.client_for_url(&other_reg_url);
        assert!(std::ptr::eq(other_c, client.base_client()));

        // 5. http:// URL (even on trusted or scoped host) returns client.base_client()
        let http_scoped = Url::parse("http://scoped-registry.example.com/scoped_prefix/pkg").unwrap();
        let http_global = Url::parse("http://global-registry.example.com/pkg").unwrap();
        assert!(std::ptr::eq(client.client_for_url(&http_scoped), client.base_client()));
        assert!(std::ptr::eq(client.client_for_url(&http_global), client.base_client()));

        // 6. Unscoped path on a scoped-TLS host returns client.base_client() (does NOT leak global_client!)
        assert!(!client.has_scoped_tls_for_url(&unscoped_on_scoped_host));
        let unscoped_c = client.client_for_url(&unscoped_on_scoped_host);
        assert!(std::ptr::eq(unscoped_c, client.base_client()));
    }

    #[test]
    fn test_scoped_tls_certfile_keyfile_from_disk_and_error_handling() {
        use std::io::Write;

        // 1. Valid certfile and keyfile on disk
        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(TEST_CERT_PEM_1.as_bytes()).unwrap();
        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(TEST_KEY_PEM_1.as_bytes()).unwrap();

        let config = RegistryClientConfig {
            certfile: Some(cert_file.path().to_path_buf()),
            keyfile: Some(key_file.path().to_path_buf()),
            ..Default::default()
        };

        let client = RegistryClient::with_config(config);
        assert!(client.is_ok(), "Failed to build client with certfile and keyfile");

        // 2. Missing certfile returns clear error
        let config_missing_cert = RegistryClientConfig {
            certfile: Some(PathBuf::from("nonexistent_cert_12345.pem")),
            keyfile: Some(key_file.path().to_path_buf()),
            ..Default::default()
        };
        match RegistryClient::with_config(config_missing_cert) {
            Err(RegistryError::Other(msg)) => {
                assert!(msg.contains("Failed to read certfile at 'nonexistent_cert_12345.pem'"));
            }
            Err(other) => panic!("Expected RegistryError::Other, got {other:?}"),
            Ok(_) => panic!("Expected error for missing certfile"),
        }

        // 3. Missing keyfile returns clear error
        let config_missing_key = RegistryClientConfig {
            certfile: Some(cert_file.path().to_path_buf()),
            keyfile: Some(PathBuf::from("nonexistent_key_12345.pem")),
            ..Default::default()
        };
        match RegistryClient::with_config(config_missing_key) {
            Err(RegistryError::Other(msg)) => {
                assert!(msg.contains("Failed to read keyfile at 'nonexistent_key_12345.pem'"));
            }
            Err(other) => panic!("Expected RegistryError::Other, got {other:?}"),
            Ok(_) => panic!("Expected error for missing keyfile"),
        }

        // 4. Invalid PEM returns clear error
        let config_invalid_pem = RegistryClientConfig {
            cert: Some("not a valid pem cert".into()),
            key: Some("not a valid pem key".into()),
            ..Default::default()
        };
        match RegistryClient::with_config(config_invalid_pem) {
            Err(RegistryError::Other(msg)) => {
                assert!(msg.contains("Failed to parse client certificate and key into Identity"));
            }
            Err(other) => panic!("Expected RegistryError::Other, got {other:?}"),
            Ok(_) => panic!("Expected error for invalid PEM"),
        }

        // 5. Cert without key returns clear error
        let config_cert_no_key = RegistryClientConfig {
            cert: Some(TEST_CERT_PEM_1.into()),
            key: None,
            ..Default::default()
        };
        match RegistryClient::with_config(config_cert_no_key) {
            Err(RegistryError::Other(msg)) => {
                assert!(msg.contains("both cert and key are required"));
            }
            Err(other) => panic!("Expected RegistryError::Other, got {other:?}"),
            Ok(_) => panic!("Expected error for cert without key"),
        }

        // 6. Key without cert returns clear error
        let config_key_no_cert = RegistryClientConfig {
            cert: None,
            key: Some(TEST_KEY_PEM_1.into()),
            ..Default::default()
        };
        match RegistryClient::with_config(config_key_no_cert) {
            Err(RegistryError::Other(msg)) => {
                assert!(msg.contains("both cert and key are required"));
            }
            Err(other) => panic!("Expected RegistryError::Other, got {other:?}"),
            Ok(_) => panic!("Expected error for key without cert"),
        }
    }

    #[test]
    fn test_scoped_tls_empty_and_null_ignored_cleanly() {
        let mut config = RegistryClientConfig::default();
        config.scoped_tls.insert(
            "//registry.example.com/null_entry/".into(),
            ScopedTlsConfig {
                cert: Some("null".into()),
                key: Some("undefined".into()),
                certfile: Some(PathBuf::from("")),
                keyfile: Some(PathBuf::from("   ")),
            },
        );
        config.scoped_tls.insert(
            "//registry.example.com/empty_entry/".into(),
            ScopedTlsConfig {
                cert: Some("".into()),
                key: Some("   ".into()),
                certfile: None,
                keyfile: None,
            },
        );

        let client = RegistryClient::with_config(config);
        assert!(client.is_ok(), "Client init should succeed with empty/null TLS config");
        let client = client.unwrap();

        // The empty/null scoped entries should have been cleanly skipped
        let url_null = Url::parse("https://registry.example.com/null_entry/pkg").unwrap();
        let url_empty = Url::parse("https://registry.example.com/empty_entry/pkg").unwrap();
        assert!(!client.has_scoped_tls_for_url(&url_null));
        assert!(!client.has_scoped_tls_for_url(&url_empty));
        assert!(std::ptr::eq(client.client_for_url(&url_null), client.base_client()));
        assert!(std::ptr::eq(client.client_for_url(&url_empty), client.base_client()));
    }

    #[test]
    fn test_scoped_tls_combined_pem_bundle() {
        use std::io::Write;

        let combined_pem = format!("{}\n{}", TEST_CERT_PEM_1.trim(), TEST_KEY_PEM_1.trim());

        // 1. Via inline combined cert string without key
        let mut config_inline = RegistryClientConfig::default();
        config_inline.scoped_tls.insert(
            "//registry.example.com/inline/".into(),
            ScopedTlsConfig {
                cert: Some(combined_pem.clone()),
                key: None,
                certfile: None,
                keyfile: None,
            },
        );
        let client_inline = RegistryClient::with_config(config_inline);
        assert!(client_inline.is_ok(), "Combined PEM string should initialize successfully");
        let client_inline = client_inline.unwrap();
        let inline_url = Url::parse("https://registry.example.com/inline/pkg").unwrap();
        assert!(client_inline.has_scoped_tls_for_url(&inline_url));
        assert!(!std::ptr::eq(client_inline.client_for_url(&inline_url), client_inline.base_client()));

        // 2. Via combined certfile on disk without keyfile
        let mut combined_file = tempfile::NamedTempFile::new().unwrap();
        combined_file.write_all(combined_pem.as_bytes()).unwrap();

        let mut config_file = RegistryClientConfig::default();
        config_file.scoped_tls.insert(
            "//registry.example.com/file/".into(),
            ScopedTlsConfig {
                cert: None,
                key: None,
                certfile: Some(combined_file.path().to_path_buf()),
                keyfile: None,
            },
        );
        let client_file = RegistryClient::with_config(config_file);
        assert!(client_file.is_ok(), "Combined PEM certfile should initialize successfully");
        let client_file = client_file.unwrap();
        let file_url = Url::parse("https://registry.example.com/file/pkg").unwrap();
        assert!(client_file.has_scoped_tls_for_url(&file_url));
        assert!(!std::ptr::eq(client_file.client_for_url(&file_url), client_file.base_client()));
    }

    #[test]
    fn test_scoped_tls_parent_prefix_inheritance() {
        use std::io::Write;

        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(TEST_CERT_PEM_1.as_bytes()).unwrap();

        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(TEST_KEY_PEM_1.as_bytes()).unwrap();

        let mut config = RegistryClientConfig::default();
        // Root of host defines certfile
        config.scoped_tls.insert(
            "//registry.example.com/".into(),
            ScopedTlsConfig {
                certfile: Some(cert_file.path().to_path_buf()),
                cert: None,
                keyfile: None,
                key: None,
            },
        );
        // Subpath defines only keyfile, inherits certfile from parent //registry.example.com/
        config.scoped_tls.insert(
            "//registry.example.com/sub/".into(),
            ScopedTlsConfig {
                certfile: None,
                cert: None,
                keyfile: Some(key_file.path().to_path_buf()),
                key: None,
            },
        );

        let client = RegistryClient::with_config(config);
        assert!(client.is_ok(), "Subpath should inherit certfile from parent prefix on the same host");
        let client = client.unwrap();

        let sub_url = Url::parse("https://registry.example.com/sub/packages/pkg").unwrap();
        assert!(client.has_scoped_tls_for_url(&sub_url));
        assert!(!std::ptr::eq(client.client_for_url(&sub_url), client.base_client()));

        // Different host does NOT inherit certfile from registry.example.com
        let mut config_diff = RegistryClientConfig::default();
        config_diff.scoped_tls.insert(
            "//registry.example.com/".into(),
            ScopedTlsConfig {
                certfile: Some(cert_file.path().to_path_buf()),
                cert: None,
                keyfile: None,
                key: None,
            },
        );
        config_diff.scoped_tls.insert(
            "//other-registry.com/sub/".into(),
            ScopedTlsConfig {
                certfile: None,
                cert: None,
                keyfile: Some(key_file.path().to_path_buf()),
                key: None,
            },
        );
        let client_diff = RegistryClient::with_config(config_diff);
        assert!(client_diff.is_err(), "Different host must NOT inherit certfile from another host");
    }

    #[test]
    fn test_lazy_http_client_init_defers_construction_until_first_use() {
        let client = RegistryClient::with_config(RegistryClientConfig::default()).unwrap();
        assert!(
            client.base_client.cell.get().is_none(),
            "base HTTP/TLS client should stay uninitialized until first network use"
        );
        let url = Url::parse("https://registry.npmjs.org/lodash").unwrap();
        let _ = client.client_for_url(&url);
        assert!(
            client.base_client.cell.get().is_some(),
            "base HTTP/TLS client should initialize lazily on first client_for_url"
        );
    }

    #[tokio::test]
    async fn test_negotiated_abbreviated_and_representation_isolated_cache_and_fallback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let abbrev_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let full_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let saw_abbrev_etag_on_full = Arc::new(AtomicBool::new(false));
        let reject_abbrev = Arc::new(AtomicBool::new(false));

        let abbrev_calls_c = Arc::clone(&abbrev_calls);
        let full_calls_c = Arc::clone(&full_calls);
        let bad_etag_c = Arc::clone(&saw_abbrev_etag_on_full);
        let reject_abbrev_c = Arc::clone(&reject_abbrev);

        let abbrev_body = serde_json::json!({
            "name": "neg-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "modified": "2026-01-01T00:00:00.000Z",
            "versions": {
                "1.0.0": {
                    "name": "neg-pkg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": format!("http://{addr}/neg-pkg/-/neg-pkg-1.0.0.tgz")
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string();

        let full_body = serde_json::json!({
            "name": "neg-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "time": {
                "created": "2025-01-01T00:00:00.000Z",
                "1.0.0": "2025-06-01T00:00:00.000Z"
            },
            "versions": {
                "1.0.0": {
                    "name": "neg-pkg",
                    "version": "1.0.0",
                    "license": "MIT",
                    "scripts": { "test": "echo ok" },
                    "dist": {
                        "tarball": format!("http://{addr}/neg-pkg/-/neg-pkg-1.0.0.tgz")
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string();

        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let abbrev_body = abbrev_body.clone();
                let full_body = full_body.clone();
                let abbrev_calls = Arc::clone(&abbrev_calls_c);
                let full_calls = Arc::clone(&full_calls_c);
                let bad_etag = Arc::clone(&bad_etag_c);
                let reject_abbrev = Arc::clone(&reject_abbrev_c);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let mut accept = "";
                    let mut inm = None;
                    for line in req_str.split("\r\n").skip(1) {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.eq_ignore_ascii_case("accept") {
                                accept = v.trim();
                            } else if k.eq_ignore_ascii_case("if-none-match") {
                                inm = Some(v.trim());
                            }
                        }
                    }
                    let is_abbrev = accept.contains("vnd.npm.install-v1+json");
                    let resp = if is_abbrev {
                        abbrev_calls.fetch_add(1, Ordering::SeqCst);
                        if reject_abbrev.load(Ordering::SeqCst) {
                            "HTTP/1.1 406 Not Acceptable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                        } else if inm == Some("\"etag-abbrev-1\"") {
                            "HTTP/1.1 304 Not Modified\r\nETag: \"etag-abbrev-1\"\r\nContent-Type: application/vnd.npm.install-v1+json\r\nVary: Accept\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                        } else {
                            format!(
                                "HTTP/1.1 200 OK\r\nETag: \"etag-abbrev-1\"\r\nContent-Type: application/vnd.npm.install-v1+json\r\nVary: Accept\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                abbrev_body.len(),
                                abbrev_body
                            )
                        }
                    } else {
                        full_calls.fetch_add(1, Ordering::SeqCst);
                        if inm == Some("\"etag-abbrev-1\"") || inm == Some("\"stale-abbrev\"") {
                            bad_etag.store(true, Ordering::SeqCst);
                        }
                        if inm == Some("\"etag-full-1\"") {
                            "HTTP/1.1 304 Not Modified\r\nETag: \"etag-full-1\"\r\nContent-Type: application/json\r\nVary: Accept\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                        } else {
                            format!(
                                "HTTP/1.1 200 OK\r\nETag: \"etag-full-1\"\r\nContent-Type: application/json\r\nVary: Accept\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                full_body.len(),
                                full_body
                            )
                        }
                    };
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let cfg = RegistryClientConfig {
            default_registry: Url::parse(&format!("http://{addr}/")).unwrap(),
            ..Default::default()
        };
        let client = RegistryClient::with_config(cfg).unwrap();

        let key_a = client
            .packument_cache_key("neg-pkg", PackumentRepresentation::Abbreviated)
            .unwrap();
        let key_f = client
            .packument_cache_key("neg-pkg", PackumentRepresentation::Full)
            .unwrap();
        assert_ne!(key_a, key_f);

        // 1. Abbreviated request populates Abbreviated cache only
        let m1 = client
            .get_package_metadata_negotiated("neg-pkg", PackumentFetchOptions::abbreviated())
            .await
            .unwrap();
        assert!(m1.time.is_empty());
        assert_eq!(
            client
                .cached_packument_etag("neg-pkg", PackumentRepresentation::Abbreviated)
                .as_deref(),
            Some("\"etag-abbrev-1\"")
        );
        assert!(client
            .cached_packument_etag("neg-pkg", PackumentRepresentation::Full)
            .is_none());

        // 2. Second abbreviated call revalidates with abbreviated ETag -> 304 hit from cache
        let m2 = client
            .get_package_metadata_negotiated("neg-pkg", PackumentFetchOptions::abbreviated())
            .await
            .unwrap();
        assert_eq!(m1.versions.len(), m2.versions.len());
        assert_eq!(abbrev_calls.load(Ordering::SeqCst), 2);
        assert_eq!(full_calls.load(Ordering::SeqCst), 0);

        // 3. Time-based resolution (--before) negotiates Full cleanly without sending abbreviated ETag
        let m_full = client
            .get_package_metadata_negotiated(
                "neg-pkg",
                PackumentFetchOptions {
                    require_publish_times: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            m_full.time.get("1.0.0").map(String::as_str),
            Some("2025-06-01T00:00:00.000Z")
        );
        assert_eq!(
            m_full.versions["1.0.0"].license.as_deref(),
            Some("MIT")
        );
        assert_eq!(
            client
                .cached_packument_etag("neg-pkg", PackumentRepresentation::Full)
                .as_deref(),
            Some("\"etag-full-1\"")
        );
        assert_eq!(
            client
                .cached_packument_etag("neg-pkg", PackumentRepresentation::Abbreviated)
                .as_deref(),
            Some("\"etag-abbrev-1\"")
        );

        // 4. Fallback when abbreviated omits `time` falls back to Full without leaking stale abbreviated ETag
        let fb = client
            .get_package_metadata_with_full_fallback("neg-pkg", Some("\"stale-abbrev\""), |m| {
                m.time.is_empty()
            })
            .await
            .unwrap();
        assert!(!saw_abbrev_etag_on_full.load(Ordering::SeqCst));
        assert!(fb.is_fresh());
        assert!(!fb.metadata().unwrap().time.is_empty());

        reject_abbrev.store(true, Ordering::SeqCst);
        let fallback = client
            .get_package_metadata_negotiated("neg-pkg", PackumentFetchOptions::abbreviated())
            .await
            .unwrap();
        assert_eq!(fallback.versions["1.0.0"].license.as_deref(), Some("MIT"));
        assert!(!saw_abbrev_etag_on_full.load(Ordering::SeqCst));

        server.abort();
    }

    #[tokio::test]
    async fn test_negotiated_application_json_response_does_not_poison_full_cache() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = serde_json::json!({
            "name": "plain-json-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "time": { "1.0.0": "2025-06-01T00:00:00.000Z" },
            "versions": {
                "1.0.0": {
                    "name": "plain-json-pkg",
                    "version": "1.0.0",
                    "license": "MIT",
                    "repository": "git+https://github.com/example/plain-json-pkg.git",
                    "dist": {
                        "tarball": format!("http://{addr}/plain-json-pkg/-/plain-json-pkg-1.0.0.tgz")
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string();

        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let mut inm = None;
                    for line in req_str.split("\r\n").skip(1) {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.eq_ignore_ascii_case("if-none-match") {
                                inm = Some(v.trim());
                            }
                        }
                    }
                    let resp = if inm == Some("\"plain-etag\"") {
                        "HTTP/1.1 304 Not Modified\r\nETag: \"plain-etag\"\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\nETag: \"plain-etag\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    };
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let cfg = RegistryClientConfig {
            default_registry: Url::parse(&format!("http://{addr}/")).unwrap(),
            ..Default::default()
        };
        let client = RegistryClient::with_config(cfg).unwrap();

        // Abbreviated fetch receives Content-Type: application/json from a server that ignores Accept
        let m1 = client
            .get_package_metadata_negotiated("plain-json-pkg", PackumentFetchOptions::abbreviated())
            .await
            .unwrap();
        assert!(!m1.versions["1.0.0"].extra.contains_key("repository"));
        assert_eq!(
            client
                .cached_packument_etag("plain-json-pkg", PackumentRepresentation::Abbreviated)
                .as_deref(),
            Some("\"plain-etag\"")
        );
        assert!(client
            .cached_packument_etag("plain-json-pkg", PackumentRepresentation::Full)
            .is_none());

        // Second abbreviated fetch hits 304 Not Modified against Abbreviated cache
        let url = Url::parse(&format!("http://{addr}/plain-json-pkg")).unwrap();
        let abbrev_etag = client
            .cached_packument_etag("plain-json-pkg", PackumentRepresentation::Abbreviated);
        let res2 = client
            .get_package_metadata_negotiated_conditional_at_url(
                "plain-json-pkg",
                &url,
                abbrev_etag.as_deref(),
                PackumentFetchOptions::abbreviated(),
            )
            .await
            .unwrap();
        assert!(res2.is_not_modified());

        // Full fetch is NOT poisoned by the Install-parsed Abbreviated cache entry
        let m_full = client
            .get_package_metadata_negotiated(
                "plain-json-pkg",
                PackumentFetchOptions {
                    representation: PackumentRepresentation::Full,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            m_full.versions["1.0.0"]
                .extra
                .get("repository")
                .and_then(|v| v.as_str()),
            Some("git+https://github.com/example/plain-json-pkg.git")
        );
        assert_eq!(
            m_full.versions["1.0.0"].license.as_deref(),
            Some("MIT")
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_download_tarball_bytes_with_sha512_integrity() {
        use sha2::{Digest, Sha512};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let payload = vec![0x42u8; 131_072];
        let expected_sri = {
            let d = Sha512::digest(&payload);
            format!("sha512-{}", data_encoding::BASE64.encode(&d))
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload_srv = payload.clone();
        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                    payload_srv.len()
                );
                let _ = stream.write_all(hdr.as_bytes()).await;
                let _ = stream.write_all(&payload_srv).await;
            }
        });

        let client = RegistryClient::with_config(RegistryClientConfig {
            default_registry: Url::parse(&format!("http://{addr}/")).unwrap(),
            ..Default::default()
        })
        .unwrap();
        let (bytes, sri) = client
            .download_tarball_bytes_with_sha512(&format!("http://{addr}/pkg/-/pkg-1.0.0.tgz"))
            .await
            .unwrap();
        assert_eq!(bytes, payload);
        assert_eq!(sri, expected_sri);
        server.abort();
    }

    #[tokio::test]
    async fn test_download_tarballs_to_files_concurrent_isolates_parent_dir_errors() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let body = b"tarball-ok";
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(hdr.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                });
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let blocking_file = dir.path().join("not-a-dir");
        std::fs::write(&blocking_file, b"x").unwrap();
        let bad_dest = blocking_file.join("pkg.tgz");
        let good_dest = dir.path().join("ok").join("pkg.tgz");
        let url = format!("http://{addr}/pkg/-/pkg-1.0.0.tgz");

        let client = RegistryClient::with_config(RegistryClientConfig {
            default_registry: Url::parse(&format!("http://{addr}/")).unwrap(),
            ..Default::default()
        })
        .unwrap();

        let results = client
            .download_tarballs_to_files_concurrent(&[
                (url.as_str(), bad_dest.as_path()),
                (url.as_str(), good_dest.as_path()),
            ])
            .await;
        assert_eq!(results.len(), 2);
        assert!(results[0].is_err(), "invalid parent must fail its own item");
        assert!(results[1].is_ok(), "sibling item with valid parent must succeed");
        assert_eq!(std::fs::read(&good_dest).unwrap(), b"tarball-ok");
        server.abort();
    }

    #[tokio::test]
    async fn test_scoped_auth_token_sent_on_initial_external_url() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured_auth = Arc::new(Mutex::new(None::<String>));
        let captured_clone = Arc::clone(&captured_auth);

        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                for line in req.lines() {
                    if line.to_ascii_lowercase().starts_with("authorization:") {
                        *captured_clone.lock().unwrap() = Some(line.trim().to_string());
                    }
                }
                let body = b"ok";
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(hdr.as_bytes()).await;
                let _ = stream.write_all(body).await;
            }
        });

        let mut auth_tokens = std::collections::BTreeMap::new();
        auth_tokens.insert(
            format!("//127.0.0.1:{}/", addr.port()),
            "cdn-secret-token".to_string(),
        );
        let client = RegistryClient::with_config(RegistryClientConfig {
            default_registry: Url::parse("https://registry.npmjs.org/").unwrap(),
            auth_tokens,
            ..Default::default()
        })
        .unwrap();

        let bytes = client
            .download_tarball_bytes(&format!("http://127.0.0.1:{}/pkg.tgz", addr.port()))
            .await
            .unwrap();
        assert_eq!(bytes, b"ok");
        assert_eq!(
            captured_auth.lock().unwrap().as_deref(),
            Some("authorization: Bearer cdn-secret-token"),
            "explicit auth_tokens entry must be attached on redirect_count == 0 even if not in trusted_hosts"
        );
        server.abort();
    }
}
