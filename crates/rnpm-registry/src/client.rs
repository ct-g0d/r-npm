use crate::error::RegistryError;
use crate::metadata::AbbreviatedPackageMetadata;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::{Client, Method, Response, StatusCode};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
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

/// Helper to percent-encode a URI component (RFC 3986 unreserved characters).
fn percent_encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{:02x}", b);
            }
        }
    }
    out
}

/// Encodes a package name according to npm registry rules:
/// Scoped packages `@scope/pkg` are encoded as `@<encoded_scope>%2f<encoded_pkg>`.
/// Unscoped packages `pkg` have special characters safely percent-encoded.
pub fn encode_package_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@') {
        if let Some((scope, pkg)) = rest.split_once('/') {
            let enc_scope = percent_encode_component(scope);
            let enc_pkg = if pkg.contains('/') {
                pkg.split('/')
                    .map(percent_encode_component)
                    .collect::<Vec<_>>()
                    .join("%2f")
            } else {
                percent_encode_component(pkg)
            };
            return format!("@{enc_scope}%2f{enc_pkg}");
        }
    }
    percent_encode_component(name)
}

/// Validates a package name against malicious patterns such as path traversal (`..`),
/// backslashes, empty names, and illegal control characters.
pub fn validate_package_name(name: &str) -> Result<(), RegistryError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(RegistryError::SecurityViolation(
            "Package name cannot be empty".to_string(),
        ));
    }

    if trimmed.contains('\0')
        || trimmed.contains('\\')
        || trimmed.contains('\r')
        || trimmed.contains('\n')
    {
        return Err(RegistryError::SecurityViolation(format!(
            "Package name contains illegal control or escape characters: '{trimmed}'"
        )));
    }

    let unverified = trimmed.strip_prefix('@').unwrap_or(trimmed);
    for segment in unverified.split('/') {
        if segment == "."
            || segment == ".."
            || segment.eq_ignore_ascii_case("%2e")
            || segment.eq_ignore_ascii_case("%2e%2e")
        {
            return Err(RegistryError::SecurityViolation(format!(
                "Package name contains forbidden path traversal component: '{name}'"
            )));
        }
    }

    Ok(())
}

/// Default maximum concurrent requests allowed across the client.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 16;

/// Default maximum idle connections per host in the connection pool.
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 32;

/// Default TCP keep-alive interval.
pub const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 60;

/// Default pool idle connection timeout.
pub const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 90;

/// Registry client configuration.
#[derive(Debug, Clone)]
pub struct RegistryClientConfig {
    pub default_registry: Url,
    pub user_agent: String,
    pub auth_token: Option<String>,
    pub auth_tokens: BTreeMap<String, String>,
    pub scoped_registries: BTreeMap<String, Url>,
    pub trusted_hosts: HashSet<String>,
    pub timeout: Duration,
    pub max_concurrent_requests: usize,
    pub pool_max_idle_per_host: usize,
    pub tcp_keepalive: Duration,
    pub pool_idle_timeout: Duration,
}

impl Default for RegistryClientConfig {
    fn default() -> Self {
        let registry_url = Url::parse("https://registry.npmjs.org/").unwrap();
        let mut trusted_hosts = HashSet::new();
        if let Some(h) = registry_url.host_str() {
            trusted_hosts.insert(h.to_ascii_lowercase());
        }

        Self {
            default_registry: registry_url,
            user_agent: default_user_agent(),
            auth_token: None,
            auth_tokens: BTreeMap::new(),
            scoped_registries: BTreeMap::new(),
            trusted_hosts,
            timeout: Duration::from_secs(30),
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE_PER_HOST,
            tcp_keepalive: Duration::from_secs(DEFAULT_TCP_KEEPALIVE_SECS),
            pool_idle_timeout: Duration::from_secs(DEFAULT_POOL_IDLE_TIMEOUT_SECS),
        }
    }
}

/// Client for interacting with npm package registries.
#[derive(Clone)]
pub struct RegistryClient {
    client: Client,
    config: RegistryClientConfig,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
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

        Ok(Self {
            client,
            config,
            semaphore,
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

    /// Determine which registry to use for a package (scoped registry if configured, otherwise default).
    pub fn registry_for_package(&self, package_name: &str) -> &Url {
        let trimmed = package_name.trim();
        if trimmed.starts_with('@') {
            let scope_part = if let Some(slash_idx) = trimmed.find('/') {
                &trimmed[..slash_idx]
            } else if let Some(enc_idx) = trimmed.to_ascii_lowercase().find("%2f") {
                &trimmed[..enc_idx]
            } else {
                trimmed
            };
            let scope_lower = scope_part.to_ascii_lowercase();
            if let Some(url) = self.config.scoped_registries.get(&scope_lower) {
                return url;
            }
        }
        &self.config.default_registry
    }

    /// Format the metadata URL for a package name, respecting scoped package precedence.
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
        validate_package_name(package_name)?;
        let encoded = encode_package_name(package_name);
        let base_str = registry.as_str().trim_end_matches('/');
        let url_str = format!("{base_str}/{encoded}");
        Url::parse(&url_str).map_err(RegistryError::UrlParse)
    }

    /// Retrieve the auth token applicable to the target URL.
    pub fn auth_token_for_url(&self, url: &Url) -> Option<&str> {
        // 1. Check url-specific tokens in auth_tokens map (e.g. "//registry.npmjs.org/")
        if !self.config.auth_tokens.is_empty() {
            if let Some(host) = url.host_str() {
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

                // Exact match "//host:port/path/"
                let key1 = format!("//{host_lower}{port_part}{normalized_path}");
                if let Some(tok) = self.config.auth_tokens.get(&key1) {
                    return Some(tok.as_str());
                }

                // Root match "//host:port/"
                let key2 = format!("//{host_lower}{port_part}/");
                if let Some(tok) = self.config.auth_tokens.get(&key2) {
                    return Some(tok.as_str());
                }

                // Root match without port "//host/"
                if !port_part.is_empty() {
                    let key3 = format!("//{host_lower}/");
                    if let Some(tok) = self.config.auth_tokens.get(&key3) {
                        return Some(tok.as_str());
                    }
                }
            }
        }

        // 2. Fall back to config.auth_token
        self.config.auth_token.as_deref()
    }

    /// Check if target URL is trusted to receive authorization headers.
    pub fn is_trusted_target(&self, initial_url: &Url, current_url: &Url) -> bool {
        // Disallow any non-HTTP(S) schemes
        if current_url.scheme() != "https" && current_url.scheme() != "http" {
            return false;
        }

        // Never allow scheme downgrade (HTTPS -> HTTP)
        if initial_url.scheme() == "https" && current_url.scheme() == "http" {
            return false;
        }

        let is_host_trusted = |url: &Url| -> bool {
            // Check default_registry origin match
            let matches_default = url.scheme() == self.config.default_registry.scheme()
                && url.host_str().map(|s| s.to_ascii_lowercase())
                    == self.config.default_registry.host_str().map(|s| s.to_ascii_lowercase())
                && url.port_or_known_default() == self.config.default_registry.port_or_known_default();

            if matches_default {
                return true;
            }

            // Check configured scoped registries
            for (_, scoped_url) in &self.config.scoped_registries {
                let matches_scoped = url.scheme() == scoped_url.scheme()
                    && url.host_str().map(|s| s.to_ascii_lowercase())
                        == scoped_url.host_str().map(|s| s.to_ascii_lowercase())
                    && url.port_or_known_default() == scoped_url.port_or_known_default();
                if matches_scoped {
                    return true;
                }
            }

            // Check trusted_hosts list
            if let Some(host) = url.host_str() {
                let host_lower = host.to_ascii_lowercase();
                if self.config.trusted_hosts.contains(&host_lower) {
                    return true;
                }
                if let Some(port) = url.port_or_known_default() {
                    if self.config.trusted_hosts.contains(&format!("{host_lower}:{port}")) {
                        return true;
                    }
                }
            }

            // Check auth_tokens map
            if !self.config.auth_tokens.is_empty() {
                if let Some(host) = url.host_str() {
                    let host_lower = host.to_ascii_lowercase();
                    let port_part = if let Some(port) = url.port() {
                        format!(":{port}")
                    } else {
                        String::new()
                    };
                    if self.config.auth_tokens.contains_key(&format!("//{host_lower}{port_part}/"))
                        || self.config.auth_tokens.contains_key(&format!("//{host_lower}/"))
                    {
                        return true;
                    }
                }
            }

            false
        };

        // If the initial URL itself is not from a trusted source, do not send credentials.
        if !is_host_trusted(initial_url) {
            return false;
        }

        // Same origin check between initial_url and current_url
        let same_origin = initial_url.scheme() == current_url.scheme()
            && initial_url.host_str().map(|s| s.to_ascii_lowercase())
                == current_url.host_str().map(|s| s.to_ascii_lowercase())
            && initial_url.port_or_known_default() == current_url.port_or_known_default();

        if same_origin {
            return true;
        }

        // If cross-origin / cross-host redirect, current_url must ALSO be individually trusted.
        is_host_trusted(current_url)
    }

    /// Execute a request following redirects manually and enforcing the security rule:
    /// Never forward auth headers across redirects to untrusted hostnames.
    pub async fn execute_with_security_policy(
        &self,
        mut method: Method,
        initial_url: Url,
        accept_header: Option<&str>,
    ) -> Result<Response, RegistryError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| RegistryError::Other(e.to_string()))?;

        let mut current_url = initial_url.clone();
        let mut credentials_stripped = false;

        for _redirect_count in 0..MAX_REDIRECTS {
            let mut req = self.client.request(method.clone(), current_url.clone());

            if let Some(accept) = accept_header {
                req = req.header(ACCEPT, accept);
            }

            // Security check: only send auth headers if the target is trusted (same origin or in trusted_hosts)
            let should_send_auth =
                !credentials_stripped && self.is_trusted_target(&initial_url, &current_url);

            if should_send_auth {
                if let Some(token) = self.auth_token_for_url(&current_url) {
                    req = req.header(AUTHORIZATION, format!("Bearer {token}"));
                }
            } else {
                credentials_stripped = true;
                debug!(
                    "Stripping Authorization header on redirect from '{}' to untrusted '{}'",
                    initial_url, current_url
                );
            }

            let resp = req.send().await?;
            let status = resp.status();

            if status.is_redirection() {
                if let Some(location) = resp.headers().get(reqwest::header::LOCATION) {
                    let loc_str = location.to_str().map_err(|_| {
                        RegistryError::SecurityViolation(
                            "Invalid characters in redirect Location header".into(),
                        )
                    })?;
                    let next_url = current_url.join(loc_str)?;

                    let next_scheme = next_url.scheme();
                    if next_scheme != "http" && next_scheme != "https" {
                        return Err(RegistryError::SecurityViolation(format!(
                            "Disallowed redirect scheme '{next_scheme}' in Location header"
                        )));
                    }

                    if status == StatusCode::SEE_OTHER
                        || ((status == StatusCode::MOVED_PERMANENTLY || status == StatusCode::FOUND)
                            && method == Method::POST)
                    {
                        method = Method::GET;
                    }

                    debug!("Following redirect {} -> {}", current_url, next_url);
                    current_url = next_url;
                    continue;
                } else {
                    return Err(RegistryError::ServerError {
                        status: status.as_u16(),
                        body: "Redirect response missing Location header".into(),
                    });
                }
            }

            return Ok(resp);
        }

        Err(RegistryError::TooManyRedirects(MAX_REDIRECTS))
    }

    /// Fetch abbreviated install metadata for a package from the default registry.
    pub async fn get_package_metadata(
        &self,
        package_name: &str,
    ) -> Result<AbbreviatedPackageMetadata, RegistryError> {
        let url = self.package_metadata_url(package_name)?;
        self.get_package_metadata_from_url(package_name, url).await
    }

    /// Fetch abbreviated install metadata from an explicit URL.
    pub async fn get_package_metadata_from_url(
        &self,
        package_name: &str,
        url: Url,
    ) -> Result<AbbreviatedPackageMetadata, RegistryError> {
        let resp = self
            .execute_with_security_policy(Method::GET, url.clone(), Some(NPM_INSTALL_V1_JSON))
            .await?;

        let status = resp.status();
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
                .get(reqwest::header::RETRY_AFTER)
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

        let metadata: AbbreviatedPackageMetadata = resp.json().await?;
        Ok(metadata)
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
        let url = Url::parse(tarball_url)?;
        let resp = self
            .execute_with_security_policy(Method::GET, url.clone(), None)
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
                .get(reqwest::header::RETRY_AFTER)
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

        Ok(resp)
    }

    /// Download tarball directly to memory bytes.
    pub async fn download_tarball_bytes(&self, tarball_url: &str) -> Result<Vec<u8>, RegistryError> {
        let resp = self.download_tarball(tarball_url).await?;
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
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
        let mut resp = self.download_tarball(tarball_url).await?;
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                RegistryError::Other(format!("Failed to create directories for {}: {e}", dest_path.display()))
            })?;
        }

        let mut file = tokio::fs::File::create(dest_path).await.map_err(|e| {
            RegistryError::Other(format!("Failed to create {}: {e}", dest_path.display()))
        })?;

        let mut written: u64 = 0;
        while let Some(chunk) = resp.chunk().await? {
            file.write_all(&chunk).await.map_err(|e| {
                RegistryError::Other(format!("Failed to write chunk to {}: {e}", dest_path.display()))
            })?;
            written += chunk.len() as u64;
        }

        file.flush().await.map_err(|e| {
            RegistryError::Other(format!("Failed to flush {}: {e}", dest_path.display()))
        })?;

        Ok(written)
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
        // Special characters and nested slashes
        assert_eq!(encode_package_name("@scope/nested/pkg"), "@scope%2fnested%2fpkg");
        assert_eq!(encode_package_name("@scope/foo bar"), "@scope%2ffoo%20bar");
        assert_eq!(encode_package_name("foo?query=1"), "foo%3fquery%3d1");
        assert_eq!(encode_package_name("foo#fragment"), "foo%23fragment");
    }

    #[test]
    fn test_validate_package_name() {
        // Valid names
        assert!(validate_package_name("lodash").is_ok());
        assert!(validate_package_name("@scope/pkg").is_ok());
        assert!(validate_package_name("my-pkg-1.0").is_ok());

        // Malicious path traversal
        assert!(validate_package_name("").is_err());
        assert!(validate_package_name("..").is_err());
        assert!(validate_package_name("../foo").is_err());
        assert!(validate_package_name("@scope/../../passwd").is_err());
        assert!(validate_package_name("@../foo").is_err());
        assert!(validate_package_name("foo/../bar").is_err());
        assert!(validate_package_name("foo\\bar").is_err());
        assert!(validate_package_name("foo\0bar").is_err());
        assert!(validate_package_name("foo\nbar").is_err());
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

        // Path traversal should be rejected
        assert!(client.package_metadata_url("../evil").is_err());
        assert!(client.package_metadata_url("@scope/../../passwd").is_err());
    }

    #[test]
    fn test_scoped_registry_routing() {
        let mut config = RegistryClientConfig::default();
        config.scoped_registries.insert(
            "@myorg".to_string(),
            Url::parse("https://npm.pkg.github.com/").unwrap(),
        );

        let client = RegistryClient::with_config(config).unwrap();

        // Scoped package routes to github pkg registry
        let scoped_url = client.package_metadata_url("@myorg/widget").unwrap();
        assert_eq!(
            scoped_url.as_str(),
            "https://npm.pkg.github.com/@myorg%2fwidget"
        );

        // Unscoped package routes to default registry
        let unscoped_url = client.package_metadata_url("express").unwrap();
        assert_eq!(
            unscoped_url.as_str(),
            "https://registry.npmjs.org/express"
        );
    }

    #[test]
    fn test_is_trusted_target_security_rules() {
        let mut config = RegistryClientConfig::default();
        config.trusted_hosts.insert("registry.npmjs.org".to_string());
        config.trusted_hosts.insert("custom.corp.net".to_string());
        let client = RegistryClient::with_config(config).unwrap();

        let initial_https = Url::parse("https://registry.npmjs.org/is-odd").unwrap();
        let same_origin = Url::parse("https://registry.npmjs.org/tarball.tgz").unwrap();
        let diff_path = Url::parse("https://registry.npmjs.org/other").unwrap();

        // Same origin: trusted
        assert!(client.is_trusted_target(&initial_https, &same_origin));
        assert!(client.is_trusted_target(&initial_https, &diff_path));

        // Downgrade HTTPS -> HTTP on same host: MUST NOT BE TRUSTED
        let downgrade_http = Url::parse("http://registry.npmjs.org/tarball.tgz").unwrap();
        assert!(!client.is_trusted_target(&initial_https, &downgrade_http));

        // Cross-host to another trusted host with HTTPS: trusted
        let other_trusted = Url::parse("https://custom.corp.net/tarball.tgz").unwrap();
        assert!(client.is_trusted_target(&initial_https, &other_trusted));

        // Cross-host to another trusted host with HTTP (not loopback): NOT trusted
        let other_trusted_http = Url::parse("http://custom.corp.net/tarball.tgz").unwrap();
        assert!(!client.is_trusted_target(&initial_https, &other_trusted_http));

        // Cross-host to untrusted CDN: MUST NOT BE TRUSTED
        let untrusted_cdn = Url::parse("https://cdn.attacker.com/tarball.tgz").unwrap();
        assert!(!client.is_trusted_target(&initial_https, &untrusted_cdn));

        // Disallowed schemes: MUST NOT BE TRUSTED
        let file_url = Url::parse("file:///etc/passwd").unwrap();
        assert!(!client.is_trusted_target(&initial_https, &file_url));

        // Initial untrusted URL: MUST NOT send credentials
        let initial_untrusted = Url::parse("https://evil.com/tarball.tgz").unwrap();
        assert!(!client.is_trusted_target(&initial_untrusted, &initial_untrusted));
    }
}
