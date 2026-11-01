use crate::error::RegistryError;
use crate::metadata::AbbreviatedPackageMetadata;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::{Client, Method, Response, StatusCode};
use std::collections::HashSet;
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

/// Registry client configuration.
#[derive(Debug, Clone)]
pub struct RegistryClientConfig {
    pub default_registry: Url,
    pub user_agent: String,
    pub auth_token: Option<String>,
    pub trusted_hosts: HashSet<String>,
    pub timeout: Duration,
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
            trusted_hosts,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Client for interacting with npm package registries.
#[derive(Clone)]
pub struct RegistryClient {
    client: Client,
    config: RegistryClientConfig,
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

        // We disable reqwest's automatic redirect following so that we can enforce
        // the strict security rule: NEVER forward auth headers across redirects to untrusted hostnames.
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .build()?;

        Ok(Self { client, config })
    }

    /// Access the client configuration.
    pub fn config(&self) -> &RegistryClientConfig {
        &self.config
    }

    /// Format the metadata URL for a package name.
    pub fn package_metadata_url(&self, package_name: &str) -> Result<Url, RegistryError> {
        self.package_metadata_url_on(&self.config.default_registry, package_name)
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
            if let Some(port) = current_url.port() {
                if self.config.trusted_hosts.contains(&format!("{host_lower}:{port}")) {
                    return true;
                }
            }
        }

        false
    }

    /// Execute a request following redirects manually and enforcing the security rule:
    /// Never forward auth headers across redirects to untrusted hostnames.
    pub async fn execute_with_security_policy(
        &self,
        method: Method,
        initial_url: Url,
        accept_header: Option<&str>,
    ) -> Result<Response, RegistryError> {
        let mut current_url = initial_url.clone();

        for _redirect_count in 0..MAX_REDIRECTS {
            let mut req = self.client.request(method.clone(), current_url.clone());

            if let Some(accept) = accept_header {
                req = req.header(ACCEPT, accept);
            }

            // Security check: only send auth headers if the target is trusted (same origin or in trusted_hosts)
            let should_send_auth = self.is_trusted_target(&initial_url, &current_url);

            if should_send_auth {
                if let Some(token) = &self.config.auth_token {
                    req = req.header(AUTHORIZATION, format!("Bearer {token}"));
                }
            } else {
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

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            let msg = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Unauthorized {
                url: url.to_string(),
                status: status.as_u16(),
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

    /// Download a tarball stream from URL, safely following redirects.
    pub async fn download_tarball(&self, tarball_url: &str) -> Result<Response, RegistryError> {
        let url = Url::parse(tarball_url)?;
        let resp = self
            .execute_with_security_policy(Method::GET, url.clone(), None)
            .await?;

        let status = resp.status();
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
}
