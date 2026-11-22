use anyhow::Result;
use reqwest::Url;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegistryAuth {
    Bearer(String),
    Basic(String),
}

pub(crate) struct CommandClient {
    pub client: reqwest::Client,
    pub registry_url: Url,
    pub auth: Option<RegistryAuth>,
    pub silent: bool,
}

impl CommandClient {
    pub async fn send_json(
        &self,
        current_dir: &Path,
        method: reqwest::Method,
        url: Url,
        body: Option<serde_json::Value>,
        otp: Option<String>,
    ) -> Result<serde_json::Value> {
        let text = self
            .send_text(current_dir, method, url.clone(), body, otp)
            .await?;
        if text.trim().is_empty() {
            Ok(serde_json::Value::Null)
        } else {
            parse_json_response(&text, &url)
        }
    }

    /// One registry request wrapped in npm's otplease retry; returns the raw body.
    pub async fn send_text(
        &self,
        current_dir: &Path,
        method: reqwest::Method,
        url: Url,
        body: Option<serde_json::Value>,
        mut otp: Option<String>,
    ) -> Result<String> {
        for attempt in 0..2 {
            let mut request = self.request(method.clone(), url.clone(), otp.as_deref());
            if let Some(body) = &body {
                request = request.json(body);
            }
            let response = request.send().await?;
            let status = response.status();
            let www = response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let text = response.text().await?;
            if status.is_success() {
                return Ok(text);
            }
            let err =
                format_http_error_with_auth(method.as_str(), &url, status, www.as_deref(), &text);
            if attempt == 0 {
                if let Some(code) = crate::http_errors::retry_otp(current_dir, &err).await? {
                    otp = Some(code);
                    continue;
                }
            }
            return Err(err);
        }
        unreachable!()
    }

    pub fn new(current_dir: &Path, explicit_registry: Option<&str>) -> Result<Self> {
        let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
        Self::with_config(config, explicit_registry)
    }

    pub fn with_config(
        config: rnpm_config::Config,
        explicit_registry: Option<&str>,
    ) -> Result<Self> {
        let registry_url = if let Some(reg_str) = explicit_registry {
            Url::parse(reg_str).map_err(|e| {
                anyhow::anyhow!(
                    "npm error code EINVALIDURL\nnpm error Invalid registry URL '{reg_str}': {e}"
                )
            })?
        } else {
            config.npmrc.registry.clone()
        };

        let auth = resolve_auth(&config.npmrc, &registry_url);

        let cli_overrides = rnpm_config::get_process_cli_overrides();
        let silent_override = cli_overrides
            .as_ref()
            .map(|o| {
                o.get("loglevel").map(|v| v == "silent").unwrap_or(false)
                    || o.get("silent")
                        .map(|v| v == "true" || v == "1")
                        .unwrap_or(false)
            })
            .unwrap_or(false);
        let silent = silent_override
            || config.get("loglevel") == Some("silent")
            || config.get_bool("silent").unwrap_or(false);

        let timeout = parse_fetch_timeout(&config);
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .tcp_nodelay(true);

        if let Some(connect_timeout_ms) = config
            .get("connect-timeout")
            .or_else(|| config.get("connect_timeout"))
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            builder = builder.connect_timeout(std::time::Duration::from_millis(connect_timeout_ms));
        }

        if config.get_bool("strict-ssl").is_some_and(|b| !b)
            || config.get_bool("strict_ssl").is_some_and(|b| !b)
        {
            builder = builder.danger_accept_invalid_certs(true);
        }

        // Proxies follow @npmcli/agent, not reqwest's system lookup: the
        // configured proxy, else HTTPS_PROXY for every URL (HTTP_PROXY and
        // PROXY only for http), bypassed only by the `noproxy` setting.
        builder = builder.no_proxy();

        let https_proxy = config
            .get("https-proxy")
            .or_else(|| config.get("https_proxy"));
        let http_proxy = config
            .get("http-proxy")
            .or_else(|| config.get("http_proxy"));
        let general_proxy = config.get("proxy");

        let no_proxy = config
            .get("noproxy")
            .or_else(|| config.get("no-proxy"))
            .or_else(|| config.get("no_proxy"))
            .filter(|v| !v.is_empty())
            .map(|s| s.to_string())
            .or_else(|| {
                std::env::vars()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("no_proxy"))
                    .last()
                    .map(|(_, v)| v)
                    .filter(|v| !v.is_empty())
            });

        let (env_https_proxy, env_http_proxy) =
            if https_proxy.is_none() && http_proxy.is_none() && general_proxy.is_none() {
                let env = |name: &str| {
                    std::env::vars()
                        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                        .last()
                        .map(|(_, v)| v)
                        .filter(|v| !v.is_empty())
                };
                let https = env("https_proxy");
                let http = https.clone().or_else(|| env("http_proxy")).or_else(|| env("proxy"));
                (https, http)
            } else {
                (None, None)
            };

        if env_https_proxy.is_some() || env_http_proxy.is_some() {
            let no_proxy_rules = parse_no_proxy(no_proxy.as_deref().unwrap_or_default());
            let https = env_https_proxy.and_then(|u| reqwest::Url::parse(&u).ok());
            let http = env_http_proxy.and_then(|u| reqwest::Url::parse(&u).ok());
            builder = builder.proxy(reqwest::Proxy::custom(move |url| {
                let proxy = if url.scheme() == "https" { https.as_ref() } else { http.as_ref() }?;
                let host = url.host_str()?;
                let bypass = matches_no_proxy(host, &no_proxy_rules);
                (!bypass).then(|| proxy.clone())
            }));
        }

        if let Some(https_proxy_val) = https_proxy {
            let mut proxy = reqwest::Proxy::https(https_proxy_val).map_err(|err| {
                anyhow::anyhow!("Invalid https_proxy '{https_proxy_val}': {err}")
            })?;
            if let Some(no_proxy_str) = &no_proxy {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy_str));
            }
            builder = builder.proxy(proxy);
        }

        if let Some(http_proxy_val) = http_proxy {
            let mut proxy = reqwest::Proxy::http(http_proxy_val).map_err(|err| {
                anyhow::anyhow!("Invalid http_proxy '{http_proxy_val}': {err}")
            })?;
            if let Some(no_proxy_str) = &no_proxy {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy_str));
            }
            builder = builder.proxy(proxy);
        }

        if let Some(general_proxy_val) = general_proxy {
            if https_proxy.is_none() && http_proxy.is_none() {
                let mut proxy = reqwest::Proxy::all(general_proxy_val).map_err(|err| {
                    anyhow::anyhow!("Invalid proxy '{general_proxy_val}': {err}")
                })?;
                if let Some(no_proxy_str) = &no_proxy {
                    proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy_str));
                }
                builder = builder.proxy(proxy);
            } else if http_proxy.is_none() {
                let mut proxy = reqwest::Proxy::http(general_proxy_val).map_err(|err| {
                    anyhow::anyhow!("Invalid proxy '{general_proxy_val}': {err}")
                })?;
                if let Some(no_proxy_str) = &no_proxy {
                    proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy_str));
                }
                builder = builder.proxy(proxy);
            } else if https_proxy.is_none() {
                let mut proxy = reqwest::Proxy::https(general_proxy_val).map_err(|err| {
                    anyhow::anyhow!("Invalid proxy '{general_proxy_val}': {err}")
                })?;
                if let Some(no_proxy_str) = &no_proxy {
                    proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy_str));
                }
                builder = builder.proxy(proxy);
            }
        }

        if let Some(cafile_path) = config.get("cafile").or_else(|| config.get("ca_file")) {
            let certs = load_certs_from_cafile(Path::new(cafile_path))?;
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        if let Some(ca_content_or_path) = config.get("ca") {
            let certs = load_certs_from_ca(ca_content_or_path)?;
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        if let (Some(cert_str), Some(key_str)) = (config.get("cert"), config.get("key")) {
            let identity = load_client_identity(cert_str, key_str)?;
            builder = builder.identity(identity);
        }

        let client = builder.build()?;
        Ok(Self {
            client,
            registry_url,
            auth,
            silent,
        })
    }

    pub fn request(
        &self,
        method: reqwest::Method,
        target_url: Url,
        otp: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut req = self.client.request(method, target_url);
        if let Some(auth) = &self.auth {
            match auth {
                RegistryAuth::Bearer(token) => {
                    req = req.header("authorization", format!("Bearer {token}"));
                }
                RegistryAuth::Basic(basic) => {
                    req = req.header("authorization", format!("Basic {basic}"));
                }
            }
        }
        if let Some(otp_val) = otp {
            req = req.header("npm-otp", otp_val);
        }
        req
    }
}

pub(crate) fn registry_error(method: &str, error: rnpm_registry::RegistryError) -> anyhow::Error {
    use rnpm_registry::RegistryError as E;
    match error {
        E::AuthChallenge {
            url,
            www_authenticate,
            body,
        } => Url::parse(&url)
            .map(|url| {
                format_http_error_with_auth(
                    method,
                    &url,
                    reqwest::StatusCode::UNAUTHORIZED,
                    Some(&www_authenticate),
                    &body,
                )
            })
            .unwrap_or_else(anyhow::Error::from),
        E::Unauthorized {
            url,
            status,
            message,
        }
        | E::Forbidden {
            url,
            status,
            message,
        }
        | E::PublishConflict {
            url,
            status,
            message,
        } => Url::parse(&url)
            .map(|url| {
                format_http_error(
                    method,
                    &url,
                    reqwest::StatusCode::from_u16(status)
                        .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
                    &message,
                )
            })
            .unwrap_or_else(anyhow::Error::from),
        other => anyhow::Error::from(other),
    }
}

pub(crate) async fn with_registry_otp<T>(
    current_dir: &Path,
    method: &str,
    otp: Option<String>,
    mut operation: impl AsyncFnMut(
        Option<String>,
    ) -> std::result::Result<T, rnpm_registry::RegistryError>,
) -> Result<T> {
    match operation(otp).await {
        Ok(value) => Ok(value),
        Err(error) => {
            let error = registry_error(method, error);
            match crate::http_errors::retry_otp(current_dir, &error).await? {
                Some(code) => operation(Some(code))
                    .await
                    .map_err(|e| registry_error(method, e)),
                None => Err(error),
            }
        }
    }
}

pub(crate) fn resolve_auth(npmrc: &rnpm_config::Npmrc, registry_url: &Url) -> Option<RegistryAuth> {
    let host = registry_url.host_str()?;
    let host_lower = host.to_ascii_lowercase();
    let port_part = registry_url
        .port()
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    let path = registry_url.path();

    let mut reg_key = format!("//{host_lower}{port_part}{path}");
    while reg_key.len() > "//".len() {
        // 1. Check for Bearer token: _authToken
        let token_key = format!("{reg_key}:_authToken");
        if let Some(tok) = npmrc.settings.get(&token_key) {
            let trimmed = tok.trim();
            if !trimmed.is_empty() {
                return Some(RegistryAuth::Bearer(trimmed.to_string()));
            }
        }

        // 2. Check for Basic token: _auth
        let auth_key = format!("{reg_key}:_auth");
        if let Some(auth_val) = npmrc.settings.get(&auth_key) {
            let trimmed = auth_val.trim();
            if !trimmed.is_empty() {
                return Some(RegistryAuth::Basic(trimmed.to_string()));
            }
        }

        // 3. Check for username + password / _password (base64 decoded before composing basic auth)
        let user_key = format!("{reg_key}:username");
        let pass_key = format!("{reg_key}:_password");
        let pass_key2 = format!("{reg_key}:password");
        if let Some(user) = npmrc.settings.get(&user_key) {
            if let Some(pass) = npmrc
                .settings
                .get(&pass_key)
                .or_else(|| npmrc.settings.get(&pass_key2))
            {
                let decoded_pass = match data_encoding::BASE64.decode(pass.trim().as_bytes()) {
                    Ok(bytes) => {
                        String::from_utf8(bytes).unwrap_or_else(|_| pass.trim().to_string())
                    }
                    Err(_) => pass.trim().to_string(),
                };
                let encoded =
                    data_encoding::BASE64.encode(format!("{user}:{decoded_pass}").as_bytes());
                return Some(RegistryAuth::Basic(encoded));
            }
        }

        // Walk outward by removing either what's after the last slash OR the trailing slash itself
        if reg_key.ends_with('/') {
            reg_key.pop();
        } else if let Some(last_slash) = reg_key.rfind('/') {
            reg_key.truncate(last_slash + 1);
        } else {
            break;
        }
    }

    None
}

pub(crate) fn format_http_error(
    method: &str,
    target_url: &Url,
    status: reqwest::StatusCode,
    body: &str,
) -> anyhow::Error {
    format_http_error_with_auth(method, target_url, status, None, body)
}

/// Renders a failed registry response the way npm does, including the
/// `www-authenticate` challenge npm-registry-fetch inspects on a 401.
pub(crate) fn format_http_error_with_auth(
    method: &str,
    target_url: &Url,
    status: reqwest::StatusCode,
    www_authenticate: Option<&str>,
    body: &str,
) -> anyhow::Error {
    use crate::http_errors::{
        auth_error_block, e404_block, general_message, package_name_from_url,
    };
    if let Some(block) =
        auth_error_block(method, target_url.as_str(), status, www_authenticate, body)
    {
        return anyhow::anyhow!(block);
    }
    let message = general_message(method, target_url.as_str(), status, body);
    match status.as_u16() {
        404 => anyhow::anyhow!(e404_block(&message, package_name_from_url(target_url).as_deref())),
        403 => anyhow::anyhow!(
            "npm error code E403\nnpm error 403 {message}\nnpm error 403 In most cases, you or one of your dependencies are requesting a package version that is forbidden by your security policy, or on a server you do not have access to."
        ),
        code => anyhow::anyhow!("npm error code E{code}\nnpm error {message}"),
    }
}

pub(crate) fn parse_json_response(body: &str, target_url: &Url) -> Result<serde_json::Value> {
    serde_json::from_str(body).map_err(|e| {
        anyhow::anyhow!(
            "npm error code FETCH_ERROR\nnpm error errno FETCH_ERROR\nnpm error invalid json response body at {target_url} reason: {e}"
        )
    })
}

pub(crate) fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", b));
            }
        }
    }
    encoded
}

pub(crate) const DEFAULT_FETCH_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(300_000);

pub(crate) fn parse_fetch_timeout(config: &rnpm_config::Config) -> std::time::Duration {
    let timeout_ms = config
        .get("fetch-timeout")
        .or_else(|| config.get("fetch_timeout"))
        .or_else(|| config.get("timeout"))
        .and_then(|val_str| val_str.trim().parse::<u64>().ok());
    timeout_ms
        .map(std::time::Duration::from_millis)
        .unwrap_or(DEFAULT_FETCH_TIMEOUT)
}

pub(crate) fn parse_no_proxy(no_proxy_str: &str) -> Vec<Vec<String>> {
    no_proxy_str
        .split(',')
        .map(|entry| {
            let mut item = entry.trim();
            if let Some((host_part, port_part)) = item.rsplit_once(':') {
                if port_part.chars().all(|c| c.is_ascii_digit()) {
                    item = host_part;
                }
            }
            item.split('.')
                .map(|s| s.trim_matches('*'))
                .filter(|s| !s.is_empty())
                .rev()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|segments| !segments.is_empty())
        .collect()
}

pub(crate) fn matches_no_proxy(host: &str, parsed_rules: &[Vec<String>]) -> bool {
    let trimmed_host = host.trim_end_matches('.');
    let host_segments: Vec<&str> = trimmed_host.split('.').rev().collect();
    parsed_rules.iter().any(|entry| {
        entry
            .iter()
            .enumerate()
            .all(|(i, s)| host_segments.get(i) == Some(&s.as_str()))
    })
}

pub(crate) fn load_certs_from_cafile(path: &Path) -> Result<Vec<reqwest::Certificate>> {
    let pem_bytes = std::fs::read(path)
        .map_err(|err| anyhow::anyhow!("Failed to read cafile at '{}': {err}", path.display()))?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem_bytes).unwrap_or_default();
    if certs.is_empty() {
        anyhow::bail!("No PEM certificates found in cafile '{}'", path.display());
    }
    Ok(certs)
}

pub(crate) fn load_certs_from_ca(ca_content_or_path: &str) -> Result<Vec<reqwest::Certificate>> {
    let path = Path::new(ca_content_or_path);
    let pem_bytes = if path.exists() {
        std::fs::read(path).map_err(|err| {
            anyhow::anyhow!("Failed to read CA path '{ca_content_or_path}': {err}")
        })?
    } else {
        ca_content_or_path.as_bytes().to_vec()
    };
    let certs = reqwest::Certificate::from_pem_bundle(&pem_bytes).unwrap_or_default();
    if certs.is_empty() {
        anyhow::bail!("No PEM certificates found in ca configuration");
    }
    Ok(certs)
}

pub(crate) fn load_client_identity(cert_str: &str, key_str: &str) -> Result<reqwest::Identity> {
    let cert_content = if Path::new(cert_str).exists() {
        std::fs::read_to_string(cert_str)
            .map_err(|err| anyhow::anyhow!("Failed to read cert file '{cert_str}': {err}"))?
    } else {
        cert_str.to_string()
    };

    let key_content = if Path::new(key_str).exists() {
        std::fs::read_to_string(key_str)
            .map_err(|err| anyhow::anyhow!("Failed to read key file '{key_str}': {err}"))?
    } else {
        key_str.to_string()
    };

    let combined_pem = format!("{}\n{}", cert_content.trim(), key_content.trim());
    reqwest::Identity::from_pem(combined_pem.as_bytes()).map_err(|err| {
        anyhow::anyhow!("Failed to parse client certificate and key into Identity: {err}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const TEST_CERT_PEM: &str = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIDGzCCAgOgAwIBAgIQE1R21Xl7NZpPyRqRv1yU8zANBgkqhkiG9w0BAQsFADAV\n",
        "MRMwEQYDVQQDDAp0ZXN0LmxvY2FsMB4XDTI2MTEyMjA5MTQwOVoXDTI3MTEyMjA5\n",
        "MzQwOVowFTETMBEGA1UEAwwKdGVzdC5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQAD\n",
        "ggEPADCCAQoCggEBANt+jRb46/O+JnmilwKBjhRSZCUHDTX0sXisTWyA37h9Fr5a\n",
        "i5EJ3+apI3if3Mu0nceV8tiBBosHxs1hJYnHEQPHJc3OISQlzDFvvdPcmMqKd2wD\n",
        "QaNWZwHojUMcxphObT8EKRgTknzQQ258tptmsWs4jjV6KurU3if11MJfZbbJ1D4s\n",
        "/2GRzrg+O1zYolHiULYfbsFbzkvv5pyCZXNV+k29mgzPCDwD5XKlExh1wAmmD2Lw\n",
        "KHjw+4c+PhjOUsUYSWCoK8aNP4pCZR920iPVSgL1yHD/kF81v4f7URr63xdGIOez\n",
        "r1fhx//CX66vfS64qlfS7iEkAyXiRKpImd8tm80CAwEAAaNnMGUwDgYDVR0PAQH/\n",
        "BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAM\n",
        "ggp0ZXN0LmxvY2FsMB0GA1UdDgQWBBSFKqgnDrGCA0xDqAgG05QiGuM+8jANBgkq\n",
        "hkiG9w0BAQsFAAOCAQEAuvJ+bGDnXR8n4GE+3V6B4LAQHD+zR9rZ8vAG+kRaUzZn\n",
        "TTlACW+8NB+5X0ioOdscaN0bdxOwHBAKBKamt1WgHxno3LK923nBsUU+GvSFggPx\n",
        "SeepnKnxYZUjQ0LtHpyTAmECqc0b8pignjwp8Iz5nOgys/rL2V+/SqKSMl7/QuVi\n",
        "05BuPRK1LKQrusb2WuhWUXfAmJJTpMPnJHhjZtoaBQ0MSogqJqFpoPdynaxg/XLZ\n",
        "1V0aJFRac8CzvB6jvCQUPIVRj7/7e0qWw77q+NVeAsjDoIOZHO6LrLYC5LaVncCR\n",
        "vjxgdLRN+rXZa8SApKBq6QISeBpTabfD4WJCsuceDQ==\n",
        "-----END CERTIFICATE-----\n"
    );

    #[test]
    fn test_client_helper_noproxy_parsing_and_matching() {
        let rules = parse_no_proxy(
            "localhost, .corp.internal, 127.0.0.1, *.npmjs.org, proxy.example.com:8080",
        );

        // Exact match
        assert!(matches_no_proxy("localhost", &rules));
        assert!(matches_no_proxy("127.0.0.1", &rules));

        // Subdomain match via leading dot
        assert!(matches_no_proxy("api.corp.internal", &rules));
        assert!(matches_no_proxy("corp.internal", &rules));

        // Wildcard match
        assert!(matches_no_proxy("pkg.npmjs.org", &rules));
        assert!(matches_no_proxy("npmjs.org", &rules));

        // Port stripped rule
        assert!(matches_no_proxy("proxy.example.com", &rules));

        // Trailing dot on host
        assert!(matches_no_proxy("localhost.", &rules));

        // Non-matches
        assert!(!matches_no_proxy("notcorp.internal", &rules));
        assert!(!matches_no_proxy("example.org", &rules));
        assert!(!matches_no_proxy("google.com", &rules));

        // Empty rules
        let empty_rules = parse_no_proxy("");
        assert!(!matches_no_proxy("localhost", &empty_rules));
    }

    #[test]
    fn test_client_helper_fetch_timeout_parsing() {
        // Default 300,000 ms (5 min)
        let cfg_default = rnpm_config::Config::default();
        assert_eq!(parse_fetch_timeout(&cfg_default), DEFAULT_FETCH_TIMEOUT);

        // fetch-timeout
        let mut cfg1 = rnpm_config::Config::default();
        cfg1.npmrc
            .settings
            .insert("fetch-timeout".into(), "60000".into());
        assert_eq!(
            parse_fetch_timeout(&cfg1),
            std::time::Duration::from_millis(60_000)
        );

        // fetch_timeout
        let mut cfg2 = rnpm_config::Config::default();
        cfg2.npmrc
            .settings
            .insert("fetch_timeout".into(), "45000".into());
        assert_eq!(
            parse_fetch_timeout(&cfg2),
            std::time::Duration::from_millis(45_000)
        );

        // timeout
        let mut cfg3 = rnpm_config::Config::default();
        cfg3.npmrc
            .settings
            .insert("timeout".into(), "15000".into());
        assert_eq!(
            parse_fetch_timeout(&cfg3),
            std::time::Duration::from_millis(15_000)
        );

        // fetch-timeout takes precedence over timeout
        let mut cfg4 = rnpm_config::Config::default();
        cfg4.npmrc
            .settings
            .insert("fetch-timeout".into(), "20000".into());
        cfg4.npmrc
            .settings
            .insert("timeout".into(), "10000".into());
        assert_eq!(
            parse_fetch_timeout(&cfg4),
            std::time::Duration::from_millis(20_000)
        );

        // Non-numeric string falls back to default
        let mut cfg5 = rnpm_config::Config::default();
        cfg5.npmrc
            .settings
            .insert("fetch-timeout".into(), "invalid".into());
        assert_eq!(parse_fetch_timeout(&cfg5), DEFAULT_FETCH_TIMEOUT);
    }

    #[test]
    fn test_client_helper_cafile_bundle_loading_valid_multi_cert() {
        let mut temp_cafile = NamedTempFile::new().unwrap();
        let multi_cert = format!("{TEST_CERT_PEM}\n{TEST_CERT_PEM}");
        temp_cafile.write_all(multi_cert.as_bytes()).unwrap();

        let certs = load_certs_from_cafile(temp_cafile.path()).unwrap();
        assert_eq!(certs.len(), 2);

        let mut config = rnpm_config::Config::default();
        config.npmrc.settings.insert(
            "cafile".into(),
            temp_cafile.path().to_str().unwrap().into(),
        );
        let client = CommandClient::with_config(config, None);
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_helper_cafile_bundle_loading_missing_and_invalid() {
        // Missing file
        let missing_path = Path::new("nonexistent_cafile_never_exists.pem");
        let err = load_certs_from_cafile(missing_path).unwrap_err();
        assert!(err.to_string().contains("Failed to read cafile at"));

        let mut config_missing = rnpm_config::Config::default();
        config_missing.npmrc.settings.insert(
            "cafile".into(),
            missing_path.to_str().unwrap().into(),
        );
        assert!(CommandClient::with_config(config_missing, None).is_err());

        // Invalid PEM content
        let mut temp_invalid = NamedTempFile::new().unwrap();
        temp_invalid.write_all(b"NOT A VALID CERTIFICATE").unwrap();

        let err = load_certs_from_cafile(temp_invalid.path()).unwrap_err();
        assert!(err
            .to_string()
            .contains("No PEM certificates found in cafile"));

        let mut config_invalid = rnpm_config::Config::default();
        config_invalid.npmrc.settings.insert(
            "cafile".into(),
            temp_invalid.path().to_str().unwrap().into(),
        );
        assert!(CommandClient::with_config(config_invalid, None).is_err());
    }

    #[test]
    fn test_client_helper_ca_inline_and_file_loading() {
        // Valid inline single cert
        let certs = load_certs_from_ca(TEST_CERT_PEM).unwrap();
        assert_eq!(certs.len(), 1);

        // Valid inline multi cert
        let multi_cert = format!("{TEST_CERT_PEM}\n{TEST_CERT_PEM}");
        let certs = load_certs_from_ca(&multi_cert).unwrap();
        assert_eq!(certs.len(), 2);

        // Valid file path in ca
        let mut temp_ca = NamedTempFile::new().unwrap();
        temp_ca.write_all(TEST_CERT_PEM.as_bytes()).unwrap();
        let certs = load_certs_from_ca(temp_ca.path().to_str().unwrap()).unwrap();
        assert_eq!(certs.len(), 1);

        // Invalid inline ca content
        let err = load_certs_from_ca("not a valid pem").unwrap_err();
        assert!(err
            .to_string()
            .contains("No PEM certificates found in ca configuration"));

        let mut config_invalid = rnpm_config::Config::default();
        config_invalid
            .npmrc
            .settings
            .insert("ca".into(), "invalid pem content".into());
        assert!(CommandClient::with_config(config_invalid, None).is_err());

        // Valid inline ca in CommandClient
        let mut config_valid = rnpm_config::Config::default();
        config_valid
            .npmrc
            .settings
            .insert("ca".into(), TEST_CERT_PEM.into());
        assert!(CommandClient::with_config(config_valid, None).is_ok());
    }

    #[test]
    fn test_client_helper_mtls_identity_and_proxy_validation() {
        // Invalid cert + key PEM content
        let err = load_client_identity("not-a-cert", "not-a-key").unwrap_err();
        assert!(err
            .to_string()
            .contains("Failed to parse client certificate and key into Identity"));

        let mut config_mtls = rnpm_config::Config::default();
        config_mtls
            .npmrc
            .settings
            .insert("cert".into(), "invalid-cert".into());
        config_mtls
            .npmrc
            .settings
            .insert("key".into(), "invalid-key".into());
        assert!(CommandClient::with_config(config_mtls, None).is_err());

        // Invalid proxy URL rejected
        let mut config_proxy = rnpm_config::Config::default();
        config_proxy
            .npmrc
            .settings
            .insert("proxy".into(), "invalid url with spaces".into());
        assert!(CommandClient::with_config(config_proxy, None).is_err());

        // Valid proxy with noproxy
        let mut config_good_proxy = rnpm_config::Config::default();
        config_good_proxy
            .npmrc
            .settings
            .insert("proxy".into(), "http://proxy.local:8080".into());
        config_good_proxy
            .npmrc
            .settings
            .insert("noproxy".into(), "localhost,127.0.0.1".into());
        assert!(CommandClient::with_config(config_good_proxy, None).is_ok());
    }
}
