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
    pub fn new(current_dir: &Path, explicit_registry: Option<&str>) -> Result<Self> {
        let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
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
        let silent_override = cli_overrides.as_ref().map(|o| {
            o.get("loglevel").map(|v| v == "silent").unwrap_or(false)
                || o.get("silent").map(|v| v == "true" || v == "1").unwrap_or(false)
        }).unwrap_or(false);
        let silent = silent_override
            || config.get("loglevel") == Some("silent")
            || config.get_bool("silent").unwrap_or(false);

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .tcp_nodelay(true);

        if config.get_bool("strict-ssl").is_some_and(|b| !b)
            || config.get_bool("strict_ssl").is_some_and(|b| !b)
        {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(cafile) = config.get("cafile") {
            if let Ok(cert_bytes) = std::fs::read(cafile) {
                if let Ok(cert) = reqwest::Certificate::from_pem(&cert_bytes) {
                    builder = builder.add_root_certificate(cert);
                }
            }
        }

        if let Some(https_proxy) = config.get("https-proxy").or_else(|| config.get("https_proxy")) {
            if let Ok(proxy) = reqwest::Proxy::https(https_proxy) {
                builder = builder.proxy(proxy);
            }
        }
        if let Some(http_proxy) = config.get("http-proxy").or_else(|| config.get("http_proxy")) {
            if let Ok(proxy) = reqwest::Proxy::http(http_proxy) {
                builder = builder.proxy(proxy);
            }
        }
        if let Some(proxy) = config.get("proxy") {
            if let Ok(p) = reqwest::Proxy::all(proxy) {
                builder = builder.proxy(p);
            }
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
            if let Some(pass) = npmrc.settings.get(&pass_key).or_else(|| npmrc.settings.get(&pass_key2)) {
                let decoded_pass = match data_encoding::BASE64.decode(pass.trim().as_bytes()) {
                    Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| pass.trim().to_string()),
                    Err(_) => pass.trim().to_string(),
                };
                let encoded = data_encoding::BASE64.encode(format!("{user}:{decoded_pass}").as_bytes());
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
    use crate::http_errors::{auth_error_block, e404_block, general_message, package_name_from_url};
    if let Some(block) = auth_error_block(method, target_url.as_str(), status, www_authenticate, body) {
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

pub(crate) fn parse_json_response(
    body: &str,
    target_url: &Url,
) -> Result<serde_json::Value> {
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
