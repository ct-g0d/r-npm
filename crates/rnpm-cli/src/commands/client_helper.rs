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
    pub auth: RegistryAuth,
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

        let auth = resolve_auth(&config.npmrc, &registry_url).ok_or_else(|| {
            anyhow::anyhow!(
                "npm error code ENEEDAUTH\nnpm error This command requires you to be logged in to {registry_url}\nnpm error You need to authorize this machine using `npm adduser` or `npm login`"
            )
        })?;

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
        match &self.auth {
            RegistryAuth::Bearer(token) => {
                req = req.header("authorization", format!("Bearer {token}"));
            }
            RegistryAuth::Basic(basic) => {
                req = req.header("authorization", format!("Basic {basic}"));
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
    let normalized_path = if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    };

    let prefixes = [
        format!("//{host_lower}{port_part}{normalized_path}"),
        format!("//{host_lower}{port_part}{path}"),
        format!("//{host_lower}{port_part}/"),
        format!("//{host_lower}/"),
    ];

    // 1. Check for Bearer token: _authToken
    for prefix in &prefixes {
        let key = format!("{prefix}:_authToken");
        if let Some(tok) = npmrc.settings.get(&key) {
            if !tok.trim().is_empty() {
                return Some(RegistryAuth::Bearer(tok.trim().to_string()));
            }
        }
    }
    if let Some(tok) = npmrc.get_auth_token(registry_url) {
        if !tok.trim().is_empty() {
            return Some(RegistryAuth::Bearer(tok.trim().to_string()));
        }
    }
    if let Some(tok) = npmrc.settings.get("_authToken") {
        if !tok.trim().is_empty() {
            return Some(RegistryAuth::Bearer(tok.trim().to_string()));
        }
    }

    // 2. Check for Basic token: _auth
    for prefix in &prefixes {
        let key = format!("{prefix}:_auth");
        if let Some(auth_val) = npmrc.settings.get(&key) {
            if !auth_val.trim().is_empty() {
                return Some(RegistryAuth::Basic(auth_val.trim().to_string()));
            }
        }
    }
    if let Some(auth_val) = npmrc.settings.get("_auth") {
        if !auth_val.trim().is_empty() {
            return Some(RegistryAuth::Basic(auth_val.trim().to_string()));
        }
    }

    // 3. Check for username + password / _password
    for prefix in &prefixes {
        let user_key = format!("{prefix}:username");
        let pass_key = format!("{prefix}:_password");
        let pass_key2 = format!("{prefix}:password");
        if let Some(user) = npmrc.settings.get(&user_key) {
            if let Some(pass) = npmrc.settings.get(&pass_key).or_else(|| npmrc.settings.get(&pass_key2)) {
                let encoded = data_encoding::BASE64.encode(format!("{user}:{pass}").as_bytes());
                return Some(RegistryAuth::Basic(encoded));
            }
        }
    }
    if let Some(user) = npmrc.settings.get("username") {
        if let Some(pass) = npmrc.settings.get("_password").or_else(|| npmrc.settings.get("password")) {
            let encoded = data_encoding::BASE64.encode(format!("{user}:{pass}").as_bytes());
            return Some(RegistryAuth::Basic(encoded));
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
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    let msg = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("error"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            if body.trim().is_empty() {
                reason.to_ascii_lowercase()
            } else {
                body.trim().to_string()
            }
        });

    if code == 403 {
        anyhow::anyhow!(
            "npm error code E403\nnpm error 403 403 Forbidden - {method} {target_url} - {msg}\nnpm error 403 In most cases, you or one of your dependencies are requesting a package version that is forbidden by your security policy, or on a server you do not have access to."
        )
    } else {
        anyhow::anyhow!(
            "npm error code E{code}\nnpm error {code} {reason} - {method} {target_url} - {msg}"
        )
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
