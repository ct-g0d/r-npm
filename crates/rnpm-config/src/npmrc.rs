use crate::error::ConfigError;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use url::Url;

pub const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org/";

#[derive(Clone, PartialEq, Eq)]
pub struct Npmrc {
    /// Raw key-value configuration pairs
    pub settings: BTreeMap<String, String>,
    /// Default registry URL
    pub registry: Url,
    /// Scoped registries: e.g. "@myorg" -> "https://npm.pkg.github.com/"
    pub scoped_registries: BTreeMap<String, Url>,
    /// Auth tokens keyed by normalized URI prefix, e.g. "//registry.npmjs.org/" -> "npm_secret123"
    pub auth_tokens: BTreeMap<String, String>,
}

impl std::fmt::Debug for Npmrc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrubbed_tokens: BTreeMap<_, _> = self
            .auth_tokens
            .iter()
            .map(|(k, v)| (k.clone(), mask_credential(v)))
            .collect();

        let scrubbed_settings: BTreeMap<_, _> = self
            .settings
            .iter()
            .map(|(k, v)| {
                if is_sensitive_credential_key(k) {
                    (k.clone(), mask_credential(v))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();

        f.debug_struct("Npmrc")
            .field("settings", &scrubbed_settings)
            .field("registry", &self.registry)
            .field("scoped_registries", &self.scoped_registries)
            .field("auth_tokens", &scrubbed_tokens)
            .finish()
    }
}

impl Default for Npmrc {
    fn default() -> Self {
        Self {
            settings: BTreeMap::new(),
            registry: Url::parse(DEFAULT_REGISTRY).expect("default registry URL is valid"),
            scoped_registries: BTreeMap::new(),
            auth_tokens: BTreeMap::new(),
        }
    }
}

impl Npmrc {
    /// URI-scoped Basic credentials (base64 `user:password`), keyed like
    /// `auth_tokens`: from `//host/:_auth`, or `//host/:username` with
    /// base64 `//host/:_password`.
    pub fn basic_auths(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (key, value) in &self.settings {
            if let Some(prefix) = key.strip_suffix(":_auth") {
                if prefix.starts_with("//") || prefix.contains("://") {
                    let v = value.trim();
                    if !v.is_empty() {
                        out.insert(normalize_uri_prefix(prefix), v.to_string());
                    }
                }
            } else if let Some(prefix) = key.strip_suffix(":username") {
                let password = self.settings.get(&format!("{prefix}:_password")).map(|p| {
                    data_encoding::BASE64
                        .decode(p.trim().as_bytes())
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                        .unwrap_or_else(|| p.trim().to_string())
                });
                if let Some(password) = password {
                    let encoded = data_encoding::BASE64
                        .encode(format!("{}:{password}", value.trim()).as_bytes());
                    out.entry(normalize_uri_prefix(prefix)).or_insert(encoded);
                }
            }
        }
        out
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Parse .npmrc file content with environment variable substitution.
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        Self::parse_with_env(content, |var| env::var(var).ok())
    }

    /// Parse .npmrc file content with a custom environment lookup closure.
    pub fn parse_with_env<F>(content: &str, env_lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut npmrc = Self::new();

        for line in content.lines() {
            let trimmed = line.trim();
            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            // Skip section headers: e.g. [section]
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                continue;
            }

            // Split key and value on '='
            let (raw_key, raw_val) = if let Some(idx) = trimmed.find('=') {
                (&trimmed[..idx], Some(&trimmed[idx + 1..]))
            } else {
                (trimmed, None)
            };

            let decoded_key = decode_ini_field(raw_key);
            if decoded_key.is_empty() {
                if raw_val.is_some() {
                    return Err(ConfigError::InvalidLine(format!("Empty key in: '{trimmed}'")));
                }
                continue;
            }

            let decoded_val = match raw_val {
                Some(v) => decode_ini_field(v),
                None => "true".to_string(),
            };

            // Interpolate environment variables
            let key = interpolate_env(&decoded_key, &env_lookup);
            let value = interpolate_env(&decoded_val, &env_lookup);

            npmrc.set(&key, &value)?;
        }

        Ok(npmrc)
    }

    /// Read and parse an .npmrc file from disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::new());
        }

        let content = fs::read_to_string(path).map_err(|err| ConfigError::Io {
            path: path.to_path_buf(),
            source: err,
        })?;

        Self::parse(&content)
    }

    /// Set a key-value setting and update parsed registry/auth structures.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        let key_trimmed = key.trim();
        let value_trimmed = value.trim();

        if key_trimmed.is_empty() {
            return Err(ConfigError::InvalidLine(
                "Configuration key cannot be empty".to_string(),
            ));
        }

        // Prevent newline and null injection in configuration keys and values
        if key_trimmed.contains('\n')
            || key_trimmed.contains('\r')
            || key_trimmed.contains('\0')
            || value_trimmed.contains('\n')
            || value_trimmed.contains('\r')
            || value_trimmed.contains('\0')
        {
            return Err(ConfigError::InvalidLine(format!(
                "Configuration line contains forbidden control character (newline or null): '{key_trimmed}'"
            )));
        }

        // 1. Check if key is the default registry
        if key_trimmed == "registry" {
            if let Ok(mut reg_url) = Url::parse(value_trimmed) {
                ensure_trailing_slash(&mut reg_url);
                self.registry = reg_url;
            }
            self.settings
                .insert(key_trimmed.to_string(), value_trimmed.to_string());
            return Ok(());
        }

        // 2. Check if key is a scoped registry: e.g. "@myorg:registry", "@myorg/registry", or "myorg:registry"
        if let Some(scope) = crate::parse_scoped_registry_key(key_trimmed) {
            if let Ok(mut reg_url) = Url::parse(value_trimmed) {
                ensure_trailing_slash(&mut reg_url);
                self.scoped_registries
                    .insert(scope.to_ascii_lowercase(), reg_url);
            }
            self.settings
                .insert(key_trimmed.to_string(), value_trimmed.to_string());
            return Ok(());
        }

        // 3. Check if key is URI-scoped auth: e.g. "//registry.npmjs.org/:_authToken" or "https://registry.npmjs.org/:_authToken"
        if let Some(uri_prefix) = key_trimmed.strip_suffix(":_authToken") {
            let norm_prefix = normalize_uri_prefix(uri_prefix);
            if value_trimmed
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(ConfigError::InvalidLine(
                    "Auth token contains illegal whitespace or control characters".to_string(),
                ));
            }
            self.auth_tokens
                .insert(norm_prefix, value_trimmed.to_string());
            self.settings
                .insert(key_trimmed.to_string(), value_trimmed.to_string());
            return Ok(());
        }

        // Array key notation (e.g. "min-release-age-exclude[]" or any "key[]")
        if let Some(base_key) = key_trimmed.strip_suffix("[]") {
            let base_key = base_key.trim();
            if let Some(existing) = self.settings.get_mut(base_key) {
                if !existing.is_empty() {
                    existing.push(',');
                }
                existing.push_str(value_trimmed);
            } else {
                self.settings
                    .insert(base_key.to_string(), value_trimmed.to_string());
            }
            if let Some(existing) = self.settings.get_mut(key_trimmed) {
                if !existing.is_empty() {
                    existing.push(',');
                }
                existing.push_str(value_trimmed);
            } else {
                self.settings
                    .insert(key_trimmed.to_string(), value_trimmed.to_string());
            }
            return Ok(());
        }

        // Multiple min-release-age-exclude lines without brackets append as comma-separated
        if key_trimmed == "min-release-age-exclude" || key_trimmed == "min_release_age_exclude" {
            let alt_key = if key_trimmed == "min-release-age-exclude" {
                "min_release_age_exclude"
            } else {
                "min-release-age-exclude"
            };
            if let Some(existing) = self.settings.get_mut(key_trimmed) {
                if !existing.is_empty() {
                    existing.push(',');
                }
                existing.push_str(value_trimmed);
                return Ok(());
            } else if let Some(existing) = self.settings.get_mut(alt_key) {
                if !existing.is_empty() {
                    existing.push(',');
                }
                existing.push_str(value_trimmed);
                return Ok(());
            }
        }

        // Fallback: general setting
        self.settings
            .insert(key_trimmed.to_string(), value_trimmed.to_string());
        Ok(())
    }

    /// Merge another Npmrc configuration into this one. The other config's settings take precedence.
    pub fn merge(&mut self, other: Npmrc) {
        if other.settings.contains_key("registry") {
            self.registry = other.registry;
        }
        for (scope, url) in other.scoped_registries {
            self.scoped_registries.insert(scope, url);
        }
        for (uri, token) in other.auth_tokens {
            self.auth_tokens.insert(uri, token);
        }
        for (k, v) in other.settings {
            self.settings.insert(k, v);
        }
    }

    /// Determine the registry URL to use for a given package name.
    /// Scoped package definitions in .npmrc take strict precedence over the default registry.
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
            if let Some(scoped_url) = self.scoped_registries.get(&scope_lower) {
                return scoped_url;
            }
        }
        &self.registry
    }

    /// Check if a package name matches a configured scoped registry.
    pub fn has_scoped_registry(&self, package_name: &str) -> bool {
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
            return self.scoped_registries.contains_key(&scope_lower);
        }
        false
    }

    /// Retrieve the auth token for a package by looking up its assigned registry (scoped or default).
    pub fn get_auth_token_for_package(&self, package_name: &str) -> Option<&str> {
        let registry = self.registry_for_package(package_name);
        self.get_auth_token(registry)
    }

    /// Compute the package metadata URL using scoped registry precedence and safe package encoding.
    pub fn package_metadata_url(&self, package_name: &str) -> Result<Url, ConfigError> {
        validate_package_name(package_name).map_err(|e| ConfigError::InvalidLine(e.to_string()))?;
        let registry = self.registry_for_package(package_name);
        let encoded = encode_package_name(package_name);
        let base_str = registry.as_str().trim_end_matches('/');
        let url_str = format!("{base_str}/{encoded}");
        Url::parse(&url_str).map_err(ConfigError::InvalidUrl)
    }

    /// Retrieve the auth token for a registry URL if configured.
    /// Performs longest-prefix matching for scoped registry paths down to root,
    /// falling back to the global `_authToken` setting if present.
    pub fn get_auth_token(&self, registry_url: &Url) -> Option<&str> {
        let host = registry_url.host_str()?;
        let port_part = if let Some(port) = registry_url.port() {
            format!(":{port}")
        } else {
            String::new()
        };

        let path = registry_url.path();
        let host_lower = host.to_ascii_lowercase();
        let prefixes = generate_path_prefixes(path);

        for prefix in &prefixes {
            if !port_part.is_empty() {
                let cand1 = format!("//{host_lower}{port_part}{prefix}");
                if let Some(token) = self.auth_tokens.get(&cand1) {
                    return Some(token.as_str());
                }
            }
            let cand2 = format!("//{host_lower}{prefix}");
            if let Some(token) = self.auth_tokens.get(&cand2) {
                return Some(token.as_str());
            }
        }

        // Global _authToken setting fallback
        if let Some(token) = self
            .settings
            .get("_authToken")
            .or_else(|| self.settings.get("_authtoken"))
        {
            return Some(token.as_str());
        }

        None
    }

    /// Retrieve the Basic auth credential for a registry URL if configured.
    /// Supports exact and scoped path prefix matching from `basic_auths()`,
    /// falling back to global `_auth` or `username` + `_password` / `password`.
    pub fn get_basic_auth(&self, registry_url: &Url) -> Option<String> {
        let host = registry_url.host_str()?;
        let port_part = if let Some(port) = registry_url.port() {
            format!(":{port}")
        } else {
            String::new()
        };

        let path = registry_url.path();
        let host_lower = host.to_ascii_lowercase();

        let basic_map = self.basic_auths();
        let prefixes = generate_path_prefixes(path);

        for prefix in &prefixes {
            if !port_part.is_empty() {
                let cand1 = format!("//{host_lower}{port_part}{prefix}");
                if let Some(auth) = basic_map.get(&cand1) {
                    return Some(auth.clone());
                }
            }
            let cand2 = format!("//{host_lower}{prefix}");
            if let Some(auth) = basic_map.get(&cand2) {
                return Some(auth.clone());
            }
        }

        // Global _auth fallback
        if let Some(auth) = self.settings.get("_auth") {
            let v = auth.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }

        // Global username + _password / password fallback
        if let Some(user) = self.settings.get("username") {
            let pass_opt = self
                .settings
                .get("_password")
                .or_else(|| self.settings.get("password"));
            if let Some(p) = pass_opt {
                let password = data_encoding::BASE64
                    .decode(p.trim().as_bytes())
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| p.trim().to_string());
                let encoded = data_encoding::BASE64
                    .encode(format!("{}:{password}", user.trim()).as_bytes());
                return Some(encoded);
            }
        }

        None
    }

    /// Retrieve a URI-scoped configuration value (e.g. `:certfile`, `:keyfile`, `:ca`, `:cafile`, `:proxy`)
    /// performing longest-prefix matching on registry URL paths down to host root.
    pub fn get_scoped_setting(&self, registry_url: &Url, suffix_key: &str) -> Option<&str> {
        let host = registry_url.host_str()?;
        let port_part = if let Some(port) = registry_url.port() {
            format!(":{port}")
        } else {
            String::new()
        };

        let path = registry_url.path();
        let host_lower = host.to_ascii_lowercase();
        let prefixes = generate_path_prefixes(path);

        for prefix in &prefixes {
            if !port_part.is_empty() {
                let cand1 = format!("//{host_lower}{port_part}{prefix}:{suffix_key}");
                if let Some(val) = self.settings.get(&cand1) {
                    return Some(val.as_str());
                }
            }
            let cand2 = format!("//{host_lower}{prefix}:{suffix_key}");
            if let Some(val) = self.settings.get(&cand2) {
                return Some(val.as_str());
            }
            if prefix.ends_with('/') {
                let no_slash = &prefix[..prefix.len() - 1];
                let cand3 = format!("//{host_lower}{no_slash}:{suffix_key}");
                if let Some(val) = self.settings.get(&cand3) {
                    return Some(val.as_str());
                }
            }
        }
        None
    }

    /// Retrieve the SSL certificate file configured for a registry URL,
    /// falling back to global `certfile` or `cert` setting.
    pub fn get_cert(&self, registry_url: &Url) -> Option<&str> {
        self.get_scoped_setting(registry_url, "certfile")
            .or_else(|| self.get_scoped_setting(registry_url, "cert"))
            .or_else(|| self.settings.get("certfile").map(|s| s.as_str()))
            .or_else(|| self.settings.get("cert").map(|s| s.as_str()))
            .filter(|s| !s.is_empty() && *s != "null")
    }

    /// Retrieve the SSL private key file configured for a registry URL,
    /// falling back to global `keyfile` or `key` setting.
    pub fn get_key(&self, registry_url: &Url) -> Option<&str> {
        self.get_scoped_setting(registry_url, "keyfile")
            .or_else(|| self.get_scoped_setting(registry_url, "key"))
            .or_else(|| self.settings.get("keyfile").map(|s| s.as_str()))
            .or_else(|| self.settings.get("key").map(|s| s.as_str()))
            .filter(|s| !s.is_empty() && *s != "null")
    }

    /// Retrieve the CA certificate or CA file configured for a registry URL,
    /// falling back to global `cafile` or `ca` setting.
    pub fn get_ca(&self, registry_url: &Url) -> Option<&str> {
        self.get_scoped_setting(registry_url, "ca")
            .or_else(|| self.get_scoped_setting(registry_url, "cafile"))
            .or_else(|| self.settings.get("ca").map(|s| s.as_str()))
            .or_else(|| self.settings.get("cafile").map(|s| s.as_str()))
            .filter(|s| !s.is_empty() && *s != "null")
    }

    /// Retrieve a proxy configured for a registry URL via URI-scoped setting (`:proxy` or `:https-proxy`),
    /// falling back to global settings.
    pub fn get_proxy_for_registry(&self, registry_url: &Url) -> Option<&str> {
        self.get_scoped_setting(registry_url, "https-proxy")
            .or_else(|| self.get_scoped_setting(registry_url, "https_proxy"))
            .or_else(|| self.get_scoped_setting(registry_url, "proxy"))
            .or_else(|| self.get_scoped_setting(registry_url, "http-proxy"))
            .or_else(|| self.get_scoped_setting(registry_url, "http_proxy"))
            .or_else(|| self.settings.get("https-proxy").map(|s| s.as_str()))
            .or_else(|| self.settings.get("https_proxy").map(|s| s.as_str()))
            .or_else(|| self.settings.get("proxy").map(|s| s.as_str()))
            .or_else(|| self.settings.get("http-proxy").map(|s| s.as_str()))
            .or_else(|| self.settings.get("http_proxy").map(|s| s.as_str()))
            .filter(|s| !s.is_empty() && *s != "null")
    }

    /// Returns a copy of the settings map with all sensitive tokens safely redacted.
    pub fn scrubbed_settings(&self) -> BTreeMap<String, String> {
        self.settings
            .iter()
            .map(|(k, v)| {
                if is_sensitive_credential_key(k) {
                    (k.clone(), "[REDACTED]".to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect()
    }

    /// Formats the configuration into an .npmrc-compatible string with all credentials safely redacted.
    pub fn format_scrubbed(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("registry={}\n", self.registry));
        for (scope, url) in &self.scoped_registries {
            out.push_str(&format!("{scope}:registry={url}\n"));
        }
        for prefix in self.auth_tokens.keys() {
            out.push_str(&format!("{prefix}:_authToken=[REDACTED]\n"));
        }
        for (k, v) in &self.settings {
            if k == "registry"
                || k.ends_with(":registry")
                || k.ends_with("/registry")
                || k.ends_with(":_authToken")
            {
                continue;
            }
            if is_sensitive_credential_key(k) {
                out.push_str(&format!("{k}=[REDACTED]\n"));
            } else {
                out.push_str(&format!("{k}={v}\n"));
            }
        }
        out
    }
}

/// Decodes an ini key or value string according to npm / ini rules:
/// - Strips quotes (double quotes with JSON unescaping, single quotes stripped).
/// - If unquoted, strips inline comments starting with unescaped ';' or '#'.
/// - Unescapes '\;', '\#', and '\\'.
pub fn decode_ini_field(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Double-quoted string: try JSON unescaping; fallback to stripping quotes
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        if let Ok(unquoted) = serde_json::from_str::<String>(trimmed) {
            return unquoted;
        }
        return trimmed[1..trimmed.len() - 1].to_string();
    }

    // Single-quoted string: strip quotes
    if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        return trimmed[1..trimmed.len() - 1].to_string();
    }

    // Unquoted: walk the string to find the first unescaped ';' or '#' (inline comment)
    let mut unesc = String::with_capacity(trimmed.len());
    let mut esc = false;

    for c in trimmed.chars() {
        if esc {
            if c == ';' || c == '#' || c == '\\' {
                unesc.push(c);
            } else {
                unesc.push('\\');
                unesc.push(c);
            }
            esc = false;
        } else if c == ';' || c == '#' {
            break;
        } else if c == '\\' {
            esc = true;
        } else {
            unesc.push(c);
        }
    }
    if esc {
        unesc.push('\\');
    }
    unesc.trim().to_string()
}

fn generate_path_prefixes(path: &str) -> Vec<String> {
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

fn ensure_trailing_slash(url: &mut Url) {
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
}

fn normalize_uri_prefix(prefix: &str) -> String {
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
/// backslashes, empty names, Unicode spoofing, and control characters.
pub fn validate_package_name(name: &str) -> Result<(), ConfigError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::InvalidLine(
            "Package name cannot be empty".to_string(),
        ));
    }

    if trimmed.contains('\0')
        || trimmed.contains('\\')
        || trimmed.contains('\r')
        || trimmed.contains('\n')
        || trimmed.chars().any(|c| c.is_control())
    {
        return Err(ConfigError::InvalidLine(format!(
            "Package name contains illegal control or escape characters: '{trimmed}'"
        )));
    }

    // Reject non-ASCII characters (e.g. Cyrillic homoglyphs, zero-width spaces, fullwidth characters, RTL overrides)
    if !trimmed.is_ascii() {
        return Err(ConfigError::InvalidLine(format!(
            "Package name contains forbidden non-ASCII or spoofed characters: '{trimmed}'"
        )));
    }

    // Check for encoded path traversal sequences (%2e, %2f, %5c)
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("%2e%2e")
        || lower.contains("..%2f")
        || lower.contains("%2f..")
        || lower.contains("%5c")
    {
        return Err(ConfigError::InvalidLine(format!(
            "Package name contains forbidden path traversal component: '{name}'"
        )));
    }

    let unverified = trimmed.strip_prefix('@').unwrap_or(trimmed);
    let segments: Vec<&str> = unverified.split('/').collect();

    // Check for empty segments (e.g. leading slash, trailing slash, double slash, empty scope)
    if trimmed.starts_with('/')
        || trimmed.ends_with('/')
        || unverified.starts_with('/')
        || unverified.ends_with('/')
        || segments.iter().any(|s| s.is_empty())
    {
        return Err(ConfigError::InvalidLine(format!(
            "Package name contains invalid slash formatting: '{name}'"
        )));
    }

    // A scoped package must have exactly one slash (@scope/pkg); unscoped package must have 0 slashes
    if trimmed.starts_with('@') {
        if segments.len() != 2 {
            return Err(ConfigError::InvalidLine(format!(
                "Scoped package must contain exactly one slash: '{name}'"
            )));
        }
    } else if segments.len() != 1 {
        return Err(ConfigError::InvalidLine(format!(
            "Unscoped package cannot contain slashes: '{name}'"
        )));
    }

    for segment in segments {
        if segment == "."
            || segment == ".."
            || segment.starts_with("..")
            || segment.ends_with("..")
            || segment.eq_ignore_ascii_case("%2e")
            || segment.eq_ignore_ascii_case("%2e%2e")
        {
            return Err(ConfigError::InvalidLine(format!(
                "Package name contains forbidden path traversal component: '{name}'"
            )));
        }
    }

    Ok(())
}

/// Interpolates `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `$VAR`, and supports `\${VAR}` / `$$` escaping.
/// Safe against multi-byte UTF-8 boundaries, nested braces, and empty string evaluations.
pub fn interpolate_env<F>(input: &str, lookup: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    let mut result = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        if ch == '\\' {
            if let Some(&(_, next_ch)) = chars.peek() {
                if next_ch == '$' {
                    chars.next();
                    result.push('$');
                    continue;
                }
            }
            result.push('\\');
            continue;
        }

        if ch == '$' {
            if let Some(&(_, next_ch)) = chars.peek() {
                if next_ch == '{' {
                    chars.next(); // consume '{'
                    let rest = &input[idx + 2..];

                    // Balance braces to find matching '}'
                    let mut depth = 1usize;
                    let mut close_rel = None;
                    for (rel_idx, c) in rest.char_indices() {
                        if c == '{' {
                            depth += 1;
                        } else if c == '}' {
                            depth -= 1;
                            if depth == 0 {
                                close_rel = Some(rel_idx);
                                break;
                            }
                        }
                    }

                    if let Some(close_rel) = close_rel {
                        let expr = &rest[..close_rel];
                        // Advance iterator past '}'
                        while let Some((c_idx, _)) = chars.peek() {
                            if *c_idx > idx + 2 + close_rel {
                                break;
                            }
                            chars.next();
                        }

                        // Split var_name and raw_default at top level (depth 0 within expr)
                        let mut split_pos = None;
                        let mut is_colon_dash = false;
                        let mut inner_depth = 0usize;
                        let expr_chars: Vec<(usize, char)> = expr.char_indices().collect();
                        for i in 0..expr_chars.len() {
                            let (c_idx, c) = expr_chars[i];
                            if c == '{' {
                                inner_depth += 1;
                            } else if c == '}' {
                                inner_depth = inner_depth.saturating_sub(1);
                            } else if inner_depth == 0 {
                                if c == ':'
                                    && i + 1 < expr_chars.len()
                                    && expr_chars[i + 1].1 == '-'
                                {
                                    split_pos = Some(c_idx);
                                    is_colon_dash = true;
                                    break;
                                } else if c == '-' && split_pos.is_none() {
                                    split_pos = Some(c_idx);
                                    is_colon_dash = false;
                                    break;
                                }
                            }
                        }

                        let (var_name, default_val, use_default_if_empty) = match split_pos {
                            Some(pos) => {
                                let v = &expr[..pos];
                                let d = if is_colon_dash {
                                    &expr[pos + 2..]
                                } else {
                                    &expr[pos + 1..]
                                };
                                (v, Some(d), is_colon_dash)
                            }
                            None => (expr, None, false),
                        };

                        let var_name = var_name.trim();
                        let is_optional = var_name.ends_with('?');
                        let clean_var_name = if is_optional {
                            &var_name[..var_name.len() - 1]
                        } else {
                            var_name
                        };
                        let is_valid_name = !clean_var_name.is_empty()
                            && clean_var_name
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_');

                        if is_valid_name {
                            let looked_up = lookup(clean_var_name);
                            let val = match looked_up {
                                Some(v) => {
                                    if use_default_if_empty && v.is_empty() {
                                        default_val
                                            .map(|d| interpolate_env(d, lookup))
                                            .unwrap_or(v)
                                    } else {
                                        v
                                    }
                                }
                                None => default_val
                                    .map(|d| interpolate_env(d, lookup))
                                    .unwrap_or_default(),
                            };
                            result.push_str(&val);
                        } else if default_val.is_some() && var_name.is_empty() {
                            result.push_str(&interpolate_env(default_val.unwrap(), lookup));
                        } else {
                            // Invalid syntax or empty without default, preserve literal
                            result.push_str("${");
                            result.push_str(expr);
                            result.push('}');
                        }
                        continue;
                    } else {
                        // Unclosed '${'
                        result.push('$');
                        result.push('{');
                        continue;
                    }
                } else if next_ch.is_ascii_alphabetic() || next_ch == '_' {
                    let start_var = idx + 1;
                    chars.next();
                    let mut end_var = start_var + next_ch.len_utf8();
                    while let Some(&(c_idx, c)) = chars.peek() {
                        if c.is_ascii_alphanumeric() || c == '_' {
                            end_var = c_idx + c.len_utf8();
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    let var_name = &input[start_var..end_var];
                    let val = lookup(var_name).unwrap_or_default();
                    result.push_str(&val);
                    continue;
                } else if next_ch == '$' {
                    chars.next();
                    result.push('$');
                    continue;
                }
            }
        }

        result.push(ch);
    }

    result
}

/// Redact sensitive tokens and passwords from configuration strings, logs, or error traces.
pub fn scrub_credentials(text: &str) -> String {
    let mut result = text.to_string();

    // 1. Redact Bearer tokens
    result = replace_bearer(&result);

    // 2. Redact Basic authorization tokens
    result = replace_basic_auth(&result);

    // 3. Redact credentials embedded in URLs
    result = replace_url_credentials(&result);

    // 4. Redact npm / ghp tokens
    result = replace_npm_tokens(&result);

    // 5. Redact :_authToken=<val> and other key-value credentials
    for key in &[
        "_authtoken",
        "_authToken",
        "authtoken",
        "password",
        "_password",
        "secret",
        "token",
        "_auth",
        "npm_token",
        "ci_auth_key",
        "auth_key",
    ] {
        result = replace_kv_pairs(&result, key);
    }

    result
}

/// Checks if a key name corresponds to a sensitive credential.
pub fn is_sensitive_credential_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    if lower.contains("password")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("auth_key")
        || lower.contains("auth_token")
        || lower.contains("_authtoken")
        || lower.contains("_auth")
        || lower.contains("apikey")
        || lower.contains("api_key")
    {
        return true;
    }
    if lower.contains("auth")
        && !lower.contains("author")
        && !lower.contains("auth-type")
        && !lower.contains("auth_type")
    {
        return true;
    }
    false
}

/// Masks a credential for display (e.g. "npm_1234567890abcdef" -> "npm_***cdef").
pub fn mask_credential(token: &str) -> String {
    let char_count = token.chars().count();
    if char_count == 0 {
        return String::new();
    }
    if char_count <= 6 {
        return "[REDACTED]".to_string();
    }
    let prefix = if token.starts_with("npm_") {
        "npm_***"
    } else if token.starts_with("ghp_") {
        "ghp_***"
    } else {
        "***"
    };
    let skip_count = char_count.saturating_sub(4);
    let tail_start = token.char_indices().nth(skip_count).map(|(i, _)| i).unwrap_or(0);
    let tail = &token[tail_start..];
    format!("{prefix}{tail}")
}

fn replace_bearer(text: &str) -> String {
    let mut out = String::new();
    let lower = text.to_ascii_lowercase();
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices("bearer ") {
        if idx < last_idx {
            continue;
        }
        out.push_str(&text[last_idx..idx + 7]);
        let remainder = &text[idx + 7..];
        let end_token = remainder
            .find(|c: char| {
                c.is_whitespace() || c == '"' || c == '\'' || c == '\n' || c == '\r' || c == ';'
            })
            .unwrap_or(remainder.len());
        out.push_str("[REDACTED]");
        last_idx = idx + 7 + end_token;
    }
    out.push_str(&text[last_idx..]);
    out
}

fn replace_basic_auth(text: &str) -> String {
    let mut out = String::new();
    let lower = text.to_ascii_lowercase();
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices("basic ") {
        if idx < last_idx {
            continue;
        }
        out.push_str(&text[last_idx..idx + 6]);
        let remainder = &text[idx + 6..];
        let end_token = remainder
            .find(|c: char| {
                c.is_whitespace() || c == '"' || c == '\'' || c == '\n' || c == '\r' || c == ';'
            })
            .unwrap_or(remainder.len());
        out.push_str("[REDACTED]");
        last_idx = idx + 6 + end_token;
    }
    out.push_str(&text[last_idx..]);
    out
}

fn replace_url_credentials(text: &str) -> String {
    let mut out = String::new();
    let mut last_idx = 0;
    let mut curr_idx = 0;

    while curr_idx < text.len() {
        let next_http = text[curr_idx..].find("http://").map(|i| curr_idx + i);
        let next_https = text[curr_idx..].find("https://").map(|i| curr_idx + i);

        let next_match = match (next_http, next_https) {
            (Some(i1), Some(i2)) => {
                if i1 < i2 {
                    Some((i1, "http://"))
                } else {
                    Some((i2, "https://"))
                }
            }
            (Some(i1), None) => Some((i1, "http://")),
            (None, Some(i2)) => Some((i2, "https://")),
            (None, None) => None,
        };

        let Some((abs_scheme_idx, scheme)) = next_match else {
            break;
        };

        let after_scheme_idx = abs_scheme_idx + scheme.len();
        let after_scheme = &text[after_scheme_idx..];
        let end_auth = after_scheme.find(|c: char| {
            c == '/'
                || c == '?'
                || c == '#'
                || c.is_whitespace()
                || c == '"'
                || c == '\''
                || c == '\\'
                || c == '\n'
                || c == '\r'
        });
        let auth_slice = match end_auth {
            Some(len) => &after_scheme[..len],
            None => after_scheme,
        };

        if let Some(at_idx) = auth_slice.find('@') {
            let userinfo = &auth_slice[..at_idx];
            out.push_str(&text[last_idx..after_scheme_idx]);
            if let Some((user, _pass)) = userinfo.split_once(':') {
                out.push_str(user);
                out.push_str(":[REDACTED]");
            } else {
                out.push_str("[REDACTED]");
            }
            out.push('@');
            last_idx = after_scheme_idx + at_idx + 1;
            curr_idx = last_idx;
        } else {
            curr_idx = after_scheme_idx;
        }
    }
    out.push_str(&text[last_idx..]);
    out
}

fn replace_npm_tokens(text: &str) -> String {
    let mut out = String::new();
    let mut last_idx = 0;

    for (idx, _) in text.match_indices("npm_") {
        if idx < last_idx {
            continue;
        }
        let remainder = &text[idx + 4..];
        let end_token = remainder
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .unwrap_or(remainder.len());
        if end_token >= 16 {
            out.push_str(&text[last_idx..idx]);
            out.push_str("npm_[REDACTED]");
            last_idx = idx + 4 + end_token;
        }
    }
    out.push_str(&text[last_idx..]);
    out
}

fn replace_kv_pairs(text: &str, key_name: &str) -> String {
    let mut out = String::new();
    let lower = text.to_ascii_lowercase();
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices(key_name) {
        if idx < last_idx {
            continue;
        }
        let after_key = &text[idx + key_name.len()..];
        let mut chars = after_key.char_indices().peekable();
        while let Some(&(_, c)) = chars.peek() {
            if c == ' ' || c == '\t' {
                chars.next();
            } else {
                break;
            }
        }
        let sep_match = match chars.peek() {
            Some(&(sep_idx, '=')) | Some(&(sep_idx, ':')) => Some(sep_idx),
            _ => None,
        };
        if sep_match.is_some() {
            chars.next(); // consume '=' or ':'
            while let Some(&(_, c)) = chars.peek() {
                if c == ' ' || c == '\t' {
                    chars.next();
                } else {
                    break;
                }
            }
            let val_start = chars.peek().map(|&(i, _)| i).unwrap_or(after_key.len());
            let val_slice = &after_key[val_start..];
            if val_slice.starts_with('"') || val_slice.starts_with('\'') {
                let quote = val_slice.chars().next().unwrap();
                let inner = &val_slice[1..];
                let mut closing_offset = None;
                let mut escaped = false;
                for (ci, ch) in inner.char_indices() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if ch == '\\' {
                        escaped = true;
                    } else if ch == quote {
                        closing_offset = Some(ci);
                        break;
                    } else if ch == '\n' || ch == '\r' {
                        break;
                    }
                }
                let (val_len, replacement) = match closing_offset {
                    Some(end_q) => (1 + end_q + 1, format!("{quote}[REDACTED]{quote}")),
                    None => {
                        let end_line = val_slice
                            .find(['\n', '\r'])
                            .unwrap_or(val_slice.len());
                        (end_line, format!("{quote}[REDACTED]{quote}"))
                    }
                };
                out.push_str(&text[last_idx..idx + key_name.len() + val_start]);
                out.push_str(&replacement);
                last_idx = idx + key_name.len() + val_start + val_len;
            } else {
                let end_token = val_slice
                    .find(|c: char| {
                        c.is_whitespace()
                            || c == ';'
                            || c == '&'
                            || c == '\n'
                            || c == '\r'
                    })
                    .unwrap_or(val_slice.len());

                out.push_str(&text[last_idx..idx + key_name.len() + val_start]);
                out.push_str("[REDACTED]");
                last_idx = idx + key_name.len() + val_start + end_token;
            }
        }
    }
    out.push_str(&text[last_idx..]);
    out
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Represents an individual rule for proxy bypass matching (NO_PROXY).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoProxyRule {
    /// Wildcard `*`: matches every target
    All,
    /// Domain/hostname suffix, e.g. `.example.com`, `example.com`, `localhost`
    Domain {
        suffix: String,
        port: Option<u16>,
    },
    /// Exact IP address with optional port
    ExactIp {
        ip: IpAddr,
        port: Option<u16>,
    },
    /// IPv4 CIDR network subnet
    Ipv4Cidr {
        network: u32,
        mask: u32,
        port: Option<u16>,
    },
    /// IPv6 CIDR network subnet
    Ipv6Cidr {
        network: u128,
        mask: u128,
        port: Option<u16>,
    },
}

impl NoProxyRule {
    pub fn parse(entry: &str) -> Option<Self> {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return None;
        }

        if trimmed == "*" {
            return Some(Self::All);
        }

        // Check for CIDR: e.g. 10.0.0.0/8 or 10.0.0.0/8:8080 or fd00::/8
        if let Some((cidr_part, maybe_port)) = trimmed.split_once(':') {
            if cidr_part.contains('/') && maybe_port.chars().all(|c| c.is_ascii_digit()) {
                let port = maybe_port.parse::<u16>().ok();
                if let Some(rule) = Self::parse_cidr(cidr_part, port) {
                    return Some(rule);
                }
            }
        }
        if trimmed.contains('/') {
            if let Some(rule) = Self::parse_cidr(trimmed, None) {
                return Some(rule);
            }
        }

        // Check for IPv6 bracketed with port: [::1]:8080 or [::1]
        if let Some(stripped) = trimmed.strip_prefix('[') {
            if let Some((ip_str, rest)) = stripped.split_once(']') {
                let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
                let clean_ip = ip_str.trim();
                if let Ok(ip) = clean_ip.parse::<IpAddr>() {
                    return Some(Self::ExactIp { ip, port });
                }
            }
        }

        // Check for host:port
        let (host_part, port) = if let Some((h, p)) = trimmed.rsplit_once(':') {
            if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') {
                (h, p.parse::<u16>().ok())
            } else {
                (trimmed, None)
            }
        } else {
            (trimmed, None)
        };

        // Check if host_part is an exact IP
        let clean_host = host_part.trim().trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = clean_host.parse::<IpAddr>() {
            return Some(Self::ExactIp { ip, port });
        }

        // Domain / hostname rule
        let norm_host = host_part.to_ascii_lowercase();
        let norm_suffix = norm_host
            .trim_start_matches('*')
            .trim_end_matches('.')
            .to_string();

        if norm_suffix.is_empty() {
            return Some(Self::All);
        }

        Some(Self::Domain {
            suffix: norm_suffix,
            port,
        })
    }

    fn parse_cidr(cidr: &str, port: Option<u16>) -> Option<Self> {
        let (ip_str, prefix_str) = cidr.split_once('/')?;
        let clean_ip_str = ip_str.trim().trim_start_matches('[').trim_end_matches(']');
        let prefix_len = prefix_str.parse::<u32>().ok()?;

        if let Ok(ipv4) = clean_ip_str.parse::<Ipv4Addr>() {
            if prefix_len > 32 {
                return None;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            let network = u32::from(ipv4) & mask;
            return Some(Self::Ipv4Cidr {
                network,
                mask,
                port,
            });
        }

        if let Ok(ipv6) = clean_ip_str.parse::<Ipv6Addr>() {
            if prefix_len > 128 {
                return None;
            }
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            let network = u128::from(ipv6) & mask;
            return Some(Self::Ipv6Cidr {
                network,
                mask,
                port,
            });
        }

        None
    }

    pub fn matches(&self, host: &str, port: Option<u16>) -> bool {
        let clean_host = host.trim().trim_start_matches('[').trim_end_matches(']');
        match self {
            Self::All => true,
            Self::ExactIp { ip, port: rule_port } => {
                if rule_port.is_some() && *rule_port != port {
                    return false;
                }
                if let Ok(target_ip) = clean_host.parse::<IpAddr>() {
                    target_ip == *ip
                } else {
                    false
                }
            }
            Self::Ipv4Cidr { network, mask, port: rule_port } => {
                if rule_port.is_some() && *rule_port != port {
                    return false;
                }
                if let Ok(target_ip) = clean_host.parse::<Ipv4Addr>() {
                    (u32::from(target_ip) & mask) == *network
                } else {
                    false
                }
            }
            Self::Ipv6Cidr { network, mask, port: rule_port } => {
                if rule_port.is_some() && *rule_port != port {
                    return false;
                }
                if let Ok(target_ip) = clean_host.parse::<Ipv6Addr>() {
                    (u128::from(target_ip) & mask) == *network
                } else {
                    false
                }
            }
            Self::Domain { suffix, port: rule_port } => {
                if rule_port.is_some() && *rule_port != port {
                    return false;
                }
                let host_domain = clean_host.trim_end_matches('.').to_ascii_lowercase();
                let clean_suffix = suffix.trim_start_matches('.').to_ascii_lowercase();

                if host_domain == clean_suffix {
                    return true;
                }
                if host_domain.ends_with(&format!(".{clean_suffix}")) {
                    return true;
                }
                false
            }
        }
    }
}

/// Matcher that evaluates target URLs or host/port pairs against configured NO_PROXY rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoProxyMatcher {
    rules: Vec<NoProxyRule>,
}

impl NoProxyMatcher {
    pub fn parse(no_proxy_str: &str) -> Self {
        let mut rules = Vec::new();
        for item in no_proxy_str.split(&[',', ' ', ';'][..]) {
            if let Some(rule) = NoProxyRule::parse(item) {
                rules.push(rule);
            }
        }
        Self { rules }
    }

    pub fn matches(&self, host: &str, port: Option<u16>) -> bool {
        self.rules.iter().any(|r| r.matches(host, port))
    }

    pub fn matches_url(&self, url: &Url) -> bool {
        let host = match url.host_str() {
            Some(h) => h,
            None => return false,
        };
        let port = url.port_or_known_default();
        self.matches(host, port)
    }
}
