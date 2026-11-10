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

            // Interpolate environment variables
            let interpolated = interpolate_env(trimmed, &env_lookup);

            // Parse key-value: key = value or key=value or bare key
            let (key, value) = if let Some(idx) = interpolated.find('=') {
                let k = interpolated[..idx].trim().to_string();
                let v = interpolated[idx + 1..].trim().to_string();
                (k, v)
            } else {
                (interpolated.to_string(), "true".to_string())
            };

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

        // Prevent newline injection in configuration keys and values
        if key_trimmed.contains('\n')
            || key_trimmed.contains('\r')
            || value_trimmed.contains('\n')
            || value_trimmed.contains('\r')
        {
            return Err(ConfigError::InvalidLine(format!(
                "Configuration line contains forbidden newline character: '{key_trimmed}'"
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
        if let Some(scope) = parse_scoped_registry_key(key_trimmed) {
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
    pub fn get_auth_token(&self, registry_url: &Url) -> Option<&str> {
        let host = registry_url.host_str()?;
        let port_part = if let Some(port) = registry_url.port() {
            format!(":{port}")
        } else {
            String::new()
        };

        let path = registry_url.path();
        let normalized_path = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{path}/")
        };

        let host_lower = host.to_ascii_lowercase();

        // Exact match: "//host:port/path/"
        let candidate1 = format!("//{host_lower}{port_part}{normalized_path}");
        if let Some(token) = self.auth_tokens.get(&candidate1) {
            return Some(token.as_str());
        }

        // Without trailing slash in path if not root
        let candidate2 = format!("//{host_lower}{port_part}{path}");
        if let Some(token) = self.auth_tokens.get(&candidate2) {
            return Some(token.as_str());
        }

        // Root "//host:port/"
        let candidate3 = format!("//{host_lower}{port_part}/");
        if let Some(token) = self.auth_tokens.get(&candidate3) {
            return Some(token.as_str());
        }

        // Root without port "//host/"
        if !port_part.is_empty() {
            let candidate4 = format!("//{host_lower}/");
            if let Some(token) = self.auth_tokens.get(&candidate4) {
                return Some(token.as_str());
            }
        }

        // Global _authToken setting fallback
        if let Some(token) = self.settings.get("_authToken") {
            return Some(token.as_str());
        }

        None
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

fn parse_scoped_registry_key(key: &str) -> Option<String> {
    if let Some(raw_scope) = key.strip_suffix(":registry") {
        let s = raw_scope.trim();
        if !s.is_empty() {
            let scope = if !s.starts_with('@') {
                format!("@{s}")
            } else {
                s.to_string()
            };
            return Some(scope);
        }
    }
    if let Some(raw_scope) = key.strip_suffix("/registry") {
        let s = raw_scope.trim();
        if !s.is_empty() {
            let scope = if !s.starts_with('@') {
                format!("@{s}")
            } else {
                s.to_string()
            };
            return Some(scope);
        }
    }
    None
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
/// Safe against multi-byte UTF-8 boundaries and empty string evaluations.
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
                    chars.next();
                    let rest = &input[idx + 2..];
                    if let Some(close_rel) = rest.find('}') {
                        let expr = &rest[..close_rel];
                        // Advance iterator past '}'
                        while let Some((c_idx, _)) = chars.peek() {
                            if *c_idx > idx + 2 + close_rel {
                                break;
                            }
                            chars.next();
                        }

                        let (var_name, default_val, use_default_if_empty) =
                            if let Some(def_idx) = expr.find(":-") {
                                (&expr[..def_idx], Some(&expr[def_idx + 2..]), true)
                            } else if let Some(def_idx) = expr.find('-') {
                                (&expr[..def_idx], Some(&expr[def_idx + 1..]), false)
                            } else {
                                (expr, None, false)
                            };

                        let var_name = var_name.trim();
                        let is_valid_name = !var_name.is_empty()
                            && var_name
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_');

                        if is_valid_name {
                            let val = match lookup(var_name) {
                                Some(v) => {
                                    if use_default_if_empty && v.is_empty() {
                                        default_val.map(|d| d.to_string()).unwrap_or(v)
                                    } else {
                                        v
                                    }
                                }
                                None => default_val.map(|d| d.to_string()).unwrap_or_default(),
                            };
                            result.push_str(&val);
                        } else if default_val.is_some() && var_name.is_empty() {
                            result.push_str(default_val.unwrap());
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

    // 2. Redact npm / ghp tokens
    result = replace_npm_tokens(&result);

    // 3. Redact :_authToken=<val> and other key-value credentials
    for key in &[
        "_authtoken",
        "_authToken",
        "authtoken",
        "password",
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
    if lower.contains("auth") && !lower.contains("author") {
        return true;
    }
    false
}

/// Masks a credential for display (e.g. "npm_1234567890abcdef" -> "npm_***cdef").
pub fn mask_credential(token: &str) -> String {
    if token.is_empty() {
        return String::new();
    }
    if token.len() <= 6 {
        return "[REDACTED]".to_string();
    }
    let prefix = if token.starts_with("npm_") {
        "npm_***"
    } else if token.starts_with("ghp_") {
        "ghp_***"
    } else {
        "***"
    };
    let tail = &token[token.len().saturating_sub(4)..];
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
    let pattern = format!("{key_name}=");
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices(&pattern) {
        if idx < last_idx {
            continue;
        }
        let key_len = pattern.len();
        out.push_str(&text[last_idx..idx + key_len]);
        let remainder = &text[idx + key_len..];
        let end_token = remainder
            .find(|c: char| {
                c.is_whitespace()
                    || c == ';'
                    || c == '&'
                    || c == '"'
                    || c == '\''
                    || c == '\n'
                    || c == '\r'
            })
            .unwrap_or(remainder.len());
        out.push_str("[REDACTED]");
        last_idx = idx + key_len + end_token;
    }
    out.push_str(&text[last_idx..]);
    out
}
