use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use url::Url;
use crate::error::ConfigError;

pub const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org/";

#[derive(Debug, Clone, PartialEq, Eq)]
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

        // 1. Check if key is the default registry
        if key_trimmed == "registry" {
            let mut reg_url = Url::parse(value_trimmed)?;
            ensure_trailing_slash(&mut reg_url);
            self.registry = reg_url;
            self.settings.insert(key_trimmed.to_string(), value_trimmed.to_string());
            return Ok(());
        }

        // 2. Check if key is a scoped registry: e.g. "@myorg:registry" or "@scope/registry"
        if key_trimmed.starts_with('@') && key_trimmed.ends_with(":registry") {
            let scope = &key_trimmed[..key_trimmed.len() - ":registry".len()];
            let mut reg_url = Url::parse(value_trimmed)?;
            ensure_trailing_slash(&mut reg_url);
            self.scoped_registries
                .insert(scope.to_ascii_lowercase(), reg_url);
            self.settings.insert(key_trimmed.to_string(), value_trimmed.to_string());
            return Ok(());
        }

        // 3. Check if key is URI-scoped auth: e.g. "//registry.npmjs.org/:_authToken"
        if let Some(uri_prefix) = key_trimmed.strip_suffix(":_authToken") {
            let norm_prefix = normalize_uri_prefix(uri_prefix);
            self.auth_tokens.insert(norm_prefix, value_trimmed.to_string());
            self.settings.insert(key_trimmed.to_string(), value_trimmed.to_string());
            return Ok(());
        }

        // Fallback: general setting
        self.settings.insert(key_trimmed.to_string(), value_trimmed.to_string());
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
    /// If package is scoped (e.g. "@myorg/foo"), looks up scoped registry first.
    pub fn registry_for_package(&self, package_name: &str) -> &Url {
        if package_name.starts_with('@') {
            if let Some(slash_idx) = package_name.find('/') {
                let scope = &package_name[..slash_idx].to_ascii_lowercase();
                if let Some(scoped_url) = self.scoped_registries.get(scope) {
                    return scoped_url;
                }
            }
        }
        &self.registry
    }

    /// Retrieve the auth token for a registry URL if configured.
    pub fn get_auth_token(&self, registry_url: &Url) -> Option<&str> {
        // Construct URI prefix: e.g. "//registry.npmjs.org/" or "//localhost:4873/"
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

        // Try exact match: "//host:port/path/"
        let candidate1 = format!("//{host}{port_part}{normalized_path}");
        if let Some(token) = self.auth_tokens.get(&candidate1) {
            return Some(token.as_str());
        }

        // Try without trailing slash in path if not root
        let candidate2 = format!("//{host}{port_part}{path}");
        if let Some(token) = self.auth_tokens.get(&candidate2) {
            return Some(token.as_str());
        }

        // Try root "//host:port/"
        let candidate3 = format!("//{host}{port_part}/");
        if let Some(token) = self.auth_tokens.get(&candidate3) {
            return Some(token.as_str());
        }

        // Try root "//host/" (if port was specified in candidate3 but key has no port)
        if !port_part.is_empty() {
            let candidate4 = format!("//{host}/");
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
}

fn ensure_trailing_slash(url: &mut Url) {
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
}

fn normalize_uri_prefix(prefix: &str) -> String {
    let mut p = prefix.trim().to_string();
    if !p.starts_with("//") {
        p = format!("//{p}");
    }
    if !p.ends_with('/') {
        p.push('/');
    }
    p
}

/// Interpolates `${VAR}` or `${VAR:-default}` or `$VAR` in input string.
pub fn interpolate_env<F>(input: &str, lookup: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() {
            if chars[i + 1] == '{' {
                // ${VAR} or ${VAR:-default}
                if let Some(end_idx) = input[i + 2..].find('}') {
                    let full_end = i + 2 + end_idx;
                    let expr = &input[i + 2..full_end];

                    let (var_name, default_val) = if let Some(def_idx) = expr.find(":-") {
                        (&expr[..def_idx], Some(&expr[def_idx + 2..]))
                    } else if let Some(def_idx) = expr.find('-') {
                        (&expr[..def_idx], Some(&expr[def_idx + 1..]))
                    } else {
                        (expr, None)
                    };

                    let val = lookup(var_name.trim())
                        .or_else(|| default_val.map(|d| d.to_string()))
                        .unwrap_or_default();

                    result.push_str(&val);
                    i = full_end + 1;
                    continue;
                }
            } else if chars[i + 1].is_alphabetic() || chars[i + 1] == '_' {
                // $VAR
                let mut end = i + 1;
                while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
                    end += 1;
                }
                let var_name: String = chars[i + 1..end].iter().collect();
                let val = lookup(&var_name).unwrap_or_default();
                result.push_str(&val);
                i = end;
                continue;
            }
        }

        result.push(chars[i]);
        i += 1;
    }

    result
}
