#![allow(clippy::manual_strip)]

pub mod config;
pub mod error;
pub mod npm_keys;
pub mod npmrc;

pub use config::{
    delete_config_value_from_file, find_global_bin_dir, find_global_node_modules,
    find_global_npmrc, find_global_npmrc_with_env, find_global_prefix, find_global_prefix_with_env,
    find_local_bin_dir, find_local_node_modules, find_local_prefix, find_user_npmrc,
    find_user_npmrc_with_env, find_workspace_root, get_default_global_npmrc,
    get_default_user_npmrc, get_process_cli_overrides, get_process_globalconfig,
    get_process_userconfig, set_config_value_in_file, set_process_cli_overrides,
    set_process_globalconfig, set_process_userconfig, Config, ConfigDetailed, ConfigLayer,
    ConfigOptions,
};
pub use npm_keys::{
    is_boolean_npm_config_key, is_known_npm_config_key, normalize_config_key,
    NPM_BOOLEAN_CONFIG_KEYS, NPM_CONFIG_KEYS,
};
pub use error::ConfigError;
pub use npmrc::{
    encode_package_name, interpolate_env, is_sensitive_credential_key, mask_credential,
    scrub_credentials, validate_package_name, Npmrc, DEFAULT_REGISTRY,
};

use url::Url;

/// Parse a scoped registry key or CLI flag into a normalized scope name (e.g. `@scope`).
///
/// Accepts:
/// - `--@scope:registry` -> `@scope`
/// - `@scope:registry` -> `@scope`
/// - `--scope:registry` -> `@scope`
/// - `scope:registry` -> `@scope`
/// - `--@scope/registry` -> `@scope`
/// - `@scope/registry` -> `@scope`
pub fn parse_scoped_registry_key(key: &str) -> Option<String> {
    let clean = key.strip_prefix("--").unwrap_or(key).trim();
    if let Some(raw_scope) = clean
        .strip_suffix(":registry")
        .or_else(|| clean.strip_suffix("/registry"))
    {
        let s = raw_scope.trim();
        if !s.is_empty() {
            let scope = if !s.starts_with('@') {
                format!("@{s}")
            } else {
                s.to_string()
            };
            return Some(scope.to_ascii_lowercase());
        }
    }
    None
}

/// Parse a scoped registry CLI flag or configuration entry into a tuple of `(scope, Url)`.
///
/// Supports:
/// - Combined form: `"--@scope:registry=https://custom.registry/"`
/// - Combined form without dashes: `"@scope:registry=https://custom.registry/"`
/// - Key-value form: key `"--@scope:registry"`, value `"https://custom.registry/"`
/// - Key-value form without dashes: key `"@scope:registry"`, value `"https://custom.registry/"`
pub fn parse_scoped_registry_entry(
    key_or_arg: &str,
    value: Option<&str>,
) -> Result<Option<(String, Url)>, ConfigError> {
    let (key, val_str) = if let Some(v) = value {
        (key_or_arg, v)
    } else if let Some((k, v)) = key_or_arg.split_once('=') {
        (k, v)
    } else {
        return Ok(None);
    };

    if let Some(scope) = parse_scoped_registry_key(key) {
        let mut parsed_url = Url::parse(val_str.trim())?;
        if !parsed_url.path().ends_with('/') {
            let new_path = format!("{}/", parsed_url.path());
            parsed_url.set_path(&new_path);
        }
        return Ok(Some((scope, parsed_url)));
    }

    Ok(None)
}

/// Apply a scoped registry configuration to an `Npmrc` instance.
///
/// Automatically parses `--@scope:registry` or `@scope:registry` (and `=url` or explicit value),
/// inserts the normalized scope into `scoped_registries`, and records the setting.
pub fn apply_scoped_registry(
    npmrc: &mut Npmrc,
    key_or_arg: &str,
    value: Option<&str>,
) -> Result<bool, ConfigError> {
    if let Some((scope, url)) = parse_scoped_registry_entry(key_or_arg, value)? {
        let setting_key = format!("{scope}:registry");
        npmrc.scoped_registries.insert(scope, url.clone());
        npmrc.settings.insert(setting_key, url.to_string());
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Resolve the registry URL for a package using an `Npmrc` configuration.
///
/// Scoped packages matching a configured scope return their scoped registry URL;
/// unmatched scoped packages and unscoped packages return the default registry URL.
pub fn resolve_package_registry<'a>(npmrc: &'a Npmrc, package_name: &str) -> &'a Url {
    npmrc.registry_for_package(package_name)
}

impl Config {
    /// Resolve the registry URL for a package using this configuration.
    pub fn registry_for_package(&self, package_name: &str) -> &Url {
        self.npmrc.registry_for_package(package_name)
    }

    /// Apply a scoped registry configuration entry to this configuration.
    pub fn apply_scoped_registry(
        &mut self,
        key_or_arg: &str,
        value: Option<&str>,
    ) -> Result<bool, ConfigError> {
        apply_scoped_registry(&mut self.npmrc, key_or_arg, value)
    }
}

#[cfg(test)]
mod scoped_registry_tests {
    use super::*;

    #[test]
    fn test_parse_scoped_registry_flags_and_entries() {
        let res1 =
            parse_scoped_registry_entry("--@myorg:registry=https://custom.registry.com", None)
                .unwrap();
        assert!(res1.is_some());
        let (scope1, url1) = res1.unwrap();
        assert_eq!(scope1, "@myorg");
        assert_eq!(url1.as_str(), "https://custom.registry.com/");

        let res2 = parse_scoped_registry_entry("@other:registry=https://other.registry.org/", None)
            .unwrap();
        assert!(res2.is_some());
        let (scope2, url2) = res2.unwrap();
        assert_eq!(scope2, "@other");
        assert_eq!(url2.as_str(), "https://other.registry.org/");

        let res3 = parse_scoped_registry_entry("--@scope:registry", Some("https://scope.pkg.dev"))
            .unwrap();
        assert!(res3.is_some());
        let (scope3, url3) = res3.unwrap();
        assert_eq!(scope3, "@scope");
        assert_eq!(url3.as_str(), "https://scope.pkg.dev/");

        // Non-registry args should return None
        assert!(parse_scoped_registry_entry("--legacy-peer-deps", None)
            .unwrap()
            .is_none());
        assert!(parse_scoped_registry_entry("lodash", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_scoped_registry_resolution_via_config() {
        let mut config = Config::new();
        config
            .apply_scoped_registry("--@mycorp:registry=https://npm.mycorp.internal", None)
            .unwrap();

        let scoped_url = config.registry_for_package("@mycorp/tools");
        assert_eq!(scoped_url.as_str(), "https://npm.mycorp.internal/");

        let unscoped_url = config.registry_for_package("react");
        assert_eq!(unscoped_url.as_str(), "https://registry.npmjs.org/");

        let other_scoped = config.registry_for_package("@public/tools");
        assert_eq!(other_scoped.as_str(), "https://registry.npmjs.org/");
    }
}

#[cfg(test)]
mod tests;
