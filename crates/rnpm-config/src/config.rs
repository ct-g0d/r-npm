use crate::error::ConfigError;
use crate::npmrc::Npmrc;
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

static PROCESS_CLI_OVERRIDES: RwLock<Option<BTreeMap<String, String>>> = RwLock::new(None);
static PROCESS_USERCONFIG: RwLock<Option<PathBuf>> = RwLock::new(None);
static PROCESS_GLOBALCONFIG: RwLock<Option<PathBuf>> = RwLock::new(None);

pub fn set_process_cli_overrides(overrides: BTreeMap<String, String>) {
    if let Ok(mut lock) = PROCESS_CLI_OVERRIDES.write() {
        *lock = Some(overrides);
    }
}

pub fn get_process_cli_overrides() -> Option<BTreeMap<String, String>> {
    PROCESS_CLI_OVERRIDES
        .read()
        .ok()
        .and_then(|lock| lock.clone())
}

pub fn set_process_userconfig(path: PathBuf) {
    if let Ok(mut lock) = PROCESS_USERCONFIG.write() {
        *lock = Some(path);
    }
}

pub fn get_process_userconfig() -> Option<PathBuf> {
    PROCESS_USERCONFIG.read().ok().and_then(|lock| lock.clone())
}

pub fn set_process_globalconfig(path: PathBuf) {
    if let Ok(mut lock) = PROCESS_GLOBALCONFIG.write() {
        *lock = Some(path);
    }
}

pub fn get_process_globalconfig() -> Option<PathBuf> {
    PROCESS_GLOBALCONFIG
        .read()
        .ok()
        .and_then(|lock| lock.clone())
}

#[derive(Debug, Clone, Default)]
pub struct ConfigOptions<'a> {
    pub project_dir: Option<&'a Path>,
    pub workspace_root: Option<&'a Path>,
    pub builtin_config: Option<PathBuf>,
    pub globalconfig: Option<PathBuf>,
    pub userconfig: Option<PathBuf>,
    pub cli_overrides: Option<BTreeMap<String, String>>,
    pub env_vars: Option<BTreeMap<String, String>>,
}

impl<'a> ConfigOptions<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn project_dir(mut self, path: &'a Path) -> Self {
        self.project_dir = Some(path);
        self
    }

    pub fn workspace_root(mut self, path: &'a Path) -> Self {
        self.workspace_root = Some(path);
        self
    }

    pub fn builtin_config(mut self, path: PathBuf) -> Self {
        self.builtin_config = Some(path);
        self
    }

    pub fn globalconfig(mut self, path: PathBuf) -> Self {
        self.globalconfig = Some(path);
        self
    }

    pub fn userconfig(mut self, path: PathBuf) -> Self {
        self.userconfig = Some(path);
        self
    }

    pub fn with_cli<KeyType: Into<String>, ValType: Into<String>>(
        mut self,
        key: KeyType,
        value: ValType,
    ) -> Self {
        let mut map = self.cli_overrides.unwrap_or_default();
        map.insert(key.into(), value.into());
        self.cli_overrides = Some(map);
        self
    }

    pub fn cli_overrides(mut self, overrides: BTreeMap<String, String>) -> Self {
        self.cli_overrides = Some(overrides);
        self
    }

    pub fn env_vars(mut self, env_map: BTreeMap<String, String>) -> Self {
        self.env_vars = Some(env_map);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub npmrc: Npmrc,
    pub layers: Vec<ConfigLayer>,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        let key_lower = key.to_ascii_lowercase();
        let dashed = key_lower.replace('_', "-");
        let underscored = key_lower.replace('-', "_");
        self.npmrc
            .settings
            .get(key)
            .or_else(|| self.npmrc.settings.get(&key_lower))
            .or_else(|| self.npmrc.settings.get(&dashed))
            .or_else(|| self.npmrc.settings.get(&underscored))
            .map(|val| val.as_str())
            .or_else(|| (dashed == "registry").then(|| self.npmrc.registry.as_str()))
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key)
            .and_then(|val| match val.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Some(true),
                "false" | "0" | "no" | "off" => Some(false),
                _ => None,
            })
    }

    pub fn proxy(&self) -> Option<&str> {
        self.get("proxy").filter(|s| !s.is_empty() && *s != "null")
    }

    pub fn https_proxy(&self) -> Option<&str> {
        self.get("https-proxy")
            .or_else(|| self.get("https_proxy"))
            .filter(|s| !s.is_empty() && *s != "null")
    }

    pub fn http_proxy(&self) -> Option<&str> {
        self.get("http-proxy")
            .or_else(|| self.get("http_proxy"))
            .filter(|s| !s.is_empty() && *s != "null")
    }

    pub fn no_proxy(&self) -> Option<&str> {
        self.get("noproxy")
            .or_else(|| self.get("no-proxy"))
            .or_else(|| self.get("no_proxy"))
            .filter(|s| !s.is_empty() && *s != "null")
    }

    pub fn no_proxy_matcher(&self) -> crate::npmrc::NoProxyMatcher {
        let val = self.no_proxy().unwrap_or_default();
        crate::npmrc::NoProxyMatcher::parse(val)
    }

    pub fn should_bypass_proxy(&self, url: &url::Url) -> bool {
        let host = match url.host_str() {
            Some(h) => h,
            None => return false,
        };
        let clean_host = host.trim().trim_start_matches('[').trim_end_matches(']');
        if clean_host == "localhost"
            || clean_host == "127.0.0.1"
            || clean_host == "::1"
            || clean_host.ends_with(".localhost")
        {
            return true;
        }
        let port = url.port_or_known_default();
        self.no_proxy_matcher().matches(clean_host, port)
    }

    /// Parse `min-release-age` config (in days) into a UTC cutoff timestamp
    /// (milliseconds since epoch), computed relative to `now_ms`.
    ///
    /// In npm 11.20.0, `min-release-age` accepts a relative number of days (`<days>`).
    /// The cutoff timestamp is `now - (86400000 * age)`.
    /// If age is 0 or non-positive, no cutoff applies (`None`).
    pub fn min_release_age_cutoff_at(&self, now_ms: i64) -> Option<i64> {
        let val_str = self
            .get("min-release-age")
            .or_else(|| self.get("min_release_age"))?;
        let trimmed = val_str.trim();
        if trimmed.eq_ignore_ascii_case("null") || trimmed.is_empty() {
            return None;
        }
        let days = trimmed.parse::<f64>().ok()?;
        if days <= 0.0 || !days.is_finite() {
            return None;
        }
        let delta_ms = (days * 86_400_000.0).round() as i64;
        Some(now_ms.saturating_sub(delta_ms))
    }

    /// Parse `min-release-age` config into a UTC cutoff timestamp (milliseconds
    /// since epoch) relative to the current system time.
    pub fn min_release_age_cutoff(&self) -> Option<i64> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        self.min_release_age_cutoff_at(now_ms)
    }

    /// npm's `before` / `min-release-age`: resolve only versions published on
    /// or before this instant (milliseconds since the epoch).
    ///
    /// Matching npm 11.20.0 semantics:
    /// - `before` accepts an exact JS date/timestamp.
    /// - `min-release-age` accepts a relative number of days.
    /// - When both apply within config, `before` wins (an explicit date overrides a relative window).
    /// - When `before` is explicitly set to `"null"` or empty, it disables the cutoff.
    pub fn before_cutoff(&self) -> Option<i64> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        self.before_cutoff_at(now_ms)
    }

    /// npm's `before` / `min-release-age` cutoff computed relative to `now_ms`.
    ///
    /// Precedence follows npm 11.20.0 across configuration layers:
    /// CLI > env > project `.npmrc` > workspace `.npmrc` > user `.npmrc` > global `.npmrc` > default.
    /// The highest-priority layer specifying either `before` or `min-release-age` wins.
    /// If both `before` and `min-release-age` appear in the same layer, `before` wins as tie-breaker.
    pub fn before_cutoff_at(&self, now_ms: i64) -> Option<i64> {
        let parse_before_val = |val: &str| -> Option<i64> {
            let trimmed = val.trim();
            if trimmed.eq_ignore_ascii_case("null") || trimmed.is_empty() {
                return None;
            }
            crate::date::parse_js_date(trimmed)
        };

        let parse_age_val = |val: &str| -> Option<i64> {
            let trimmed = val.trim();
            if trimmed.eq_ignore_ascii_case("null") || trimmed.is_empty() {
                return None;
            }
            let days = trimmed.parse::<f64>().ok()?;
            if days <= 0.0 || !days.is_finite() {
                return None;
            }
            let delta_ms = (days * 86_400_000.0).round() as i64;
            Some(now_ms.saturating_sub(delta_ms))
        };

        let layer_lookup = |settings: &BTreeMap<String, String>, key: &str| -> Option<String> {
            let key_lower = key.to_ascii_lowercase();
            let dashed = key_lower.replace('_', "-");
            let underscored = key_lower.replace('-', "_");
            settings
                .get(key)
                .or_else(|| settings.get(&key_lower))
                .or_else(|| settings.get(&dashed))
                .or_else(|| settings.get(&underscored))
                .cloned()
        };

        if !self.layers.is_empty() {
            let layer_priority = |name: &str| -> u8 {
                match name.to_ascii_lowercase().as_str() {
                    "cli" => 7,
                    "env" => 6,
                    "project" => 5,
                    "workspace" => 4,
                    "user" => 3,
                    "global" => 2,
                    "builtin" => 1,
                    _ => 0,
                }
            };

            let mut sorted_layers: Vec<&ConfigLayer> = self.layers.iter().collect();
            sorted_layers.sort_by_key(|a| std::cmp::Reverse(layer_priority(&a.name)));

            for layer in sorted_layers {
                let before_opt = layer_lookup(&layer.settings, "before");
                let age_opt = layer_lookup(&layer.settings, "min-release-age");

                if before_opt.is_some() || age_opt.is_some() {
                    if let Some(b_val) = before_opt {
                        return parse_before_val(&b_val);
                    } else if let Some(a_val) = age_opt {
                        return parse_age_val(&a_val);
                    }
                }
            }
            return None;
        }

        if let Some(before_str) = self.get("before") {
            let trimmed = before_str.trim();
            if trimmed.eq_ignore_ascii_case("null") || trimmed.is_empty() {
                return None;
            }
            if let Some(cutoff) = crate::date::parse_js_date(trimmed) {
                return Some(cutoff);
            }
            return None;
        }
        self.min_release_age_cutoff_at(now_ms)
    }

    /// npm's `min-release-age-exclude`: list of package names or `minimatch` glob patterns
    /// that are exempt from the `min-release-age` and `before` release-age filter.
    pub fn min_release_age_exclude(&self) -> Vec<String> {
        let mut list = Vec::new();
        let keys = [
            "min-release-age-exclude",
            "min-release-age-exclude[]",
            "min_release_age_exclude",
            "min_release_age_exclude[]",
        ];
        for k in keys {
            if let Some(val) = self.get(k) {
                for item in val.split(',') {
                    let trimmed = item.trim();
                    if !trimmed.is_empty() && !list.contains(&trimmed.to_string()) {
                        list.push(trimmed.to_string());
                    }
                }
            }
        }
        list
    }

    pub fn load(project_dir: Option<&Path>) -> Result<Self, ConfigError> {
        Self::load_with_options(ConfigOptions {
            project_dir,
            ..Default::default()
        })
    }

    pub fn load_with_cli(
        project_dir: Option<&Path>,
        cli_overrides: BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        Self::load_with_options(ConfigOptions {
            project_dir,
            cli_overrides: Some(cli_overrides),
            ..Default::default()
        })
    }

    pub fn load_with_options(options: ConfigOptions<'_>) -> Result<Self, ConfigError> {
        let env_lookup = |var_name: &str| -> Option<String> {
            if let Some(ref map) = options.env_vars {
                map.get(var_name).cloned()
            } else {
                env::var(var_name).ok()
            }
        };

        let cli_map_opt = options.cli_overrides.or_else(get_process_cli_overrides);
        let mut layers = Vec::new();
        let mut base_npmrc = Npmrc::default();

        let builtin_config_path = options
            .builtin_config
            .clone()
            .or_else(|| {
                cli_map_opt
                    .as_ref()
                    .and_then(|cli| {
                        cli.get("builtinconfig")
                            .or_else(|| cli.get("--builtinconfig"))
                            .map(PathBuf::from)
                    })
            })
            .or_else(|| {
                env_lookup("npm_config_builtinconfig")
                    .or_else(|| env_lookup("NPM_CONFIG_BUILTINCONFIG"))
                    .map(PathBuf::from)
            });

        if let Some(path) = builtin_config_path {
            if path.as_os_str() != "false" && !path.as_os_str().is_empty() && path.exists() {
                let builtin_config = Npmrc::from_file(&path)?;
                layers.push(ConfigLayer {
                    name: "builtin".to_string(),
                    source: Some(path),
                    settings: builtin_config.scrubbed_settings(),
                });
                base_npmrc.merge(builtin_config);
            }
        }

        let disable_global = options
            .globalconfig
            .as_ref()
            .map(|p| p.as_os_str() == "false")
            .unwrap_or(false)
            || cli_map_opt
                .as_ref()
                .and_then(|cli| {
                    cli.get("globalconfig")
                        .or_else(|| cli.get("--globalconfig"))
                        .map(|v| v == "false")
                })
                .unwrap_or(false);

        let global_config_path = if disable_global {
            None
        } else {
            options
                .globalconfig
                .clone()
                .or_else(get_process_globalconfig)
                .or_else(|| {
                    cli_map_opt
                        .as_ref()
                        .and_then(|cli| {
                            cli.get("globalconfig")
                                .or_else(|| cli.get("--globalconfig"))
                                .map(PathBuf::from)
                        })
                })
                .or_else(|| {
                    env_lookup("npm_config_globalconfig")
                        .or_else(|| env_lookup("NPM_CONFIG_GLOBALCONFIG"))
                        .map(PathBuf::from)
                })
                .or_else(|| find_global_npmrc_with_env(env_lookup))
        };

        if let Some(path) = global_config_path {
            if path.as_os_str() != "false" && !path.as_os_str().is_empty() && path.exists() {
                let global_config = Npmrc::from_file(&path)?;
                layers.push(ConfigLayer {
                    name: "global".to_string(),
                    source: Some(path),
                    settings: global_config.scrubbed_settings(),
                });
                base_npmrc.merge(global_config);
            }
        }

        let disable_user = options
            .userconfig
            .as_ref()
            .map(|p| p.as_os_str() == "false")
            .unwrap_or(false)
            || cli_map_opt
                .as_ref()
                .and_then(|cli| {
                    cli.get("userconfig")
                        .or_else(|| cli.get("--userconfig"))
                        .map(|v| v == "false")
                })
                .unwrap_or(false);

        let user_config_path = if disable_user {
            None
        } else {
            options
                .userconfig
                .clone()
                .or_else(get_process_userconfig)
                .or_else(|| {
                    cli_map_opt
                        .as_ref()
                        .and_then(|cli| {
                            cli.get("userconfig")
                                .or_else(|| cli.get("--userconfig"))
                                .map(PathBuf::from)
                        })
                })
                .or_else(|| {
                    env_lookup("npm_config_userconfig")
                        .or_else(|| env_lookup("NPM_CONFIG_USERCONFIG"))
                        .map(PathBuf::from)
                })
                .or_else(|| base_npmrc.settings.get("userconfig").map(PathBuf::from))
                .or_else(|| find_user_npmrc_with_env(env_lookup))
        };

        if let Some(path) = user_config_path {
            if path.as_os_str() != "false" && !path.as_os_str().is_empty() && path.exists() {
                let user_config = Npmrc::from_file(&path)?;
                layers.push(ConfigLayer {
                    name: "user".to_string(),
                    source: Some(path),
                    settings: user_config.scrubbed_settings(),
                });
                base_npmrc.merge(user_config);
            }
        }

        let ws_root = options
            .workspace_root
            .map(|path| path.to_path_buf())
            .or_else(|| options.project_dir.and_then(find_workspace_root));

        if let Some(ws_path) = ws_root {
            let ws_npmrc_path = ws_path.join(".npmrc");
            if ws_npmrc_path.exists() {
                let ws_config = Npmrc::from_file(&ws_npmrc_path)?;
                layers.push(ConfigLayer {
                    name: "workspace".to_string(),
                    source: Some(ws_npmrc_path),
                    settings: ws_config.scrubbed_settings(),
                });
                base_npmrc.merge(ws_config);
            }
        }

        if let Some(dir) = options.project_dir {
            let project_npmrc_path = dir.join(".npmrc");
            if project_npmrc_path.exists() {
                let project_config = Npmrc::from_file(&project_npmrc_path)?;
                layers.push(ConfigLayer {
                    name: "project".to_string(),
                    source: Some(project_npmrc_path),
                    settings: project_config.scrubbed_settings(),
                });
                base_npmrc.merge(project_config);
            }
        }

        let all_env: BTreeMap<String, String> = if let Some(ref map) = options.env_vars {
            map.clone()
        } else {
            let mut filtered = BTreeMap::new();
            for (k, v) in env::vars() {
                if let Some(prefix) = k.get(..11) {
                    if prefix.eq_ignore_ascii_case("npm_config_") {
                        filtered.insert(k, v);
                    }
                }
            }
            filtered
        };

        let mut env_layer_settings = BTreeMap::new();
        for (raw_key, value) in all_env {
            let rest_opt = if let Some(prefix) = raw_key.get(..11) {
                if prefix.eq_ignore_ascii_case("npm_config_") {
                    raw_key.get(11..)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(rest) = rest_opt {
                if rest.is_empty() {
                    continue;
                }
                // In npm, nerf-darted keys (e.g. //registry.npmjs.org/:_authToken)
                // preserve case and underscores without normalizing.
                if rest.starts_with("//") {
                    let val_display = if crate::npmrc::is_sensitive_credential_key(rest) {
                        crate::npmrc::mask_credential(&value)
                    } else {
                        value.clone()
                    };
                    env_layer_settings.insert(rest.to_string(), val_display);
                    base_npmrc.set(rest, &value)?;
                } else {
                    let lower = rest.to_ascii_lowercase();
                    let (prefix, body) = if let Some(stripped) = lower.strip_prefix('_') {
                        ("_", stripped)
                    } else {
                        ("", lower.as_str())
                    };
                    let dashed = format!("{prefix}{}", body.replace('_', "-"));
                    let val_display = if crate::npmrc::is_sensitive_credential_key(&dashed) {
                        crate::npmrc::mask_credential(&value)
                    } else {
                        value.clone()
                    };
                    env_layer_settings.insert(dashed.clone(), val_display);
                    base_npmrc.set(&dashed, &value)?;
                    if dashed != rest {
                        let _ = base_npmrc.set(rest, &value);
                    }
                    if dashed == "no-proxy" || dashed == "no_proxy" {
                        let _ = base_npmrc.set("noproxy", &value);
                    } else if dashed == "noproxy" {
                        let _ = base_npmrc.set("no-proxy", &value);
                    }
                }
            }
        }

        if !env_layer_settings.is_empty() {
            layers.push(ConfigLayer {
                name: "env".to_string(),
                source: None,
                settings: env_layer_settings,
            });
        }

        if let Some(cli_map) = cli_map_opt {
            let mut cli_layer_settings = BTreeMap::new();
            for (key, value) in cli_map {
                let clean_key = key.strip_prefix("--").unwrap_or(&key);
                let lower_clean = clean_key.to_ascii_lowercase();
                let (prefix, body) = if let Some(stripped) = lower_clean.strip_prefix('_') {
                    ("_", stripped)
                } else {
                    ("", lower_clean.as_str())
                };
                let dashed = format!("{prefix}{}", body.replace('_', "-"));
                let val_display = if crate::npmrc::is_sensitive_credential_key(clean_key) {
                    crate::npmrc::mask_credential(&value)
                } else {
                    value.clone()
                };
                cli_layer_settings.insert(clean_key.to_string(), val_display.clone());
                if clean_key != dashed {
                    cli_layer_settings.insert(dashed.clone(), val_display);
                }
                base_npmrc.set(clean_key, &value)?;
                if clean_key != dashed {
                    let _ = base_npmrc.set(&dashed, &value);
                }
                if dashed == "no-proxy" || dashed == "no_proxy" {
                    let _ = base_npmrc.set("noproxy", &value);
                } else if dashed == "noproxy" {
                    let _ = base_npmrc.set("no-proxy", &value);
                }
            }
            if !cli_layer_settings.is_empty() {
                layers.push(ConfigLayer {
                    name: "cli".to_string(),
                    source: None,
                    settings: cli_layer_settings,
                });
            }
        }

        // Standard proxy env vars fallback if not set in any config layer.
        // Explicit `.npmrc` `proxy` takes precedence over ambient `HTTPS_PROXY`/`HTTP_PROXY`,
        // and `HTTP_PROXY` only fills `http-proxy` so it does not hijack HTTPS requests.
        if !base_npmrc.settings.contains_key("https-proxy")
            && !base_npmrc.settings.contains_key("https_proxy")
            && !base_npmrc.settings.contains_key("proxy")
        {
            if let Some(hp) = env_lookup("HTTPS_PROXY").or_else(|| env_lookup("https_proxy")) {
                if !hp.is_empty() {
                    let _ = base_npmrc.set("https-proxy", &hp);
                }
            }
        }
        if !base_npmrc.settings.contains_key("proxy")
            && !base_npmrc.settings.contains_key("http-proxy")
            && !base_npmrc.settings.contains_key("http_proxy")
        {
            if let Some(p) = env_lookup("HTTP_PROXY").or_else(|| env_lookup("http_proxy")) {
                if !p.is_empty() {
                    let _ = base_npmrc.set("http-proxy", &p);
                }
            }
        }
        if !base_npmrc.settings.contains_key("noproxy") && !base_npmrc.settings.contains_key("no-proxy") && !base_npmrc.settings.contains_key("no_proxy") {
            if let Some(np) = env_lookup("NO_PROXY").or_else(|| env_lookup("no_proxy")) {
                if !np.is_empty() {
                    let _ = base_npmrc.set("noproxy", &np);
                }
            }
        }

        Ok(Self {
            npmrc: base_npmrc,
            layers,
        })
    }

    pub fn load_detailed(options: ConfigOptions<'_>) -> Result<ConfigDetailed, ConfigError> {
        let env_lookup = |var_name: &str| -> Option<String> {
            if let Some(ref map) = options.env_vars {
                map.get(var_name).cloned()
            } else {
                env::var(var_name).ok()
            }
        };

        let global_prefix = find_global_prefix_with_env(env_lookup);
        let local_prefix = options
            .project_dir
            .map(find_local_prefix)
            .unwrap_or_else(|| {
                env::current_dir()
                    .map(|d| find_local_prefix(&d))
                    .unwrap_or_else(|_| PathBuf::from("."))
            });

        let config = Self::load_with_options(options)?;
        let effective = config.npmrc.scrubbed_settings();

        Ok(ConfigDetailed {
            layers: config.layers,
            effective,
            global_prefix,
            local_prefix,
        })
    }
}

pub fn find_workspace_root(project_dir: &Path) -> Option<PathBuf> {
    let project_dir_canon = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());
    let mut current = project_dir.parent();
    while let Some(dir) = current {
        let pkg_json = dir.join("package.json");
        if pkg_json.is_file() {
            if let Ok(manifest) = rnpm_core::manifest::Manifest::from_file(&pkg_json) {
                if !manifest.workspace_patterns().is_empty() {
                    if let Ok(members) =
                        rnpm_core::workspace::discover_workspaces_from_manifest(dir, &manifest)
                    {
                        for member in members {
                            let member_canon = member
                                .path
                                .canonicalize()
                                .unwrap_or_else(|_| member.path.clone());
                            if member_canon == project_dir_canon
                                || member.path == project_dir
                                || project_dir.ends_with(&member.relative_path)
                            {
                                return Some(dir.to_path_buf());
                            }
                        }
                    }
                }
            }
        }
        current = dir.parent();
    }
    None
}

pub fn find_global_npmrc() -> Option<PathBuf> {
    find_global_npmrc_with_env(|var_name| env::var(var_name).ok())
}

pub fn find_global_npmrc_with_env<LookupFn>(lookup: LookupFn) -> Option<PathBuf>
where
    LookupFn: Fn(&str) -> Option<String>,
{
    // Same prefix resolution as `config set --global` and global installs
    // (NPM_CONFIG_PREFIX, npm_config_prefix, PREFIX, then the platform default),
    // so global config is read from where it was written.
    let path = find_global_prefix_with_env(&lookup)
        .join("etc")
        .join("npmrc");
    if path.exists() {
        return Some(path);
    }
    let etc_path = PathBuf::from("/etc/npmrc");
    if etc_path.exists() {
        return Some(etc_path);
    }
    None
}

pub fn find_user_npmrc() -> Option<PathBuf> {
    find_user_npmrc_with_env(|var_name| env::var(var_name).ok())
}

pub fn find_user_npmrc_with_env<LookupFn>(lookup: LookupFn) -> Option<PathBuf>
where
    LookupFn: Fn(&str) -> Option<String>,
{
    if let Some(userconfig) = lookup("npm_config_userconfig")
        .or_else(|| lookup("NPM_CONFIG_USERCONFIG"))
        .or_else(|| lookup("USERCONFIG"))
    {
        return Some(PathBuf::from(userconfig));
    }
    if let Some(userprofile) = lookup("USERPROFILE") {
        let path = PathBuf::from(userprofile).join(".npmrc");
        return Some(path);
    }
    if let Some(home) = lookup("HOME") {
        let path = PathBuf::from(home).join(".npmrc");
        return Some(path);
    }
    None
}

/// Identifies a specific configuration layer in npm configuration hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct ConfigLayer {
    pub name: String,
    pub source: Option<PathBuf>,
    pub settings: BTreeMap<String, String>,
}

/// Detailed configuration report including sources, layers, and effective settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct ConfigDetailed {
    pub layers: Vec<ConfigLayer>,
    pub effective: BTreeMap<String, String>,
    pub global_prefix: PathBuf,
    pub local_prefix: PathBuf,
}

impl ConfigDetailed {
    pub fn format_text(&self) -> String {
        let mut out = String::new();
        for layer in &self.layers {
            if layer.settings.is_empty() {
                continue;
            }
            if let Some(src) = &layer.source {
                out.push_str(&format!(
                    "; \"{}\" config from {}\n",
                    layer.name,
                    src.display()
                ));
            } else if layer.name == "env" {
                out.push_str("; environment-related config\n");
            } else {
                out.push_str(&format!("; \"{}\" config\n", layer.name));
            }
            for (k, v) in &layer.settings {
                out.push_str(&format!("{k} = \"{v}\"\n"));
            }
            out.push('\n');
        }

        out.push_str(&format!(
            "; npm local prefix = {}\n",
            self.local_prefix.display()
        ));
        out.push_str(&format!(
            "; npm global prefix = {}\n",
            self.global_prefix.display()
        ));
        if let Ok(cwd) = env::current_dir() {
            out.push_str(&format!("; cwd = {}\n", cwd.display()));
        }

        out
    }
}

/// Resolves the global installation prefix path according to environment and platform defaults.
pub fn find_global_prefix() -> PathBuf {
    find_global_prefix_with_env(|var_name| env::var(var_name).ok())
}

/// Resolves the global installation prefix path with a custom environment lookup function.
pub fn find_global_prefix_with_env<LookupFn>(lookup: LookupFn) -> PathBuf
where
    LookupFn: Fn(&str) -> Option<String>,
{
    if let Some(prefix) = lookup("NPM_CONFIG_PREFIX")
        .or_else(|| lookup("npm_config_prefix"))
        .or_else(|| lookup("PREFIX"))
    {
        return PathBuf::from(prefix);
    }

    #[cfg(windows)]
    {
        if let Some(appdata) = lookup("APPDATA") {
            return PathBuf::from(appdata).join("npm");
        }
        if let Some(userprofile) = lookup("USERPROFILE") {
            return PathBuf::from(userprofile)
                .join("AppData")
                .join("Roaming")
                .join("npm");
        }
        PathBuf::from(r"C:\npm")
    }

    #[cfg(not(windows))]
    {
        PathBuf::from("/usr/local")
    }
}

/// Resolves the global executable bin directory from a given prefix.
pub fn find_global_bin_dir(prefix: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        prefix.to_path_buf()
    }
    #[cfg(not(windows))]
    {
        prefix.join("bin")
    }
}

/// Resolves the global node_modules directory from a given prefix.
pub fn find_global_node_modules(prefix: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        prefix.join("node_modules")
    }
    #[cfg(not(windows))]
    {
        prefix.join("lib").join("node_modules")
    }
}

/// Locates the local project prefix directory by searching upwards for package.json or node_modules.
pub fn find_local_prefix(start_dir: &Path) -> PathBuf {
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        if dir.join("package.json").exists() || dir.join("node_modules").exists() {
            return dir.to_path_buf();
        }
        current = dir.parent();
    }
    start_dir.to_path_buf()
}

/// Resolves the local executable bin directory (node_modules/.bin) for a project.
pub fn find_local_bin_dir(start_dir: &Path) -> PathBuf {
    find_local_prefix(start_dir)
        .join("node_modules")
        .join(".bin")
}

/// Resolves the local node_modules directory for a project.
pub fn find_local_node_modules(start_dir: &Path) -> PathBuf {
    find_local_prefix(start_dir).join("node_modules")
}

/// Returns default path for global .npmrc given a prefix.
pub fn get_default_global_npmrc(prefix: &Path) -> PathBuf {
    if let Some(globalconfig) = get_process_globalconfig() {
        return globalconfig;
    }
    if let Ok(globalconfig) = env::var("NPM_CONFIG_GLOBALCONFIG")
        .or_else(|_| env::var("npm_config_globalconfig"))
        .or_else(|_| env::var("GLOBALCONFIG"))
    {
        return PathBuf::from(globalconfig);
    }
    prefix.join("etc").join("npmrc")
}

/// Returns default path for user .npmrc.
pub fn get_default_user_npmrc() -> PathBuf {
    if let Some(userconfig) = get_process_userconfig() {
        return userconfig;
    }
    if let Some(overrides) = get_process_cli_overrides() {
        if let Some(val) = overrides.get("userconfig").or_else(|| overrides.get("user-config")) {
            if val != "false" && !val.is_empty() {
                return PathBuf::from(val);
            }
        }
    }
    if let Some(user) = find_user_npmrc() {
        return user;
    }
    if let Ok(userprofile) = env::var("USERPROFILE") {
        return PathBuf::from(userprofile).join(".npmrc");
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(".npmrc");
    }
    PathBuf::from(".npmrc")
}

/// Encodes an `.npmrc` INI value so comment delimiters (`#`, `;`), quotes, and
/// backslashes survive a round-trip through `decode_ini_field`.
fn encode_ini_value(val: &str) -> String {
    let needs_quotes = val.starts_with('"')
        || val.starts_with('\'')
        || val.starts_with(char::is_whitespace)
        || val.ends_with(char::is_whitespace)
        || val.contains('#')
        || val.contains(';')
        || val.contains('\\')
        || val.contains('"')
        || val.contains('\'')
        || val.contains('=');
    if !needs_quotes {
        return val.to_string();
    }
    let mut out = String::with_capacity(val.len() + 2);
    out.push('"');
    for ch in val.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Updates or appends a key-value setting in an .npmrc file on disk.
/// Preserves comments and existing lines. If `value` is empty, the key is deleted
/// matching npm 11.20.0 behavior.
pub fn set_config_value_in_file(path: &Path, key: &str, value: &str) -> Result<(), ConfigError> {
    let key_trimmed = key.trim();
    if key_trimmed.is_empty() {
        return Err(ConfigError::InvalidLine("Empty key".to_string()));
    }

    if value.is_empty() {
        let _ = delete_config_value_from_file(path, key_trimmed)?;
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
    }

    if key_trimmed.contains('\n')
        || key_trimmed.contains('\r')
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(ConfigError::InvalidLine(
            "Newline in key or value".to_string(),
        ));
    }

    let mut lines = Vec::new();
    let mut updated = false;

    if path.exists() {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') && !trimmed.starts_with(';') {
                let line_key = if let Some(idx) = line.find('=') {
                    line[..idx].trim()
                } else {
                    line.trim()
                };

                if line_key == key_trimmed || line_key.eq_ignore_ascii_case(key_trimmed) {
                    lines.push(format!("{key_trimmed}={}", encode_ini_value(value)));
                    updated = true;
                    continue;
                }
            }
            lines.push(line.to_string());
        }
    }

    if !updated {
        lines.push(format!("{key_trimmed}={}", encode_ini_value(value)));
    }

    let mut out_str = lines.join("\n");
    out_str.push('\n');

    std::fs::write(path, out_str).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Deletes a key from an .npmrc file on disk.
/// Returns true if a key was found and removed, false otherwise.
pub fn delete_config_value_from_file(path: &Path, key: &str) -> Result<bool, ConfigError> {
    if !path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let key_trimmed = key.trim();
    let mut lines = Vec::new();
    let mut deleted = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') && !trimmed.starts_with(';') {
            let line_key = if let Some(idx) = line.find('=') {
                line[..idx].trim()
            } else {
                line.trim()
            };

            if line_key == key_trimmed || line_key.eq_ignore_ascii_case(key_trimmed) {
                deleted = true;
                continue;
            }
        }
        lines.push(line.to_string());
    }

    if deleted {
        let mut out_str = lines.join("\n");
        if !lines.is_empty() {
            out_str.push('\n');
        }
        std::fs::write(path, out_str).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    }

    Ok(deleted)
}

/// Repairs legacy unscoped auth keys and deprecated config keys in .npmrc content.
/// Returns the repaired content and a list of formatted summary messages.
pub fn fix_npmrc_content(
    content: &str,
    where_name: &str,
    nerfed_registry: &str,
) -> (String, Vec<String>) {
    // 1. Scan for unscoped username and _password to know if both or only one exist
    let mut has_unscoped_username = false;
    let mut has_unscoped_password = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
            continue;
        }
        let key = if let Some(idx) = trimmed.find('=') {
            trimmed[..idx].trim()
        } else {
            trimmed
        };
        if key == "username" {
            has_unscoped_username = true;
        } else if key == "_password" {
            has_unscoped_password = true;
        }
    }

    let nerfed = if nerfed_registry.ends_with(':') {
        nerfed_registry.to_string()
    } else {
        format!("{nerfed_registry}:")
    };

    let mut fixed_lines = Vec::new();
    let mut summaries = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
            fixed_lines.push(line.to_string());
            continue;
        }

        let (key, val, has_val) = if let Some(idx) = trimmed.find('=') {
            (trimmed[..idx].trim(), trimmed[idx + 1..].trim(), true)
        } else {
            (trimmed, "", false)
        };

        // Check rules
        if key == "_authtoken" || key == "-authtoken" {
            summaries.push(format!("- `{key}` deleted from {where_name} config"));
            continue;
        }

        if key == "_authToken" || key == "_auth" || key == "email" {
            let new_key = format!("{nerfed}{key}");
            let new_line = if has_val {
                format!("{new_key}={val}")
            } else {
                new_key.clone()
            };
            fixed_lines.push(new_line);
            summaries.push(format!("~ `{key}` renamed to `{new_key}` in {where_name} config"));
            continue;
        }

        if key == "username" {
            if has_unscoped_password {
                let new_key = format!("{nerfed}username");
                let new_line = if has_val {
                    format!("{new_key}={val}")
                } else {
                    new_key.clone()
                };
                fixed_lines.push(new_line);
                summaries.push(format!("~ `username` renamed to `{new_key}` in {where_name} config"));
            } else {
                summaries.push(format!("- `username` deleted from {where_name} config"));
            }
            continue;
        }

        if key == "_password" {
            if has_unscoped_username {
                let new_key = format!("{nerfed}_password");
                let new_line = if has_val {
                    format!("{new_key}={val}")
                } else {
                    new_key.clone()
                };
                fixed_lines.push(new_line);
                summaries.push(format!("~ `_password` renamed to `{new_key}` in {where_name} config"));
            } else {
                summaries.push(format!("- `_password` deleted from {where_name} config"));
            }
            continue;
        }

        // Deprecated keys
        if key == "global-style" {
            fixed_lines.push("install-strategy=shallow".to_string());
            summaries.push(format!("~ `global-style` renamed to `install-strategy=shallow` in {where_name} config"));
            continue;
        }

        if key == "legacy-bundling" {
            fixed_lines.push("install-strategy=nested".to_string());
            summaries.push(format!("~ `legacy-bundling` renamed to `install-strategy=nested` in {where_name} config"));
            continue;
        }

        if key == "only" {
            if val.eq_ignore_ascii_case("prod") || val.eq_ignore_ascii_case("production") {
                fixed_lines.push("omit=dev".to_string());
                summaries.push(format!("~ `only` renamed to `omit=dev` in {where_name} config"));
            } else if val.eq_ignore_ascii_case("dev") || val.eq_ignore_ascii_case("development") {
                fixed_lines.push("include=dev".to_string());
                summaries.push(format!("~ `only` renamed to `include=dev` in {where_name} config"));
            } else {
                fixed_lines.push(line.to_string());
            }
            continue;
        }

        if key == "production" {
            if val.is_empty() || val.eq_ignore_ascii_case("true") {
                fixed_lines.push("omit=dev".to_string());
                summaries.push(format!("~ `production` renamed to `omit=dev` in {where_name} config"));
            } else if val.eq_ignore_ascii_case("false") {
                summaries.push(format!("- `production` deleted from {where_name} config"));
            } else {
                fixed_lines.push(line.to_string());
            }
            continue;
        }

        if key == "shrinkwrap" {
            if val.eq_ignore_ascii_case("false") {
                fixed_lines.push("package-lock=false".to_string());
            } else {
                fixed_lines.push("package-lock=true".to_string());
            }
            summaries.push(format!("~ `shrinkwrap` renamed to `package-lock` in {where_name} config"));
            continue;
        }

        if key == "also"
            && (val.eq_ignore_ascii_case("dev") || val.eq_ignore_ascii_case("development"))
        {
            fixed_lines.push("include=dev".to_string());
            summaries.push(format!("~ `also` renamed to `include=dev` in {where_name} config"));
            continue;
        }

        if key == "dev" && (val.is_empty() || val.eq_ignore_ascii_case("true")) {
            fixed_lines.push("include=dev".to_string());
            summaries.push(format!("~ `dev` renamed to `include=dev` in {where_name} config"));
            continue;
        }

        if key == "optional" {
            if val.eq_ignore_ascii_case("false") {
                fixed_lines.push("omit=optional".to_string());
                summaries.push(format!("~ `optional` renamed to `omit=optional` in {where_name} config"));
                continue;
            } else if val.eq_ignore_ascii_case("true") {
                fixed_lines.push("include=optional".to_string());
                summaries.push(format!("~ `optional` renamed to `include=optional` in {where_name} config"));
                continue;
            }
        }

        if let Some(rest) = key.strip_prefix("init.") {
            let normalized_rest = rest.replace('.', "-");
            let new_key = format!("init-{normalized_rest}");
            let new_line = if has_val {
                format!("{new_key}={val}")
            } else {
                new_key.clone()
            };
            fixed_lines.push(new_line);
            summaries.push(format!("~ `{key}` renamed to `{new_key}` in {where_name} config"));
            continue;
        }

        // Unmodified line
        fixed_lines.push(line.to_string());
    }

    let mut out_str = fixed_lines.join("\n");
    if !fixed_lines.is_empty() && (content.ends_with('\n') || content.ends_with("\r\n")) {
        out_str.push('\n');
    }

    (out_str, summaries)
}
