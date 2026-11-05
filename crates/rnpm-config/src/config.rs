use std::env;
use std::path::{Path, PathBuf};
use std::collections::BTreeMap;
use crate::error::ConfigError;
use crate::npmrc::Npmrc;

#[derive(Debug, Clone, Default)]
pub struct ConfigOptions<'a> {
    pub project_dir: Option<&'a Path>,
    pub workspace_root: Option<&'a Path>,
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

    pub fn globalconfig(mut self, path: PathBuf) -> Self {
        self.globalconfig = Some(path);
        self
    }

    pub fn userconfig(mut self, path: PathBuf) -> Self {
        self.userconfig = Some(path);
        self
    }

    pub fn with_cli<KeyType: Into<String>, ValType: Into<String>>(mut self, key: KeyType, value: ValType) -> Self {
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
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|val| match val.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        })
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

        let mut base_npmrc = Npmrc::default();

        let global_config_path = options
            .globalconfig
            .clone()
            .or_else(|| {
                options
                    .cli_overrides
                    .as_ref()
                    .and_then(|cli| cli.get("globalconfig").map(PathBuf::from))
            })
            .or_else(|| {
                env_lookup("NPM_CONFIG_GLOBALCONFIG")
                    .or_else(|| env_lookup("npm_config_globalconfig"))
                    .map(PathBuf::from)
            })
            .or_else(|| find_global_npmrc_with_env(env_lookup));

        if let Some(path) = global_config_path {
            if path.exists() {
                let global_config = Npmrc::from_file(&path)?;
                base_npmrc.merge(global_config);
            }
        }

        let user_config_path = options
            .userconfig
            .clone()
            .or_else(|| {
                options
                    .cli_overrides
                    .as_ref()
                    .and_then(|cli| cli.get("userconfig").map(PathBuf::from))
            })
            .or_else(|| {
                env_lookup("NPM_CONFIG_USERCONFIG")
                    .or_else(|| env_lookup("npm_config_userconfig"))
                    .map(PathBuf::from)
            })
            .or_else(|| {
                base_npmrc.settings.get("userconfig").map(PathBuf::from)
            })
            .or_else(|| find_user_npmrc_with_env(env_lookup));

        if let Some(path) = user_config_path {
            if path.exists() {
                let user_config = Npmrc::from_file(&path)?;
                base_npmrc.merge(user_config);
            }
        }

        let ws_root = options.workspace_root.map(|path| path.to_path_buf()).or_else(|| {
            options.project_dir.and_then(find_workspace_root)
        });

        if let Some(ws_path) = ws_root {
            let ws_npmrc_path = ws_path.join(".npmrc");
            if ws_npmrc_path.exists() {
                let ws_config = Npmrc::from_file(&ws_npmrc_path)?;
                base_npmrc.merge(ws_config);
            }
        }

        if let Some(dir) = options.project_dir {
            let project_npmrc_path = dir.join(".npmrc");
            if project_npmrc_path.exists() {
                let project_config = Npmrc::from_file(&project_npmrc_path)?;
                base_npmrc.merge(project_config);
            }
        }

        let all_env: BTreeMap<String, String> = if let Some(map) = options.env_vars {
            map
        } else {
            env::vars().collect()
        };

        for (raw_key, value) in all_env {
            let lower_key = raw_key.to_ascii_lowercase();
            if let Some(rest) = lower_key.strip_prefix("npm_config_") {
                if rest.is_empty() {
                    continue;
                }
                let (prefix, body) = if rest.starts_with('_') {
                    ("_", &rest[1..])
                } else {
                    ("", rest)
                };
                let dashed = format!("{prefix}{}", body.replace('_', "-"));
                base_npmrc.set(&dashed, &value)?;
                if dashed != rest {
                    let _ = base_npmrc.set(rest, &value);
                }
            }
        }

        if let Some(cli_map) = options.cli_overrides {
            for (key, value) in cli_map {
                let clean_key = key.strip_prefix("--").unwrap_or(&key);
                let lower_clean = clean_key.to_ascii_lowercase();
                let (prefix, body) = if lower_clean.starts_with('_') {
                    ("_", &lower_clean[1..])
                } else {
                    ("", lower_clean.as_str())
                };
                let dashed = format!("{prefix}{}", body.replace('_', "-"));
                base_npmrc.set(clean_key, &value)?;
                if clean_key != dashed {
                    let _ = base_npmrc.set(&dashed, &value);
                }
            }
        }

        Ok(Self { npmrc: base_npmrc })
    }

    pub fn load_detailed(options: ConfigOptions<'_>) -> Result<ConfigDetailed, ConfigError> {
        let env_lookup = |var_name: &str| -> Option<String> {
            if let Some(ref map) = options.env_vars {
                map.get(var_name).cloned()
            } else {
                env::var(var_name).ok()
            }
        };

        let mut layers = Vec::new();
        let mut base_npmrc = Npmrc::default();

        let global_config_path = options
            .globalconfig
            .clone()
            .or_else(|| {
                options
                    .cli_overrides
                    .as_ref()
                    .and_then(|cli| cli.get("globalconfig").map(PathBuf::from))
            })
            .or_else(|| {
                env_lookup("NPM_CONFIG_GLOBALCONFIG")
                    .or_else(|| env_lookup("npm_config_globalconfig"))
                    .map(PathBuf::from)
            })
            .or_else(|| find_global_npmrc_with_env(&env_lookup));

        if let Some(path) = &global_config_path {
            if path.exists() {
                let global_config = Npmrc::from_file(path)?;
                layers.push(ConfigLayer {
                    name: "global".to_string(),
                    source: Some(path.clone()),
                    settings: global_config.scrubbed_settings(),
                });
                base_npmrc.merge(global_config);
            }
        }

        let user_config_path = options
            .userconfig
            .clone()
            .or_else(|| {
                options
                    .cli_overrides
                    .as_ref()
                    .and_then(|cli| cli.get("userconfig").map(PathBuf::from))
            })
            .or_else(|| {
                env_lookup("NPM_CONFIG_USERCONFIG")
                    .or_else(|| env_lookup("npm_config_userconfig"))
                    .map(PathBuf::from)
            })
            .or_else(|| {
                base_npmrc.settings.get("userconfig").map(PathBuf::from)
            })
            .or_else(|| find_user_npmrc_with_env(&env_lookup));

        if let Some(path) = &user_config_path {
            if path.exists() {
                let user_config = Npmrc::from_file(path)?;
                layers.push(ConfigLayer {
                    name: "user".to_string(),
                    source: Some(path.clone()),
                    settings: user_config.scrubbed_settings(),
                });
                base_npmrc.merge(user_config);
            }
        }

        let ws_root = options.workspace_root.map(|path| path.to_path_buf()).or_else(|| {
            options.project_dir.and_then(find_workspace_root)
        });

        if let Some(ws_path) = &ws_root {
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
            env::vars().collect()
        };

        let mut env_layer_settings = BTreeMap::new();
        for (raw_key, value) in all_env {
            let lower_key = raw_key.to_ascii_lowercase();
            if let Some(rest) = lower_key.strip_prefix("npm_config_") {
                if rest.is_empty() {
                    continue;
                }
                let (prefix, body) = if rest.starts_with('_') {
                    ("_", &rest[1..])
                } else {
                    ("", rest)
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
            }
        }

        if !env_layer_settings.is_empty() {
            layers.push(ConfigLayer {
                name: "env".to_string(),
                source: None,
                settings: env_layer_settings,
            });
        }

        if let Some(cli_map) = options.cli_overrides {
            let mut cli_layer_settings = BTreeMap::new();
            for (key, value) in cli_map {
                let clean_key = key.strip_prefix("--").unwrap_or(&key);
                let lower_clean = clean_key.to_ascii_lowercase();
                let (prefix, body) = if lower_clean.starts_with('_') {
                    ("_", &lower_clean[1..])
                } else {
                    ("", lower_clean.as_str())
                };
                let dashed = format!("{prefix}{}", body.replace('_', "-"));
                let val_display = if crate::npmrc::is_sensitive_credential_key(clean_key) {
                    crate::npmrc::mask_credential(&value)
                } else {
                    value.clone()
                };
                cli_layer_settings.insert(clean_key.to_string(), val_display);
                base_npmrc.set(clean_key, &value)?;
                if clean_key != dashed {
                    let _ = base_npmrc.set(&dashed, &value);
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

        let global_prefix = find_global_prefix_with_env(&env_lookup);
        let local_prefix = options.project_dir.map(find_local_prefix).unwrap_or_else(|| {
            env::current_dir().map(|d| find_local_prefix(&d)).unwrap_or_else(|_| PathBuf::from("."))
        });

        let effective = base_npmrc.scrubbed_settings();

        Ok(ConfigDetailed {
            layers,
            effective,
            global_prefix,
            local_prefix,
        })
    }
}

pub fn find_workspace_root(project_dir: &Path) -> Option<PathBuf> {
    let project_dir_canon = project_dir.canonicalize().unwrap_or_else(|_| project_dir.to_path_buf());
    let mut current = project_dir.parent();
    while let Some(dir) = current {
        let pkg_json = dir.join("package.json");
        if pkg_json.exists() {
            if let Ok(manifest) = rnpm_core::manifest::Manifest::from_file(&pkg_json) {
                if !manifest.workspace_patterns().is_empty() {
                    if let Ok(members) = rnpm_core::workspace::discover_workspaces_from_manifest(dir, &manifest) {
                        for member in members {
                            let member_canon = member.path.canonicalize().unwrap_or_else(|_| member.path.clone());
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
    if let Some(prefix) = lookup("PREFIX") {
        let path = PathBuf::from(prefix).join("etc").join("npmrc");
        if path.exists() {
            return Some(path);
        }
    }
    if let Some(appdata) = lookup("APPDATA") {
        let path = PathBuf::from(appdata).join("npm").join("etc").join("npmrc");
        if path.exists() {
            return Some(path);
        }
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
                out.push_str(&format!("; \"{}\" config from {}\n", layer.name, src.display()));
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

        out.push_str(&format!("; npm local prefix = {}\n", self.local_prefix.display()));
        out.push_str(&format!("; npm global prefix = {}\n", self.global_prefix.display()));
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
            return PathBuf::from(userprofile).join("AppData").join("Roaming").join("npm");
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
    find_local_prefix(start_dir).join("node_modules").join(".bin")
}

/// Resolves the local node_modules directory for a project.
pub fn find_local_node_modules(start_dir: &Path) -> PathBuf {
    find_local_prefix(start_dir).join("node_modules")
}

/// Returns default path for global .npmrc given a prefix.
pub fn get_default_global_npmrc(prefix: &Path) -> PathBuf {
    prefix.join("etc").join("npmrc")
}

/// Returns default path for user .npmrc.
pub fn get_default_user_npmrc() -> PathBuf {
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

/// Updates or appends a key-value setting in an .npmrc file on disk.
/// Preserves comments and existing lines.
pub fn set_config_value_in_file(path: &Path, key: &str, value: &str) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
    }

    let key_trimmed = key.trim();
    let value_trimmed = value.trim();

    if key_trimmed.contains('\n')
        || key_trimmed.contains('\r')
        || value_trimmed.contains('\n')
        || value_trimmed.contains('\r')
    {
        return Err(ConfigError::InvalidLine("Newline in key or value".to_string()));
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
                    lines.push(format!("{key_trimmed}={value_trimmed}"));
                    updated = true;
                    continue;
                }
            }
            lines.push(line.to_string());
        }
    }

    if !updated {
        lines.push(format!("{key_trimmed}={value_trimmed}"));
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
