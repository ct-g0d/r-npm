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
            .or_else(|| find_global_npmrc_with_env(&env_lookup));

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
            .or_else(|| find_user_npmrc_with_env(&env_lookup));

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
