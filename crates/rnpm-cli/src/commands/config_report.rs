use anyhow::Result;
use rnpm_core::ordered_json::{OrderedJsonMap as Map, OrderedJsonValue as Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

struct Layer {
    name: String,
    source: String,
    data: Map,
}

fn base_defaults() -> Result<Map> {
    static DEFAULTS: OnceLock<Map> = OnceLock::new();
    if let Some(cached) = DEFAULTS.get() {
        return Ok(cached.clone());
    }
    let parsed = serde_json::from_str::<Value>(include_str!("config_defaults.json"))?
        .as_object()
        .cloned()
        .unwrap_or_default();
    Ok(DEFAULTS.get_or_init(|| parsed).clone())
}

struct EnvSnapshot {
    npm_env_order: Vec<String>,
    proxy_vars: Vec<(String, String)>,
}

fn collect_env_snapshot(collect_npm_order: bool, collect_proxies: bool) -> EnvSnapshot {
    let mut npm_env_order = Vec::new();
    let mut proxy_vars = Vec::new();
    if !collect_npm_order && !collect_proxies {
        return EnvSnapshot {
            npm_env_order,
            proxy_vars,
        };
    }
    let mut seen_proxies = std::collections::HashSet::new();
    for (k, v) in std::env::vars() {
        if collect_npm_order
            && k.get(..11)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("npm_config_"))
        {
            if let Some(raw) = k.get(11..) {
                if !raw.is_empty() {
                    let norm = if raw.starts_with("//") {
                        raw.to_string()
                    } else {
                        let mut chars = raw.chars();
                        let first = chars.next().map(|c| c.to_ascii_lowercase());
                        let rest: String = chars
                            .map(|c| if c == '_' { '-' } else { c.to_ascii_lowercase() })
                            .collect();
                        match first {
                            Some(f) => format!("{f}{rest}"),
                            None => String::new(),
                        }
                    };
                    npm_env_order.push(norm);
                }
            }
        }
        if collect_proxies {
            let lower = k.to_ascii_lowercase();
            if ["http_proxy", "https_proxy", "proxy", "no_proxy"].contains(&lower.as_str())
                && seen_proxies.insert(lower)
            {
                proxy_vars.push((k, v));
            }
        }
    }
    if collect_proxies && cfg!(windows) {
        // Windows keeps its environment block sorted by uppercased name.
        proxy_vars.sort_by_key(|(k, _)| k.to_ascii_uppercase());
    }
    EnvSnapshot {
        npm_env_order,
        proxy_vars,
    }
}

fn typed(key: &str, text: &str, defaults: &Map) -> Value {
    if defaults.get(key).is_some_and(Value::is_array) {
        return Value::Array(
            text.split('\n')
                .map(|s| Value::String(s.to_string()))
                .collect(),
        );
    }
    if rnpm_config::is_boolean_npm_config_key(key)
        || defaults
            .get(key)
            .is_some_and(|v| matches!(v, Value::Bool(_)))
    {
        if text == "true" {
            return Value::Bool(true);
        }
        if text == "false" {
            return Value::Bool(false);
        }
    }
    if text == "null" {
        return Value::Null;
    }
    if defaults
        .get(key)
        .is_some_and(|v| matches!(v, Value::Number(_)))
    {
        if let Ok(number) = text.parse::<serde_json::Number>() {
            return Value::Number(number);
        }
    }
    Value::String(text.to_string())
}

fn private(key: &str) -> bool {
    const PROTECTED: &[&str] = &[
        "auth",
        "authToken",
        "certfile",
        "email",
        "keyfile",
        "password",
        "username",
    ];
    key.starts_with('_')
        || PROTECTED.contains(&key)
        || (key.starts_with("//")
            && (key.contains(":_") || PROTECTED.iter().any(|p| key.ends_with(&format!(":{p}")))))
}

pub(super) fn run(
    json: bool,
    long: bool,
    dir: &Path,
    config: Option<&rnpm_config::Config>,
) -> Result<()> {
    let node = rnpm_lifecycle::node_executable().unwrap_or_else(|| PathBuf::from("node"));
    let node_dir = node.parent().unwrap_or(Path::new("."));
    let node_prefix = if cfg!(windows) {
        node_dir.to_path_buf()
    } else {
        node_dir.parent().unwrap_or(node_dir).to_path_buf()
    };
    let npm_dir = if cfg!(windows) {
        node_prefix.join("node_modules").join("npm")
    } else {
        node_prefix.join("lib").join("node_modules").join("npm")
    };
    let home =
        std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap_or_default();
    let loaded_config;
    let config_ref = match config {
        Some(cfg) => cfg,
        None => {
            loaded_config = rnpm_config::Config::load(Some(dir))?;
            &loaded_config
        }
    };
    let mut defaults = base_defaults()?;
    for (key, value) in &mut defaults {
        if value.get("dynamic").is_none() {
            continue;
        }
        let dynamic = match key.as_str() {
            "prefix" => node_prefix.display().to_string(),
            "globalconfig" => rnpm_config::get_process_globalconfig()
                .map(|p| p.display().to_string())
                .or_else(|| std::env::var("NPM_CONFIG_GLOBALCONFIG").ok())
                .unwrap_or_else(|| {
                    rnpm_config::find_global_prefix()
                        .join("etc")
                        .join("npmrc")
                        .display()
                        .to_string()
                }),
            "userconfig" => Path::new(&home).join(".npmrc").display().to_string(),
            "init.module" => Path::new(&home).join(".npm-init.js").display().to_string(),
            "node-gyp" => npm_dir
                .join("node_modules")
                .join("node-gyp")
                .join("bin")
                .join("node-gyp.js")
                .display()
                .to_string(),
            "color" => {
                *value = Value::Bool(std::env::var_os("NO_COLOR").is_none());
                continue;
            }
            "unicode" => {
                *value = Value::Bool(
                    ["LC_ALL", "LC_CTYPE", "LANG"]
                        .iter()
                        .find_map(|key| std::env::var(key).ok().filter(|v| !v.is_empty()))
                        .is_some_and(|v| {
                            v.to_uppercase().ends_with("UTF8")
                                || v.to_uppercase().ends_with("UTF-8")
                        }),
                );
                continue;
            }
            "noproxy" => {
                // npm's default is "", shown as [""]; NO_PROXY is not read
                // into the setting.
                *value = Value::Array(vec![Value::String(String::new())]);
                continue;
            }
            _ => rnpm_config::npm_default(key).unwrap_or_default(),
        };
        *value = Value::String(dynamic);
    }
    let has_env_layer = config_ref.layers.iter().any(|l| l.name == "env");
    let env_snapshot = collect_env_snapshot(has_env_layer, !json && !long);
    let mut layers = vec![Layer {
        name: "default".into(),
        source: "default values".into(),
        data: defaults.clone(),
    }];
    let builtin = npm_dir.join("npmrc");
    if builtin.exists() {
        let data = rnpm_config::Npmrc::from_file(&builtin)?
            .scrubbed_settings()
            .into_iter()
            .map(|(k, v)| {
                let value = typed(&k, &v, &defaults);
                (k, value)
            })
            .collect();
        layers.push(Layer {
            name: "builtin".into(),
            source: builtin.display().to_string(),
            data,
        });
    }
    for layer in &config_ref.layers {
        let source = layer
            .source
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| {
                if layer.name == "env" {
                    "environment".into()
                } else {
                    "command line options".into()
                }
            });
        let data: Map = if layer.name == "env" {
            // Preserve OS environment insertion order (matching Node's Object.entries(process.env))
            // so `npm config list --json` key order matches on Linux, macOS, and Windows.
            let mut ordered = Map::new();
            let mut remaining = layer.settings.clone();
            remaining.remove("globalconfig");
            for norm in &env_snapshot.npm_env_order {
                if let Some(v) = remaining.remove(norm) {
                    let value = typed(norm, &v, &defaults);
                    ordered.insert(norm.clone(), value);
                }
            }
            for (k, v) in remaining {
                let value = typed(&k, &v, &defaults);
                ordered.insert(k, value);
            }
            ordered
        } else {
            layer
                .settings
                .iter()
                .filter(|(k, _)| k.as_str() != "globalconfig")
                .map(|(k, v)| {
                    let value = typed(k, v, &defaults);
                    (k.clone(), value)
                })
                .collect()
        };
        layers.push(Layer {
            name: layer.name.clone(),
            source,
            data,
        });
    }
    let cli = if layers.last().is_some_and(|l| l.name == "cli") {
        layers.last_mut().unwrap()
    } else {
        layers.push(Layer {
            name: "cli".into(),
            source: "command line options".into(),
            data: Map::new(),
        });
        layers.last_mut().unwrap()
    };
    if json {
        cli.data.insert("json".into(), Value::Bool(true));
    }
    if long {
        cli.data.insert("long".into(), Value::Bool(true));
    }
    if let Some(userconfig) = rnpm_config::get_process_userconfig() {
        cli.data.insert(
            "userconfig".into(),
            Value::String(userconfig.display().to_string()),
        );
    }
    let mut owners = BTreeMap::new();
    for (i, layer) in layers.iter().enumerate() {
        for key in layer.data.keys() {
            owners.insert(key.clone(), i);
        }
    }
    if json {
        let mut result = Map::new();
        for layer in layers.iter().rev() {
            for (key, value) in &layer.data {
                if !private(key) && !result.contains_key(key) {
                    result.insert(key.clone(), value.clone());
                }
            }
        }
        println!("{}", serde_json::to_string_pretty(&Value::Object(result))?);
        return Ok(());
    }
    let mut text = Vec::new();
    for (i, layer) in layers.iter().enumerate() {
        if (i == 0 && !long) || layer.data.is_empty() {
            continue;
        }
        text.push(format!("; \"{}\" config from {}", layer.name, layer.source));
        text.push(String::new());
        let mut keys: Vec<_> = layer.data.keys().collect();
        keys.sort();
        for key in keys {
            let display = if private(key) {
                "(protected)".into()
            } else {
                serde_json::to_string(&layer.data[key])?
            };
            let entry = format!("{key} = {display}");
            let owner = owners[key];
            text.push(if owner == i {
                entry
            } else {
                format!("; {entry} ; overridden by {}", layers[owner].name)
            });
        }
        text.push(String::new());
    }
    if !long {
        let version = crate::node_info::node_version_for(&node);
        let local_prefix = rnpm_config::find_local_prefix(dir);
        if !env_snapshot.proxy_vars.is_empty() {
            text.push("; environment-related config".into());
            text.push(String::new());
            for (k, v) in &env_snapshot.proxy_vars {
                text.push(format!("; {k} = {}", serde_json::to_string(v).unwrap_or_default()));
            }
            text.push(String::new());
        }
        text.extend([
            format!("; node bin location = {}", node.display()),
            format!("; node version = {version}"),
            format!("; npm local prefix = {}", local_prefix.display()),
            "; npm version = 11.20.0".into(),
            format!("; cwd = {}", dir.display()),
            format!("; HOME = {home}"),
            "; Run `npm config ls -l` to show all defaults.".into(),
        ]);
    }
    let manifest = std::fs::read_to_string(dir.join("package.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    if let Some(publish) = manifest
        .as_ref()
        .and_then(|m| m.get("publishConfig"))
        .and_then(serde_json::Value::as_object)
    {
        text.extend([
            format!(
                "; \"publishConfig\" from {}",
                dir.join("package.json").display()
            ),
            "; This set of config values will be used at publish-time.".into(),
            String::new(),
        ]);
        for (key, value) in publish {
            text.push(format!(
                "{key} = {}",
                if private(key) {
                    "(protected)".into()
                } else {
                    serde_json::to_string(value)?
                }
            ));
        }
    }
    println!("{}", text.join("\n").trim());
    Ok(())
}
