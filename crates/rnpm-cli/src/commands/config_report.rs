use anyhow::Result;
use rnpm_core::ordered_json::{OrderedJsonMap as Map, OrderedJsonValue as Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

struct Layer {
    name: String,
    source: String,
    data: Map,
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

pub(super) fn run(json: bool, long: bool, dir: &Path) -> Result<()> {
    let node = rnpm_lifecycle::node_executable().unwrap_or_else(|| PathBuf::from("node"));
    let node_dir = node.parent().unwrap_or(Path::new("."));
    let npm_dir = node_dir.join("node_modules").join("npm");
    let home =
        std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap_or_default();
    let mut defaults: Map = serde_json::from_str::<Value>(include_str!("config_defaults.json"))?
        .as_object()
        .cloned()
        .unwrap_or_default();
    for (key, value) in &mut defaults {
        if value.get("dynamic").is_none() {
            continue;
        }
        let dynamic = match key.as_str() {
            "prefix" => node_dir.display().to_string(),
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
                *value = Value::Array(vec![Value::String(
                    std::env::var("NO_PROXY")
                        .or_else(|_| std::env::var("no_proxy"))
                        .unwrap_or_default(),
                )]);
                continue;
            }
            _ => rnpm_config::npm_default(key).unwrap_or_default(),
        };
        *value = Value::String(dynamic);
    }
    let detailed =
        rnpm_config::Config::load_detailed(rnpm_config::ConfigOptions::new().project_dir(dir))?;
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
    for layer in detailed.layers {
        let source = layer
            .source
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| {
                if layer.name == "env" {
                    "environment".into()
                } else {
                    "command line options".into()
                }
            });
        let data = layer
            .settings
            .into_iter()
            .filter(|(k, _)| k != "globalconfig")
            .map(|(k, v)| {
                let value = typed(&k, &v, &defaults);
                (k, value)
            })
            .collect();
        layers.push(Layer {
            name: layer.name,
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
        let version = std::process::Command::new(&node)
            .arg("--version")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        text.extend([
            format!("; node bin location = {}", node.display()),
            format!("; node version = {version}"),
            format!("; npm local prefix = {}", detailed.local_prefix.display()),
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
