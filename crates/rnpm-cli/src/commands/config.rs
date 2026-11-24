#[path = "config_report.rs"]
mod report;

use crate::ConfigAction;
use anyhow::Result;
use std::path::{Path, PathBuf};

pub(crate) fn run(action: ConfigAction, current_dir: PathBuf) -> Result<()> {
    match action {
        ConfigAction::Set {
            args,
            global,
            location,
        } => run_set_args(&args, global, location.as_deref(), &current_dir)?,
        ConfigAction::Get { key, extra_keys } => {
            run_get_keys(key.as_deref(), &extra_keys, &current_dir)?
        }
        ConfigAction::Delete {
            key,
            extra_keys,
            global,
            location,
        } => run_delete_keys(&key, &extra_keys, global, location.as_deref(), &current_dir)?,
        ConfigAction::List { json, long } => report::run(json, long, &current_dir)?,
        ConfigAction::Edit {
            editor,
            global,
            location,
        } => run_edit(editor, global, location.as_deref(), &current_dir)?,
        ConfigAction::Fix { location, global } => {
            run_fix(location.as_deref(), global, &current_dir)?
        }
    }
    Ok(())
}

pub(crate) fn parse_key_values(args: &[String]) -> Vec<(String, String)> {
    let mut kv = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if let Some((k, v)) = args[i].split_once('=') {
            kv.push((k.trim().to_string(), v.trim().to_string()));
            i += 1;
        } else if i + 1 < args.len() && !args[i + 1].contains('=') {
            kv.push((args[i].trim().to_string(), args[i + 1].trim().to_string()));
            i += 2;
        } else {
            kv.push((args[i].trim().to_string(), String::new()));
            i += 1;
        }
    }
    kv
}

pub(crate) fn run_set_args(
    args: &[String],
    global: bool,
    location: Option<&str>,
    current_dir: &Path,
) -> Result<()> {
    let pairs = parse_key_values(args);
    let target_path = resolve_target_npmrc(global, location, current_dir);
    for (k, v) in pairs {
        if v.is_empty() {
            let _ = rnpm_config::delete_config_value_from_file(&target_path, &k)?;
        } else {
            rnpm_config::set_config_value_in_file(&target_path, &k, &v)?;
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn run_set(
    key: &str,
    value: Option<&str>,
    global: bool,
    location: Option<&str>,
    current_dir: &Path,
) -> Result<()> {
    let (real_key, real_val) = match value {
        Some(v) => (key, v),
        None => {
            if let Some((k, v)) = key.split_once('=') {
                (k, v)
            } else {
                (key, "")
            }
        }
    };
    let target_path = resolve_target_npmrc(global, location, current_dir);
    if real_val.is_empty() {
        let _ = rnpm_config::delete_config_value_from_file(&target_path, real_key)?;
    } else {
        rnpm_config::set_config_value_in_file(&target_path, real_key, real_val)?;
    }
    Ok(())
}

/// `npm config get a b c` prints `key=value` lines; one key prints the value.
pub(crate) fn run_get_keys(key: Option<&str>, extra: &[String], current_dir: &Path) -> Result<()> {
    if extra.is_empty() {
        return run_get(key, current_dir);
    }
    let config = rnpm_config::Config::load(Some(current_dir))?;
    for k in key.into_iter().chain(extra.iter().map(String::as_str)) {
        let value = config
            .get(k)
            .map(str::to_string)
            .or_else(|| rnpm_config::npm_default(k))
            .unwrap_or_else(|| "undefined".into());
        println!("{k}={value}");
    }
    Ok(())
}

pub(crate) fn run_get(key: Option<&str>, current_dir: &Path) -> Result<()> {
    if let Some(key_str) = key {
        let config = rnpm_config::Config::load(Some(current_dir))?;
        match config
            .get(key_str)
            .map(str::to_string)
            .or_else(|| rnpm_config::npm_default(key_str))
        {
            Some(val) => println!("{val}"),
            None => println!("undefined"),
        }
    } else {
        report::run(false, false, current_dir)?;
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn run_delete(
    key: &str,
    global: bool,
    location: Option<&str>,
    current_dir: &Path,
) -> Result<()> {
    run_delete_keys(key, &[], global, location, current_dir)
}

pub(crate) fn run_delete_keys(
    key: &str,
    extra_keys: &[String],
    global: bool,
    location: Option<&str>,
    current_dir: &Path,
) -> Result<()> {
    let target_path = resolve_target_npmrc(global, location, current_dir);
    let _ = rnpm_config::delete_config_value_from_file(&target_path, key)?;
    for extra in extra_keys {
        let _ = rnpm_config::delete_config_value_from_file(&target_path, extra)?;
    }
    Ok(())
}

pub(crate) fn run_edit(
    editor: Option<String>,
    global: bool,
    location: Option<&str>,
    current_dir: &Path,
) -> Result<()> {
    let (target_path, where_str) =
        resolve_target_npmrc_with_location(global, location, current_dir);

    if !target_path.exists() {
        if let Some(parent) = target_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let header = format!(
            ";;;;\n\
             ; npm {where_str}config file: {}\n\
             ; this is a simple ini-formatted file\n\
             ; lines that start with semi-colons are comments\n\
             ; run `npm help 7 config` for documentation of the various options\n\
             ;\n\
             ; Configs like `@scope:registry` map a scope to a given registry url.\n\
             ;\n\
             ; Configs like `//<hostname>/:_authToken` are auth that is restricted\n\
             ; to the registry host specified.\n\n",
            target_path.display()
        );
        std::fs::write(&target_path, header)?;
    }

    let editor_str = crate::commands::edit::resolve_editor_command(editor, current_dir)?;
    let mut tokens = crate::commands::edit::parse_editor_command(&editor_str);
    if tokens.is_empty() {
        return Err(anyhow::anyhow!(
            "npm error code ENOENT\nnpm error no editor configured"
        ));
    }

    let bin = tokens.remove(0);
    let mut spawn_args = tokens;
    spawn_args.push(target_path.to_string_lossy().to_string());

    let status = std::process::Command::new(&bin)
        .args(&spawn_args)
        .current_dir(current_dir)
        .status()
        .map_err(|e| anyhow::anyhow!("npm error failed to spawn editor '{}': {e}", bin))?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        return Err(anyhow::anyhow!(
            "npm error editor process exited with code: {code}"
        ));
    }

    Ok(())
}

pub(crate) fn run_fix(
    location: Option<&str>,
    global: bool,
    current_dir: &Path,
) -> Result<()> {
    let mut targets = Vec::new();
    if global || location == Some("global") {
        let global_path = rnpm_config::find_global_npmrc().unwrap_or_else(|| {
            rnpm_config::get_default_global_npmrc(&rnpm_config::find_global_prefix())
        });
        targets.push(("global", global_path));
    } else if location == Some("project") {
        targets.push(("project", current_dir.join(".npmrc")));
    } else if location == Some("user") {
        targets.push(("user", rnpm_config::get_default_user_npmrc()));
    } else {
        // Default: inspect project, user, and global if they exist
        let project_path = current_dir.join(".npmrc");
        if project_path.exists() {
            targets.push(("project", project_path));
        }
        let user_path = rnpm_config::get_default_user_npmrc();
        if user_path.exists() {
            targets.push(("user", user_path));
        }
        if let Some(global_path) = rnpm_config::find_global_npmrc() {
            if global_path.exists() {
                targets.push(("global", global_path));
            }
        }
    }

    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    let registry_url = config.npmrc.registry;
    let host = registry_url.host_str().unwrap_or_default();
    let port = registry_url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = if registry_url.path().is_empty() {
        "/".to_string()
    } else {
        format!("{}/", registry_url.path().trim_end_matches('/'))
    };
    let nerfed_reg = format!("//{host}{port}{path}");

    let mut all_summaries = Vec::new();

    for (where_name, target_path) in targets {
        if !target_path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&target_path)?;
        let (fixed_content, summaries) =
            rnpm_config::fix_npmrc_content(&content, where_name, &nerfed_reg);
        if !summaries.is_empty() {
            std::fs::write(&target_path, fixed_content)?;
            all_summaries.extend(summaries);
        }
    }

    if !all_summaries.is_empty() {
        println!("The following configuration problems have been repaired:\n");
        println!("{}", all_summaries.join("\n"));
    }

    Ok(())
}

fn resolve_target_npmrc_with_location(
    global: bool,
    location: Option<&str>,
    current_dir: &Path,
) -> (PathBuf, &'static str) {
    if global || location == Some("global") {
        let path = rnpm_config::find_global_npmrc().unwrap_or_else(|| {
            rnpm_config::get_default_global_npmrc(&rnpm_config::find_global_prefix())
        });
        (path, "global")
    } else if location == Some("project") {
        (current_dir.join(".npmrc"), "project")
    } else {
        // In npm 11.20.0, bare `config edit` (and location=user) defaults to user config
        // (~/.npmrc or explicit --userconfig / npm_config_userconfig)
        // unless --location=project or --location=global is explicitly passed!
        (rnpm_config::get_default_user_npmrc(), "user")
    }
}

fn resolve_target_npmrc(global: bool, location: Option<&str>, current_dir: &Path) -> PathBuf {
    resolve_target_npmrc_with_location(global, location, current_dir).0
}
