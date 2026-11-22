#[path = "config_report.rs"]
mod report;

use crate::ConfigAction;
use anyhow::Result;
use std::path::{Path, PathBuf};

pub(crate) fn run(action: ConfigAction, current_dir: PathBuf) -> Result<()> {
    match action {
        ConfigAction::Set {
            key,
            value,
            global,
            location,
        } => run_set(
            &key,
            value.as_deref(),
            global,
            location.as_deref(),
            &current_dir,
        )?,
        ConfigAction::Get { key, extra_keys } => {
            run_get_keys(key.as_deref(), &extra_keys, &current_dir)?
        }
        ConfigAction::Delete {
            key,
            global,
            location,
        } => run_delete(&key, global, location.as_deref(), &current_dir)?,
        ConfigAction::List { json, long } => report::run(json, long, &current_dir)?,
        ConfigAction::Edit {
            editor,
            global,
            location,
        } => run_edit(editor, global, location.as_deref(), &current_dir)?,
        ConfigAction::Fix => run_fix(&current_dir)?,
    }
    Ok(())
}

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
    rnpm_config::set_config_value_in_file(&target_path, real_key, real_val)?;
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

pub(crate) fn run_delete(
    key: &str,
    global: bool,
    location: Option<&str>,
    current_dir: &Path,
) -> Result<()> {
    let target_path = resolve_target_npmrc(global, location, current_dir);
    let _ = rnpm_config::delete_config_value_from_file(&target_path, key)?;
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

pub(crate) fn run_fix(current_dir: &Path) -> Result<()> {
    let opts = rnpm_config::ConfigOptions::new().project_dir(current_dir);
    let _ = rnpm_config::Config::load_detailed(opts)?;
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
    } else if location == Some("user") {
        (rnpm_config::get_default_user_npmrc(), "user")
    } else if current_dir.join(".npmrc").exists() {
        (current_dir.join(".npmrc"), "project")
    } else {
        (rnpm_config::get_default_user_npmrc(), "user")
    }
}

fn resolve_target_npmrc(global: bool, location: Option<&str>, current_dir: &Path) -> PathBuf {
    resolve_target_npmrc_with_location(global, location, current_dir).0
}
