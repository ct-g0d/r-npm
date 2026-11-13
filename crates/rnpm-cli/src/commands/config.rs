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
        } => run_set(&key, value.as_deref(), global, location.as_deref(), &current_dir)?,
        ConfigAction::Get { key, extra_keys } => {
            run_get_keys(key.as_deref(), &extra_keys, &current_dir)?
        }
        ConfigAction::Delete {
            key,
            global,
            location,
        } => run_delete(&key, global, location.as_deref(), &current_dir)?,
        ConfigAction::List { json } => run_list(json, &current_dir)?,
        ConfigAction::Edit => run_edit(&current_dir)?,
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
        let opts = rnpm_config::ConfigOptions::new().project_dir(current_dir);
        let detailed = rnpm_config::Config::load_detailed(opts)?;
        print!("{}", detailed.format_text());
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

pub(crate) fn run_list(json: bool, current_dir: &Path) -> Result<()> {
    let opts = rnpm_config::ConfigOptions::new().project_dir(current_dir);
    let detailed = rnpm_config::Config::load_detailed(opts)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&detailed.effective)?);
    } else {
        print!("{}", detailed.format_text());
    }
    Ok(())
}

pub(crate) fn run_edit(current_dir: &Path) -> Result<()> {
    let user_npmrc = rnpm_config::get_default_user_npmrc();
    let path_to_edit = if current_dir.join(".npmrc").exists() {
        current_dir.join(".npmrc")
    } else {
        user_npmrc
    };
    println!("{}", path_to_edit.display());
    Ok(())
}

pub(crate) fn run_fix(current_dir: &Path) -> Result<()> {
    let opts = rnpm_config::ConfigOptions::new().project_dir(current_dir);
    let _ = rnpm_config::Config::load_detailed(opts)?;
    Ok(())
}

fn resolve_target_npmrc(global: bool, location: Option<&str>, current_dir: &Path) -> PathBuf {
    if global || location == Some("global") {
        rnpm_config::find_global_npmrc().unwrap_or_else(|| {
            rnpm_config::get_default_global_npmrc(&rnpm_config::find_global_prefix())
        })
    } else if location == Some("project") {
        current_dir.join(".npmrc")
    } else if location == Some("user") {
        rnpm_config::get_default_user_npmrc()
    } else if current_dir.join(".npmrc").exists() {
        current_dir.join(".npmrc")
    } else {
        rnpm_config::get_default_user_npmrc()
    }
}
