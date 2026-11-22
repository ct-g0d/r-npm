use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

pub(crate) struct LinkCommandArgs {
    pub package: Option<String>,
    pub workspace: Vec<String>,
    pub workspaces: bool,
    pub save: bool,
    pub save_dev: bool,
    pub save_optional: bool,
    pub save_peer: bool,
    pub save_prod: bool,
    pub no_save: bool,
}

pub(crate) struct UnlinkCommandArgs {
    pub package: Option<String>,
    pub workspace: Vec<String>,
    pub workspaces: bool,
}

pub(crate) fn run_link(args: LinkCommandArgs, current_dir: PathBuf) -> Result<()> {
    let global_prefix = rnpm_config::find_global_prefix();
    let start_time = std::time::Instant::now();
    let has_ws = !args.workspace.is_empty() || args.workspaces;

    if !has_ws {
        match args.package {
            None => {
                let _target_link = rnpm_install::link_package(&current_dir, &global_prefix)?;
                let elapsed_str = crate::format_duration(start_time.elapsed());
                println!("\nadded 1 package in {elapsed_str}");
            }
            Some(ref pkg) => {
                let _target_link =
                    rnpm_install::link_package_from_global(&current_dir, pkg, &global_prefix)?;
                if (args.save
                    || args.save_dev
                    || args.save_optional
                    || args.save_peer
                    || args.save_prod)
                    && !args.no_save
                {
                    save_link_dependency(&current_dir, pkg, &global_prefix, &args)?;
                }
                let elapsed_str = crate::format_duration(start_time.elapsed());
                println!("\nadded 1 package in {elapsed_str}");
            }
        }
        return Ok(());
    }

    // Workspaces mode
    let root = rnpm_config::find_workspace_root(&current_dir).unwrap_or_else(|| current_dir.clone());
    let members = crate::select_workspace_members(&root, &args.workspace, false)?;

    match args.package {
        None => {
            // `rnpm link -w <ws>` (no package args):
            // registers/links the workspace package(s) into the global prefix
            for member in &members {
                rnpm_install::link_package(&member.path, &global_prefix)?;
            }
            let count = members.len();
            let elapsed_str = crate::format_duration(start_time.elapsed());
            let pkg_str = if count == 1 { "package" } else { "packages" };
            println!("\nadded {count} {pkg_str} in {elapsed_str}");
        }
        Some(ref pkg) => {
            // `rnpm link <pkg> -w <ws>` (with package args):
            // links the globally-registered <pkg> into targeted workspace(s)
            let global_nm = rnpm_config::find_global_node_modules(&global_prefix);
            let source_pkg = global_nm.join(pkg);
            if !source_pkg.exists() && !rnpm_fs::is_junction(&source_pkg).unwrap_or(false) {
                return Err(anyhow!(
                    "npm error code ENOENT\nnpm error package '{}' not found in global node_modules ({})\nnpm error Did you run 'rnpm link' in '{}' first?",
                    pkg,
                    global_nm.display(),
                    pkg,
                ));
            }

            let real_target = source_pkg.canonicalize().unwrap_or_else(|_| source_pkg.clone());

            for member in &members {
                rnpm_install::link_package_from_global(&member.path, pkg, &global_prefix)?;

                if (args.save
                    || args.save_dev
                    || args.save_optional
                    || args.save_peer
                    || args.save_prod)
                    && !args.no_save
                {
                    save_link_dependency(&member.path, pkg, &global_prefix, &args)?;
                }
            }

            // Also link in root node_modules if root has node_modules
            let root_nm = root.join("node_modules");
            if root_nm.is_dir() {
                let root_link = root_nm.join(pkg);
                if !root_link.exists() && !rnpm_fs::is_junction(&root_link).unwrap_or(false) {
                    if let Some(parent) = root_link.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = rnpm_fs::create_junction(&root_link, &real_target);
                }
            }

            let total = members.len();
            let elapsed_str = crate::format_duration(start_time.elapsed());
            let pkg_str = if total == 1 { "package" } else { "packages" };
            println!("\nadded {total} {pkg_str} in {elapsed_str}");
        }
    }

    Ok(())
}

fn compute_relative_path(from: &Path, to: &Path) -> Option<String> {
    let from_canon = from.canonicalize().unwrap_or_else(|_| from.to_path_buf());
    let to_canon = to.canonicalize().unwrap_or_else(|_| to.to_path_buf());

    let from_components: Vec<_> = from_canon.components().collect();
    let to_components: Vec<_> = to_canon.components().collect();

    if from_components.first() != to_components.first() {
        return None;
    }

    let mut common_len = 0;
    while common_len < from_components.len()
        && common_len < to_components.len()
        && from_components[common_len] == to_components[common_len]
    {
        common_len += 1;
    }

    let count = from_components.len().saturating_sub(common_len);
    let mut rel_parts: Vec<&str> = vec![".."; count];
    for comp in &to_components[common_len..] {
        rel_parts.push(comp.as_os_str().to_str()?);
    }

    if rel_parts.is_empty() {
        Some(".".to_string())
    } else {
        Some(rel_parts.join("/"))
    }
}

fn save_link_dependency(
    target_dir: &Path,
    pkg_name: &str,
    global_prefix: &Path,
    args: &LinkCommandArgs,
) -> Result<()> {
    let manifest_path = target_dir.join("package.json");
    if !manifest_path.exists() {
        return Ok(());
    }

    let global_nm = rnpm_config::find_global_node_modules(global_prefix);
    let source_pkg = global_nm.join(pkg_name);
    let real_target = source_pkg.canonicalize().unwrap_or_else(|_| source_pkg.clone());

    let dep_spec = if let Some(rel) = compute_relative_path(target_dir, &real_target) {
        format!("file:{rel}")
    } else {
        let src_manifest = rnpm_core::manifest::Manifest::from_file(real_target.join("package.json")).ok();
        let ver = src_manifest.and_then(|m| m.version).unwrap_or_else(|| "*".to_string());
        format!("^{ver}")
    };

    let section = if args.save_dev {
        "devDependencies"
    } else if args.save_optional {
        "optionalDependencies"
    } else if args.save_peer {
        "peerDependencies"
    } else {
        "dependencies"
    };

    let manifest = rnpm_core::manifest::Manifest::from_file(&manifest_path)?;
    let mut raw_val = manifest.raw_json.unwrap_or_else(|| {
        rnpm_core::ordered_json::OrderedJsonValue::Object(rnpm_core::ordered_json::OrderedJsonMap::new())
    });

    if let Some(map) = raw_val.as_object_mut() {
        if let Some(rnpm_core::ordered_json::OrderedJsonValue::Object(sec_map)) = map.get_mut(section) {
            sec_map.insert(pkg_name.to_string(), rnpm_core::ordered_json::OrderedJsonValue::String(dep_spec));
        } else {
            let mut sec_map = rnpm_core::ordered_json::OrderedJsonMap::new();
            sec_map.insert(pkg_name.to_string(), rnpm_core::ordered_json::OrderedJsonValue::String(dep_spec));
            map.insert(section.to_string(), rnpm_core::ordered_json::OrderedJsonValue::Object(sec_map));
        }
        let formatted = rnpm_core::manifest::Manifest::format_json_value(&raw_val, &manifest.format)?;
        std::fs::write(&manifest_path, formatted)?;
    }

    Ok(())
}

pub(crate) fn run_unlink(args: UnlinkCommandArgs, current_dir: PathBuf) -> Result<()> {
    let global_prefix = rnpm_config::find_global_prefix();
    let start_time = std::time::Instant::now();
    let has_ws = !args.workspace.is_empty() || args.workspaces;

    if !has_ws {
        match args.package {
            None => {
                if rnpm_install::unlink_package(&current_dir, &global_prefix)?.is_some() {
                    let elapsed_str = crate::format_duration(start_time.elapsed());
                    println!("removed 1 package in {elapsed_str}");
                }
            }
            Some(ref pkg) => {
                if rnpm_install::unlink_package_from_consumer(&current_dir, pkg)?.is_some() {
                    let elapsed_str = crate::format_duration(start_time.elapsed());
                    println!("removed 1 package in {elapsed_str}");
                }
            }
        }
        return Ok(());
    }

    // Workspaces unlink
    let root = rnpm_config::find_workspace_root(&current_dir).unwrap_or_else(|| current_dir.clone());
    let members = crate::select_workspace_members(&root, &args.workspace, false)?;

    match args.package {
        None => {
            let mut removed = 0;
            for member in &members {
                if rnpm_install::unlink_package(&member.path, &global_prefix)?.is_some() {
                    removed += 1;
                }
            }
            if removed > 0 {
                let elapsed_str = crate::format_duration(start_time.elapsed());
                let pkg_str = if removed == 1 { "package" } else { "packages" };
                println!("removed {removed} {pkg_str} in {elapsed_str}");
            }
        }
        Some(ref pkg) => {
            let mut removed = 0;
            for member in &members {
                if rnpm_install::unlink_package_from_consumer(&member.path, pkg)?.is_some() {
                    removed += 1;
                }
            }
            if removed > 0 {
                let elapsed_str = crate::format_duration(start_time.elapsed());
                let pkg_str = if removed == 1 { "package" } else { "packages" };
                println!("removed {removed} {pkg_str} in {elapsed_str}");
            }
        }
    }

    Ok(())
}
