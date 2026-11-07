use anyhow::{anyhow, Context, Result};
use rnpm_config::{find_global_bin_dir, find_global_node_modules};
use rnpm_core::manifest::Manifest;
use rnpm_fs::junction::{create_junction, is_junction, remove_dir_all_safe, remove_junction};
use rnpm_shim::generator::create_shim_trio;
use rnpm_shim::normalize_shebang;
use std::path::{Path, PathBuf};

/// Invoked with no arguments: `npm link`
/// Creates a global link (NTFS junction on Windows, symlink on Unix) from global prefix
/// 'node_modules/<pkg>' to current directory. Also installs bin shims in global bin directory.
pub fn link_package(current_dir: &Path, global_prefix: &Path) -> Result<PathBuf> {
    let manifest_path = current_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow!(
            "npm error code ENOENT\nnpm error package.json not found in {}",
            current_dir.display()
        ));
    }

    let manifest =
        Manifest::from_file(&manifest_path).context("Failed to parse package.json for npm link")?;

    let pkg_name = manifest.name.as_deref().ok_or_else(|| {
        anyhow!("npm error code EINVALIDPKG\nnpm error package.json missing 'name' field")
    })?;

    let global_nm = find_global_node_modules(global_prefix);
    let target_link = global_nm.join(pkg_name);

    if let Some(parent) = target_link.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if target_link.exists() || is_junction(&target_link).unwrap_or(false) {
        if is_junction(&target_link).unwrap_or(false) {
            remove_junction(&target_link)?;
        } else if target_link.is_dir() {
            remove_dir_all_safe(&target_link)?;
        } else {
            let _ = std::fs::remove_file(&target_link);
        }
    }

    create_junction(&target_link, current_dir).map_err(|e| {
        anyhow!(
            "Failed to create global link at '{}' -> '{}': {e}",
            target_link.display(),
            current_dir.display()
        )
    })?;

    // Install bin shims in global bin directory
    let global_bin = find_global_bin_dir(global_prefix);
    std::fs::create_dir_all(&global_bin)?;

    for (bin_name, script_rel) in manifest.bin_entries() {
        let target_script = current_dir.join(&script_rel);
        if target_script.exists() {
            let _ = normalize_shebang(&target_script);
        }
        let _ = create_shim_trio(&target_script, &global_bin, &bin_name)?;
    }

    Ok(target_link)
}

/// Invoked with package name: `npm link <pkg>`
/// Links the global package from global prefix into local 'node_modules/<pkg>'.
/// Also installs bin shims in local 'node_modules/.bin'.
pub fn link_package_from_global(
    consumer_dir: &Path,
    package_name: &str,
    global_prefix: &Path,
) -> Result<PathBuf> {
    let global_nm = find_global_node_modules(global_prefix);
    let source_pkg = global_nm.join(package_name);

    if !source_pkg.exists() && !is_junction(&source_pkg).unwrap_or(false) {
        return Err(anyhow!(
            "npm error code ENOENT\nnpm error package '{}' not found in global node_modules ({})\nnpm error Did you run 'rnpm link' in '{}' first?",
            package_name,
            global_nm.display(),
            package_name,
        ));
    }

    let local_nm = consumer_dir.join("node_modules");
    let target_link = local_nm.join(package_name);

    if let Some(parent) = target_link.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if target_link.exists() || is_junction(&target_link).unwrap_or(false) {
        if is_junction(&target_link).unwrap_or(false) {
            remove_junction(&target_link)?;
        } else if target_link.is_dir() {
            remove_dir_all_safe(&target_link)?;
        } else {
            let _ = std::fs::remove_file(&target_link);
        }
    }

    let real_target = source_pkg
        .canonicalize()
        .unwrap_or_else(|_| source_pkg.clone());
    create_junction(&target_link, &real_target).map_err(|e| {
        anyhow!(
            "Failed to link package '{}' into '{}': {e}",
            package_name,
            target_link.display()
        )
    })?;

    // Install bin shims in local node_modules/.bin if package has binaries
    let manifest_path = real_target.join("package.json");
    if manifest_path.exists() {
        if let Ok(m) = Manifest::from_file(&manifest_path) {
            let local_bin = local_nm.join(".bin");
            std::fs::create_dir_all(&local_bin)?;
            for (bin_name, script_rel) in m.bin_entries() {
                let target_script = target_link.join(&script_rel);
                if target_script.exists() {
                    let _ = normalize_shebang(&target_script);
                }
                let _ = create_shim_trio(&target_script, &local_bin, &bin_name)?;
            }
        }
    }

    Ok(target_link)
}

/// Invoked with no arguments in linked package: `npm unlink`
/// Unlinks global entry from global prefix and removes global bin shims.
pub fn unlink_package(current_dir: &Path, global_prefix: &Path) -> Result<Option<PathBuf>> {
    let manifest_path = current_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow!(
            "npm error code ENOENT\nnpm error package.json not found in {}",
            current_dir.display()
        ));
    }

    let manifest = Manifest::from_file(&manifest_path)
        .context("Failed to parse package.json for npm unlink")?;

    let pkg_name = manifest.name.as_deref().ok_or_else(|| {
        anyhow!("npm error code EINVALIDPKG\nnpm error package.json missing 'name' field")
    })?;

    let global_nm = find_global_node_modules(global_prefix);
    let target_link = global_nm.join(pkg_name);
    let global_bin = find_global_bin_dir(global_prefix);

    // Remove bin shims
    for (bin_name, _) in manifest.bin_entries() {
        let _ = std::fs::remove_file(global_bin.join(&bin_name));
        #[cfg(windows)]
        {
            let _ = std::fs::remove_file(global_bin.join(format!("{bin_name}.cmd")));
            let _ = std::fs::remove_file(global_bin.join(format!("{bin_name}.ps1")));
        }
    }

    if is_junction(&target_link).unwrap_or(false) {
        remove_junction(&target_link)?;
    } else if target_link.is_dir() {
        remove_dir_all_safe(&target_link)?;
    } else if target_link.exists() {
        let _ = std::fs::remove_file(&target_link);
    }

    // Clean up empty scoped directory (e.g. @scope)
    if let Some(parent) = target_link.parent() {
        if let Some(name) = parent.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('@') && parent.is_dir() {
                if let Ok(mut entries) = std::fs::read_dir(parent) {
                    if entries.next().is_none() {
                        let _ = std::fs::remove_dir(parent);
                    }
                }
            }
        }
    }

    Ok(Some(target_link))
}

/// Invoked with package name in consumer project: `npm unlink <pkg>`
/// Unlinks local reference from consumer's node_modules/<pkg> and removes local bin shims.
pub fn unlink_package_from_consumer(
    consumer_dir: &Path,
    package_name: &str,
) -> Result<Option<PathBuf>> {
    let local_nm = consumer_dir.join("node_modules");
    let target_link = local_nm.join(package_name);
    let local_bin = local_nm.join(".bin");

    // If package has manifest, remove bin shims
    let manifest_path = target_link.join("package.json");
    if let Ok(manifest) = Manifest::from_file(&manifest_path) {
        for (bin_name, _) in manifest.bin_entries() {
            let _ = std::fs::remove_file(local_bin.join(&bin_name));
            #[cfg(windows)]
            {
                let _ = std::fs::remove_file(local_bin.join(format!("{bin_name}.cmd")));
                let _ = std::fs::remove_file(local_bin.join(format!("{bin_name}.ps1")));
            }
        }
    }

    if is_junction(&target_link).unwrap_or(false) {
        remove_junction(&target_link)?;
    } else if target_link.is_dir() {
        remove_dir_all_safe(&target_link)?;
    } else if target_link.exists() {
        let _ = std::fs::remove_file(&target_link);
    }

    // Clean up empty scoped directory (e.g. @scope)
    if let Some(parent) = target_link.parent() {
        if let Some(name) = parent.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('@') && parent.is_dir() {
                if let Ok(mut entries) = std::fs::read_dir(parent) {
                    if entries.next().is_none() {
                        let _ = std::fs::remove_dir(parent);
                    }
                }
            }
        }
    }

    Ok(Some(target_link))
}
