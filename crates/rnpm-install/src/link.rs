use anyhow::{anyhow, Context, Result};
use rnpm_config::{find_global_bin_dir, find_global_node_modules};
use rnpm_core::manifest::Manifest;
use rnpm_fs::junction::{create_junction, is_junction, remove_dir_all_safe, remove_junction};
use rnpm_shim::generator::create_shim_trio;
use rnpm_shim::{create_shims, normalize_shebang};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::debug;

use crate::timing::{Phase, TimingCollector};

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

pub(crate) fn is_same_or_matching_root_nm(p: &Path, root_nm: &Path) -> bool {
    let clean_p = path_clean::clean(p);
    let clean_root = path_clean::clean(root_nm);
    let s_p = clean_p.to_string_lossy().replace('\\', "/");
    let s_root = clean_root.to_string_lossy().replace('\\', "/");

    #[cfg(windows)]
    let eq = s_p.eq_ignore_ascii_case(&s_root);
    #[cfg(not(windows))]
    let eq = s_p == s_root;

    if eq {
        return true;
    }

    if (clean_p.is_relative()
        && clean_root.is_absolute()
        && s_p == "node_modules"
        && s_root.ends_with("/node_modules"))
        || (clean_p.is_absolute()
            && clean_root.is_relative()
            && s_root == "node_modules"
            && s_p.ends_with("/node_modules"))
    {
        return true;
    }
    false
}

pub(crate) fn find_enclosing_bin_dir(
    dest_dir: &Path,
    root_bin_dir: &Path,
    root_node_modules: &Path,
) -> PathBuf {
    let mut curr = dest_dir.parent();
    while let Some(p) = curr {
        if p.file_name().map(|n| n == "node_modules").unwrap_or(false) {
            if is_same_or_matching_root_nm(p, root_node_modules) {
                return root_bin_dir.to_path_buf();
            }
            return p.join(".bin");
        }
        curr = p.parent();
    }
    root_bin_dir.to_path_buf()
}

pub(crate) fn compute_bin_target_rel(pkg_dir: &Path, bin_dir: &Path, script_rel: &str) -> String {
    let script_abs = pkg_dir.join(script_rel);
    let clean_bin = path_clean::clean(bin_dir);
    if clean_bin.file_name().map(|n| n == ".bin").unwrap_or(false) {
        if let Some(enclosing_nm) = clean_bin.parent() {
            if let Ok(rel) = rnpm_shim::path::compute_relative_path(enclosing_nm, &script_abs) {
                return rel.replace('\\', "/");
            }
        }
    }
    // Fallback or global install: package name relative to node_modules
    let clean_pkg = path_clean::clean(pkg_dir);
    let pkg_name = if let Some(parent) = clean_pkg.parent() {
        if parent
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with('@'))
            .unwrap_or(false)
        {
            format!(
                "{}/{}",
                parent.file_name().unwrap().to_string_lossy(),
                clean_pkg.file_name().unwrap().to_string_lossy()
            )
        } else {
            clean_pkg
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        }
    } else {
        clean_pkg
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    };
    format!("{pkg_name}/{script_rel}")
}

/// Cleans up any empty `.bin` directories under `node_modules` (including nested `node_modules` and root `.bin`).
pub(crate) fn clean_empty_bin_dirs(root_nm: &Path) {
    if !root_nm.is_dir() {
        return;
    }
    fn visit(dir: &Path, is_root: bool) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let file_name = entry.file_name();
                    if file_name == ".bin" {
                        if let Ok(mut bin_entries) = std::fs::read_dir(&path) {
                            if bin_entries.next().is_none() {
                                let _ = std::fs::remove_dir(&path);
                            }
                        }
                    } else if file_name == "node_modules" {
                        visit(&path, false);
                    } else if file_name.to_string_lossy().starts_with('@') {
                        if let Ok(scoped_entries) = std::fs::read_dir(&path) {
                            for scoped_entry in scoped_entries.flatten() {
                                let scoped_pkg_path = scoped_entry.path();
                                if scoped_pkg_path.is_dir() {
                                    let nested_nm = scoped_pkg_path.join("node_modules");
                                    if nested_nm.is_dir() {
                                        visit(&nested_nm, false);
                                    }
                                }
                            }
                        }
                    } else {
                        let nested_nm = path.join("node_modules");
                        if nested_nm.is_dir() {
                            visit(&nested_nm, false);
                        }
                    }
                }
            }
        }
        if !is_root {
            if let Ok(mut entries) = std::fs::read_dir(dir) {
                if entries.next().is_none() {
                    let _ = std::fs::remove_dir(dir);
                }
            }
        }
    }
    visit(root_nm, true);
    if root_nm.is_dir() {
        if let Ok(mut entries) = std::fs::read_dir(root_nm) {
            if entries.next().is_none() {
                let _ = std::fs::remove_dir(root_nm);
            }
        }
    }
}

/// Cleans up a specific `.bin` directory if it exists and is empty.
pub(crate) fn clean_empty_bin_dir_at(bin_dir: &Path) {
    if bin_dir.exists() && bin_dir.file_name().map(|n| n == ".bin").unwrap_or(false) {
        if let Ok(mut entries) = std::fs::read_dir(bin_dir) {
            if entries.next().is_none() {
                let _ = std::fs::remove_dir(bin_dir);
            }
        }
    }
}

pub(crate) fn link_single_pkg_bin(
    target_path: &Path,
    pkg_bin_dir: &Path,
    bin_name: &str,
    script_rel: &str,
    source_script_path: &Path,
) {
    let target_rel = compute_bin_target_rel(target_path, pkg_bin_dir, script_rel);
    let _ = normalize_shebang(source_script_path);
    let _ = create_shims(pkg_bin_dir, bin_name, &target_rel);
}

pub(crate) fn package_name_from_loc(loc: &str) -> &str {
    let clean = loc.strip_prefix("node_modules/").unwrap_or(loc);
    if let Some(idx) = clean.rfind("/node_modules/") {
        &clean[idx + "/node_modules/".len()..]
    } else {
        clean
    }
}

pub(crate) fn extract_bin_entries_from_lockfile(
    pkg_name: &str,
    bin: &rnpm_lockfile::PackageBin,
) -> Vec<(String, String)> {
    match bin {
        rnpm_lockfile::PackageBin::Single(script_path) => {
            let bin_name = if let Some(slash_idx) = pkg_name.find('/') {
                &pkg_name[slash_idx + 1..]
            } else {
                pkg_name
            };
            let bin_name = if bin_name.is_empty() { "app" } else { bin_name };
            vec![(bin_name.to_string(), script_path.clone())]
        }
        rnpm_lockfile::PackageBin::Map(map) => {
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        }
    }
}

pub(crate) fn cleanup_stale_shims(
    node_modules_dir: &Path,
    wanted_shims: &HashMap<PathBuf, HashSet<String>>,
) {
    let mut bin_dirs: Vec<PathBuf> = wanted_shims.keys().cloned().collect();
    let root_bin = node_modules_dir.join(".bin");
    if !bin_dirs.contains(&root_bin) {
        bin_dirs.push(root_bin);
    }

    for bin_dir in bin_dirs {
        // Only clean directories ending with ".bin"
        if bin_dir.file_name().map(|n| n != ".bin").unwrap_or(true) {
            continue;
        }
        if !bin_dir.is_dir() {
            continue;
        }

        let clean_path = path_clean::clean(&bin_dir);
        let wanted_set = wanted_shims.get(&clean_path);

        if let Ok(entries) = std::fs::read_dir(&bin_dir) {
            for entry in entries.flatten() {
                let file_name = entry.file_name().to_string_lossy().to_string();
                let is_wanted = wanted_set.is_some_and(|set| set.contains(&file_name));
                if !is_wanted {
                    let path = entry.path();
                    if path.is_dir() {
                        let _ = std::fs::remove_dir_all(&path);
                    } else {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }

        clean_empty_bin_dir_at(&bin_dir);
    }
}

pub(crate) fn package_location_depth(loc: &str) -> usize {
    loc.matches("node_modules/").count()
}

pub(crate) fn bin_package_order_cmp(loc_a: &str, loc_b: &str) -> std::cmp::Ordering {
    let depth_a = package_location_depth(loc_a);
    let depth_b = package_location_depth(loc_b);
    depth_a.cmp(&depth_b).then_with(|| loc_a.cmp(loc_b))
}

pub(crate) type CiPackage = (String, String, String, bool, Vec<String>, bool);

pub(crate) fn sort_packages_for_bin_linking(packages: &mut [CiPackage]) {
    packages.sort_by(|a, b| bin_package_order_cmp(&a.0, &b.0));
}

pub(crate) fn link_tree_bins(
    mut package_locs: Vec<String>,
    known_bins: Option<&HashMap<String, Vec<(String, String)>>>,
    loc_base_dir: &Path,
    root_bin_dir: &Path,
    node_modules_dir: &Path,
    is_clean_install: bool,
    collector: Option<&TimingCollector>,
) {
    let t_bins = std::time::Instant::now();

    // 1. If known_bins is provided, filter package_locs to only packages that actually have bins in memory!
    if let Some(bins) = known_bins {
        package_locs.retain(|loc| bins.contains_key(loc));
    }

    // 2. Walk packages shallowest first (depth based on `node_modules/` count), sorted according to npm precedence.
    package_locs.sort_by(|a, b| bin_package_order_cmp(a, b));

    // 3. Track claimed bin names per .bin directory in memory for the current run.
    let mut claimed_bins: HashMap<PathBuf, HashSet<String>> = HashMap::new();
    let mut wanted_shims: HashMap<PathBuf, HashSet<String>> = HashMap::new();
    let mut shims_to_link = Vec::new();

    for loc in &package_locs {
        let target_path = loc_base_dir.join(loc);

        let bin_entries = if let Some(bins) = known_bins {
            if let Some(entries) = bins.get(loc) {
                entries.clone()
            } else {
                continue;
            }
        } else {
            let pkg_manifest_path = target_path.join("package.json");
            if !pkg_manifest_path.exists() {
                continue;
            }

            let pkg_manifest = match Manifest::from_file(&pkg_manifest_path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            pkg_manifest.bin_entries()
        };

        if bin_entries.is_empty() {
            continue;
        }

        let pkg_bin_dir = find_enclosing_bin_dir(&target_path, root_bin_dir, node_modules_dir);
        let clean_bin_dir = path_clean::clean(&pkg_bin_dir);

        let claimed_set = claimed_bins.entry(clean_bin_dir.clone()).or_default();
        let wanted_set = wanted_shims.entry(clean_bin_dir.clone()).or_default();

        for (bin_name, script_rel) in bin_entries {
            // First-writer-wins within the current installation run
            if claimed_set.insert(bin_name.clone()) {
                let script_path = target_path.join(&script_rel);
                shims_to_link.push((target_path.clone(), pkg_bin_dir.clone(), bin_name.clone(), script_rel, script_path));

                wanted_set.insert(bin_name.clone());
                wanted_set.insert(format!("{bin_name}.cmd"));
                wanted_set.insert(format!("{bin_name}.ps1"));
            } else {
                debug!(
                    "Bin '{bin_name}' in '{}' already claimed in this run; skipping",
                    clean_bin_dir.display()
                );
            }
        }
    }

    if shims_to_link.len() <= 2 {
        for (target_path, pkg_bin_dir, bin_name, script_rel, script_path) in &shims_to_link {
            link_single_pkg_bin(target_path, pkg_bin_dir, bin_name, script_rel, script_path);
        }
    } else {
        let num_threads = 16.min(shims_to_link.len());
        let chunk_size = shims_to_link.len().div_ceil(num_threads);
        std::thread::scope(|scope| {
            for chunk in shims_to_link.chunks(chunk_size) {
                scope.spawn(move || {
                    for (target_path, pkg_bin_dir, bin_name, script_rel, script_path) in chunk {
                        link_single_pkg_bin(target_path, pkg_bin_dir, bin_name, script_rel, script_path);
                    }
                });
            }
        });
    }

    // 4. Clean up stale shims: remove any shims in .bin that are not owned by any package in the new tree's wanted bin set.
    if !is_clean_install {
        cleanup_stale_shims(node_modules_dir, &wanted_shims);
    }

    if let Some(c) = collector {
        c.record_phase(Phase::Bins, t_bins.elapsed());
    }
}
