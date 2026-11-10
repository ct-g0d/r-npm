use anyhow::{anyhow, Context, Result};
use data_encoding::HEXLOWER;
use rnpm_cache::{PackagePack, PackStore};
use rnpm_config::Config;
use rnpm_core::manifest::Manifest;
use rnpm_core::workspace::discover_workspaces_from_manifest;
use rnpm_lockfile::LockfileV3;
use rnpm_solver::Platform;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, warn};

use crate::linked::InstallStrategy;
use crate::InstallOptions;

/// Calculate deterministic fingerprint hash of all install inputs:
/// - Root `package.json`
/// - Workspace manifests if in monorepo
/// - Lockfile (`package-lock.json` or `npm-shrinkwrap.json`)
/// - `.npmrc` settings
/// - Resolution-impacting CLI / install options (install strategy, omit/include, target platform, workspaces)
pub fn compute_project_fingerprint(project_dir: &Path, options: &InstallOptions) -> Result<String> {
    let manifest_path = project_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow!(
            "package.json not found in {}",
            project_dir.display()
        ));
    }

    let pkg_json_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
    let manifest =
        Manifest::from_slice(&pkg_json_bytes).context("Failed to parse project package.json")?;

    let mut hasher = Sha256::new();

    // 1. Root package.json content
    hasher.update(b"manifest:package.json:\n");
    hasher.update(&pkg_json_bytes);

    // 2. Monorepo workspace manifests (if any)
    let mut workspace_members =
        discover_workspaces_from_manifest(project_dir, &manifest).unwrap_or_default();
    workspace_members.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    for member in &workspace_members {
        let member_pkg_json = member.path.join("package.json");
        if let Ok(bytes) = std::fs::read(&member_pkg_json) {
            hasher
                .update(format!("\nworkspace:{}:package.json:\n", member.relative_path).as_bytes());
            hasher.update(&bytes);
        }
    }

    // 3. Lockfile: npm-shrinkwrap.json takes precedence over package-lock.json in npm
    let shrinkwrap_path = project_dir.join("npm-shrinkwrap.json");
    let lockfile_path = project_dir.join("package-lock.json");
    if shrinkwrap_path.exists() {
        if let Ok(bytes) = std::fs::read(&shrinkwrap_path) {
            hasher.update(b"\nlockfile:npm-shrinkwrap.json:\n");
            hasher.update(&bytes);
        }
    } else if lockfile_path.exists() {
        if let Ok(bytes) = std::fs::read(&lockfile_path) {
            hasher.update(b"\nlockfile:package-lock.json:\n");
            hasher.update(&bytes);
        }
    } else {
        hasher.update(b"\nlockfile:none\n");
    }

    // 4. .npmrc configuration & registry settings
    let config = Config::load(Some(project_dir)).unwrap_or_default();
    hasher.update(format!("\nnpmrc:registry:{}\n", config.npmrc.registry).as_bytes());
    for (scope, url) in &config.npmrc.scoped_registries {
        hasher.update(format!("npmrc:scoped:{scope}={url}\n").as_bytes());
    }
    for (k, v) in &config.npmrc.settings {
        hasher.update(format!("npmrc:setting:{k}={v}\n").as_bytes());
    }

    // 5. Options impacting resolution and tree structure
    let target_platform = options.platform();
    let mut sorted_include = options.include.clone();
    sorted_include.sort();
    let mut sorted_workspace = options.workspace.clone();
    sorted_workspace.sort();

    hasher.update(
        format!(
            "\noptions:install_strategy={:?}:omit_dev={}:omit_opt={}:omit_peer={}:legacy_peer={}:strict_peer={}:global={}:os={:?}:cpu={:?}:libc={:?}:target_os={}:target_cpu={}:target_libc={:?}:lock_ver={}:include={:?}:workspaces={}:workspace_root={}:workspace={:?}\n",
            options.install_strategy,
            options.omit_dev,
            options.omit_optional,
            options.omit_peer,
            options.legacy_peer_deps,
            options.strict_peer_deps,
            options.is_global,
            options.os,
            options.cpu,
            options.libc,
            target_platform.os,
            target_platform.cpu,
            target_platform.libc,
            options.lockfile_version,
            sorted_include,
            options.workspaces,
            options.workspace_root,
            sorted_workspace,
        )
        .as_bytes(),
    );

    let digest = hasher.finalize();
    Ok(HEXLOWER.encode(&digest))
}

/// Validate hidden lockfile (`node_modules/.package-lock.json`).
///
/// Applies npm's trust rule:
/// The hidden lockfile is valid when it exists AND its mtime is at least as new as
/// the root `node_modules` directory, any scope directory, and every active package
/// folder on disk.
///
/// Packages that were skipped for the current platform (e.g. optional packages
/// with incompatible os/cpu/libc) or omitted via `--omit` are not required to exist
/// on disk.
///
/// In linked mode (`--install-strategy=linked`), transitive packages live in the
/// global store, so only top-level direct packages exist in `project_dir/node_modules`
/// as directory junctions.
pub fn validate_hidden_lockfile(project_dir: &Path, options: Option<&InstallOptions>) -> bool {
    let node_modules = project_dir.join("node_modules");
    if !node_modules.is_dir() {
        debug!("Hidden lockfile invalid: node_modules directory does not exist");
        return false;
    }

    let hidden_path = project_dir.join(LockfileV3::HIDDEN_LOCKFILE_PATH);
    let hidden_meta = match std::fs::symlink_metadata(&hidden_path) {
        Ok(m) => m,
        Err(_) => {
            debug!(
                "Hidden lockfile does not exist at {}",
                hidden_path.display()
            );
            return false;
        }
    };
    let hidden_mtime = match hidden_meta.modified() {
        Ok(t) => t,
        Err(_) => return false,
    };

    // Check modification time of root node_modules directory:
    // If files or folders were added or removed directly in node_modules after the
    // hidden lockfile was written, node_modules mtime will be newer than hidden_mtime.
    if let Ok(nm_meta) = std::fs::symlink_metadata(&node_modules) {
        if let Ok(nm_mtime) = nm_meta.modified() {
            if nm_mtime > hidden_mtime {
                debug!(
                    "Hidden lockfile invalid: node_modules directory mtime ({:?}) is newer than hidden lockfile ({:?})",
                    nm_mtime, hidden_mtime
                );
                return false;
            }
        }
    }

    let content = match std::fs::read_to_string(&hidden_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let lockfile = match LockfileV3::from_json_str(&content) {
        Ok(l) => l,
        Err(_) => {
            debug!("Hidden lockfile is not valid JSON / LockfileV3");
            return false;
        }
    };

    // Resolve target platform and filtering flags
    let platform = options
        .map(|o| o.platform())
        .unwrap_or_else(Platform::current);
    let is_linked = options
        .map(|o| o.install_strategy == InstallStrategy::Linked)
        .unwrap_or_else(|| {
            if let Ok(entries) = std::fs::read_dir(&node_modules) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if !name_str.starts_with('.')
                        && rnpm_fs::is_junction(&entry.path()).unwrap_or(false)
                    {
                        return true;
                    }
                }
            }
            false
        });

    let omit_dev = options.map(|o| o.omit_dev).unwrap_or(false);
    let omit_optional = options.map(|o| o.omit_optional).unwrap_or(false);
    let omit_peer = options.map(|o| o.omit_peer).unwrap_or(false);

    // Platform-skipped lockfile packages (incompatible optional packages and their descendants)
    let platform_skipped = crate::lockfile_platform_skipped_packages(&lockfile, &platform);

    // Direct top-level packages declared on root
    let mut direct_top_level_deps: HashSet<String> = HashSet::new();
    if let Some(root_pkg) = lockfile.packages.get("") {
        if let Some(deps) = &root_pkg.dependencies {
            for name in deps.keys() {
                direct_top_level_deps.insert(format!("node_modules/{name}"));
            }
        }
        if !omit_dev {
            if let Some(dev_deps) = &root_pkg.dev_dependencies {
                for name in dev_deps.keys() {
                    direct_top_level_deps.insert(format!("node_modules/{name}"));
                }
            }
        }
        if !omit_optional {
            if let Some(opt_deps) = &root_pkg.optional_dependencies {
                for name in opt_deps.keys() {
                    direct_top_level_deps.insert(format!("node_modules/{name}"));
                }
            }
        }
    } else if let Ok(manifest) = Manifest::from_file(project_dir.join("package.json")) {
        for name in manifest.dependencies.keys() {
            direct_top_level_deps.insert(format!("node_modules/{name}"));
        }
        if !omit_dev {
            for name in manifest.dev_dependencies.keys() {
                direct_top_level_deps.insert(format!("node_modules/{name}"));
            }
        }
        if !omit_optional {
            for name in manifest.optional_dependencies.keys() {
                direct_top_level_deps.insert(format!("node_modules/{name}"));
            }
        }
    }

    // Fast directory scan: populate mtimes for top-level and scoped packages in node_modules,
    // and verify scope directory modification times.
    let mut dir_mtimes: HashMap<String, SystemTime> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&node_modules) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            if name_str.starts_with('@') {
                // Check scope directory mtime:
                // If a package was added to or removed from @scope, scope directory mtime is updated
                if let Ok(meta) = entry.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        if mtime > hidden_mtime {
                            debug!(
                                "Hidden lockfile invalid: scope directory '{}' mtime ({:?}) is newer than hidden lockfile ({:?})",
                                name_str, mtime, hidden_mtime
                            );
                            return false;
                        }
                    }
                }
                // Scoped directory: inspect its packages
                if let Ok(scoped_entries) = std::fs::read_dir(entry.path()) {
                    for scoped_entry in scoped_entries.flatten() {
                        let sub_name = scoped_entry.file_name();
                        let sub_str = sub_name.to_string_lossy();
                        if let Ok(meta) = scoped_entry.metadata() {
                            if let Ok(mtime) = meta.modified() {
                                let key = format!("node_modules/{}/{}", name_str, sub_str);
                                dir_mtimes.insert(key, mtime);
                            }
                        }
                    }
                }
            } else if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    let key = format!("node_modules/{}", name_str);
                    dir_mtimes.insert(key, mtime);
                }
            }
        }
    }

    // Verify every package folder listed in lockfile:
    // - If it exists on disk, its mtime must be <= hidden_mtime
    // - If it does not exist on disk, check if it was platform-skipped, omitted,
    //   or is a transitive package in linked mode (which lives in the store).
    for (pkg_key, pkg_info) in &lockfile.packages {
        if pkg_key.is_empty() {
            continue;
        }
        if !pkg_key.starts_with("node_modules/") && !pkg_key.contains("/node_modules/") {
            continue;
        }

        let normalized_key = pkg_key.replace('\\', "/");

        let is_platform_skipped = platform_skipped.contains(pkg_key)
            || pkg_info
                .extra
                .get("skipped")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            || ((pkg_info.is_effective_optional() || pkg_info.is_peer_optional())
                && !platform.matches_with_libc(
                    pkg_info.os.as_deref(),
                    pkg_info.cpu.as_deref(),
                    pkg_info.libc.as_deref(),
                ));

        let is_omitted = (omit_dev
            && (pkg_info.is_dev() || pkg_info.dev_optional.unwrap_or(false)))
            || (omit_optional && (pkg_info.is_effective_optional() || pkg_info.is_peer_optional()))
            || (omit_peer
                && (pkg_info.peer.unwrap_or(false) || pkg_info.peer_optional.unwrap_or(false)));

        let is_top_level = direct_top_level_deps.contains(&normalized_key);
        let is_transitive_in_linked = is_linked && !is_top_level;

        let folder_path = project_dir.join(&normalized_key);
        let exists_on_disk =
            folder_path.exists() || rnpm_fs::is_junction(&folder_path).unwrap_or(false);

        if exists_on_disk {
            // Top-level junction check in linked mode: if junction exists, ensure target is not broken
            if is_linked
                && is_top_level
                && rnpm_fs::is_junction(&folder_path).unwrap_or(false)
                && !folder_path.exists()
            {
                debug!(
                    "Hidden lockfile invalid: linked junction target for '{}' missing from store",
                    normalized_key
                );
                return false;
            }

            let folder_mtime = if let Some(mtime) = dir_mtimes.get(&normalized_key) {
                Some(*mtime)
            } else {
                match std::fs::symlink_metadata(&folder_path) {
                    Ok(meta) => meta.modified().ok(),
                    Err(_) => return false,
                }
            };

            if let Some(mtime) = folder_mtime {
                if mtime > hidden_mtime {
                    debug!(
                        "Hidden lockfile invalid: package folder '{}' mtime ({:?}) is newer than hidden lockfile ({:?})",
                        normalized_key, folder_mtime, hidden_mtime
                    );
                    return false;
                }
            }
        } else {
            // Missing on disk
            if is_platform_skipped || is_omitted || is_transitive_in_linked {
                continue;
            }
            debug!(
                "Hidden lockfile invalid: package folder '{}' missing from disk",
                normalized_key
            );
            return false;
        }
    }

    true
}

/// Convenience helper for validating hidden lockfile with default or no explicit options.
pub fn validate_hidden_lockfile_simple(project_dir: &Path) -> bool {
    validate_hidden_lockfile(project_dir, None)
}

/// Loads package packs in parallel across workers.
pub(crate) fn parallel_load_packs(
    pack_store: &Arc<PackStore>,
    loc_base_dir: &Path,
    packages_to_process: &[crate::link::CiPackage],
) -> (Vec<(String, PathBuf, PackagePack)>, bool) {
    let total_pkgs = packages_to_process.len();
    let num_workers = 16.min(total_pkgs);
    let next_idx = std::sync::atomic::AtomicUsize::new(0);
    let load_failed = std::sync::atomic::AtomicBool::new(false);
    let pack_store = Arc::clone(pack_store);

    let mut loaded_packs = Vec::with_capacity(total_pkgs);
    let load_success = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            handles.push(scope.spawn(|| -> Result<Vec<(usize, String, PathBuf, PackagePack)>, ()> {
                let mut local = Vec::new();
                while !load_failed.load(std::sync::atomic::Ordering::Relaxed) {
                    let idx = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if idx >= total_pkgs {
                        break;
                    }
                    let (pkg_key, _, integrity_str, _, _, _) = &packages_to_process[idx];
                    let pkg_target = loc_base_dir.join(pkg_key);
                    match pack_store.get_package_pack(integrity_str) {
                        Ok(Some(pack)) => {
                            local.push((idx, pkg_key.clone(), pkg_target, pack));
                        }
                        Err(e) => {
                            warn!("get_package_pack failed for {pkg_key}: {e}. Falling back to standard pipeline.");
                            load_failed.store(true, std::sync::atomic::Ordering::Relaxed);
                            return Err(());
                        }
                        Ok(None) => {
                            warn!("Package pack missing for {pkg_key}. Falling back to standard pipeline.");
                            load_failed.store(true, std::sync::atomic::Ordering::Relaxed);
                            return Err(());
                        }
                    }
                }
                Ok(local)
            }));
        }

        let mut all_results = Vec::with_capacity(total_pkgs);
        let mut any_err = false;
        for handle in handles {
            match handle.join() {
                Ok(Ok(items)) => all_results.extend(items),
                _ => any_err = true,
            }
        }
        if any_err || all_results.len() != total_pkgs {
            false
        } else {
            all_results.sort_by_key(|(idx, _, _, _)| *idx);
            for (_, pkg_key, pkg_target, pack) in all_results {
                loaded_packs.push((pkg_key, pkg_target, pack));
            }
            true
        }
    });

    (loaded_packs, load_success)
}

/// Builds in-memory lookup map of known package bins from lockfile metadata.
pub(crate) fn build_known_bins_map(
    lockfile: &LockfileV3,
) -> HashMap<String, Vec<(String, String)>> {
    let mut known_bins = HashMap::new();
    for (loc, pkg_info) in &lockfile.packages {
        if let Some(ref bin) = pkg_info.bin {
            let pkg_name = pkg_info
                .name
                .as_deref()
                .unwrap_or_else(|| crate::link::package_name_from_loc(loc));
            let entries = crate::link::extract_bin_entries_from_lockfile(pkg_name, bin);
            if !entries.is_empty() {
                known_bins.insert(loc.clone(), entries);
            }
        } else if pkg_info.link == Some(true) {
            if let Some(ref resolved) = pkg_info.resolved {
                if let Some(target) = lockfile.packages.get(resolved) {
                    if let Some(ref bin) = target.bin {
                        let pkg_name = target
                            .name
                            .as_deref()
                            .unwrap_or_else(|| crate::link::package_name_from_loc(loc));
                        let entries = crate::link::extract_bin_entries_from_lockfile(pkg_name, bin);
                        if !entries.is_empty() {
                            known_bins.insert(loc.clone(), entries);
                        }
                    }
                }
            }
        }
    }
    known_bins
}

/// Enrich lockfile entries with author/funding/license/engines from installed manifests
pub(crate) fn enrich_lockfile_from_installed_manifests(
    lockfile: &mut LockfileV3,
    project_dir: &Path,
    manifest_cache: Option<&HashMap<String, Manifest>>,
) {
    let mut manifests_by_loc: HashMap<String, Manifest> = HashMap::new();
    let mut missing_locations = Vec::new();

    for (location, package) in &lockfile.packages {
        if location.is_empty() || package.link == Some(true) {
            continue;
        }
        if package.license.is_some() && package.engines.is_some() {
            continue;
        }
        if let Some(cache) = manifest_cache {
            if let Some(m) = cache.get(location) {
                manifests_by_loc.insert(location.clone(), m.clone());
                continue;
            }
        }
        missing_locations.push(location.clone());
    }

    if !missing_locations.is_empty() {
        let num_threads = 16.min(missing_locations.len());
        let chunk_size = missing_locations.len().div_ceil(num_threads);
        let disk_manifests = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(num_threads);
            for chunk in missing_locations.chunks(chunk_size) {
                handles.push(scope.spawn(move || {
                    let mut local = Vec::with_capacity(chunk.len());
                    for loc in chunk {
                        let manifest_path = if loc.is_empty() {
                            project_dir.join("package.json")
                        } else {
                            project_dir.join(loc).join("package.json")
                        };
                        if let Ok(m) = Manifest::from_file(&manifest_path) {
                            local.push((loc.clone(), m));
                        }
                    }
                    local
                }));
            }
            let mut results = HashMap::with_capacity(missing_locations.len());
            for handle in handles {
                if let Ok(items) = handle.join() {
                    results.extend(items);
                }
            }
            results
        });
        manifests_by_loc.extend(disk_manifests);
    }

    for (location, manifest) in manifests_by_loc {
        let Some(package) = lockfile.packages.get_mut(&location) else {
            continue;
        };

        if package.license.is_none() {
            package.license = manifest
                .extra
                .get("license")
                .and_then(|value| {
                    if let Some(s) = value.as_str() {
                        Some(s.to_string())
                    } else if let Some(obj) = value.as_object() {
                        obj.get("type").and_then(|t| t.as_str()).map(str::to_owned)
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    manifest.extra.get("licenses").and_then(|v| {
                        v.as_array().and_then(|arr| {
                            arr.first().and_then(|item| {
                                if let Some(s) = item.as_str() {
                                    Some(s.to_string())
                                } else if let Some(obj) = item.as_object() {
                                    obj.get("type").and_then(|t| t.as_str()).map(str::to_owned)
                                } else {
                                    None
                                }
                            })
                        })
                    })
                });
        }

        if package.engines.is_none() {
            let manifest_path = if location.is_empty() {
                project_dir.join("package.json")
            } else {
                project_dir.join(&location).join("package.json")
            };
            if let Ok(raw_str) = std::fs::read_to_string(&manifest_path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw_str) {
                    if let Some(engines_val) = json.get("engines") {
                        if let Ok(engines) = serde_json::from_value::<rnpm_lockfile::PackageEngines>(engines_val.clone()) {
                            if !engines.is_empty() {
                                package.engines = Some(engines);
                            }
                        }
                    }
                }
            }
            if package.engines.is_none() && !manifest.engines.is_empty() {
                package.engines = Some(rnpm_lockfile::PackageEngines::Map(manifest.engines.clone()));
            }
        }
        if package.bin.is_none() {
            if let Some(bin) = &manifest.bin {
                let lock_bin = match bin {
                    rnpm_core::manifest::PackageBin::Single(s) => {
                        let clean = s.strip_prefix("./").unwrap_or(s);
                        let pkg_name = manifest.name.as_deref().unwrap_or("");
                        let bin_name = pkg_name.rsplit('/').next().unwrap_or(pkg_name);
                        let mut m = std::collections::BTreeMap::new();
                        m.insert(bin_name.to_string(), clean.to_string());
                        rnpm_lockfile::PackageBin::Map(m)
                    }
                    rnpm_core::manifest::PackageBin::Map(m) => {
                        rnpm_lockfile::PackageBin::Map(m.clone())
                    }
                };
                package.bin = Some(lock_bin);
            }
        } else if let Some(rnpm_lockfile::PackageBin::Single(s)) = &package.bin {
            let clean = s.strip_prefix("./").unwrap_or(s);
            let pkg_name = manifest.name.as_deref().unwrap_or("");
            let bin_name = pkg_name.rsplit('/').next().unwrap_or(pkg_name);
            let mut m = std::collections::BTreeMap::new();
            m.insert(bin_name.to_string(), clean.to_string());
            package.bin = Some(rnpm_lockfile::PackageBin::Map(m));
        }
        if package.os.is_none() {
            if let Some(os) = &manifest.os {
                package.os = Some(os.clone());
            }
        }
        if package.cpu.is_none() {
            if let Some(cpu) = &manifest.cpu {
                package.cpu = Some(cpu.clone());
            }
        }
        if package.libc.is_none() {
            if let Some(libc) = &manifest.libc {
                package.libc = Some(libc.clone());
            }
        }
        let funding_val_opt = manifest
            .extra
            .get("funding")
            .or_else(|| package.extra.get("funding"));
        if let Some(value) = funding_val_opt {
            let normalized_val = if let Some(url_str) = value.as_str() {
                let mut map = serde_json::Map::new();
                map.insert(
                    "url".to_string(),
                    serde_json::Value::String(url_str.to_string()),
                );
                serde_json::Value::Object(map)
            } else {
                value.clone()
            };
            package.extra.insert("funding".to_string(), normalized_val);
        }
        if !package.extra.contains_key("deprecated") {
            if let Some(value) = manifest.extra.get("deprecated") {
                if value != &serde_json::Value::Bool(false) && !value.is_null() && value != "" {
                    package
                        .extra
                        .insert("deprecated".to_string(), value.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rnpm_lockfile::LockfilePackage;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    #[test]
    fn test_compute_project_fingerprint_includes_strategy() {
        let tmp = tempdir().unwrap();
        let pkg_json = tmp.path().join("package.json");
        std::fs::write(&pkg_json, r#"{"name": "test-pkg", "version": "1.0.0"}"#).unwrap();

        let mut opts1 = InstallOptions::default();
        opts1.project_dir = tmp.path().to_path_buf();
        opts1.install_strategy = InstallStrategy::Hoisted;

        let mut opts2 = opts1.clone();
        opts2.install_strategy = InstallStrategy::Linked;

        let mut opts3 = opts1.clone();
        opts3.install_strategy = InstallStrategy::Nested;

        let fp1 = compute_project_fingerprint(tmp.path(), &opts1).unwrap();
        let fp2 = compute_project_fingerprint(tmp.path(), &opts2).unwrap();
        let fp3 = compute_project_fingerprint(tmp.path(), &opts3).unwrap();

        assert_ne!(
            fp1, fp2,
            "Hoisted vs Linked strategy must produce different fingerprints"
        );
        assert_ne!(
            fp1, fp3,
            "Hoisted vs Nested strategy must produce different fingerprints"
        );
        assert_ne!(
            fp2, fp3,
            "Linked vs Nested strategy must produce different fingerprints"
        );
    }

    #[test]
    fn test_compute_project_fingerprint_includes_include_and_workspaces_and_platform() {
        let tmp = tempdir().unwrap();
        let pkg_json = tmp.path().join("package.json");
        std::fs::write(&pkg_json, r#"{"name": "test-pkg", "version": "1.0.0"}"#).unwrap();

        let mut opts_base = InstallOptions::default();
        opts_base.project_dir = tmp.path().to_path_buf();
        let base_fp = compute_project_fingerprint(tmp.path(), &opts_base).unwrap();

        // 1. Changing include
        let mut opts_include = opts_base.clone();
        opts_include.include = vec!["dev".to_string()];
        let include_fp = compute_project_fingerprint(tmp.path(), &opts_include).unwrap();
        assert_ne!(
            base_fp, include_fp,
            "include options must impact fingerprint"
        );

        // 2. Changing workspace flags
        let mut opts_ws = opts_base.clone();
        opts_ws.workspaces = true;
        let ws_fp = compute_project_fingerprint(tmp.path(), &opts_ws).unwrap();
        assert_ne!(base_fp, ws_fp, "workspaces flag must impact fingerprint");

        let mut opts_ws_root = opts_base.clone();
        opts_ws_root.workspace_root = true;
        let ws_root_fp = compute_project_fingerprint(tmp.path(), &opts_ws_root).unwrap();
        assert_ne!(
            base_fp, ws_root_fp,
            "workspace_root flag must impact fingerprint"
        );

        let mut opts_ws_member = opts_base.clone();
        opts_ws_member.workspace = vec!["packages/a".to_string()];
        let ws_member_fp = compute_project_fingerprint(tmp.path(), &opts_ws_member).unwrap();
        assert_ne!(
            base_fp, ws_member_fp,
            "workspace filter must impact fingerprint"
        );

        // 3. Changing target platform
        let mut opts_os = opts_base.clone();
        opts_os.os = Some("linux".to_string());
        let os_fp = compute_project_fingerprint(tmp.path(), &opts_os).unwrap();
        assert_ne!(base_fp, os_fp, "target os must impact fingerprint");

        let mut opts_cpu = opts_base.clone();
        opts_cpu.cpu = Some("arm64".to_string());
        let cpu_fp = compute_project_fingerprint(tmp.path(), &opts_cpu).unwrap();
        assert_ne!(base_fp, cpu_fp, "target cpu must impact fingerprint");
    }

    #[test]
    fn test_validate_hidden_lockfile_ignores_platform_skipped_optional_package() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        // Package present on disk: foo
        let foo_dir = nm.join("foo");
        std::fs::create_dir_all(&foo_dir).unwrap();
        std::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .unwrap();

        // Package missing on disk: darwin-native (optional, incompatible os)
        // Note: we do NOT create nm.join("darwin-native") on disk!

        let mut lockfile = LockfileV3::new("test-project", Some("1.0.0".to_string()));
        let mut root_pkg = LockfilePackage::default();
        let mut root_deps = BTreeMap::new();
        root_deps.insert("foo".to_string(), "^1.0.0".to_string());
        let mut root_opt = BTreeMap::new();
        root_opt.insert("darwin-native".to_string(), "^1.0.0".to_string());
        root_pkg.dependencies = Some(root_deps);
        root_pkg.optional_dependencies = Some(root_opt);
        lockfile.packages.insert("".to_string(), root_pkg);

        let mut foo_pkg = LockfilePackage::default();
        foo_pkg.version = Some("1.0.0".to_string());
        lockfile
            .packages
            .insert("node_modules/foo".to_string(), foo_pkg);

        let mut darwin_pkg = LockfilePackage::default();
        darwin_pkg.version = Some("1.0.0".to_string());
        darwin_pkg.optional = Some(true);
        darwin_pkg.os = Some(vec!["darwin".to_string()]); // incompatible on Windows
        lockfile
            .packages
            .insert("node_modules/darwin-native".to_string(), darwin_pkg);

        // Save hidden lockfile after creating files
        std::thread::sleep(std::time::Duration::from_millis(50));
        lockfile.save_hidden(tmp.path()).unwrap();

        let mut opts = InstallOptions::default();
        opts.project_dir = tmp.path().to_path_buf();
        opts.os = Some("win32".to_string()); // Host is win32, darwin is incompatible

        // Must be VALID even though darwin-native is missing on disk!
        assert!(
            validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "validate_hidden_lockfile must succeed when missing package was platform-skipped"
        );
    }

    #[test]
    fn test_validate_hidden_lockfile_ignores_omitted_packages() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        // Package present on disk: prod-dep
        let prod_dir = nm.join("prod-dep");
        std::fs::create_dir_all(&prod_dir).unwrap();
        std::fs::write(
            prod_dir.join("package.json"),
            r#"{"name": "prod-dep", "version": "1.0.0"}"#,
        )
        .unwrap();

        // Package missing on disk: dev-dep (omitted)
        let mut lockfile = LockfileV3::new("test-project", Some("1.0.0".to_string()));
        let mut root_pkg = LockfilePackage::default();
        let mut root_deps = BTreeMap::new();
        root_deps.insert("prod-dep".to_string(), "^1.0.0".to_string());
        let mut root_dev = BTreeMap::new();
        root_dev.insert("dev-dep".to_string(), "^1.0.0".to_string());
        root_pkg.dependencies = Some(root_deps);
        root_pkg.dev_dependencies = Some(root_dev);
        lockfile.packages.insert("".to_string(), root_pkg);

        let mut prod_pkg = LockfilePackage::default();
        prod_pkg.version = Some("1.0.0".to_string());
        lockfile
            .packages
            .insert("node_modules/prod-dep".to_string(), prod_pkg);

        let mut dev_pkg = LockfilePackage::default();
        dev_pkg.version = Some("1.0.0".to_string());
        dev_pkg.dev = Some(true);
        lockfile
            .packages
            .insert("node_modules/dev-dep".to_string(), dev_pkg);

        std::thread::sleep(std::time::Duration::from_millis(50));
        lockfile.save_hidden(tmp.path()).unwrap();

        // When omit_dev is false: missing dev-dep makes it invalid
        let mut opts_include_dev = InstallOptions::default();
        opts_include_dev.project_dir = tmp.path().to_path_buf();
        opts_include_dev.omit_dev = false;
        assert!(
            !validate_hidden_lockfile(tmp.path(), Some(&opts_include_dev)),
            "Must be invalid if dev package is missing and omit_dev is false"
        );

        // When omit_dev is true: missing dev-dep is ignored and validation succeeds!
        let mut opts_omit_dev = InstallOptions::default();
        opts_omit_dev.project_dir = tmp.path().to_path_buf();
        opts_omit_dev.omit_dev = true;
        assert!(
            validate_hidden_lockfile(tmp.path(), Some(&opts_omit_dev)),
            "Must be valid when missing dev package is omitted via omit_dev: true"
        );
    }

    #[test]
    fn test_validate_hidden_lockfile_linked_mode_handles_transitive_packages_in_store() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        // Direct dependency: top-dep (installed as junction to store)
        let store_dir = tmp
            .path()
            .join("store")
            .join("top-dep@1.0.0-123456")
            .join("node_modules")
            .join("top-dep");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::write(
            store_dir.join("package.json"),
            r#"{"name": "top-dep", "version": "1.0.0"}"#,
        )
        .unwrap();

        let top_link = nm.join("top-dep");
        rnpm_fs::create_junction(&top_link, &store_dir).unwrap();

        // Transitive dependency: trans-dep (exists in store, NOT in project_dir/node_modules)
        let mut lockfile = LockfileV3::new("test-project", Some("1.0.0".to_string()));
        let mut root_pkg = LockfilePackage::default();
        let mut root_deps = BTreeMap::new();
        root_deps.insert("top-dep".to_string(), "^1.0.0".to_string());
        root_pkg.dependencies = Some(root_deps);
        lockfile.packages.insert("".to_string(), root_pkg);

        let mut top_pkg = LockfilePackage::default();
        top_pkg.version = Some("1.0.0".to_string());
        lockfile
            .packages
            .insert("node_modules/top-dep".to_string(), top_pkg);

        let mut trans_pkg = LockfilePackage::default();
        trans_pkg.version = Some("2.0.0".to_string());
        lockfile
            .packages
            .insert("node_modules/trans-dep".to_string(), trans_pkg);

        std::thread::sleep(std::time::Duration::from_millis(50));
        lockfile.save_hidden(tmp.path()).unwrap();

        let mut opts = InstallOptions::default();
        opts.project_dir = tmp.path().to_path_buf();
        opts.install_strategy = InstallStrategy::Linked;

        // In linked mode, transitive package absence in project_dir/node_modules must NOT invalidate!
        assert!(
            validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "Linked mode must succeed when transitive packages live in store and are absent from project node_modules"
        );
    }

    #[test]
    fn test_validate_hidden_lockfile_invalidated_when_unexpected_files_added() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        let foo_dir = nm.join("foo");
        std::fs::create_dir_all(&foo_dir).unwrap();
        std::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .unwrap();

        let mut lockfile = LockfileV3::new("test-project", Some("1.0.0".to_string()));
        let mut root_pkg = LockfilePackage::default();
        let mut root_deps = BTreeMap::new();
        root_deps.insert("foo".to_string(), "^1.0.0".to_string());
        root_pkg.dependencies = Some(root_deps);
        lockfile.packages.insert("".to_string(), root_pkg);

        let mut foo_pkg = LockfilePackage::default();
        foo_pkg.version = Some("1.0.0".to_string());
        lockfile
            .packages
            .insert("node_modules/foo".to_string(), foo_pkg);

        std::thread::sleep(std::time::Duration::from_millis(50));
        lockfile.save_hidden(tmp.path()).unwrap();

        // Valid initially
        assert!(validate_hidden_lockfile_simple(tmp.path()));

        // Add unexpected folder or file to node_modules later
        std::thread::sleep(std::time::Duration::from_millis(50));
        let unexpected = nm.join("unexpected-folder");
        std::fs::create_dir_all(&unexpected).unwrap();

        // Root node_modules mtime is now newer than hidden lockfile mtime
        assert!(
            !validate_hidden_lockfile_simple(tmp.path()),
            "Hidden lockfile must be invalidated when unexpected files/folders are added to node_modules"
        );
    }
}
