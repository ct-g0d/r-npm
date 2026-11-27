use anyhow::{anyhow, Context, Result};
use data_encoding::HEXLOWER;
use rnpm_cache::{PackStore, PackagePack};
use rnpm_config::Config;
use rnpm_core::manifest::Manifest;
use rnpm_core::workspace::discover_workspaces_from_manifest;
use rnpm_lockfile::LockfileV3;
use rnpm_solver::Platform;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
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
pub use compute_project_fingerprint as compute_input_fingerprint;

pub fn compute_project_fingerprint(project_dir: &Path, options: &InstallOptions) -> Result<String> {
    let manifest_path = project_dir.join("package.json");
    let pkg_json_bytes = match std::fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(anyhow!(
                "package.json not found in {}",
                project_dir.display()
            ));
        }
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to read {}", manifest_path.display()));
        }
    };
    let manifest = Manifest::from_slice_readonly(&pkg_json_bytes)
        .context("Failed to parse project package.json")?;

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
        let member_npmrc = member.path.join(".npmrc");
        if let Ok(bytes) = std::fs::read(&member_npmrc) {
            hasher.update(format!("\nworkspace:{}:.npmrc:\n", member.relative_path).as_bytes());
            hasher.update(&bytes);
        }
    }

    // 3. Lockfile: npm-shrinkwrap.json takes precedence over package-lock.json in npm
    let shrinkwrap_path = project_dir.join("npm-shrinkwrap.json");
    let lockfile_path = project_dir.join("package-lock.json");
    let mut lockfile_bytes_for_version: Option<Vec<u8>> = None;
    match std::fs::read(&shrinkwrap_path) {
        Ok(bytes) => {
            hasher.update(b"\nlockfile:npm-shrinkwrap.json:\n");
            hasher.update(&bytes);
            lockfile_bytes_for_version = Some(bytes);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::read(&lockfile_path) {
                Ok(bytes) => {
                    hasher.update(b"\nlockfile:package-lock.json:\n");
                    hasher.update(&bytes);
                    lockfile_bytes_for_version = Some(bytes);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    hasher.update(b"\nlockfile:none\n");
                }
                Err(_) => {
                    hasher.update(b"\nlockfile:package-lock.json:unreadable\n");
                }
            }
        }
        Err(_) => {
            hasher.update(b"\nlockfile:npm-shrinkwrap.json:unreadable\n");
        }
    }

    // 4. .npmrc configuration & registry settings
    let config: std::borrow::Cow<'_, Config> = if let Some(ref c) = options.config_override {
        std::borrow::Cow::Borrowed(c)
    } else {
        let mut config_opts = rnpm_config::ConfigOptions::new().project_dir(project_dir);
        if let Some(userconfig) = rnpm_config::get_process_userconfig() {
            config_opts = config_opts.userconfig(userconfig);
        }
        if let Some(globalconfig) = rnpm_config::get_process_globalconfig() {
            config_opts = config_opts.globalconfig(globalconfig);
        }
        if let Some(cli_overrides) = rnpm_config::get_process_cli_overrides() {
            config_opts = config_opts.cli_overrides(cli_overrides);
        }
        if let Some(ref reg) = options.registry_url {
            config_opts = config_opts.with_cli("registry", reg.clone());
        }
        let ws_root = rnpm_config::find_workspace_root(project_dir);
        if let Some(ref ws) = ws_root {
            config_opts = config_opts.workspace_root(ws.as_path());
        }
        std::borrow::Cow::Owned(
            Config::load_with_options(config_opts)
                .or_else(|_| Config::load(Some(project_dir)))
                .unwrap_or_default(),
        )
    };
    hasher.update(format!("\nnpmrc:registry:{}\n", config.npmrc.registry).as_bytes());
    let mut sorted_scoped: Vec<_> = config.npmrc.scoped_registries.iter().collect();
    sorted_scoped.sort_by_key(|(k, _)| *k);
    for (scope, url) in sorted_scoped {
        hasher.update(format!("npmrc:scoped:{scope}={url}\n").as_bytes());
    }
    let mut sorted_settings: Vec<_> = config.npmrc.settings.iter().collect();
    sorted_settings.sort_by_key(|(k, _)| *k);
    for (k, v) in sorted_settings {
        hasher.update(format!("npmrc:setting:{k}={v}\n").as_bytes());
    }

    // Hash raw configuration file sources from loaded layers (project, workspace, user, global, builtin),
    // deduplicating file reads when process configs or project/workspace .npmrc match layer paths.
    let mut rc_file_cache: HashMap<PathBuf, Option<Vec<u8>>> = HashMap::with_capacity(8);
    fn read_rc_cached<'a>(
        cache: &'a mut HashMap<PathBuf, Option<Vec<u8>>>,
        path: &Path,
    ) -> Option<&'a [u8]> {
        if !cache.contains_key(path) {
            cache.insert(path.to_path_buf(), std::fs::read(path).ok());
        }
        cache.get(path).and_then(|o| o.as_deref())
    }

    for layer in &config.layers {
        if let Some(ref src) = layer.source {
            if let Some(bytes) = read_rc_cached(&mut rc_file_cache, src) {
                hasher.update(
                    format!("\nconfig_layer:{}:{}:\n", layer.name, src.display()).as_bytes(),
                );
                hasher.update(bytes);
            }
        }
    }

    // Process-level userconfig, globalconfig, and CLI overrides
    if let Some(user_cfg) = rnpm_config::get_process_userconfig() {
        hasher.update(format!("\nprocess_userconfig:{:?}:\n", user_cfg).as_bytes());
        if let Some(bytes) = read_rc_cached(&mut rc_file_cache, &user_cfg) {
            hasher.update(b"userconfig_bytes:\n");
            hasher.update(bytes);
        }
    }
    if let Some(global_cfg) = rnpm_config::get_process_globalconfig() {
        hasher.update(format!("\nprocess_globalconfig:{:?}:\n", global_cfg).as_bytes());
        if let Some(bytes) = read_rc_cached(&mut rc_file_cache, &global_cfg) {
            hasher.update(b"globalconfig_bytes:\n");
            hasher.update(bytes);
        }
    }
    if let Some(cli_map) = rnpm_config::get_process_cli_overrides() {
        for (k, v) in cli_map {
            hasher.update(format!("\nprocess_cli_override:{k}={v}\n").as_bytes());
        }
    }

    let project_npmrc = project_dir.join(".npmrc");
    if let Some(bytes) = read_rc_cached(&mut rc_file_cache, &project_npmrc) {
        hasher.update(b"\nproject_npmrc_bytes:\n");
        hasher.update(bytes);
    }

    let ws_npmrc_opt = if let Some(ref cfg) = options.config_override {
        cfg.layers
            .iter()
            .find(|l| l.name == "workspace")
            .and_then(|l| l.source.clone())
    } else {
        rnpm_config::find_workspace_root(project_dir).map(|ws_root| ws_root.join(".npmrc"))
    };
    if let Some(ws_npmrc) = ws_npmrc_opt {
        if let Some(bytes) = read_rc_cached(&mut rc_file_cache, &ws_npmrc) {
            hasher.update(b"\nworkspace_root_npmrc_bytes:\n");
            hasher.update(bytes);
        }
    }

    // 5. Options impacting resolution and tree structure
    let target_platform = options.platform();
    let mut sorted_include = options.include.clone();
    sorted_include.sort();
    let mut sorted_workspace = options.workspace.clone();
    sorted_workspace.sort();
    let mut sorted_min_release_age_exclude = options.min_release_age_exclude.clone();
    sorted_min_release_age_exclude.sort();

    let effective_lock_ver = if let Some(v) = options.lockfile_version {
        v
    } else if let Some(ref bytes) = lockfile_bytes_for_version {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(crate::detect_lockfile_version)
            .filter(|&v| v == 2)
            .unwrap_or(3)
    } else {
        3
    };

    hasher.update(
        format!(
            "\noptions:install_strategy={:?}:omit_dev={}:omit_opt={}:omit_peer={}:legacy_peer={}:strict_peer={}:global={}:os={:?}:cpu={:?}:libc={:?}:target_os={}:target_cpu={}:target_libc={:?}:lock_ver={}:include={:?}:workspaces={}:workspace_root={}:workspace={:?}:bin_links={}:force={}:ignore_scripts={}:offline={}:prefer_offline={}:prefer_online={}:prefer_dedupe={}:install_links={}:package_lock_only={}:pkg_lock={}:no_pkg_lock={}:registry_url={:?}:before={:?}:release_age_ex={:?}:store_dir={:?}:strict_sandbox={}:foreground_scripts={}:audit={}:fund={}:source_policy={:?}:force_non_root={}:config_override={}\n",
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
            effective_lock_ver,
            sorted_include,
            options.workspaces,
            options.workspace_root,
            sorted_workspace,
            options.bin_links,
            options.force,
            options.ignore_scripts,
            options.offline,
            options.prefer_offline,
            options.prefer_online,
            options.prefer_dedupe,
            options.install_links,
            options.package_lock_only,
            options.package_lock,
            options.no_package_lock,
            options.registry_url,
            options.before_cutoff,
            sorted_min_release_age_exclude,
            options.store_dir,
            options.strict_sandbox,
            options.foreground_scripts,
            options.audit,
            options.fund,
            options.source_policy_override,
            options.force_non_root_policy,
            options.config_override.is_some(),
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
    validate_hidden_lockfile_loaded(project_dir, options).is_some()
}

pub(crate) fn validate_hidden_lockfile_loaded(
    project_dir: &Path,
    options: Option<&InstallOptions>,
) -> Option<(LockfileV3, Option<Manifest>)> {
    let node_modules = project_dir.join("node_modules");
    if !node_modules.is_dir() {
        debug!("Hidden lockfile invalid: node_modules directory does not exist");
        return None;
    }

    let hidden_path = project_dir.join(LockfileV3::HIDDEN_LOCKFILE_PATH);
    let hidden_meta = match std::fs::symlink_metadata(&hidden_path) {
        Ok(m) => m,
        Err(_) => {
            debug!(
                "Hidden lockfile does not exist at {}",
                hidden_path.display()
            );
            return None;
        }
    };
    let hidden_mtime = match hidden_meta.modified() {
        Ok(t) => t,
        Err(_) => return None,
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
                return None;
            }
        }
    }

    // Check modification time of root package-lock.json or npm-shrinkwrap.json if present
    let lockfile_path = project_dir.join("package-lock.json");
    if let Ok(meta) = std::fs::symlink_metadata(&lockfile_path) {
        if let Ok(mtime) = meta.modified() {
            if mtime > hidden_mtime {
                debug!(
                    "Hidden lockfile invalid: package-lock.json mtime ({:?}) is newer than hidden lockfile ({:?})",
                    mtime, hidden_mtime
                );
                return None;
            }
        }
    }
    let shrinkwrap_path = project_dir.join("npm-shrinkwrap.json");
    if let Ok(meta) = std::fs::symlink_metadata(&shrinkwrap_path) {
        if let Ok(mtime) = meta.modified() {
            if mtime > hidden_mtime {
                debug!(
                    "Hidden lockfile invalid: npm-shrinkwrap.json mtime ({:?}) is newer than hidden lockfile ({:?})",
                    mtime, hidden_mtime
                );
                return None;
            }
        }
    }

    // Load lockfile using zero-DOM read-only loader (avoids Value allocations and raw_value cloning)
    let lockfile = match LockfileV3::from_file_readonly(&hidden_path) {
        Ok(l) => l,
        Err(_) => {
            debug!("Hidden lockfile is not valid JSON / LockfileV3");
            return None;
        }
    };

    // Resolve target platform and filtering flags
    let platform = options
        .map(|o| o.platform())
        .unwrap_or_else(Platform::current);

    let omit_dev = options.map(|o| o.omit_dev && !o.include.iter().any(|i| i == "dev")).unwrap_or(false);
    let omit_optional = options.map(|o| o.omit_optional && !o.include.iter().any(|i| i == "optional")).unwrap_or(false);
    let omit_peer = options.map(|o| o.omit_peer && !o.include.iter().any(|i| i == "peer")).unwrap_or(false);

    // Platform-skipped lockfile packages (incompatible optional packages and their descendants)
    let platform_skipped = crate::lockfile_platform_skipped_packages(&lockfile, &platform);

    // Verify root package.json if present on disk
    let pkg_json_path = project_dir.join("package.json");
    let (root_manifest, root_may_have_overrides) = match std::fs::read(&pkg_json_path) {
        Ok(bytes) => {
            if let Ok(meta) = std::fs::symlink_metadata(&pkg_json_path) {
                if let Ok(mtime) = meta.modified() {
                    if mtime > hidden_mtime {
                        debug!(
                            "Hidden lockfile invalid: package.json mtime ({:?}) is newer than hidden lockfile ({:?})",
                            mtime, hidden_mtime
                        );
                        return None;
                    }
                }
            }
            let has_overrides = bytes.windows(9).any(|w| w == b"overrides");
            (Manifest::from_slice_readonly(&bytes).ok(), has_overrides)
        }
        Err(_) => (None, false),
    };

    if let (Some(manifest), Some(root_pkg)) = (&root_manifest, lockfile.packages.get("")) {
        if let Some(lock_deps) = &root_pkg.dependencies {
            for (name, spec) in &manifest.dependencies {
                if manifest.optional_dependencies.contains_key(name) {
                    continue;
                }
                if lock_deps.get(name) != Some(spec) {
                    debug!(
                        "Hidden lockfile invalid: dependency '{}' spec mismatch between package.json ({:?}) and hidden lockfile ({:?})",
                        name, Some(spec), lock_deps.get(name)
                    );
                    return None;
                }
            }
            for name in lock_deps.keys() {
                if !manifest.dependencies.contains_key(name)
                    && !manifest.optional_dependencies.contains_key(name)
                {
                    debug!(
                        "Hidden lockfile invalid: dependency '{}' in hidden lockfile removed from package.json",
                        name
                    );
                    return None;
                }
            }
        } else if !manifest.dependencies.is_empty() {
            debug!("Hidden lockfile invalid: package.json has dependencies but hidden lockfile has none");
            return None;
        }

        if !omit_dev {
            if let Some(lock_dev) = &root_pkg.dev_dependencies {
                for (name, spec) in &manifest.dev_dependencies {
                    if lock_dev.get(name) != Some(spec) {
                        debug!(
                            "Hidden lockfile invalid: devDependency '{}' spec mismatch between package.json ({:?}) and hidden lockfile ({:?})",
                            name, Some(spec), lock_dev.get(name)
                        );
                        return None;
                    }
                }
                for name in lock_dev.keys() {
                    if !manifest.dev_dependencies.contains_key(name) {
                        debug!(
                            "Hidden lockfile invalid: devDependency '{}' in hidden lockfile removed from package.json",
                            name
                        );
                        return None;
                    }
                }
            } else if !manifest.dev_dependencies.is_empty() {
                debug!("Hidden lockfile invalid: package.json has devDependencies but hidden lockfile has none");
                return None;
            }
        }

        if !omit_optional {
            if let Some(lock_opt) = &root_pkg.optional_dependencies {
                for (name, spec) in &manifest.optional_dependencies {
                    if lock_opt.get(name) != Some(spec) {
                        debug!(
                            "Hidden lockfile invalid: optionalDependency '{}' spec mismatch between package.json ({:?}) and hidden lockfile ({:?})",
                            name, Some(spec), lock_opt.get(name)
                        );
                        return None;
                    }
                }
                for name in lock_opt.keys() {
                    if !manifest.optional_dependencies.contains_key(name) {
                        debug!(
                            "Hidden lockfile invalid: optionalDependency '{}' in hidden lockfile removed from package.json",
                            name
                        );
                        return None;
                    }
                }
            } else if !manifest.optional_dependencies.is_empty() {
                debug!("Hidden lockfile invalid: package.json has optionalDependencies but hidden lockfile has none");
                return None;
            }
        }
    }

    // Direct top-level packages declared on root
    let mut direct_top_level_deps: HashSet<String> = HashSet::new();
    let mut optional_or_opt_peer_direct_deps: HashSet<String> = HashSet::new();
    if let Some(root_pkg) = lockfile.packages.get("") {
        if let Some(deps) = &root_pkg.dependencies {
            for name in deps.keys() {
                if root_pkg
                    .optional_dependencies
                    .as_ref()
                    .is_some_and(|od| od.contains_key(name))
                {
                    continue;
                }
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
                    let key = format!("node_modules/{name}");
                    direct_top_level_deps.insert(key.clone());
                    optional_or_opt_peer_direct_deps.insert(key);
                }
            }
        }
        if !omit_peer {
            if let Some(peer_deps) = &root_pkg.peer_dependencies {
                for name in peer_deps.keys() {
                    let is_opt_peer = root_pkg
                        .peer_dependencies_meta
                        .as_ref()
                        .and_then(|m| m.get(name))
                        .and_then(|pm| pm.get("optional"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !is_opt_peer || !omit_optional {
                        let key = format!("node_modules/{name}");
                        direct_top_level_deps.insert(key.clone());
                        if is_opt_peer {
                            optional_or_opt_peer_direct_deps.insert(key);
                        }
                    }
                }
            }
        }
    } else if let Some(manifest) = &root_manifest {
        let check_direct_spec = |key: &str, name: &str, spec: &str| -> bool {
            if root_may_have_overrides || platform_skipped.contains(key) {
                return true;
            }
            let Some(pkg) = lockfile.packages.get(key) else {
                return true;
            };
            if pkg.link == Some(true) || pkg.name.as_deref().is_some_and(|n| n != name) {
                return true;
            }
            let Some(ver_str) = pkg.version.as_deref() else {
                return true;
            };
            if let (Ok(range), Ok(ver)) = (
                rnpm_core::semver::Range::parse(spec),
                rnpm_core::semver::Version::parse(ver_str),
            ) {
                if !range.satisfies(&ver) {
                    debug!(
                        "Hidden lockfile invalid: installed {}@{} does not satisfy package.json spec '{}'",
                        name, ver_str, spec
                    );
                    return false;
                }
            }
            true
        };

        for (name, spec) in &manifest.dependencies {
            if manifest.optional_dependencies.contains_key(name) {
                continue;
            }
            let key = format!("node_modules/{name}");
            if !check_direct_spec(&key, name, spec) {
                return None;
            }
            direct_top_level_deps.insert(key);
        }
        if !omit_dev {
            for (name, spec) in &manifest.dev_dependencies {
                let key = format!("node_modules/{name}");
                if !check_direct_spec(&key, name, spec) {
                    return None;
                }
                direct_top_level_deps.insert(key);
            }
        }
        if !omit_optional {
            for (name, spec) in &manifest.optional_dependencies {
                let key = format!("node_modules/{name}");
                if !check_direct_spec(&key, name, spec) {
                    return None;
                }
                direct_top_level_deps.insert(key.clone());
                optional_or_opt_peer_direct_deps.insert(key);
            }
        }
        if !omit_peer {
            for name in manifest.peer_dependencies.keys() {
                let is_opt_peer = manifest.peer_dependencies_meta.get(name).map(|pm| pm.optional).unwrap_or(false);
                if !is_opt_peer || !omit_optional {
                    let key = format!("node_modules/{name}");
                    direct_top_level_deps.insert(key.clone());
                    if is_opt_peer {
                        optional_or_opt_peer_direct_deps.insert(key);
                    }
                }
            }
        }
    }

    struct DiskEntry {
        path: PathBuf,
        is_symlink: bool,
    }

    let mut disk_packages: HashMap<String, DiskEntry> = HashMap::with_capacity(lockfile.packages.len());
    #[cfg(windows)]
    let mut disk_packages_lower: HashMap<String, String> = HashMap::with_capacity(lockfile.packages.len());

    let mut detected_junction = false;

    // Fast directory scan: populate entries for top-level and scoped package directories in node_modules,
    // and verify scope directory modification times. Non-directory files are ignored.
    let nm_entries = match std::fs::read_dir(&node_modules) {
        Ok(e) => e,
        Err(_) => return None,
    };

    for entry in nm_entries.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str.starts_with('.') {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let is_symlink = rnpm_fs::is_dir_entry_reparse_or_symlink(&entry, &file_type);
        if is_symlink {
            detected_junction = true;
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
                        return None;
                    }
                }
            }
            if let Ok(scoped_entries) = std::fs::read_dir(entry.path()) {
                for scoped_entry in scoped_entries.flatten() {
                    let sub_name = scoped_entry.file_name();
                    let sub_str = sub_name.to_string_lossy();
                    if sub_str.starts_with('.') {
                        continue;
                    }
                    let Ok(sub_type) = scoped_entry.file_type() else {
                        continue;
                    };
                    let sub_is_symlink =
                        rnpm_fs::is_dir_entry_reparse_or_symlink(&scoped_entry, &sub_type);
                    if sub_is_symlink {
                        detected_junction = true;
                    }
                    let is_sub_dir = sub_type.is_dir() || sub_is_symlink;
                    if !is_sub_dir {
                        continue;
                    }

                    let mtime = scoped_entry.metadata().ok().and_then(|m| m.modified().ok());
                    if let Some(m) = mtime {
                        if m > hidden_mtime {
                            debug!(
                                "Hidden lockfile invalid: package folder 'node_modules/{}/{}' mtime ({:?}) is newer than hidden lockfile ({:?})",
                                name_str, sub_str, m, hidden_mtime
                            );
                            return None;
                        }
                    }

                    let key = format!("node_modules/{}/{}", name_str, sub_str);
                    #[cfg(windows)]
                    disk_packages_lower.insert(key.to_ascii_lowercase(), key.clone());

                    disk_packages.insert(key, DiskEntry {
                        path: scoped_entry.path(),
                        is_symlink: sub_is_symlink,
                    });
                }
            }
        } else {
            let is_dir = file_type.is_dir() || is_symlink;
            if !is_dir {
                continue;
            }

            let mtime = entry.metadata().ok().and_then(|m| m.modified().ok());
            if let Some(m) = mtime {
                if m > hidden_mtime {
                    debug!(
                        "Hidden lockfile invalid: package folder 'node_modules/{}' mtime ({:?}) is newer than hidden lockfile ({:?})",
                        name_str, m, hidden_mtime
                    );
                    return None;
                }
            }

            let key = format!("node_modules/{}", name_str);
            #[cfg(windows)]
            disk_packages_lower.insert(key.to_ascii_lowercase(), key.clone());

            disk_packages.insert(key, DiskEntry {
                path: entry.path(),
                is_symlink,
            });
        }
    }

    let is_linked = options
        .map(|o| o.install_strategy == InstallStrategy::Linked)
        .unwrap_or(detected_junction);

    // Verify there are no extraneous package directories in node_modules
    let has_backslash_keys = lockfile.packages.keys().any(|k| k.contains('\\'));
    let normalized_lockfile_keys_owned: HashSet<String> = if has_backslash_keys {
        lockfile
            .packages
            .keys()
            .map(|k| k.replace('\\', "/"))
            .collect()
    } else {
        HashSet::new()
    };

    #[cfg(windows)]
    let normalized_lockfile_keys_lower: HashSet<String> = if has_backslash_keys {
        normalized_lockfile_keys_owned
            .iter()
            .map(|k| k.to_ascii_lowercase())
            .collect()
    } else {
        lockfile
            .packages
            .keys()
            .map(|k| k.to_ascii_lowercase())
            .collect()
    };

    for key in disk_packages.keys() {
        let is_known = if has_backslash_keys {
            normalized_lockfile_keys_owned.contains(key)
        } else {
            lockfile.packages.contains_key(key)
        };
        #[cfg(windows)]
        let is_known = is_known || normalized_lockfile_keys_lower.contains(&key.to_ascii_lowercase());

        if !is_known {
            debug!(
                "Hidden lockfile invalid: extraneous directory '{}' found on disk",
                key
            );
            return None;
        }
    }

    // Verify all non-omitted, non-skipped direct dependencies exist in lockfile and on disk
    for dep_key in &direct_top_level_deps {
        let pkg_info = lockfile.packages.get(dep_key)
            .or_else(|| lockfile.packages.get(&dep_key.replace('/', "\\")));

        let on_disk = disk_packages.contains_key(dep_key);
        #[cfg(windows)]
        let on_disk = on_disk || disk_packages_lower.contains_key(&dep_key.to_ascii_lowercase());

        let Some(pkg_info) = pkg_info else {
            // Platform-skipped optional / optional-peer direct dependencies (e.g. fsevents on Windows/Linux)
            // are stripped from `node_modules/.package-lock.json` by `save_hidden` and are not on disk.
            if optional_or_opt_peer_direct_deps.contains(dep_key) && !on_disk {
                continue;
            }
            debug!(
                "Hidden lockfile invalid: declared direct dependency '{}' missing from hidden lockfile",
                dep_key
            );
            return None;
        };

        let is_platform_skipped = platform_skipped.contains(dep_key)
            || pkg_info.extra.get("skipped").and_then(|v| v.as_bool()).unwrap_or(false)
            || ((pkg_info.is_effective_optional() || pkg_info.is_peer_optional())
                && !platform.matches_with_libc(
                    pkg_info.os.as_deref(),
                    pkg_info.cpu.as_deref(),
                    pkg_info.libc.as_deref(),
                ));
        let dev_opt = pkg_info.dev_optional.unwrap_or(false);
        let is_dev = (pkg_info.is_dev() || pkg_info.dev.unwrap_or(false)) && !dev_opt;
        let is_opt = (pkg_info.is_effective_optional() || pkg_info.is_peer_optional()) && !dev_opt;
        let is_peer = pkg_info.peer.unwrap_or(false) || pkg_info.peer_optional.unwrap_or(false);
        let is_omitted = (omit_dev && is_dev)
            || (omit_optional && is_opt)
            || (omit_dev && omit_optional && dev_opt)
            || (omit_peer && is_peer);

        if is_platform_skipped || is_omitted {
            continue;
        }

        if !on_disk {
            debug!(
                "Hidden lockfile invalid: declared direct dependency '{}' missing on disk",
                dep_key
            );
            return None;
        }
    }

    struct PackageDiskCheck<'a> {
        folder_path: Cow<'a, Path>,
        is_link_or_junction: bool,
        check_mtime: Option<SystemTime>,
    }

    let mut checks: Vec<PackageDiskCheck> = Vec::with_capacity(lockfile.packages.len());
    let mut present_packages: HashSet<String> = HashSet::with_capacity(lockfile.packages.len());
    #[cfg(windows)]
    let mut present_packages_lower: HashSet<String> = HashSet::with_capacity(lockfile.packages.len());

    // Verify every package folder listed in lockfile:
    // - If it exists on disk, its mtime must be <= hidden_mtime
    // - If it does not exist on disk, check if it was platform-skipped, omitted,
    //   or is a transitive package in linked mode (which lives in the store).
    for (pkg_key, pkg_info) in &lockfile.packages {
        if pkg_key.is_empty() {
            continue;
        }
        let normalized_key: Cow<str> = if pkg_key.contains('\\') {
            Cow::Owned(pkg_key.replace('\\', "/"))
        } else {
            Cow::Borrowed(pkg_key)
        };

        if !normalized_key.starts_with("node_modules/") && !normalized_key.contains("/node_modules/") {
            // Workspace member directory (e.g. "packages/a")
            let ws_folder = project_dir.join(normalized_key.as_ref());
            checks.push(PackageDiskCheck {
                folder_path: Cow::Owned(ws_folder),
                is_link_or_junction: false,
                check_mtime: None,
            });
            continue;
        }

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

        let is_dev_optional = pkg_info.dev_optional.unwrap_or(false);
        let is_dev = (pkg_info.is_dev() || pkg_info.dev.unwrap_or(false)) && !is_dev_optional;
        let is_optional = (pkg_info.is_effective_optional() || pkg_info.is_peer_optional()) && !is_dev_optional;
        let is_peer = pkg_info.peer.unwrap_or(false) || pkg_info.peer_optional.unwrap_or(false);

        let is_omitted = (omit_dev && is_dev)
            || (omit_optional && is_optional)
            || (omit_dev && omit_optional && is_dev_optional)
            || (omit_peer && is_peer);

        let is_top_level = direct_top_level_deps.contains(normalized_key.as_ref());
        let is_transitive_in_linked = is_linked && !is_top_level;

        let is_nested = normalized_key.contains("/node_modules/");
        let is_link = pkg_info.link == Some(true);

        if !is_nested {
            let disk_pkg = disk_packages.get(normalized_key.as_ref());
            #[cfg(windows)]
            let disk_pkg = disk_pkg.or_else(|| {
                disk_packages_lower.get(&normalized_key.to_ascii_lowercase()).and_then(|k| disk_packages.get(k))
            });

            if let Some(entry) = disk_pkg {
                if is_omitted {
                    debug!(
                        "Hidden lockfile invalid: package folder '{}' exists on disk but is omitted by options",
                        normalized_key
                    );
                    return None;
                }

                // In linked mode, top-level non-link packages MUST be junctions to the store
                if is_linked && is_top_level && !is_link && !entry.is_symlink {
                    debug!(
                        "Hidden lockfile invalid: top-level package '{}' is a directory instead of a junction in linked mode",
                        normalized_key
                    );
                    return None;
                }

                present_packages.insert(normalized_key.to_string());
                #[cfg(windows)]
                present_packages_lower.insert(normalized_key.to_ascii_lowercase());

                checks.push(PackageDiskCheck {
                    folder_path: Cow::Borrowed(&entry.path),
                    is_link_or_junction: entry.is_symlink || is_link,
                    check_mtime: None,
                });
            } else {
                // Missing on disk
                if is_platform_skipped || is_omitted || is_transitive_in_linked {
                    continue;
                }
                debug!(
                    "Hidden lockfile invalid: package folder '{}' missing from disk",
                    normalized_key
                );
                return None;
            }
        } else {
            // Nested package
            let folder_path = project_dir.join(normalized_key.as_ref());
            let is_junction = rnpm_fs::is_junction(&folder_path).unwrap_or(false);
            let exists_on_disk = folder_path.exists() || is_junction;

            if exists_on_disk {
                if is_omitted {
                    debug!(
                        "Hidden lockfile invalid: nested package folder '{}' exists on disk but is omitted by options",
                        normalized_key
                    );
                    return None;
                }

                let folder_mtime = match std::fs::symlink_metadata(&folder_path) {
                    Ok(meta) => meta.modified().ok(),
                    Err(_) => return None,
                };

                present_packages.insert(normalized_key.to_string());
                #[cfg(windows)]
                present_packages_lower.insert(normalized_key.to_ascii_lowercase());

                checks.push(PackageDiskCheck {
                    folder_path: Cow::Owned(folder_path),
                    is_link_or_junction: is_junction || is_link,
                    check_mtime: folder_mtime,
                });
            } else {
                if is_platform_skipped || is_omitted || is_transitive_in_linked {
                    continue;
                }
                debug!(
                    "Hidden lockfile invalid: nested package folder '{}' missing from disk",
                    normalized_key
                );
                return None;
            }
        }
    }

    // Execute package disk checks (package.json presence/length, junction target existence, mtime)
    let avail = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let num_threads = checks.len().div_ceil(16).min(avail).min(8);

    if checks.len() <= 16 || num_threads <= 1 {
        for check in &checks {
            if check.is_link_or_junction && !check.folder_path.exists() {
                debug!(
                    "Hidden lockfile invalid: junction or link target for '{:?}' is missing on disk",
                    check.folder_path
                );
                return None;
            }
            if let Some(mtime) = check.check_mtime {
                if mtime > hidden_mtime {
                    debug!(
                        "Hidden lockfile invalid: package folder '{:?}' mtime ({:?}) is newer than hidden lockfile ({:?})",
                        check.folder_path, mtime, hidden_mtime
                    );
                    return None;
                }
            }
            let pkg_json = check.folder_path.join("package.json");
            let is_valid = match std::fs::metadata(&pkg_json) {
                Ok(m) => m.is_file() && m.len() > 0,
                Err(_) => false,
            };
            if !is_valid {
                debug!(
                    "Hidden lockfile invalid: package.json missing or 0 bytes in package folder '{:?}'",
                    check.folder_path
                );
                return None;
            }
        }
    } else {
        let chunk_size = checks.len().div_ceil(num_threads);
        let failed = std::sync::atomic::AtomicBool::new(false);

        std::thread::scope(|scope| {
            for chunk in checks.chunks(chunk_size) {
                let failed_ref = &failed;
                scope.spawn(move || {
                    for check in chunk {
                        if failed_ref.load(std::sync::atomic::Ordering::Relaxed) {
                            return;
                        }
                        if check.is_link_or_junction && !check.folder_path.exists() {
                            failed_ref.store(true, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        if let Some(mtime) = check.check_mtime {
                            if mtime > hidden_mtime {
                                failed_ref.store(true, std::sync::atomic::Ordering::Relaxed);
                                return;
                            }
                        }
                        let pkg_json = check.folder_path.join("package.json");
                        let is_valid = match std::fs::metadata(&pkg_json) {
                            Ok(m) => m.is_file() && m.len() > 0,
                            Err(_) => false,
                        };
                        if !is_valid {
                            failed_ref.store(true, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                    }
                });
            }
        });

        if failed.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
    }

    // Check bin shims when bin_links is active
    let check_bin_links = options.map(|o| o.bin_links).unwrap_or(true);
    if check_bin_links {
        let known_bins = build_known_bins_map(&lockfile);
        let bin_dir = node_modules.join(".bin");
        let mut bin_files = HashSet::new();
        let bin_dir_is_dir = bin_dir.is_dir();
        if bin_dir_is_dir {
            if let Ok(entries) = std::fs::read_dir(&bin_dir) {
                for entry in entries.flatten() {
                    let s = entry.file_name().to_string_lossy().to_string();
                    #[cfg(windows)]
                    bin_files.insert(s.to_ascii_lowercase());
                    #[cfg(not(windows))]
                    bin_files.insert(s);
                }
            }
        }

        let mut has_expected_bins = false;

        for (loc, bins) in &known_bins {
            let normalized: Cow<str> = if loc.contains('\\') {
                Cow::Owned(loc.replace('\\', "/"))
            } else {
                Cow::Borrowed(loc)
            };
            if !normalized.starts_with("node_modules/") && !normalized.contains("/node_modules/") {
                continue;
            }

            let exists_pkg = present_packages.contains(normalized.as_ref());
            #[cfg(windows)]
            let exists_pkg = exists_pkg || present_packages_lower.contains(&normalized.to_ascii_lowercase());
            if !exists_pkg {
                continue;
            }

            if let Some(pkg_info) = lockfile.packages.get(loc) {
                let is_skipped = platform_skipped.contains(loc)
                    || pkg_info.extra.get("skipped").and_then(|v| v.as_bool()).unwrap_or(false)
                    || ((pkg_info.is_effective_optional() || pkg_info.is_peer_optional())
                        && !platform.matches_with_libc(
                            pkg_info.os.as_deref(),
                            pkg_info.cpu.as_deref(),
                            pkg_info.libc.as_deref(),
                        ));
                let dev_opt = pkg_info.dev_optional.unwrap_or(false);
                let is_dev = (pkg_info.is_dev() || pkg_info.dev.unwrap_or(false)) && !dev_opt;
                let is_opt = (pkg_info.is_effective_optional() || pkg_info.is_peer_optional()) && !dev_opt;
                let is_peer = pkg_info.peer.unwrap_or(false) || pkg_info.peer_optional.unwrap_or(false);
                let is_omitted = (omit_dev && is_dev)
                    || (omit_optional && is_opt)
                    || (omit_dev && omit_optional && dev_opt)
                    || (omit_peer && is_peer);
                if is_skipped || is_omitted {
                    continue;
                }
            }

            let is_top_level = direct_top_level_deps.contains(normalized.as_ref())
                || normalized
                    .strip_prefix("node_modules/")
                    .is_some_and(|rest| !rest.contains("/node_modules/"));
            if is_top_level {
                for (bin_name, _) in bins {
                    has_expected_bins = true;
                    #[cfg(windows)]
                    let bin_exists = {
                        let lower = bin_name.to_ascii_lowercase();
                        bin_files.contains(&format!("{lower}.cmd"))
                            || bin_files.contains(&lower)
                            || bin_files.contains(&format!("{lower}.ps1"))
                    };
                    #[cfg(not(windows))]
                    let bin_exists = bin_files.contains(bin_name);

                    if !bin_exists {
                        debug!(
                            "Hidden lockfile invalid: expected bin shim '{}' for '{}' is missing in {}",
                            bin_name,
                            normalized,
                            bin_dir.display()
                        );
                        return None;
                    }
                }
            }
        }

        if has_expected_bins && !bin_dir_is_dir {
            debug!("Hidden lockfile invalid: node_modules/.bin directory missing");
            return None;
        }
    }

    Some((lockfile, root_manifest))
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

fn parse_engines_fallback_from_bytes(bytes: &[u8]) -> Option<rnpm_lockfile::PackageEngines> {
    if !bytes.windows(9).any(|w| w == b"\"engines\"") && !bytes.windows(2).any(|w| w == b"\\u") {
        return None;
    }
    let clean = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let json: serde_json::Value = serde_json::from_slice(clean).ok()?;
    let engines_val = json.get("engines")?;
    let engines: rnpm_lockfile::PackageEngines = serde_json::from_value(engines_val.clone()).ok()?;
    (!engines.is_empty()).then_some(engines)
}

/// Enrich lockfile entries with author/funding/license/engines from installed manifests
pub fn enrich_lockfile_from_installed_manifests(
    lockfile: &mut LockfileV3,
    project_dir: &Path,
    manifest_cache: Option<&HashMap<String, Manifest>>,
) {
    let mut manifests_by_loc: HashMap<String, Manifest> = HashMap::new();
    let mut raw_engines_by_loc: HashMap<String, rnpm_lockfile::PackageEngines> = HashMap::new();
    let mut missing_locations = Vec::new();

    for (location, package) in &lockfile.packages {
        if location.is_empty() || package.link == Some(true) {
            continue;
        }
        // A cached manifest costs no IO, so always use it: npm also records
        // fields such as `workspaces` that the registry metadata lacks.
        if let Some(cache) = manifest_cache {
            if let Some(m) = cache.get(location) {
                manifests_by_loc.insert(location.clone(), m.clone());
                continue;
            }
        }
        // Registry metadata never carries `workspaces`, so even entries with
        // license and engines need their package.json read.
        missing_locations.push(location.clone());
    }

    if !missing_locations.is_empty() {
        let num_threads = 16.min(missing_locations.len());
        let chunk_size = missing_locations.len().div_ceil(num_threads);
        let (disk_manifests, disk_engines) = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(num_threads);
            for chunk in missing_locations.chunks(chunk_size) {
                handles.push(scope.spawn(move || {
                    let mut local = Vec::with_capacity(chunk.len());
                    let mut local_engines = Vec::new();
                    for loc in chunk {
                        let manifest_path = if loc.is_empty() {
                            project_dir.join("package.json")
                        } else {
                            project_dir.join(loc).join("package.json")
                        };
                        if let Ok(bytes) = std::fs::read(&manifest_path) {
                            if let Ok(m) = Manifest::from_slice_readonly(&bytes) {
                                if m.engines.is_empty() && !m.extra.contains_key("engines") {
                                    if let Some(engines) = parse_engines_fallback_from_bytes(&bytes) {
                                        local_engines.push((loc.clone(), engines));
                                    }
                                }
                                local.push((loc.clone(), m));
                            }
                        }
                    }
                    (local, local_engines)
                }));
            }
            let mut results = HashMap::with_capacity(missing_locations.len());
            let mut engines_results = HashMap::new();
            for handle in handles {
                if let Ok((items, eng_items)) = handle.join() {
                    results.extend(items);
                    engines_results.extend(eng_items);
                }
            }
            (results, engines_results)
        });
        manifests_by_loc.extend(disk_manifests);
        raw_engines_by_loc.extend(disk_engines);
    }

    for (location, manifest) in manifests_by_loc {
        let Some(package) = lockfile.packages.get_mut(&location) else {
            continue;
        };

        if package.license.is_none() {
            package.license = manifest.extra.get("license").and_then(|value| {
                if let Some(s) = value.as_str() {
                    Some(s.to_string())
                } else if let Some(obj) = value.as_object() {
                    obj.get("type").and_then(|t| t.as_str()).map(str::to_owned)
                } else {
                    None
                }
            });
        }

        // arborist pkgMetaKeys: the abbreviated packument has no `workspaces`,
        // so npm records it from the installed package.json.
        if !location.is_empty() && !package.extra.contains_key("workspaces") {
            let workspaces = match &manifest.workspaces {
                Some(rnpm_core::manifest::PackageWorkspaces::List(list)) if !list.is_empty() => {
                    serde_json::to_value(list).ok()
                }
                Some(config @ rnpm_core::manifest::PackageWorkspaces::Config { .. }) => {
                    serde_json::to_value(config).ok()
                }
                _ => None,
            };
            if let Some(value) = workspaces {
                package.extra.insert("workspaces".to_string(), value);
            }
        }

        // Parity with npm Arborist: populate bundleDependencies from installed manifest
        if package.bundle_dependencies.is_none() {
            if let Some(ref bundled) = manifest.bundled_dependencies {
                package.bundle_dependencies = Some(bundled.clone());
            }
        }

        if package.engines.is_none() {
            if let Some(engines_val) = manifest.extra.get("engines") {
                if let Ok(engines) = serde_json::from_value::<rnpm_lockfile::PackageEngines>(
                    engines_val.clone(),
                ) {
                    if !engines.is_empty() {
                        package.engines = Some(engines);
                    }
                }
            } else if !manifest.engines.is_empty() {
                package.engines =
                    Some(rnpm_lockfile::PackageEngines::Map(manifest.engines.clone()));
            } else if let Some(engines) = raw_engines_by_loc.remove(&location) {
                package.engines = Some(engines);
            } else if let Some(engines) = manifest
                .raw_text
                .as_deref()
                .and_then(|raw| parse_engines_fallback_from_bytes(raw.as_bytes()))
            {
                package.engines = Some(engines);
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
    fn test_compute_project_fingerprint_includes_bin_links() {
        let tmp = tempdir().unwrap();
        let pkg_json = tmp.path().join("package.json");
        std::fs::write(&pkg_json, r#"{"name": "test-pkg", "version": "1.0.0"}"#).unwrap();

        let mut opts_true = InstallOptions::default();
        opts_true.project_dir = tmp.path().to_path_buf();
        opts_true.bin_links = true;

        let mut opts_false = opts_true.clone();
        opts_false.bin_links = false;

        let fp_true = compute_project_fingerprint(tmp.path(), &opts_true).unwrap();
        let fp_false = compute_project_fingerprint(tmp.path(), &opts_false).unwrap();

        assert_ne!(
            fp_true, fp_false,
            "bin_links true vs false must produce different fingerprints"
        );
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
        darwin_pkg.os = Some(vec!["darwin".to_string()].into()); // incompatible on Windows
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

    #[test]
    fn test_validate_hidden_lockfile_detects_missing_bin_shims() {
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
        let mut bin_map = BTreeMap::new();
        bin_map.insert("foo-cli".to_string(), "bin/cli.js".to_string());
        foo_pkg.bin = Some(rnpm_lockfile::PackageBin::Map(bin_map));
        lockfile
            .packages
            .insert("node_modules/foo".to_string(), foo_pkg);

        // Case 1: node_modules/.bin not created yet
        std::thread::sleep(std::time::Duration::from_millis(50));
        lockfile.save_hidden(tmp.path()).unwrap();

        let mut opts = InstallOptions::default();
        opts.project_dir = tmp.path().to_path_buf();
        opts.bin_links = false;

        // When bin_links=false, missing bin shims must NOT invalidate!
        assert!(
            validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "Must be valid when bin_links=false even if node_modules/.bin is missing"
        );

        // When bin_links=true, missing bin shims MUST invalidate!
        opts.bin_links = true;
        assert!(
            !validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "Must be invalid when bin_links=true and node_modules/.bin is missing"
        );

        // Case 2: Create bin shims and re-save hidden lockfile
        let bin_dir = nm.join(".bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        #[cfg(windows)]
        let shim_path = bin_dir.join("foo-cli.cmd");
        #[cfg(not(windows))]
        let shim_path = bin_dir.join("foo-cli");
        std::fs::write(&shim_path, "@echo off\n").unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));
        lockfile.save_hidden(tmp.path()).unwrap();

        // Valid initially with bin shims present
        assert!(
            validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "Must be valid when bin shims exist"
        );

        // Remove the individual bin shim (without touching node_modules directory mtime)
        std::fs::remove_file(&shim_path).unwrap();
        assert!(
            !validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "Must be invalid when bin shim was deleted and bin_links=true"
        );

        // With bin_links=false, missing shim must NOT invalidate!
        opts.bin_links = false;
        assert!(
            validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "Must be valid when bin_links=false even if shim was removed"
        );
    }

    #[test]
    fn test_validate_hidden_lockfile_detects_corrupted_zero_byte_package_json() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        let foo_dir = nm.join("foo");
        std::fs::create_dir_all(&foo_dir).unwrap();
        // 0-byte package.json (corrupted)
        std::fs::write(foo_dir.join("package.json"), b"").unwrap();

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

        let mut opts = InstallOptions::default();
        opts.project_dir = tmp.path().to_path_buf();

        assert!(
            !validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "Must be invalid when package.json is 0 bytes (corrupted)"
        );
    }

    #[test]
    fn test_validate_hidden_lockfile_detects_dangling_workspace_link() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        let ws_dir = tmp.path().join("packages").join("pkg-a");
        std::fs::create_dir_all(&ws_dir).unwrap();
        std::fs::write(
            ws_dir.join("package.json"),
            r#"{"name": "pkg-a", "version": "1.0.0"}"#,
        )
        .unwrap();

        let link_path = nm.join("pkg-a");
        rnpm_fs::create_junction(&link_path, &ws_dir).unwrap();

        let mut lockfile = LockfileV3::new("test-project", Some("1.0.0".to_string()));
        let mut root_pkg = LockfilePackage::default();
        let mut root_deps = BTreeMap::new();
        root_deps.insert("pkg-a".to_string(), "^1.0.0".to_string());
        root_pkg.dependencies = Some(root_deps);
        lockfile.packages.insert("".to_string(), root_pkg);

        let mut ws_pkg = LockfilePackage::default();
        ws_pkg.version = Some("1.0.0".to_string());
        ws_pkg.link = Some(true);
        ws_pkg.resolved = Some("packages/pkg-a".to_string());
        lockfile
            .packages
            .insert("node_modules/pkg-a".to_string(), ws_pkg);

        let mut target_pkg = LockfilePackage::default();
        target_pkg.version = Some("1.0.0".to_string());
        lockfile
            .packages
            .insert("packages/pkg-a".to_string(), target_pkg);

        std::thread::sleep(std::time::Duration::from_millis(50));
        lockfile.save_hidden(tmp.path()).unwrap();

        let mut opts = InstallOptions::default();
        opts.project_dir = tmp.path().to_path_buf();

        // Valid initially
        assert!(
            validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "Must be valid when workspace link and target exist"
        );

        // Delete the workspace target folder -> dangling junction
        std::fs::remove_dir_all(&ws_dir).unwrap();

        assert!(
            !validate_hidden_lockfile(tmp.path(), Some(&opts)),
            "Must be invalid when workspace junction target was deleted"
        );
    }

    #[test]
    fn test_validate_hidden_lockfile_dev_optional_not_omitted_by_omit_dev_alone() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        let dep_dir = nm.join("dev-opt-dep");
        std::fs::create_dir_all(&dep_dir).unwrap();
        std::fs::write(
            dep_dir.join("package.json"),
            r#"{"name": "dev-opt-dep", "version": "1.0.0"}"#,
        )
        .unwrap();

        let mut lockfile = LockfileV3::new("test-project", Some("1.0.0".to_string()));
        let mut root_pkg = LockfilePackage::default();
        let mut root_deps = BTreeMap::new();
        root_deps.insert("dev-opt-dep".to_string(), "^1.0.0".to_string());
        root_pkg.dependencies = Some(root_deps);
        lockfile.packages.insert("".to_string(), root_pkg);

        let mut dep_pkg = LockfilePackage::default();
        dep_pkg.version = Some("1.0.0".to_string());
        dep_pkg.dev_optional = Some(true); // devOptional package
        lockfile
            .packages
            .insert("node_modules/dev-opt-dep".to_string(), dep_pkg);

        std::thread::sleep(std::time::Duration::from_millis(50));
        lockfile.save_hidden(tmp.path()).unwrap();

        // 1. Under omit_dev=true only: devOptional is NOT omitted in npm Arborist, so staying on disk is VALID!
        let mut opts_omit_dev = InstallOptions::default();
        opts_omit_dev.project_dir = tmp.path().to_path_buf();
        opts_omit_dev.omit_dev = true;
        opts_omit_dev.omit_optional = false;
        assert!(
            validate_hidden_lockfile(tmp.path(), Some(&opts_omit_dev)),
            "devOptional package on disk must NOT be considered omitted under omit_dev=true alone"
        );

        // 2. Under omit_optional=true only: devOptional is also NOT omitted!
        let mut opts_omit_opt = InstallOptions::default();
        opts_omit_opt.project_dir = tmp.path().to_path_buf();
        opts_omit_opt.omit_dev = false;
        opts_omit_opt.omit_optional = true;
        assert!(
            validate_hidden_lockfile(tmp.path(), Some(&opts_omit_opt)),
            "devOptional package on disk must NOT be considered omitted under omit_optional=true alone"
        );

        // 3. Under BOTH omit_dev=true AND omit_optional=true: devOptional IS omitted!
        // Because it's on disk, validate_hidden_lockfile must return false so prune runs!
        let mut opts_omit_both = InstallOptions::default();
        opts_omit_both.project_dir = tmp.path().to_path_buf();
        opts_omit_both.omit_dev = true;
        opts_omit_both.omit_optional = true;
        assert!(
            !validate_hidden_lockfile(tmp.path(), Some(&opts_omit_both)),
            "devOptional package on disk MUST be considered omitted when BOTH omit_dev and omit_optional are true"
        );
    }

    #[test]
    fn test_enrich_lockfile_enriches_bundle_dependencies() {
        let tmp = tempdir().unwrap();
        let pkg_dir = tmp.path().join("node_modules").join("bundler-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            serde_json::json!({
                "name": "bundler-pkg",
                "version": "1.0.0",
                "dependencies": {
                    "bundled-dep": "1.0.0"
                },
                "bundleDependencies": ["bundled-dep"]
            })
            .to_string(),
        )
        .unwrap();

        let mut lockfile = LockfileV3::new("test-project", Some("1.0.0".to_string()));
        let mut bundler_pkg = LockfilePackage::default();
        bundler_pkg.version = Some("1.0.0".to_string());
        bundler_pkg.bundle_dependencies = None; // initially not set
        lockfile
            .packages
            .insert("node_modules/bundler-pkg".to_string(), bundler_pkg);

        enrich_lockfile_from_installed_manifests(&mut lockfile, tmp.path(), None);

        let enriched = lockfile.packages.get("node_modules/bundler-pkg").unwrap();
        assert!(
            enriched.bundle_dependencies.is_some(),
            "bundle_dependencies must be enriched from installed package.json"
        );
        match &enriched.bundle_dependencies {
            Some(rnpm_core::manifest::BundledDependencies::List(list)) => {
                assert_eq!(list, &vec!["bundled-dep".to_string()]);
            }
            _ => panic!("Expected BundledDependencies::List"),
        }
    }
}
