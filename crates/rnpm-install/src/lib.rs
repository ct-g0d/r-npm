use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::path::PathBuf;
use anyhow::{anyhow, Context, Result};
use tracing::{debug, info, warn};
use url::Url;

use rnpm_cache::Cache;
use rnpm_config::Config;
use rnpm_core::integrity::Integrity;
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_fs::junction::{is_junction, remove_junction};
use rnpm_fs::tarball::extract_tar_gz;
use rnpm_lifecycle::{
    execute_lifecycle_script, execute_topological, LifecycleContext, LifecycleOptions,
    LifecyclePackageNode, PackageSource,
};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use rnpm_registry::client::{RegistryClient, RegistryClientConfig};
use rnpm_registry::metadata::AbbreviatedPackageMetadata;
use rnpm_shim::{create_shims, normalize_shebang};
use rnpm_solver::Platform;
use rnpm_solver::graph::DependencyGraph;

/// Options for running rnpm install.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub project_dir: PathBuf,
    pub registry_url: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub offline: bool,
    pub ignore_scripts: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::from("."),
            registry_url: None,
            cache_dir: None,
            offline: false,
            ignore_scripts: false,
        }
    }
}

/// Result of an installation run.
#[derive(Debug, Clone)]
pub struct InstallSummary {
    pub packages_installed: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub lockfile_path: PathBuf,
}

/// Resolved node in dependency graph.
#[derive(Debug, Clone)]
pub struct ResolvedNode {
    pub name: String,
    pub version: String,
    pub resolved_url: String,
    pub integrity: String,
    pub dependencies: BTreeMap<String, String>,
    pub optional_dependencies: BTreeMap<String, String>,
    pub optional: bool,
    pub skipped: bool,
    pub os: Vec<String>,
    pub cpu: Vec<String>,
    pub libc: Vec<String>,
}

pub struct Installer {
    options: InstallOptions,
    cache: Cache,
    registry_client: RegistryClient,
    metadata_cache: HashMap<String, AbbreviatedPackageMetadata>,
}

impl Installer {
    pub fn new(options: InstallOptions) -> Result<Self> {
        let root_dir = &options.project_dir;
        let config = Config::load(Some(root_dir)).unwrap_or_default();

        let registry_url = if let Some(ref reg_str) = options.registry_url {
            Url::parse(reg_str).context("Invalid registry URL")?
        } else {
            config.npmrc.registry.clone()
        };

        let cache_path = options.cache_dir.clone().unwrap_or_else(|| {
            if let Some(user_cache) = config.npmrc.settings.get("cache") {
                PathBuf::from(user_cache)
            } else if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
                PathBuf::from(appdata).join("rnpm").join("cache")
            } else {
                std::env::temp_dir().join(".rnpm-cache")
            }
        });

        let cache = Cache::new(&cache_path).context("Failed to initialize cache")?;

        let mut trusted_hosts = HashSet::new();
        if let Some(host) = registry_url.host_str() {
            trusted_hosts.insert(host.to_ascii_lowercase());
        }

        let mut client_config = RegistryClientConfig::default();
        client_config.default_registry = registry_url;
        client_config.trusted_hosts = trusted_hosts;

        let registry_client = RegistryClient::with_config(client_config)
            .context("Failed to initialize registry client")?;

        Ok(Self {
            options,
            cache,
            registry_client,
            metadata_cache: HashMap::new(),
        })
    }

    /// Run standard install workflow from project package.json.
    pub async fn run(&mut self) -> Result<InstallSummary> {
        let manifest_path = self.options.project_dir.join("package.json");
        if !manifest_path.exists() {
            return Err(anyhow!("package.json not found in {}", self.options.project_dir.display()));
        }

        let manifest = Manifest::from_file(&manifest_path)
            .context("Failed to parse project package.json")?;

        let project_name = manifest.name.clone().unwrap_or_else(|| "project".to_string());
        let project_version = manifest.version.clone();

        // 1. Resolve dependency graph
        let mut resolved_tree: BTreeMap<String, ResolvedNode> = BTreeMap::new();
        let mut queue: VecDeque<(String, String, bool)> = VecDeque::new();

        for (dep_name, dep_range) in &manifest.dependencies {
            let is_opt = manifest.optional_dependencies.contains_key(dep_name);
            queue.push_back((dep_name.clone(), dep_range.clone(), is_opt));
        }

        for (opt_name, opt_range) in &manifest.optional_dependencies {
            if !manifest.dependencies.contains_key(opt_name) {
                queue.push_back((opt_name.clone(), opt_range.clone(), true));
            }
        }

        while let Some((dep_name, dep_range, is_optional)) = queue.pop_front() {
            if let Some(existing) = resolved_tree.get_mut(&dep_name) {
                if !is_optional && existing.optional {
                    existing.optional = false;
                }
                continue;
            }

            let node = match self.resolve_package(&dep_name, &dep_range, is_optional).await {
                Ok(n) => n,
                Err(err) => {
                    if is_optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to resolve {}@{}: {:#}",
                            dep_name, dep_range, err
                        );
                        continue;
                    } else {
                        return Err(err);
                    }
                }
            };

            if node.skipped {
                debug!(
                    "Skipping optional dependency {} due to platform filter",
                    dep_name
                );
                resolved_tree.insert(dep_name, node);
                continue;
            }

            for (sub_name, sub_range) in &node.dependencies {
                let sub_is_opt = node.optional_dependencies.contains_key(sub_name) || node.optional;
                if !resolved_tree.contains_key(sub_name) {
                    queue.push_back((sub_name.clone(), sub_range.clone(), sub_is_opt));
                }
            }

            for (opt_name, opt_range) in &node.optional_dependencies {
                if !node.dependencies.contains_key(opt_name) && !resolved_tree.contains_key(opt_name) {
                    queue.push_back((opt_name.clone(), opt_range.clone(), true));
                }
            }

            resolved_tree.insert(dep_name, node);
        }

        // 2. Reify: download or fetch from cache, verify integrity, extract to node_modules
        let node_modules_dir = self.options.project_dir.join("node_modules");
        let bin_dir = node_modules_dir.join(".bin");
        std::fs::create_dir_all(&node_modules_dir).context("Failed to create node_modules")?;

        let mut cache_hits = 0;
        let mut cache_misses = 0;
        let mut packages_installed = 0;

        let mut lockfile = LockfileV3::new(project_name, project_version);
        if let Some(root_pkg) = lockfile.root_package_mut() {
            if !manifest.dependencies.is_empty() {
                root_pkg.dependencies = Some(manifest.dependencies.clone());
            }
            if !manifest.dev_dependencies.is_empty() {
                root_pkg.dev_dependencies = Some(manifest.dev_dependencies.clone());
            }
            if !manifest.optional_dependencies.is_empty() {
                root_pkg.optional_dependencies = Some(manifest.optional_dependencies.clone());
            }
        }

        let mut lifecycle_nodes: Vec<LifecyclePackageNode> = Vec::new();

        for (pkg_name, node) in &resolved_tree {
            if node.skipped {
                // NEVER download or extract skipped packages!
                debug!("Package {} is marked skipped, bypassing download and extraction", pkg_name);
                let lockfile_key = format!("node_modules/{pkg_name}");
                let mut lock_entry = LockfilePackage {
                    version: Some(node.version.clone()),
                    resolved: Some(node.resolved_url.clone()),
                    integrity: if !node.integrity.is_empty() { Some(node.integrity.clone()) } else { None },
                    optional: Some(true),
                    ..Default::default()
                };
                if !node.os.is_empty() { lock_entry.os = Some(node.os.clone()); }
                if !node.cpu.is_empty() { lock_entry.cpu = Some(node.cpu.clone()); }
                if !node.libc.is_empty() { lock_entry.libc = Some(node.libc.clone()); }
                lockfile.insert_package(&lockfile_key, lock_entry);
                continue;
            }

            let fetch_res = self.fetch_tarball(&node.resolved_url).await;
            let (bytes, was_hit) = match fetch_res {
                Ok(res) => res,
                Err(err) => {
                    if node.optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to download {}: {:#}",
                            pkg_name, err
                        );
                        continue;
                    } else {
                        return Err(err);
                    }
                }
            };

            if was_hit {
                cache_hits += 1;
            } else {
                cache_misses += 1;
            }

            // Verify integrity
            let expected_integrity: Result<Integrity, _> = node.integrity.parse()
                .map_err(|e| anyhow!("Invalid integrity string: {e}"));
            let expected_integrity = match expected_integrity {
                Ok(i) => i,
                Err(e) => {
                    if node.optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Invalid integrity for {}: {}",
                            pkg_name, e
                        );
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            };

            if let Err(e) = expected_integrity.verify(&bytes) {
                if node.optional {
                    warn!(
                        "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {}: {}",
                        pkg_name, e
                    );
                    continue;
                } else {
                    return Err(anyhow!("Integrity verification failed for {}: {e}", pkg_name));
                }
            }

            // Extract to node_modules/<pkg_name>
            let dest_dir = node_modules_dir.join(pkg_name);
            if dest_dir.exists() {
                let _ = std::fs::remove_dir_all(&dest_dir);
            }
            if let Err(e) = std::fs::create_dir_all(&dest_dir) {
                if node.optional {
                    warn!(
                        "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to create dir for {}: {}",
                        pkg_name, e
                    );
                    continue;
                } else {
                    return Err(e.into());
                }
            }

            if let Err(e) = extract_tar_gz(Cursor::new(&bytes), &dest_dir, None) {
                if node.optional {
                    warn!(
                        "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to extract package {}: {}",
                        pkg_name, e
                    );
                    let _ = std::fs::remove_dir_all(&dest_dir);
                    continue;
                } else {
                    return Err(anyhow!("Failed to extract package {}: {e}", pkg_name));
                }
            }

            packages_installed += 1;

            // Generate shims if package declares bin and collect lifecycle node
            let pkg_manifest_path = dest_dir.join("package.json");
            let mut has_install_script = false;

            if pkg_manifest_path.exists() {
                if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                    // Create companion shims
                    for (bin_name, script_rel) in pkg_manifest.bin_entries() {
                        let target_rel = format!("{pkg_name}/{script_rel}");
                        let script_path = dest_dir.join(&script_rel);
                        let _ = normalize_shebang(&script_path);
                        let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                    }

                    has_install_script = pkg_manifest.scripts.contains_key("preinstall")
                        || pkg_manifest.scripts.contains_key("install")
                        || pkg_manifest.scripts.contains_key("postinstall");

                    lifecycle_nodes.push(LifecyclePackageNode {
                        package_path: format!("node_modules/{pkg_name}"),
                        disk_path: dest_dir.clone(),
                        manifest: pkg_manifest,
                        source: PackageSource::Registry,
                        dependencies: node.dependencies.keys().cloned().collect(),
                        optional: node.optional,
                    });
                }
            }

            // Add entry to lockfile v3
            let lockfile_key = format!("node_modules/{pkg_name}");
            let mut lock_entry = LockfilePackage {
                version: Some(node.version.clone()),
                resolved: Some(node.resolved_url.clone()),
                integrity: Some(node.integrity.clone()),
                optional: if node.optional { Some(true) } else { None },
                ..Default::default()
            };

            if !node.os.is_empty() { lock_entry.os = Some(node.os.clone()); }
            if !node.cpu.is_empty() { lock_entry.cpu = Some(node.cpu.clone()); }
            if !node.libc.is_empty() { lock_entry.libc = Some(node.libc.clone()); }

            if has_install_script {
                lock_entry.has_install_script = Some(true);
            }

            if !node.dependencies.is_empty() {
                lock_entry.dependencies = Some(node.dependencies.clone());
            }

            lockfile.insert_package(&lockfile_key, lock_entry);
        }

        // 3. Execute lifecycle scripts bottom-up followed by root hooks
        if !self.options.ignore_scripts {
            let lifecycle_opts = LifecycleOptions {
                root_dir: self.options.project_dir.clone(),
                init_cwd: self.options.project_dir.clone(),
                ignore_scripts: false,
                capture_output: false,
            };
            execute_topological(&lifecycle_nodes, &manifest, &lifecycle_opts).await?;
        }

        // 4. Write deterministic package-lock.json
        let lockfile_path = self.options.project_dir.join("package-lock.json");
        lockfile.save_to_file(&lockfile_path)
            .context("Failed to save package-lock.json")?;

        Ok(InstallSummary {
            packages_installed,
            cache_hits,
            cache_misses,
            lockfile_path,
        })
    }

    /// Run strict CI installation from committed package-lock.json.
    pub async fn run_ci(&mut self) -> Result<InstallSummary> {
        let manifest_path = self.options.project_dir.join("package.json");
        let lockfile_path = self.options.project_dir.join("package-lock.json");

        if !manifest_path.exists() {
            return Err(anyhow!("package.json not found in {}", self.options.project_dir.display()));
        }
        if !lockfile_path.exists() {
            return Err(anyhow!("package-lock.json not found: rnpm ci requires a committed lockfile"));
        }

        let manifest = Manifest::from_file(&manifest_path)?;
        let lockfile_str = std::fs::read_to_string(&lockfile_path)?;
        let lockfile = LockfileV3::from_json_str(&lockfile_str)
            .context("Failed to parse package-lock.json")?;

        // Strict drift check between manifest and lockfile
        if let Some(root_pkg) = lockfile.packages.get("") {
            if let Some(lock_deps) = &root_pkg.dependencies {
                for (dep_name, dep_spec) in &manifest.dependencies {
                    if let Some(lock_spec) = lock_deps.get(dep_name) {
                        if lock_spec != dep_spec {
                            return Err(anyhow!(
                                "rnpm ERR! code EUSAGE: package.json dependency {}@{} does not match lockfile spec {}",
                                dep_name, dep_spec, lock_spec
                            ));
                        }
                    } else {
                        return Err(anyhow!(
                            "rnpm ERR! code EUSAGE: package.json dependency {} missing from package-lock.json",
                            dep_name
                        ));
                    }
                }
            } else if !manifest.dependencies.is_empty() {
                return Err(anyhow!(
                    "rnpm ERR! code EUSAGE: package.json defines dependencies but lockfile has none"
                ));
            }
        }

        // Clean-slate: remove node_modules completely
        let node_modules_dir = self.options.project_dir.join("node_modules");
        let bin_dir = node_modules_dir.join(".bin");
        if node_modules_dir.exists() {
            std::fs::remove_dir_all(&node_modules_dir)?;
        }
        std::fs::create_dir_all(&node_modules_dir)?;

        let mut cache_hits = 0;
        let mut cache_misses = 0;
        let mut packages_installed = 0;

        for (pkg_key, pkg_info) in &lockfile.packages {
            if pkg_key.is_empty() {
                continue;
            }

            let is_optional = pkg_info.optional.unwrap_or(false);

            // Filter optional dependencies by platform: os, cpu, libc
            if is_optional {
                let host_platform = Platform::current();
                let os_match = host_platform.matches_with_libc(
                    pkg_info.os.as_deref(),
                    pkg_info.cpu.as_deref(),
                    pkg_info.libc.as_deref(),
                );
                if !os_match {
                    debug!("Skipping optional dependency {pkg_key} due to platform constraint");
                    continue;
                }
            }

            let resolved_url = match pkg_info.resolved.as_ref() {
                Some(url) => url,
                None => {
                    if is_optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Package {} missing resolved URL in lockfile",
                            pkg_key
                        );
                        continue;
                    } else {
                        return Err(anyhow!("Package {} missing resolved URL in lockfile", pkg_key));
                    }
                }
            };

            let integrity_str = match pkg_info.integrity.as_ref() {
                Some(i) => i,
                None => {
                    if is_optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Package {} missing integrity in lockfile",
                            pkg_key
                        );
                        continue;
                    } else {
                        return Err(anyhow!("Package {} missing integrity in lockfile", pkg_key));
                    }
                }
            };

            let fetch_res = self.fetch_tarball(resolved_url).await;
            let (bytes, was_hit) = match fetch_res {
                Ok(res) => res,
                Err(err) => {
                    if is_optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to download {}: {:#}",
                            pkg_key, err
                        );
                        continue;
                    } else {
                        return Err(err);
                    }
                }
            };

            if was_hit {
                cache_hits += 1;
            } else {
                cache_misses += 1;
            }

            let expected_integrity: Result<Integrity, _> = integrity_str.parse()
                .map_err(|e| anyhow!("Invalid integrity hash: {e}"));
            let expected_integrity = match expected_integrity {
                Ok(i) => i,
                Err(e) => {
                    if is_optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Invalid integrity for {}: {}",
                            pkg_key, e
                        );
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            };

            if let Err(e) = expected_integrity.verify(&bytes) {
                if is_optional {
                    warn!(
                        "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {pkg_key}: {e}"
                    );
                    continue;
                } else {
                    return Err(anyhow!("Integrity verification failed for {pkg_key}: {e}"));
                }
            }

            let target_path = self.options.project_dir.join(pkg_key);
            if let Err(e) = std::fs::create_dir_all(&target_path) {
                if is_optional {
                    warn!(
                        "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to create target dir for {pkg_key}: {e}"
                    );
                    continue;
                } else {
                    return Err(e.into());
                }
            }

            if let Err(e) = extract_tar_gz(Cursor::new(&bytes), &target_path, None) {
                if is_optional {
                    warn!(
                        "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to extract {pkg_key}: {e}"
                    );
                    let _ = std::fs::remove_dir_all(&target_path);
                    continue;
                } else {
                    return Err(anyhow!("Failed to extract {pkg_key}: {e}"));
                }
            }

            packages_installed += 1;

            let pkg_manifest_path = target_path.join("package.json");
            if pkg_manifest_path.exists() {
                if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                    for (bin_name, script_rel) in pkg_manifest.bin_entries() {
                        let clean_pkg_name = pkg_key.strip_prefix("node_modules/").unwrap_or(pkg_key);
                        let target_rel = format!("{clean_pkg_name}/{script_rel}");
                        let script_path = target_path.join(&script_rel);
                        let _ = normalize_shebang(&script_path);
                        let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                    }

                    if !self.options.ignore_scripts {
                        let mut script_failed = false;
                        for event in &["preinstall", "install", "postinstall"] {
                            if let Some(cmd) = pkg_manifest.scripts.get(*event) {
                                let mut ctx = LifecycleContext::new(
                                    &self.options.project_dir,
                                    &target_path,
                                    pkg_key,
                                    *event,
                                    cmd,
                                );
                                ctx.package_version = pkg_manifest.version.clone();
                                match execute_lifecycle_script(&ctx) {
                                    Ok(status) if status.success() => {},
                                    Ok(status) => {
                                        if is_optional {
                                            warn!(
                                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: {} failed at {} script with exit code: {:?}",
                                                pkg_key, event, status.code()
                                            );
                                            script_failed = true;
                                            break;
                                        } else {
                                            return Err(anyhow!(
                                                "Lifecycle script '{}' failed for package {} with exit code: {:?}",
                                                event, pkg_key, status.code()
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        if is_optional {
                                            warn!(
                                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Optional dependency lifecycle script error: {e}"
                                            );
                                            script_failed = true;
                                            break;
                                        } else {
                                            return Err(e);
                                        }
                                    }
                                }
                            }
                        }
                        if script_failed {
                            let _ = std::fs::remove_dir_all(&target_path);
                        }
                    }
                }
            }
        }

        Ok(InstallSummary {
            packages_installed,
            cache_hits,
            cache_misses,
            lockfile_path,
        })
    }

    async fn resolve_package(
        &mut self,
        name: &str,
        range_str: &str,
        is_optional: bool,
    ) -> Result<ResolvedNode> {
        let metadata = if let Some(cached) = self.metadata_cache.get(name) {
            cached.clone()
        } else {
            let meta = self.registry_client.get_package_metadata(name).await
                .map_err(|e| anyhow!("Failed to fetch metadata for {name}: {e}"))?;
            self.metadata_cache.insert(name.to_string(), meta.clone());
            meta
        };

        let range = Range::parse(range_str)
            .map_err(|e| anyhow!("Failed to parse semver range '{range_str}' for {name}: {e}"))?;

        let mut matching_versions: Vec<(Version, String)> = Vec::new();
        for (ver_str, _ver_info) in &metadata.versions {
            if let Ok(ver) = ver_str.parse::<Version>() {
                if range.satisfies(&ver) {
                    matching_versions.push((ver, ver_str.clone()));
                }
            }
        }

        if matching_versions.is_empty() {
            return Err(anyhow!("No matching version found for {}@{}", name, range_str));
        }

        matching_versions.sort_by(|a, b| a.0.cmp(&b.0));
        let (_, best_ver_str) = matching_versions.last().unwrap();
        let ver_info = metadata.versions.get(best_ver_str)
            .ok_or_else(|| anyhow!("Version info missing for {}", best_ver_str))?;

        let integrity = ver_info.dist.integrity.clone()
            .unwrap_or_default();

        let mut deps = BTreeMap::new();
        for (d_name, d_range) in &ver_info.dependencies {
            deps.insert(d_name.clone(), d_range.clone());
        }

        let mut opt_deps = BTreeMap::new();
        for (d_name, d_range) in &ver_info.optional_dependencies {
            opt_deps.insert(d_name.clone(), d_range.clone());
        }

        let os_list = if ver_info.os.is_empty() { None } else { Some(ver_info.os.as_slice()) };
        let cpu_list = if ver_info.cpu.is_empty() { None } else { Some(ver_info.cpu.as_slice()) };
        let libc_list = if ver_info.libc.is_empty() { None } else { Some(ver_info.libc.as_slice()) };

        let host_platform = Platform::current();
        let compatible = host_platform.matches_with_libc(os_list, cpu_list, libc_list);
        let skipped = is_optional && !compatible;

        Ok(ResolvedNode {
            name: name.to_string(),
            version: best_ver_str.clone(),
            resolved_url: ver_info.dist.tarball.clone(),
            integrity,
            dependencies: deps,
            optional_dependencies: opt_deps,
            optional: is_optional,
            skipped,
            os: ver_info.os.clone(),
            cpu: ver_info.cpu.clone(),
            libc: ver_info.libc.clone(),
        })
    }

    async fn fetch_tarball(&self, tarball_url: &str) -> Result<(Vec<u8>, bool)> {
        if let Ok(Some((_entry, data))) = self.cache.get(tarball_url) {
            debug!("Cache hit for {}", tarball_url);
            return Ok((data, true));
        }

        info!("Downloading {}", tarball_url);
        let bytes = self.registry_client.download_tarball_bytes(tarball_url).await
            .map_err(|e| anyhow!("Failed to download tarball from {tarball_url}: {e}"))?;

        let _ = self.cache.put(tarball_url, &bytes, None);

        Ok((bytes, false))
    }

    /// Uninstall packages from project:
    /// 1. Removes specified package names from package.json (`dependencies`, `devDependencies`, `optionalDependencies`).
    /// 2. Prunes unreferenced dependencies from the in-memory dependency graph and lockfile.
    /// 3. Deletes the corresponding package directories from `node_modules` (including nested packages that are no longer referenced).
    /// 4. Writes updated deterministic `package.json` and `package-lock.json`.
    pub fn uninstall(&self, options: &UninstallOptions) -> Result<UninstallSummary> {
        let manifest_path = self.options.project_dir.join("package.json");
        if !manifest_path.exists() {
            return Err(anyhow!("package.json not found in {}", self.options.project_dir.display()));
        }

        let mut manifest = Manifest::from_file(&manifest_path)
            .context("Failed to parse project package.json")?;

        // Validate package names against malformed inputs or path traversal attacks
        for pkg in &options.packages {
            let trimmed = pkg.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("..") || trimmed.contains('\\') || trimmed.starts_with('/') {
                return Err(anyhow!("Invalid package name '{trimmed}': path traversal not permitted"));
            }
        }

        let mut removed_packages = Vec::new();

        // Determine which sections to target
        let target_all = !options.save_dev && !options.save_optional && !options.save_prod;

        for raw_pkg in &options.packages {
            let pkg = raw_pkg.trim();
            if pkg.is_empty() {
                continue;
            }

            let mut removed = false;

            if options.save_dev || target_all {
                if manifest.dev_dependencies.remove(pkg).is_some() {
                    removed = true;
                }
            }

            if options.save_optional || target_all {
                if manifest.optional_dependencies.remove(pkg).is_some() {
                    removed = true;
                }
            }

            if options.save_prod || target_all {
                if manifest.dependencies.remove(pkg).is_some() {
                    removed = true;
                }
            }

            if removed {
                removed_packages.push(pkg.to_string());
            }
        }

        // Save updated package.json deterministically
        manifest.save_to_file(&manifest_path)
            .context("Failed to save updated package.json")?;

        let lockfile_path = self.options.project_dir.join("package-lock.json");
        let mut pruned_nodes: HashSet<String> = HashSet::new();

        if lockfile_path.exists() {
            let lockfile_str = std::fs::read_to_string(&lockfile_path)
                .context("Failed to read package-lock.json")?;
            let mut lockfile = LockfileV3::from_json_str(&lockfile_str)
                .context("Failed to parse package-lock.json")?;

            // Build and prune in-memory dependency graph
            let mut in_memory_graph = DependencyGraph::from_lockfile_v3(&lockfile);
            for pkg in &removed_packages {
                in_memory_graph.remove_root_dependency(pkg);
            }
            let graph_pruned = in_memory_graph.prune_unreferenced();

            // Sync root package metadata with updated manifest
            if let Some(root_pkg) = lockfile.root_package_mut() {
                if manifest.dependencies.is_empty() {
                    root_pkg.dependencies = None;
                } else {
                    root_pkg.dependencies = Some(manifest.dependencies.clone());
                }

                if manifest.dev_dependencies.is_empty() {
                    root_pkg.dev_dependencies = None;
                } else {
                    root_pkg.dev_dependencies = Some(manifest.dev_dependencies.clone());
                }

                if manifest.optional_dependencies.is_empty() {
                    root_pkg.optional_dependencies = None;
                } else {
                    root_pkg.optional_dependencies = Some(manifest.optional_dependencies.clone());
                }
            }

            // Prune unreferenced dependencies using reachability graph
            pruned_nodes = prune_lockfile(&mut lockfile, &manifest);
            pruned_nodes.extend(graph_pruned);

            // Write updated deterministic package-lock.json
            lockfile.save_to_file(&lockfile_path)
                .context("Failed to save updated package-lock.json")?;
        }

        // Remove deleted package directories from node_modules
        let node_modules_dir = self.options.project_dir.join("node_modules");
        let bin_dir = node_modules_dir.join(".bin");

        // Clean direct removed packages and all pruned lockfile nodes
        let mut dirs_to_remove = HashSet::new();
        for pkg in &removed_packages {
            dirs_to_remove.insert(format!("node_modules/{pkg}"));
        }
        for pruned in &pruned_nodes {
            dirs_to_remove.insert(pruned.clone());
        }

        // Sort descending by length so nested subdirectories are deleted before parent directories
        let mut sorted_dirs: Vec<String> = dirs_to_remove.into_iter().collect();
        sorted_dirs.sort_by_key(|b| std::cmp::Reverse(b.len()));

        for rel_dir in sorted_dirs {
            let target_path = self.options.project_dir.join(&rel_dir);
            let is_junc = is_junction(&target_path).unwrap_or(false);
            if target_path.exists() || is_junc {
                // Remove shims from .bin if package had bin entries
                let pkg_manifest_path = target_path.join("package.json");
                if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                    for (bin_name, _) in pkg_manifest.bin_entries() {
                        let shim_path = bin_dir.join(&bin_name);
                        let _ = std::fs::remove_file(&shim_path);
                        #[cfg(windows)]
                        {
                            let _ = std::fs::remove_file(bin_dir.join(format!("{bin_name}.cmd")));
                            let _ = std::fs::remove_file(bin_dir.join(format!("{bin_name}.ps1")));
                        }
                    }
                }

                if is_junc {
                    let _ = remove_junction(&target_path);
                } else if target_path.is_dir() {
                    let _ = std::fs::remove_dir_all(&target_path);
                } else {
                    let _ = std::fs::remove_file(&target_path);
                }

                // If parent is a scoped directory (e.g. @scope) and empty, remove it
                if let Some(parent) = target_path.parent() {
                    if let Some(parent_name) = parent.file_name().and_then(|n| n.to_str()) {
                        if parent_name.starts_with('@') && parent.is_dir() {
                            if let Ok(mut entries) = std::fs::read_dir(parent) {
                                if entries.next().is_none() {
                                    let _ = std::fs::remove_dir(parent);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Clean up .bin if empty
        if bin_dir.exists() {
            if let Ok(mut entries) = std::fs::read_dir(&bin_dir) {
                if entries.next().is_none() {
                    let _ = std::fs::remove_dir(&bin_dir);
                }
            }
        }

        Ok(UninstallSummary {
            removed_packages,
            pruned_dependencies: pruned_nodes.into_iter().collect(),
            lockfile_path,
        })
    }
}

/// Options for running rnpm uninstall.
#[derive(Debug, Clone, Default)]
pub struct UninstallOptions {
    pub packages: Vec<String>,
    pub save_dev: bool,
    pub save_optional: bool,
    pub save_prod: bool,
}

/// Result of an uninstall run.
#[derive(Debug, Clone)]
pub struct UninstallSummary {
    pub removed_packages: Vec<String>,
    pub pruned_dependencies: Vec<String>,
    pub lockfile_path: PathBuf,
}

/// Prunes unreferenced packages from lockfile based on reachability from manifest direct dependencies.
/// Returns the set of lockfile package paths (e.g. "node_modules/foo") that were pruned.
pub fn prune_lockfile(lockfile: &mut LockfileV3, manifest: &Manifest) -> HashSet<String> {
    // 1. Collect all root direct dependency names
    let mut root_dep_names = HashSet::new();
    for name in manifest.dependencies.keys() {
        root_dep_names.insert(name.clone());
    }
    for name in manifest.dev_dependencies.keys() {
        root_dep_names.insert(name.clone());
    }
    for name in manifest.optional_dependencies.keys() {
        root_dep_names.insert(name.clone());
    }

    // 2. Breadth-First-Search from root to mark reachable lockfile keys
    let mut reachable_keys = HashSet::new();
    reachable_keys.insert(String::new()); // Root package "" is always reachable

    let mut queue: VecDeque<String> = VecDeque::new();

    // Direct root dependencies point to "node_modules/<name>"
    for dep_name in &root_dep_names {
        let key = format!("node_modules/{dep_name}");
        if lockfile.packages.contains_key(&key) {
            reachable_keys.insert(key.clone());
            queue.push_back(key);
        }
    }

    while let Some(current_key) = queue.pop_front() {
        if let Some(pkg) = lockfile.packages.get(&current_key) {
            let mut all_deps = Vec::new();
            if let Some(deps) = &pkg.dependencies {
                all_deps.extend(deps.keys().cloned());
            }
            if let Some(opt_deps) = &pkg.optional_dependencies {
                all_deps.extend(opt_deps.keys().cloned());
            }

            for dep_name in all_deps {
                // Resolution in node_modules tree: check nested then parent scopes
                let nested_key = format!("{current_key}/node_modules/{dep_name}");
                let hoisted_key = format!("node_modules/{dep_name}");

                let target_key = if lockfile.packages.contains_key(&nested_key) {
                    Some(nested_key)
                } else if lockfile.packages.contains_key(&hoisted_key) {
                    Some(hoisted_key)
                } else {
                    // Search ancestors
                    let mut found = None;
                    let parts: Vec<&str> = current_key.split("/node_modules/").collect();
                    for i in (1..parts.len()).rev() {
                        let ancestor = parts[..i].join("/node_modules/");
                        let candidate = format!("{ancestor}/node_modules/{dep_name}");
                        if lockfile.packages.contains_key(&candidate) {
                            found = Some(candidate);
                            break;
                        }
                    }
                    found
                };

                if let Some(k) = target_key {
                    if !reachable_keys.contains(&k) {
                        reachable_keys.insert(k.clone());
                        queue.push_back(k);
                    }
                }
            }
        }
    }

    // 3. Remove all unreachable keys (excluding "")
    let mut pruned = HashSet::new();
    let all_keys: Vec<String> = lockfile.packages.keys().cloned().collect();

    for key in all_keys {
        if !key.is_empty() && !reachable_keys.contains(&key) {
            lockfile.packages.remove(&key);
            pruned.insert(key);
        }
    }

    pruned
}

#[cfg(test)]
mod tests;
