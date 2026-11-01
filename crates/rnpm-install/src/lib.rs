use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::path::PathBuf;
use anyhow::{anyhow, Context, Result};
use tracing::{debug, info};
use url::Url;

use rnpm_cache::Cache;
use rnpm_config::Config;
use rnpm_core::integrity::Integrity;
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_fs::tarball::extract_tar_gz;
use rnpm_lifecycle::{
    execute_lifecycle_script, execute_topological, LifecycleContext, LifecycleOptions,
    LifecyclePackageNode, PackageSource,
};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use rnpm_registry::client::{RegistryClient, RegistryClientConfig};
use rnpm_registry::metadata::AbbreviatedPackageMetadata;
use rnpm_shim::{create_shims, normalize_shebang};

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

/// Result of an update run.
#[derive(Debug, Clone)]
pub struct UpdateSummary {
    pub packages_updated: usize,
    pub updated_packages: Vec<String>,
    pub old_versions: HashMap<String, String>,
    pub new_versions: HashMap<String, String>,
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
        let mut queue: VecDeque<(String, String)> = VecDeque::new();

        for (dep_name, dep_range) in &manifest.dependencies {
            queue.push_back((dep_name.clone(), dep_range.clone()));
        }

        while let Some((dep_name, dep_range)) = queue.pop_front() {
            if resolved_tree.contains_key(&dep_name) {
                continue;
            }

            let node = self.resolve_package(&dep_name, &dep_range).await?;
            for (sub_name, sub_range) in &node.dependencies {
                if !resolved_tree.contains_key(sub_name) {
                    queue.push_back((sub_name.clone(), sub_range.clone()));
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
        }

        let mut lifecycle_nodes: Vec<LifecyclePackageNode> = Vec::new();

        for (pkg_name, node) in &resolved_tree {
            let (bytes, was_hit) = self.fetch_tarball(&node.resolved_url).await?;
            if was_hit {
                cache_hits += 1;
            } else {
                cache_misses += 1;
            }

            // Verify integrity
            let expected_integrity: Integrity = node.integrity.parse()
                .map_err(|e| anyhow!("Invalid integrity string: {e}"))?;
            expected_integrity.verify(&bytes)
                .map_err(|e| anyhow!("Integrity verification failed for {}: {e}", pkg_name))?;

            // Extract to node_modules/<pkg_name>
            let dest_dir = node_modules_dir.join(pkg_name);
            if dest_dir.exists() {
                let _ = std::fs::remove_dir_all(&dest_dir);
            }
            std::fs::create_dir_all(&dest_dir)?;

            extract_tar_gz(Cursor::new(&bytes), &dest_dir, None)
                .map_err(|e| anyhow!("Failed to extract package {}: {e}", pkg_name))?;

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
                        optional: false,
                    });
                }
            }

            // Add entry to lockfile v3
            let lockfile_key = format!("node_modules/{pkg_name}");
            let mut lock_entry = LockfilePackage {
                version: Some(node.version.clone()),
                resolved: Some(node.resolved_url.clone()),
                integrity: Some(node.integrity.clone()),
                ..Default::default()
            };

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
            let _ = execute_topological(&lifecycle_nodes, &manifest, &lifecycle_opts).await;
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

            let resolved_url = pkg_info.resolved.as_ref()
                .ok_or_else(|| anyhow!("Package {} missing resolved URL in lockfile", pkg_key))?;
            let integrity_str = pkg_info.integrity.as_ref()
                .ok_or_else(|| anyhow!("Package {} missing integrity in lockfile", pkg_key))?;

            let (bytes, was_hit) = self.fetch_tarball(resolved_url).await?;
            if was_hit {
                cache_hits += 1;
            } else {
                cache_misses += 1;
            }

            let expected_integrity: Integrity = integrity_str.parse()
                .map_err(|e| anyhow!("Invalid integrity hash: {e}"))?;
            expected_integrity.verify(&bytes)
                .map_err(|e| anyhow!("Integrity verification failed for {pkg_key}: {e}"))?;

            let target_path = self.options.project_dir.join(pkg_key);
            std::fs::create_dir_all(&target_path)?;

            extract_tar_gz(Cursor::new(&bytes), &target_path, None)
                .map_err(|e| anyhow!("Failed to extract {pkg_key}: {e}"))?;

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
                                let _ = execute_lifecycle_script(&ctx);
                            }
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

    async fn resolve_package(&mut self, name: &str, range_str: &str) -> Result<ResolvedNode> {
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
            .ok_or_else(|| anyhow!("Integrity hash missing for {}@{}", name, best_ver_str))?;

        let mut deps = BTreeMap::new();
        for (d_name, d_range) in &ver_info.dependencies {
            deps.insert(d_name.clone(), d_range.clone());
        }

        Ok(ResolvedNode {
            name: name.to_string(),
            version: best_ver_str.clone(),
            resolved_url: ver_info.dist.tarball.clone(),
            integrity,
            dependencies: deps,
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

    /// Helper to reify a single package node into node_modules and return lifecycle node and lockfile package.
    async fn reify_package(
        &self,
        node: &ResolvedNode,
        node_modules_dir: &std::path::Path,
        bin_dir: &std::path::Path,
    ) -> Result<(usize, usize, LockfilePackage, Option<LifecyclePackageNode>)> {
        let (bytes, was_hit) = self.fetch_tarball(&node.resolved_url).await?;
        let cache_hits = if was_hit { 1 } else { 0 };
        let cache_misses = if was_hit { 0 } else { 1 };

        let expected_integrity: Integrity = node.integrity.parse()
            .map_err(|e| anyhow!("Invalid integrity string: {e}"))?;
        expected_integrity.verify(&bytes)
            .map_err(|e| anyhow!("Integrity verification failed for {}: {e}", node.name))?;

        let dest_dir = node_modules_dir.join(&node.name);
        if dest_dir.exists() {
            let _ = std::fs::remove_dir_all(&dest_dir);
        }
        std::fs::create_dir_all(&dest_dir)?;

        extract_tar_gz(Cursor::new(&bytes), &dest_dir, None)
            .map_err(|e| anyhow!("Failed to extract package {}: {e}", node.name))?;

        let pkg_manifest_path = dest_dir.join("package.json");
        let mut has_install_script = false;
        let mut lifecycle_node = None;

        if pkg_manifest_path.exists() {
            if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                for (bin_name, script_rel) in pkg_manifest.bin_entries() {
                    let target_rel = format!("{}/{script_rel}", node.name);
                    let script_path = dest_dir.join(&script_rel);
                    let _ = normalize_shebang(&script_path);
                    let _ = create_shims(bin_dir, &bin_name, &target_rel);
                }

                has_install_script = pkg_manifest.scripts.contains_key("preinstall")
                    || pkg_manifest.scripts.contains_key("install")
                    || pkg_manifest.scripts.contains_key("postinstall");

                lifecycle_node = Some(LifecyclePackageNode {
                    package_path: format!("node_modules/{}", node.name),
                    disk_path: dest_dir.clone(),
                    manifest: pkg_manifest,
                    source: PackageSource::Registry,
                    dependencies: node.dependencies.keys().cloned().collect(),
                    optional: false,
                });
            }
        }

        let mut lock_entry = LockfilePackage {
            version: Some(node.version.clone()),
            resolved: Some(node.resolved_url.clone()),
            integrity: Some(node.integrity.clone()),
            ..Default::default()
        };

        if has_install_script {
            lock_entry.has_install_script = Some(true);
        }

        if !node.dependencies.is_empty() {
            lock_entry.dependencies = Some(node.dependencies.clone());
        }

        Ok((cache_hits, cache_misses, lock_entry, lifecycle_node))
    }

    /// Run package update workflow.
    /// If `targets` is non-empty, only update those specified packages.
    /// Otherwise, update all top-level dependencies declared in `package.json`.
    pub async fn update(&mut self, targets: &[String]) -> Result<UpdateSummary> {
        let manifest_path = self.options.project_dir.join("package.json");
        if !manifest_path.exists() {
            return Err(anyhow!("package.json not found in {}", self.options.project_dir.display()));
        }

        let manifest = Manifest::from_file(&manifest_path)
            .context("Failed to parse project package.json")?;

        let project_name = manifest.name.clone().unwrap_or_else(|| "project".to_string());
        let project_version = manifest.version.clone();

        let lockfile_path = self.options.project_dir.join("package-lock.json");
        let mut lockfile = if lockfile_path.exists() {
            LockfileV3::load_from_file(&lockfile_path)?
        } else {
            LockfileV3::new(project_name.clone(), project_version.clone())
        };

        // Ensure root package matches current manifest dependencies
        if let Some(root_pkg) = lockfile.root_package_mut() {
            root_pkg.name = Some(project_name.clone());
            root_pkg.version = project_version.clone();
            if !manifest.dependencies.is_empty() {
                root_pkg.dependencies = Some(manifest.dependencies.clone());
            }
            if !manifest.dev_dependencies.is_empty() {
                root_pkg.dev_dependencies = Some(manifest.dev_dependencies.clone());
            }
        }

        // Determine which packages to update
        let mut deps_to_update: BTreeMap<String, String> = BTreeMap::new();
        if targets.is_empty() {
            // Update all top-level dependencies
            for (k, v) in &manifest.dependencies {
                deps_to_update.insert(k.clone(), v.clone());
            }
            for (k, v) in &manifest.dev_dependencies {
                deps_to_update.insert(k.clone(), v.clone());
            }
        } else {
            for target in targets {
                if let Some(range) = manifest.dependencies.get(target) {
                    deps_to_update.insert(target.clone(), range.clone());
                } else if let Some(range) = manifest.dev_dependencies.get(target) {
                    deps_to_update.insert(target.clone(), range.clone());
                } else {
                    return Err(anyhow!("Package '{}' is not a dependency in package.json", target));
                }
            }
        }

        let mut updated_packages: Vec<String> = Vec::new();
        let mut old_versions: HashMap<String, String> = HashMap::new();
        let mut new_versions: HashMap<String, String> = HashMap::new();

        // 1. Check for newer versions satisfying ranges
        let mut newly_resolved_roots: BTreeMap<String, ResolvedNode> = BTreeMap::new();
        for (pkg_name, range_str) in &deps_to_update {
            let lock_key = format!("node_modules/{pkg_name}");
            let current_locked_ver = lockfile.get_package(&lock_key)
                .and_then(|p| p.version.clone());

            let resolved = self.resolve_package(pkg_name, range_str).await?;

            if let Some(ref cur_ver) = current_locked_ver {
                if cur_ver != &resolved.version {
                    updated_packages.push(pkg_name.clone());
                    old_versions.insert(pkg_name.clone(), cur_ver.clone());
                    new_versions.insert(pkg_name.clone(), resolved.version.clone());
                    newly_resolved_roots.insert(pkg_name.clone(), resolved);
                }
            } else {
                // Not in lockfile yet
                updated_packages.push(pkg_name.clone());
                new_versions.insert(pkg_name.clone(), resolved.version.clone());
                newly_resolved_roots.insert(pkg_name.clone(), resolved);
            }
        }

        let node_modules_dir = self.options.project_dir.join("node_modules");
        let bin_dir = node_modules_dir.join(".bin");
        std::fs::create_dir_all(&node_modules_dir)?;

        let mut cache_hits = 0;
        let mut cache_misses = 0;
        let mut lifecycle_nodes: Vec<LifecyclePackageNode> = Vec::new();

        if !updated_packages.is_empty() {
            // 2. Resolve transitive dependencies for newly updated packages
            let mut full_subgraph: BTreeMap<String, ResolvedNode> = BTreeMap::new();
            let mut queue: VecDeque<(String, String)> = VecDeque::new();

            for (name, node) in newly_resolved_roots {
                for (sub_name, sub_range) in &node.dependencies {
                    queue.push_back((sub_name.clone(), sub_range.clone()));
                }
                full_subgraph.insert(name, node);
            }

            while let Some((dep_name, dep_range)) = queue.pop_front() {
                if full_subgraph.contains_key(&dep_name) {
                    continue;
                }
                let node = self.resolve_package(&dep_name, &dep_range).await?;
                for (sub_name, sub_range) in &node.dependencies {
                    if !full_subgraph.contains_key(sub_name) {
                        queue.push_back((sub_name.clone(), sub_range.clone()));
                    }
                }
                full_subgraph.insert(dep_name, node);
            }

            // 3. Reify newly resolved packages into node_modules and update lockfile
            for (pkg_name, node) in &full_subgraph {
                let (hits, misses, lock_entry, l_node) = self
                    .reify_package(node, &node_modules_dir, &bin_dir)
                    .await?;
                cache_hits += hits;
                cache_misses += misses;
                if let Some(ln) = l_node {
                    lifecycle_nodes.push(ln);
                }

                let lockfile_key = format!("node_modules/{pkg_name}");
                lockfile.insert_package(&lockfile_key, lock_entry);
            }

            // 4. Garbage collection / cleanup of superseded orphaned transitive dependencies
            let mut reachable: HashSet<String> = HashSet::new();
            let mut to_visit: VecDeque<String> = VecDeque::new();

            if let Some(root_pkg) = lockfile.root_package() {
                if let Some(deps) = &root_pkg.dependencies {
                    for dep in deps.keys() {
                        to_visit.push_back(dep.clone());
                    }
                }
                if let Some(dev_deps) = &root_pkg.dev_dependencies {
                    for dep in dev_deps.keys() {
                        to_visit.push_back(dep.clone());
                    }
                }
            }

            while let Some(pkg_name) = to_visit.pop_front() {
                if !reachable.insert(pkg_name.clone()) {
                    continue;
                }
                let key = format!("node_modules/{pkg_name}");
                if let Some(pkg_entry) = lockfile.get_package(&key) {
                    if let Some(deps) = &pkg_entry.dependencies {
                        for sub_dep in deps.keys() {
                            if !reachable.contains(sub_dep) {
                                to_visit.push_back(sub_dep.clone());
                            }
                        }
                    }
                }
            }

            let all_keys: Vec<String> = lockfile.packages.keys().cloned().collect();
            for key in all_keys {
                if key.is_empty() {
                    continue;
                }
                let pkg_name = key.strip_prefix("node_modules/").unwrap_or(&key);
                if !pkg_name.contains('/') || (pkg_name.starts_with('@') && pkg_name.matches('/').count() == 1) {
                    if !reachable.contains(pkg_name) {
                        lockfile.remove_package(&key);
                        let path_to_remove = self.options.project_dir.join(&key);
                        if path_to_remove.exists() {
                            let _ = std::fs::remove_dir_all(&path_to_remove);
                        }
                    }
                }
            }

            // 5. Run lifecycle scripts if needed
            if !self.options.ignore_scripts && !lifecycle_nodes.is_empty() {
                let lifecycle_opts = LifecycleOptions {
                    root_dir: self.options.project_dir.clone(),
                    init_cwd: self.options.project_dir.clone(),
                    ignore_scripts: false,
                    capture_output: false,
                };
                let _ = execute_topological(&lifecycle_nodes, &manifest, &lifecycle_opts).await;
            }
        }

        // 6. Rewrite package-lock.json deterministically
        lockfile.save_to_file(&lockfile_path)
            .context("Failed to save package-lock.json")?;

        Ok(UpdateSummary {
            packages_updated: updated_packages.len(),
            updated_packages,
            old_versions,
            new_versions,
            cache_hits,
            cache_misses,
            lockfile_path,
        })
    }
}

#[cfg(test)]
mod tests;
