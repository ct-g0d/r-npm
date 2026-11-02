use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use anyhow::{anyhow, Context, Result};
use tracing::{debug, info, warn};
use url::Url;

use rnpm_cache::Cache;
use rnpm_config::Config;
use rnpm_core::integrity::Integrity;
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_core::workspace::{discover_workspaces_from_manifest, WorkspaceMember};
use std::sync::Arc;
use rnpm_fs::atomic::extract_and_replace;
use rnpm_fs::junction::{is_junction, remove_junction};
use rnpm_lifecycle::{
    execute_topological, LifecycleOptions, LifecyclePackageNode, PackageSource,
};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use rnpm_registry::client::{RegistryClient, RegistryClientConfig};
use rnpm_registry::metadata::AbbreviatedPackageMetadata;
use rnpm_shim::{create_shims, normalize_shebang};
use rnpm_solver::graph::DependencyGraph;
use rnpm_solver::{Platform, WorkspaceDependencyGraph};

/// Helper to link a workspace member into node_modules/<pkg-name> using directory junctions (Windows) or symlinks (Unix).
pub fn link_workspace_member(node_modules_dir: &Path, member: &WorkspaceMember) -> Result<()> {
    let link_path = node_modules_dir.join(&member.name);
    if let Some(parent) = link_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if link_path.exists() || rnpm_fs::is_junction(&link_path).unwrap_or(false) {
        let _ = rnpm_fs::remove_junction(&link_path);
        if link_path.exists() && !rnpm_fs::is_junction(&link_path).unwrap_or(false) {
            let _ = std::fs::remove_dir_all(&link_path);
        }
    }

    rnpm_fs::create_junction(&link_path, &member.path)
        .map_err(|e| anyhow!("Failed to link workspace package '{}' at '{}' -> '{}': {e}", member.name, link_path.display(), member.path.display()))?;

    Ok(())
}

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
    pub optional_dependencies: BTreeMap<String, String>,
    pub optional: bool,
    pub skipped: bool,
    pub os: Vec<String>,
    pub cpu: Vec<String>,
    pub libc: Vec<String>,
    pub is_file_dir: bool,
    pub is_file_archive: bool,
    pub local_path: Option<PathBuf>,
}

/// Helper to compute normalized POSIX relative path from one directory to another.
pub fn relative_posix_path(from: &Path, to: &Path) -> String {
    if let Ok(rel) = to.strip_prefix(from) {
        let s = rel.to_string_lossy();
        if s.is_empty() {
            return ".".to_string();
        }
        return rnpm_core::to_posix_path(&s);
    }
    let from_components: Vec<_> = from.components().collect();
    let to_components: Vec<_> = to.components().collect();
    let mut common = 0;
    while common < from_components.len()
        && common < to_components.len()
        && from_components[common] == to_components[common]
    {
        common += 1;
    }
    let mut result = PathBuf::new();
    for _ in common..from_components.len() {
        result.push("..");
    }
    for comp in &to_components[common..] {
        result.push(comp);
    }
    let s = result.to_string_lossy();
    if s.is_empty() {
        ".".to_string()
    } else {
        rnpm_core::to_posix_path(&s)
    }
}

/// Helper to read package.json directly from a tarball in memory without extracting to disk.
pub fn inspect_manifest_from_tarball(bytes: &[u8]) -> Result<Manifest> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    if let Ok(entries) = archive.entries() {
        for entry_res in entries.flatten() {
            let mut entry = entry_res;
            if let Ok(path) = entry.path() {
                let path_str = path.to_string_lossy();
                if path_str == "package/package.json"
                    || path_str.ends_with("/package.json")
                    || path_str == "package.json"
                {
                    let mut manifest_bytes = Vec::new();
                    if std::io::Read::read_to_end(&mut entry, &mut manifest_bytes).is_ok() {
                        if let Ok(manifest) = Manifest::from_slice(&manifest_bytes) {
                            return Ok(manifest);
                        }
                    }
                }
            }
        }
    }
    Err(anyhow!("No valid package.json found inside tarball"))
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
        client_config.default_registry = registry_url.clone();
        client_config.auth_tokens = config.npmrc.auth_tokens.clone();
        client_config.scoped_registries = config.npmrc.scoped_registries.clone();
        if let Some(token) = config.npmrc.get_auth_token(&registry_url) {
            client_config.auth_token = Some(token.to_string());
        }

        for (_, scoped_reg) in &config.npmrc.scoped_registries {
            if let Some(h) = scoped_reg.host_str() {
                trusted_hosts.insert(h.to_ascii_lowercase());
                if let Some(p) = scoped_reg.port_or_known_default() {
                    trusted_hosts.insert(format!("{}:{}", h.to_ascii_lowercase(), p));
                }
            }
        }
        client_config.trusted_hosts = trusted_hosts;

        let concurrency = config
            .npmrc
            .settings
            .get("maxsockets")
            .or_else(|| config.npmrc.settings.get("concurrency"))
            .and_then(|s| s.parse::<usize>().ok())
            .or_else(|| {
                std::env::var("RNPM_CONCURRENCY")
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
            });

        if let Some(c) = concurrency {
            if c > 0 {
                client_config.max_concurrent_requests = c;
            }
        }

        let registry_client = RegistryClient::with_config(client_config)
            .context("Failed to initialize registry client")?;

        Ok(Self {
            options,
            cache,
            registry_client,
            metadata_cache: HashMap::new(),
        })
    }

    /// Reconfigure maximum network worker concurrency (bounded semaphore).
    pub fn with_concurrency(mut self, concurrency: usize) -> Result<Self> {
        let mut cfg = self.registry_client.config().clone();
        cfg.max_concurrent_requests = concurrency;
        self.registry_client = RegistryClient::with_config(cfg)
            .context("Failed to reconfigure registry client with concurrency")?;
        Ok(self)
    }

    /// Access the underlying registry client.
    pub fn registry_client(&self) -> &RegistryClient {
        &self.registry_client
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

        // 0. Discover workspace members (if any)
        let workspace_members = discover_workspaces_from_manifest(
            &self.options.project_dir,
            &manifest,
        ).map_err(|e| anyhow!("Failed to discover workspaces: {e}"))?;

        let ws_graph_opt = if !workspace_members.is_empty() {
            Some(WorkspaceDependencyGraph::construct(&workspace_members)
                .map_err(|e| anyhow!("Workspace dependency error: {e}"))?)
        } else {
            None
        };

        // 1. Resolve external dependency graph
        let mut resolved_tree: BTreeMap<String, ResolvedNode> = BTreeMap::new();
        let mut queue: VecDeque<(String, String, bool)> = VecDeque::new();

        // Enqueue root dependencies
        for (dep_name, dep_range) in &manifest.dependencies {
            let is_ws = ws_graph_opt.as_ref().map(|g| g.is_member(dep_name)).unwrap_or(false)
                || dep_range.starts_with("workspace:");
            if !is_ws {
                let is_opt = manifest.optional_dependencies.contains_key(dep_name);
                queue.push_back((dep_name.clone(), dep_range.clone(), is_opt));
            }
        }
        for (dep_name, dep_range) in &manifest.dev_dependencies {
            let is_ws = ws_graph_opt.as_ref().map(|g| g.is_member(dep_name)).unwrap_or(false)
                || dep_range.starts_with("workspace:");
            if !is_ws {
                let is_opt = manifest.optional_dependencies.contains_key(dep_name);
                queue.push_back((dep_name.clone(), dep_range.clone(), is_opt));
            }
        }

        // Enqueue external dependencies from all workspace members
        for member in &workspace_members {
            for (dep_name, dep_range) in &member.manifest.dependencies {
                let is_ws = ws_graph_opt.as_ref().map(|g| g.is_member(dep_name)).unwrap_or(false)
                    || dep_range.starts_with("workspace:");
                if !is_ws && !resolved_tree.contains_key(dep_name) {
                    let is_opt = member.manifest.optional_dependencies.contains_key(dep_name);
                    queue.push_back((dep_name.clone(), dep_range.clone(), is_opt));
                }
            }
            for (dep_name, dep_range) in &member.manifest.dev_dependencies {
                let is_ws = ws_graph_opt.as_ref().map(|g| g.is_member(dep_name)).unwrap_or(false)
                    || dep_range.starts_with("workspace:");
                if !is_ws && !resolved_tree.contains_key(dep_name) {
                    let is_opt = member.manifest.optional_dependencies.contains_key(dep_name);
                    queue.push_back((dep_name.clone(), dep_range.clone(), is_opt));
                }
            }
            for (opt_name, opt_range) in &member.manifest.optional_dependencies {
                let is_ws = ws_graph_opt.as_ref().map(|g| g.is_member(opt_name)).unwrap_or(false)
                    || opt_range.starts_with("workspace:");
                if !is_ws && !resolved_tree.contains_key(opt_name) {
                    queue.push_back((opt_name.clone(), opt_range.clone(), true));
                }
            }
        }

        for (opt_name, opt_range) in &manifest.optional_dependencies {
            let is_ws = ws_graph_opt.as_ref().map(|g| g.is_member(opt_name)).unwrap_or(false)
                || opt_range.starts_with("workspace:");
            if !is_ws && !manifest.dependencies.contains_key(opt_name) {
                queue.push_back((opt_name.clone(), opt_range.clone(), true));
            }
        }

        let initial_names: Vec<&str> = queue
            .iter()
            .filter(|(_, r, _)| !r.starts_with("file:"))
            .map(|(n, _, _)| n.as_str())
            .collect();
        let _ = self.prefetch_metadata(&initial_names).await;

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
                let is_ws = ws_graph_opt.as_ref().map(|g| g.is_member(sub_name)).unwrap_or(false)
                    || sub_range.starts_with("workspace:");
                if !is_ws && !resolved_tree.contains_key(sub_name) {
                    let sub_is_opt = node.optional_dependencies.contains_key(sub_name) || node.optional;
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
        std::fs::create_dir_all(&bin_dir).context("Failed to create node_modules/.bin")?;

        let mut cache_hits = 0;
        let mut cache_misses = 0;
        let mut packages_installed = 0;

        let mut lockfile = LockfileV3::new(project_name, project_version);
        if let Some(root_pkg) = lockfile.root_package_mut() {
            if !manifest.workspace_patterns().is_empty() {
                root_pkg.workspaces = Some(manifest.workspace_patterns());
            }
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

        // Reify workspace packages: link into root node_modules/<member.name>
        for member in &workspace_members {
            link_workspace_member(&node_modules_dir, member)?;
            packages_installed += 1;

            // Companion shims for member binaries
            for (bin_name, script_rel) in member.manifest.bin_entries() {
                let target_rel = format!("{}/{}", member.name, script_rel);
                let script_path = member.path.join(&script_rel);
                let _ = normalize_shebang(&script_path);
                let _ = create_shims(&bin_dir, &bin_name, &target_rel);
            }

            // Lockfile entry for member source package
            let mut member_pkg = LockfilePackage {
                version: member.version.clone(),
                ..Default::default()
            };
            if !member.manifest.dependencies.is_empty() {
                member_pkg.dependencies = Some(member.manifest.dependencies.clone());
            }
            if !member.manifest.dev_dependencies.is_empty() {
                member_pkg.dev_dependencies = Some(member.manifest.dev_dependencies.clone());
            }
            lockfile.insert_package(&member.relative_path, member_pkg);

            // Lockfile entry for node_modules link
            let link_key = format!("node_modules/{}", member.name);
            let link_pkg = LockfilePackage {
                resolved: Some(member.relative_path.clone()),
                link: Some(true),
                ..Default::default()
            };
            lockfile.insert_package(&link_key, link_pkg);

            // Collect lifecycle scripts for workspace member
            let has_scripts = member.manifest.scripts.contains_key("preinstall")
                || member.manifest.scripts.contains_key("install")
                || member.manifest.scripts.contains_key("postinstall")
                || member.manifest.scripts.contains_key("prepare");

            if has_scripts {
                let mut member_deps: Vec<String> = member.manifest.dependencies.keys().cloned().collect();
                for (dep_name, dep_spec) in &member.manifest.dev_dependencies {
                    let is_sibling = ws_graph_opt.as_ref().map(|g| g.is_member(dep_name)).unwrap_or(false)
                        || dep_spec.starts_with("workspace:")
                        || workspace_members.iter().any(|m| &m.name == dep_name);
                    if is_sibling && !member_deps.contains(dep_name) {
                        member_deps.push(dep_name.clone());
                    }
                }
                if let Some(ref ws_graph) = ws_graph_opt {
                    if let Some(sibling_map) = ws_graph.dependencies.get(&member.name) {
                        for sibling_name in sibling_map.keys() {
                            if !member_deps.contains(sibling_name) {
                                member_deps.push(sibling_name.clone());
                            }
                        }
                    }
                }

                let mut member_manifest = member.manifest.clone();
                if member_manifest.name.is_none() {
                    member_manifest.name = Some(member.name.clone());
                }

                lifecycle_nodes.push(LifecyclePackageNode {
                    package_path: format!("node_modules/{}", member.name),
                    disk_path: member.path.clone(),
                    manifest: member_manifest,
                    source: PackageSource::Local,
                    dependencies: member_deps,
                    optional: false,
                });
            }
        }

        // Reify external packages with bounded parallelism and direct memory decompression
        let mut packages_to_reify = Vec::new();
        for (pkg_name, node) in resolved_tree {
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
            } else {
                packages_to_reify.push((pkg_name, node));
            }
        }

        let mut packages_to_download = Vec::new();
        for (pkg_name, node) in packages_to_reify {
            if node.is_file_dir {
                let local_dir = node.local_path.as_ref().unwrap();
                let link_path = node_modules_dir.join(&pkg_name);
                if let Some(parent) = link_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if link_path.exists() || rnpm_fs::is_junction(&link_path).unwrap_or(false) {
                    let _ = rnpm_fs::remove_junction(&link_path);
                    if link_path.exists() && !rnpm_fs::is_junction(&link_path).unwrap_or(false) {
                        let _ = std::fs::remove_dir_all(&link_path);
                    }
                }
                rnpm_fs::create_junction(&link_path, local_dir)
                    .map_err(|e| anyhow!("Failed to link file package '{pkg_name}' at '{}': {e}", link_path.display()))?;

                packages_installed += 1;

                let pkg_manifest_path = local_dir.join("package.json");
                if let Ok(m) = Manifest::from_file(&pkg_manifest_path) {
                    for (bin_name, script_rel) in m.bin_entries() {
                        let target_rel = format!("{pkg_name}/{script_rel}");
                        let script_path = local_dir.join(&script_rel);
                        let _ = normalize_shebang(&script_path);
                        let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                    }

                    if m.scripts.contains_key("preinstall")
                        || m.scripts.contains_key("install")
                        || m.scripts.contains_key("postinstall")
                        || m.scripts.contains_key("prepare")
                    {
                        lifecycle_nodes.push(LifecyclePackageNode {
                            package_path: format!("node_modules/{pkg_name}"),
                            disk_path: local_dir.clone(),
                            manifest: m.clone(),
                            source: PackageSource::Local,
                            dependencies: m.dependencies.keys().cloned().collect(),
                            optional: false,
                        });
                    }

                    let rel_posix = relative_posix_path(&self.options.project_dir, local_dir);
                    let mut source_pkg = LockfilePackage {
                        name: Some(node.name.clone()),
                        version: Some(node.version.clone()),
                        ..Default::default()
                    };
                    if !m.dependencies.is_empty() {
                        source_pkg.dependencies = Some(m.dependencies.clone());
                    }
                    if !m.dev_dependencies.is_empty() {
                        source_pkg.dev_dependencies = Some(m.dev_dependencies.clone());
                    }
                    lockfile.insert_package(&rel_posix, source_pkg);

                    let link_pkg = LockfilePackage {
                        resolved: Some(rel_posix),
                        link: Some(true),
                        ..Default::default()
                    };
                    lockfile.insert_package(&format!("node_modules/{pkg_name}"), link_pkg);
                }
            } else if node.is_file_archive {
                let local_archive = node.local_path.as_ref().unwrap();
                let archive_bytes = std::fs::read(local_archive)?;
                let dest_dir = node_modules_dir.join(&pkg_name);
                extract_and_replace(Cursor::new(&archive_bytes), &dest_dir, None)
                    .map_err(|e| anyhow!("Failed to extract local archive {}: {e}", pkg_name))?;

                packages_installed += 1;
                cache_hits += 1;

                let manifest_path = dest_dir.join("package.json");
                let (manifest, lifecycle_node) = if manifest_path.exists() {
                    if let Ok(m) = Manifest::from_file(&manifest_path) {
                        for (bin_name, script_rel) in m.bin_entries() {
                            let target_rel = format!("{pkg_name}/{script_rel}");
                            let script_path = dest_dir.join(&script_rel);
                            let _ = normalize_shebang(&script_path);
                            let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                        }
                        let l_node = if m.scripts.contains_key("preinstall")
                            || m.scripts.contains_key("install")
                            || m.scripts.contains_key("postinstall")
                        {
                            Some(LifecyclePackageNode {
                                package_path: format!("node_modules/{pkg_name}"),
                                disk_path: dest_dir.clone(),
                                manifest: m.clone(),
                                source: PackageSource::Registry,
                                dependencies: m.dependencies.keys().cloned().collect(),
                                optional: node.optional,
                            })
                        } else {
                            None
                        };
                        (Some(m), l_node)
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };

                if let Some(l) = lifecycle_node {
                    lifecycle_nodes.push(l);
                }

                let mut lock_entry = LockfilePackage {
                    version: Some(node.version.clone()),
                    resolved: Some(node.resolved_url.clone()),
                    integrity: if !node.integrity.is_empty() {
                        Some(node.integrity.clone())
                    } else {
                        None
                    },
                    ..Default::default()
                };
                if let Some(m) = manifest {
                    if !m.dependencies.is_empty() {
                        lock_entry.dependencies = Some(m.dependencies);
                    }
                }
                lockfile.insert_package(&format!("node_modules/{pkg_name}"), lock_entry);
            } else {
                packages_to_download.push((pkg_name, node));
            }
        }

        let concurrency = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(4, 16);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut join_set = tokio::task::JoinSet::new();

        for (pkg_name, node) in packages_to_download {
            let sem = Arc::clone(&semaphore);
            let cache = self.cache.clone();
            let registry_client = self.registry_client.clone();
            let node_modules_dir = node_modules_dir.clone();
            let bin_dir = bin_dir.clone();

            join_set.spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| anyhow!("{e}"))?;

                let fetch_res = if let Ok(Some((_entry, data))) = cache.get(&node.resolved_url) {
                    let is_valid = if let Ok(expected) = node.integrity.parse::<Integrity>() {
                        expected.verify(&data).is_ok()
                    } else {
                        true
                    };

                    if is_valid {
                        debug!("Cache hit for {}", node.resolved_url);
                        Ok((data, true))
                    } else {
                        debug!("Cached blob for {} failed integrity, purging and re-fetching", node.resolved_url);
                        let _ = cache.purge_key(&node.resolved_url);
                        match registry_client.download_tarball_bytes(&node.resolved_url).await {
                            Ok(bytes) => {
                                let _ = cache.put(&node.resolved_url, &bytes, None);
                                Ok((bytes, false))
                            }
                            Err(e) => Err(anyhow!("Failed to download tarball from {}: {e}", node.resolved_url)),
                        }
                    }
                } else {
                    info!("Downloading {}", node.resolved_url);
                    match registry_client.download_tarball_bytes(&node.resolved_url).await {
                        Ok(bytes) => {
                            let _ = cache.put(&node.resolved_url, &bytes, None);
                            Ok((bytes, false))
                        }
                        Err(e) => Err(anyhow!("Failed to download tarball from {}: {e}", node.resolved_url)),
                    }
                };

                let (bytes, was_hit) = match fetch_res {
                    Ok(res) => res,
                    Err(err) => {
                        if node.optional {
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to download {}: {:#}",
                                pkg_name, err
                            );
                            return Ok(None);
                        } else {
                            return Err(err);
                        }
                    }
                };

                // Verify integrity in memory
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
                            return Ok(None);
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
                        return Ok(None);
                    } else {
                        return Err(anyhow!("Integrity verification failed for {}: {e}", pkg_name));
                    }
                }

                // Streaming memory bound: enforce maximum compressed tarball size (256 MB)
                const MAX_COMPRESSED_TARBALL_BYTES: usize = 256 * 1024 * 1024;
                if bytes.len() > MAX_COMPRESSED_TARBALL_BYTES {
                    return Err(anyhow!(
                        "Tarball for {} exceeds maximum allowed compressed size of {} bytes",
                        pkg_name, MAX_COMPRESSED_TARBALL_BYTES
                    ));
                }

                // Path containment defense: ensure pkg_name has no traversal or device escaping
                if pkg_name.contains("..") || pkg_name.contains(':') || pkg_name.contains('\\') || pkg_name.contains('\0') {
                    return Err(anyhow!("Package name '{pkg_name}' contains illegal path characters"));
                }

                let dest_dir = node_modules_dir.join(&pkg_name);
                let cleaned_dest = path_clean::clean(&dest_dir);
                if !cleaned_dest.starts_with(&node_modules_dir) {
                    return Err(anyhow!("Package installation path '{cleaned_dest:?}' escapes node_modules"));
                }

                // Decompress directly through memory buffer and extract with atomic replacement & backoff retries
                let dest_dir_clone = dest_dir.clone();
                let extract_res = tokio::task::spawn_blocking(move || {
                    extract_and_replace(Cursor::new(bytes), &dest_dir_clone, None)
                }).await?;

                if let Err(e) = extract_res {
                    if node.optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to extract package {}: {}",
                            pkg_name, e
                        );
                        let _ = std::fs::remove_dir_all(&dest_dir);
                        return Ok(None);
                    } else {
                        return Err(anyhow!("Failed to extract package {}: {e}", pkg_name));
                    }
                }

                // Generate shims if package declares bin and collect lifecycle node
                let pkg_manifest_path = dest_dir.join("package.json");
                let mut has_install_script = false;
                let mut lifecycle_node = None;

                if pkg_manifest_path.exists() {
                    if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                        for (bin_name, script_rel) in pkg_manifest.bin_entries() {
                            let target_rel = format!("{pkg_name}/{script_rel}");
                            let script_path = dest_dir.join(&script_rel);
                            let _ = normalize_shebang(&script_path);
                            let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                        }

                        has_install_script = pkg_manifest.scripts.contains_key("preinstall")
                            || pkg_manifest.scripts.contains_key("install")
                            || pkg_manifest.scripts.contains_key("postinstall");

                        lifecycle_node = Some(LifecyclePackageNode {
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

                Ok(Some((
                    pkg_name,
                    was_hit,
                    lockfile_key,
                    lock_entry,
                    lifecycle_node,
                )))
            });
        }

        while let Some(join_res) = join_set.join_next().await {
            let item_opt = join_res.map_err(|e| anyhow!("Reification worker panicked: {e}"))??;
            if let Some((_pkg_name, was_hit, lockfile_key, lock_entry, lifecycle_node)) = item_opt {
                if was_hit {
                    cache_hits += 1;
                } else {
                    cache_misses += 1;
                }
                packages_installed += 1;
                if let Some(l_node) = lifecycle_node {
                    lifecycle_nodes.push(l_node);
                }
                lockfile.insert_package(&lockfile_key, lock_entry);
            }
        }

        // 3. Execute lifecycle scripts bottom-up followed by root hooks
        if !self.options.ignore_scripts {
            let lifecycle_opts = LifecycleOptions {
                root_dir: self.options.project_dir.clone(),
                init_cwd: self.options.project_dir.clone(),
                ignore_scripts: false,
                capture_output: false,
                timeout: None,
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

        // 0. Discover workspace members (if any)
        let workspace_members = discover_workspaces_from_manifest(
            &self.options.project_dir,
            &manifest,
        ).unwrap_or_default();

        let ws_graph_opt = if !workspace_members.is_empty() {
            WorkspaceDependencyGraph::construct(&workspace_members).ok()
        } else {
            None
        };

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
        std::fs::create_dir_all(&bin_dir)?;

        let mut cache_hits = 0;
        let mut cache_misses = 0;
        let mut packages_installed = 0;

        let mut lifecycle_nodes: Vec<LifecyclePackageNode> = Vec::new();

        // Collect lifecycle scripts for workspace members
        for member in &workspace_members {
            let has_scripts = member.manifest.scripts.contains_key("preinstall")
                || member.manifest.scripts.contains_key("install")
                || member.manifest.scripts.contains_key("postinstall")
                || member.manifest.scripts.contains_key("prepare");

            if has_scripts {
                let mut member_deps: Vec<String> = member.manifest.dependencies.keys().cloned().collect();
                for (dep_name, dep_spec) in &member.manifest.dev_dependencies {
                    let is_sibling = ws_graph_opt.as_ref().map(|g| g.is_member(dep_name)).unwrap_or(false)
                        || dep_spec.starts_with("workspace:")
                        || workspace_members.iter().any(|m| &m.name == dep_name);
                    if is_sibling && !member_deps.contains(dep_name) {
                        member_deps.push(dep_name.clone());
                    }
                }
                if let Some(ref ws_graph) = ws_graph_opt {
                    if let Some(sibling_map) = ws_graph.dependencies.get(&member.name) {
                        for sibling_name in sibling_map.keys() {
                            if !member_deps.contains(sibling_name) {
                                member_deps.push(sibling_name.clone());
                            }
                        }
                    }
                }

                let mut member_manifest = member.manifest.clone();
                if member_manifest.name.is_none() {
                    member_manifest.name = Some(member.name.clone());
                }

                lifecycle_nodes.push(LifecyclePackageNode {
                    package_path: format!("node_modules/{}", member.name),
                    disk_path: member.path.clone(),
                    manifest: member_manifest,
                    source: PackageSource::Local,
                    dependencies: member_deps,
                    optional: false,
                });
            }
        }

        let mut packages_to_download: Vec<(&String, &String, &String, bool)> = Vec::new();

        for (pkg_key, pkg_info) in &lockfile.packages {
            if pkg_key.is_empty() {
                continue;
            }

            // Handle workspace links
            if pkg_info.link == Some(true) {
                let target_rel = pkg_info.resolved.as_ref().ok_or_else(|| {
                    anyhow!("Workspace link {pkg_key} missing resolved target in lockfile")
                })?;
                let target_dir = self.options.project_dir.join(target_rel);
                let link_path = self.options.project_dir.join(pkg_key);
                if let Some(parent) = link_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if link_path.exists() || rnpm_fs::is_junction(&link_path).unwrap_or(false) {
                    let _ = rnpm_fs::remove_junction(&link_path);
                    if link_path.exists() && !rnpm_fs::is_junction(&link_path).unwrap_or(false) {
                        let _ = std::fs::remove_dir_all(&link_path);
                    }
                }
                rnpm_fs::create_junction(&link_path, &target_dir)
                    .map_err(|e| anyhow!("Failed to link workspace package at '{}': {e}", link_path.display()))?;

                packages_installed += 1;

                let pkg_manifest_path = target_dir.join("package.json");
                if pkg_manifest_path.exists() {
                    if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                        for (bin_name, script_rel) in pkg_manifest.bin_entries() {
                            let clean_pkg_name = pkg_key.strip_prefix("node_modules/").unwrap_or(pkg_key);
                            let target_rel_bin = format!("{clean_pkg_name}/{script_rel}");
                            let script_path = target_dir.join(&script_rel);
                            let _ = normalize_shebang(&script_path);
                            let _ = create_shims(&bin_dir, &bin_name, &target_rel_bin);
                        }

                        let clean_pkg_name = pkg_key.strip_prefix("node_modules/").unwrap_or(pkg_key);
                        if !workspace_members.iter().any(|m| m.name == clean_pkg_name) {
                            let has_scripts = pkg_manifest.scripts.contains_key("preinstall")
                                || pkg_manifest.scripts.contains_key("install")
                                || pkg_manifest.scripts.contains_key("postinstall")
                                || pkg_manifest.scripts.contains_key("prepare");

                            if has_scripts {
                                let mut member_deps: Vec<String> = pkg_manifest.dependencies.keys().cloned().collect();
                                for (dep_name, dep_spec) in &pkg_manifest.dev_dependencies {
                                    let is_sibling = dep_spec.starts_with("workspace:")
                                        || lockfile.packages.contains_key(&format!("node_modules/{dep_name}"));
                                    if is_sibling && !member_deps.contains(dep_name) {
                                        member_deps.push(dep_name.clone());
                                    }
                                }

                                let mut m = pkg_manifest.clone();
                                if m.name.is_none() {
                                    m.name = Some(clean_pkg_name.to_string());
                                }

                                lifecycle_nodes.push(LifecyclePackageNode {
                                    package_path: pkg_key.clone(),
                                    disk_path: target_dir.clone(),
                                    manifest: m,
                                    source: PackageSource::Local,
                                    dependencies: member_deps,
                                    optional: false,
                                });
                            }
                        }
                    }
                }
                continue;
            }

            // Skip workspace member physical directories
            if !pkg_key.starts_with("node_modules/") {
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

            if resolved_url.starts_with("file:") {
                let file_path = resolved_url.strip_prefix("file:").unwrap().trim();
                let abs_path = if Path::new(file_path).is_absolute() {
                    PathBuf::from(file_path)
                } else {
                    self.options.project_dir.join(file_path)
                };
                if !abs_path.exists() {
                    if is_optional {
                        warn!("npm warn optional SKIPPING OPTIONAL DEPENDENCY: Archive {} not found", abs_path.display());
                        continue;
                    } else {
                        return Err(anyhow!("Archive file not found: {}", abs_path.display()));
                    }
                }
                let bytes = std::fs::read(&abs_path)
                    .with_context(|| format!("Failed to read local archive file '{}'", abs_path.display()))?;

                let target_path = self.options.project_dir.join(pkg_key);
                extract_and_replace(Cursor::new(&bytes), &target_path, None)
                    .map_err(|e| anyhow!("Failed to extract local archive {pkg_key}: {e}"))?;

                let manifest_path = target_path.join("package.json");
                if manifest_path.exists() {
                    if let Ok(pkg_manifest) = Manifest::from_file(&manifest_path) {
                        for (bin_name, script_rel) in pkg_manifest.bin_entries() {
                            let clean_pkg_name = pkg_key.strip_prefix("node_modules/").unwrap_or(pkg_key);
                            let target_rel_bin = format!("{clean_pkg_name}/{script_rel}");
                            let script_path = target_path.join(&script_rel);
                            let _ = normalize_shebang(&script_path);
                            let _ = create_shims(&bin_dir, &bin_name, &target_rel_bin);
                        }

                        let has_scripts = pkg_manifest.scripts.contains_key("preinstall")
                            || pkg_manifest.scripts.contains_key("install")
                            || pkg_manifest.scripts.contains_key("postinstall");
                        if has_scripts {
                            let deps = pkg_info.dependencies.as_ref()
                                .map(|d| d.keys().cloned().collect())
                                .unwrap_or_else(|| pkg_manifest.dependencies.keys().cloned().collect());
                            lifecycle_nodes.push(LifecyclePackageNode {
                                package_path: pkg_key.clone(),
                                disk_path: target_path.clone(),
                                manifest: pkg_manifest,
                                source: PackageSource::Registry,
                                dependencies: deps,
                                optional: is_optional,
                            });
                        }
                    }
                }
                packages_installed += 1;
                cache_hits += 1;
                continue;
            }

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

            packages_to_download.push((pkg_key, resolved_url, integrity_str, is_optional));
        }

        let ci_urls: Vec<&str> = packages_to_download
            .iter()
            .map(|(_, url, _, _)| url.as_str())
            .collect();
        let ci_download_results = self.fetch_tarballs_concurrent(&ci_urls).await;

        for ((pkg_key, _resolved_url, integrity_str, is_optional), fetch_res) in packages_to_download.into_iter().zip(ci_download_results) {
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

            let bytes = if let Err(e) = expected_integrity.verify(&bytes) {
                if was_hit {
                    debug!("Cached blob for {pkg_key} failed integrity ({e}), re-fetching from registry");
                    let _ = self.cache.purge_key(_resolved_url);
                    match self.registry_client.download_tarball_bytes(_resolved_url).await {
                        Ok(fresh_bytes) => {
                            if let Err(fresh_err) = expected_integrity.verify(&fresh_bytes) {
                                if is_optional {
                                    warn!(
                                        "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {pkg_key}: {fresh_err}"
                                    );
                                    continue;
                                } else {
                                    return Err(anyhow!("Integrity verification failed for {pkg_key}: {fresh_err}"));
                                }
                            }
                            let _ = self.cache.put(_resolved_url, &fresh_bytes, None);
                            fresh_bytes
                        }
                        Err(fetch_err) => {
                            if is_optional {
                                warn!(
                                    "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to download {}: {:#}",
                                    pkg_key, fetch_err
                                );
                                continue;
                            } else {
                                return Err(fetch_err.into());
                            }
                        }
                    }
                } else {
                    if is_optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {pkg_key}: {e}"
                        );
                        continue;
                    } else {
                        return Err(anyhow!("Integrity verification failed for {pkg_key}: {e}"));
                    }
                }
            } else {
                bytes
            };

            let target_path = self.options.project_dir.join(pkg_key);
            if let Err(e) = extract_and_replace(Cursor::new(&bytes), &target_path, None) {
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

                    let has_scripts = pkg_manifest.scripts.contains_key("preinstall")
                        || pkg_manifest.scripts.contains_key("install")
                        || pkg_manifest.scripts.contains_key("postinstall");

                    if has_scripts {
                        let deps = if let Some(pkg_info) = lockfile.packages.get(pkg_key) {
                            pkg_info.dependencies.as_ref()
                                .map(|d| d.keys().cloned().collect())
                                .unwrap_or_else(|| pkg_manifest.dependencies.keys().cloned().collect())
                        } else {
                            pkg_manifest.dependencies.keys().cloned().collect()
                        };
                        lifecycle_nodes.push(LifecyclePackageNode {
                            package_path: pkg_key.clone(),
                            disk_path: target_path.clone(),
                            manifest: pkg_manifest,
                            source: PackageSource::Registry,
                            dependencies: deps,
                            optional: is_optional,
                        });
                    }
                }
            }
        }

        // Execute lifecycle scripts bottom-up followed by root hooks
        if !self.options.ignore_scripts {
            let lifecycle_opts = LifecycleOptions {
                root_dir: self.options.project_dir.clone(),
                init_cwd: self.options.project_dir.clone(),
                ignore_scripts: false,
                capture_output: false,
            };
            execute_topological(&lifecycle_nodes, &manifest, &lifecycle_opts).await?;
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
        if let Some(file_spec) = range_str.strip_prefix("file:") {
            let file_spec_clean = file_spec.trim();
            let rel_path = PathBuf::from(file_spec_clean);
            let abs_path = if rel_path.is_absolute() {
                rel_path
            } else {
                self.options.project_dir.join(&rel_path)
            };

            let is_archive = file_spec_clean.ends_with(".tgz")
                || file_spec_clean.ends_with(".tar.gz")
                || file_spec_clean.ends_with(".tar")
                || (abs_path.exists() && abs_path.is_file());

            if is_archive {
                if !abs_path.exists() {
                    return Err(anyhow!(
                        "Archive file not found for dependency '{}' at '{}'",
                        name,
                        abs_path.display()
                    ));
                }
                let archive_bytes = std::fs::read(&abs_path).with_context(|| {
                    format!("Failed to read local archive file '{}'", abs_path.display())
                })?;
                let integrity = Integrity::from_bytes(
                    &archive_bytes,
                    rnpm_core::integrity::Algorithm::Sha512,
                )
                .to_string();

                let manifest = match inspect_manifest_from_tarball(&archive_bytes) {
                    Ok(m) => m,
                    Err(_) => {
                        let mut m = Manifest::default();
                        m.name = Some(name.to_string());
                        m.version = Some("1.0.0".to_string());
                        m
                    }
                };

                let version = manifest.version.clone().unwrap_or_else(|| "1.0.0".to_string());
                let posix_rel = rnpm_core::to_posix_path(file_spec_clean);
                let resolved_url = format!("file:{posix_rel}");

                return Ok(ResolvedNode {
                    name: manifest.name.clone().unwrap_or_else(|| name.to_string()),
                    version,
                    resolved_url,
                    integrity,
                    dependencies: manifest.dependencies,
                    optional_dependencies: manifest.optional_dependencies,
                    optional: is_optional,
                    skipped: false,
                    os: manifest.os.unwrap_or_default(),
                    cpu: manifest.cpu.unwrap_or_default(),
                    libc: manifest.libc.unwrap_or_default(),
                    is_file_dir: false,
                    is_file_archive: true,
                    local_path: Some(abs_path),
                });
            } else {
                // Local directory dependency
                let manifest_path = abs_path.join("package.json");
                if !manifest_path.exists() {
                    return Err(anyhow!(
                        "package.json not found in local file dependency '{}' at '{}'",
                        name,
                        abs_path.display()
                    ));
                }
                let manifest = Manifest::from_file(&manifest_path).with_context(|| {
                    format!("Failed to parse package.json at '{}'", manifest_path.display())
                })?;

                let version = manifest.version.clone().unwrap_or_else(|| "1.0.0".to_string());
                let posix_rel = rnpm_core::to_posix_path(file_spec_clean);
                let resolved_url = format!("file:{posix_rel}");

                return Ok(ResolvedNode {
                    name: manifest.name.clone().unwrap_or_else(|| name.to_string()),
                    version,
                    resolved_url,
                    integrity: String::new(),
                    dependencies: manifest.dependencies,
                    optional_dependencies: manifest.optional_dependencies,
                    optional: is_optional,
                    skipped: false,
                    os: manifest.os.unwrap_or_default(),
                    cpu: manifest.cpu.unwrap_or_default(),
                    libc: manifest.libc.unwrap_or_default(),
                    is_file_dir: true,
                    is_file_archive: false,
                    local_path: Some(abs_path),
                });
            }
        }

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
            is_file_dir: false,
            is_file_archive: false,
            local_path: None,
        })
    }

    /// Prefetch package metadata concurrently for a set of package names.
    pub async fn prefetch_metadata(&mut self, names: &[&str]) -> Result<()> {
        let missing: Vec<String> = names
            .iter()
            .filter(|n| !self.metadata_cache.contains_key(**n))
            .map(|n| n.to_string())
            .collect();

        if missing.is_empty() {
            return Ok(());
        }

        let results = self
            .registry_client
            .get_package_metadata_concurrent(&missing)
            .await;

        for (name, res) in missing.into_iter().zip(results) {
            if let Ok(meta) = res {
                self.metadata_cache.insert(name, meta);
            }
        }

        Ok(())
    }

    /// Fetch multiple tarballs concurrently with bounded semaphore limits and local disk cache.
    pub async fn fetch_tarballs_concurrent(
        &self,
        urls: &[&str],
    ) -> Vec<Result<(Vec<u8>, bool)>> {
        let mut join_set = tokio::task::JoinSet::new();

        for (idx, url) in urls.iter().enumerate() {
            let cache = self.cache.clone();
            let registry_client = self.registry_client.clone();
            let url_str = url.to_string();

            join_set.spawn(async move {
                if let Ok(Some((_entry, data))) = cache.get(&url_str) {
                    debug!("Cache hit for {}", url_str);
                    return (idx, Ok((data, true)));
                }

                info!("Downloading {}", url_str);
                match registry_client.download_tarball_bytes(&url_str).await {
                    Ok(bytes) => {
                        let _ = cache.put(&url_str, &bytes, None);
                        (idx, Ok((bytes, false)))
                    }
                    Err(e) => (idx, Err(anyhow!("Failed to download tarball from {url_str}: {e}"))),
                }
            });
        }

        let mut results: Vec<Option<Result<(Vec<u8>, bool)>>> = (0..urls.len()).map(|_| None).collect();
        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, result)) = res {
                results[idx] = Some(result);
            }
        }

        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(anyhow!("Download task cancelled"))))
            .collect()
    }

    #[allow(dead_code)]
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

    /// Helper to reify a package with pre-downloaded or cached bytes.
    fn reify_package_with_bytes(
        &self,
        node: &ResolvedNode,
        bytes: &[u8],
        was_hit: bool,
        node_modules_dir: &std::path::Path,
        bin_dir: &std::path::Path,
    ) -> Result<(usize, usize, LockfilePackage, Option<LifecyclePackageNode>)> {
        let cache_hits = if was_hit { 1 } else { 0 };
        let cache_misses = if was_hit { 0 } else { 1 };

        let expected_integrity: Integrity = node.integrity.parse()
            .map_err(|e| anyhow!("Invalid integrity string: {e}"))?;
        expected_integrity.verify(bytes)
            .map_err(|e| anyhow!("Integrity verification failed for {}: {e}", node.name))?;

        let dest_dir = node_modules_dir.join(&node.name);
        extract_and_replace(Cursor::new(bytes), &dest_dir, None)
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

    /// Helper to reify a single package node into node_modules and return lifecycle node and lockfile package.
    #[allow(dead_code)]
    async fn reify_package(
        &self,
        node: &ResolvedNode,
        node_modules_dir: &std::path::Path,
        bin_dir: &std::path::Path,
    ) -> Result<(usize, usize, LockfilePackage, Option<LifecyclePackageNode>)> {
        let (bytes, was_hit) = self.fetch_tarball(&node.resolved_url).await?;
        self.reify_package_with_bytes(node, &bytes, was_hit, node_modules_dir, bin_dir)
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

        let is_targeted = !targets.is_empty();
        let mut updated_packages: Vec<String> = Vec::new();
        let mut old_versions: HashMap<String, String> = HashMap::new();
        let mut new_versions: HashMap<String, String> = HashMap::new();

        // 1. Check for newer versions satisfying ranges (prefetch metadata first)
        let target_names: Vec<&str> = deps_to_update.keys().map(|s| s.as_str()).collect();
        let _ = self.prefetch_metadata(&target_names).await;

        let mut newly_resolved_roots: BTreeMap<String, ResolvedNode> = BTreeMap::new();
        for (pkg_name, range_str) in &deps_to_update {
            let lock_key = format!("node_modules/{pkg_name}");
            let current_locked_ver = lockfile.get_package(&lock_key)
                .and_then(|p| p.version.clone());

            let resolved = self.resolve_package(pkg_name, range_str, false).await?;

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
            // 2. Resolve transitive dependencies for newly updated packages.
            // When targeted, do not modify unrelated dependencies or dependencies
            // whose existing locked version already satisfies the required range.
            let mut full_subgraph: BTreeMap<String, ResolvedNode> = BTreeMap::new();
            let mut queue: VecDeque<(String, String)> = VecDeque::new();

            for (name, node) in newly_resolved_roots {
                for (sub_name, sub_range) in &node.dependencies {
                    let should_enqueue = if is_targeted {
                        let lock_key = format!("node_modules/{sub_name}");
                        if let Some(existing_pkg) = lockfile.get_package(&lock_key) {
                            if let Some(ref ver_str) = existing_pkg.version {
                                if let (Ok(ver), Ok(range)) = (ver_str.parse::<Version>(), Range::parse(sub_range)) {
                                    !range.satisfies(&ver)
                                } else {
                                    true
                                }
                            } else {
                                true
                            }
                        } else {
                            true
                        }
                    } else {
                        true
                    };

                    if should_enqueue {
                        queue.push_back((sub_name.clone(), sub_range.clone()));
                    }
                }
                full_subgraph.insert(name, node);
            }

            while let Some((dep_name, dep_range)) = queue.pop_front() {
                if full_subgraph.contains_key(&dep_name) {
                    continue;
                }
                let node = self.resolve_package(&dep_name, &dep_range, false).await?;
                for (sub_name, sub_range) in &node.dependencies {
                    if !full_subgraph.contains_key(sub_name) {
                        let should_enqueue = if is_targeted {
                            let lock_key = format!("node_modules/{sub_name}");
                            if let Some(existing_pkg) = lockfile.get_package(&lock_key) {
                                if let Some(ref ver_str) = existing_pkg.version {
                                    if let (Ok(ver), Ok(range)) = (ver_str.parse::<Version>(), Range::parse(sub_range)) {
                                        !range.satisfies(&ver)
                                    } else {
                                        true
                                    }
                                } else {
                                    true
                                }
                            } else {
                                true
                            }
                        } else {
                            true
                        };

                        if should_enqueue {
                            queue.push_back((sub_name.clone(), sub_range.clone()));
                        }
                    }
                }
                full_subgraph.insert(dep_name, node);
            }

            // 3. Reify newly resolved packages into node_modules and update lockfile concurrently
            let mut packages_to_download: Vec<(&String, &ResolvedNode)> = Vec::new();
            for (pkg_name, node) in &full_subgraph {
                if !node.skipped {
                    packages_to_download.push((pkg_name, node));
                }
            }

            let download_urls: Vec<&str> = packages_to_download
                .iter()
                .map(|(_, n)| n.resolved_url.as_str())
                .collect();
            let download_results = self.fetch_tarballs_concurrent(&download_urls).await;

            for ((pkg_name, node), fetch_res) in packages_to_download.into_iter().zip(download_results) {
                let (bytes, was_hit) = fetch_res?;
                let (hits, misses, lock_entry, l_node) = self
                    .reify_package_with_bytes(node, &bytes, was_hit, &node_modules_dir, &bin_dir)?;
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
                if let Some(opt_deps) = &root_pkg.optional_dependencies {
                    for dep in opt_deps.keys() {
                        to_visit.push_back(dep.clone());
                    }
                }
            }

            for dep in manifest.dependencies.keys() {
                to_visit.push_back(dep.clone());
            }
            for dep in manifest.dev_dependencies.keys() {
                to_visit.push_back(dep.clone());
            }
            for dep in manifest.optional_dependencies.keys() {
                to_visit.push_back(dep.clone());
            }

            // Also check workspace packages in lockfile
            for (pkg_key, pkg_entry) in &lockfile.packages {
                if !pkg_key.starts_with("node_modules/") && !pkg_key.is_empty() {
                    if let Some(deps) = &pkg_entry.dependencies {
                        for dep in deps.keys() {
                            to_visit.push_back(dep.clone());
                        }
                    }
                    if let Some(dev_deps) = &pkg_entry.dev_dependencies {
                        for dep in dev_deps.keys() {
                            to_visit.push_back(dep.clone());
                        }
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
                    if let Some(opt_deps) = &pkg_entry.optional_dependencies {
                        for sub_dep in opt_deps.keys() {
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
                    timeout: None,
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
            if pkg.link == Some(true) {
                if let Some(target_rel) = &pkg.resolved {
                    if !reachable_keys.contains(target_rel) {
                        reachable_keys.insert(target_rel.clone());
                        queue.push_back(target_rel.clone());
                    }
                }
            }
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
