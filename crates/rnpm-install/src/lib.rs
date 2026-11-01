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
}
