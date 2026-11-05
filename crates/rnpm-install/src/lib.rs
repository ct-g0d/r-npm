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
use rnpm_core::spec::{PackageSpec, PackageTarget};
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
pub mod git;
pub use git::GitFetcher;

pub mod prune;
pub use prune::{
    analyze_reachability, discover_extraneous_packages, execute_prune,
    extract_package_name_from_path, scan_node_modules, ExtraneousPackage,
    PruneAnalysis, PruneOptions, PruneSummary,
};

use rnpm_solver::{
    resolve_workspace_graph, Overrides, PackageMetadata, PackageMetadataProvider,
    PackageVersionMetadata, Platform, ResolverOptions, Solver, SolverError,
    WorkspaceDependencyGraph,
};

/// Converts registry AbbreviatedPackageMetadata to Solver PackageMetadata.
pub fn abbreviated_to_package_metadata(meta: &AbbreviatedPackageMetadata) -> PackageMetadata {
    let mut dist_tags = BTreeMap::new();
    for (k, v) in &meta.dist_tags {
        dist_tags.insert(k.clone(), v.clone());
    }

    let mut versions = BTreeMap::new();
    for (ver_str, ver_info) in &meta.versions {
        let mut deps = BTreeMap::new();
        for (k, v) in &ver_info.dependencies {
            deps.insert(k.clone(), v.clone());
        }
        let mut dev_deps = BTreeMap::new();
        for (k, v) in &ver_info.dev_dependencies {
            dev_deps.insert(k.clone(), v.clone());
        }
        let mut peer_deps = BTreeMap::new();
        for (k, v) in &ver_info.peer_dependencies {
            peer_deps.insert(k.clone(), v.clone());
        }
        let mut peer_meta = BTreeMap::new();
        for (k, v) in &ver_info.peer_dependencies_meta {
            peer_meta.insert(k.clone(), v.clone());
        }
        let mut opt_deps = BTreeMap::new();
        for (k, v) in &ver_info.optional_dependencies {
            opt_deps.insert(k.clone(), v.clone());
        }

        let bin = ver_info.bin.as_ref().map(|b| match b {
            rnpm_registry::metadata::PackageBin::Single(s) => rnpm_lockfile::PackageBin::Single(s.clone()),
            rnpm_registry::metadata::PackageBin::Map(m) => rnpm_lockfile::PackageBin::Map(m.clone()),
        });

        versions.insert(
            ver_str.clone(),
            PackageVersionMetadata {
                name: ver_info.name.clone(),
                version: ver_info.version.clone(),
                dist_tarball: Some(ver_info.dist.tarball.clone()),
                dist_integrity: ver_info.dist.integrity.clone(),
                dependencies: deps,
                dev_dependencies: dev_deps,
                peer_dependencies: peer_deps,
                peer_dependencies_meta: peer_meta,
                optional_dependencies: opt_deps,
                os: if ver_info.os.is_empty() { None } else { Some(ver_info.os.clone()) },
                cpu: if ver_info.cpu.is_empty() { None } else { Some(ver_info.cpu.clone()) },
                libc: if ver_info.libc.is_empty() { None } else { Some(ver_info.libc.clone()) },
                bin,
                has_install_script: ver_info.has_install_script,
                deprecated: ver_info.deprecated.clone(),
            },
        );
    }

    PackageMetadata {
        name: meta.name.clone(),
        dist_tags,
        versions,
    }
}

pub struct RegistryPackageProvider {
    client: RegistryClient,
    handle: tokio::runtime::Handle,
    metadata_cache: Arc<std::sync::Mutex<HashMap<String, PackageMetadata>>>,
    cache: Cache,
    offline: bool,
    git_fetcher: crate::git::GitFetcher,
}

impl PackageMetadataProvider for RegistryPackageProvider {
    fn get_package(&self, name: &str) -> Result<Option<PackageMetadata>, SolverError> {
        if let Ok(cache) = self.metadata_cache.lock() {
            if let Some(meta) = cache.get(name) {
                return Ok(Some(meta.clone()));
            }
        }

        if let Ok(Some((_entry, data))) = self.cache.get(name) {
            if let Ok(abbrev) = serde_json::from_slice::<AbbreviatedPackageMetadata>(&data) {
                let meta = abbreviated_to_package_metadata(&abbrev);
                if let Ok(mut cache) = self.metadata_cache.lock() {
                    cache.insert(name.to_string(), meta.clone());
                }
                return Ok(Some(meta));
            }
        }

        if name.starts_with("git+")
            || name.starts_with("git:")
            || PackageTarget::parse(name).map(|t| t.is_git()).unwrap_or(false)
        {
            if let Ok(target) = PackageTarget::parse(name) {
                let fetcher = self.git_fetcher.clone();
                let offline = self.offline;
                let res = self.handle.block_on(async move {
                    fetcher.resolve_git_dependency(&target, offline).await
                });
                match res {
                    Ok(resolved) => {
                        let m = resolved.manifest;
                        let version = m.version.clone().unwrap_or_else(|| "1.0.0".to_string());
                        let bin = m.bin.as_ref().map(|b| match b {
                            rnpm_core::manifest::PackageBin::Single(s) => rnpm_lockfile::PackageBin::Single(s.clone()),
                            rnpm_core::manifest::PackageBin::Map(map) => rnpm_lockfile::PackageBin::Map(map.clone()),
                        });

                        let ver_meta = PackageVersionMetadata {
                            name: name.to_string(),
                            version: version.clone(),
                            dist_tarball: Some(resolved.resolved_url.clone()),
                            dist_integrity: None,
                            dependencies: m.dependencies.clone(),
                            dev_dependencies: m.dev_dependencies.clone(),
                            peer_dependencies: m.peer_dependencies.clone(),
                            peer_dependencies_meta: m.peer_dependencies_meta.clone(),
                            optional_dependencies: m.optional_dependencies.clone(),
                            os: m.os.clone(),
                            cpu: m.cpu.clone(),
                            libc: m.libc.clone(),
                            bin,
                            has_install_script: m.scripts.contains_key("install")
                                || m.scripts.contains_key("postinstall")
                                || m.scripts.contains_key("preinstall"),
                            deprecated: None,
                        };

                        let mut dist_tags = BTreeMap::new();
                        dist_tags.insert("latest".to_string(), version.clone());
                        let mut versions = BTreeMap::new();
                        versions.insert(version, ver_meta);

                        let meta = PackageMetadata {
                            name: name.to_string(),
                            dist_tags,
                            versions,
                        };
                        if let Ok(mut cache) = self.metadata_cache.lock() {
                            cache.insert(name.to_string(), meta.clone());
                        }
                        return Ok(Some(meta));
                    }
                    Err(e) => {
                        return Err(SolverError::PackageMetadata(name.to_string(), e.to_string()));
                    }
                }
            }
        }

        if self.offline {
            return Err(SolverError::PackageMetadata(
                name.to_string(),
                format!(
                    "npm error code ENOTCACHED\nnpm error request to fetch metadata for '{name}' failed: cache mode is 'only-if-cached' (--offline) but no cached response is available."
                ),
            ));
        }

        let client = self.client.clone();
        let pkg_name = name.to_string();
        let res = self.handle.block_on(async move {
            client.get_package_metadata(&pkg_name).await
        });
        match res {
            Ok(abbrev) => {
                let meta = abbreviated_to_package_metadata(&abbrev);
                if let Ok(mut cache) = self.metadata_cache.lock() {
                    cache.insert(name.to_string(), meta.clone());
                }
                Ok(Some(meta))
            }
            Err(e) => {
                if e.is_not_found() {
                    Ok(None)
                } else {
                    Err(SolverError::PackageMetadata(name.to_string(), e.to_string()))
                }
            }
        }
    }
}

pub fn apply_npmrc_to_client_config(
    client_config: &mut RegistryClientConfig,
    npmrc: &rnpm_config::Npmrc,
) {
    if let Some(strict_val) = npmrc
        .settings
        .get("strict-ssl")
        .or_else(|| npmrc.settings.get("strict_ssl"))
    {
        let trimmed = strict_val.trim().to_ascii_lowercase();
        client_config.strict_ssl = !matches!(trimmed.as_str(), "false" | "0" | "no" | "off");
    }

    if let Some(proxy_val) = npmrc.settings.get("proxy") {
        client_config.proxy = Some(proxy_val.clone());
    }

    if let Some(https_val) = npmrc
        .settings
        .get("https-proxy")
        .or_else(|| npmrc.settings.get("https_proxy"))
    {
        client_config.https_proxy = Some(https_val.clone());
    }

    if let Some(http_val) = npmrc
        .settings
        .get("http-proxy")
        .or_else(|| npmrc.settings.get("http_proxy"))
    {
        client_config.http_proxy = Some(http_val.clone());
    }

    if let Some(no_proxy_val) = npmrc
        .settings
        .get("no-proxy")
        .or_else(|| npmrc.settings.get("no_proxy"))
    {
        client_config.no_proxy = Some(no_proxy_val.clone());
    }

    if let Some(ca_val) = npmrc.settings.get("ca") {
        client_config.ca = Some(ca_val.clone());
    }

    if let Some(cafile_val) = npmrc
        .settings
        .get("cafile")
        .or_else(|| npmrc.settings.get("ca_file"))
    {
        client_config.cafile = Some(PathBuf::from(cafile_val));
    }

    if let Some(cert_val) = npmrc.settings.get("cert") {
        client_config.cert = Some(cert_val.clone());
    }

    if let Some(key_val) = npmrc.settings.get("key") {
        client_config.key = Some(key_val.clone());
    }

    let timeout_ms = npmrc
        .settings
        .get("fetch-timeout")
        .or_else(|| npmrc.settings.get("fetch_timeout"))
        .or_else(|| npmrc.settings.get("timeout"))
        .and_then(|val_str| val_str.trim().parse::<u64>().ok());
    if let Some(ms) = timeout_ms {
        client_config.timeout = std::time::Duration::from_millis(ms);
    }

    let connect_timeout_ms = npmrc
        .settings
        .get("connect-timeout")
        .or_else(|| npmrc.settings.get("connect_timeout"))
        .and_then(|val_str| val_str.trim().parse::<u64>().ok());
    if let Some(ms) = connect_timeout_ms {
        client_config.connect_timeout = std::time::Duration::from_millis(ms);
    }
}

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

fn find_enclosing_bin_dir(dest_dir: &Path, root_bin_dir: &Path) -> PathBuf {
    let mut curr = dest_dir.parent();
    while let Some(p) = curr {
        if p.file_name().map(|n| n == "node_modules").unwrap_or(false) {
            return p.join(".bin");
        }
        curr = p.parent();
    }
    root_bin_dir.to_path_buf()
}

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub project_dir: PathBuf,
    pub registry_url: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub offline: bool,
    pub ignore_scripts: bool,
    pub save_dev: bool,
    pub save_exact: bool,
    pub save_prod: bool,
    pub save_optional: bool,
    pub save_peer: bool,
    pub no_save: bool,
    pub package_lock_only: bool,
    pub packages: Vec<String>,
    pub omit_dev: bool,
    pub omit_optional: bool,
    pub omit_peer: bool,
    pub legacy_peer_deps: bool,
    pub strict_peer_deps: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::from("."),
            registry_url: None,
            cache_dir: None,
            offline: false,
            ignore_scripts: false,
            save_dev: false,
            save_exact: false,
            save_prod: false,
            save_optional: false,
            save_peer: false,
            no_save: false,
            package_lock_only: false,
            packages: Vec::new(),
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            legacy_peer_deps: false,
            strict_peer_deps: false,
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

        apply_npmrc_to_client_config(&mut client_config, &config.npmrc);

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

    /// Alias for `run()`.
    pub async fn install(&mut self) -> Result<InstallSummary> {
        self.run().await
    }

    /// Alias for `run_ci()`.
    pub async fn ci(&mut self) -> Result<InstallSummary> {
        self.run_ci().await
    }

    /// Install specific packages.
    pub async fn install_packages(&mut self, packages: &[String]) -> Result<InstallSummary> {
        self.options.packages = packages.to_vec();
        self.run().await
    }

    /// Run standard install workflow from project package.json.
    pub async fn run(&mut self) -> Result<InstallSummary> {
        self.install_internal().await
    }

    async fn install_internal(&mut self) -> Result<InstallSummary> {
        let manifest_path = self.options.project_dir.join("package.json");
        if !manifest_path.exists() {
            return Err(anyhow!("package.json not found in {}", self.options.project_dir.display()));
        }

        let mut manifest = Manifest::from_file(&manifest_path)
            .context("Failed to parse project package.json")?;

        // Track added packages and their original requested specifiers
        struct AddedPkgInfo {
            name: String,
            user_spec: Option<String>,
            target: PackageTarget,
        }
        let mut added_pkgs: Vec<AddedPkgInfo> = Vec::new();

        for raw_pkg in &self.options.packages {
            let trimmed = raw_pkg.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed.contains('\0') {
                return Err(anyhow!("Package argument contains null character"));
            }

            let formatted_input = if (trimmed.starts_with("./")
                || trimmed.starts_with("../")
                || trimmed.starts_with(".\\")
                || trimmed.starts_with("..\\"))
                && !trimmed.starts_with("file:")
            {
                format!("file:{}", trimmed)
            } else {
                trimmed.to_string()
            };

            let spec = PackageSpec::parse(&formatted_input)
                .map_err(|e| anyhow!("Failed to parse package specifier '{trimmed}': {e}"))?;

            if spec.name.contains("..") || spec.name.contains(':') || spec.name.contains('\\') || spec.name.contains('\0') {
                return Err(anyhow!("Package name '{}' contains illegal path characters", spec.name));
            }
            rnpm_fs::validate_entry_path(Path::new(&spec.name))
                .map_err(|e| anyhow!("Invalid package name '{}': {e}", spec.name))?;

            let user_spec = if let Some(at_idx) = trimmed.rfind('@') {
                let slash_idx = trimmed.find('/').unwrap_or(0);
                if at_idx > slash_idx {
                    Some(trimmed[at_idx + 1..].trim().to_string())
                } else {
                    None
                }
            } else {
                None
            };

            let solver_spec = match &spec.target {
                PackageTarget::Tag(t) => t.clone(),
                PackageTarget::Range(r) => user_spec.clone().unwrap_or_else(|| r.to_string()),
                PackageTarget::Version(v) => v.to_string(),
                PackageTarget::File(p) => format!("file:{}", rnpm_core::to_posix_path(&p.to_string_lossy())),
                PackageTarget::Git { url, committish } => {
                    format!("{}{}", url, committish.as_ref().map(|c| format!("#{c}")).unwrap_or_default())
                }
                PackageTarget::Workspace(ws) => format!("workspace:{}", ws),
                PackageTarget::Alias { name: real_name, target } => {
                    format!("npm:{}@{}", real_name, target)
                }
                PackageTarget::Url(u) => u.to_string(),
            };

            if self.options.save_dev {
                manifest.dev_dependencies.insert(spec.name.clone(), solver_spec);
                manifest.dependencies.remove(&spec.name);
                manifest.optional_dependencies.remove(&spec.name);
                manifest.peer_dependencies.remove(&spec.name);
            } else if self.options.save_optional {
                manifest.optional_dependencies.insert(spec.name.clone(), solver_spec);
                manifest.dependencies.remove(&spec.name);
                manifest.dev_dependencies.remove(&spec.name);
                manifest.peer_dependencies.remove(&spec.name);
            } else if self.options.save_peer {
                manifest.peer_dependencies.insert(spec.name.clone(), solver_spec);
                manifest.dependencies.remove(&spec.name);
                manifest.dev_dependencies.remove(&spec.name);
                manifest.optional_dependencies.remove(&spec.name);
            } else {
                manifest.dependencies.insert(spec.name.clone(), solver_spec);
                manifest.dev_dependencies.remove(&spec.name);
                manifest.optional_dependencies.remove(&spec.name);
                manifest.peer_dependencies.remove(&spec.name);
            }

            added_pkgs.push(AddedPkgInfo {
                name: spec.name,
                user_spec,
                target: spec.target,
            });
        }

        let project_name = manifest.name.clone().unwrap_or_else(|| "project".to_string());
        let project_version = manifest.version.clone();

        // Validate dependency names for path containment
        for dep_name in manifest.dependencies.keys()
            .chain(manifest.dev_dependencies.keys())
            .chain(manifest.optional_dependencies.keys())
            .chain(manifest.peer_dependencies.keys())
        {
            if dep_name.contains("..") || dep_name.contains(':') || dep_name.contains('\\') || dep_name.contains('\0') {
                return Err(anyhow!("Package name '{dep_name}' contains illegal path characters"));
            }
            rnpm_fs::validate_entry_path(Path::new(dep_name))
                .map_err(|e| anyhow!("Invalid package name '{dep_name}': {e}"))?;
        }

        // 0. Discover workspace members (if any)
        let mut workspace_members = discover_workspaces_from_manifest(
            &self.options.project_dir,
            &manifest,
        ).map_err(|e| anyhow!("Failed to discover workspaces: {e}"))?;

        if self.options.omit_dev {
            manifest.dev_dependencies.clear();
            for member in &mut workspace_members {
                member.manifest.dev_dependencies.clear();
            }
        }
        if self.options.omit_optional {
            manifest.optional_dependencies.clear();
            for member in &mut workspace_members {
                member.manifest.optional_dependencies.clear();
            }
        }

        let ws_graph_opt = if !workspace_members.is_empty() {
            Some(WorkspaceDependencyGraph::construct(&workspace_members)
                .map_err(|e| anyhow!("Workspace dependency error: {e}"))?)
        } else {
            None
        };

        // 1. Resolve dependency graph via Solver directly
        let handle = tokio::runtime::Handle::current();
        let metadata_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        self.populate_custom_target_metadata(&manifest, &metadata_cache).await?;
        for member in &workspace_members {
            self.populate_custom_target_metadata(&member.manifest, &metadata_cache).await?;
        }

        let provider = RegistryPackageProvider {
            client: self.registry_client.clone(),
            handle,
            metadata_cache,
            cache: self.cache.clone(),
            offline: self.options.offline,
            git_fetcher: crate::git::GitFetcher::new(self.cache.root()),
        };

        let lockfile_path = self.options.project_dir.join("package-lock.json");
        let existing_lockfile = if lockfile_path.exists() {
            std::fs::read_to_string(&lockfile_path)
                .ok()
                .and_then(|s| rnpm_lockfile::parse_and_migrate(&s).ok())
                .map(Arc::new)
        } else {
            None
        };

        let resolver_options = ResolverOptions {
            platform: Platform::current(),
            dev: !self.options.omit_dev,
            legacy_peer_deps: self.options.legacy_peer_deps,
            strict_peers: !self.options.legacy_peer_deps,
            strict_peer_deps: self.options.strict_peer_deps,
            lockfile: existing_lockfile,
        };

        let graph = if !workspace_members.is_empty() {
            let members = workspace_members.clone();
            let root_m = manifest.clone();
            tokio::task::spawn_blocking(move || {
                resolve_workspace_graph(
                    &root_m,
                    &members,
                    &provider,
                    &resolver_options,
                ).map_err(|e| anyhow!("Workspace dependency error: {e}"))
            }).await.map_err(|e| anyhow!("Solver task panicked: {e}"))??
        } else {
            let root_m = manifest.clone();
            tokio::task::spawn_blocking(move || {
                let overrides = Overrides::from_manifest(&root_m)
                    .map_err(|e| anyhow!("Failed to parse overrides: {e}"))?;
                let solver = Solver::new(&provider, resolver_options, overrides);
                solver.resolve(&root_m)
                    .map_err(|e| anyhow!("{e}"))
            }).await.map_err(|e| anyhow!("Solver task panicked: {e}"))??
        };

        // 2. Post-solve: finalize versions for added packages in manifest
        if !added_pkgs.is_empty() {
            for added in &added_pkgs {
                let resolved_version_opt = graph.nodes.get(&format!("node_modules/{}", added.name))
                    .or_else(|| graph.nodes.values().find(|n| n.install_name == added.name || n.name == added.name))
                    .map(|n| n.version.clone());

                let resolved_ver = resolved_version_opt.unwrap_or_else(|| "1.0.0".to_string());

                let final_spec = if self.options.save_exact {
                    match &added.target {
                        PackageTarget::Alias { name: real_name, .. } => {
                            format!("npm:{}@{}", real_name, resolved_ver)
                        }
                        PackageTarget::File(p) => {
                            format!("file:{}", rnpm_core::to_posix_path(&p.to_string_lossy()))
                        }
                        PackageTarget::Git { url, committish } => {
                            format!("{}{}", url, committish.as_ref().map(|c| format!("#{c}")).unwrap_or_default())
                        }
                        PackageTarget::Workspace(ws) => format!("workspace:{}", ws),
                        PackageTarget::Url(u) => u.to_string(),
                        _ => resolved_ver,
                    }
                } else {
                    match &added.target {
                        PackageTarget::Range(_) => {
                            if let Some(ref u_spec) = added.user_spec {
                                if u_spec == "*" || u_spec.eq_ignore_ascii_case("x") {
                                    format!("^{}", resolved_ver)
                                } else {
                                    u_spec.clone()
                                }
                            } else {
                                format!("^{}", resolved_ver)
                            }
                        }
                        PackageTarget::Tag(_) | PackageTarget::Version(_) => {
                            format!("^{}", resolved_ver)
                        }
                        PackageTarget::Alias { name: real_name, .. } => {
                            if let Some(ref u_spec) = added.user_spec {
                                format!("npm:{}@{}", real_name, u_spec)
                            } else {
                                format!("npm:{}@^{}", real_name, resolved_ver)
                            }
                        }
                        PackageTarget::File(p) => {
                            format!("file:{}", rnpm_core::to_posix_path(&p.to_string_lossy()))
                        }
                        PackageTarget::Git { url, committish } => {
                            format!("{}{}", url, committish.as_ref().map(|c| format!("#{c}")).unwrap_or_default())
                        }
                        PackageTarget::Workspace(ws) => format!("workspace:{}", ws),
                        PackageTarget::Url(u) => u.to_string(),
                    }
                };

                if self.options.save_dev {
                    manifest.dev_dependencies.insert(added.name.clone(), final_spec);
                } else if self.options.save_optional {
                    manifest.optional_dependencies.insert(added.name.clone(), final_spec);
                } else if self.options.save_peer {
                    manifest.peer_dependencies.insert(added.name.clone(), final_spec);
                } else {
                    manifest.dependencies.insert(added.name.clone(), final_spec);
                }
            }

            // Save package.json unless --no-save was passed
            if !self.options.no_save {
                manifest.save_to_file(&manifest_path)
                    .context("Failed to save updated package.json")?;
            }
        }

        let mut lockfile = graph.to_lockfile_v3(&project_name, project_version.as_deref());
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
            if manifest.peer_dependencies.is_empty() {
                root_pkg.peer_dependencies = None;
            } else {
                root_pkg.peer_dependencies = Some(manifest.peer_dependencies.clone());
            }
            if !manifest.workspace_patterns().is_empty() {
                root_pkg.workspaces = Some(manifest.workspace_patterns());
            }
        }

        // 3. For --package-lock-only, write package-lock.json and skip disk reification & lifecycle scripts
        if self.options.package_lock_only {
            for (loc, node) in &graph.nodes {
                if let Some(ref res) = node.resolved {
                    if let Some(rel_file) = res.strip_prefix("file:") {
                        let abs_file = self.options.project_dir.join(rel_file);
                        if abs_file.is_dir() {
                            let link_entry = LockfilePackage {
                                resolved: Some(rel_file.to_string()),
                                link: Some(true),
                                ..Default::default()
                            };
                            lockfile.insert_package(loc, link_entry);

                            let mut target_entry = LockfilePackage {
                                version: Some(node.version.clone()),
                                ..Default::default()
                            };
                            if !node.dependencies.is_empty() {
                                target_entry.dependencies = Some(node.dependencies.clone());
                            }
                            lockfile.insert_package(rel_file, target_entry);
                        }
                    }
                }
            }

            let lockfile_path = self.options.project_dir.join("package-lock.json");
            lockfile.save_to_file(&lockfile_path)
                .context("Failed to save package-lock.json")?;

            return Ok(InstallSummary {
                packages_installed: 0,
                cache_hits: 0,
                cache_misses: 0,
                lockfile_path,
            });
        }

        // 2. Build proper nested node_modules trees and lockfile v3 from solver graph
        let node_modules_dir = self.options.project_dir.join("node_modules");
        let root_bin_dir = node_modules_dir.join(".bin");
        std::fs::create_dir_all(&node_modules_dir).context("Failed to create node_modules")?;
        std::fs::create_dir_all(&root_bin_dir).context("Failed to create node_modules/.bin")?;

        let mut cache_hits = 0;
        let mut cache_misses = 0;
        let mut packages_installed = 0;

        let mut lifecycle_nodes: Vec<LifecyclePackageNode> = Vec::new();
        let mut packages_to_download = Vec::new();

        for (loc, node) in &graph.nodes {
            if loc.is_empty() {
                continue;
            }

            if self.options.omit_dev && node.flags.dev {
                continue;
            }
            if self.options.omit_optional && node.flags.optional {
                continue;
            }
            if self.options.omit_peer && node.flags.peer {
                continue;
            }

            if node.flags.link {
                let link_target = self.options.project_dir.join(loc);
                if let Some(parent) = link_target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if link_target.exists() || rnpm_fs::is_junction(&link_target).unwrap_or(false) {
                    let _ = rnpm_fs::remove_junction(&link_target);
                    if link_target.exists() && !rnpm_fs::is_junction(&link_target).unwrap_or(false) {
                        let _ = std::fs::remove_dir_all(&link_target);
                    }
                }
                let source_path = if let Some(ref res) = node.resolved {
                    self.options.project_dir.join(res)
                } else {
                    self.options.project_dir.join(&node.name)
                };

                rnpm_fs::create_junction(&link_target, &source_path)
                    .map_err(|e| anyhow!("Failed to link package at '{}' -> '{}': {e}", link_target.display(), source_path.display()))?;

                packages_installed += 1;

                let bin_dir = find_enclosing_bin_dir(&link_target, &root_bin_dir);
                std::fs::create_dir_all(&bin_dir)?;
                let manifest_path = source_path.join("package.json");
                if let Ok(m) = Manifest::from_file(&manifest_path) {
                    for (bin_name, script_rel) in m.bin_entries() {
                        let target_rel = format!("{}/{}", node.install_name, script_rel);
                        let script_path = source_path.join(&script_rel);
                        let _ = normalize_shebang(&script_path);
                        let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                    }
                }
                continue;
            }

            if workspace_members.iter().any(|m| &m.relative_path == loc) {
                continue;
            }

            if node.flags.skipped {
                debug!("Package at {} is marked skipped, bypassing download and extraction", loc);
                continue;
            }

            let dest_dir = self.options.project_dir.join(loc);
            if let Some(parent) = dest_dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bin_dir = find_enclosing_bin_dir(&dest_dir, &root_bin_dir);
            std::fs::create_dir_all(&bin_dir)?;

            if let Some(ref res) = node.resolved {
                let is_git = res.starts_with("git+")
                    || res.starts_with("git:")
                    || PackageTarget::parse(res).map(|t| t.is_git()).unwrap_or(false);

                if is_git {
                    let git_fetcher = crate::git::GitFetcher::new(self.cache.root());
                    let target = PackageTarget::parse(res)
                        .map_err(|e| anyhow!("Failed to parse git target: {e}"))?;
                    let checkout_dir = git_fetcher
                        .checkout_git_dependency(&target, self.options.offline)
                        .await?;

                    crate::git::copy_dir_all(&checkout_dir, &dest_dir)?;
                    packages_installed += 1;
                    cache_hits += 1;

                    let pkg_manifest_path = dest_dir.join("package.json");
                    if pkg_manifest_path.exists() {
                        if let Ok(m) = Manifest::from_file(&pkg_manifest_path) {
                            for (bin_name, script_rel) in m.bin_entries() {
                                let target_rel = format!("{}/{}", node.install_name, script_rel);
                                let script_path = dest_dir.join(&script_rel);
                                let _ = normalize_shebang(&script_path);
                                let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                            }
                            if m.scripts.contains_key("preinstall")
                                || m.scripts.contains_key("install")
                                || m.scripts.contains_key("postinstall")
                            {
                                lifecycle_nodes.push(LifecyclePackageNode {
                                    package_path: loc.clone(),
                                    disk_path: dest_dir.clone(),
                                    manifest: m,
                                    source: PackageSource::Registry,
                                    dependencies: node.dependencies.keys().cloned().collect(),
                                    optional: node.flags.optional,
                                });
                            }
                        }
                    }
                    continue;
                }

                if res.starts_with("file:") {
                    let rel_file = res.strip_prefix("file:").unwrap();
                    let abs_file = self.options.project_dir.join(rel_file);
                    if abs_file.is_file() {
                        let archive_bytes = std::fs::read(&abs_file)?;
                        extract_and_replace(Cursor::new(&archive_bytes), &dest_dir, None)
                            .map_err(|e| anyhow!("Failed to extract local archive {}: {e}", loc))?;

                        packages_installed += 1;
                        cache_hits += 1;

                        let pkg_manifest_path = dest_dir.join("package.json");
                        if pkg_manifest_path.exists() {
                            if let Ok(m) = Manifest::from_file(&pkg_manifest_path) {
                                for (bin_name, script_rel) in m.bin_entries() {
                                    let target_rel = format!("{}/{}", node.install_name, script_rel);
                                    let script_path = dest_dir.join(&script_rel);
                                    let _ = normalize_shebang(&script_path);
                                    let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                                }
                                if m.scripts.contains_key("preinstall")
                                    || m.scripts.contains_key("install")
                                    || m.scripts.contains_key("postinstall")
                                {
                                    lifecycle_nodes.push(LifecyclePackageNode {
                                        package_path: loc.clone(),
                                        disk_path: dest_dir.clone(),
                                        manifest: m,
                                        source: PackageSource::Registry,
                                        dependencies: node.dependencies.keys().cloned().collect(),
                                        optional: node.flags.optional,
                                    });
                                }
                            }
                        }
                        continue;
                    } else if abs_file.is_dir() {
                        if dest_dir.exists() || rnpm_fs::is_junction(&dest_dir).unwrap_or(false) {
                            let _ = rnpm_fs::remove_junction(&dest_dir);
                            if dest_dir.exists() && !rnpm_fs::is_junction(&dest_dir).unwrap_or(false) {
                                let _ = std::fs::remove_dir_all(&dest_dir);
                            }
                        }
                        rnpm_fs::create_junction(&dest_dir, &abs_file)
                            .map_err(|e| anyhow!("Failed to link file dir {}: {e}", loc))?;
                        packages_installed += 1;
                        let pkg_manifest_path = abs_file.join("package.json");
                        if let Ok(m) = Manifest::from_file(&pkg_manifest_path) {
                            for (bin_name, script_rel) in m.bin_entries() {
                                let target_rel = format!("{}/{}", node.install_name, script_rel);
                                let script_path = abs_file.join(&script_rel);
                                let _ = normalize_shebang(&script_path);
                                let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                            }
                        }

                        let link_entry = LockfilePackage {
                            resolved: Some(rel_file.to_string()),
                            link: Some(true),
                            ..Default::default()
                        };
                        lockfile.insert_package(loc, link_entry);

                        let mut target_entry = LockfilePackage {
                            version: Some(node.version.clone()),
                            ..Default::default()
                        };
                        if !node.dependencies.is_empty() {
                            target_entry.dependencies = Some(node.dependencies.clone());
                        }
                        lockfile.insert_package(rel_file, target_entry);
                        continue;
                    }
                }
            }

            packages_to_download.push((loc.clone(), node.clone()));
        }

        // Collect lifecycle nodes for workspace members
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

        let concurrency = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(4, 16);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut join_set = tokio::task::JoinSet::new();

        for (loc, node) in packages_to_download {
            let sem = Arc::clone(&semaphore);
            let cache = self.cache.clone();
            let registry_client = self.registry_client.clone();
            let project_dir = self.options.project_dir.clone();
            let root_bin = root_bin_dir.clone();
            let offline = self.options.offline;

            join_set.spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| anyhow!("{e}"))?;

                let dest_dir = project_dir.join(&loc);
                if let Some(parent) = dest_dir.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let bin_dir = find_enclosing_bin_dir(&dest_dir, &root_bin);
                std::fs::create_dir_all(&bin_dir)?;

                let resolved_url = node.resolved.as_ref().ok_or_else(|| {
                    anyhow!("Missing resolved URL for package at {loc}")
                })?;

                let expected_integrity: Option<Integrity> = if let Some(ref integ_str) = node.integrity {
                    if !integ_str.is_empty() {
                        match integ_str.parse::<Integrity>() {
                            Ok(i) => Some(i),
                            Err(e) => {
                                if node.flags.optional {
                                    warn!(
                                        "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Invalid integrity for {}: {}",
                                        loc, e
                                    );
                                    return Ok(None);
                                } else {
                                    return Err(anyhow!("Invalid integrity string for {loc}: {e}"));
                                }
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let fetch_res = if let Ok(Some((_entry, data))) = cache.get(resolved_url) {
                    let is_valid = if let Some(ref exp) = expected_integrity {
                        exp.verify(&data).is_ok()
                    } else {
                        true
                    };

                    if is_valid {
                        debug!("Cache hit for {}", resolved_url);
                        Ok((data, true))
                    } else {
                        debug!("Cached blob for {} failed integrity, purging and re-fetching", resolved_url);
                        let _ = cache.purge_key(resolved_url);
                        if offline {
                            if node.flags.optional {
                                return Ok(None);
                            }
                            return Err(anyhow!(
                                "npm error code EINTEGRITY\nnpm error Integrity verification failed for cached package {loc}"
                            ));
                        }
                        match registry_client.download_tarball_bytes(resolved_url).await {
                            Ok(bytes) => {
                                if let Some(ref exp) = expected_integrity {
                                    if let Err(e) = exp.verify(&bytes) {
                                        if node.flags.optional {
                                            warn!(
                                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {}: {}",
                                                loc, e
                                            );
                                            return Ok(None);
                                        } else {
                                            return Err(anyhow!("Integrity verification failed for {loc}: {e}"));
                                        }
                                    }
                                }
                                let _ = cache.put_with_integrity(resolved_url, &bytes, expected_integrity.as_ref(), None);
                                Ok((bytes, false))
                            }
                            Err(e) => Err(anyhow!("Failed to download tarball from {}: {e}", resolved_url)),
                        }
                    }
                } else if offline {
                    if node.flags.optional {
                        warn!("npm warn optional SKIPPING OPTIONAL DEPENDENCY: Package {} not found in local cache (--offline)", loc);
                        return Ok(None);
                    }
                    return Err(anyhow!(
                        "npm error code ENOTCACHED\nnpm error request to download tarball from '{resolved_url}' failed: cache mode is 'only-if-cached' (--offline) but no cached response is available."
                    ));
                } else {
                    info!("Downloading {}", resolved_url);
                    match registry_client.download_tarball_bytes(resolved_url).await {
                        Ok(bytes) => {
                            if let Some(ref exp) = expected_integrity {
                                if let Err(e) = exp.verify(&bytes) {
                                    if node.flags.optional {
                                        warn!(
                                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {}: {}",
                                            loc, e
                                        );
                                        return Ok(None);
                                    } else {
                                        return Err(anyhow!("Integrity verification failed for {loc}: {e}"));
                                    }
                                }
                            }
                            let _ = cache.put_with_integrity(resolved_url, &bytes, expected_integrity.as_ref(), None);
                            Ok((bytes, false))
                        }
                        Err(e) => Err(anyhow!("Failed to download tarball from {}: {e}", resolved_url)),
                    }
                };

                let (bytes, was_hit) = match fetch_res {
                    Ok(res) => res,
                    Err(err) => {
                        if node.flags.optional {
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to fetch {}: {:#}",
                                loc, err
                            );
                            return Ok(None);
                        } else {
                            return Err(err);
                        }
                    }
                };

                // Verify integrity in memory (defense in depth)
                if let Some(ref exp) = expected_integrity {
                    if let Err(e) = exp.verify(&bytes) {
                        if node.flags.optional {
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {}: {}",
                                loc, e
                            );
                            return Ok(None);
                        } else {
                            return Err(anyhow!("Integrity verification failed for {}: {e}", loc));
                        }
                    }
                }

                // Streaming memory bound: enforce maximum compressed tarball size (256 MB)
                const MAX_COMPRESSED_TARBALL_BYTES: usize = 256 * 1024 * 1024;
                if bytes.len() > MAX_COMPRESSED_TARBALL_BYTES {
                    return Err(anyhow!(
                        "Tarball for {} exceeds maximum allowed compressed size of {} bytes",
                        loc, MAX_COMPRESSED_TARBALL_BYTES
                    ));
                }

                // Path containment defense: ensure loc has no traversal or device escaping
                if loc.contains("..") || loc.contains(':') || loc.contains('\\') || loc.contains('\0') {
                    return Err(anyhow!("Package path '{loc}' contains illegal path characters"));
                }

                let cleaned_dest = path_clean::clean(&dest_dir);
                let cleaned_project = path_clean::clean(&project_dir);
                if !cleaned_dest.starts_with(&cleaned_project) {
                    return Err(anyhow!("Package installation path '{cleaned_dest:?}' escapes project root"));
                }

                // Decompress directly through memory buffer and extract with atomic replacement & backoff retries
                let dest_dir_clone = dest_dir.clone();
                let extract_res = tokio::task::spawn_blocking(move || {
                    extract_and_replace(Cursor::new(bytes), &dest_dir_clone, None)
                }).await?;

                if let Err(e) = extract_res {
                    if node.flags.optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to extract package {}: {}",
                            loc, e
                        );
                        let _ = std::fs::remove_dir_all(&dest_dir);
                        return Ok(None);
                    } else {
                        return Err(anyhow!("Failed to extract package {}: {e}", loc));
                    }
                }

                // Generate shims if package declares bin and collect lifecycle node
                let pkg_manifest_path = dest_dir.join("package.json");
                let mut lifecycle_node = None;

                if pkg_manifest_path.exists() {
                    if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                        for (bin_name, script_rel) in pkg_manifest.bin_entries() {
                            let target_rel = format!("{}/{}", node.install_name, script_rel);
                            let script_path = dest_dir.join(&script_rel);
                            let _ = normalize_shebang(&script_path);
                            let _ = create_shims(&bin_dir, &bin_name, &target_rel);
                        }

                        let has_install_script = pkg_manifest.scripts.contains_key("preinstall")
                            || pkg_manifest.scripts.contains_key("install")
                            || pkg_manifest.scripts.contains_key("postinstall");

                        if has_install_script {
                            lifecycle_node = Some(LifecyclePackageNode {
                                package_path: loc.clone(),
                                disk_path: dest_dir.clone(),
                                manifest: pkg_manifest,
                                source: PackageSource::Registry,
                                dependencies: node.dependencies.keys().cloned().collect(),
                                optional: node.flags.optional,
                            });
                        }
                    }
                }

                Ok(Some((
                    was_hit,
                    lifecycle_node,
                )))
            });
        }

        while let Some(join_res) = join_set.join_next().await {
            let item_opt = join_res.map_err(|e| anyhow!("Reification worker panicked: {e}"))??;
            if let Some((was_hit, lifecycle_node)) = item_opt {
                if was_hit {
                    cache_hits += 1;
                } else {
                    cache_misses += 1;
                }
                packages_installed += 1;
                if let Some(l_node) = lifecycle_node {
                    lifecycle_nodes.push(l_node);
                }
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
                sandbox_policy: Default::default(),
            };
            execute_topological(&lifecycle_nodes, &manifest, &lifecycle_opts).await?;
        }

        let lockfile_path = self.options.project_dir.join("package-lock.json");
        if !self.options.no_save {
            // 4. Write deterministic package-lock.json
            lockfile.save_to_file(&lockfile_path)
                .context("Failed to save package-lock.json")?;

            // 5. Persist hidden lockfile to node_modules/.package-lock.json
            lockfile.save_hidden(&self.options.project_dir)
                .context("Failed to save hidden package-lock.json")?;
        }

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
        let lockfile = rnpm_lockfile::parse_and_migrate(&lockfile_str)
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

        // Comprehensive bidirectional drift check between manifest and lockfile
        let root_pkg = lockfile.packages.get("").ok_or_else(|| {
            anyhow!("rnpm ERR! code ELOCKFILE_DRIFT: package-lock.json missing root package descriptor (EUSAGE)")
        })?;

        // 1. Production dependencies drift check
        let empty_deps = BTreeMap::new();
        let lock_deps = root_pkg.dependencies.as_ref().unwrap_or(&empty_deps);

        for (dep_name, dep_spec) in &manifest.dependencies {
            if let Some(lock_spec) = lock_deps.get(dep_name) {
                if lock_spec != dep_spec {
                    let satisfies = if let Ok(v) = Version::parse(lock_spec) {
                        if let Ok(r) = Range::parse(dep_spec) {
                            r.satisfies(&v)
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !satisfies {
                    return Err(anyhow!(
                        "rnpm ERR! code ELOCKFILE_DRIFT: package.json dependency {}@{} does not match lockfile spec {} (EUSAGE)",
                        dep_name, dep_spec, lock_spec
                    ));
                    }
                }
            } else {
                return Err(anyhow!(
                    "rnpm ERR! code ELOCKFILE_DRIFT: package.json dependency {} missing from package-lock.json (EUSAGE)",
                    dep_name
                ));
            }
        }
        for dep_name in lock_deps.keys() {
            if !manifest.dependencies.contains_key(dep_name) {
                return Err(anyhow!(
                    "rnpm ERR! code ELOCKFILE_DRIFT: dependency {} present in package-lock.json but removed from package.json (EUSAGE)",
                    dep_name
                ));
            }
        }

        // 2. Dev dependencies drift check
        let lock_dev_deps = root_pkg.dev_dependencies.as_ref().unwrap_or(&empty_deps);

        if !self.options.omit_dev {
        for (dep_name, dep_spec) in &manifest.dev_dependencies {
            if let Some(lock_spec) = lock_dev_deps.get(dep_name) {
                if lock_spec != dep_spec {
                    let satisfies = if let Ok(v) = Version::parse(lock_spec) {
                        if let Ok(r) = Range::parse(dep_spec) {
                            r.satisfies(&v)
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !satisfies {
                    return Err(anyhow!(
                        "rnpm ERR! code ELOCKFILE_DRIFT: package.json devDependency {}@{} does not match lockfile spec {} (EUSAGE)",
                        dep_name, dep_spec, lock_spec
                    ));
                    }
                }
            } else {
                return Err(anyhow!(
                    "rnpm ERR! code ELOCKFILE_DRIFT: package.json devDependency {} missing from package-lock.json (EUSAGE)",
                    dep_name
                ));
            }
        }
        for dep_name in lock_dev_deps.keys() {
            if !manifest.dev_dependencies.contains_key(dep_name) {
                return Err(anyhow!(
                    "rnpm ERR! code ELOCKFILE_DRIFT: devDependency {} present in package-lock.json but removed from package.json (EUSAGE)",
                    dep_name
                ));
            }
        }
        }

        // 3. Optional dependencies drift check
        let lock_opt_deps = root_pkg.optional_dependencies.as_ref().unwrap_or(&empty_deps);

        if !self.options.omit_optional {
        for (dep_name, dep_spec) in &manifest.optional_dependencies {
            if let Some(lock_spec) = lock_opt_deps.get(dep_name) {
                if lock_spec != dep_spec {
                    let satisfies = if let Ok(v) = Version::parse(lock_spec) {
                        if let Ok(r) = Range::parse(dep_spec) {
                            r.satisfies(&v)
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !satisfies {
                    return Err(anyhow!(
                        "rnpm ERR! code ELOCKFILE_DRIFT: package.json optionalDependency {}@{} does not match lockfile spec {} (EUSAGE)",
                        dep_name, dep_spec, lock_spec
                    ));
                    }
                }
            } else {
                return Err(anyhow!(
                    "rnpm ERR! code ELOCKFILE_DRIFT: package.json optionalDependency {} missing from package-lock.json (EUSAGE)",
                    dep_name
                ));
            }
        }
        for dep_name in lock_opt_deps.keys() {
            if !manifest.optional_dependencies.contains_key(dep_name) {
                return Err(anyhow!(
                    "rnpm ERR! code ELOCKFILE_DRIFT: optionalDependency {} present in package-lock.json but removed from package.json (EUSAGE)",
                    dep_name
                ));
            }
        }
        }

        // 4. Comprehensive lockfile validation via matches_manifest
        if !lockfile.matches_manifest(&manifest, !self.options.omit_dev) {
            return Err(anyhow!(
                "rnpm ERR! code ELOCKFILE_DRIFT: package.json and package-lock.json are out of sync. Please run `rnpm install` to update your lockfile. (EUSAGE)"
            ));
        }

        // Clean-slate: remove node_modules completely using junction-safe removal
        let node_modules_dir = self.options.project_dir.join("node_modules");
        let bin_dir = node_modules_dir.join(".bin");
        if node_modules_dir.exists() || rnpm_fs::is_junction(&node_modules_dir).unwrap_or(false) {
            rnpm_fs::remove_dir_all_safe(&node_modules_dir)?;
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
                if !self.options.omit_dev {
                for (dep_name, dep_spec) in &member.manifest.dev_dependencies {
                    let is_sibling = ws_graph_opt.as_ref().map(|g| g.is_member(dep_name)).unwrap_or(false)
                        || dep_spec.starts_with("workspace:")
                        || workspace_members.iter().any(|m| &m.name == dep_name);
                    if is_sibling && !member_deps.contains(dep_name) {
                        member_deps.push(dep_name.clone());
                    }
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

        let mut packages_to_download: Vec<(&String, &String, &str, bool)> = Vec::new();

        for (pkg_key, pkg_info) in &lockfile.packages {
            if pkg_key.is_empty() {
                continue;
            }

            // Omit filtering
            let is_dev = pkg_info.dev.unwrap_or(false);
            let is_optional = pkg_info.optional.unwrap_or(false);
            let is_dev_optional = pkg_info.dev_optional.unwrap_or(false);
            let is_peer = pkg_info.peer.unwrap_or(false) || pkg_info.peer_optional.unwrap_or(false);

            if self.options.omit_dev {
                if is_dev || is_dev_optional {
                    continue;
                }
                if let Some(clean_name) = pkg_key.strip_prefix("node_modules/") {
                    if !clean_name.contains('/') {
                        if manifest.dev_dependencies.contains_key(clean_name)
                            && !manifest.dependencies.contains_key(clean_name)
                        {
                            continue;
                        }
                    }
                }
            }
            if self.options.omit_optional {
                if is_optional || is_dev_optional {
                    continue;
                }
                if let Some(clean_name) = pkg_key.strip_prefix("node_modules/") {
                    if !clean_name.contains('/') {
                        if manifest.optional_dependencies.contains_key(clean_name)
                            && !manifest.dependencies.contains_key(clean_name)
                        {
                            continue;
                        }
                    }
                }
            }
            if self.options.omit_peer || self.options.legacy_peer_deps {
                if is_peer {
                    continue;
                }
                if let Some(clean_name) = pkg_key.strip_prefix("node_modules/") {
                    if !clean_name.contains('/') {
                        if manifest.peer_dependencies.contains_key(clean_name)
                            && !manifest.dependencies.contains_key(clean_name)
                        {
                            continue;
                        }
                    }
                }
            }

            // Handle workspace links
            if pkg_info.link == Some(true) {
                // Path containment defense: ensure pkg_key has no traversal, device names, or escapes
                if pkg_key.contains("..") || pkg_key.contains(':') || pkg_key.contains('\\') || pkg_key.contains('\0') {
                    return Err(anyhow!("Package lock entry '{pkg_key}' contains illegal path characters"));
                }
                rnpm_fs::validate_entry_path(Path::new(pkg_key))
                    .map_err(|e| anyhow!("Invalid package path in lockfile '{pkg_key}': {e}"))?;

                let full_target = self.options.project_dir.join(pkg_key);
                let cleaned = path_clean::clean(&full_target);
                if !cleaned.starts_with(&self.options.project_dir) {
                    return Err(anyhow!("Package path '{cleaned:?}' escapes project boundary"));
                }
                if pkg_key.starts_with("node_modules/") && !cleaned.starts_with(&node_modules_dir) {
                    return Err(anyhow!("Package path '{cleaned:?}' escapes node_modules boundary"));
                }

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

            // Path containment defense: ensure pkg_key has no traversal, device names, or escapes
            if pkg_key.contains("..") || pkg_key.contains(':') || pkg_key.contains('\\') || pkg_key.contains('\0') {
                return Err(anyhow!("Package lock entry '{pkg_key}' contains illegal path characters"));
            }
            rnpm_fs::validate_entry_path(Path::new(pkg_key))
                .map_err(|e| anyhow!("Invalid package path in lockfile '{pkg_key}': {e}"))?;

            let full_target = self.options.project_dir.join(pkg_key);
            let cleaned = path_clean::clean(&full_target);
            if !cleaned.starts_with(&self.options.project_dir) {
                return Err(anyhow!("Package path '{cleaned:?}' escapes project boundary"));
            }
            if !cleaned.starts_with(&node_modules_dir) {
                return Err(anyhow!("Package path '{cleaned:?}' escapes node_modules boundary"));
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

            let is_git = resolved_url.starts_with("git+")
                || resolved_url.starts_with("git:")
                || PackageTarget::parse(resolved_url).map(|t| t.is_git()).unwrap_or(false);

            if is_git {
                let git_fetcher = crate::git::GitFetcher::new(self.cache.root());
                let target = PackageTarget::parse(resolved_url)
                    .map_err(|e| anyhow!("Failed to parse git target in lockfile: {e}"))?;
                let checkout_dir = git_fetcher
                    .checkout_git_dependency(&target, self.options.offline)
                    .await?;

                crate::git::copy_dir_all(&checkout_dir, &full_target)?;
                packages_installed += 1;
                cache_hits += 1;

                let target_bin_dir = find_enclosing_bin_dir(&full_target, &bin_dir);
                let _ = std::fs::create_dir_all(&target_bin_dir);

                let pkg_manifest_path = full_target.join("package.json");
                if pkg_manifest_path.exists() {
                    if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                        let clean_pkg_name = pkg_key.strip_prefix("node_modules/").unwrap_or(pkg_key);
                        for (bin_name, script_rel) in pkg_manifest.bin_entries() {
                            let target_rel = format!("{clean_pkg_name}/{script_rel}");
                            let script_path = full_target.join(&script_rel);
                            let _ = normalize_shebang(&script_path);
                            let _ = create_shims(&target_bin_dir, &bin_name, &target_rel);
                        }
                    }
                }
                continue;
            }

            // Validate that lockfile packages have non-empty valid integrity hashes
            let integrity_str = match pkg_info.integrity.as_deref() {
                Some(i) if !i.trim().is_empty() => {
                    if let Err(e) = i.trim().parse::<Integrity>() {
                        if is_optional {
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Package {} has invalid integrity in lockfile: {}",
                                pkg_key, e
                            );
                            continue;
                        } else {
                            return Err(anyhow!("Package {} has invalid integrity in lockfile: {}", pkg_key, e));
                        }
                    }
                    i.trim()
                }
                _ => {
                    if is_optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Package {} missing or empty integrity in lockfile",
                            pkg_key
                        );
                        continue;
                    } else {
                        return Err(anyhow!("Package {} missing or empty integrity in lockfile", pkg_key));
                    }
                }
            };

            if resolved_url.starts_with("file:") {
                let file_path = resolved_url.strip_prefix("file:").unwrap().trim();
                if file_path.contains('\0') {
                    return Err(anyhow!("Resolved file URL contains null bytes: {resolved_url}"));
                }
                let project_dir_abs = if self.options.project_dir.is_absolute() {
                    self.options.project_dir.clone()
                } else {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(&self.options.project_dir)
                };
                let clean_project_dir = path_clean::clean(&project_dir_abs);
                let candidate_path = if Path::new(file_path).is_absolute() {
                    PathBuf::from(file_path)
                } else {
                    clean_project_dir.join(file_path)
                };
                let clean_file_path = path_clean::clean(&candidate_path);
                if !clean_file_path.starts_with(&clean_project_dir) {
                    return Err(anyhow!(
                        "Security error: resolved file URL '{}' escapes project directory '{}'",
                        resolved_url,
                        clean_project_dir.display()
                    ));
                }
                if let (Ok(canon_proj), Ok(canon_file)) = (clean_project_dir.canonicalize(), clean_file_path.canonicalize()) {
                    if !canon_file.starts_with(&canon_proj) {
                        return Err(anyhow!(
                            "Security error: resolved file path '{}' canonical path '{}' escapes project directory '{}'",
                            resolved_url,
                            canon_file.display(),
                            canon_proj.display()
                        ));
                    }
                }
                if !clean_file_path.exists() {
                    if is_optional {
                        warn!("npm warn optional SKIPPING OPTIONAL DEPENDENCY: Archive {} not found", clean_file_path.display());
                        continue;
                    } else {
                        return Err(anyhow!("Archive file not found: {}", clean_file_path.display()));
                    }
                }
                let bytes = std::fs::read(&clean_file_path)
                    .with_context(|| format!("Failed to read local archive file '{}'", clean_file_path.display()))?;

                let expected_integrity: Integrity = integrity_str
                    .parse()
                    .map_err(|e| anyhow!("Invalid integrity hash: {e}"))?;
                if let Err(e) = expected_integrity.verify(&bytes) {
                    if is_optional {
                        warn!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for local archive {pkg_key}: {e}"
                        );
                        continue;
                    } else {
                        return Err(anyhow!("Integrity verification failed for local archive {pkg_key}: {e}"));
                    }
                }

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

            packages_to_download.push((pkg_key, resolved_url, integrity_str, is_optional));
        }

        if self.options.offline {
            for (pkg_key, resolved_url, integrity_str, is_optional) in &packages_to_download {
                match self.cache.get(resolved_url) {
                    Ok(Some((_entry, data))) => {
                        if let Ok(expected) = integrity_str.parse::<Integrity>() {
                            if let Err(e) = expected.verify(&data) {
                                if *is_optional {
                                    warn!(
                                        "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for cached package {pkg_key}: {e}"
                                    );
                                    continue;
                                }
                                return Err(anyhow!(
                                    "npm error code EINTEGRITY\nnpm error Integrity verification failed for cached package {pkg_key}: {e}"
                                ));
                            }
                        }
                    }
                    _ => {
                        if *is_optional {
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Package {} not found in local cache (--offline)",
                                pkg_key
                            );
                            continue;
                        }
                        return Err(anyhow!(
                            "npm error code ENOTCACHED\nnpm error request to download tarball from '{resolved_url}' failed: cache mode is 'only-if-cached' (--offline) but no cached response is available."
                        ));
                    }
                }
            }
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
                    if self.options.offline {
                        if is_optional {
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {pkg_key}: {e}"
                            );
                            continue;
                        } else {
                            return Err(anyhow!(
                                "npm error code EINTEGRITY\nnpm error Integrity verification failed for {pkg_key}: {e}"
                            ));
                        }
                    }
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
                            let _ = self.cache.put_with_integrity(_resolved_url, &fresh_bytes, Some(&expected_integrity), None);
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
                if !was_hit {
                    let _ = self.cache.put_with_integrity(_resolved_url, &bytes, Some(&expected_integrity), None);
                }
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
                timeout: None,
                sandbox_policy: Default::default(),
            };
            execute_topological(&lifecycle_nodes, &manifest, &lifecycle_opts).await?;
        }

        // Persist hidden lockfile to node_modules/.package-lock.json
        lockfile.save_hidden(&self.options.project_dir)
            .context("Failed to save hidden package-lock.json")?;

        Ok(InstallSummary {
            packages_installed,
            cache_hits,
            cache_misses,
            lockfile_path,
        })
    }

    async fn populate_custom_target_metadata(
        &self,
        manifest: &Manifest,
        cache: &Arc<std::sync::Mutex<HashMap<String, PackageMetadata>>>,
    ) -> Result<()> {
        let mut all_deps = Vec::new();
        for (name, spec) in &manifest.dependencies {
            all_deps.push((name, spec));
        }
        for (name, spec) in &manifest.dev_dependencies {
            all_deps.push((name, spec));
        }
        for (name, spec) in &manifest.optional_dependencies {
            all_deps.push((name, spec));
        }
        for (name, spec) in &manifest.peer_dependencies {
            all_deps.push((name, spec));
        }

        for (name, spec) in all_deps {
            if let Ok(locked) = cache.lock() {
                if locked.contains_key(name) {
                    continue;
                }
            }

            let parsed = match PackageTarget::parse(spec) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let git_target_opt = match &parsed {
                PackageTarget::Git { .. } => Some(parsed.clone()),
                PackageTarget::Alias { target, .. } if target.is_git() => Some((**target).clone()),
                _ => None,
            };

            if let Some(git_target) = git_target_opt {
                let git_fetcher = crate::git::GitFetcher::new(self.cache.root());
                let resolved = git_fetcher
                    .resolve_git_dependency(&git_target, self.options.offline)
                    .await?;

                let m = resolved.manifest;
                let version = m.version.clone().unwrap_or_else(|| "1.0.0".to_string());

                let bin = m.bin.as_ref().map(|b| match b {
                    rnpm_core::manifest::PackageBin::Single(s) => rnpm_lockfile::PackageBin::Single(s.clone()),
                    rnpm_core::manifest::PackageBin::Map(map) => rnpm_lockfile::PackageBin::Map(map.clone()),
                });

                let ver_meta = PackageVersionMetadata {
                    name: name.clone(),
                    version: version.clone(),
                    dist_tarball: Some(resolved.resolved_url.clone()),
                    dist_integrity: None,
                    dependencies: m.dependencies.clone(),
                    dev_dependencies: m.dev_dependencies.clone(),
                    peer_dependencies: m.peer_dependencies.clone(),
                    peer_dependencies_meta: m.peer_dependencies_meta.clone(),
                    optional_dependencies: m.optional_dependencies.clone(),
                    os: m.os.clone(),
                    cpu: m.cpu.clone(),
                    libc: m.libc.clone(),
                    bin,
                    has_install_script: m.scripts.contains_key("install")
                        || m.scripts.contains_key("postinstall")
                        || m.scripts.contains_key("preinstall"),
                    deprecated: None,
                };

                let mut dist_tags = BTreeMap::new();
                dist_tags.insert("latest".to_string(), version.clone());
                let mut versions = BTreeMap::new();
                versions.insert(version.clone(), ver_meta);

                if let Ok(mut locked) = cache.lock() {
                    locked.insert(name.clone(), PackageMetadata {
                        name: name.clone(),
                        dist_tags: dist_tags.clone(),
                        versions: versions.clone(),
                    });
                }

                Box::pin(self.populate_custom_target_metadata(&m, cache)).await?;
                continue;
            }

            match parsed {
                PackageTarget::File(ref rel_path) => {
                    let file_spec_clean = spec.strip_prefix("file:").unwrap_or(spec).trim();
                    let abs_path = if rel_path.is_absolute() {
                        rel_path.clone()
                    } else {
                        self.options.project_dir.join(rel_path)
                    };

                    let is_archive = file_spec_clean.ends_with(".tgz")
                        || file_spec_clean.ends_with(".tar.gz")
                        || file_spec_clean.ends_with(".tar")
                        || (abs_path.exists() && abs_path.is_file());

                    if is_archive && abs_path.exists() {
                        if let Ok(archive_bytes) = std::fs::read(&abs_path) {
                            let integrity = Integrity::from_bytes(
                                &archive_bytes,
                                rnpm_core::integrity::Algorithm::Sha512,
                            ).to_string();

                            let m = inspect_manifest_from_tarball(&archive_bytes).unwrap_or_default();
                            let version = m.version.clone().unwrap_or_else(|| "1.0.0".to_string());
                            let posix_rel = rnpm_core::to_posix_path(file_spec_clean);
                            let resolved_url = format!("file:{posix_rel}");

                            let bin = m.bin.as_ref().map(|b| match b {
                                rnpm_core::manifest::PackageBin::Single(s) => rnpm_lockfile::PackageBin::Single(s.clone()),
                                rnpm_core::manifest::PackageBin::Map(map) => rnpm_lockfile::PackageBin::Map(map.clone()),
                            });

                            let ver_meta = PackageVersionMetadata {
                                name: name.clone(),
                                version: version.clone(),
                                dist_tarball: Some(resolved_url),
                                dist_integrity: Some(integrity),
                                dependencies: m.dependencies.clone(),
                                dev_dependencies: m.dev_dependencies.clone(),
                                peer_dependencies: m.peer_dependencies.clone(),
                                peer_dependencies_meta: m.peer_dependencies_meta.clone(),
                                optional_dependencies: m.optional_dependencies.clone(),
                                os: m.os.clone(),
                                cpu: m.cpu.clone(),
                                libc: m.libc.clone(),
                                bin,
                                has_install_script: m.scripts.contains_key("install")
                                    || m.scripts.contains_key("postinstall")
                                    || m.scripts.contains_key("preinstall"),
                                deprecated: None,
                            };

                            let mut dist_tags = BTreeMap::new();
                            dist_tags.insert("latest".to_string(), version.clone());
                            let mut versions = BTreeMap::new();
                            versions.insert(version, ver_meta);

                            if let Ok(mut locked) = cache.lock() {
                                locked.insert(name.clone(), PackageMetadata {
                                    name: name.clone(),
                                    dist_tags,
                                    versions,
                                });
                            }

                            Box::pin(self.populate_custom_target_metadata(&m, cache)).await?;
                        }
                    } else if abs_path.exists() && abs_path.is_dir() {
                        let manifest_path = abs_path.join("package.json");
                        let m = if manifest_path.exists() {
                            Manifest::from_file(&manifest_path).unwrap_or_default()
                        } else {
                            Manifest::default()
                        };

                        let version = m.version.clone().unwrap_or_else(|| "1.0.0".to_string());
                        let posix_rel = rnpm_core::to_posix_path(file_spec_clean);
                        let resolved_url = format!("file:{posix_rel}");

                        let bin = m.bin.as_ref().map(|b| match b {
                            rnpm_core::manifest::PackageBin::Single(s) => rnpm_lockfile::PackageBin::Single(s.clone()),
                            rnpm_core::manifest::PackageBin::Map(map) => rnpm_lockfile::PackageBin::Map(map.clone()),
                        });

                        let ver_meta = PackageVersionMetadata {
                            name: name.clone(),
                            version: version.clone(),
                            dist_tarball: Some(resolved_url),
                            dist_integrity: None,
                            dependencies: m.dependencies.clone(),
                            dev_dependencies: m.dev_dependencies.clone(),
                            peer_dependencies: m.peer_dependencies.clone(),
                            peer_dependencies_meta: m.peer_dependencies_meta.clone(),
                            optional_dependencies: m.optional_dependencies.clone(),
                            os: m.os.clone(),
                            cpu: m.cpu.clone(),
                            libc: m.libc.clone(),
                            bin,
                            has_install_script: m.scripts.contains_key("install")
                                || m.scripts.contains_key("postinstall")
                                || m.scripts.contains_key("preinstall"),
                            deprecated: None,
                        };

                        let mut dist_tags = BTreeMap::new();
                        dist_tags.insert("latest".to_string(), version.clone());
                        let mut versions = BTreeMap::new();
                        versions.insert(version, ver_meta);

                        if let Ok(mut locked) = cache.lock() {
                            locked.insert(name.clone(), PackageMetadata {
                                name: name.clone(),
                                dist_tags,
                                versions,
                            });
                        }

                        Box::pin(self.populate_custom_target_metadata(&m, cache)).await?;
                    }
                }
                PackageTarget::Url(ref url) => {
                    let version = "1.0.0".to_string();
                    let ver_meta = PackageVersionMetadata {
                        name: name.clone(),
                        version: version.clone(),
                        dist_tarball: Some(url.to_string()),
                        dist_integrity: None,
                        dependencies: BTreeMap::new(),
                        dev_dependencies: BTreeMap::new(),
                        peer_dependencies: BTreeMap::new(),
                        peer_dependencies_meta: BTreeMap::new(),
                        optional_dependencies: BTreeMap::new(),
                        os: None,
                        cpu: None,
                        libc: None,
                        bin: None,
                        has_install_script: false,
                        deprecated: None,
                    };
                    let mut dist_tags = BTreeMap::new();
                    dist_tags.insert("latest".to_string(), version.clone());
                    let mut versions = BTreeMap::new();
                    versions.insert(version, ver_meta);

                    if let Ok(mut locked) = cache.lock() {
                        locked.insert(name.clone(), PackageMetadata {
                            name: name.clone(),
                            dist_tags,
                            versions,
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn resolve_package(
        &mut self,
        name: &str,
        range_str: &str,
        is_optional: bool,
    ) -> Result<ResolvedNode> {
        let parsed_target = PackageTarget::parse(range_str)?;
        match parsed_target {
            PackageTarget::File(ref rel_path) => {
                let file_spec_clean = range_str.strip_prefix("file:").unwrap_or(range_str).trim();
                let abs_path = if rel_path.is_absolute() {
                    rel_path.clone()
                } else {
                    self.options.project_dir.join(rel_path)
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
            PackageTarget::Url(ref url) => {
                return Ok(ResolvedNode {
                    name: name.to_string(),
                    version: "1.0.0".to_string(),
                    resolved_url: url.to_string(),
                    integrity: String::new(),
                    dependencies: BTreeMap::new(),
                    optional_dependencies: BTreeMap::new(),
                    optional: is_optional,
                    skipped: false,
                    os: Vec::new(),
                    cpu: Vec::new(),
                    libc: Vec::new(),
                    is_file_dir: false,
                    is_file_archive: false,
                    local_path: None,
                });
            }
            PackageTarget::Git { ref committish, .. } => {
                let ver = committish.clone().unwrap_or_else(|| "1.0.0".to_string());
                return Ok(ResolvedNode {
                    name: name.to_string(),
                    version: ver,
                    resolved_url: range_str.to_string(),
                    integrity: String::new(),
                    dependencies: BTreeMap::new(),
                    optional_dependencies: BTreeMap::new(),
                    optional: is_optional,
                    skipped: false,
                    os: Vec::new(),
                    cpu: Vec::new(),
                    libc: Vec::new(),
                    is_file_dir: false,
                    is_file_archive: false,
                    local_path: None,
                });
            }
            _ => {}
        }

        let (lookup_name, target_to_match) = match parsed_target {
            PackageTarget::Alias { ref name, ref target } => (name.as_str(), target.as_ref()),
            ref other => (name, other),
        };

        let metadata = if let Some(cached) = self.metadata_cache.get(lookup_name) {
            cached.clone()
        } else {
            let meta = self.registry_client.get_package_metadata(lookup_name).await
                .map_err(|e| anyhow!("Failed to fetch metadata for {lookup_name}: {e}"))?;
            self.metadata_cache.insert(lookup_name.to_string(), meta.clone());
            meta
        };

        let best_ver_str = match target_to_match {
            PackageTarget::Tag(tag) => {
                metadata.dist_tags.get(tag).cloned().ok_or_else(|| {
                    anyhow!("No matching dist-tag '{tag}' found for {lookup_name}")
                })?
            }
            PackageTarget::Version(v) => {
                let v_str = v.to_string();
                if metadata.versions.contains_key(&v_str) {
                    v_str
                } else {
                    return Err(anyhow!("Exact version {v_str} not found for {lookup_name}"));
                }
            }
            PackageTarget::Range(range) => {
                let mut matching: Vec<(Version, String)> = Vec::new();
                for (ver_str, _) in &metadata.versions {
                    if let Ok(ver) = ver_str.parse::<Version>() {
                        if range.satisfies(&ver) {
                            matching.push((ver, ver_str.clone()));
                        }
                    }
                }
                if matching.is_empty() {
                    return Err(anyhow!("No matching version found for {}@{}", lookup_name, range));
                }
                matching.sort_by(|a, b| a.0.cmp(&b.0));
                matching.last().unwrap().1.clone()
            }
            _ => {
                if let Some(latest) = metadata.dist_tags.get("latest") {
                    latest.clone()
                } else if let Some(last) = metadata.versions.keys().last() {
                    last.clone()
                } else {
                    return Err(anyhow!("No versions found for {lookup_name}"));
                }
            }
        };

        let ver_info = metadata.versions.get(&best_ver_str)
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
        if !compatible {
            if !is_optional {
                return Err(anyhow!(
                    "rnpm ERR! code EBADPLATFORM: Unsupported platform for {}@{}: wanted os: {:?}, cpu: {:?}, libc: {:?}",
                    name, best_ver_str, ver_info.os, ver_info.cpu, ver_info.libc
                ));
            }
        }
        let skipped = is_optional && !compatible;

        Ok(ResolvedNode {
            name: name.to_string(),
            version: best_ver_str,
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
    /// Does NOT write unverified tarballs into the cache. Cache writing must be performed
    /// by callers only after SSRI integrity verification.
    pub async fn fetch_tarballs_concurrent(
        &self,
        urls: &[&str],
    ) -> Vec<Result<(Vec<u8>, bool)>> {
        let mut join_set = tokio::task::JoinSet::new();
        let offline = self.options.offline;

        for (idx, url) in urls.iter().enumerate() {
            let cache = self.cache.clone();
            let registry_client = self.registry_client.clone();
            let url_str = url.to_string();

            join_set.spawn(async move {
                if let Ok(Some((_entry, data))) = cache.get(&url_str) {
                    debug!("Cache hit for {}", url_str);
                    return (idx, Ok((data, true)));
                }

                if offline {
                    return (
                        idx,
                        Err(anyhow!(
                            "npm error code ENOTCACHED\nnpm error request to download tarball from '{url_str}' failed: cache mode is 'only-if-cached' (--offline) but no cached response is available."
                        )),
                    );
                }

                info!("Downloading {}", url_str);
                match registry_client.download_tarball_bytes(&url_str).await {
                    Ok(bytes) => {
                        // Do not pollute cache with unverified bytes!
                        // Caching must be performed after integrity verification by the caller.
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

        // Do not pollute the cache with unverified bytes!

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

        if !was_hit {
            let _ = self.cache.put_with_integrity(&node.resolved_url, bytes, Some(&expected_integrity), None);
        }

        // Path containment defense: ensure node.name has no traversal, device names, or escapes
        if node.name.contains("..") || node.name.contains(':') || node.name.contains('\\') || node.name.contains('\0') {
            return Err(anyhow!("Package name '{}' contains illegal path characters", node.name));
        }
        rnpm_fs::validate_entry_path(Path::new(&node.name))
            .map_err(|e| anyhow!("Invalid package name '{}': {e}", node.name))?;

        let dest_dir = node_modules_dir.join(&node.name);
        let cleaned_dest = path_clean::clean(&dest_dir);
        if !cleaned_dest.starts_with(node_modules_dir) {
            return Err(anyhow!("Package installation path '{cleaned_dest:?}' escapes node_modules"));
        }
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
                    sandbox_policy: Default::default(),
                };
                let _ = execute_topological(&lifecycle_nodes, &manifest, &lifecycle_opts).await;
            }
        }

        // 6. Rewrite package-lock.json deterministically
        lockfile.save_to_file(&lockfile_path)
            .context("Failed to save package-lock.json")?;

        // 7. Persist hidden lockfile to node_modules/.package-lock.json
        lockfile.save_hidden(&self.options.project_dir)
            .context("Failed to save hidden package-lock.json")?;

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

            // Persist hidden lockfile to node_modules/.package-lock.json
            let _ = lockfile.save_hidden(&self.options.project_dir);
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
    /// Prunes extraneous dependencies from node_modules based on reachability from package.json.
    pub fn prune(&self, options: &PruneOptions) -> Result<PruneSummary> {
        let mut opts = options.clone();
        opts.project_dir = self.options.project_dir.clone();
        let analysis = prune::discover_extraneous_packages(&self.options.project_dir, &opts)?;
        prune::execute_prune(&self.options.project_dir, &analysis.extraneous_packages)
    }

    /// Discovers extraneous dependencies in node_modules without modifying the filesystem.
    pub fn analyze_prune(&self, options: &PruneOptions) -> Result<PruneAnalysis> {
        let mut opts = options.clone();
        opts.project_dir = self.options.project_dir.clone();
        prune::discover_extraneous_packages(&self.options.project_dir, &opts)
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
