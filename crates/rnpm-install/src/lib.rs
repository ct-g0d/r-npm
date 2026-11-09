#![allow(clippy::field_reassign_with_default)]

use anyhow::{anyhow, Context, Result};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use url::Url;

use rnpm_cache::{Cache, CacheError, PackStore};
use rnpm_config::Config;
use rnpm_core::integrity::Integrity;
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_core::spec::{PackageSpec, PackageTarget};
use rnpm_core::workspace::{discover_workspaces_from_manifest, WorkspaceMember};
use rnpm_fs::junction::{is_junction, remove_junction};
use rnpm_fs::{determine_writer_config, extract_tarball_direct, precreate_directories};
use rnpm_lifecycle::{execute_topological, LifecycleOptions, LifecyclePackageNode, PackageSource};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use rnpm_registry::client::{RegistryClient, RegistryClientConfig, NPM_INSTALL_V1_JSON};
use rnpm_registry::metadata::AbbreviatedPackageMetadata;
use rnpm_shim::{create_shims, normalize_shebang};
use rnpm_solver::graph::DependencyGraph;
use std::sync::Arc;
pub mod git;
pub use git::GitFetcher;

pub mod link;
pub use link::*;

pub mod prune;
pub use prune::{
    analyze_reachability, discover_extraneous_packages, execute_prune,
    extract_package_name_from_path, scan_node_modules, ExtraneousPackage, PruneAnalysis,
    PruneOptions, PruneSummary,
};

pub mod rebuild;
pub use rebuild::{execute_rebuild, matches_rebuild_filter, RebuildOptions, RebuildSummary};

pub mod dedupe;
pub use dedupe::{
    execute_dedupe, version_matches_range, DedupeAction, DedupeActionType, DedupeOptions,
    DedupeSummary,
};

pub mod fast_path;
pub use fast_path::{
    compute_project_fingerprint, validate_hidden_lockfile, validate_hidden_lockfile_simple,
};

pub mod timing;
pub use timing::{Phase, PhaseGuard, TimingCollector, TimingMetrics, TimingPhase};

pub mod diff;
pub use diff::*;

pub mod trash;
pub use trash::*;

pub mod linked;
pub use linked::*;

/// Resolves the committed lockfile path for a project directory, giving `npm-shrinkwrap.json` precedence over `package-lock.json`.
/// Returns `(lockfile_path, is_shrinkwrap)`.
pub fn resolve_lockfile_path(project_dir: &Path) -> (PathBuf, bool) {
    let shrinkwrap = project_dir.join("npm-shrinkwrap.json");
    if shrinkwrap.exists() {
        (shrinkwrap, true)
    } else {
        (project_dir.join("package-lock.json"), false)
    }
}

/// Returns the lockfile path to read or write, giving `npm-shrinkwrap.json` precedence if it exists.
pub fn project_lockfile_path(project_dir: &Path) -> PathBuf {
    resolve_lockfile_path(project_dir).0
}

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
        // npm serializes an overlapping optional dependency only under
        // `optionalDependencies`; the optional declaration supersedes the
        // same key in `dependencies`.
        for k in opt_deps.keys() {
            deps.remove(k);
        }

        let bin = ver_info.bin.as_ref().map(|b| match b {
            rnpm_registry::metadata::PackageBin::Single(s) => {
                rnpm_lockfile::PackageBin::Single(s.clone())
            }
            rnpm_registry::metadata::PackageBin::Map(m) => {
                rnpm_lockfile::PackageBin::Map(m.clone())
            }
        });

        versions.insert(
            ver_str.clone(),
            PackageVersionMetadata {
                name: ver_info.name.clone(),
                version: ver_info.version.clone(),
                dist_tarball: Some(ver_info.dist.tarball.clone()),
                dist_integrity: ver_info.dist.integrity.clone(),
                dependencies: deps,
                dependency_order: ver_info.dependencies.keys().cloned().collect(),
                dev_dependencies: dev_deps,
                peer_dependencies: peer_deps,
                peer_dependencies_meta: peer_meta,
                optional_dependencies: opt_deps,
                os: if ver_info.os.is_empty() {
                    None
                } else {
                    Some(ver_info.os.clone())
                },
                cpu: if ver_info.cpu.is_empty() {
                    None
                } else {
                    Some(ver_info.cpu.clone())
                },
                libc: if ver_info.libc.is_empty() {
                    None
                } else {
                    Some(ver_info.libc.clone())
                },
                bin,
                license: ver_info.license.clone(),
                engines: ver_info
                    .engines
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                has_install_script: ver_info.has_install_script,
                deprecated: ver_info.deprecated.clone(),
                extra: ver_info.extra.clone(),
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
    lockfile: Option<Arc<LockfileV3>>,
}

fn package_metadata_from_lockfile(name: &str, lf: &LockfileV3) -> Option<PackageMetadata> {
    let mut versions = BTreeMap::new();
    let mut top_ver = None;

    let target_top = format!("node_modules/{name}");
    let target_suffix = format!("/node_modules/{name}");

    for (k, pkg) in &lf.packages {
        if k == &target_top || k.ends_with(&target_suffix) {
            let Some(ref ver_str) = pkg.version else { continue };
            if k == &target_top {
                top_ver = Some(ver_str.clone());
            }
            if versions.contains_key(ver_str) {
                continue;
            }
            let bin = pkg.bin.clone();
            let ver_meta = PackageVersionMetadata {
                name: name.to_string(),
                version: ver_str.clone(),
                dist_tarball: pkg.resolved.clone(),
                dist_integrity: pkg.integrity.clone(),
                dependencies: pkg.dependencies.clone().unwrap_or_default(),
                dependency_order: pkg
                    .dependencies
                    .as_ref()
                    .map(|d| d.keys().cloned().collect())
                    .unwrap_or_default(),
                dev_dependencies: pkg.dev_dependencies.clone().unwrap_or_default(),
                peer_dependencies: pkg.peer_dependencies.clone().unwrap_or_default(),
                peer_dependencies_meta: BTreeMap::new(),
                optional_dependencies: pkg.optional_dependencies.clone().unwrap_or_default(),
                os: pkg.os.clone(),
                cpu: pkg.cpu.clone(),
                libc: pkg.libc.clone(),
                bin,
                license: None,
                engines: match &pkg.engines {
                    Some(rnpm_lockfile::PackageEngines::Map(m)) => m.clone(),
                    _ => BTreeMap::new(),
                },
                has_install_script: pkg.has_install_script == Some(true),
                deprecated: None,
                extra: BTreeMap::new(),
            };
            versions.insert(ver_str.clone(), ver_meta);
        }
    }

    if versions.is_empty() {
        return None;
    }

    let latest_ver = top_ver.or_else(|| versions.keys().last().cloned()).unwrap();
    let mut dist_tags = BTreeMap::new();
    dist_tags.insert("latest".to_string(), latest_ver);
    Some(PackageMetadata {
        name: name.to_string(),
        dist_tags,
        versions,
    })
}

fn package_metadata_from_manifest(m: &Manifest) -> Option<PackageMetadata> {
    let name = m.name.clone()?;
    let ver_str = m.version.clone().unwrap_or_else(|| "1.0.0".to_string());
    let bin = m.bin.as_ref().map(|b| match b {
        rnpm_core::manifest::PackageBin::Single(s) => {
            rnpm_lockfile::PackageBin::Single(s.clone())
        }
        rnpm_core::manifest::PackageBin::Map(map) => {
            rnpm_lockfile::PackageBin::Map(map.clone())
        }
    });
    let ver_meta = PackageVersionMetadata {
        name: name.clone(),
        version: ver_str.clone(),
        dist_tarball: None,
        dist_integrity: None,
        dependencies: m.dependencies.clone(),
        dependency_order: m.dependencies.keys().cloned().collect(),
        dev_dependencies: m.dev_dependencies.clone(),
        peer_dependencies: m.peer_dependencies.clone(),
        peer_dependencies_meta: m.peer_dependencies_meta.clone(),
        optional_dependencies: m.optional_dependencies.clone(),
        os: m.os.clone(),
        cpu: m.cpu.clone(),
        libc: m.libc.clone(),
        bin,
        license: m.extra.get("license").and_then(|v| v.as_str()).map(str::to_owned),
        engines: m.engines.clone(),
        has_install_script: m.scripts.contains_key("install")
            || m.scripts.contains_key("postinstall")
            || m.scripts.contains_key("preinstall"),
        deprecated: None,
        extra: m.extra.clone(),
    };
    let mut dist_tags = BTreeMap::new();
    dist_tags.insert("latest".to_string(), ver_str.clone());
    let mut versions = BTreeMap::new();
    versions.insert(ver_str, ver_meta);
    Some(PackageMetadata {
        name,
        dist_tags,
        versions,
    })
}

/// Scans the global `node_modules` directory for installed top-level packages (including `@scope/*`),
/// returning a map of package name to version constraint (e.g. `^version`).
pub(crate) fn scan_global_packages(global_nm: &Path) -> HashMap<String, String> {
    let mut installed = HashMap::new();
    if !global_nm.is_dir() {
        return installed;
    }
    let Ok(entries) = std::fs::read_dir(global_nm) else {
        return installed;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if name.starts_with('@') && path.is_dir() {
            if let Ok(scoped_entries) = std::fs::read_dir(&path) {
                for scoped_entry in scoped_entries.flatten() {
                    let sub_name = scoped_entry.file_name().to_string_lossy().to_string();
                    if sub_name.starts_with('.') {
                        continue;
                    }
                    let pkg_dir = scoped_entry.path();
                    let pkg_json = pkg_dir.join("package.json");
                    if pkg_json.is_file() {
                        if let Ok(pkg_m) = Manifest::from_file(&pkg_json) {
                            let pkg_name = pkg_m.name.unwrap_or_else(|| format!("{name}/{sub_name}"));
                            let version = pkg_m.version.unwrap_or_else(|| "1.0.0".to_string());
                            installed.insert(pkg_name, format!("^{version}"));
                        }
                    }
                }
            }
        } else if path.is_dir() || rnpm_fs::is_junction(&path).unwrap_or(false) {
            let pkg_json = path.join("package.json");
            if pkg_json.is_file() {
                if let Ok(pkg_m) = Manifest::from_file(&pkg_json) {
                    let pkg_name = pkg_m.name.unwrap_or(name);
                    let version = pkg_m.version.unwrap_or_else(|| "1.0.0".to_string());
                    installed.insert(pkg_name, format!("^{version}"));
                }
            }
        }
    }
    installed
}

fn populate_global_disk_metadata(
    global_nm: &Path,
    metadata_cache: &Arc<std::sync::Mutex<HashMap<String, PackageMetadata>>>,
) {
    if !global_nm.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(global_nm) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if name.starts_with('@') && path.is_dir() {
            if let Ok(scoped_entries) = std::fs::read_dir(&path) {
                for scoped_entry in scoped_entries.flatten() {
                    let sub_name = scoped_entry.file_name().to_string_lossy().to_string();
                    if sub_name.starts_with('.') {
                        continue;
                    }
                    let pkg_dir = scoped_entry.path();
                    let pkg_json = pkg_dir.join("package.json");
                    if pkg_json.is_file() {
                        if let Ok(pkg_m) = Manifest::from_file(&pkg_json) {
                            if let Some(meta) = package_metadata_from_manifest(&pkg_m) {
                                if let Ok(mut cache) = metadata_cache.lock() {
                                    cache.entry(meta.name.clone()).or_insert(meta);
                                }
                            }
                        }
                    }
                }
            }
        } else if path.is_dir() || rnpm_fs::is_junction(&path).unwrap_or(false) {
            let pkg_json = path.join("package.json");
            if pkg_json.is_file() {
                if let Ok(pkg_m) = Manifest::from_file(&pkg_json) {
                    if let Some(meta) = package_metadata_from_manifest(&pkg_m) {
                        if let Ok(mut cache) = metadata_cache.lock() {
                            cache.entry(meta.name.clone()).or_insert(meta);
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn isolate_global_dependencies(graph: &mut DependencyGraph, manifest: &Manifest) {
    let top_level_packages: HashSet<String> = manifest
        .dependencies
        .keys()
        .chain(manifest.dev_dependencies.keys())
        .chain(manifest.optional_dependencies.keys())
        .chain(manifest.peer_dependencies.keys())
        .cloned()
        .collect();

    let mut new_nodes = BTreeMap::new();
    let mut new_edges = Vec::new();

    // Preserve root node if present
    if let Some(root_node) = graph.nodes.get("") {
        new_nodes.insert(String::new(), root_node.clone());
    }

    for top_pkg in &top_level_packages {
        let top_loc = format!("node_modules/{top_pkg}");
        let top_node = if let Some(n) = graph.nodes.get(&top_loc) {
            n.clone()
        } else if let Some((_, n)) = graph.nodes.iter().find(|(l, n)| {
            !l.is_empty()
                && !l.strip_prefix("node_modules/").unwrap_or("").contains("/node_modules/")
                && (&n.install_name == top_pkg || &n.name == top_pkg)
        }) {
            n.clone()
        } else {
            continue;
        };

        new_nodes.insert(top_loc.clone(), top_node);

        // Retain direct edges from root to top_pkg
        for edge in &graph.edges {
            if edge.from_location.is_empty() && edge.to_location == top_loc {
                new_edges.push(edge.clone());
            }
        }

        // BFS traversal to discover all transitive dependencies reachable from top_loc
        let mut loc_map: HashMap<String, String> = HashMap::new();
        loc_map.insert(top_loc.clone(), top_loc.clone());

        let mut queue = VecDeque::new();
        queue.push_back(top_loc.clone());

        while let Some(curr_orig_loc) = queue.pop_front() {
            for edge in graph.get_outgoing_edges(&curr_orig_loc) {
                let target_orig_loc = &edge.to_location;
                if target_orig_loc.is_empty() || target_orig_loc == &top_loc {
                    continue;
                }
                if !loc_map.contains_key(target_orig_loc) {
                    if let Some(target_node) = graph.nodes.get(target_orig_loc) {
                        // Compute new nested location under top_loc:
                        // node_modules/<dep> -> node_modules/<top-pkg>/node_modules/<dep>
                        let rel = target_orig_loc
                            .strip_prefix("node_modules/")
                            .unwrap_or(target_orig_loc);
                        let target_new_loc = format!("{top_loc}/node_modules/{rel}");
                        loc_map.insert(target_orig_loc.clone(), target_new_loc.clone());

                        let mut new_node = target_node.clone();
                        new_node.location = target_new_loc.clone();
                        new_nodes.insert(target_new_loc, new_node);

                        queue.push_back(target_orig_loc.clone());
                    }
                }
            }
        }

        // Map and retain edges within this top_pkg's component
        for edge in &graph.edges {
            if edge.from_location.is_empty() {
                continue;
            }
            if let (Some(from_new), Some(to_new)) =
                (loc_map.get(&edge.from_location), loc_map.get(&edge.to_location))
            {
                let mut new_edge = edge.clone();
                new_edge.from_location = from_new.clone();
                new_edge.to_location = to_new.clone();
                new_edges.push(new_edge);
            }
        }
    }

    graph.nodes = new_nodes;
    graph.edges = new_edges;
}

impl PackageMetadataProvider for RegistryPackageProvider {
    fn get_package(&self, name: &str) -> Result<Option<PackageMetadata>, SolverError> {
        if let Ok(cache) = self.metadata_cache.lock() {
            if let Some(meta) = cache.get(name) {
                return Ok(Some(meta.clone()));
            }
        }

        let registry_url = self.client.registry_for_package(name).as_str().to_string();

        let cached_data = self
            .cache
            .get_packument_with_accept(&registry_url, name, Some(NPM_INSTALL_V1_JSON))
            .ok()
            .flatten()
            .or_else(|| {
                self.cache
                    .get(&format!("pacote:packument:{name}"))
                    .ok()
                    .flatten()
            });

        if let Some((_entry, data)) = cached_data {
            if let Ok(abbrev) = serde_json::from_slice::<AbbreviatedPackageMetadata>(&data) {
                let mut meta = abbreviated_to_package_metadata(&abbrev);
                if let Some(ref lf) = self.lockfile {
                    if let Some(lf_meta) = package_metadata_from_lockfile(name, lf) {
                        for (v, vm) in lf_meta.versions {
                            meta.versions.entry(v).or_insert(vm);
                        }
                    }
                }
                if let Ok(mut cache) = self.metadata_cache.lock() {
                    cache.insert(name.to_string(), meta.clone());
                }
                return Ok(Some(meta));
            }
        }

        if name.starts_with("git+")
            || name.starts_with("git:")
            || PackageTarget::parse(name)
                .map(|t| t.is_git())
                .unwrap_or(false)
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
                            rnpm_core::manifest::PackageBin::Single(s) => {
                                rnpm_lockfile::PackageBin::Single(s.clone())
                            }
                            rnpm_core::manifest::PackageBin::Map(map) => {
                                rnpm_lockfile::PackageBin::Map(map.clone())
                            }
                        });

                        let ver_meta = PackageVersionMetadata {
                            name: name.to_string(),
                            version: version.clone(),
                            dist_tarball: Some(resolved.resolved_url.clone()),
                            dist_integrity: None,
                            dependencies: m.dependencies.clone(),
                            dependency_order: m.dependencies.keys().cloned().collect(),
                            dev_dependencies: m.dev_dependencies.clone(),
                            peer_dependencies: m.peer_dependencies.clone(),
                            peer_dependencies_meta: m.peer_dependencies_meta.clone(),
                            optional_dependencies: m.optional_dependencies.clone(),
                            os: m.os.clone(),
                            cpu: m.cpu.clone(),
                            libc: m.libc.clone(),
                            bin,
                            license: m
                                .extra
                                .get("license")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned),
                            engines: m.engines.clone(),
                            has_install_script: m.scripts.contains_key("install")
                                || m.scripts.contains_key("postinstall")
                                || m.scripts.contains_key("preinstall"),
                            deprecated: None,
                            extra: m.extra.clone(),
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
                        return Err(SolverError::PackageMetadata(
                            name.to_string(),
                            e.to_string(),
                        ));
                    }
                }
            }
        }

        if self.offline {
            if let Some(ref lf) = self.lockfile {
                if let Some(meta) = package_metadata_from_lockfile(name, lf) {
                    if let Ok(mut cache) = self.metadata_cache.lock() {
                        cache.insert(name.to_string(), meta.clone());
                    }
                    return Ok(Some(meta));
                }
            }
            return Err(SolverError::PackageMetadata(
                name.to_string(),
                format!(
                    "npm error code ENOTCACHED\nnpm error request to fetch metadata for '{name}' failed: cache mode is 'only-if-cached' (--offline) but no cached response is available."
                ),
            ));
        }

        let client = self.client.clone();
        let pkg_name = name.to_string();
        let res = self
            .handle
            .block_on(async move { client.get_package_metadata(&pkg_name).await });
        match res {
            Ok(abbrev) => {
                // Persist the abbreviated packument under the registry-scoped key
                // so a later invocation can resolve from disk without repeating
                // metadata requests and metadata from different registries is completely isolated.
                if let Ok(bytes) = serde_json::to_vec(&abbrev) {
                    let _ = self.cache.put_packument_with_accept(
                        &registry_url,
                        name,
                        Some(NPM_INSTALL_V1_JSON),
                        &bytes,
                        None,
                    );
                }
                let mut meta = abbreviated_to_package_metadata(&abbrev);
                if let Some(ref lf) = self.lockfile {
                    if let Some(lf_meta) = package_metadata_from_lockfile(name, lf) {
                        for (v, vm) in lf_meta.versions {
                            meta.versions.entry(v).or_insert(vm);
                        }
                    }
                }
                if let Ok(mut cache) = self.metadata_cache.lock() {
                    cache.insert(name.to_string(), meta.clone());
                }
                Ok(Some(meta))
            }
            Err(e) => {
                if let Some(ref lf) = self.lockfile {
                    if let Some(meta) = package_metadata_from_lockfile(name, lf) {
                        if let Ok(mut cache) = self.metadata_cache.lock() {
                            cache.insert(name.to_string(), meta.clone());
                        }
                        return Ok(Some(meta));
                    }
                }
                if e.is_not_found() {
                    Ok(None)
                } else {
                    Err(SolverError::PackageMetadata(
                        name.to_string(),
                        e.to_string(),
                    ))
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

    rnpm_fs::create_junction(&link_path, &member.path).map_err(|e| {
        anyhow!(
            "Failed to link workspace package '{}' at '{}' -> '{}': {e}",
            member.name,
            link_path.display(),
            member.path.display()
        )
    })?;

    Ok(())
}

fn lifecycle_node_for_manifest(
    target_path: &Path,
    pkg_key: &str,
    resolved_url: &str,
    declared_dependencies: &[String],
    is_optional: bool,
    pkg_manifest: Manifest,
) -> Option<LifecyclePackageNode> {
    let is_file_archive = resolved_url.starts_with("file:");
    let source = if is_file_archive {
        PackageSource::LocalTarball
    } else {
        PackageSource::Registry
    };
    let has_scripts = pkg_manifest.scripts.contains_key("preinstall")
        || pkg_manifest.scripts.contains_key("install")
        || pkg_manifest.scripts.contains_key("postinstall")
        || (source.runs_prepare() && pkg_manifest.scripts.contains_key("prepare"));

    if has_scripts {
        let deps = if !declared_dependencies.is_empty() {
            declared_dependencies.to_vec()
        } else {
            pkg_manifest.dependencies.keys().cloned().collect()
        };
        Some(LifecyclePackageNode {
            package_path: pkg_key.to_string(),
            disk_path: target_path.to_path_buf(),
            manifest: pkg_manifest,
            source,
            dependencies: deps,
            optional: is_optional,
        })
    } else {
        None
    }
}

fn process_installed_pkg_manifest_without_bins(
    target_path: &Path,
    pkg_key: &str,
    resolved_url: &str,
    declared_dependencies: &[String],
    is_optional: bool,
) -> Option<LifecyclePackageNode> {
    let pkg_manifest = Manifest::from_file(target_path.join("package.json")).ok()?;
    lifecycle_node_for_manifest(
        target_path,
        pkg_key,
        resolved_url,
        declared_dependencies,
        is_optional,
        pkg_manifest,
    )
}

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub project_dir: PathBuf,
    pub registry_url: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub offline: bool,
    pub force: bool,
    pub ignore_scripts: bool,
    pub foreground_scripts: bool,
    pub strict_sandbox: bool,
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
    pub is_global: bool,
    pub include: Vec<String>,
    pub package_lock: bool,
    pub no_package_lock: bool,
    pub dry_run: bool,
    pub os: Option<String>,
    pub cpu: Option<String>,
    pub libc: Option<String>,
    pub audit: bool,
    pub fund: bool,
    pub workspace_root: bool,
    pub workspace: Vec<String>,
    pub workspaces: bool,
    /// Public package-lock serialization version (1, 2, or 3). Hidden lockfiles remain v3.
    pub lockfile_version: u32,
    /// High-resolution phase instrumentation and timing output.
    pub timing: bool,
    /// Installation layout strategy: hoisted (default), linked, or nested.
    pub install_strategy: InstallStrategy,
    /// Optional custom global store directory override.
    pub store_dir: Option<PathBuf>,
    /// Whether background trash deletions run detached without blocking command exit (default: true).
    pub detached_trash: bool,
    /// Whether to wait for all background trash deletions to complete before command exit (default: false).
    pub wait_for_trash: bool,
    /// Unlocked packages that must be re-resolved to newer versions rather than locked to lockfile.
    pub unlocked_packages: std::collections::HashSet<String>,
    /// Vulnerability constraints to avoid when selecting versions during audit fix.
    pub vulnerability_constraints: std::collections::HashMap<String, Vec<rnpm_core::semver::Range>>,
}

impl InstallOptions {
    /// Evaluates if package-lock reading and writing is enabled.
    pub fn package_lock_enabled(&self) -> bool {
        self.package_lock && !self.no_package_lock
    }

    /// Evaluates target platform using CLI overrides for os, cpu, and libc if provided.
    pub fn platform(&self) -> Platform {
        let mut p = Platform::current();
        if let Some(ref os) = self.os {
            p.os = os.clone();
        }
        if let Some(ref cpu) = self.cpu {
            p.cpu = cpu.clone();
        }
        if let Some(ref libc) = self.libc {
            p.libc = Some(libc.clone());
        }
        p
    }
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::from("."),
            registry_url: None,
            cache_dir: None,
            offline: false,
            force: false,
            ignore_scripts: false,
            foreground_scripts: false,
            strict_sandbox: false,
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
            is_global: false,
            include: Vec::new(),
            package_lock: true,
            no_package_lock: false,
            dry_run: false,
            os: None,
            cpu: None,
            libc: None,
            audit: true,
            fund: true,
            workspace_root: false,
            workspace: Vec::new(),
            workspaces: false,
            lockfile_version: 3,
            timing: false,
            install_strategy: InstallStrategy::Hoisted,
            store_dir: None,
            detached_trash: true,
            wait_for_trash: false,
            unlocked_packages: std::collections::HashSet::new(),
            vulnerability_constraints: std::collections::HashMap::new(),
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
    pub timing: Option<TimingMetrics>,
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
    pack_store: Arc<PackStore>,
    registry_client: RegistryClient,
    metadata_cache: HashMap<String, AbbreviatedPackageMetadata>,
    writer_cfg: Arc<rnpm_fs::ParallelWriterConfig>,
    io_semaphore: Arc<tokio::sync::Semaphore>,
}

impl Installer {
    pub fn new(options: InstallOptions) -> Result<Self> {
        let mut options = options;
        let root_dir = &options.project_dir;
        crate::trash::cleanup_leftover_trash(root_dir);
        if options.is_global && !root_dir.join("package.json").exists() {
            let _ = std::fs::create_dir_all(root_dir);
            let global_nm = rnpm_config::find_global_node_modules(root_dir);
            let _ = std::fs::create_dir_all(&global_nm);
            let global_bin = rnpm_config::find_global_bin_dir(root_dir);
            let _ = std::fs::create_dir_all(&global_bin);
        }
        let config = Config::load(Some(root_dir)).unwrap_or_default();

        if options.install_strategy == InstallStrategy::Hoisted {
            if let Some(strat_str) = config
                .get("install-strategy")
                .or_else(|| config.get("install_strategy"))
            {
                if let Ok(strat) = strat_str.parse::<InstallStrategy>() {
                    options.install_strategy = strat;
                }
            }
        }

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

        let pack_store_path = if let Some(ref s) = options.store_dir {
            s.clone()
        } else if let Ok(store_env) = std::env::var("RNPM_STORE_DIR") {
            if !store_env.trim().is_empty() {
                PathBuf::from(store_env)
            } else if let Some(ref c) = options.cache_dir {
                c.join("store-v1")
            } else if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
                PathBuf::from(appdata).join("rnpm").join("store-v1")
            } else {
                cache_path.join("store-v1")
            }
        } else if let Some(ref c) = options.cache_dir {
            c.join("store-v1")
        } else if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            PathBuf::from(appdata).join("rnpm").join("store-v1")
        } else {
            cache_path.join("store-v1")
        };

        let pack_store =
            Arc::new(PackStore::new(&pack_store_path).context("Failed to initialize pack store")?);

        let mut trusted_hosts = HashSet::new();
        if let Some(host) = registry_url.host_str() {
            trusted_hosts.insert(host.to_ascii_lowercase());
        }

        let mut client_config = RegistryClientConfig {
            default_registry: registry_url.clone(),
            auth_tokens: config.npmrc.auth_tokens.clone(),
            scoped_registries: config.npmrc.scoped_registries.clone(),
            ..Default::default()
        };
        if let Some(token) = config.npmrc.get_auth_token(&registry_url) {
            client_config.auth_token = Some(token.to_string());
        }

        for scoped_reg in config.npmrc.scoped_registries.values() {
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

        let writer_cfg = Arc::new(determine_writer_config(&options.project_dir, concurrency));
        let io_concurrency = 64;
        let io_semaphore = Arc::new(tokio::sync::Semaphore::new(io_concurrency));

        Ok(Self {
            options,
            cache,
            pack_store,
            registry_client,
            metadata_cache: HashMap::new(),
            writer_cfg,
            io_semaphore,
        })
    }

    /// Access the underlying PackStore.
    pub fn pack_store(&self) -> &PackStore {
        &self.pack_store
    }

    /// Access the underlying PackStore Arc.
    pub fn pack_store_arc(&self) -> Arc<PackStore> {
        Arc::clone(&self.pack_store)
    }

    /// Reconfigure maximum network worker concurrency (bounded semaphore).
    pub fn with_concurrency(mut self, concurrency: usize) -> Result<Self> {
        let mut cfg = self.registry_client.config().clone();
        cfg.max_concurrent_requests = concurrency;
        self.registry_client = RegistryClient::with_config(cfg)
            .context("Failed to reconfigure registry client with concurrency")?;
        self.writer_cfg = Arc::new(determine_writer_config(
            &self.options.project_dir,
            Some(concurrency),
        ));
        let io_concurrency = concurrency.clamp(32, 128);
        self.io_semaphore = Arc::new(tokio::sync::Semaphore::new(io_concurrency));
        Ok(self)
    }

    /// Access the shared ParallelWriterConfig.
    pub fn writer_config(&self) -> &rnpm_fs::ParallelWriterConfig {
        &self.writer_cfg
    }

    /// Access the shared ParallelWriterConfig Arc.
    pub fn writer_config_arc(&self) -> Arc<rnpm_fs::ParallelWriterConfig> {
        Arc::clone(&self.writer_cfg)
    }

    /// Access the shared I/O semaphore.
    pub fn io_semaphore(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.io_semaphore)
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
        let res = self.install_internal().await;
        if self.options.wait_for_trash || !self.options.detached_trash {
            crate::trash::wait_all_trash_deletions();
        }
        res
    }

    async fn install_internal(&mut self) -> Result<InstallSummary> {
        crate::trash::cleanup_leftover_trash(&self.options.project_dir);
        let collector = TimingCollector::new();
        let plan_start = std::time::Instant::now();
        let _plan_span = tracing::info_span!("plan").entered();

        let manifest_path = self.options.project_dir.join("package.json");
        if !manifest_path.exists() && !self.options.is_global {
            return Err(anyhow!(
                "package.json not found in {}",
                self.options.project_dir.display()
            ));
        }

        // Fast path check when nothing changed (Milestone M2, fixes Bug B7)
        if self.options.packages.is_empty()
            && !self.options.force
            && !self.options.dry_run
            && !self.options.package_lock_only
        {
            if let Ok(current_fingerprint) =
                compute_project_fingerprint(&self.options.project_dir, &self.options)
            {
                if let Ok(Some(stored_fingerprint)) = self
                    .cache
                    .get_project_fingerprint(&self.options.project_dir)
                {
                    if current_fingerprint == stored_fingerprint
                        && validate_hidden_lockfile(&self.options.project_dir, Some(&self.options))
                    {
                        info!("Fast path hit: inputs unchanged and hidden lockfile valid");
                        let lockfile_path = project_lockfile_path(&self.options.project_dir);
                        drop(_plan_span);
                        collector.record_phase(Phase::Plan, plan_start.elapsed());
                        return Ok(InstallSummary {
                            packages_installed: 0,
                            cache_hits: 0,
                            cache_misses: 0,
                            lockfile_path,
                            timing: Some(collector.finish()),
                        });
                    }
                }
            }
        }

        let mut manifest = if manifest_path.exists() && !self.options.is_global {
            Manifest::from_file(&manifest_path).context("Failed to parse project package.json")?
        } else if self.options.is_global {
            let mut m = if manifest_path.exists() {
                Manifest::from_file(&manifest_path).unwrap_or_else(|_| Manifest {
                    name: Some("global-packages".to_string()),
                    version: Some("1.0.0".to_string()),
                    ..Default::default()
                })
            } else {
                Manifest {
                    name: Some("global-packages".to_string()),
                    version: Some("1.0.0".to_string()),
                    ..Default::default()
                }
            };
            let global_nm = rnpm_config::find_global_node_modules(&self.options.project_dir);
            for (pkg_name, ver) in scan_global_packages(&global_nm) {
                m.dependencies.entry(pkg_name).or_insert(ver);
            }
            m
        } else {
            return Err(anyhow!(
                "package.json not found in {}",
                self.options.project_dir.display()
            ));
        };

        // Fast path: if package.json matches existing committed lockfile and no package args were passed,
        // take the exact same reification fast path as `ci` without re-resolving through network metadata or calling solver!
        if self.options.packages.is_empty()
            && self.options.unlocked_packages.is_empty()
            && self.options.vulnerability_constraints.is_empty()
            && !self.options.force
            && !self.options.package_lock_only
            && self.options.workspace.is_empty()
            && self.options.package_lock_enabled()
        {
            let (lockfile_path, _) = resolve_lockfile_path(&self.options.project_dir);
            if lockfile_path.exists() {
                if let Ok(lockfile_str) = std::fs::read_to_string(&lockfile_path) {
                    if let Ok(existing_lockfile) = rnpm_lockfile::parse_and_migrate(&lockfile_str) {
                        if existing_lockfile.matches_manifest(&manifest, !self.options.omit_dev) {
                            info!(
                                "Lockfile matches manifest: taking lockfile reification fast path"
                            );
                            match self.run_ci_internal().await {
                                Ok(summary) => return Ok(summary),
                                Err(err) => {
                                    let err_msg = err.to_string();
                                    if err_msg.contains("ELOCKFILE_DRIFT") {
                                        warn!("Lockfile drift detected during fast path; falling back to full solver: {err_msg}");
                                    } else {
                                        return Err(err);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

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

            if spec.name.contains("..")
                || spec.name.contains(':')
                || spec.name.contains('\\')
                || spec.name.contains('\0')
            {
                return Err(anyhow!(
                    "Package name '{}' contains illegal path characters",
                    spec.name
                ));
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
                PackageTarget::File(p) => {
                    format!("file:{}", rnpm_core::to_posix_path(&p.to_string_lossy()))
                }
                PackageTarget::Git { url, committish } => {
                    format!(
                        "{}{}",
                        url,
                        committish
                            .as_ref()
                            .map(|c| format!("#{c}"))
                            .unwrap_or_default()
                    )
                }
                PackageTarget::Workspace(ws) => format!("workspace:{}", ws),
                PackageTarget::Alias {
                    name: real_name,
                    target,
                } => {
                    format!("npm:{}@{}", real_name, target)
                }
                PackageTarget::Url(u) => u.to_string(),
            };

            if self.options.save_dev {
                manifest
                    .dev_dependencies
                    .insert(spec.name.clone(), solver_spec);
                manifest.dependencies.remove(&spec.name);
                manifest.optional_dependencies.remove(&spec.name);
                manifest.peer_dependencies.remove(&spec.name);
            } else if self.options.save_optional {
                manifest
                    .optional_dependencies
                    .insert(spec.name.clone(), solver_spec);
                manifest.dependencies.remove(&spec.name);
                manifest.dev_dependencies.remove(&spec.name);
                manifest.peer_dependencies.remove(&spec.name);
            } else if self.options.save_peer {
                manifest
                    .peer_dependencies
                    .insert(spec.name.clone(), solver_spec);
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

        let project_name = manifest
            .name
            .clone()
            .unwrap_or_else(|| "project".to_string());
        let project_version = manifest.version.clone();

        // Validate dependency names for path containment
        for dep_name in manifest
            .dependencies
            .keys()
            .chain(manifest.dev_dependencies.keys())
            .chain(manifest.optional_dependencies.keys())
            .chain(manifest.peer_dependencies.keys())
        {
            if dep_name.contains("..")
                || dep_name.contains(':')
                || dep_name.contains('\\')
                || dep_name.contains('\0')
            {
                return Err(anyhow!(
                    "Package name '{dep_name}' contains illegal path characters"
                ));
            }
            rnpm_fs::validate_entry_path(Path::new(dep_name))
                .map_err(|e| anyhow!("Invalid package name '{dep_name}': {e}"))?;
        }

        // 0. Discover workspace members (if any)
        let mut workspace_members =
            discover_workspaces_from_manifest(&self.options.project_dir, &manifest)
                .map_err(|e| anyhow!("Failed to discover workspaces: {e}"))?;

        if !self.options.workspace.is_empty() {
            workspace_members.retain(|m| {
                self.options.workspace.iter().any(|target| {
                    target == &m.name
                        || target == &m.relative_path
                        || m.relative_path.ends_with(target)
                        || target.trim_start_matches("./") == m.relative_path
                })
            });

            if !self.options.workspace_root {
                manifest.dependencies.clear();
                manifest.dev_dependencies.clear();
                manifest.optional_dependencies.clear();
                manifest.peer_dependencies.clear();
            }
        }

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
            Some(
                WorkspaceDependencyGraph::construct(&workspace_members)
                    .map_err(|e| anyhow!("Workspace dependency error: {e}"))?,
            )
        } else {
            None
        };

        drop(_plan_span);
        collector.record_phase(Phase::Plan, plan_start.elapsed());

        let metadata_start = std::time::Instant::now();
        let _meta_span = tracing::info_span!("metadata").entered();

        // 1. Resolve dependency graph via Solver directly
        let handle = tokio::runtime::Handle::current();
        let metadata_cache = Arc::new(std::sync::Mutex::new(HashMap::new()));
        self.populate_custom_target_metadata(&manifest, &metadata_cache)
            .await?;
        for member in &workspace_members {
            self.populate_custom_target_metadata(&member.manifest, &metadata_cache)
                .await?;
        }

        let loc_base_dir = if self.options.is_global {
            if cfg!(windows) {
                self.options.project_dir.clone()
            } else {
                self.options.project_dir.join("lib")
            }
        } else {
            self.options.project_dir.clone()
        };

        if self.options.is_global {
            let global_nm = rnpm_config::find_global_node_modules(&self.options.project_dir);
            populate_global_disk_metadata(&global_nm, &metadata_cache);
        }

        let lockfile_path = project_lockfile_path(&self.options.project_dir);
        let existing_lockfile = if !self.options.package_lock_enabled() {
            None
        } else if lockfile_path.exists() {
            std::fs::read_to_string(&lockfile_path)
                .ok()
                .and_then(|s| rnpm_lockfile::parse_and_migrate(&s).ok())
                .map(Arc::new)
        } else if self.options.is_global {
            LockfileV3::load_hidden(&loc_base_dir).ok().map(Arc::new)
        } else {
            None
        };
        let existing_lockfile_for_merge = existing_lockfile.clone();

        if let Some(ref lf) = existing_lockfile {
            let mut set = tokio::task::JoinSet::new();
            let mut seen = HashSet::new();
            for loc in lf.packages.keys() {
                if loc.is_empty() {
                    continue;
                }
                let name = package_name_from_loc(loc).to_string();
                if seen.insert(name.clone()) {
                    let cache = self.cache.clone();
                    let reg_url = self
                        .registry_client
                        .registry_for_package(&name)
                        .as_str()
                        .to_string();
                    let name_clone = name.clone();
                    let lf_clone = lf.clone();
                    set.spawn_blocking(move || {
                        let cached_data = cache
                            .get_packument_with_accept(
                                &reg_url,
                                &name_clone,
                                Some(NPM_INSTALL_V1_JSON),
                            )
                            .ok()
                            .flatten()
                            .or_else(|| {
                                cache
                                    .get(&format!("pacote:packument:{name_clone}"))
                                    .ok()
                                    .flatten()
                            });
                        if let Some((_entry, data)) = cached_data {
                            if let Ok(abbrev) =
                                serde_json::from_slice::<AbbreviatedPackageMetadata>(&data)
                            {
                                let mut meta = abbreviated_to_package_metadata(&abbrev);
                                if let Some(lf_meta) =
                                    package_metadata_from_lockfile(&name_clone, &lf_clone)
                                {
                                    for (v, vm) in lf_meta.versions {
                                        meta.versions.entry(v).or_insert(vm);
                                    }
                                }
                                return Some((name_clone, meta));
                            }
                        }
                        None
                    });
                }
            }
            while let Some(res) = set.join_next().await {
                if let Ok(Some((name, meta))) = res {
                    if let Ok(mut cache_guard) = metadata_cache.lock() {
                        cache_guard.insert(name, meta);
                    }
                }
            }
        }

        let provider = RegistryPackageProvider {
            client: self.registry_client.clone(),
            handle,
            metadata_cache,
            cache: self.cache.clone(),
            offline: self.options.offline,
            git_fetcher: crate::git::GitFetcher::new(self.cache.root()),
            lockfile: existing_lockfile.clone(),
        };

        let resolver_options = ResolverOptions {
            platform: self.options.platform(),
            dev: !self.options.omit_dev,
            legacy_peer_deps: self.options.legacy_peer_deps,
            strict_peers: !self.options.legacy_peer_deps,
            strict_peer_deps: self.options.strict_peer_deps,
            lockfile: existing_lockfile,
            unlocked_packages: self.options.unlocked_packages.clone(),
            vulnerability_constraints: self.options.vulnerability_constraints.clone(),
        };

        let mut graph = if !workspace_members.is_empty() {
            let members = workspace_members.clone();
            let root_m = manifest.clone();
            tokio::task::spawn_blocking(move || {
                resolve_workspace_graph(&root_m, &members, &provider, &resolver_options)
                    .map_err(|e| anyhow!("Workspace dependency error: {e}"))
            })
            .await
            .map_err(|e| anyhow!("Solver task panicked: {e}"))??
        } else {
            let root_m = manifest.clone();
            tokio::task::spawn_blocking(move || {
                let overrides = Overrides::from_manifest(&root_m)
                    .map_err(|e| anyhow!("Failed to parse overrides: {e}"))?;
                let solver = Solver::new(&provider, resolver_options, overrides);
                solver.resolve(&root_m).map_err(|e| anyhow!("{e}"))
            })
            .await
            .map_err(|e| anyhow!("Solver task panicked: {e}"))??
        };

        drop(_meta_span);
        collector.record_phase(Phase::Metadata, metadata_start.elapsed());

        // 2. Post-solve: finalize versions for added packages in manifest
        if !added_pkgs.is_empty() {
            for added in &added_pkgs {
                let resolved_version_opt = graph
                    .nodes
                    .get(&format!("node_modules/{}", added.name))
                    .or_else(|| {
                        graph
                            .nodes
                            .values()
                            .find(|n| n.install_name == added.name || n.name == added.name)
                    })
                    .map(|n| n.version.clone());

                let resolved_ver = resolved_version_opt.unwrap_or_else(|| "1.0.0".to_string());

                let final_spec = if self.options.save_exact {
                    match &added.target {
                        PackageTarget::Alias {
                            name: real_name, ..
                        } => {
                            format!("npm:{}@{}", real_name, resolved_ver)
                        }
                        PackageTarget::File(p) => {
                            format!("file:{}", rnpm_core::to_posix_path(&p.to_string_lossy()))
                        }
                        PackageTarget::Git { url, committish } => {
                            format!(
                                "{}{}",
                                url,
                                committish
                                    .as_ref()
                                    .map(|c| format!("#{c}"))
                                    .unwrap_or_default()
                            )
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
                        PackageTarget::Alias {
                            name: real_name, ..
                        } => {
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
                            format!(
                                "{}{}",
                                url,
                                committish
                                    .as_ref()
                                    .map(|c| format!("#{c}"))
                                    .unwrap_or_default()
                            )
                        }
                        PackageTarget::Workspace(ws) => format!("workspace:{}", ws),
                        PackageTarget::Url(u) => u.to_string(),
                    }
                };

                if self.options.save_dev {
                    manifest
                        .dev_dependencies
                        .insert(added.name.clone(), final_spec);
                } else if self.options.save_optional {
                    manifest
                        .optional_dependencies
                        .insert(added.name.clone(), final_spec);
                } else if self.options.save_peer {
                    manifest
                        .peer_dependencies
                        .insert(added.name.clone(), final_spec);
                } else {
                    manifest.dependencies.insert(added.name.clone(), final_spec);
                }
            }

            // Save package.json unless --no-save was passed or in global mode
            if !self.options.is_global && !self.options.no_save && !self.options.dry_run {
                manifest
                    .save_to_file(&manifest_path)
                    .context("Failed to save updated package.json")?;
            } else if self.options.dry_run {
                for added in &added_pkgs {
                    println!("rnpm: would add {} to package.json", added.name);
                }
            }
        }

        // If this is a global install, isolate dependencies so that only top-level
        // packages live directly under root node_modules, and their transitive
        // dependencies are nested under node_modules/<top-pkg>/node_modules/...
        if self.options.is_global {
            isolate_global_dependencies(&mut graph, &manifest);
            if let Some(ref existing) = existing_lockfile_for_merge {
                for (loc, node) in &mut graph.nodes {
                    if let Some(old_pkg) = existing.packages.get(loc) {
                        if node.resolved.is_none() {
                            node.resolved = old_pkg.resolved.clone();
                        }
                        if node.integrity.is_none() {
                            node.integrity = old_pkg.integrity.clone();
                        }
                        if old_pkg.link == Some(true) {
                            node.flags.link = true;
                        }
                    }
                }
            }
        }

        let mut lockfile = graph.to_lockfile_v3(&project_name, project_version.as_deref());
        if let Some(ref existing) = existing_lockfile_for_merge {
            for (loc, pkg) in &mut lockfile.packages {
                if loc.is_empty() {
                    continue;
                }
                if let Some(old_pkg) = existing.packages.get(loc) {
                    let is_added_pkg = added_pkgs.iter().any(|a| {
                        loc == &format!("node_modules/{}", a.name)
                            || loc.starts_with(&format!("node_modules/{}/", a.name))
                    });
                    if (self.options.is_global && !is_added_pkg)
                        || (pkg.version == old_pkg.version
                            && pkg.resolved == old_pkg.resolved
                            && pkg.integrity == old_pkg.integrity
                            && pkg.dependencies == old_pkg.dependencies
                            && pkg.peer_dependencies == old_pkg.peer_dependencies
                            && pkg.optional_dependencies == old_pkg.optional_dependencies)
                    {
                        *pkg = old_pkg.clone();
                    }
                }
            }
        }
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
            self.enrich_lockfile_from_registry(&mut lockfile).await?;
            for (loc, node) in &graph.nodes {
                if let Some(ref res) = node.resolved {
                    if let Some(rel_file) = res.strip_prefix("file:") {
                        let abs_file = self.options.project_dir.join(rel_file);
                        if abs_file.is_dir() {
                            let clean_rel = rel_file.strip_prefix("./").unwrap_or(rel_file);
                            let link_entry = LockfilePackage {
                                resolved: Some(clean_rel.to_string()),
                                link: Some(true),
                                ..Default::default()
                            };
                            lockfile.insert_package(loc, link_entry);

                            let mut target_entry = LockfilePackage {
                                name: Some(node.name.clone()),
                                version: Some(node.version.clone()),
                                ..Default::default()
                            };
                            if !node.dependencies.is_empty() {
                                target_entry.dependencies = Some(node.dependencies.clone());
                            }
                            lockfile.insert_package(clean_rel, target_entry);
                        }
                    }
                }
            }

            let lockfile_path = project_lockfile_path(&self.options.project_dir);
            if !self.options.dry_run && self.options.package_lock_enabled() && !self.options.no_save && !self.options.is_global
            {
                let _lock_guard = collector.enter_phase(Phase::Lockfile);
                lockfile
                    .save_to_file_version(&lockfile_path, self.options.lockfile_version)
                    .with_context(|| format!("Failed to save {}", lockfile_path.display()))?;
            }

            return Ok(InstallSummary {
                packages_installed: 0,
                cache_hits: 0,
                cache_misses: 0,
                lockfile_path,
                timing: Some(collector.finish()),
            });
        }

        // 3b. For --dry-run, simulate installation and report what would be installed
        if self.options.dry_run {
            let mut packages_installed = 0;
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
                if workspace_members.iter().any(|m| &m.relative_path == loc) {
                    continue;
                }
                if node.flags.skipped {
                    continue;
                }
                let is_optional = node.flags.optional || node.flags.dev_optional;
                if is_optional {
                    let host_platform = self.options.platform();
                    let is_compat = rnpm_solver::is_platform_compatible(
                        &host_platform,
                        node.os.as_deref(),
                        node.cpu.as_deref(),
                        node.libc.as_deref(),
                    );
                    if !is_compat {
                        continue;
                    }
                }
                println!(
                    "rnpm: would install {}@{} at {}",
                    node.name, node.version, loc
                );
                packages_installed += 1;
            }

            return Ok(InstallSummary {
                packages_installed,
                cache_hits: 0,
                cache_misses: 0,
                lockfile_path,
                timing: Some(collector.finish()),
            });
        }

        // 2. Build proper nested node_modules trees and lockfile v3 from solver graph
        let (node_modules_dir, root_bin_dir, loc_base_dir) = if self.options.is_global {
            let nm = rnpm_config::find_global_node_modules(&self.options.project_dir);
            let bin = rnpm_config::find_global_bin_dir(&self.options.project_dir);
            let base = if cfg!(windows) {
                self.options.project_dir.clone()
            } else {
                self.options.project_dir.join("lib")
            };
            (nm, bin, base)
        } else {
            let nm = self.options.project_dir.join("node_modules");
            let bin = nm.join(".bin");
            let base = self.options.project_dir.clone();
            (nm, bin, base)
        };
        std::fs::create_dir_all(&node_modules_dir).context("Failed to create node_modules")?;
        std::fs::create_dir_all(&root_bin_dir).context("Failed to create bin dir")?;

        // Milestone M3: Diff ideal tree against actual tree (node_modules/.package-lock.json)
        let actual_lockfile_opt = if !self.options.force
            && validate_hidden_lockfile(&loc_base_dir, Some(&self.options))
        {
            LockfileV3::load_hidden(&loc_base_dir).ok()
        } else {
            None
        };

        let tree_diff_opt = actual_lockfile_opt
            .as_ref()
            .map(|actual| diff_trees(&lockfile, actual));

        // Fast trash deletion for removed packages from previous lockfile if hidden lockfile was missing
        if actual_lockfile_opt.is_none() {
            if let Some(ref old_lock) = existing_lockfile_for_merge {
                for rel_path in old_lock.packages.keys() {
                    if !lockfile.packages.contains_key(rel_path) {
                        if !is_node_modules_package_path(rel_path) {
                            continue;
                        }
                        let target_path = loc_base_dir.join(rel_path);
                        let clean_target = path_clean::clean(&target_path);
                        let clean_nm = path_clean::clean(&node_modules_dir);
                        if clean_target.starts_with(&clean_nm)
                            && (target_path.exists()
                                || rnpm_fs::is_junction(&target_path).unwrap_or(false))
                        {
                            let pkg_manifest_path = target_path.join("package.json");
                            if let Ok(pkg_m) = Manifest::from_file(&pkg_manifest_path) {
                                let bin_dir = find_enclosing_bin_dir(
                                    &target_path,
                                    &root_bin_dir,
                                    &node_modules_dir,
                                );
                                for (bin_name, _) in pkg_m.bin_entries() {
                                    let _ = std::fs::remove_file(bin_dir.join(&bin_name));
                                    let _ = std::fs::remove_file(
                                        bin_dir.join(format!("{bin_name}.cmd")),
                                    );
                                    let _ = std::fs::remove_file(
                                        bin_dir.join(format!("{bin_name}.ps1")),
                                    );
                                }
                                clean_empty_bin_dir_at(&bin_dir);
                            }
                            let _ = fast_trash_delete(&target_path, &node_modules_dir);
                        }
                    }
                }
            }
        }

        // Fast trash deletion for removed packages off the critical path
        if let Some(ref diff) = tree_diff_opt {
            for (rel_path, _pkg) in diff.removes() {
                if !is_node_modules_package_path(rel_path) {
                    continue;
                }
                let target_path = loc_base_dir.join(rel_path);
                let clean_target = path_clean::clean(&target_path);
                let clean_nm = path_clean::clean(&node_modules_dir);
                if !clean_target.starts_with(&clean_nm) {
                    continue;
                }
                if target_path.exists() || rnpm_fs::is_junction(&target_path).unwrap_or(false) {
                    let pkg_manifest_path = target_path.join("package.json");
                    if let Ok(pkg_m) = Manifest::from_file(&pkg_manifest_path) {
                        let bin_dir =
                            find_enclosing_bin_dir(&target_path, &root_bin_dir, &node_modules_dir);
                        for (bin_name, _) in pkg_m.bin_entries() {
                            let _ = std::fs::remove_file(bin_dir.join(&bin_name));
                            let _ = std::fs::remove_file(bin_dir.join(format!("{bin_name}.cmd")));
                            let _ = std::fs::remove_file(bin_dir.join(format!("{bin_name}.ps1")));
                        }
                        clean_empty_bin_dir_at(&bin_dir);
                    }
                    fast_trash_delete(&target_path, &node_modules_dir).with_context(|| {
                        format!(
                            "Failed to remove package directory {}",
                            target_path.display()
                        )
                    })?;
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
        }

        if self.options.install_strategy == InstallStrategy::Linked {
            return self
                .execute_linked_install(
                    &manifest,
                    &graph,
                    &lockfile,
                    &node_modules_dir,
                    &root_bin_dir,
                    collector,
                    plan_start,
                )
                .await;
        }

        let mut cache_hits = 0;
        let mut cache_misses = 0;
        let mut packages_installed = 0;

        // Milestone M3: Clean up stale files in replaced packages, preserving unchanged nested node_modules
        if let Some(ref diff) = tree_diff_opt {
            for (rel_path, _, _) in diff.replaces() {
                if !is_node_modules_package_path(rel_path) {
                    continue;
                }
                let target_path = loc_base_dir.join(rel_path);
                let clean_target = path_clean::clean(&target_path);
                let clean_nm = path_clean::clean(&node_modules_dir);
                if !clean_target.starts_with(&clean_nm) {
                    continue;
                }
                clean_stale_package_dir(&target_path, rel_path, Some(diff));
            }
        }

        // Pre-create all package parent directories and bin directories in one breadth-first pass
        {
            let mut dirs_to_precreate = Vec::with_capacity(graph.nodes.len() * 2);
            for (loc, node) in &graph.nodes {
                if loc.is_empty() {
                    continue;
                }
                if let Some(ref diff) = tree_diff_opt {
                    if let Some(action) = diff.get(loc) {
                        if action.is_unchanged() {
                            continue;
                        }
                    }
                }
                let dest_dir = loc_base_dir.join(loc);
                if let Some(parent) = dest_dir.parent() {
                    dirs_to_precreate.push(parent.to_path_buf());
                }
                let has_bin = match &node.bin {
                    Some(rnpm_lockfile::PackageBin::Single(_)) => true,
                    Some(rnpm_lockfile::PackageBin::Map(map)) => !map.is_empty(),
                    None => false,
                };
                if has_bin {
                    let bin_dir =
                        find_enclosing_bin_dir(&dest_dir, &root_bin_dir, &node_modules_dir);
                    dirs_to_precreate.push(bin_dir);
                }
            }
            let dir_refs: Vec<&Path> = dirs_to_precreate.iter().map(|p| p.as_path()).collect();
            let _ = precreate_directories(dir_refs);
        }

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

            // Milestone M3: Partial install optimization - only touch what changed
            if let Some(ref diff) = tree_diff_opt {
                if let Some(action) = diff.get(loc) {
                    if action.is_unchanged() {
                        let dest_dir = loc_base_dir.join(loc);
                        if dest_dir.exists() || rnpm_fs::is_junction(&dest_dir).unwrap_or(false) {
                            debug!("Skipping unchanged package: {}", loc);
                            continue;
                        }
                    } else if action.is_replace() {
                        let dest_dir = loc_base_dir.join(loc);
                        clean_stale_package_dir(&dest_dir, loc, Some(diff));
                    }
                }
            }

            if self.options.is_global {
                let dest_dir = loc_base_dir.join(loc);
                let is_junc = rnpm_fs::is_junction(&dest_dir).unwrap_or(false);
                if dest_dir.join("package.json").is_file() || is_junc {
                    let is_being_reinstalled = added_pkgs.iter().any(|a| {
                        loc == &format!("node_modules/{}", a.name)
                            || loc.starts_with(&format!("node_modules/{}/", a.name))
                    });
                    if !is_being_reinstalled {
                        debug!("Skipping existing untouched global package: {}", loc);
                        continue;
                    }
                }
            }

            if node.flags.link {
                let link_target = loc_base_dir.join(loc);
                if let Some(parent) = link_target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if link_target.exists() || rnpm_fs::is_junction(&link_target).unwrap_or(false) {
                    let _ = rnpm_fs::remove_junction(&link_target);
                    if link_target.exists() && !rnpm_fs::is_junction(&link_target).unwrap_or(false)
                    {
                        let _ = std::fs::remove_dir_all(&link_target);
                    }
                }
                let source_path = if let Some(ref res) = node.resolved {
                    self.options.project_dir.join(res)
                } else {
                    self.options.project_dir.join(&node.name)
                };

                rnpm_fs::create_junction(&link_target, &source_path).map_err(|e| {
                    anyhow!(
                        "Failed to link package at '{}' -> '{}': {e}",
                        link_target.display(),
                        source_path.display()
                    )
                })?;

                packages_installed += 1;
                continue;
            }

            if workspace_members.iter().any(|m| &m.relative_path == loc) {
                continue;
            }

            if node.flags.skipped {
                debug!(
                    "Package at {} is marked skipped, bypassing download and extraction",
                    loc
                );
                continue;
            }
            let is_optional = node.flags.optional || node.flags.dev_optional;
            if is_optional {
                let host_platform = self.options.platform();
                let is_compat = rnpm_solver::is_platform_compatible(
                    &host_platform,
                    node.os.as_deref(),
                    node.cpu.as_deref(),
                    node.libc.as_deref(),
                );
                if !is_compat {
                    debug!("Package at {} is incompatible optional package on this platform, bypassing download and extraction", loc);
                    continue;
                }
            }

            let dest_dir = loc_base_dir.join(loc);
            let _bin_dir = find_enclosing_bin_dir(&dest_dir, &root_bin_dir, &node_modules_dir);

            if let Some(ref res) = node.resolved {
                let is_git = res.starts_with("git+")
                    || res.starts_with("git:")
                    || PackageTarget::parse(res)
                        .map(|t| t.is_git())
                        .unwrap_or(false);

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
                            if m.scripts.contains_key("preinstall")
                                || m.scripts.contains_key("install")
                                || m.scripts.contains_key("postinstall")
                                || m.scripts.contains_key("prepare")
                            {
                                lifecycle_nodes.push(LifecyclePackageNode {
                                    package_path: loc.clone(),
                                    disk_path: dest_dir.clone(),
                                    manifest: m,
                                    source: PackageSource::Git,
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
                        let computed_integrity = if let Some(ref integ) = node.integrity {
                            if !integ.is_empty() {
                                let expected_integrity: Integrity = integ
                                    .parse()
                                    .map_err(|e| anyhow!("Invalid integrity hash: {e}"))?;
                                if let Err(e) = expected_integrity.verify(&archive_bytes) {
                                    if node.flags.optional {
                                        warn!(
                                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for local archive {loc}: {e}"
                                        );
                                        continue;
                                    } else {
                                        return Err(anyhow!("Integrity verification failed for local archive {loc}: {e}"));
                                    }
                                }
                            }
                            integ.clone()
                        } else {
                            use sha2::Digest;
                            let hash = sha2::Sha512::digest(&archive_bytes);
                            format!("sha512-{}", data_encoding::BASE64.encode(&hash))
                        };

                        if !computed_integrity.is_empty()
                            && !self.pack_store.has_package_pack(&computed_integrity)
                        {
                            let _ = self
                                .pack_store
                                .put_package_from_tarball(&computed_integrity, &archive_bytes);
                        }

                        if rnpm_fs::is_junction(&dest_dir).unwrap_or(false) {
                            let _ = rnpm_fs::remove_junction(&dest_dir);
                        }

                        let extracted = if !computed_integrity.is_empty()
                            && self.pack_store.has_package_pack(&computed_integrity)
                        {
                            match self.pack_store.materialize_pack(
                                &computed_integrity,
                                &dest_dir,
                                Some(&self.writer_cfg),
                            ) {
                                Ok(_) => Ok(()),
                                Err(e) => {
                                    if e.is_pack_corruption() {
                                        warn!("materialize_pack failed for {computed_integrity}: {e}, purging pack and falling back to tarball extraction");
                                        let _ = self.pack_store.purge(&computed_integrity);
                                        let _ = std::fs::remove_dir_all(&dest_dir);
                                        extract_tarball_direct(
                                            Cursor::new(&archive_bytes),
                                            &dest_dir,
                                            None,
                                            Some(&self.writer_cfg),
                                        )
                                        .map(|_| ())
                                        .map_err(|e| {
                                            anyhow!("Failed to extract local archive {}: {e}", loc)
                                        })
                                    } else {
                                        return Err(anyhow!("Failed to materialize pack for {computed_integrity}: {e}"));
                                    }
                                }
                            }
                        } else {
                            extract_tarball_direct(
                                Cursor::new(&archive_bytes),
                                &dest_dir,
                                None,
                                Some(&self.writer_cfg),
                            )
                            .map(|_| ())
                            .map_err(|e| anyhow!("Failed to extract local archive {}: {e}", loc))
                        };
                        extracted?;

                        packages_installed += 1;
                        cache_hits += 1;

                        if let Some(pkg) = lockfile.packages.get_mut(loc) {
                            if pkg.integrity.is_none() {
                                pkg.integrity = Some(computed_integrity);
                            }
                        }

                        let pkg_manifest_path = dest_dir.join("package.json");
                        if pkg_manifest_path.exists() {
                            if let Ok(m) = Manifest::from_file(&pkg_manifest_path) {
                                if m.scripts.contains_key("preinstall")
                                    || m.scripts.contains_key("install")
                                    || m.scripts.contains_key("postinstall")
                                    || m.scripts.contains_key("prepare")
                                {
                                    lifecycle_nodes.push(LifecyclePackageNode {
                                        package_path: loc.clone(),
                                        disk_path: dest_dir.clone(),
                                        manifest: m,
                                        source: PackageSource::LocalTarball,
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
                            if dest_dir.exists()
                                && !rnpm_fs::is_junction(&dest_dir).unwrap_or(false)
                            {
                                let _ = std::fs::remove_dir_all(&dest_dir);
                            }
                        }
                        rnpm_fs::create_junction(&dest_dir, &abs_file)
                            .map_err(|e| anyhow!("Failed to link file dir {}: {e}", loc))?;
                        packages_installed += 1;
                        let pkg_manifest_path = abs_file.join("package.json");
                        if let Ok(m) = Manifest::from_file(&pkg_manifest_path) {
                            if m.scripts.contains_key("preinstall")
                                || m.scripts.contains_key("install")
                                || m.scripts.contains_key("postinstall")
                                || m.scripts.contains_key("prepare")
                            {
                                lifecycle_nodes.push(LifecyclePackageNode {
                                    package_path: loc.clone(),
                                    disk_path: abs_file.clone(),
                                    manifest: m,
                                    source: PackageSource::Local,
                                    dependencies: node.dependencies.keys().cloned().collect(),
                                    optional: node.flags.optional,
                                });
                            }
                        }

                        let clean_rel = rel_file.strip_prefix("./").unwrap_or(rel_file);
                        let link_entry = LockfilePackage {
                            resolved: Some(clean_rel.to_string()),
                            link: Some(true),
                            ..Default::default()
                        };
                        lockfile.insert_package(loc, link_entry);

                        let mut target_entry = LockfilePackage {
                            name: Some(node.name.clone()),
                            version: Some(node.version.clone()),
                            ..Default::default()
                        };
                        if !node.dependencies.is_empty() {
                            target_entry.dependencies = Some(node.dependencies.clone());
                        }
                        lockfile.insert_package(clean_rel, target_entry);
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
                let mut member_deps: Vec<String> =
                    member.manifest.dependencies.keys().cloned().collect();
                for (dep_name, dep_spec) in &member.manifest.dev_dependencies {
                    let is_sibling = ws_graph_opt
                        .as_ref()
                        .map(|g| g.is_member(dep_name))
                        .unwrap_or(false)
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

        let mut active_writer_cfg = (*self.writer_cfg).clone();
        if loc_base_dir.join("node_modules").is_dir() {
            active_writer_cfg.skip_existing_matching = true;
        }
        let writer_cfg = Arc::new(active_writer_cfg);
        let semaphore = Arc::clone(&self.io_semaphore);

        // Early path containment check on all packages to download before precreating dirs
        for (loc, _) in &packages_to_download {
            if loc.contains("..") || loc.contains(':') || loc.contains('\\') || loc.contains('\0') {
                return Err(anyhow!(
                    "Package path '{loc}' contains illegal path characters"
                ));
            }
            rnpm_fs::validate_entry_path(Path::new(loc))
                .map_err(|e| anyhow!("Invalid package path '{loc}': {e}"))?;
            let dest_dir = loc_base_dir.join(loc);
            let cleaned_dest = path_clean::clean(&dest_dir);
            let cleaned_project = path_clean::clean(&loc_base_dir);
            if !cleaned_dest.starts_with(&cleaned_project) {
                return Err(anyhow!(
                    "Package installation path '{cleaned_dest:?}' escapes project root"
                ));
            }
        }

        let all_packs_available = !packages_to_download.is_empty()
            && packages_to_download.iter().all(|(_, node)| {
                node.integrity
                    .as_ref()
                    .is_some_and(|i| !i.is_empty() && self.pack_store.has_package_pack(i))
            });

        let mut used_fast_materialize = false;
        let mut in_memory_manifests: HashMap<String, Manifest> = HashMap::new();
        if all_packs_available {
            let t_mat = std::time::Instant::now();
            let mut all_dirs = std::collections::BTreeSet::new();
            all_dirs.insert(node_modules_dir.clone());
            all_dirs.insert(root_bin_dir.clone());

            for (loc, _) in &packages_to_download {
                let pkg_target = loc_base_dir.join(loc);
                if rnpm_fs::is_junction(&pkg_target).unwrap_or(false) {
                    let _ = rnpm_fs::remove_junction(&pkg_target);
                }
                all_dirs.insert(pkg_target.clone());
                if let Some(parent) = pkg_target.parent() {
                    all_dirs.insert(parent.to_path_buf());
                }
            }

            let total_pkgs = packages_to_download.len();
            let num_workers = 16.min(total_pkgs);
            let next_idx = std::sync::atomic::AtomicUsize::new(0);
            let load_failed = std::sync::atomic::AtomicBool::new(false);
            let pack_store = Arc::clone(&self.pack_store);

            let mut loaded_packs = Vec::with_capacity(total_pkgs);
            let load_success = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(num_workers);
                for _ in 0..num_workers {
                    handles.push(scope.spawn(|| -> Result<Vec<(usize, String, PathBuf, rnpm_cache::PackagePack)>, ()> {
                        let mut local = Vec::new();
                        while !load_failed.load(std::sync::atomic::Ordering::Relaxed) {
                            let idx = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if idx >= total_pkgs {
                                break;
                            }
                            let (loc, node) = &packages_to_download[idx];
                            let integrity_str = node.integrity.as_ref().unwrap();
                            let pkg_target = loc_base_dir.join(loc);
                            match pack_store.get_package_pack(integrity_str) {
                                Ok(Some(pack)) => {
                                    local.push((idx, loc.clone(), pkg_target, pack));
                                }
                                _ => {
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
                    for (_, loc, pkg_target, pack) in all_results {
                        loaded_packs.push((loc, pkg_target, pack));
                    }
                    true
                }
            });

            if load_success {
                let mut all_file_refs = Vec::with_capacity(16384);
                let mut all_symlinks = Vec::new();

                let mut files_valid = true;
                for (loc, pkg_target, pack) in &loaded_packs {
                    for entry in &pack.index.files {
                        let full_path = pkg_target.join(&entry.path);
                        if let Some(parent) = full_path.parent() {
                            all_dirs.insert(parent.to_path_buf());
                        }
                        if let Some(slice) = pack.get_file_slice(&entry.path) {
                            all_file_refs.push(rnpm_fs::MaterializeFileRef {
                                path: full_path,
                                data: slice,
                                mode: entry.mode,
                                package_id: Some(loc.as_str()),
                                source_path: entry.cas_path.as_deref(),
                                expected_sha256: entry.sha256.as_deref(),
                                source_verified: entry.cas_verified,
                            });
                        } else {
                            files_valid = false;
                            break;
                        }
                    }
                    for (link_rel, target_rel) in &pack.index.symlinks {
                        all_symlinks.push((pkg_target.join(link_rel), pkg_target.join(target_rel)));
                    }
                }

                if files_valid {
                    let dir_refs: Vec<&Path> = all_dirs.iter().map(|p| p.as_path()).collect();
                    if precreate_directories(dir_refs).is_ok()
                        && rnpm_fs::materialize_files_parallel_refs(all_file_refs, &writer_cfg).is_ok()
                    {
                        for (link_path, target_path) in all_symlinks {
                            let _ = rnpm_fs::create_link_or_copy(&link_path, &target_path);
                        }

                        // Collect lifecycle scripts and cache in-memory manifests
                        for (idx, (loc, pkg_target, pack)) in loaded_packs.iter().enumerate() {
                            let node = &packages_to_download[idx].1;
                            if let Some(slice) = pack.get_file_slice("package.json") {
                                if let Ok(pkg_manifest) = Manifest::from_slice(slice) {
                                    in_memory_manifests.insert(loc.clone(), pkg_manifest.clone());
                                    let has_install_script = pkg_manifest.scripts.contains_key("preinstall")
                                        || pkg_manifest.scripts.contains_key("install")
                                        || pkg_manifest.scripts.contains_key("postinstall");
                                    if has_install_script {
                                        lifecycle_nodes.push(LifecyclePackageNode {
                                            package_path: loc.clone(),
                                            disk_path: pkg_target.clone(),
                                            manifest: pkg_manifest,
                                            source: PackageSource::Registry,
                                            dependencies: node.dependencies.keys().cloned().collect(),
                                            optional: node.flags.optional,
                                        });
                                    }
                                }
                            }
                            packages_installed += 1;
                            cache_hits += 1;
                            collector.record_cache_hit();
                        }
                        collector.record_phase(Phase::Materialize, t_mat.elapsed());
                        used_fast_materialize = true;
                    }
                }
            }
        }

        if !used_fast_materialize {
            let mut join_set = tokio::task::JoinSet::new();
            let unlocked_packages = self.options.unlocked_packages.clone();

            for (loc, node) in &packages_to_download {
                let sem = Arc::clone(&semaphore);
                let cache = self.cache.clone();
                let pack_store = Arc::clone(&self.pack_store);
                let registry_client = self.registry_client.clone();
                let project_dir = loc_base_dir.clone();
                let worker_unlocked_packages = unlocked_packages.clone();
                let offline = self.options.offline;
                let worker_collector = collector.clone();
                let pkg_writer_cfg = Arc::clone(&writer_cfg);
                let loc = loc.clone();
                let node = node.clone();

                join_set.spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| anyhow!("{e}"))?;

                // Early path containment defense: validate loc before warm pack check or junction removal
                if loc.contains("..") || loc.contains(':') || loc.contains('\\') || loc.contains('\0') {
                    return Err(anyhow!("Package path '{loc}' contains illegal path characters"));
                }
                rnpm_fs::validate_entry_path(Path::new(&loc))
                    .map_err(|e| anyhow!("Invalid package path '{loc}': {e}"))?;

                let dest_dir = project_dir.join(&loc);
                let cleaned_dest = path_clean::clean(&dest_dir);
                let cleaned_project = path_clean::clean(&project_dir);
                if !cleaned_dest.starts_with(&cleaned_project) {
                    return Err(anyhow!("Package installation path '{cleaned_dest:?}' escapes project root"));
                }

                if rnpm_fs::is_junction(&dest_dir).unwrap_or(false) {
                    let _ = rnpm_fs::remove_junction(&dest_dir);
                }

                // Warm Pack Store fast path: if package pack already exists, materialize directly without downloading/parsing!
                if let Some(ref integ_str) = node.integrity {
                    if !integ_str.is_empty() && pack_store.has_package_pack(integ_str) {
                        let t_mat = std::time::Instant::now();
                        let dest_dir_clone = dest_dir.clone();
                        let ps_clone = Arc::clone(&pack_store);
                        let integ_clone = integ_str.clone();
                        let cfg_clone = Arc::clone(&pkg_writer_cfg);
                        let loc_clone = loc.clone();
                        let mat_res = tokio::task::spawn_blocking(move || {
                            let _mat_span = tracing::info_span!("materialize-pack", package = %loc_clone).entered();
                            let res = ps_clone.materialize_pack(&integ_clone, &dest_dir_clone, Some(&cfg_clone));
                            drop(_mat_span);
                            res
                        }).await?;
                        worker_collector.record_phase(Phase::Materialize, t_mat.elapsed());

                        match mat_res {
                            Ok(_) => {
                                let pkg_manifest_path = dest_dir.join("package.json");
                                let mut lifecycle_node = None;
                                if pkg_manifest_path.exists() {
                                    if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                                        let has_scripts = pkg_manifest.scripts.contains_key("preinstall")
                                            || pkg_manifest.scripts.contains_key("install")
                                            || pkg_manifest.scripts.contains_key("postinstall");

                                        if has_scripts {
                                            let lifecycle_deps = node.dependencies.clone().into_keys().collect();
                                            lifecycle_node = Some(LifecyclePackageNode {
                                                package_path: loc.clone(),
                                                disk_path: dest_dir.clone(),
                                                manifest: pkg_manifest,
                                                source: PackageSource::Registry,
                                                dependencies: lifecycle_deps,
                                                optional: node.flags.optional,
                                            });
                                        }
                                    }
                                }
                                return Ok(Some((true, lifecycle_node)));
                            }
                            Err(e) => {
                                if e.is_pack_corruption() {
                                    warn!("Failed to materialize package {loc} from pack: {e}. Purging pack and falling back to tarball fetch.");
                                    let _ = pack_store.purge(integ_str);
                                    let _ = std::fs::remove_dir_all(&dest_dir);
                                } else {
                                    return Err(anyhow!("Failed to materialize package {loc} from pack: {e}"));
                                }
                            }
                        }
                    }
                }

                let resolved_url = node.resolved.as_ref().ok_or_else(|| {
                    anyhow!("Missing resolved URL for package at {loc}")
                })?;

                let expected_integrity: Option<Integrity> = if let Some(ref integ_str) = node.integrity {
                    if !integ_str.is_empty() {
                        match integ_str.parse::<Integrity>() {
                            Ok(i) => Some(i),
                            Err(e) => {
                                // Targeted updates retain satisfying, already-installed
                                // transitive packages. Older lockfiles may contain placeholder
                                // integrity values for those entries; do not refetch or reject a
                                // package that was not unlocked and is present on disk.
                                let location_name = loc
                                    .strip_prefix("node_modules/")
                                    .unwrap_or(&loc)
                                    .rsplit("/node_modules/")
                                    .next()
                                    .unwrap_or(&loc);
                                if !worker_unlocked_packages.is_empty()
                                    && !worker_unlocked_packages.contains(location_name)
                                    && dest_dir.join("package.json").exists()
                                {
                                    return Ok(Some((true, None)));
                                }
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

                let t_fetch = std::time::Instant::now();
                let _fetch_span = tracing::info_span!("fetch", package = %loc);
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
                                let t_sw = std::time::Instant::now();
                                let _sw_span = tracing::info_span!("store-write", package = %loc).entered();
                                let _ = cache.put_with_integrity(resolved_url, &bytes, expected_integrity.as_ref(), None);
                                drop(_sw_span);
                                worker_collector.record_phase(Phase::StoreWrite, t_sw.elapsed());
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
                            let t_sw = std::time::Instant::now();
                            let _sw_span = tracing::info_span!("store-write", package = %loc).entered();
                            let _ = cache.put_with_integrity(resolved_url, &bytes, expected_integrity.as_ref(), None);
                            drop(_sw_span);
                            worker_collector.record_phase(Phase::StoreWrite, t_sw.elapsed());
                            Ok((bytes, false))
                        }
                        Err(e) => Err(anyhow!("Failed to download tarball from {}: {e}", resolved_url)),
                    }
                };
                worker_collector.record_phase(Phase::Fetch, t_fetch.elapsed());

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
                let t_verify = std::time::Instant::now();
                let _v_span = tracing::info_span!("verify", package = %loc).entered();
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
                drop(_v_span);
                worker_collector.record_phase(Phase::Verify, t_verify.elapsed());

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

                // Construct and write pack to store if not already present (deferred CAS write)
                if let Some(ref integ_str) = node.integrity {
                    if !integ_str.is_empty() && !pack_store.has_package_pack(integ_str) {
                        let _ = pack_store.put_package_from_tarball_deferred(integ_str, &bytes);
                    }
                }

                // Parallel native materialization straight into place without staging dirs or renames
                let dest_dir_clone = dest_dir.clone();
                let cfg_clone = Arc::clone(&pkg_writer_cfg);
                let ps_clone = Arc::clone(&pack_store);
                let integ_opt = node.integrity.clone();
                let extract_res = tokio::task::spawn_blocking(move || {
                    if rnpm_fs::is_junction(&dest_dir_clone).unwrap_or(false) {
                        let _ = rnpm_fs::remove_junction(&dest_dir_clone);
                    }
                    if let Some(ref integ) = integ_opt {
                        if !integ.is_empty() && ps_clone.has_package_pack(integ) {
                            match ps_clone.materialize_pack(integ, &dest_dir_clone, Some(&cfg_clone)) {
                                Ok(sum) => return Ok(sum),
                                Err(e) => {
                                    if e.is_pack_corruption() {
                                        warn!("materialize_pack failed: {e}, purging pack and falling back to tarball extraction");
                                        let _ = ps_clone.purge(integ);
                                        let _ = std::fs::remove_dir_all(&dest_dir_clone);
                                    } else {
                                        return Err(rnpm_fs::FsError::Io(match e {
                                            CacheError::Io(io_err) => io_err,
                                            other => std::io::Error::other(other.to_string()),
                                        }));
                                    }
                                }
                            }
                        }
                    }
                    extract_tarball_direct(Cursor::new(bytes), &dest_dir_clone, None, Some(&cfg_clone))
                }).await?;

                match extract_res {
                    Ok(sum) => {
                        let _inf = tracing::info_span!("inflate", package = %loc).entered();
                        worker_collector.record_phase(Phase::Inflate, sum.inflate_duration);
                        drop(_inf);
                        let _mat = tracing::info_span!("materialize", package = %loc).entered();
                        worker_collector.record_phase(Phase::Materialize, sum.materialize_duration);
                        drop(_mat);
                    }
                    Err(e) => {
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
                }

                // Generate shims if package declares bin and collect lifecycle node
                let pkg_manifest_path = dest_dir.join("package.json");
                let mut lifecycle_node = None;

                if pkg_manifest_path.exists() {
                    if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
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
                    collector.record_cache_hit();
                } else {
                    cache_misses += 1;
                    collector.record_cache_miss();
                }
                packages_installed += 1;
                if let Some(l_node) = lifecycle_node {
                    lifecycle_nodes.push(l_node);
                }
            }
        }
        }

        // Fill CAS by copying from node_modules on 16 threads for cold installs
        if !used_fast_materialize {
            let mut cas_copy_list = Vec::new();
            for (loc, node) in &packages_to_download {
                if let Some(ref integrity_str) = node.integrity {
                    if !integrity_str.is_empty() {
                        if let Ok(Some(pack)) = self.pack_store.get_package_pack(integrity_str) {
                            for entry in &pack.index.files {
                                if let Some(ref cas_path) = entry.cas_path {
                                    let src = loc_base_dir.join(loc).join(&entry.path);
                                    cas_copy_list.push((src, cas_path.clone()));
                                }
                            }
                        }
                    }
                }
            }
            if !cas_copy_list.is_empty() {
                let t_cas = std::time::Instant::now();
                self.pack_store.populate_cas_from_installed(&cas_copy_list);
                collector.record_phase(Phase::StoreWrite, t_cas.elapsed());
            }
        }

        // Link all package bins across the tree in shallowest-first order with first-writer-wins
        // per .bin directory in this run, overwriting shims and cleaning up stale ones.
        let tree_packages: Vec<String> = graph
            .nodes
            .keys()
            .filter(|loc| {
                if loc.is_empty() {
                    return false;
                }
                if self.options.omit_dev && graph.nodes.get(*loc).is_some_and(|n| n.flags.dev) {
                    return false;
                }
                if self.options.omit_optional
                    && graph.nodes.get(*loc).is_some_and(|n| n.flags.optional)
                {
                    return false;
                }
                if self.options.omit_peer && graph.nodes.get(*loc).is_some_and(|n| n.flags.peer) {
                    return false;
                }
                if let Some(node) = graph.nodes.get(*loc) {
                    let is_optional = node.flags.optional || node.flags.dev_optional;
                    if is_optional {
                        let host_platform = self.options.platform();
                        let is_compat = rnpm_solver::is_platform_compatible(
                            &host_platform,
                            node.os.as_deref(),
                            node.cpu.as_deref(),
                            node.libc.as_deref(),
                        );
                        if !is_compat {
                            return false;
                        }
                    }
                }
                if workspace_members.iter().any(|m| &m.relative_path == *loc) {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        let mut known_bins = HashMap::new();
        for (loc, node) in &graph.nodes {
            if let Some(ref bin) = node.bin {
                let entries = extract_bin_entries_from_lockfile(&node.name, bin);
                if !entries.is_empty() {
                    known_bins.insert(loc.clone(), entries);
                }
            }
        }
        for member in &workspace_members {
            let entries = member.manifest.bin_entries();
            if !entries.is_empty() {
                known_bins.insert(format!("node_modules/{}", member.name), entries.clone());
                known_bins.insert(member.relative_path.clone(), entries);
            }
        }

        link_tree_bins(
            tree_packages,
            Some(&known_bins),
            &loc_base_dir,
            &root_bin_dir,
            &node_modules_dir,
            false,
            Some(&collector),
        );

        // 3. Execute lifecycle scripts bottom-up followed by root hooks
        if !self.options.ignore_scripts {
            let _life_guard = collector.enter_phase(Phase::Lifecycle);
            let sandbox_policy = if self.options.strict_sandbox {
                rnpm_lifecycle::ScriptSandboxPolicy::restricted()
            } else {
                rnpm_lifecycle::ScriptSandboxPolicy::permissive()
            };
            let lifecycle_opts = LifecycleOptions {
                root_dir: self.options.project_dir.clone(),
                init_cwd: self.options.project_dir.clone(),
                ignore_scripts: false,
                capture_output: !self.options.foreground_scripts,
                foreground_scripts: self.options.foreground_scripts,
                timeout: None,
                sandbox_policy,
            };
            execute_topological(&lifecycle_nodes, &manifest, &lifecycle_opts).await?;
        }

        let lockfile_path = project_lockfile_path(&self.options.project_dir);
        if !self.options.no_save && self.options.package_lock_enabled() {
            let _lock_guard = collector.enter_phase(Phase::Lockfile);
            crate::fast_path::enrich_lockfile_from_installed_manifests(&mut lockfile, &self.options.project_dir, Some(&in_memory_manifests));
            // 4. Write deterministic lockfile (only for local projects, not global prefix)
            if !self.options.is_global {
                lockfile
                    .save_to_file_version(&lockfile_path, self.options.lockfile_version)
                    .with_context(|| format!("Failed to save {}", lockfile_path.display()))?;
            }

            // 5. Persist hidden lockfile to node_modules/.package-lock.json
            lockfile
                .save_hidden(&loc_base_dir)
                .context("Failed to save hidden package-lock.json")?;
        }

        if !self.options.dry_run && !self.options.package_lock_only {
            if let Ok(fingerprint) =
                compute_project_fingerprint(&self.options.project_dir, &self.options)
            {
                let _ = self
                    .cache
                    .set_project_fingerprint(&self.options.project_dir, &fingerprint);
            }
        }

        clean_empty_bin_dirs(&node_modules_dir);

        Ok(InstallSummary {
            packages_installed,
            cache_hits,
            cache_misses,
            lockfile_path,
            timing: Some(collector.finish()),
        })
    }

    /// Run strict CI installation from committed package-lock.json.
    pub async fn run_ci(&mut self) -> Result<InstallSummary> {
        let res = self.run_ci_internal().await;
        if self.options.wait_for_trash || !self.options.detached_trash {
            crate::trash::wait_all_trash_deletions();
        }
        res
    }

    async fn run_ci_internal(&mut self) -> Result<InstallSummary> {
        crate::trash::cleanup_leftover_trash(&self.options.project_dir);
        let collector = TimingCollector::new();
        let plan_start = std::time::Instant::now();
        let _plan_span = tracing::info_span!("plan").entered();

        let manifest_path = self.options.project_dir.join("package.json");
        let (lockfile_path, is_shrinkwrap) = resolve_lockfile_path(&self.options.project_dir);
        let lockfile_name = if is_shrinkwrap {
            "npm-shrinkwrap.json"
        } else {
            "package-lock.json"
        };

        if !manifest_path.exists() {
            return Err(anyhow!(
                "package.json not found in {}",
                self.options.project_dir.display()
            ));
        }
        if !lockfile_path.exists() {
            return Err(anyhow!(
                "{lockfile_name} not found: rnpm ci requires a committed lockfile"
            ));
        }

        let manifest = Manifest::from_file(&manifest_path)?;
        drop(_plan_span);
        collector.record_phase(Phase::Plan, plan_start.elapsed());

        let metadata_start = std::time::Instant::now();
        let _meta_span = tracing::info_span!("metadata").entered();

        let lockfile_str = std::fs::read_to_string(&lockfile_path)?;
        let lockfile = rnpm_lockfile::parse_and_migrate(&lockfile_str)
            .with_context(|| format!("Failed to parse {lockfile_name}"))?;
        let platform_skipped_packages =
            lockfile_platform_skipped_packages(&lockfile, &self.options.platform());

        // 0. Discover workspace members (if any)
        let workspace_members =
            discover_workspaces_from_manifest(&self.options.project_dir, &manifest)
                .unwrap_or_default();

        let ws_graph_opt = if !workspace_members.is_empty() {
            WorkspaceDependencyGraph::construct(&workspace_members).ok()
        } else {
            None
        };

        // Comprehensive bidirectional drift check between manifest and lockfile
        let root_pkg = lockfile.packages.get("").ok_or_else(|| {
            anyhow!("rnpm ERR! code ELOCKFILE_DRIFT: {lockfile_name} missing root package descriptor (EUSAGE)")
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
                    "rnpm ERR! code ELOCKFILE_DRIFT: package.json dependency {} missing from {} (EUSAGE)",
                    dep_name,
                    lockfile_name
                ));
            }
        }
        for dep_name in lock_deps.keys() {
            if !manifest.dependencies.contains_key(dep_name) {
                return Err(anyhow!(
                    "rnpm ERR! code ELOCKFILE_DRIFT: dependency {} present in {} but removed from package.json (EUSAGE)",
                    dep_name,
                    lockfile_name
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
                    "rnpm ERR! code ELOCKFILE_DRIFT: package.json devDependency {} missing from {} (EUSAGE)",
                    dep_name,
                    lockfile_name
                ));
                }
            }
            for dep_name in lock_dev_deps.keys() {
                if !manifest.dev_dependencies.contains_key(dep_name) {
                    return Err(anyhow!(
                    "rnpm ERR! code ELOCKFILE_DRIFT: devDependency {} present in {} but removed from package.json (EUSAGE)",
                    dep_name,
                    lockfile_name
                ));
                }
            }
        }

        // 3. Optional dependencies drift check
        let lock_opt_deps = root_pkg
            .optional_dependencies
            .as_ref()
            .unwrap_or(&empty_deps);

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
                    "rnpm ERR! code ELOCKFILE_DRIFT: package.json optionalDependency {} missing from {} (EUSAGE)",
                    dep_name,
                    lockfile_name
                ));
                }
            }
            for dep_name in lock_opt_deps.keys() {
                if !manifest.optional_dependencies.contains_key(dep_name) {
                    return Err(anyhow!(
                    "rnpm ERR! code ELOCKFILE_DRIFT: optionalDependency {} present in {} but removed from package.json (EUSAGE)",
                    dep_name,
                    lockfile_name
                ));
                }
            }
        }

        // 4. Comprehensive lockfile validation via matches_manifest
        if !lockfile.matches_manifest(&manifest, !self.options.omit_dev) {
            return Err(anyhow!(
                "rnpm ERR! code ELOCKFILE_DRIFT: package.json and {} are out of sync. Please run `rnpm install` to update your lockfile. (EUSAGE)",
                lockfile_name
            ));
        }

        // 5. Internal lockfile consistency check: every dependency declared in the lockfile
        // must be satisfied by a package resolved according to node_modules lookup rules.
        let overrides = rnpm_solver::Overrides::from_manifest(&manifest).ok();
        let mut missing_dependencies = Vec::new();
        for (pkg_key, pkg_info) in &lockfile.packages {
            if platform_skipped_packages.contains(pkg_key) {
                continue;
            }
            if self.options.omit_dev && pkg_info.dev == Some(true) {
                continue;
            }
            if let Some(deps) = &pkg_info.dependencies {
                for (dep_name, range_str) in deps {
                    let effective_range = if let Some(ref ov) = overrides {
                        let mut ancestors: Vec<String> = Vec::new();
                        let parts = pkg_key.split("/node_modules/").filter(|p| !p.is_empty());
                        for p in parts {
                            let clean_p = p.strip_prefix("node_modules/").unwrap_or(p);
                            ancestors.push(clean_p.to_string());
                        }
                        ov.resolve_override_strings(dep_name, range_str, &ancestors)
                            .unwrap_or_else(|| range_str.clone())
                    } else {
                        range_str.clone()
                    };

                    let mut found_node: Option<&LockfilePackage> = None;
                    let mut curr = pkg_key.as_str();
                    loop {
                        let candidate_key = if curr.is_empty() {
                            format!("node_modules/{dep_name}")
                        } else {
                            format!("{curr}/node_modules/{dep_name}")
                        };
                        if let Some(p) = lockfile.packages.get(&candidate_key) {
                            found_node = Some(p);
                            break;
                        }
                        if curr.is_empty() {
                            break;
                        }
                        if let Some(idx) = curr.rfind("/node_modules/") {
                            curr = &curr[..idx];
                        } else {
                            curr = "";
                        }
                    }

                    let is_satisfied = if let Some(resolved_pkg) = found_node {
                        if resolved_pkg.link == Some(true)
                            || effective_range.starts_with("file:")
                            || effective_range.starts_with("workspace:")
                            || effective_range.starts_with("git")
                            || effective_range.starts_with("http:")
                            || effective_range.starts_with("https:")
                        {
                            true
                        } else if let Some(ref ver_str) = resolved_pkg.version {
                            if let (Ok(ver), Ok(range)) =
                                (Version::parse(ver_str), Range::parse(&effective_range))
                            {
                                range.satisfies(&ver)
                            } else {
                                ver_str == &effective_range
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if !is_satisfied {
                        missing_dependencies.push(format!("{dep_name}@{range_str}"));
                    }
                }
            }
        }

        if !missing_dependencies.is_empty() {
            missing_dependencies.sort();
            missing_dependencies.dedup();
            return Err(anyhow!(
                "npm error code EUSAGE\nnpm error Missing: {} from lock file",
                missing_dependencies.join(", ")
            ));
        }
        drop(_meta_span);
        collector.record_phase(Phase::Metadata, metadata_start.elapsed());

        if self.options.dry_run {
            let host_platform = self.options.platform();
            let mut packages_installed = 0;
            for (pkg_key, pkg_info) in &lockfile.packages {
                if pkg_key.is_empty() {
                    continue;
                }
                let is_dev = pkg_info.dev.unwrap_or(false);
                let is_optional = pkg_info.optional.unwrap_or(false)
                    || pkg_info.is_effective_optional()
                    || pkg_info.is_peer_optional();
                let is_dev_optional = pkg_info.dev_optional.unwrap_or(false);
                let is_peer =
                    pkg_info.peer.unwrap_or(false) || pkg_info.peer_optional.unwrap_or(false);

                if self.options.omit_dev && (is_dev || is_dev_optional) {
                    continue;
                }
                if self.options.omit_optional && (is_optional || is_dev_optional) {
                    continue;
                }
                if self.options.omit_peer && is_peer {
                    continue;
                }
                if platform_skipped_packages.contains(pkg_key) {
                    continue;
                }
                if is_optional {
                    let os_match = rnpm_solver::is_platform_compatible(
                        &host_platform,
                        pkg_info.os.as_deref(),
                        pkg_info.cpu.as_deref(),
                        pkg_info.libc.as_deref(),
                    );
                    if !os_match {
                        continue;
                    }
                }
                if !pkg_key.starts_with("node_modules/") && pkg_info.link != Some(true) {
                    continue;
                }
                println!("rnpm: would install {}", pkg_key);
                packages_installed += 1;
            }
            return Ok(InstallSummary {
                packages_installed,
                cache_hits: 0,
                cache_misses: 0,
                lockfile_path,
                timing: Some(collector.finish()),
            });
        }

        let plan2_start = std::time::Instant::now();
        let _plan2_span = tracing::info_span!("plan").entered();

        // Clean-slate: remove node_modules completely using junction-safe removal
        let (node_modules_dir, bin_dir, loc_base_dir) = if self.options.is_global {
            let nm = rnpm_config::find_global_node_modules(&self.options.project_dir);
            let bin = rnpm_config::find_global_bin_dir(&self.options.project_dir);
            let base = if cfg!(windows) {
                self.options.project_dir.clone()
            } else {
                self.options.project_dir.join("lib")
            };
            (nm, bin, base)
        } else {
            let nm = self.options.project_dir.join("node_modules");
            let bin = nm.join(".bin");
            let base = self.options.project_dir.clone();
            (nm, bin, base)
        };
        if node_modules_dir.exists() || rnpm_fs::is_junction(&node_modules_dir).unwrap_or(false) {
            fast_trash_wipe_dir(&node_modules_dir)?;
        }
        std::fs::create_dir_all(&node_modules_dir)?;
        std::fs::create_dir_all(&bin_dir)?;

        // Pre-create all package parent directories and bin directories in one breadth-first pass
        {
            let mut dirs_to_precreate = Vec::with_capacity(lockfile.packages.len() * 2);
            for (pkg_key, pkg_info) in &lockfile.packages {
                if pkg_key.is_empty() || platform_skipped_packages.contains(pkg_key) {
                    continue;
                }
                let is_dev = pkg_info.dev.unwrap_or(false);
                let is_optional = pkg_info.optional.unwrap_or(false)
                    || pkg_info.is_effective_optional()
                    || pkg_info.is_peer_optional();
                let is_dev_optional = pkg_info.dev_optional.unwrap_or(false);
                if self.options.omit_dev && (is_dev || is_dev_optional) {
                    continue;
                }
                if self.options.omit_optional && (is_optional || is_dev_optional) {
                    continue;
                }
                if is_optional {
                    let host_platform = self.options.platform();
                    if !rnpm_solver::is_platform_compatible(
                        &host_platform,
                        pkg_info.os.as_deref(),
                        pkg_info.cpu.as_deref(),
                        pkg_info.libc.as_deref(),
                    ) {
                        continue;
                    }
                }
                let target_path = self.options.project_dir.join(pkg_key);
                if let Some(parent) = target_path.parent() {
                    dirs_to_precreate.push(parent.to_path_buf());
                }
                let has_bin = match &pkg_info.bin {
                    Some(rnpm_lockfile::PackageBin::Single(_)) => true,
                    Some(rnpm_lockfile::PackageBin::Map(map)) => !map.is_empty(),
                    None => false,
                };
                if has_bin {
                    let pkg_bin_dir =
                        find_enclosing_bin_dir(&target_path, &bin_dir, &node_modules_dir);
                    dirs_to_precreate.push(pkg_bin_dir);
                }
            }
            let dir_refs: Vec<&Path> = dirs_to_precreate.iter().map(|p| p.as_path()).collect();
            if let Err(e) = precreate_directories(dir_refs) {
                warn!("precreate_directories warning: {e}");
            }
        }
        drop(_plan2_span);
        collector.record_phase(Phase::Plan, plan2_start.elapsed());

        if self.options.install_strategy == InstallStrategy::Linked {
            return self
                .execute_linked_ci(&manifest, &lockfile, &node_modules_dir, &bin_dir, collector)
                .await;
        }

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
                let mut member_deps: Vec<String> =
                    member.manifest.dependencies.keys().cloned().collect();
                if !self.options.omit_dev {
                    for (dep_name, dep_spec) in &member.manifest.dev_dependencies {
                        let is_sibling = ws_graph_opt
                            .as_ref()
                            .map(|g| g.is_member(dep_name))
                            .unwrap_or(false)
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

        let mut packages_to_process: Vec<CiPackage> = Vec::new();

        for (pkg_key, pkg_info) in &lockfile.packages {
            if pkg_key.is_empty() {
                continue;
            }

            // Omit filtering
            let is_dev = pkg_info.dev.unwrap_or(false);
            let is_optional = pkg_info.is_effective_optional() || pkg_info.is_peer_optional();
            let is_dev_optional = pkg_info.dev_optional.unwrap_or(false);
            let is_peer = pkg_info.peer.unwrap_or(false) || pkg_info.peer_optional.unwrap_or(false);

            if self.options.omit_dev {
                if is_dev || is_dev_optional {
                    continue;
                }
                if let Some(clean_name) = pkg_key.strip_prefix("node_modules/") {
                    if !clean_name.contains('/')
                        && manifest.dev_dependencies.contains_key(clean_name)
                        && !manifest.dependencies.contains_key(clean_name)
                    {
                        continue;
                    }
                }
            }
            if self.options.omit_optional {
                if is_optional || is_dev_optional {
                    continue;
                }
                if let Some(clean_name) = pkg_key.strip_prefix("node_modules/") {
                    if !clean_name.contains('/')
                        && manifest.optional_dependencies.contains_key(clean_name)
                        && !manifest.dependencies.contains_key(clean_name)
                    {
                        continue;
                    }
                }
            }
            if self.options.omit_peer || self.options.legacy_peer_deps {
                if is_peer {
                    continue;
                }
                if let Some(clean_name) = pkg_key.strip_prefix("node_modules/") {
                    if !clean_name.contains('/')
                        && manifest.peer_dependencies.contains_key(clean_name)
                        && !manifest.dependencies.contains_key(clean_name)
                    {
                        continue;
                    }
                }
            }

            if platform_skipped_packages.contains(pkg_key) {
                debug!("Skipping lockfile package {pkg_key} because its optional platform ancestor is incompatible");
                continue;
            }

            // Handle workspace links
            if pkg_info.link == Some(true) {
                // Path containment defense: ensure pkg_key has no traversal, device names, or escapes
                if pkg_key.contains("..")
                    || pkg_key.contains(':')
                    || pkg_key.contains('\\')
                    || pkg_key.contains('\0')
                {
                    return Err(anyhow!(
                        "Package lock entry '{pkg_key}' contains illegal path characters"
                    ));
                }
                rnpm_fs::validate_entry_path(Path::new(pkg_key))
                    .map_err(|e| anyhow!("Invalid package path in lockfile '{pkg_key}': {e}"))?;

                let full_target = self.options.project_dir.join(pkg_key);
                let cleaned = path_clean::clean(&full_target);
                if !cleaned.starts_with(&self.options.project_dir) {
                    return Err(anyhow!(
                        "Package path '{cleaned:?}' escapes project boundary"
                    ));
                }
                if pkg_key.starts_with("node_modules/") && !cleaned.starts_with(&node_modules_dir) {
                    return Err(anyhow!(
                        "Package path '{cleaned:?}' escapes node_modules boundary"
                    ));
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
                rnpm_fs::create_junction(&link_path, &target_dir).map_err(|e| {
                    anyhow!(
                        "Failed to link workspace package at '{}': {e}",
                        link_path.display()
                    )
                })?;

                packages_installed += 1;

                let pkg_manifest_path = target_dir.join("package.json");
                if pkg_manifest_path.exists() {
                    if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                        let clean_pkg_name =
                            pkg_key.strip_prefix("node_modules/").unwrap_or(pkg_key);
                        if !workspace_members.iter().any(|m| m.name == clean_pkg_name) {
                            let has_scripts = pkg_manifest.scripts.contains_key("preinstall")
                                || pkg_manifest.scripts.contains_key("install")
                                || pkg_manifest.scripts.contains_key("postinstall")
                                || pkg_manifest.scripts.contains_key("prepare");

                            if has_scripts {
                                let mut member_deps: Vec<String> =
                                    pkg_manifest.dependencies.keys().cloned().collect();
                                for (dep_name, dep_spec) in &pkg_manifest.dev_dependencies {
                                    let is_sibling = dep_spec.starts_with("workspace:")
                                        || lockfile
                                            .packages
                                            .contains_key(&format!("node_modules/{dep_name}"));
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
            if pkg_key.contains("..")
                || pkg_key.contains(':')
                || pkg_key.contains('\\')
                || pkg_key.contains('\0')
            {
                return Err(anyhow!(
                    "Package lock entry '{pkg_key}' contains illegal path characters"
                ));
            }
            rnpm_fs::validate_entry_path(Path::new(pkg_key))
                .map_err(|e| anyhow!("Invalid package path in lockfile '{pkg_key}': {e}"))?;

            let full_target = loc_base_dir.join(pkg_key);
            let cleaned = path_clean::clean(&full_target);
            if !cleaned.starts_with(&loc_base_dir) {
                return Err(anyhow!(
                    "Package path '{cleaned:?}' escapes project boundary"
                ));
            }
            if !cleaned.starts_with(&node_modules_dir) {
                return Err(anyhow!(
                    "Package path '{cleaned:?}' escapes node_modules boundary"
                ));
            }

            let is_optional = pkg_info.is_effective_optional()
                || pkg_info.is_peer_optional()
                || pkg_info.optional == Some(true);

            // Filter optional dependencies by platform: os, cpu, libc
            if is_optional {
                let host_platform = self.options.platform();
                let os_match = rnpm_solver::is_platform_compatible(
                    &host_platform,
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
                        return Err(anyhow!(
                            "Package {} missing resolved URL in lockfile",
                            pkg_key
                        ));
                    }
                }
            };

            let is_git = resolved_url.starts_with("git+")
                || resolved_url.starts_with("git:")
                || PackageTarget::parse(resolved_url)
                    .map(|t| t.is_git())
                    .unwrap_or(false);

            if is_git {
                let git_fetcher = crate::git::GitFetcher::new(self.cache.root());
                let target = PackageTarget::parse(resolved_url)
                    .map_err(|e| anyhow!("Failed to parse git target in lockfile: {e}"))?;
                let t_fetch = std::time::Instant::now();
                let _f_span = tracing::info_span!("fetch", package = %pkg_key).entered();
                let checkout_dir = git_fetcher
                    .checkout_git_dependency(&target, self.options.offline)
                    .await?;
                drop(_f_span);
                collector.record_phase(Phase::Fetch, t_fetch.elapsed());

                let t_mat = std::time::Instant::now();
                let _mat_span = tracing::info_span!("materialize", package = %pkg_key).entered();
                crate::git::copy_dir_all(&checkout_dir, &full_target)?;
                drop(_mat_span);
                collector.record_phase(Phase::Materialize, t_mat.elapsed());

                packages_installed += 1;
                cache_hits += 1;
                collector.record_cache_hit();

                let pkg_manifest_path = full_target.join("package.json");
                if pkg_manifest_path.exists() {
                    if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                        let has_scripts = pkg_manifest.scripts.contains_key("preinstall")
                            || pkg_manifest.scripts.contains_key("install")
                            || pkg_manifest.scripts.contains_key("postinstall")
                            || pkg_manifest.scripts.contains_key("prepare");
                        if has_scripts {
                            let deps = pkg_info
                                .dependencies
                                .as_ref()
                                .map(|d| d.keys().cloned().collect())
                                .unwrap_or_else(|| {
                                    pkg_manifest.dependencies.keys().cloned().collect()
                                });
                            lifecycle_nodes.push(LifecyclePackageNode {
                                package_path: pkg_key.clone(),
                                disk_path: full_target.clone(),
                                manifest: pkg_manifest,
                                source: PackageSource::Git,
                                dependencies: deps,
                                optional: is_optional,
                            });
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
                            return Err(anyhow!(
                                "Package {} has invalid integrity in lockfile: {}",
                                pkg_key,
                                e
                            ));
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
                        return Err(anyhow!(
                            "Package {} missing or empty integrity in lockfile",
                            pkg_key
                        ));
                    }
                }
            };

            let deps = pkg_info
                .dependencies
                .as_ref()
                .map(|d| d.keys().cloned().collect())
                .unwrap_or_default();

            let has_bin = match &pkg_info.bin {
                Some(rnpm_lockfile::PackageBin::Single(_)) => true,
                Some(rnpm_lockfile::PackageBin::Map(m)) => !m.is_empty(),
                None => false,
            };
            let has_scripts = pkg_info.has_install_script.unwrap_or(false);
            let has_bins_or_scripts = has_bin || has_scripts;

            packages_to_process.push((
                pkg_key.clone(),
                resolved_url.clone(),
                integrity_str.to_string(),
                is_optional,
                deps,
                has_bins_or_scripts,
            ));
        }

        if self.options.offline {
            for (pkg_key, resolved_url, integrity_str, is_optional, _, _) in &packages_to_process {
                if resolved_url.starts_with("file:") {
                    continue;
                }
                if !integrity_str.is_empty() && self.pack_store.has_package_pack(integrity_str) {
                    continue;
                }
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

        let ci_writer_cfg = Arc::clone(&self.writer_cfg);

        let all_packs_available = !packages_to_process.is_empty()
            && packages_to_process
                .iter()
                .all(|(_, _, integrity_str, _, _, _)| {
                    !integrity_str.is_empty() && self.pack_store.has_package_pack(integrity_str)
                });

        let mut used_fast_path = false;
        let mut bin_packages = packages_to_process.clone();
        sort_packages_for_bin_linking(&mut bin_packages);

        if all_packs_available {
            let t_mat = std::time::Instant::now();
            let mut all_dirs = std::collections::BTreeSet::new();
            all_dirs.insert(node_modules_dir.clone());
            all_dirs.insert(bin_dir.clone());

            for (pkg_key, _, _, _, _, _) in &packages_to_process {
                let pkg_target = loc_base_dir.join(pkg_key);
                if rnpm_fs::is_junction(&pkg_target).unwrap_or(false) {
                    let _ = rnpm_fs::remove_junction(&pkg_target);
                }
                all_dirs.insert(pkg_target.clone());
                if let Some(parent) = pkg_target.parent() {
                    all_dirs.insert(parent.to_path_buf());
                }
            }

            let (loaded_packs, mut load_success) =
                crate::fast_path::parallel_load_packs(&self.pack_store, &loc_base_dir, &packages_to_process);

            if load_success {
                let mut all_file_refs = Vec::with_capacity(16384);
                let mut all_symlinks = Vec::new();

                'load_files: for (pkg_key, pkg_target, pack) in &loaded_packs {
                    for entry in &pack.index.files {
                        let full_path = pkg_target.join(&entry.path);
                        if let Some(parent) = full_path.parent() {
                            all_dirs.insert(parent.to_path_buf());
                        }
                        if let Some(slice) = pack.get_file_slice(&entry.path) {
                            all_file_refs.push(rnpm_fs::MaterializeFileRef {
                                path: full_path,
                                data: slice,
                                mode: entry.mode,
                                package_id: Some(pkg_key.as_str()),
                                source_path: entry.cas_path.as_deref(),
                                expected_sha256: entry.sha256.as_deref(),
                                source_verified: entry.cas_verified,
                            });
                        } else {
                            warn!(
                                "Corrupted pack: missing file slice for '{}' in pack '{}'. Falling back to standard extraction.",
                                entry.path, pkg_key
                            );
                            load_success = false;
                            break 'load_files;
                        }
                    }
                    for (link_rel, target_rel) in &pack.index.symlinks {
                        all_symlinks.push((pkg_target.join(link_rel), pkg_target.join(target_rel)));
                    }
                }

                if load_success {
                    used_fast_path = true;

                    // 1. Precreate all directories breadth-first in a single pass
                    let dir_refs: Vec<&Path> = all_dirs.iter().map(|p| p.as_path()).collect();
                    precreate_directories(dir_refs)
                        .map_err(|e| anyhow!("Failed to precreate directories: {e}"))?;

                    // Prepare bin linking and hidden lockfile data to overlap with materialize
                    let ci_tree_packages: Vec<String> = lockfile
                        .packages
                        .keys()
                        .filter(|k| {
                            if k.is_empty() {
                                return false;
                            }
                            if platform_skipped_packages.contains(*k) {
                                return false;
                            }
                            if let Some(info) = lockfile.packages.get(*k) {
                                if info.link == Some(true) {
                                    return true;
                                }
                            }
                            k.starts_with("node_modules/")
                        })
                        .cloned()
                        .collect();

                    let known_bins = crate::fast_path::build_known_bins_map(&lockfile);
                    let save_hidden_needed = self.options.package_lock_enabled() && !self.options.dry_run;
                    let project_dir_ref = &self.options.project_dir;
                    let lockfile_ref = &lockfile;
                    let loc_base_ref = &loc_base_dir;
                    let bin_dir_ref = &bin_dir;
                    let nm_dir_ref = &node_modules_dir;

                    // Overlap materialize tail with bin link phase
                    let (bin_time, mat_res) = std::thread::scope(|s| {
                        let bin_handle = s.spawn(|| {
                            let t_start = std::time::Instant::now();
                            link_tree_bins(
                                ci_tree_packages,
                                Some(&known_bins),
                                loc_base_ref,
                                bin_dir_ref,
                                nm_dir_ref,
                                true,
                                None,
                            );
                            t_start.elapsed()
                        });

                        let mat_res = rnpm_fs::materialize_files_parallel_refs(all_file_refs, &ci_writer_cfg);
                        let bin_time = bin_handle.join().unwrap_or_default();

                        (bin_time, mat_res)
                    });

                    mat_res.map_err(|e| anyhow!("{e}"))?;
                    collector.record_phase(Phase::Materialize, t_mat.elapsed());
                    collector.record_phase(Phase::Bins, bin_time);

                    if save_hidden_needed {
                        let t_lock = std::time::Instant::now();
                        let _ = lockfile_ref.save_hidden(project_dir_ref);
                        collector.record_phase(Phase::Lockfile, t_lock.elapsed());
                    }

                    // 3. Recreate symlinks (directories via junctions, files via symlink or copy)
                    for (link_path, target_path) in all_symlinks {
                        if let Err(e) = rnpm_fs::create_link_or_copy(&link_path, &target_path) {
                            warn!(
                                "Failed to create link or copy from '{}' to '{}': {e}",
                                link_path.display(),
                                target_path.display()
                            );
                        }
                    }

                    // 4. Process lifecycle scripts directly from in-memory pack slices
                    let pack_map: HashMap<&str, &rnpm_cache::PackagePack> = loaded_packs
                        .iter()
                        .map(|(k, _, p)| (k.as_str(), p))
                        .collect();

                    for (
                        pkg_key,
                        resolved_url,
                        _,
                        is_optional,
                        declared_dependencies,
                        has_bins_or_scripts,
                    ) in &bin_packages
                    {
                        let target_path = loc_base_dir.join(pkg_key);
                        if *has_bins_or_scripts {
                            let mut found_node = None;
                            if let Some(pack) = pack_map.get(pkg_key.as_str()) {
                                if let Some(slice) = pack.get_file_slice("package.json") {
                                    if let Ok(pkg_manifest) = Manifest::from_slice(slice) {
                                        found_node = lifecycle_node_for_manifest(
                                            &target_path,
                                            pkg_key,
                                            resolved_url,
                                            declared_dependencies,
                                            *is_optional,
                                            pkg_manifest,
                                        );
                                    }
                                }
                            }
                            if found_node.is_none() {
                                found_node = process_installed_pkg_manifest_without_bins(
                                    &target_path,
                                    pkg_key,
                                    resolved_url,
                                    declared_dependencies,
                                    *is_optional,
                                );
                            }
                            if let Some(l_node) = found_node {
                                lifecycle_nodes.push(l_node);
                            }
                        }
                        packages_installed += 1;
                        cache_hits += 1;
                        collector.record_cache_hit();
                    }
                }
            }
            if !used_fast_path {
                collector.record_phase(Phase::Materialize, t_mat.elapsed());
            }
        }

        if !used_fast_path {
            let semaphore = Arc::clone(&self.io_semaphore);
            let mut join_set = tokio::task::JoinSet::new();

            for (
                pkg_key,
                resolved_url,
                integrity_str,
                is_optional,
                declared_dependencies,
                has_bins_or_scripts,
            ) in &packages_to_process
            {
                let sem = Arc::clone(&semaphore);
                let cache = self.cache.clone();
                let pack_store = Arc::clone(&self.pack_store);
                let registry_client = self.registry_client.clone();
                let project_dir = loc_base_dir.clone();
                let offline = self.options.offline;
                let worker_collector = collector.clone();
                let pkg_writer_cfg = Arc::clone(&ci_writer_cfg);
                let pkg_key = pkg_key.clone();
                let resolved_url = resolved_url.clone();
                let integrity_str = integrity_str.clone();
                let is_optional = *is_optional;
                let declared_dependencies = declared_dependencies.clone();
                let has_bins_or_scripts = *has_bins_or_scripts;

                join_set.spawn(async move {
                    let _permit = sem.acquire().await.map_err(|e| anyhow!("{e}"))?;

                    let target_path = project_dir.join(&pkg_key);
                    if rnpm_fs::is_junction(&target_path).unwrap_or(false) {
                        let _ = rnpm_fs::remove_junction(&target_path);
                    }

                    // 1. Warm CI Pack Store check: if pack exists, materialize directly from pack!
                    if !integrity_str.is_empty() && pack_store.has_package_pack(&integrity_str) {
                        let t_mat = std::time::Instant::now();
                        let target_clone = target_path.clone();
                        let ps_clone = Arc::clone(&pack_store);
                        let integ_clone = integrity_str.clone();
                        let cfg_clone = Arc::clone(&pkg_writer_cfg);
                        let key_clone = pkg_key.clone();

                        let mat_res = tokio::task::spawn_blocking(move || {
                            let _mat_span =
                                tracing::info_span!("materialize", package = %key_clone).entered();
                            let res = ps_clone.materialize_pack_opt(
                                &integ_clone,
                                &target_clone,
                                Some(&cfg_clone),
                                true,
                            );
                            drop(_mat_span);
                            res
                        })
                        .await?;
                        worker_collector.record_phase(Phase::Materialize, t_mat.elapsed());

                        match mat_res {
                            Ok(_) => {
                                let lifecycle_node = if has_bins_or_scripts {
                                    process_installed_pkg_manifest_without_bins(
                                        &target_path,
                                        &pkg_key,
                                        &resolved_url,
                                        &declared_dependencies,
                                        is_optional,
                                    )
                                } else {
                                    None
                                };
                                return Ok(Some((true, lifecycle_node)));
                            }
                            Err(e) => {
                                if e.is_pack_corruption() {
                                    warn!("Warm CI materialize_pack failed for {pkg_key}: {e}. Purging pack and falling back to tarball fetch.");
                                    let _ = pack_store.purge(&integrity_str);
                                    let _ = std::fs::remove_dir_all(&target_path);
                                } else {
                                    return Err(anyhow!(
                                        "Warm CI materialize_pack failed for {pkg_key}: {e}"
                                    ));
                                }
                            }
                        }
                    }

                    // 2. Local archive or registry download
                    let (bytes, was_hit) = if resolved_url.starts_with("file:") {
                        let file_path = resolved_url.strip_prefix("file:").unwrap().trim();
                        if file_path.contains('\0') {
                            return Err(anyhow!(
                                "Resolved file URL contains null bytes: {resolved_url}"
                            ));
                        }
                        let clean_project_dir = path_clean::clean(&project_dir);
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
                        if let (Ok(canon_proj), Ok(canon_file)) = (
                            clean_project_dir.canonicalize(),
                            clean_file_path.canonicalize(),
                        ) {
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
                                warn!(
                                    "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Archive {} not found",
                                    clean_file_path.display()
                                );
                                return Ok(None);
                            } else {
                                return Err(anyhow!(
                                    "Archive file not found: {}",
                                    clean_file_path.display()
                                ));
                            }
                        }
                        let bytes = std::fs::read(&clean_file_path).with_context(|| {
                            format!(
                                "Failed to read local archive file '{}'",
                                clean_file_path.display()
                            )
                        })?;

                        let expected_integrity: Integrity = integrity_str
                            .parse()
                            .map_err(|e| anyhow!("Invalid integrity hash: {e}"))?;
                        if let Err(e) = expected_integrity.verify(&bytes) {
                            if is_optional {
                                warn!(
                                    "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for local archive {pkg_key}: {e}"
                                );
                                return Ok(None);
                            } else {
                                return Err(anyhow!(
                                    "Integrity verification failed for local archive {pkg_key}: {e}"
                                ));
                            }
                        }
                        (bytes, true)
                    } else {
                        let expected_integrity: Integrity = integrity_str
                            .parse()
                            .map_err(|e| anyhow!("Invalid integrity hash: {e}"))?;

                        let t_fetch = std::time::Instant::now();
                        let fetch_res = if let Ok(Some((_entry, data))) = cache.get(&resolved_url) {
                            if expected_integrity.verify(&data).is_ok() {
                                Ok((data, true))
                            } else {
                                debug!("Cached blob for {pkg_key} failed integrity, purging and re-fetching");
                                let _ = cache.purge_key(&resolved_url);
                                if offline {
                                    if is_optional {
                                        return Ok(None);
                                    }
                                    return Err(anyhow!(
                                        "npm error code EINTEGRITY\nnpm error Integrity verification failed for cached package {pkg_key}"
                                    ));
                                }
                                match registry_client.download_tarball_bytes(&resolved_url).await {
                                    Ok(fresh_bytes) => {
                                        if let Err(fresh_err) = expected_integrity.verify(&fresh_bytes) {
                                            if is_optional {
                                                warn!(
                                                    "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {pkg_key}: {fresh_err}"
                                                );
                                                return Ok(None);
                                            } else {
                                                return Err(anyhow!("Integrity verification failed for {pkg_key}: {fresh_err}"));
                                            }
                                        }
                                        let t_sw = std::time::Instant::now();
                                        let _ = cache.put_with_integrity(&resolved_url, &fresh_bytes, Some(&expected_integrity), None);
                                        worker_collector.record_phase(Phase::StoreWrite, t_sw.elapsed());
                                        Ok((fresh_bytes, false))
                                    }
                                    Err(e) => Err(anyhow!("Failed to download tarball from {resolved_url}: {e}")),
                                }
                            }
                        } else if offline {
                            if is_optional {
                                warn!("npm warn optional SKIPPING OPTIONAL DEPENDENCY: Package {pkg_key} not found in local cache (--offline)");
                                return Ok(None);
                            }
                            return Err(anyhow!(
                                "npm error code ENOTCACHED\nnpm error request to download tarball from '{resolved_url}' failed: cache mode is 'only-if-cached' (--offline) but no cached response is available."
                            ));
                        } else {
                            match registry_client.download_tarball_bytes(&resolved_url).await {
                                Ok(fresh_bytes) => {
                                    if let Err(fresh_err) = expected_integrity.verify(&fresh_bytes) {
                                        if is_optional {
                                            warn!(
                                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: Integrity verification failed for {pkg_key}: {fresh_err}"
                                            );
                                            return Ok(None);
                                        } else {
                                            return Err(anyhow!("Integrity verification failed for {pkg_key}: {fresh_err}"));
                                        }
                                    }
                                    let t_sw = std::time::Instant::now();
                                    let _ = cache.put_with_integrity(&resolved_url, &fresh_bytes, Some(&expected_integrity), None);
                                    worker_collector.record_phase(Phase::StoreWrite, t_sw.elapsed());
                                    Ok((fresh_bytes, false))
                                }
                                Err(e) => Err(anyhow!("Failed to download tarball from {resolved_url}: {e}")),
                            }
                        };
                        worker_collector.record_phase(Phase::Fetch, t_fetch.elapsed());

                        match fetch_res {
                            Ok(res) => res,
                            Err(err) => {
                                if is_optional {
                                    warn!("npm warn optional SKIPPING OPTIONAL DEPENDENCY: Failed to fetch {pkg_key}: {err}");
                                    return Ok(None);
                                } else {
                                    return Err(err);
                                }
                            }
                        }
                    };

                    // Construct pack in pack store if not present (deferred CAS write)
                    if !integrity_str.is_empty() && !pack_store.has_package_pack(&integrity_str) {
                        let t_sw = std::time::Instant::now();
                        let _ = pack_store.put_package_from_tarball_deferred(&integrity_str, &bytes);
                        worker_collector.record_phase(Phase::StoreWrite, t_sw.elapsed());
                    }

                    // Materialize via spawn_blocking
                    let target_clone = target_path.clone();
                    let cfg_clone = Arc::clone(&pkg_writer_cfg);
                    let ps_clone = Arc::clone(&pack_store);
                    let integ_clone = integrity_str.clone();
                    let key_clone = pkg_key.clone();

                    let extract_res = tokio::task::spawn_blocking(move || {
                        if !integ_clone.is_empty() && ps_clone.has_package_pack(&integ_clone) {
                            match ps_clone.materialize_pack(&integ_clone, &target_clone, Some(&cfg_clone)) {
                                Ok(sum) => Ok(sum),
                                Err(e) => {
                                    if e.is_pack_corruption() {
                                        warn!("materialize_pack failed: {e}, purging pack and falling back to tarball extraction");
                                        let _ = ps_clone.purge(&integ_clone);
                                        let _ = std::fs::remove_dir_all(&target_clone);
                                        extract_tarball_direct(Cursor::new(&bytes), &target_clone, None, Some(&cfg_clone))
                                            .map_err(|e| anyhow!("{e}"))
                                    } else {
                                        Err(anyhow!("Failed to materialize package {key_clone}: {e}"))
                                    }
                                }
                            }
                        } else {
                            extract_tarball_direct(Cursor::new(&bytes), &target_clone, None, Some(&cfg_clone))
                                .map_err(|e| anyhow!("{e}"))
                        }
                    }).await??;

                    worker_collector.record_phase(Phase::Materialize, extract_res.materialize_duration);
                    worker_collector.record_phase(Phase::Inflate, extract_res.inflate_duration);

                    let lifecycle_node = if has_bins_or_scripts {
                        process_installed_pkg_manifest_without_bins(
                            &target_path,
                            &pkg_key,
                            &resolved_url,
                            &declared_dependencies,
                            is_optional,
                        )
                    } else {
                        None
                    };

                    Ok(Some((was_hit, lifecycle_node)))
                });
            }

            while let Some(join_res) = join_set.join_next().await {
                let item_opt =
                    join_res.map_err(|e| anyhow!("CI reification worker panicked: {e}"))??;
                if let Some((was_hit, lifecycle_node)) = item_opt {
                    if was_hit {
                        cache_hits += 1;
                        collector.record_cache_hit();
                    } else {
                        cache_misses += 1;
                        collector.record_cache_miss();
                    }
                    packages_installed += 1;
                    if let Some(l_node) = lifecycle_node {
                        lifecycle_nodes.push(l_node);
                    }
                }
            }

            // Fill CAS by copying from node_modules on 16 threads for cold installs
            let mut cas_copy_list = Vec::new();
            for (pkg_key, _, integrity_str, _, _, _) in &packages_to_process {
                if !integrity_str.is_empty() {
                    if let Ok(Some(pack)) = self.pack_store.get_package_pack(integrity_str) {
                        for entry in &pack.index.files {
                            if let Some(ref cas_path) = entry.cas_path {
                                let src = loc_base_dir.join(pkg_key).join(&entry.path);
                                cas_copy_list.push((src, cas_path.clone()));
                            }
                        }
                    }
                }
            }
            if !cas_copy_list.is_empty() {
                let t_cas = std::time::Instant::now();
                self.pack_store.populate_cas_from_installed(&cas_copy_list);
                collector.record_phase(Phase::StoreWrite, t_cas.elapsed());
            }
        }

        if !used_fast_path {
            // Link all package bins across the tree in shallowest-first order with first-writer-wins
            // per .bin directory in this run, overwriting shims and cleaning up stale ones.
            let ci_tree_packages: Vec<String> = lockfile
                .packages
                .keys()
                .filter(|k| {
                    if k.is_empty() {
                        return false;
                    }
                    if platform_skipped_packages.contains(*k) {
                        return false;
                    }
                    if let Some(info) = lockfile.packages.get(*k) {
                        if info.link == Some(true) {
                            return true;
                        }
                    }
                    k.starts_with("node_modules/")
                })
                .cloned()
                .collect();

            let known_bins = crate::fast_path::build_known_bins_map(&lockfile);

            link_tree_bins(
                ci_tree_packages,
                Some(&known_bins),
                &loc_base_dir,
                &bin_dir,
                &node_modules_dir,
                true,
                Some(&collector),
            );
        }

        // Execute lifecycle scripts bottom-up followed by root hooks
        if !self.options.ignore_scripts {
            let _life_guard = collector.enter_phase(Phase::Lifecycle);
            let sandbox_policy = if self.options.strict_sandbox {
                rnpm_lifecycle::ScriptSandboxPolicy::restricted()
            } else {
                rnpm_lifecycle::ScriptSandboxPolicy::permissive()
            };
            let lifecycle_opts = LifecycleOptions {
                root_dir: self.options.project_dir.clone(),
                init_cwd: self.options.project_dir.clone(),
                ignore_scripts: false,
                capture_output: !self.options.foreground_scripts,
                foreground_scripts: self.options.foreground_scripts,
                timeout: None,
                sandbox_policy,
            };
            execute_topological(&lifecycle_nodes, &manifest, &lifecycle_opts).await?;
        }

        // Persist hidden lockfile to node_modules/.package-lock.json unless package-lock is disabled
        if !used_fast_path && self.options.package_lock_enabled() && !self.options.dry_run {
            let _lock_guard = collector.enter_phase(Phase::Lockfile);
            lockfile
                .save_hidden(&self.options.project_dir)
                .context("Failed to save hidden package-lock.json")?;
        }

        if !self.options.dry_run && !self.options.package_lock_only {
            if let Ok(fingerprint) =
                compute_project_fingerprint(&self.options.project_dir, &self.options)
            {
                let _ = self
                    .cache
                    .set_project_fingerprint(&self.options.project_dir, &fingerprint);
            }
        }

        clean_empty_bin_dirs(&node_modules_dir);

        Ok(InstallSummary {
            packages_installed,
            cache_hits,
            cache_misses,
            lockfile_path,
            timing: Some(collector.finish()),
        })
    }

    /// Fill lockfile metadata that the abbreviated install packument omits.
    /// Requests are deduplicated and run concurrently; offline installs keep
    /// the metadata already available in the lockfile/cache.
    async fn enrich_lockfile_from_registry(&mut self, lockfile: &mut LockfileV3) -> Result<()> {
        if self.options.offline {
            return Ok(());
        }

        let mut names = std::collections::BTreeSet::new();
        for (location, package) in &lockfile.packages {
            if location.is_empty()
                || package.link == Some(true)
                || (package.license.is_some() && package.libc.is_some())
            {
                continue;
            }
            let name = package.name.clone().or_else(|| {
                let leaf = location.rsplit("/node_modules/").next().unwrap_or(location);
                location
                    .strip_prefix("node_modules/")
                    .map(|_| leaf.to_string())
            });
            if let Some(name) = name {
                names.insert(name);
            }
        }

        let client = self.registry_client.clone();
        let mut jobs = tokio::task::JoinSet::new();
        for name in names {
            let client = client.clone();
            jobs.spawn(async move {
                let result = client.get_package_metadata_full(&name).await;
                (name, result)
            });
        }

        while let Some(result) = jobs.join_next().await {
            let (name, metadata) =
                result.map_err(|e| anyhow!("metadata enrichment task failed: {e}"))?;
            if let Ok(metadata) = metadata {
                self.metadata_cache.insert(name, metadata);
            }
        }

        for (location, package) in &mut lockfile.packages {
            if location.is_empty() {
                continue;
            }
            let Some(name) = package.name.clone().or_else(|| {
                location.strip_prefix("node_modules/").map(|leaf| {
                    leaf.rsplit("/node_modules/")
                        .next()
                        .unwrap_or(leaf)
                        .to_string()
                })
            }) else {
                continue;
            };
            let Some(version) = package.version.as_deref() else {
                continue;
            };
            let Some(metadata) = self.metadata_cache.get(&name) else {
                continue;
            };
            let Some(version_meta) = metadata.versions.get(version) else {
                continue;
            };

            if package.license.is_none() {
                package.license = version_meta.license.clone();
            }
            if package.engines.is_none() && !version_meta.engines.is_empty() {
                package.engines = Some(rnpm_lockfile::PackageEngines::Map(
                    version_meta
                        .engines
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                ));
            }
            if package.os.is_none() && !version_meta.os.is_empty() {
                package.os = Some(version_meta.os.clone());
            }
            if package.cpu.is_none() && !version_meta.cpu.is_empty() {
                package.cpu = Some(version_meta.cpu.clone());
            }
            if package.libc.is_none() && !version_meta.libc.is_empty() {
                package.libc = Some(version_meta.libc.clone());
            }
            for key in ["funding", "deprecated"] {
                if let Some(value) = version_meta.extra.get(key) {
                    if key == "deprecated"
                        && (value == &serde_json::Value::Bool(false)
                            || value.is_null()
                            || value == "")
                    {
                        continue;
                    }
                    package.extra.insert(key.to_string(), value.clone());
                }
            }
        }

        Ok(())
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
                    rnpm_core::manifest::PackageBin::Single(s) => {
                        rnpm_lockfile::PackageBin::Single(s.clone())
                    }
                    rnpm_core::manifest::PackageBin::Map(map) => {
                        rnpm_lockfile::PackageBin::Map(map.clone())
                    }
                });

                let ver_meta = PackageVersionMetadata {
                    name: name.clone(),
                    version: version.clone(),
                    dist_tarball: Some(resolved.resolved_url.clone()),
                    dist_integrity: None,
                    dependencies: m.dependencies.clone(),
                    dependency_order: m.dependencies.keys().cloned().collect(),
                    dev_dependencies: m.dev_dependencies.clone(),
                    peer_dependencies: m.peer_dependencies.clone(),
                    peer_dependencies_meta: m.peer_dependencies_meta.clone(),
                    optional_dependencies: m.optional_dependencies.clone(),
                    os: m.os.clone(),
                    cpu: m.cpu.clone(),
                    libc: m.libc.clone(),
                    bin,
                    license: m
                        .extra
                        .get("license")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    engines: m.engines.clone(),
                    has_install_script: m.scripts.contains_key("install")
                        || m.scripts.contains_key("postinstall")
                        || m.scripts.contains_key("preinstall"),
                    deprecated: None,
                    extra: m.extra.clone(),
                };

                let mut dist_tags = BTreeMap::new();
                dist_tags.insert("latest".to_string(), version.clone());
                let mut versions = BTreeMap::new();
                versions.insert(version.clone(), ver_meta);

                if let Ok(mut locked) = cache.lock() {
                    locked.insert(
                        name.clone(),
                        PackageMetadata {
                            name: name.clone(),
                            dist_tags: dist_tags.clone(),
                            versions: versions.clone(),
                        },
                    );
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
                            )
                            .to_string();

                            let m =
                                inspect_manifest_from_tarball(&archive_bytes).unwrap_or_default();
                            let version = m.version.clone().unwrap_or_else(|| "1.0.0".to_string());
                            let posix_rel = rnpm_core::to_posix_path(file_spec_clean);
                            let resolved_url = format!("file:{posix_rel}");

                            let bin = m.bin.as_ref().map(|b| match b {
                                rnpm_core::manifest::PackageBin::Single(s) => {
                                    rnpm_lockfile::PackageBin::Single(s.clone())
                                }
                                rnpm_core::manifest::PackageBin::Map(map) => {
                                    rnpm_lockfile::PackageBin::Map(map.clone())
                                }
                            });

                            let ver_meta = PackageVersionMetadata {
                                name: name.clone(),
                                version: version.clone(),
                                dist_tarball: Some(resolved_url),
                                dist_integrity: Some(integrity),
                                dependencies: m.dependencies.clone(),
                                dependency_order: m.dependencies.keys().cloned().collect(),
                                dev_dependencies: m.dev_dependencies.clone(),
                                peer_dependencies: m.peer_dependencies.clone(),
                                peer_dependencies_meta: m.peer_dependencies_meta.clone(),
                                optional_dependencies: m.optional_dependencies.clone(),
                                os: m.os.clone(),
                                cpu: m.cpu.clone(),
                                libc: m.libc.clone(),
                                bin,
                                license: m
                                    .extra
                                    .get("license")
                                    .and_then(|v| v.as_str())
                                    .map(str::to_owned),
                                engines: m.engines.clone(),
                                has_install_script: m.scripts.contains_key("install")
                                    || m.scripts.contains_key("postinstall")
                                    || m.scripts.contains_key("preinstall"),
                                deprecated: None,
                                extra: m.extra.clone(),
                            };

                            let mut dist_tags = BTreeMap::new();
                            dist_tags.insert("latest".to_string(), version.clone());
                            let mut versions = BTreeMap::new();
                            versions.insert(version, ver_meta);

                            if let Ok(mut locked) = cache.lock() {
                                locked.insert(
                                    name.clone(),
                                    PackageMetadata {
                                        name: name.clone(),
                                        dist_tags,
                                        versions,
                                    },
                                );
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
                            rnpm_core::manifest::PackageBin::Single(s) => {
                                rnpm_lockfile::PackageBin::Single(s.clone())
                            }
                            rnpm_core::manifest::PackageBin::Map(map) => {
                                rnpm_lockfile::PackageBin::Map(map.clone())
                            }
                        });

                        let ver_meta = PackageVersionMetadata {
                            name: name.clone(),
                            version: version.clone(),
                            dist_tarball: Some(resolved_url),
                            dist_integrity: None,
                            dependencies: m.dependencies.clone(),
                            dependency_order: m.dependencies.keys().cloned().collect(),
                            dev_dependencies: m.dev_dependencies.clone(),
                            peer_dependencies: m.peer_dependencies.clone(),
                            peer_dependencies_meta: m.peer_dependencies_meta.clone(),
                            optional_dependencies: m.optional_dependencies.clone(),
                            os: m.os.clone(),
                            cpu: m.cpu.clone(),
                            libc: m.libc.clone(),
                            bin,
                            license: m
                                .extra
                                .get("license")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned),
                            engines: m.engines.clone(),
                            has_install_script: m.scripts.contains_key("install")
                                || m.scripts.contains_key("postinstall")
                                || m.scripts.contains_key("preinstall"),
                            deprecated: None,
                            extra: m.extra.clone(),
                        };

                        let mut dist_tags = BTreeMap::new();
                        dist_tags.insert("latest".to_string(), version.clone());
                        let mut versions = BTreeMap::new();
                        versions.insert(version, ver_meta);

                        if let Ok(mut locked) = cache.lock() {
                            locked.insert(
                                name.clone(),
                                PackageMetadata {
                                    name: name.clone(),
                                    dist_tags,
                                    versions,
                                },
                            );
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
                        dependency_order: Vec::new(),
                        dev_dependencies: BTreeMap::new(),
                        peer_dependencies: BTreeMap::new(),
                        peer_dependencies_meta: BTreeMap::new(),
                        optional_dependencies: BTreeMap::new(),
                        os: None,
                        cpu: None,
                        libc: None,
                        bin: None,
                        license: None,
                        engines: BTreeMap::new(),
                        has_install_script: false,
                        deprecated: None,
                        extra: BTreeMap::new(),
                    };
                    let mut dist_tags = BTreeMap::new();
                    dist_tags.insert("latest".to_string(), version.clone());
                    let mut versions = BTreeMap::new();
                    versions.insert(version, ver_meta);

                    if let Ok(mut locked) = cache.lock() {
                        locked.insert(
                            name.clone(),
                            PackageMetadata {
                                name: name.clone(),
                                dist_tags,
                                versions,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
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
                        Err(_) => Manifest {
                            name: Some(name.to_string()),
                            version: Some("1.0.0".to_string()),
                            ..Default::default()
                        },
                    };

                    let version = manifest
                        .version
                        .clone()
                        .unwrap_or_else(|| "1.0.0".to_string());
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
                        format!(
                            "Failed to parse package.json at '{}'",
                            manifest_path.display()
                        )
                    })?;

                    let version = manifest
                        .version
                        .clone()
                        .unwrap_or_else(|| "1.0.0".to_string());
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
            PackageTarget::Alias {
                ref name,
                ref target,
            } => (name.as_str(), target.as_ref()),
            ref other => (name, other),
        };

        let metadata = if let Some(cached) = self.metadata_cache.get(lookup_name) {
            cached.clone()
        } else {
            let meta = self
                .registry_client
                .get_package_metadata(lookup_name)
                .await
                .map_err(|e| anyhow!("Failed to fetch metadata for {lookup_name}: {e}"))?;
            self.metadata_cache
                .insert(lookup_name.to_string(), meta.clone());
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
                let latest_match = metadata.dist_tags.get("latest").and_then(|latest_version| {
                    metadata.versions.get(latest_version).and_then(|latest| {
                        latest
                            .version
                            .parse::<Version>()
                            .ok()
                            .filter(|v| range.satisfies(v))
                            .map(|_| latest_version.clone())
                    })
                });
                if let Some(latest) = latest_match {
                    latest
                } else {
                    let mut matching: Vec<(Version, String)> = Vec::new();
                    for ver_str in metadata.versions.keys() {
                        if let Ok(ver) = ver_str.parse::<Version>() {
                            if range.satisfies(&ver) {
                                matching.push((ver, ver_str.clone()));
                            }
                        }
                    }
                    if matching.is_empty() {
                        return Err(anyhow!(
                            "No matching version found for {}@{}",
                            lookup_name,
                            range
                        ));
                    }
                    matching.sort_by(|a, b| a.0.cmp(&b.0));
                    matching.last().unwrap().1.clone()
                }
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

        let ver_info = metadata
            .versions
            .get(&best_ver_str)
            .ok_or_else(|| anyhow!("Version info missing for {}", best_ver_str))?;

        let integrity = ver_info.dist.integrity.clone().unwrap_or_default();

        let mut deps = BTreeMap::new();
        for (d_name, d_range) in &ver_info.dependencies {
            deps.insert(d_name.clone(), d_range.clone());
        }

        let mut opt_deps = BTreeMap::new();
        for (d_name, d_range) in &ver_info.optional_dependencies {
            opt_deps.insert(d_name.clone(), d_range.clone());
        }

        let os_list = if ver_info.os.is_empty() {
            None
        } else {
            Some(ver_info.os.as_slice())
        };
        let cpu_list = if ver_info.cpu.is_empty() {
            None
        } else {
            Some(ver_info.cpu.as_slice())
        };
        let libc_list = if ver_info.libc.is_empty() {
            None
        } else {
            Some(ver_info.libc.as_slice())
        };

        let host_platform = self.options.platform();
        let compatible = host_platform.matches_with_libc(os_list, cpu_list, libc_list);
        if !compatible && !is_optional {
            return Err(anyhow!(
                "rnpm ERR! code EBADPLATFORM: Unsupported platform for {}@{}: wanted os: {:?}, cpu: {:?}, libc: {:?}",
                name, best_ver_str, ver_info.os, ver_info.cpu, ver_info.libc
            ));
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
    pub async fn fetch_tarballs_concurrent(&self, urls: &[&str]) -> Vec<Result<(Vec<u8>, bool)>> {
        let mut join_set = tokio::task::JoinSet::new();
        let offline = self.options.offline;

        let sem = Arc::clone(&self.io_semaphore);
        for (idx, url) in urls.iter().enumerate() {
            let cache = self.cache.clone();
            let registry_client = self.registry_client.clone();
            let url_str = url.to_string();
            let task_sem = Arc::clone(&sem);

            join_set.spawn(async move {
                let _permit = task_sem.acquire().await;
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

        type DownloadItemResult = Result<(Vec<u8>, bool)>;
        let mut results: Vec<Option<DownloadItemResult>> = (0..urls.len()).map(|_| None).collect();
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
        let bytes = self
            .registry_client
            .download_tarball_bytes(tarball_url)
            .await
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

        let expected_integrity: Integrity = node
            .integrity
            .parse()
            .map_err(|e| anyhow!("Invalid integrity string: {e}"))?;
        expected_integrity
            .verify(bytes)
            .map_err(|e| anyhow!("Integrity verification failed for {}: {e}", node.name))?;

        if !was_hit {
            let _ = self.cache.put_with_integrity(
                &node.resolved_url,
                bytes,
                Some(&expected_integrity),
                None,
            );
        }

        // Path containment defense: ensure node.name has no traversal, device names, or escapes
        if node.name.contains("..")
            || node.name.contains(':')
            || node.name.contains('\\')
            || node.name.contains('\0')
        {
            return Err(anyhow!(
                "Package name '{}' contains illegal path characters",
                node.name
            ));
        }
        rnpm_fs::validate_entry_path(Path::new(&node.name))
            .map_err(|e| anyhow!("Invalid package name '{}': {e}", node.name))?;

        let dest_dir = node_modules_dir.join(&node.name);
        if rnpm_fs::is_junction(&dest_dir).unwrap_or(false) {
            let _ = rnpm_fs::remove_junction(&dest_dir);
        }
        let cleaned_dest = path_clean::clean(&dest_dir);
        if !cleaned_dest.starts_with(node_modules_dir) {
            return Err(anyhow!(
                "Package installation path '{cleaned_dest:?}' escapes node_modules"
            ));
        }
        if dest_dir.is_dir() {
            clean_stale_package_dir(&dest_dir, &format!("node_modules/{}", node.name), None);
        }
        let writer_cfg = Arc::clone(&self.writer_cfg);
        if !self.pack_store.has_package_pack(&node.integrity) {
            let _ = self
                .pack_store
                .put_package_from_tarball(&node.integrity, bytes);
        }
        let extract_res = if self.pack_store.has_package_pack(&node.integrity) {
            match self
                .pack_store
                .materialize_pack(&node.integrity, &dest_dir, Some(&writer_cfg))
            {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.is_pack_corruption() {
                        warn!("materialize_pack failed: {e}, purging pack and falling back to tarball extraction");
                        let _ = self.pack_store.purge(&node.integrity);
                        let _ = std::fs::remove_dir_all(&dest_dir);
                        extract_tarball_direct(
                            Cursor::new(bytes),
                            &dest_dir,
                            None,
                            Some(&writer_cfg),
                        )
                        .map(|_| ())
                        .map_err(|e| anyhow!("{e}"))
                    } else {
                        return Err(anyhow!("Failed to materialize package {}: {e}", node.name));
                    }
                }
            }
        } else {
            extract_tarball_direct(Cursor::new(bytes), &dest_dir, None, Some(&writer_cfg))
                .map(|_| ())
                .map_err(|e| anyhow!("{e}"))
        };
        extract_res.map_err(|e| anyhow!("Failed to extract package {}: {e}", node.name))?;

        let pkg_manifest_path = dest_dir.join("package.json");
        let mut has_install_script = false;
        let mut lifecycle_node = None;

        if pkg_manifest_path.exists() {
            if let Ok(pkg_manifest) = Manifest::from_file(&pkg_manifest_path) {
                let pkg_bin_dir = find_enclosing_bin_dir(&dest_dir, bin_dir, node_modules_dir);
                let _ = std::fs::create_dir_all(&pkg_bin_dir);
                for (bin_name, script_rel) in pkg_manifest.bin_entries() {
                    let target_rel = compute_bin_target_rel(&dest_dir, &pkg_bin_dir, &script_rel);
                    let script_path = dest_dir.join(&script_rel);
                    let _ = normalize_shebang(&script_path);
                    let _ = create_shims(&pkg_bin_dir, &bin_name, &target_rel);
                }

                let is_git = node.resolved_url.starts_with("git+")
                    || node.resolved_url.starts_with("git:")
                    || PackageTarget::parse(&node.resolved_url)
                        .map(|t| t.is_git())
                        .unwrap_or(false);
                let is_file_archive = node.resolved_url.starts_with("file:");
                let source = if is_git {
                    PackageSource::Git
                } else if is_file_archive {
                    PackageSource::LocalTarball
                } else {
                    PackageSource::Registry
                };

                has_install_script = pkg_manifest.scripts.contains_key("preinstall")
                    || pkg_manifest.scripts.contains_key("install")
                    || pkg_manifest.scripts.contains_key("postinstall")
                    || (source.runs_prepare() && pkg_manifest.scripts.contains_key("prepare"));

                lifecycle_node = Some(LifecyclePackageNode {
                    package_path: format!("node_modules/{}", node.name),
                    disk_path: dest_dir.clone(),
                    manifest: pkg_manifest,
                    source,
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
        self.update_with_constraints(targets, &HashMap::new()).await
    }

    /// Run package update workflow with optional vulnerability avoidance constraints.
    pub async fn update_with_constraints(
        &mut self,
        targets: &[String],
        vulnerability_constraints: &HashMap<String, Vec<rnpm_core::semver::Range>>,
    ) -> Result<UpdateSummary> {
        let manifest_path = self.options.project_dir.join("package.json");
        if !manifest_path.exists() {
            return Err(anyhow!(
                "package.json not found in {}",
                self.options.project_dir.display()
            ));
        }

        let manifest =
            Manifest::from_file(&manifest_path).context("Failed to parse project package.json")?;

        let lockfile_path = project_lockfile_path(&self.options.project_dir);
        let existing_lockfile_opt = if lockfile_path.exists() {
            LockfileV3::load_from_file(&lockfile_path).ok()
        } else {
            None
        };

        // Determine which packages to unlock
        let mut unlocked: HashSet<String> = HashSet::new();
        if targets.is_empty() {
            for k in manifest.dependencies.keys() {
                unlocked.insert(k.clone());
            }
            for k in manifest.dev_dependencies.keys() {
                unlocked.insert(k.clone());
            }
            for k in manifest.optional_dependencies.keys() {
                unlocked.insert(k.clone());
            }
        } else {
            for target in targets {
                let pkg_name = if let Some(idx) = target.rfind("/node_modules/") {
                    &target[idx + "/node_modules/".len()..]
                } else if let Some(stripped) = target.strip_prefix("node_modules/") {
                    stripped
                } else if let Some(at) = target.find('@') {
                    if at > 0 && !target.starts_with('@') {
                        &target[..at]
                    } else if let Some(rest) = target.strip_prefix('@') {
                        if let Some(second_at) = rest.find('@') {
                            &target[..second_at + 1]
                        } else {
                            target.as_str()
                        }
                    } else {
                        target.as_str()
                    }
                } else {
                    target.as_str()
                };
                unlocked.insert(pkg_name.to_string());
            }
        }

        for pkg in vulnerability_constraints.keys() {
            unlocked.insert(pkg.clone());
        }

        self.options.unlocked_packages = unlocked;
        self.options.vulnerability_constraints = vulnerability_constraints.clone();

        let install_summary = self.install().await?;

        // Compare old lockfile with newly written lockfile to construct UpdateSummary
        let new_lockfile = LockfileV3::load_from_file(&install_summary.lockfile_path)?;
        let mut updated_packages = Vec::new();
        let mut old_versions = HashMap::new();
        let mut new_versions = HashMap::new();

        if let Some(ref old_lock) = existing_lockfile_opt {
            for (loc, new_pkg) in &new_lockfile.packages {
                if loc.is_empty() {
                    continue;
                }
                let old_ver = old_lock.packages.get(loc).and_then(|p| p.version.clone());
                let new_ver = new_pkg.version.clone();
                if let (Some(ov), Some(nv)) = (old_ver, new_ver) {
                    if ov != nv {
                        let name = new_pkg.name.clone().unwrap_or_else(|| {
                            loc.strip_prefix("node_modules/").unwrap_or(loc).to_string()
                        });
                        old_versions.insert(name.clone(), ov);
                        new_versions.insert(name.clone(), nv);
                        updated_packages.push(name);
                    }
                }
            }
        } else {
            for (loc, new_pkg) in &new_lockfile.packages {
                if loc.is_empty() {
                    continue;
                }
                let name = new_pkg.name.clone().unwrap_or_else(|| {
                    loc.strip_prefix("node_modules/").unwrap_or(loc).to_string()
                });
                if let Some(nv) = &new_pkg.version {
                    new_versions.insert(name.clone(), nv.clone());
                }
                updated_packages.push(name);
            }
        }

        Ok(UpdateSummary {
            packages_updated: updated_packages.len(),
            updated_packages,
            old_versions,
            new_versions,
            cache_hits: install_summary.cache_hits,
            cache_misses: install_summary.cache_misses,
            lockfile_path: install_summary.lockfile_path,
        })
    }

    /// Uninstall packages from project:
    /// 1. Removes specified package names from package.json (`dependencies`, `devDependencies`, `optionalDependencies`).
    /// 2. Prunes unreferenced dependencies from the in-memory dependency graph and lockfile.
    /// 3. Deletes the corresponding package directories from `node_modules` (including nested packages that are no longer referenced).
    /// 4. Writes updated deterministic `package.json` and `package-lock.json`.
    pub fn uninstall(&self, options: &UninstallOptions) -> Result<UninstallSummary> {
        let is_global = options.is_global || self.options.is_global;

        // Validate package names against malformed inputs or path traversal attacks
        for pkg in &options.packages {
            let trimmed = pkg.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("..") || trimmed.contains('\\') || trimmed.starts_with('/') {
                return Err(anyhow!(
                    "Invalid package name '{trimmed}': path traversal not permitted"
                ));
            }
        }

        if is_global {
            return self.uninstall_global(options);
        }

        let manifest_path = self.options.project_dir.join("package.json");
        if !manifest_path.exists() {
            return Err(anyhow!(
                "package.json not found in {}",
                self.options.project_dir.display()
            ));
        }

        let mut manifest =
            Manifest::from_file(&manifest_path).context("Failed to parse project package.json")?;

        let mut removed_packages = Vec::new();

        // Determine which sections to target
        let target_all = !options.save_dev && !options.save_optional && !options.save_prod;

        for raw_pkg in &options.packages {
            let pkg = raw_pkg.trim();
            if pkg.is_empty() {
                continue;
            }

            let mut removed = false;

            if (options.save_dev || target_all) && manifest.dev_dependencies.remove(pkg).is_some() {
                removed = true;
            }

            if (options.save_optional || target_all)
                && manifest.optional_dependencies.remove(pkg).is_some()
            {
                removed = true;
            }

            if (options.save_prod || target_all) && manifest.dependencies.remove(pkg).is_some() {
                removed = true;
            }

            if removed || options.is_global || self.options.is_global {
                removed_packages.push(pkg.to_string());
            }
        }

        // Save updated package.json deterministically
        manifest
            .save_to_file(&manifest_path)
            .context("Failed to save updated package.json")?;

        let lockfile_path = project_lockfile_path(&self.options.project_dir);
        let mut pruned_nodes: HashSet<String> = HashSet::new();

        if lockfile_path.exists() {
            let lockfile_str = std::fs::read_to_string(&lockfile_path)
                .with_context(|| format!("Failed to read {}", lockfile_path.display()))?;
            let mut lockfile = LockfileV3::from_json_str(&lockfile_str)
                .with_context(|| format!("Failed to parse {}", lockfile_path.display()))?;

            // Build and prune in-memory dependency graph
            let mut in_memory_graph = DependencyGraph::from_lockfile_v3(&lockfile);
            for pkg in &removed_packages {
                in_memory_graph.remove_root_dependency(pkg);
            }
            let graph_pruned = in_memory_graph.prune_unreferenced();

            // Sync root package metadata with updated manifest
            if let Some(root_pkg) = lockfile.root_package_mut() {
                root_pkg.raw_value = None;
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

            // Write updated deterministic lockfile
            lockfile
                .save_to_file_version(&lockfile_path, self.options.lockfile_version)
                .with_context(|| format!("Failed to save updated {}", lockfile_path.display()))?;

            // Persist hidden lockfile to node_modules/.package-lock.json
            let _ = lockfile.save_hidden(&self.options.project_dir);
        }

        // Remove deleted package directories from node_modules
        let (node_modules_dir, bin_dir, loc_base_dir) =
            if options.is_global || self.options.is_global {
                let nm = rnpm_config::find_global_node_modules(&self.options.project_dir);
                let bin = rnpm_config::find_global_bin_dir(&self.options.project_dir);
                let base = if cfg!(windows) {
                    self.options.project_dir.clone()
                } else {
                    self.options.project_dir.join("lib")
                };
                (nm, bin, base)
            } else {
                let nm = self.options.project_dir.join("node_modules");
                let bin = nm.join(".bin");
                let base = self.options.project_dir.clone();
                (nm, bin, base)
            };

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
            let target_path = loc_base_dir.join(&rel_dir);
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
        if bin_dir.exists() && bin_dir.file_name().is_some_and(|f| f == ".bin") {
            if let Ok(mut entries) = std::fs::read_dir(&bin_dir) {
                if entries.next().is_none() {
                    let _ = std::fs::remove_dir(&bin_dir);
                }
            }
        }
        clean_empty_bin_dirs(&node_modules_dir);

        if self.options.wait_for_trash || !self.options.detached_trash {
            crate::trash::wait_all_trash_deletions();
        }

        Ok(UninstallSummary {
            removed_packages,
            pruned_dependencies: pruned_nodes.into_iter().collect(),
            lockfile_path,
        })
    }

    fn uninstall_global(&self, options: &UninstallOptions) -> Result<UninstallSummary> {
        let (node_modules_dir, bin_dir, _loc_base_dir) = {
            let nm = rnpm_config::find_global_node_modules(&self.options.project_dir);
            let bin = rnpm_config::find_global_bin_dir(&self.options.project_dir);
            let base = if cfg!(windows) {
                self.options.project_dir.clone()
            } else {
                self.options.project_dir.join("lib")
            };
            (nm, bin, base)
        };

        let mut removed_packages = Vec::new();

        for raw_pkg in &options.packages {
            let pkg = raw_pkg.trim();
            if pkg.is_empty() {
                continue;
            }

            let target_path = node_modules_dir.join(pkg);
            let is_junc = is_junction(&target_path).unwrap_or(false);

            if target_path.exists() || is_junc {
                // Remove shims from global bin dir if package had bin entries
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

                // Delete package directory (which includes all its nested dependencies)
                if is_junc {
                    let _ = remove_junction(&target_path);
                } else if target_path.is_dir() {
                    let _ = std::fs::remove_dir_all(&target_path);
                } else {
                    let _ = std::fs::remove_file(&target_path);
                }

                // If package was scoped (e.g. @scope/pkg) and scope dir is now empty, remove scope dir
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

                removed_packages.push(pkg.to_string());
            }
        }

        // Update hidden lockfile if it exists
        let loc_base_dir = if cfg!(windows) {
            self.options.project_dir.clone()
        } else {
            self.options.project_dir.join("lib")
        };
        if let Ok(mut lockfile) = LockfileV3::load_hidden(&loc_base_dir) {
            let prefix = "node_modules/";
            for pkg in &removed_packages {
                let pkg_key = format!("{prefix}{pkg}");
                let nested_prefix = format!("{pkg_key}/node_modules/");
                lockfile.packages.retain(|k, _| k != &pkg_key && !k.starts_with(&nested_prefix));
            }
            let _ = lockfile.save_hidden(&loc_base_dir);
        }

        // Clean up .bin if empty
        if bin_dir.exists() && bin_dir.file_name().is_some_and(|f| f == ".bin") {
            if let Ok(mut entries) = std::fs::read_dir(&bin_dir) {
                if entries.next().is_none() {
                    let _ = std::fs::remove_dir(&bin_dir);
                }
            }
        }
        clean_empty_bin_dirs(&node_modules_dir);

        if self.options.wait_for_trash || !self.options.detached_trash {
            crate::trash::wait_all_trash_deletions();
        }

        let lockfile_path = project_lockfile_path(&self.options.project_dir);
        Ok(UninstallSummary {
            removed_packages,
            pruned_dependencies: Vec::new(),
            lockfile_path,
        })
    }
    /// Prunes extraneous dependencies from node_modules based on reachability from package.json.
    pub fn prune(&self, options: &PruneOptions) -> Result<PruneSummary> {
        let mut opts = options.clone();
        opts.project_dir = self.options.project_dir.clone();
        let analysis = prune::discover_extraneous_packages(&self.options.project_dir, &opts)?;
        let summary =
            prune::execute_prune(&self.options.project_dir, &analysis.extraneous_packages)?;
        if self.options.wait_for_trash || !self.options.detached_trash {
            crate::trash::wait_all_trash_deletions();
        }
        Ok(summary)
    }

    /// Discovers extraneous dependencies in node_modules without modifying the filesystem.
    pub fn analyze_prune(&self, options: &PruneOptions) -> Result<PruneAnalysis> {
        let mut opts = options.clone();
        opts.project_dir = self.options.project_dir.clone();
        prune::discover_extraneous_packages(&self.options.project_dir, &opts)
    }

    /// Re-runs compilation and lifecycle build scripts for installed packages.
    pub async fn rebuild(&self, options: &RebuildOptions) -> Result<RebuildSummary> {
        let mut opts = options.clone();
        if opts.project_dir.as_os_str().is_empty() || opts.project_dir == Path::new(".") {
            opts.project_dir = self.options.project_dir.clone();
        }
        rebuild::execute_rebuild(&opts).await
    }

    /// Reduces duplicate packages in node_modules and package-lock.json by hoisting compatible versions.
    pub fn dedupe(&self, options: &DedupeOptions) -> Result<DedupeSummary> {
        let mut opts = options.clone();
        if opts.project_dir.as_os_str().is_empty() || opts.project_dir == Path::new(".") {
            opts.project_dir = self.options.project_dir.clone();
        }
        dedupe::execute_dedupe(&opts)
    }

    /// Inspects and reports duplicate packages without modifying the filesystem or lockfile.
    pub fn find_dupes(&self, options: &DedupeOptions) -> Result<DedupeSummary> {
        let mut opts = options.clone();
        if opts.project_dir.as_os_str().is_empty() || opts.project_dir == Path::new(".") {
            opts.project_dir = self.options.project_dir.clone();
        }
        opts.dry_run = true;
        dedupe::execute_dedupe(&opts)
    }
}

/// Options for running rnpm uninstall.
#[derive(Debug, Clone, Default)]
pub struct UninstallOptions {
    pub packages: Vec<String>,
    pub save_dev: bool,
    pub save_optional: bool,
    pub save_prod: bool,
    pub is_global: bool,
}

/// Result of an uninstall run.
#[derive(Debug, Clone)]
pub struct UninstallSummary {
    pub removed_packages: Vec<String>,
    pub pruned_dependencies: Vec<String>,
    pub lockfile_path: PathBuf,
}

/// Cleans up stale files and directories in a package directory that is being replaced,
/// while preserving any nested `node_modules` packages that are marked `Unchanged`.
///
/// If `dest_dir` is an NTFS junction or symlink (e.g. leftover from `--install-strategy=linked`),
/// it is unlinked/removed immediately to prevent writing through into the linked store.
fn clean_stale_package_dir(dest_dir: &Path, loc: &str, tree_diff_opt: Option<&TreeDiff>) {
    if rnpm_fs::is_junction(dest_dir).unwrap_or(false) {
        let _ = rnpm_fs::remove_junction(dest_dir);
        return;
    }
    if !dest_dir.is_dir() {
        return;
    }

    let nested_nm = dest_dir.join("node_modules");
    if nested_nm.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&nested_nm) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                let sub_path = entry.path();
                if name_str.starts_with('@') && sub_path.is_dir() {
                    // Scoped package directory
                    if let Ok(scoped_entries) = std::fs::read_dir(&sub_path) {
                        for scoped_entry in scoped_entries.flatten() {
                            let scoped_name = scoped_entry.file_name();
                            let scoped_name_str = scoped_name.to_string_lossy();
                            let child_loc =
                                format!("{loc}/node_modules/{name_str}/{scoped_name_str}");
                            let is_unchanged = tree_diff_opt
                                .and_then(|diff| diff.get(&child_loc))
                                .map(|action| action.is_unchanged())
                                .unwrap_or(false);
                            if !is_unchanged {
                                let child_path = scoped_entry.path();
                                if rnpm_fs::is_junction(&child_path).unwrap_or(false) {
                                    let _ = rnpm_fs::remove_junction(&child_path);
                                } else {
                                    let _ = rnpm_fs::remove_dir_all_safe(&child_path);
                                }
                            }
                        }
                    }
                    if let Ok(mut remaining) = std::fs::read_dir(&sub_path) {
                        if remaining.next().is_none() {
                            let _ = std::fs::remove_dir(&sub_path);
                        }
                    }
                } else {
                    let child_loc = format!("{loc}/node_modules/{name_str}");
                    let is_unchanged = tree_diff_opt
                        .and_then(|diff| diff.get(&child_loc))
                        .map(|action| action.is_unchanged())
                        .unwrap_or(false);
                    if !is_unchanged {
                        if rnpm_fs::is_junction(&sub_path).unwrap_or(false) {
                            let _ = rnpm_fs::remove_junction(&sub_path);
                        } else {
                            let _ = rnpm_fs::remove_dir_all_safe(&sub_path);
                        }
                    }
                }
            }
        }
    }

    // Remove all non-node_modules files and directories in dest_dir
    if let Ok(entries) = std::fs::read_dir(dest_dir) {
        for entry in entries.flatten() {
            if entry.file_name() == "node_modules" {
                continue;
            }
            let path = entry.path();
            if rnpm_fs::is_junction(&path).unwrap_or(false) {
                let _ = rnpm_fs::remove_junction(&path);
            } else if path.is_dir() {
                let _ = rnpm_fs::remove_dir_all_safe(&path);
            } else {
                #[cfg(windows)]
                if let Ok(meta) = std::fs::metadata(&path) {
                    let mut perms = meta.permissions();
                    if perms.readonly() {
                        #[allow(clippy::permissions_set_readonly_false)]
                        perms.set_readonly(false);
                        let _ = std::fs::set_permissions(&path, perms);
                    }
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    if nested_nm.is_dir() {
        clean_empty_bin_dirs(&nested_nm);
        if let Ok(mut remaining) = std::fs::read_dir(&nested_nm) {
            if remaining.next().is_none() {
                let _ = std::fs::remove_dir(&nested_nm);
            }
        }
    }
}

/// Computes lockfile entries that must be skipped because they are incompatible optional
/// platform packages or reachable only below an incompatible optional platform package.
/// npm retains these records for cross-platform lockfile parity but does not extract their
/// tarballs on the current host.
pub fn lockfile_platform_skipped_packages(
    lockfile: &LockfileV3,
    platform: &Platform,
) -> HashSet<String> {
    const ACTIVE: u8 = 0b01;
    const SKIPPED: u8 = 0b10;

    let mut children: HashMap<String, Vec<(String, bool)>> = HashMap::new();
    for (parent_key, parent_pkg) in &lockfile.packages {
        let mut dep_entries: Vec<(&String, bool)> = Vec::new();

        if let Some(deps) = &parent_pkg.dependencies {
            for dep_name in deps.keys() {
                dep_entries.push((dep_name, false));
            }
        }
        if let Some(deps) = &parent_pkg.dev_dependencies {
            for dep_name in deps.keys() {
                dep_entries.push((dep_name, false));
            }
        }
        if let Some(deps) = &parent_pkg.optional_dependencies {
            for dep_name in deps.keys() {
                dep_entries.push((dep_name, true));
            }
        }
        if let Some(deps) = &parent_pkg.peer_dependencies {
            for dep_name in deps.keys() {
                let is_opt_peer = parent_pkg
                    .peer_dependencies_meta
                    .as_ref()
                    .and_then(|m| m.get(dep_name))
                    .is_some_and(|v| v.get("optional").and_then(|o| o.as_bool()).unwrap_or(false));
                dep_entries.push((dep_name, is_opt_peer));
            }
        }

        for (dep_name, is_opt_edge) in dep_entries {
            if let Some(child_key) =
                resolve_lockfile_dependency_path(lockfile, parent_key, dep_name)
            {
                children
                    .entry(parent_key.clone())
                    .or_default()
                    .push((child_key, is_opt_edge));
            }
        }
    }

    let mut states: HashMap<String, u8> = HashMap::new();
    // Entry points: root package "" and any workspace members
    states.insert(String::new(), ACTIVE);
    for key in lockfile.packages.keys() {
        if !key.is_empty() && !key.starts_with("node_modules/") {
            states.insert(key.clone(), ACTIVE);
        }
    }

    // Direct platform compatibility check: mark incompatible optional packages as SKIPPED
    for (key, pkg) in &lockfile.packages {
        if key.is_empty() {
            continue;
        }
        let is_optional =
            pkg.is_effective_optional() || pkg.is_peer_optional() || pkg.optional == Some(true);
        if !is_optional {
            continue;
        }
        let compatible = rnpm_solver::is_platform_compatible(
            platform,
            pkg.os.as_deref(),
            pkg.cpu.as_deref(),
            pkg.libc.as_deref(),
        );
        if !compatible {
            *states.entry(key.clone()).or_default() |= SKIPPED;
        }
    }

    let mut queue: VecDeque<String> = states.keys().cloned().collect();
    while let Some(parent_key) = queue.pop_front() {
        let parent_state = states.get(&parent_key).copied().unwrap_or(0);
        let Some(dependent_entries) = children.get(&parent_key) else {
            continue;
        };
        for (child_key, is_opt_edge) in dependent_entries {
            let child_pkg = match lockfile.packages.get(child_key) {
                Some(p) => p,
                None => continue,
            };
            let child_is_optional = *is_opt_edge
                || child_pkg.is_effective_optional()
                || child_pkg.is_peer_optional()
                || child_pkg.optional == Some(true);
            let child_compatible = rnpm_solver::is_platform_compatible(
                platform,
                child_pkg.os.as_deref(),
                child_pkg.cpu.as_deref(),
                child_pkg.libc.as_deref(),
            );

            let child_state = states.entry(child_key.clone()).or_default();
            let mut next = 0;

            if parent_state & ACTIVE != 0 {
                if child_is_optional && !child_compatible {
                    next |= SKIPPED;
                } else {
                    next |= ACTIVE;
                }
            }
            if parent_state & SKIPPED != 0 {
                next |= SKIPPED;
            }

            let changed = (*child_state | next) != *child_state;
            *child_state |= next;
            if changed {
                queue.push_back(child_key.clone());
            }
        }
    }

    states
        .into_iter()
        .filter_map(|(key, state)| ((state & SKIPPED != 0) && (state & ACTIVE == 0)).then_some(key))
        .collect()
}

pub fn resolve_lockfile_dependency_path(
    lockfile: &LockfileV3,
    parent_key: &str,
    dependency_name: &str,
) -> Option<String> {
    let mut scope = parent_key.to_string();
    loop {
        let candidate = if scope.is_empty() {
            format!("node_modules/{dependency_name}")
        } else {
            format!("{scope}/node_modules/{dependency_name}")
        };
        if lockfile.packages.contains_key(&candidate) {
            return Some(candidate);
        }
        if scope.is_empty() {
            return None;
        }
        if let Some(index) = scope.rfind("/node_modules/") {
            scope.truncate(index);
        } else if scope.starts_with("node_modules/") {
            scope.clear();
        } else if let Some(index) = scope.rfind('/') {
            scope.truncate(index);
        } else {
            scope.clear();
        }
    }
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
                // Resolution in node_modules tree: check closest scope up through parent ancestors to root
                let mut target_key = None;
                let nested_key = format!("{current_key}/node_modules/{dep_name}");
                if lockfile.packages.contains_key(&nested_key) {
                    target_key = Some(nested_key);
                } else {
                    let mut curr = current_key.as_str();
                    while let Some(idx) = curr.rfind("/node_modules/") {
                        curr = &curr[..idx];
                        if !curr.is_empty() {
                            let candidate = format!("{curr}/node_modules/{dep_name}");
                            if lockfile.packages.contains_key(&candidate) {
                                target_key = Some(candidate);
                                break;
                            }
                        }
                    }
                    if target_key.is_none() {
                        let root_key = format!("node_modules/{dep_name}");
                        if lockfile.packages.contains_key(&root_key) {
                            target_key = Some(root_key);
                        }
                    }
                }

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
