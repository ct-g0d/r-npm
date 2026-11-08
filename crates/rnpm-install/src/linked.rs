use anyhow::{anyhow, Result};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::timing::{Phase, TimingCollector};
use crate::{InstallOptions, InstallSummary, Installer};
use rnpm_cache::Cache;
use rnpm_core::integrity::Integrity;
use rnpm_core::manifest::Manifest;
use rnpm_fs::junction::{
    create_junction, is_junction, junction_points_to, remove_dir_all_safe, remove_junction,
};
use rnpm_fs::{determine_writer_config, extract_tarball_direct};
use rnpm_lifecycle::{
    execute_topological, LifecycleOptions, LifecyclePackageNode, PackageSource, ScriptSandboxPolicy,
};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use rnpm_registry::client::RegistryClient;
use rnpm_shim::{create_shims, normalize_shebang};
use rnpm_solver::graph::DependencyGraph;

/// Strategy used for installing packages into node_modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallStrategy {
    #[default]
    Hoisted,
    Linked,
    Nested,
    Shallow,
}

impl std::str::FromStr for InstallStrategy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "hoisted" => Ok(InstallStrategy::Hoisted),
            "linked" => Ok(InstallStrategy::Linked),
            "nested" => Ok(InstallStrategy::Nested),
            "shallow" => Ok(InstallStrategy::Shallow),
            other => Err(anyhow!(
                "Unknown install strategy: '{other}'. Valid strategies are: hoisted, linked, nested, shallow"
            )),
        }
    }
}

impl std::fmt::Display for InstallStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallStrategy::Hoisted => write!(f, "hoisted"),
            InstallStrategy::Linked => write!(f, "linked"),
            InstallStrategy::Nested => write!(f, "nested"),
            InstallStrategy::Shallow => write!(f, "shallow"),
        }
    }
}

/// Resolves the global linked store directory.
/// Default: `%LOCALAPPDATA%\rnpm\store-v1\linked`
pub fn get_linked_store_dir(options: &InstallOptions) -> PathBuf {
    if let Some(ref dir) = options.store_dir {
        return dir.clone();
    }
    if let Ok(dir) = std::env::var("RNPM_STORE_DIR") {
        if !dir.trim().is_empty() {
            let p = PathBuf::from(dir.trim());
            return if p.ends_with("linked") {
                p
            } else {
                p.join("linked")
            };
        }
    }
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(localappdata)
            .join("rnpm")
            .join("store-v1")
            .join("linked")
    } else if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        PathBuf::from(home)
            .join(".rnpm")
            .join("store-v1")
            .join("linked")
    } else {
        std::env::temp_dir()
            .join("rnpm")
            .join("store-v1")
            .join("linked")
    }
}

pub trait IntoDepHashEntry {
    fn version(&self) -> &str;
    fn integrity(&self) -> Option<&str>;
    fn tree_hash(&self) -> Option<&str> {
        None
    }
}

impl IntoDepHashEntry for String {
    fn version(&self) -> &str {
        self.as_str()
    }
    fn integrity(&self) -> Option<&str> {
        None
    }
}

impl IntoDepHashEntry for &str {
    fn version(&self) -> &str {
        self
    }
    fn integrity(&self) -> Option<&str> {
        None
    }
}

impl IntoDepHashEntry for (String, Option<String>) {
    fn version(&self) -> &str {
        &self.0
    }
    fn integrity(&self) -> Option<&str> {
        self.1.as_deref()
    }
}

impl<'a> IntoDepHashEntry for (&'a str, Option<&'a str>) {
    fn version(&self) -> &str {
        self.0
    }
    fn integrity(&self) -> Option<&str> {
        self.1
    }
}

impl IntoDepHashEntry for (String, Option<String>, Option<String>) {
    fn version(&self) -> &str {
        &self.0
    }
    fn integrity(&self) -> Option<&str> {
        self.1.as_deref()
    }
    fn tree_hash(&self) -> Option<&str> {
        self.2.as_deref()
    }
}

impl IntoDepHashEntry for (String, String, String) {
    fn version(&self) -> &str {
        &self.1
    }
    fn integrity(&self) -> Option<&str> {
        None
    }
    fn tree_hash(&self) -> Option<&str> {
        Some(&self.2)
    }
}

impl<'a> IntoDepHashEntry for (&'a str, Option<&'a str>, Option<&'a str>) {
    fn version(&self) -> &str {
        self.0
    }
    fn integrity(&self) -> Option<&str> {
        self.1
    }
    fn tree_hash(&self) -> Option<&str> {
        self.2
    }
}

/// Computes a deterministic 12-char hex hash of a package's direct dependencies,
/// incorporating dependency names, resolved versions, integrity hashes, and child tree hashes.
pub fn compute_deps_hash<T: IntoDepHashEntry>(dependencies: &BTreeMap<String, T>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for (name, entry) in dependencies {
        hasher.update(name.as_bytes());
        hasher.update(b"@");
        hasher.update(entry.version().as_bytes());
        if let Some(integ) = entry.integrity() {
            hasher.update(b"@");
            hasher.update(integ.as_bytes());
        }
        if let Some(th) = entry.tree_hash() {
            hasher.update(b"#");
            hasher.update(th.as_bytes());
        }
        hasher.update(b"\n");
    }
    let hash_hex = data_encoding::HEXLOWER.encode(&hasher.finalize());
    hash_hex[..12].to_string()
}

/// A node in the dependency graph used for computing transitive linked store hashes.
#[derive(Debug, Clone)]
pub struct DepGraphNode {
    pub id: String,
    pub name: String,
    pub version: String,
    pub resolved_url: String,
    pub integrity: Option<String>,
    /// Direct dependencies: dep_name -> target_node_id
    pub dependencies: BTreeMap<String, String>,
}

/// Computes transitive dependency tree hashes for all nodes in `nodes`.
/// Incorporates:
/// - Package's own name, version, resolved URL/spec, and integrity.
/// - Transitive dependency tree hashes in topological order from leaves to root.
/// - Strongly connected components (dependency cycles) hashed together.
pub fn compute_transitive_deps_hashes(
    nodes: &HashMap<String, DepGraphNode>,
) -> HashMap<String, String> {
    use sha2::{Digest, Sha256};

    // 1. Tarjan's Strongly Connected Components algorithm
    struct Tarjan<'a> {
        nodes: &'a HashMap<String, DepGraphNode>,
        index: usize,
        indices: HashMap<String, usize>,
        lowlink: HashMap<String, usize>,
        on_stack: HashSet<String>,
        stack: Vec<String>,
        sccs: Vec<Vec<String>>,
    }

    fn strongconnect(u: &str, ctx: &mut Tarjan) {
        ctx.indices.insert(u.to_string(), ctx.index);
        ctx.lowlink.insert(u.to_string(), ctx.index);
        ctx.index += 1;
        ctx.stack.push(u.to_string());
        ctx.on_stack.insert(u.to_string());

        if let Some(node) = ctx.nodes.get(u) {
            for target_id in node.dependencies.values() {
                if ctx.nodes.contains_key(target_id) {
                    if !ctx.indices.contains_key(target_id) {
                        strongconnect(target_id, ctx);
                        let target_low = ctx.lowlink[target_id];
                        let u_low = ctx.lowlink.get_mut(u).unwrap();
                        *u_low = (*u_low).min(target_low);
                    } else if ctx.on_stack.contains(target_id) {
                        let target_index = ctx.indices[target_id];
                        let u_low = ctx.lowlink.get_mut(u).unwrap();
                        *u_low = (*u_low).min(target_index);
                    }
                }
            }
        }

        if ctx.lowlink[u] == ctx.indices[u] {
            let mut scc = Vec::new();
            while let Some(w) = ctx.stack.pop() {
                ctx.on_stack.remove(&w);
                scc.push(w.clone());
                if w == u {
                    break;
                }
            }
            ctx.sccs.push(scc);
        }
    }

    let mut ctx = Tarjan {
        nodes,
        index: 0,
        indices: HashMap::new(),
        lowlink: HashMap::new(),
        on_stack: HashSet::new(),
        stack: Vec::new(),
        sccs: Vec::new(),
    };

    let mut node_keys: Vec<String> = nodes.keys().cloned().collect();
    node_keys.sort();

    for key in &node_keys {
        if !ctx.indices.contains_key(key) {
            strongconnect(key, &mut ctx);
        }
    }

    // 2. Compute hashes in reverse topological order (leaves to root)
    let mut computed_hashes: HashMap<String, String> = HashMap::new();

    for scc in ctx.sccs {
        if scc.len() == 1 {
            let u = &scc[0];
            let node = &nodes[u];
            let has_self_cycle = node.dependencies.values().any(|target| target == u);

            if !has_self_cycle {
                let mut hasher = Sha256::new();
                hasher.update(node.name.as_bytes());
                hasher.update(b"@");
                hasher.update(node.version.as_bytes());
                hasher.update(b"\nurl:");
                hasher.update(node.resolved_url.as_bytes());
                if let Some(ref integ) = node.integrity {
                    hasher.update(b"\ninteg:");
                    hasher.update(integ.as_bytes());
                }
                hasher.update(b"\ndeps:\n");
                for (dep_name, target_id) in &node.dependencies {
                    hasher.update(dep_name.as_bytes());
                    hasher.update(b"->");
                    if let Some(target_node) = nodes.get(target_id) {
                        hasher.update(target_node.name.as_bytes());
                        hasher.update(b"@");
                        hasher.update(target_node.version.as_bytes());
                        if let Some(ref integ) = target_node.integrity {
                            hasher.update(b"@");
                            hasher.update(integ.as_bytes());
                        }
                        if let Some(child_hash) = computed_hashes.get(target_id) {
                            hasher.update(b"#");
                            hasher.update(child_hash.as_bytes());
                        }
                    } else {
                        hasher.update(target_id.as_bytes());
                    }
                    hasher.update(b"\n");
                }
                let hash_hex = data_encoding::HEXLOWER.encode(&hasher.finalize());
                computed_hashes.insert(u.clone(), hash_hex[..12].to_string());
                continue;
            }
        }

        // Cyclic SCC: hash all components in the strongly connected component together
        let scc_set: HashSet<String> = scc.iter().cloned().collect();
        let mut sorted_scc = scc.clone();
        sorted_scc.sort_by(|a, b| {
            let na = &nodes[a];
            let nb = &nodes[b];
            na.name
                .cmp(&nb.name)
                .then_with(|| na.version.cmp(&nb.version))
                .then_with(|| na.resolved_url.cmp(&nb.resolved_url))
                .then_with(|| a.cmp(b))
        });

        // Compute overall cycle signature
        let mut scc_hasher = Sha256::new();
        scc_hasher.update(b"SCC_CYCLE:\n");
        for node_id in &sorted_scc {
            let node = &nodes[node_id];
            scc_hasher.update(node.name.as_bytes());
            scc_hasher.update(b"@");
            scc_hasher.update(node.version.as_bytes());
            scc_hasher.update(b"\nurl:");
            scc_hasher.update(node.resolved_url.as_bytes());
            if let Some(ref integ) = node.integrity {
                scc_hasher.update(b"\ninteg:");
                scc_hasher.update(integ.as_bytes());
            }
            for (dep_name, target_id) in &node.dependencies {
                if !scc_set.contains(target_id) {
                    scc_hasher.update(b"\next_dep:");
                    scc_hasher.update(dep_name.as_bytes());
                    if let Some(child_hash) = computed_hashes.get(target_id) {
                        scc_hasher.update(b"#");
                        scc_hasher.update(child_hash.as_bytes());
                    }
                }
            }
            scc_hasher.update(b"\n---\n");
        }
        let scc_cycle_hash = data_encoding::HEXLOWER.encode(&scc_hasher.finalize());

        // For each node in the SCC, compute individual hash incorporating SCC cycle hash
        for node_id in &sorted_scc {
            let node = &nodes[node_id];
            let mut hasher = Sha256::new();
            hasher.update(node.name.as_bytes());
            hasher.update(b"@");
            hasher.update(node.version.as_bytes());
            hasher.update(b"\nurl:");
            hasher.update(node.resolved_url.as_bytes());
            if let Some(ref integ) = node.integrity {
                hasher.update(b"\ninteg:");
                hasher.update(integ.as_bytes());
            }
            hasher.update(b"\nscc_cycle:");
            hasher.update(scc_cycle_hash.as_bytes());
            hasher.update(b"\ndeps:\n");
            for (dep_name, target_id) in &node.dependencies {
                hasher.update(dep_name.as_bytes());
                hasher.update(b"->");
                if let Some(target_node) = nodes.get(target_id) {
                    hasher.update(target_node.name.as_bytes());
                    hasher.update(b"@");
                    hasher.update(target_node.version.as_bytes());
                    if scc_set.contains(target_id) {
                        hasher.update(b"#cycle");
                    } else if let Some(child_hash) = computed_hashes.get(target_id) {
                        hasher.update(b"#");
                        hasher.update(child_hash.as_bytes());
                    }
                } else {
                    hasher.update(target_id.as_bytes());
                }
                hasher.update(b"\n");
            }
            let hash_hex = data_encoding::HEXLOWER.encode(&hasher.finalize());
            computed_hashes.insert(node_id.clone(), hash_hex[..12].to_string());
        }
    }

    computed_hashes
}

/// Returns the store entry root directory for a package.
/// `<store_root>/<name>@<version>-<deps-hash>`
pub fn get_store_entry_dir(
    store_root: &Path,
    name: &str,
    version: &str,
    deps_hash: &str,
) -> PathBuf {
    let entry_name = format!("{name}@{version}-{deps_hash}");
    store_root.join(entry_name)
}

/// Returns the materialized package directory inside its store entry:
/// `<store_entry>/node_modules/<name>`
pub fn get_pkg_store_dir(store_root: &Path, name: &str, version: &str, deps_hash: &str) -> PathBuf {
    get_store_entry_dir(store_root, name, version, deps_hash)
        .join("node_modules")
        .join(name)
}

/// Checks whether a package is a native addon or mutates its folder during lifecycle scripts.
pub fn is_mutating_lifecycle_package(pkg_path: &Path, manifest: &Manifest) -> bool {
    if pkg_path.join("binding.gyp").exists() {
        return true;
    }
    if let Some(script) = manifest.scripts.get("install") {
        if !script.trim().is_empty() {
            return true;
        }
    }
    if let Some(script) = manifest.scripts.get("postinstall") {
        let s = script.to_ascii_lowercase();
        if s.contains("node-gyp")
            || s.contains("cmake-js")
            || s.contains("build")
            || s.contains("prebuild")
            || s.contains("compile")
        {
            return true;
        }
    }
    false
}

/// Safely creates or replaces an NTFS junction or directory.
pub fn create_or_replace_junction(link: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }
    if is_junction(link).unwrap_or(false) {
        let _ = remove_junction(link);
    } else if link.exists() {
        let _ = remove_dir_all_safe(link);
    }
    create_junction(link, target).map_err(|e| {
        anyhow!(
            "Failed to create junction from {:?} to {:?}: {}",
            link,
            target,
            e
        )
    })?;
    Ok(())
}

/// Recursively copies a directory (used for native addon fallbacks).
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let entry_type = entry.file_type()?;
        let target_path = dst.join(entry.file_name());
        if entry_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target_path)?;
        } else {
            fs::copy(entry.path(), &target_path)?;
        }
    }
    Ok(())
}

/// Cleans up stale junctions and old hoisted directories in node_modules for linked install mode.
pub fn cleanup_stale_linked_entries(
    node_modules_dir: &Path,
    root_bin_dir: &Path,
    expected_top_packages: &HashSet<String>,
) -> Result<()> {
    if !node_modules_dir.exists() {
        return Ok(());
    }

    let entries = match fs::read_dir(node_modules_dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Skip internal/dot entries (.bin, .package-lock.json, .cache, .trash, etc.)
        if name_str.starts_with('.') {
            continue;
        }

        let entry_path = entry.path();

        if name_str.starts_with('@') {
            let scope_entries = match fs::read_dir(&entry_path) {
                Ok(se) => se,
                Err(_) => continue,
            };

            for sub_entry in scope_entries.flatten() {
                let sub_file_name = sub_entry.file_name();
                let sub_name_str = sub_file_name.to_string_lossy();
                if sub_name_str.starts_with('.') {
                    continue;
                }

                let full_pkg_name = format!("{name_str}/{sub_name_str}");
                let sub_path = sub_entry.path();
                let is_junc = is_junction(&sub_path).unwrap_or(false);

                if !expected_top_packages.contains(&full_pkg_name) {
                    clean_bin_shims_for_pkg(&sub_path, root_bin_dir);
                    if is_junc {
                        let _ = remove_junction(&sub_path);
                    } else if sub_path.is_dir() {
                        let _ = remove_dir_all_safe(&sub_path);
                    } else {
                        let _ = fs::remove_file(&sub_path);
                    }
                } else if sub_path.is_dir() && !is_junc {
                    // Old hoisted directory for an expected package: remove to make way for junction
                    let _ = remove_dir_all_safe(&sub_path);
                }
            }

            if let Ok(mut remaining) = fs::read_dir(&entry_path) {
                if remaining.next().is_none() {
                    let _ = fs::remove_dir(&entry_path);
                }
            }
        } else {
            let is_junc = is_junction(&entry_path).unwrap_or(false);
            let pkg_name = name_str.to_string();

            if !expected_top_packages.contains(&pkg_name) {
                clean_bin_shims_for_pkg(&entry_path, root_bin_dir);
                if is_junc {
                    let _ = remove_junction(&entry_path);
                } else if entry_path.is_dir() {
                    let _ = remove_dir_all_safe(&entry_path);
                } else {
                    let _ = fs::remove_file(&entry_path);
                }
            } else if entry_path.is_dir() && !is_junc {
                // Old hoisted directory for an expected package: remove to make way for junction
                let _ = remove_dir_all_safe(&entry_path);
            }
        }
    }

    Ok(())
}

fn clean_bin_shims_for_pkg(pkg_dir: &Path, root_bin_dir: &Path) {
    let manifest_path = pkg_dir.join("package.json");
    if let Ok(manifest) = Manifest::from_file(&manifest_path) {
        for (bin_name, _) in manifest.bin_entries() {
            let _ = fs::remove_file(root_bin_dir.join(&bin_name));
            let _ = fs::remove_file(root_bin_dir.join(format!("{bin_name}.cmd")));
            let _ = fs::remove_file(root_bin_dir.join(format!("{bin_name}.ps1")));
        }
    }
}

/// Represents an item to be materialized in the global linked store.
#[derive(Debug, Clone)]
pub struct StorePackagePlan {
    pub name: String,
    pub version: String,
    pub resolved_url: String,
    pub integrity: Option<String>,
    pub deps_hash: String,
    pub store_entry_dir: PathBuf,
    pub pkg_store_dir: PathBuf,
    /// Direct dependencies: dep_name -> (dep_pkg_name, dep_version, dep_deps_hash)
    pub dependencies: BTreeMap<String, (String, String, String)>,
    pub is_optional: bool,
    pub has_install_script: bool,
}

/// Derives the global store root directory from a store entry path and the package name.
/// Handles both scoped (e.g. `@eslint/eslintrc`) and non-scoped packages.
pub fn get_store_root_for_entry(store_entry: &Path, pkg_name: &str) -> PathBuf {
    let slash_count = pkg_name.matches('/').count() + pkg_name.matches('\\').count();
    let mut current = store_entry;
    for _ in 0..=slash_count {
        if let Some(p) = current.parent() {
            current = p;
        } else {
            break;
        }
    }
    current.to_path_buf()
}

/// Topologically sorts store package plans into strongly connected components (SCCs)
/// using Tarjan's algorithm, ordered from leaves (dependencies) to root (dependents).
fn sort_store_plans_sccs(
    unique_plans: &BTreeMap<String, StorePackagePlan>,
) -> Vec<Vec<StorePackagePlan>> {
    struct Tarjan<'a> {
        plans: &'a BTreeMap<String, StorePackagePlan>,
        index: usize,
        indices: HashMap<String, usize>,
        lowlink: HashMap<String, usize>,
        on_stack: HashSet<String>,
        stack: Vec<String>,
        sccs: Vec<Vec<StorePackagePlan>>,
    }

    fn strongconnect(u: &str, ctx: &mut Tarjan) {
        ctx.indices.insert(u.to_string(), ctx.index);
        ctx.lowlink.insert(u.to_string(), ctx.index);
        ctx.index += 1;
        ctx.stack.push(u.to_string());
        ctx.on_stack.insert(u.to_string());

        if let Some(plan) = ctx.plans.get(u) {
            for (dep_pkg_name, dep_ver, dep_hash) in plan.dependencies.values() {
                let dep_key = format!("{dep_pkg_name}@{dep_ver}-{dep_hash}");
                if ctx.plans.contains_key(&dep_key) {
                    if !ctx.indices.contains_key(&dep_key) {
                        strongconnect(&dep_key, ctx);
                        let dep_low = ctx.lowlink[&dep_key];
                        let u_low = ctx.lowlink.get_mut(u).unwrap();
                        *u_low = (*u_low).min(dep_low);
                    } else if ctx.on_stack.contains(&dep_key) {
                        let dep_index = ctx.indices[&dep_key];
                        let u_low = ctx.lowlink.get_mut(u).unwrap();
                        *u_low = (*u_low).min(dep_index);
                    }
                }
            }
        }

        if ctx.lowlink[u] == ctx.indices[u] {
            let mut scc = Vec::new();
            while let Some(w) = ctx.stack.pop() {
                ctx.on_stack.remove(&w);
                if let Some(plan) = ctx.plans.get(&w) {
                    scc.push(plan.clone());
                }
                if w == u {
                    break;
                }
            }
            ctx.sccs.push(scc);
        }
    }

    let mut ctx = Tarjan {
        plans: unique_plans,
        index: 0,
        indices: HashMap::new(),
        lowlink: HashMap::new(),
        on_stack: HashSet::new(),
        stack: Vec::new(),
        sccs: Vec::new(),
    };

    let keys: Vec<String> = unique_plans.keys().cloned().collect();
    for key in &keys {
        if !ctx.indices.contains_key(key) {
            strongconnect(key, &mut ctx);
        }
    }

    ctx.sccs
}

/// Materializes packages in the global store and wires their dependencies as junctions.
/// Packages are materialized in topological order (dependencies first, dependents later)
/// with strongly connected components (cycles) unpacked together before wiring.
pub async fn materialize_store_packages(
    packages: &[StorePackagePlan],
    cache: &Cache,
    registry_client: &RegistryClient,
    offline: bool,
) -> Result<(usize, usize)> {
    let mut cache_hits = 0;
    let mut cache_misses = 0;

    let writer_cfg = determine_writer_config(Path::new("."), None);

    // Deduplicate packages by store entry key
    let mut unique_plans: BTreeMap<String, StorePackagePlan> = BTreeMap::new();
    for pkg in packages {
        let key = format!("{}@{}-{}", pkg.name, pkg.version, pkg.deps_hash);
        unique_plans.entry(key).or_insert_with(|| pkg.clone());
    }

    // Topological sort into SCCs (dependencies / leaves first, dependents later)
    let sccs = sort_store_plans_sccs(&unique_plans);

    for scc in sccs {
        // 1. Unpack all un-materialized packages in this SCC
        for pkg in &scc {
            let marker = pkg.store_entry_dir.join(".rnpm-materialized");
            let manifest_file = pkg.pkg_store_dir.join("package.json");

            if marker.exists() && manifest_file.exists() {
                cache_hits += 1;
                continue;
            }

            let expected_integrity: Option<Integrity> = if let Some(ref integ_str) = pkg.integrity {
                if !integ_str.is_empty() {
                    match integ_str.parse::<Integrity>() {
                        Ok(i) => Some(i),
                        Err(e) => {
                            if pkg.is_optional {
                                warn!(
                                    "Optional dependency {} has invalid integrity string: {}",
                                    pkg.name, e
                                );
                                continue;
                            } else {
                                return Err(anyhow!(
                                    "Invalid integrity string for {}: {}",
                                    pkg.name,
                                    e
                                ));
                            }
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Fetch tarball bytes
            let (bytes, was_cached) = if let Ok(Some((_entry, data))) = cache.get(&pkg.resolved_url)
            {
                let valid = if let Some(ref exp) = expected_integrity {
                    exp.verify(&data).is_ok()
                } else {
                    true
                };
                if valid {
                    (data, true)
                } else {
                    let _ = cache.purge_key(&pkg.resolved_url);
                    if offline {
                        if pkg.is_optional {
                            continue;
                        }
                        return Err(anyhow!("Offline mode: missing tarball for {}", pkg.name));
                    }
                    let data = registry_client
                        .download_tarball_bytes(&pkg.resolved_url)
                        .await?;
                    if let Some(ref exp) = expected_integrity {
                        if let Err(e) = exp.verify(&data) {
                            if pkg.is_optional {
                                warn!(
                                    "Integrity verification failed for optional dependency {}: {}",
                                    pkg.name, e
                                );
                                continue;
                            } else {
                                return Err(anyhow!(
                                    "Integrity verification failed for {}: {}",
                                    pkg.name,
                                    e
                                ));
                            }
                        }
                    }
                    let _ = cache.put_with_integrity(
                        &pkg.resolved_url,
                        &data,
                        expected_integrity.as_ref(),
                        None,
                    );
                    (data, false)
                }
            } else {
                if offline {
                    if pkg.is_optional {
                        continue;
                    }
                    return Err(anyhow!("Offline mode: missing tarball for {}", pkg.name));
                }
                let data = registry_client
                    .download_tarball_bytes(&pkg.resolved_url)
                    .await?;
                if let Some(ref exp) = expected_integrity {
                    if let Err(e) = exp.verify(&data) {
                        if pkg.is_optional {
                            warn!(
                                "Integrity verification failed for optional dependency {}: {}",
                                pkg.name, e
                            );
                            continue;
                        } else {
                            return Err(anyhow!(
                                "Integrity verification failed for {}: {}",
                                pkg.name,
                                e
                            ));
                        }
                    }
                }
                let _ = cache.put_with_integrity(
                    &pkg.resolved_url,
                    &data,
                    expected_integrity.as_ref(),
                    None,
                );
                (data, false)
            };

            if was_cached {
                cache_hits += 1;
            } else {
                cache_misses += 1;
            }

            // Clean any existing partial directory before unpacking
            if pkg.pkg_store_dir.exists() {
                let _ = remove_dir_all_safe(&pkg.pkg_store_dir);
            }
            fs::create_dir_all(&pkg.pkg_store_dir)?;

            if let Err(e) = extract_tarball_direct(
                Cursor::new(&bytes),
                &pkg.pkg_store_dir,
                None,
                Some(&writer_cfg),
            ) {
                let _ = remove_dir_all_safe(&pkg.store_entry_dir);
                if pkg.is_optional {
                    warn!("Failed to extract optional dependency {}: {e}", pkg.name);
                    continue;
                } else {
                    return Err(anyhow!("Failed to extract {}: {e}", pkg.name));
                }
            }
        }

        // 2. Wire dependencies inside each store entry's node_modules as junctions
        for pkg in &scc {
            let marker = pkg.store_entry_dir.join(".rnpm-materialized");
            let manifest_file = pkg.pkg_store_dir.join("package.json");
            if marker.exists() && manifest_file.exists() {
                continue;
            }

            let store_root = get_store_root_for_entry(&pkg.store_entry_dir, &pkg.name);
            let store_nm = pkg.store_entry_dir.join("node_modules");
            fs::create_dir_all(&store_nm)?;

            let mut all_wired = true;

            for (dep_name, (dep_pkg_name, dep_ver, dep_hash)) in &pkg.dependencies {
                let dep_target = get_pkg_store_dir(&store_root, dep_pkg_name, dep_ver, dep_hash);

                let dep_link = store_nm.join(dep_name);

                // Skip self-link if dep_link resolves to the package's own store directory
                if dep_link == pkg.pkg_store_dir {
                    continue;
                }

                if dep_target.exists() {
                    if !junction_points_to(&dep_link, &dep_target) {
                        if let Err(e) = create_or_replace_junction(&dep_link, &dep_target) {
                            if pkg.is_optional {
                                warn!("Failed to wire optional dependency {dep_name}: {e}");
                            } else {
                                all_wired = false;
                                warn!("Failed to wire dependency {dep_name} for {}: {e}", pkg.name);
                            }
                        }
                    }
                    if !junction_points_to(&dep_link, &dep_target) {
                        if pkg.is_optional {
                            warn!(
                                "Optional dependency junction {:?} does not point to {:?}",
                                dep_link, dep_target
                            );
                        } else {
                            all_wired = false;
                            warn!(
                                "Dependency junction {:?} failed verification for {}",
                                dep_link, pkg.name
                            );
                        }
                    }
                } else {
                    if pkg.is_optional {
                        warn!("Optional dependency target {:?} does not exist", dep_target);
                    } else {
                        all_wired = false;
                        warn!(
                            "Dependency target {:?} does not exist for {}",
                            dep_target, pkg.name
                        );
                    }
                }
            }

            // 3. Mark as .rnpm-materialized ONLY IF all declared dependency junctions
            // have been successfully created and verified! If any junction failed,
            // do NOT mark as materialized, and clean up the failed entry.
            if all_wired {
                let _ = fs::write(&marker, b"1");
            } else {
                let _ = remove_dir_all_safe(&pkg.store_entry_dir);
                if !pkg.is_optional {
                    return Err(anyhow!(
                        "Failed to materialize store package {}: one or more dependencies failed to wire or verify",
                        pkg.name
                    ));
                }
            }
        }
    }

    Ok((cache_hits, cache_misses))
}

/// Resolves a dependency from an arbitrary consumer location in a LockfileV3 tree.
pub fn resolve_lockfile_dep<'a>(
    lockfile: &'a LockfileV3,
    consumer_loc: &str,
    dep_name: &str,
) -> Option<(String, &'a LockfilePackage)> {
    if consumer_loc.is_empty() {
        let root_key = format!("node_modules/{dep_name}");
        if let Some(pkg) = lockfile.packages.get(&root_key) {
            return Some((root_key, pkg));
        }
        return None;
    }

    let mut current = consumer_loc;
    loop {
        let candidate = format!("{current}/node_modules/{dep_name}");
        if let Some(pkg) = lockfile.packages.get(&candidate) {
            return Some((candidate, pkg));
        }
        if let Some(idx) = current.rfind("/node_modules/") {
            current = &current[..idx];
        } else {
            break;
        }
    }

    let root_candidate = format!("node_modules/{dep_name}");
    if let Some(pkg) = lockfile.packages.get(&root_candidate) {
        return Some((root_candidate, pkg));
    }

    None
}

impl Installer {
    /// Executes linked installation (`--install-strategy=linked`) using NTFS junctions.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_linked_install(
        &mut self,
        manifest: &Manifest,
        graph: &DependencyGraph,
        lockfile: &LockfileV3,
        node_modules_dir: &Path,
        root_bin_dir: &Path,
        collector: TimingCollector,
        plan_start: std::time::Instant,
    ) -> Result<InstallSummary> {
        let store_root = get_linked_store_dir(&self.options);
        fs::create_dir_all(&store_root)?;
        fs::create_dir_all(node_modules_dir)?;
        fs::create_dir_all(root_bin_dir)?;

        // Stale junction and old hoisted directory cleanup:
        // Identify all expected top-level packages in node_modules
        let mut expected_top_packages: HashSet<String> = HashSet::new();
        for edge in graph.get_outgoing_edges(&graph.root_location) {
            expected_top_packages.insert(edge.install_name.clone());
        }
        for (loc, node) in &graph.nodes {
            if loc.is_empty() || node.flags.skipped {
                continue;
            }
            if node.flags.link
                || node
                    .resolved
                    .as_ref()
                    .is_some_and(|r| r.starts_with("packages/"))
            {
                if let Some(clean) = loc.strip_prefix("node_modules/") {
                    expected_top_packages.insert(clean.to_string());
                }
            }
        }
        for name in manifest.dependencies.keys() {
            expected_top_packages.insert(name.clone());
        }
        if !self.options.omit_dev {
            for name in manifest.dev_dependencies.keys() {
                expected_top_packages.insert(name.clone());
            }
        }
        if !self.options.omit_optional {
            for name in manifest.optional_dependencies.keys() {
                expected_top_packages.insert(name.clone());
            }
        }
        if !self.options.omit_peer {
            for name in manifest.peer_dependencies.keys() {
                expected_top_packages.insert(name.clone());
            }
        }

        cleanup_stale_linked_entries(node_modules_dir, root_bin_dir, &expected_top_packages)?;

        // 1. Build DepGraphNode for every non-skipped, non-workspace node in graph
        let mut graph_nodes: HashMap<String, DepGraphNode> = HashMap::new();

        for (loc, node) in &graph.nodes {
            if loc.is_empty() || node.flags.skipped {
                continue;
            }
            let is_workspace = node.flags.link
                || node
                    .resolved
                    .as_ref()
                    .is_some_and(|r| r.starts_with("packages/"))
                || loc.starts_with("packages/");
            if is_workspace {
                continue;
            }

            let mut deps = BTreeMap::new();
            let mut all_dep_names: HashSet<String> = HashSet::new();

            for edge in graph.get_outgoing_edges(loc) {
                deps.insert(edge.install_name.clone(), edge.to_location.clone());
                all_dep_names.insert(edge.install_name.clone());
            }

            for dep_name in node
                .dependencies
                .keys()
                .chain(node.optional_dependencies.keys())
                .chain(node.peer_dependencies.keys())
            {
                all_dep_names.insert(dep_name.clone());
            }

            if let Some(pkg_info) = lockfile.packages.get(loc) {
                if let Some(ref d) = pkg_info.dependencies {
                    for k in d.keys() {
                        all_dep_names.insert(k.clone());
                    }
                }
                if let Some(ref d) = pkg_info.optional_dependencies {
                    for k in d.keys() {
                        all_dep_names.insert(k.clone());
                    }
                }
                if let Some(ref d) = pkg_info.peer_dependencies {
                    for k in d.keys() {
                        all_dep_names.insert(k.clone());
                    }
                }
            }

            for dep_name in all_dep_names {
                if let std::collections::btree_map::Entry::Vacant(e) = deps.entry(dep_name) {
                    if let Some((target_key, _)) = resolve_lockfile_dep(lockfile, loc, e.key()) {
                        e.insert(target_key);
                    } else {
                        let candidate_nested = format!("{loc}/node_modules/{}", e.key());
                        let candidate_root = format!("node_modules/{}", e.key());
                        if graph.get_node(&candidate_nested).is_some() {
                            e.insert(candidate_nested);
                        } else if graph.get_node(&candidate_root).is_some() {
                            e.insert(candidate_root);
                        }
                    }
                }
            }

            let resolved_url = node.resolved.clone().unwrap_or_default();
            graph_nodes.insert(
                loc.clone(),
                DepGraphNode {
                    id: loc.clone(),
                    name: node.name.clone(),
                    version: node.version.clone(),
                    resolved_url,
                    integrity: node.integrity.clone(),
                    dependencies: deps,
                },
            );
        }

        // Compute deterministic transitive tree hashes (topological order + cycle handling)
        let computed_hashes = compute_transitive_deps_hashes(&graph_nodes);

        // Build complete StorePackagePlan with target hashes
        let mut store_plans = Vec::new();
        for (loc, gnode) in &graph_nodes {
            let node = match graph.get_node(loc) {
                Some(n) => n,
                None => continue,
            };

            if gnode.resolved_url.is_empty()
                || gnode.resolved_url.starts_with("packages/")
                || gnode.resolved_url.starts_with("file:")
            {
                continue;
            }

            let deps_hash = match computed_hashes.get(loc) {
                Some(h) => h.clone(),
                None => continue,
            };

            let mut dep_targets = BTreeMap::new();
            for (dep_name, target_id) in &gnode.dependencies {
                if let Some(target_gnode) = graph_nodes.get(target_id) {
                    if let Some(target_hash) = computed_hashes.get(target_id) {
                        dep_targets.insert(
                            dep_name.clone(),
                            (
                                target_gnode.name.clone(),
                                target_gnode.version.clone(),
                                target_hash.clone(),
                            ),
                        );
                    }
                }
            }

            let store_entry_dir =
                get_store_entry_dir(&store_root, &gnode.name, &gnode.version, &deps_hash);
            let pkg_store_dir =
                get_pkg_store_dir(&store_root, &gnode.name, &gnode.version, &deps_hash);

            store_plans.push(StorePackagePlan {
                name: gnode.name.clone(),
                version: gnode.version.clone(),
                resolved_url: gnode.resolved_url.clone(),
                integrity: gnode.integrity.clone(),
                deps_hash,
                store_entry_dir,
                pkg_store_dir,
                dependencies: dep_targets,
                is_optional: node.flags.optional,
                has_install_script: node.flags.has_install_script,
            });
        }

        // 2. Materialize store packages and wire their internal dependency junctions
        let (cache_hits, cache_misses) = materialize_store_packages(
            &store_plans,
            &self.cache,
            &self.registry_client,
            self.options.offline,
        )
        .await?;

        // 3. Wire project node_modules with top-level junctions or copies (for native addons)
        let mut packages_installed = 0;
        let mut lifecycle_nodes: Vec<LifecyclePackageNode> = Vec::new();

        // 3a. Wire workspace member link nodes directly via NTFS junctions to project workspace directories
        for (loc, node) in &graph.nodes {
            if loc.is_empty() || node.flags.skipped {
                continue;
            }
            let is_workspace_link = node.flags.link
                || node
                    .resolved
                    .as_ref()
                    .is_some_and(|r| r.starts_with("packages/"));
            if is_workspace_link {
                let link_target = self.options.project_dir.join(loc);
                let source_path = if let Some(ref res) = node.resolved {
                    self.options.project_dir.join(res)
                } else {
                    self.options.project_dir.join(&node.name)
                };
                if source_path.exists() {
                    if !junction_points_to(&link_target, &source_path) {
                        create_or_replace_junction(&link_target, &source_path)?;
                    }
                    packages_installed += 1;

                    let manifest_path = source_path.join("package.json");
                    if let Ok(pkg_m) = Manifest::from_file(&manifest_path) {
                        let clean_name = loc.strip_prefix("node_modules/").unwrap_or(loc);
                        for (bin_name, script_rel) in pkg_m.bin_entries() {
                            let target_rel = format!("{clean_name}/{script_rel}");
                            let script_path = source_path.join(&script_rel);
                            let _ = normalize_shebang(&script_path);
                            let _ = create_shims(root_bin_dir, &bin_name, &target_rel);
                        }
                    }
                }
            }
        }

        // 3b. Wire top-level store packages
        for edge in graph.get_outgoing_edges(&graph.root_location) {
            let child_node = match graph.get_node(&edge.to_location) {
                Some(n) => n,
                None => continue,
            };

            // Workspace members are already linked in 3a
            if child_node.flags.link
                || child_node
                    .resolved
                    .as_ref()
                    .is_some_and(|r| r.starts_with("packages/"))
            {
                continue;
            }

            let child_hash = match computed_hashes.get(&edge.to_location) {
                Some(h) => h,
                None => continue,
            };

            let target_pkg_dir = get_pkg_store_dir(
                &store_root,
                &child_node.name,
                &child_node.version,
                child_hash,
            );
            if !target_pkg_dir.exists() {
                continue;
            }

            let top_pkg_name = &edge.install_name;
            let proj_link = node_modules_dir.join(top_pkg_name);

            // Read manifest to check for native addon / mutating scripts
            let manifest_path = target_pkg_dir.join("package.json");
            let is_native = if let Ok(pkg_m) = Manifest::from_file(&manifest_path) {
                is_mutating_lifecycle_package(&target_pkg_dir, &pkg_m)
            } else {
                false
            };

            if is_native {
                copy_dir_recursive(&target_pkg_dir, &proj_link)?;
                if let Ok(pkg_m) = Manifest::from_file(&manifest_path) {
                    if pkg_m.scripts.contains_key("preinstall")
                        || pkg_m.scripts.contains_key("install")
                        || pkg_m.scripts.contains_key("postinstall")
                    {
                        lifecycle_nodes.push(LifecyclePackageNode {
                            package_path: format!("node_modules/{top_pkg_name}"),
                            disk_path: proj_link.clone(),
                            manifest: pkg_m,
                            source: PackageSource::Registry,
                            dependencies: child_node.dependencies.keys().cloned().collect(),
                            optional: child_node.flags.optional,
                        });
                    }
                }
            } else {
                if !junction_points_to(&proj_link, &target_pkg_dir) {
                    create_or_replace_junction(&proj_link, &target_pkg_dir)?;
                }
            }

            packages_installed += 1;

            // Generate shims in node_modules/.bin
            if let Ok(pkg_m) = Manifest::from_file(&manifest_path) {
                for (bin_name, script_rel) in pkg_m.bin_entries() {
                    let target_rel = format!("{top_pkg_name}/{script_rel}");
                    let script_path = target_pkg_dir.join(&script_rel);
                    let _ = normalize_shebang(&script_path);
                    let _ = create_shims(root_bin_dir, &bin_name, &target_rel);
                }
            }
        }

        // 4. Run lifecycle scripts for any per-project fallback copies
        if !self.options.ignore_scripts && !lifecycle_nodes.is_empty() {
            let sandbox_policy = if self.options.strict_sandbox {
                ScriptSandboxPolicy::restricted()
            } else {
                ScriptSandboxPolicy::permissive()
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
            execute_topological(&lifecycle_nodes, manifest, &lifecycle_opts).await?;
        }

        // 5. Persist hidden lockfile
        let hidden_lockfile_path = node_modules_dir.join(".package-lock.json");
        let _ = lockfile.save_to_file(&hidden_lockfile_path);

        if self.options.package_lock_enabled() && !self.options.no_save {
            let public_lockfile_path = self.options.project_dir.join("package-lock.json");
            let _ = lockfile.save_to_file(&public_lockfile_path);
        }

        collector.record_phase(Phase::Plan, plan_start.elapsed());

        Ok(InstallSummary {
            packages_installed,
            cache_hits,
            cache_misses,
            lockfile_path: self.options.project_dir.join("package-lock.json"),
            timing: Some(collector.finish()),
        })
    }

    /// Executes linked ci (`ci --install-strategy=linked`) using NTFS junctions.
    pub async fn execute_linked_ci(
        &mut self,
        manifest: &Manifest,
        lockfile: &LockfileV3,
        node_modules_dir: &Path,
        bin_dir: &Path,
        collector: TimingCollector,
    ) -> Result<InstallSummary> {
        let store_root = get_linked_store_dir(&self.options);
        fs::create_dir_all(&store_root)?;

        // Wiping node_modules is safe with reparse points
        if node_modules_dir.exists() || is_junction(node_modules_dir).unwrap_or(false) {
            crate::trash::fast_trash_wipe_dir(node_modules_dir)?;
        }
        fs::create_dir_all(node_modules_dir)?;
        fs::create_dir_all(bin_dir)?;

        let root_pkg = lockfile
            .packages
            .get("")
            .ok_or_else(|| anyhow!("package-lock.json missing root package descriptor"))?;

        let platform_skipped_packages =
            crate::lockfile_platform_skipped_packages(lockfile, &self.options.platform());

        // 1. Build DepGraphNode for every non-link package in lockfile
        let mut graph_nodes: HashMap<String, DepGraphNode> = HashMap::new();

        for (pkg_key, pkg_info) in &lockfile.packages {
            if pkg_key.is_empty() || !pkg_key.starts_with("node_modules/") {
                continue;
            }
            if platform_skipped_packages.contains(pkg_key) {
                continue;
            }
            let is_optional = pkg_info.is_effective_optional()
                || pkg_info.is_peer_optional()
                || pkg_info.optional == Some(true);
            if is_optional {
                let host_platform = self.options.platform();
                let is_compat = rnpm_solver::is_platform_compatible(
                    &host_platform,
                    pkg_info.os.as_deref(),
                    pkg_info.cpu.as_deref(),
                    pkg_info.libc.as_deref(),
                );
                if !is_compat {
                    continue;
                }
            }
            let is_link = pkg_info.link == Some(true)
                || pkg_info
                    .resolved
                    .as_ref()
                    .is_some_and(|r| r.starts_with("packages/"));
            if is_link {
                continue;
            }

            let name = pkg_info
                .name
                .clone()
                .unwrap_or_else(|| crate::prune::extract_package_name_from_path(pkg_key));
            let version = pkg_info.version.clone().unwrap_or_default();
            let resolved_url = pkg_info.resolved.clone().unwrap_or_default();

            let mut all_deps = BTreeMap::new();
            if let Some(ref deps) = pkg_info.dependencies {
                all_deps.extend(deps.clone());
            }
            if let Some(ref opt_deps) = pkg_info.optional_dependencies {
                all_deps.extend(opt_deps.clone());
            }
            if let Some(ref peer_deps) = pkg_info.peer_dependencies {
                all_deps.extend(peer_deps.clone());
            }

            let mut deps = BTreeMap::new();
            for dep_name in all_deps.keys() {
                if let Some((target_key, _target_pkg)) =
                    resolve_lockfile_dep(lockfile, pkg_key, dep_name)
                {
                    deps.insert(dep_name.clone(), target_key);
                }
            }

            graph_nodes.insert(
                pkg_key.clone(),
                DepGraphNode {
                    id: pkg_key.clone(),
                    name,
                    version,
                    resolved_url,
                    integrity: pkg_info.integrity.clone(),
                    dependencies: deps,
                },
            );
        }

        // Compute deterministic transitive tree hashes (topological order + cycle handling)
        let computed_hashes = compute_transitive_deps_hashes(&graph_nodes);

        // 2. Build StorePackagePlan for all packages in lockfile, excluding workspace packages
        let mut store_plans = Vec::new();

        for (pkg_key, gnode) in &graph_nodes {
            let pkg_info = match lockfile.packages.get(pkg_key) {
                Some(p) => p,
                None => continue,
            };

            if gnode.resolved_url.starts_with("packages/")
                || gnode.resolved_url.starts_with("file:")
            {
                continue;
            }

            let deps_hash = match computed_hashes.get(pkg_key) {
                Some(h) => h.clone(),
                None => continue,
            };

            let mut dep_targets = BTreeMap::new();
            for (dep_name, target_id) in &gnode.dependencies {
                if let Some(target_gnode) = graph_nodes.get(target_id) {
                    if let Some(target_hash) = computed_hashes.get(target_id) {
                        dep_targets.insert(
                            dep_name.clone(),
                            (
                                target_gnode.name.clone(),
                                target_gnode.version.clone(),
                                target_hash.clone(),
                            ),
                        );
                    }
                }
            }

            let store_entry_dir =
                get_store_entry_dir(&store_root, &gnode.name, &gnode.version, &deps_hash);
            let pkg_store_dir =
                get_pkg_store_dir(&store_root, &gnode.name, &gnode.version, &deps_hash);

            let is_optional = pkg_info.is_effective_optional() || pkg_info.is_peer_optional();

            store_plans.push(StorePackagePlan {
                name: gnode.name.clone(),
                version: gnode.version.clone(),
                resolved_url: gnode.resolved_url.clone(),
                integrity: gnode.integrity.clone(),
                deps_hash,
                store_entry_dir,
                pkg_store_dir,
                dependencies: dep_targets,
                is_optional,
                has_install_script: pkg_info.has_install_script.unwrap_or(false),
            });
        }

        // 3. Materialize store packages and wire internal dependency junctions
        let _mat_guard = collector.enter_phase(Phase::Materialize);
        let (cache_hits, cache_misses) = materialize_store_packages(
            &store_plans,
            &self.cache,
            &self.registry_client,
            self.options.offline,
        )
        .await?;
        drop(_mat_guard);
        collector.add_cache_hits(cache_hits as u64);
        collector.add_cache_misses(cache_misses as u64);

        // 4. Wire workspace member links and top-level dependencies in project node_modules
        let mut packages_installed = 0;
        let mut lifecycle_nodes: Vec<LifecyclePackageNode> = Vec::new();

        // 4a. Wire workspace member link nodes directly via NTFS junctions to project workspace directories
        for (pkg_key, pkg_info) in &lockfile.packages {
            if pkg_key.is_empty() {
                continue;
            }
            let is_workspace_link = pkg_info.link == Some(true)
                || pkg_info
                    .resolved
                    .as_ref()
                    .is_some_and(|r| r.starts_with("packages/"));
            if is_workspace_link {
                let target_rel = match pkg_info.resolved.as_ref() {
                    Some(r) => r.as_str(),
                    None => continue,
                };
                let target_dir = self.options.project_dir.join(target_rel);
                let link_path = self.options.project_dir.join(pkg_key);
                if target_dir.exists() {
                    if !junction_points_to(&link_path, &target_dir) {
                        create_or_replace_junction(&link_path, &target_dir)?;
                    }
                    packages_installed += 1;

                    let manifest_path = target_dir.join("package.json");
                    if let Ok(pkg_m) = Manifest::from_file(&manifest_path) {
                        let clean_name = pkg_key.strip_prefix("node_modules/").unwrap_or(pkg_key);
                        for (bin_name, script_rel) in pkg_m.bin_entries() {
                            let target_rel_bin = format!("{clean_name}/{script_rel}");
                            let script_path = target_dir.join(&script_rel);
                            let _ = normalize_shebang(&script_path);
                            let _ = create_shims(bin_dir, &bin_name, &target_rel_bin);
                        }
                    }
                }
            }
        }

        // 4b. Wire top-level dependencies from store
        let mut top_level_names: HashSet<String> = HashSet::new();
        if let Some(ref deps) = root_pkg.dependencies {
            top_level_names.extend(deps.keys().cloned());
        }
        if !self.options.omit_dev {
            if let Some(ref dev_deps) = root_pkg.dev_dependencies {
                top_level_names.extend(dev_deps.keys().cloned());
            }
        }
        if !self.options.omit_optional {
            if let Some(ref opt_deps) = root_pkg.optional_dependencies {
                top_level_names.extend(opt_deps.keys().cloned());
            }
        }

        for top_dep in top_level_names {
            let pkg_key = format!("node_modules/{top_dep}");
            if let Some(pkg_info) = lockfile.packages.get(&pkg_key) {
                if pkg_info.link == Some(true)
                    || pkg_info
                        .resolved
                        .as_ref()
                        .is_some_and(|r| r.starts_with("packages/"))
                {
                    continue; // Already wired as workspace member link
                }
            }

            let (pkg_name, pkg_ver, deps_hash) = match graph_nodes.get(&pkg_key) {
                Some(gnode) => match computed_hashes.get(&pkg_key) {
                    Some(h) => (&gnode.name, &gnode.version, h),
                    None => continue,
                },
                None => continue,
            };

            let target_pkg_dir = get_pkg_store_dir(&store_root, pkg_name, pkg_ver, deps_hash);
            if !target_pkg_dir.exists() {
                continue;
            }

            let proj_link = node_modules_dir.join(&top_dep);
            let manifest_path = target_pkg_dir.join("package.json");
            let is_native = if let Ok(pkg_m) = Manifest::from_file(&manifest_path) {
                is_mutating_lifecycle_package(&target_pkg_dir, &pkg_m)
            } else {
                false
            };

            if is_native {
                copy_dir_recursive(&target_pkg_dir, &proj_link)?;
                if let Ok(pkg_m) = Manifest::from_file(&manifest_path) {
                    if pkg_m.scripts.contains_key("preinstall")
                        || pkg_m.scripts.contains_key("install")
                        || pkg_m.scripts.contains_key("postinstall")
                    {
                        lifecycle_nodes.push(LifecyclePackageNode {
                            package_path: pkg_key.clone(),
                            disk_path: proj_link.clone(),
                            manifest: pkg_m,
                            source: PackageSource::Registry,
                            dependencies: Vec::new(),
                            optional: false,
                        });
                    }
                }
            } else {
                if !junction_points_to(&proj_link, &target_pkg_dir) {
                    create_or_replace_junction(&proj_link, &target_pkg_dir)?;
                }
            }

            packages_installed += 1;

            // Create shims in node_modules/.bin
            if let Ok(pkg_m) = Manifest::from_file(&manifest_path) {
                for (bin_name, script_rel) in pkg_m.bin_entries() {
                    let target_rel = format!("{top_dep}/{script_rel}");
                    let script_path = target_pkg_dir.join(&script_rel);
                    let _ = normalize_shebang(&script_path);
                    let _ = create_shims(bin_dir, &bin_name, &target_rel);
                }
            }
        }

        // 5. Run lifecycle scripts for per-project copies
        if !self.options.ignore_scripts && !lifecycle_nodes.is_empty() {
            let _life_guard = collector.enter_phase(Phase::Lifecycle);
            let sandbox_policy = if self.options.strict_sandbox {
                ScriptSandboxPolicy::restricted()
            } else {
                ScriptSandboxPolicy::permissive()
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
            execute_topological(&lifecycle_nodes, manifest, &lifecycle_opts).await?;
        }

        // 6. Write hidden lockfile
        let _lock_guard = collector.enter_phase(Phase::Lockfile);
        let hidden_lockfile_path = node_modules_dir.join(".package-lock.json");
        let _ = lockfile.save_to_file(&hidden_lockfile_path);
        drop(_lock_guard);

        Ok(InstallSummary {
            packages_installed,
            cache_hits,
            cache_misses,
            lockfile_path: self.options.project_dir.join("package-lock.json"),
            timing: Some(collector.finish()),
        })
    }
}
