use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_fs::junction::is_junction;
use rnpm_lockfile::LockfileV3;

/// A node in the dependency tree, representing either the root project or a package in node_modules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectedNode {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engines: Option<BTreeMap<String, String>>,

    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkgid: Option<String>,

    pub location: String, // "" for root, "node_modules/foo"
    pub path: Option<PathBuf>,
    pub realpath: Option<PathBuf>,
    pub resolved: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,

    #[serde(default)]
    pub from: Vec<String>,
    #[serde(default)]
    pub to: Vec<String>,

    #[serde(default)]
    pub dev: bool,
    #[serde(rename = "inBundle", default)]
    pub in_bundle: bool,
    #[serde(default)]
    pub deduped: bool,
    #[serde(default)]
    pub overridden: bool,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub peer: bool,

    #[serde(default)]
    pub extraneous: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid: Option<String>,
    #[serde(default)]
    pub missing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<String>,

    #[serde(rename = "queryContext", default)]
    pub query_context: BTreeMap<String, Value>,

    #[serde(default)]
    pub problems: Vec<String>,

    #[serde(default)]
    pub dependencies: BTreeMap<String, InspectedNode>,

    /// Raw package manifest JSON if available
    #[serde(skip)]
    pub raw_manifest: Option<Value>,
}

impl InspectedNode {
    pub fn new_root(name: String, version: Option<String>, project_dir: &Path) -> Self {
        let pkgid = match &version {
            Some(v) => format!("{name}@{v}"),
            None => name.clone(),
        };
        Self {
            id: Some(pkgid.clone()),
            pkgid: Some(pkgid),
            name,
            version,
            description: None,
            license: None,
            homepage: None,
            repository: None,
            engines: None,
            location: String::new(),
            path: Some(project_dir.to_path_buf()),
            realpath: Some(project_dir.to_path_buf()),
            resolved: None,
            integrity: None,
            from: Vec::new(),
            to: Vec::new(),
            dev: false,
            in_bundle: false,
            deduped: false,
            overridden: false,
            optional: false,
            peer: false,
            extraneous: false,
            invalid: None,
            missing: false,
            required: None,
            query_context: BTreeMap::new(),
            problems: Vec::new(),
            dependencies: BTreeMap::new(),
            raw_manifest: None,
        }
    }

    /// Flattens the dependency tree into a deduplicated list of all inspected nodes.
    pub fn collect_all_nodes(&self) -> Vec<&InspectedNode> {
        let mut list = Vec::new();
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(self);

        while let Some(node) = queue.pop_front() {
            if seen.insert(node.location.clone()) {
                list.push(node);
                for child in node.dependencies.values() {
                    queue.push_back(child);
                }
            }
        }

        list
    }

    /// Emits query representation matching npm query node schema.
    pub fn to_query_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("name".to_string(), Value::String(self.name.clone()));
        if let Some(v) = &self.version {
            map.insert("version".to_string(), Value::String(v.clone()));
        }
        if let Some(desc) = &self.description {
            map.insert("description".to_string(), Value::String(desc.clone()));
        }
        if let Some(lic) = &self.license {
            map.insert("license".to_string(), Value::String(lic.clone()));
        }
        if let Some(repo) = &self.repository {
            map.insert("repository".to_string(), repo.clone());
        }
        if let Some(eng) = &self.engines {
            map.insert(
                "engines".to_string(),
                serde_json::to_value(eng).unwrap_or(Value::Null),
            );
        }

        let pkgid = self.pkgid.clone().unwrap_or_else(|| match &self.version {
            Some(v) => format!("{}@{}", self.name, v),
            None => self.name.clone(),
        });
        map.insert("_id".to_string(), Value::String(pkgid.clone()));
        map.insert("pkgid".to_string(), Value::String(pkgid));

        map.insert("location".to_string(), Value::String(self.location.clone()));
        map.insert(
            "path".to_string(),
            match &self.path {
                Some(p) => Value::String(p.to_string_lossy().to_string()),
                None => Value::Null,
            },
        );
        map.insert(
            "realpath".to_string(),
            match &self.realpath {
                Some(p) => Value::String(p.to_string_lossy().to_string()),
                None => Value::Null,
            },
        );
        map.insert(
            "resolved".to_string(),
            match &self.resolved {
                Some(r) => Value::String(r.clone()),
                None => Value::Null,
            },
        );

        map.insert(
            "from".to_string(),
            serde_json::to_value(&self.from).unwrap_or_default(),
        );
        map.insert(
            "to".to_string(),
            serde_json::to_value(&self.to).unwrap_or_default(),
        );

        map.insert("dev".to_string(), Value::Bool(self.dev));
        map.insert("inBundle".to_string(), Value::Bool(self.in_bundle));
        map.insert("deduped".to_string(), Value::Bool(self.deduped));
        map.insert("overridden".to_string(), Value::Bool(self.overridden));

        let mut query_ctx = self.query_context.clone();
        if self.missing {
            query_ctx.insert("missing".to_string(), Value::Bool(true));
        }
        map.insert(
            "queryContext".to_string(),
            serde_json::to_value(query_ctx).unwrap_or_default(),
        );

        Value::Object(map)
    }
}

/// Options for tree building.
#[derive(Debug, Clone, Default)]
pub struct TreeOptions {
    /// Read dependency tree purely from package-lock.json without inspecting node_modules on disk.
    pub package_lock_only: bool,
    /// Omit development dependencies.
    pub omit_dev: bool,
    /// Omit optional dependencies.
    pub omit_optional: bool,
    /// Omit peer dependencies.
    pub omit_peer: bool,
}

/// Discovered package on disk.
#[derive(Debug, Clone)]
struct DiskPackage {
    pub location: String, // e.g. "node_modules/foo"
    pub dir_path: PathBuf,
    pub name: String,
    pub version: Option<String>,
    pub manifest: Option<Manifest>,
    pub raw_json: Option<Value>,
}

/// Scan `node_modules` directory recursively on disk and return map of location -> DiskPackage.
fn scan_disk_packages(project_dir: &Path) -> HashMap<String, DiskPackage> {
    let mut result = HashMap::new();
    let root_nm = project_dir.join("node_modules");
    if !root_nm.is_dir() {
        return result;
    }
    scan_nm_dir(project_dir, "node_modules", &mut result);
    result
}

fn scan_nm_dir(project_dir: &Path, nm_rel: &str, result: &mut HashMap<String, DiskPackage>) {
    let full_path = project_dir.join(nm_rel);
    let entries = match std::fs::read_dir(&full_path) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str.starts_with('.') {
            continue;
        }

        let entry_path = entry.path();
        let is_junc = is_junction(&entry_path).unwrap_or(false);
        if !entry_path.is_dir() && !is_junc {
            continue;
        }

        if name_str.starts_with('@') {
            // Scoped packages
            if let Ok(scoped_entries) = std::fs::read_dir(&entry_path) {
                for scoped_entry in scoped_entries.flatten() {
                    let sub_name = scoped_entry.file_name();
                    let sub_name_str = sub_name.to_string_lossy();
                    if sub_name_str.starts_with('.') {
                        continue;
                    }
                    let sub_path = scoped_entry.path();
                    let sub_junc = is_junction(&sub_path).unwrap_or(false);
                    if !sub_path.is_dir() && !sub_junc {
                        continue;
                    }

                    let loc = format!("{nm_rel}/{name_str}/{sub_name_str}");
                    let pkg_name = format!("{name_str}/{sub_name_str}");
                    let (manifest, raw_json, version) = load_package_manifest(&sub_path);

                    result.insert(
                        loc.clone(),
                        DiskPackage {
                            location: loc.clone(),
                            dir_path: sub_path.clone(),
                            name: manifest
                                .as_ref()
                                .and_then(|m| m.name.clone())
                                .unwrap_or(pkg_name),
                            version,
                            manifest,
                            raw_json,
                        },
                    );

                    if !sub_junc {
                        let nested_nm = sub_path.join("node_modules");
                        if nested_nm.is_dir() {
                            scan_nm_dir(project_dir, &format!("{loc}/node_modules"), result);
                        }
                    }
                }
            }
        } else {
            // Standard package
            let loc = format!("{nm_rel}/{name_str}");
            let pkg_name = name_str.to_string();
            let (manifest, raw_json, version) = load_package_manifest(&entry_path);

            result.insert(
                loc.clone(),
                DiskPackage {
                    location: loc.clone(),
                    dir_path: entry_path.clone(),
                    name: manifest
                        .as_ref()
                        .and_then(|m| m.name.clone())
                        .unwrap_or(pkg_name),
                    version,
                    manifest,
                    raw_json,
                },
            );

            if !is_junc {
                let nested_nm = entry_path.join("node_modules");
                if nested_nm.is_dir() {
                    scan_nm_dir(project_dir, &format!("{loc}/node_modules"), result);
                }
            }
        }
    }
}

fn load_package_manifest(dir: &Path) -> (Option<Manifest>, Option<Value>, Option<String>) {
    let manifest_path = dir.join("package.json");
    if let Ok(content) = std::fs::read_to_string(&manifest_path) {
        let manifest = serde_json::from_str::<Manifest>(&content).ok();
        let raw_json = serde_json::from_str::<Value>(&content).ok();
        let version = raw_json
            .as_ref()
            .and_then(|j| j.get("version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| manifest.as_ref().and_then(|m| m.version.clone()));
        (manifest, raw_json, version)
    } else {
        (None, None, None)
    }
}

/// Candidate locations in resolution order: from most nested to root node_modules.
pub fn candidate_locations(current_loc: &str, dep_name: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if current_loc.is_empty() {
        candidates.push(format!("node_modules/{dep_name}"));
        return candidates;
    }

    candidates.push(format!("{current_loc}/node_modules/{dep_name}"));

    let mut curr = current_loc;
    while let Some(idx) = curr.rfind("/node_modules/") {
        let ancestor = &curr[..idx];
        candidates.push(format!("{ancestor}/node_modules/{dep_name}"));
        curr = ancestor;
    }

    let root_cand = format!("node_modules/{dep_name}");
    if !candidates.contains(&root_cand) {
        candidates.push(root_cand);
    }

    candidates
}

/// Builds the complete inspected dependency tree.
pub fn build_dependency_tree(
    project_dir: &Path,
    options: &TreeOptions,
) -> anyhow::Result<InspectedNode> {
    let manifest_path = project_dir.join("package.json");
    let (root_manifest, root_raw) = if manifest_path.exists() {
        let content = std::fs::read_to_string(&manifest_path)?;
        let m = serde_json::from_str::<Manifest>(&content).ok();
        let j = serde_json::from_str::<Value>(&content).ok();
        (m, j)
    } else {
        (None, None)
    };

    let root_name = root_manifest
        .as_ref()
        .and_then(|m| m.name.clone())
        .or_else(|| {
            project_dir
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "project".to_string());
    let root_version = root_manifest.as_ref().and_then(|m| m.version.clone());

    let mut root = InspectedNode::new_root(root_name, root_version, project_dir);
    if let Some(m) = &root_manifest {
        root.description = m.description.clone();
    }
    if let Some(r) = &root_raw {
        root.license = r
            .get("license")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        root.homepage = r
            .get("homepage")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        root.repository = r.get("repository").cloned();
        root.raw_manifest = Some(r.clone());
    }

    let lockfile_path = project_dir.join("package-lock.json");
    let lockfile = if lockfile_path.exists() {
        LockfileV3::load_from_file(&lockfile_path).ok()
    } else {
        None
    };

    if options.package_lock_only {
        // Build purely from lockfile
        if let Some(lock) = lockfile {
            build_tree_from_lockfile(&mut root, project_dir, &lock, options)?;
        }
        return Ok(root);
    }

    // Normal mode: build from disk node_modules enriched by lockfile
    let disk_packages = scan_disk_packages(project_dir);

    // Track visited disk packages for reachability analysis
    let mut reachable_locations: HashSet<String> = HashSet::new();

    // 1. Direct dependencies from root manifest
    let mut direct_deps: BTreeMap<String, (String, &'static str)> = BTreeMap::new();
    if let Some(m) = &root_manifest {
        for (name, req) in &m.dependencies {
            direct_deps.insert(name.clone(), (req.clone(), "prod"));
        }
        if !options.omit_dev {
            for (name, req) in &m.dev_dependencies {
                direct_deps
                    .entry(name.clone())
                    .or_insert((req.clone(), "dev"));
            }
        }
        if !options.omit_optional {
            for (name, req) in &m.optional_dependencies {
                direct_deps
                    .entry(name.clone())
                    .or_insert((req.clone(), "optional"));
            }
        }
        if !options.omit_peer {
            for (name, req) in &m.peer_dependencies {
                direct_deps
                    .entry(name.clone())
                    .or_insert((req.clone(), "peer"));
            }
        }
    }

    let mut queue: VecDeque<String> = VecDeque::new();
    let mut resolved_nodes_by_loc: HashMap<String, InspectedNode> = HashMap::new();

    for (dep_name, (dep_req, dep_type)) in &direct_deps {
        let expected_loc = format!("node_modules/{dep_name}");
        root.to.push(expected_loc.clone());

        if let Some(disk_pkg) = disk_packages.get(&expected_loc) {
            reachable_locations.insert(expected_loc.clone());
            let mut node = create_node_from_disk(
                project_dir,
                disk_pkg,
                lockfile.as_ref(),
                Some(dep_req.clone()),
                dep_type,
            );
            node.from.push(String::new());

            // Validate version against requirement
            if let Some(v_str) = &node.version {
                if let (Ok(ver), Ok(range)) = (Version::parse(v_str), Range::parse(dep_req)) {
                    if !range.satisfies(&ver) {
                        let err_str = format!("\"{}\" from the root project", dep_req);
                        node.invalid = Some(err_str.clone());
                        let prob = format!(
                            "invalid: {}@{} {}",
                            node.name,
                            v_str,
                            node.path
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default()
                        );
                        node.problems.push(prob.clone());
                        root.problems.push(prob);
                    }
                }
            }

            resolved_nodes_by_loc.insert(expected_loc.clone(), node);
            queue.push_back(expected_loc);
        } else {
            // Missing package
            let mut missing_node = create_missing_node(dep_name, dep_req, &expected_loc, dep_type);
            missing_node.from.push(String::new());
            let prob = format!(
                "missing: {}@{}, required by {}@{}",
                dep_name,
                dep_req,
                root.name,
                root.version.as_deref().unwrap_or("")
            );
            missing_node.problems.push(prob.clone());
            root.problems.push(prob);

            root.dependencies.insert(dep_name.clone(), missing_node);
        }
    }

    // 2. Transitive BFS traversal
    while let Some(current_loc) = queue.pop_front() {
        let current_disk = match disk_packages.get(&current_loc) {
            Some(d) => d.clone(),
            None => continue,
        };

        let mut child_deps: BTreeMap<String, (String, &'static str)> = BTreeMap::new();
        if let Some(m) = &current_disk.manifest {
            for (name, req) in &m.dependencies {
                child_deps.insert(name.clone(), (req.clone(), "prod"));
            }
            if !options.omit_optional {
                for (name, req) in &m.optional_dependencies {
                    child_deps
                        .entry(name.clone())
                        .or_insert((req.clone(), "optional"));
                }
            }
            if !options.omit_peer {
                for (name, req) in &m.peer_dependencies {
                    child_deps
                        .entry(name.clone())
                        .or_insert((req.clone(), "peer"));
                }
            }
        }

        for (child_name, (child_req, child_type)) in &child_deps {
            let candidates = candidate_locations(&current_loc, child_name);
            let mut resolved_loc = None;

            for cand in &candidates {
                if disk_packages.contains_key(cand) {
                    resolved_loc = Some(cand.clone());
                    break;
                }
            }

            if let Some(target_loc) = resolved_loc {
                if let Some(curr_node) = resolved_nodes_by_loc.get_mut(&current_loc) {
                    if !curr_node.to.contains(&target_loc) {
                        curr_node.to.push(target_loc.clone());
                    }
                }

                let is_new = reachable_locations.insert(target_loc.clone());
                if is_new {
                    let disk_pkg = disk_packages.get(&target_loc).unwrap();
                    let mut node = create_node_from_disk(
                        project_dir,
                        disk_pkg,
                        lockfile.as_ref(),
                        Some(child_req.clone()),
                        child_type,
                    );
                    node.from.push(current_loc.clone());

                    // Check version validity
                    if let Some(v_str) = &node.version {
                        if let (Ok(ver), Ok(range)) =
                            (Version::parse(v_str), Range::parse(child_req))
                        {
                            if !range.satisfies(&ver) {
                                let err_str =
                                    format!("\"{}\" from {}", child_req, current_disk.name);
                                node.invalid = Some(err_str);
                            }
                        }
                    }

                    resolved_nodes_by_loc.insert(target_loc.clone(), node);
                    queue.push_back(target_loc);
                } else if let Some(existing) = resolved_nodes_by_loc.get_mut(&target_loc) {
                    if !existing.from.contains(&current_loc) {
                        existing.from.push(current_loc.clone());
                    }
                }
            } else {
                // Missing transitive dependency
                let expected_loc = format!("{current_loc}/node_modules/{child_name}");
                if let Some(curr_node) = resolved_nodes_by_loc.get_mut(&current_loc) {
                    curr_node.to.push(expected_loc.clone());
                }
                let mut missing_node =
                    create_missing_node(child_name, child_req, &expected_loc, child_type);
                missing_node.from.push(current_loc.clone());
                let prob = format!(
                    "missing: {}@{}, required by {}@{}",
                    child_name,
                    child_req,
                    current_disk.name,
                    current_disk.version.as_deref().unwrap_or("")
                );
                missing_node.problems.push(prob.clone());
                root.problems.push(prob);

                if let Some(curr_node) = resolved_nodes_by_loc.get_mut(&current_loc) {
                    curr_node
                        .dependencies
                        .insert(child_name.clone(), missing_node);
                }
            }
        }
    }

    // 3. Extraneous packages on disk (packages in node_modules not reachable from root dependencies)
    let mut extraneous_locations: Vec<String> = disk_packages
        .keys()
        .filter(|loc| !reachable_locations.contains(*loc))
        .cloned()
        .collect();
    extraneous_locations.sort();

    for ext_loc in extraneous_locations {
        let disk_pkg = disk_packages.get(&ext_loc).unwrap();
        let mut node = create_node_from_disk(
            project_dir,
            disk_pkg,
            lockfile.as_ref(),
            None,
            "dev", // or extraneous
        );
        node.extraneous = true;
        let prob = format!(
            "extraneous: {}@{} {}",
            node.name,
            node.version.as_deref().unwrap_or(""),
            node.path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );
        node.problems.push(prob.clone());
        root.problems.push(prob);

        root.dependencies.insert(node.name.clone(), node);
    }

    // 4. Assemble hierarchical tree under root
    // For direct dependencies of root:
    for dep_name in direct_deps.keys() {
        let loc = format!("node_modules/{dep_name}");
        if let Some(node) = resolved_nodes_by_loc.remove(&loc) {
            root.dependencies.insert(dep_name.clone(), node);
        }
    }

    // Attach nested children to their respective parents
    attach_nested_dependencies(&mut root.dependencies, &mut resolved_nodes_by_loc);

    Ok(root)
}

fn attach_nested_dependencies(
    current_map: &mut BTreeMap<String, InspectedNode>,
    resolved_by_loc: &mut HashMap<String, InspectedNode>,
) {
    for node in current_map.values_mut() {
        let _parent_loc = &node.location;
        for to_loc in &node.to {
            if let Some(child_node) = resolved_by_loc.remove(to_loc) {
                node.dependencies
                    .insert(child_node.name.clone(), child_node);
            } else if let Some(existing) = resolved_by_loc.get(to_loc) {
                // Deduped / hoisted elsewhere
                let mut deduped_node = existing.clone();
                deduped_node.deduped = true;
                node.dependencies
                    .insert(deduped_node.name.clone(), deduped_node);
            }
        }
        if !node.dependencies.is_empty() {
            attach_nested_dependencies(&mut node.dependencies, resolved_by_loc);
        }
    }
}

fn create_node_from_disk(
    _project_dir: &Path,
    disk_pkg: &DiskPackage,
    lockfile: Option<&LockfileV3>,
    required: Option<String>,
    dep_type: &'static str,
) -> InspectedNode {
    let pkgid = match &disk_pkg.version {
        Some(v) => format!("{}@{}", disk_pkg.name, v),
        None => disk_pkg.name.clone(),
    };

    let lock_pkg = lockfile.and_then(|l| l.packages.get(&disk_pkg.location));

    let resolved = lock_pkg.and_then(|p| p.resolved.clone());
    let integrity = lock_pkg.and_then(|p| p.integrity.clone());
    let overridden = lock_pkg
        .and_then(|p| p.extra.get("overridden").and_then(|v| v.as_bool()))
        .unwrap_or(false);

    let desc = disk_pkg
        .manifest
        .as_ref()
        .and_then(|m| m.description.clone());
    let license = disk_pkg.raw_json.as_ref().and_then(|j| {
        j.get("license")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let homepage = disk_pkg.raw_json.as_ref().and_then(|j| {
        j.get("homepage")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let repo = disk_pkg
        .raw_json
        .as_ref()
        .and_then(|j| j.get("repository").cloned());
    let engines = disk_pkg.manifest.as_ref().and_then(|m| {
        if m.engines.is_empty() {
            None
        } else {
            Some(
                m.engines
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            )
        }
    });

    InspectedNode {
        name: disk_pkg.name.clone(),
        version: disk_pkg.version.clone(),
        description: desc,
        license,
        homepage,
        repository: repo,
        engines,
        id: Some(pkgid.clone()),
        pkgid: Some(pkgid),
        location: disk_pkg.location.clone(),
        path: Some(disk_pkg.dir_path.clone()),
        realpath: Some(disk_pkg.dir_path.clone()),
        resolved,
        integrity,
        from: Vec::new(),
        to: Vec::new(),
        dev: dep_type == "dev" || lock_pkg.map(|p| p.is_dev()).unwrap_or(false),
        in_bundle: lock_pkg.map(|p| p.is_in_bundle()).unwrap_or(false),
        deduped: false,
        overridden,
        optional: dep_type == "optional" || lock_pkg.map(|p| p.is_optional()).unwrap_or(false),
        peer: dep_type == "peer" || lock_pkg.map(|p| p.is_peer()).unwrap_or(false),
        extraneous: false,
        invalid: None,
        missing: false,
        required,
        query_context: BTreeMap::new(),
        problems: Vec::new(),
        dependencies: BTreeMap::new(),
        raw_manifest: disk_pkg.raw_json.clone(),
    }
}

fn create_missing_node(
    name: &str,
    required: &str,
    location: &str,
    dep_type: &'static str,
) -> InspectedNode {
    let pkgid = format!("{name}@{required}");
    InspectedNode {
        name: name.to_string(),
        version: Some(required.to_string()),
        description: None,
        license: None,
        homepage: None,
        repository: None,
        engines: None,
        id: Some(pkgid.clone()),
        pkgid: Some(pkgid),
        location: location.to_string(),
        path: None,
        realpath: None,
        resolved: None,
        integrity: None,
        from: Vec::new(),
        to: Vec::new(),
        dev: dep_type == "dev",
        in_bundle: false,
        deduped: false,
        overridden: false,
        optional: dep_type == "optional",
        peer: dep_type == "peer",
        extraneous: false,
        invalid: None,
        missing: true,
        required: Some(required.to_string()),
        query_context: {
            let mut q = BTreeMap::new();
            q.insert("missing".to_string(), Value::Bool(true));
            q
        },
        problems: Vec::new(),
        dependencies: BTreeMap::new(),
        raw_manifest: None,
    }
}

fn build_tree_from_lockfile(
    root: &mut InspectedNode,
    project_dir: &Path,
    lockfile: &LockfileV3,
    options: &TreeOptions,
) -> anyhow::Result<()> {
    let root_lock = lockfile.packages.get("");
    let mut direct_deps: BTreeMap<String, String> = BTreeMap::new();

    if let Some(r) = root_lock {
        if let Some(deps) = &r.dependencies {
            for (k, v) in deps {
                direct_deps.insert(k.clone(), v.clone());
            }
        }
        if !options.omit_dev {
            if let Some(dev_deps) = &r.dev_dependencies {
                for (k, v) in dev_deps {
                    direct_deps.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
        if !options.omit_optional {
            if let Some(opt_deps) = &r.optional_dependencies {
                for (k, v) in opt_deps {
                    direct_deps.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
        if !options.omit_peer {
            if let Some(peer_deps) = &r.peer_dependencies {
                for (k, v) in peer_deps {
                    direct_deps.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
    }

    for (dep_name, req) in direct_deps {
        let loc = format!("node_modules/{dep_name}");
        root.to.push(loc.clone());

        if let Some(pkg) = lockfile.packages.get(&loc) {
            let mut node = create_node_from_lock(project_dir, &loc, dep_name.clone(), pkg);
            node.from.push(String::new());
            node.required = Some(req);
            root.dependencies.insert(dep_name, node);
        } else {
            let mut missing_node = create_missing_node(&dep_name, &req, &loc, "prod");
            missing_node.from.push(String::new());
            root.dependencies.insert(dep_name, missing_node);
        }
    }

    Ok(())
}

fn create_node_from_lock(
    project_dir: &Path,
    location: &str,
    name: String,
    pkg: &rnpm_lockfile::LockfilePackage,
) -> InspectedNode {
    let version = pkg.version.clone();
    let pkgid = match &version {
        Some(v) => format!("{name}@{v}"),
        None => name.clone(),
    };
    let path = project_dir.join(location);
    InspectedNode {
        name,
        version,
        description: None,
        license: pkg.license.clone(),
        homepage: None,
        repository: None,
        engines: pkg.engines_map(),
        id: Some(pkgid.clone()),
        pkgid: Some(pkgid),
        location: location.to_string(),
        path: Some(path.clone()),
        realpath: Some(path),
        resolved: pkg.resolved.clone(),
        integrity: pkg.integrity.clone(),
        from: Vec::new(),
        to: Vec::new(),
        dev: pkg.is_dev(),
        in_bundle: pkg.is_in_bundle(),
        deduped: false,
        overridden: false,
        optional: pkg.is_optional(),
        peer: pkg.is_peer(),
        extraneous: false,
        invalid: None,
        missing: false,
        required: None,
        query_context: BTreeMap::new(),
        problems: Vec::new(),
        dependencies: BTreeMap::new(),
        raw_manifest: None,
    }
}
