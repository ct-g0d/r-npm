use std::collections::{BTreeMap, HashSet};
use rnpm_lockfile::{LockfilePackage, LockfileV3, PackageBin};
use serde::{Deserialize, Serialize};

/// Type classification for dependency relationships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DependencyType {
    Prod,
    Dev,
    Peer,
    PeerOptional,
    Optional,
}

/// Flags associated with a resolved node in the tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeFlags {
    pub dev: bool,
    pub optional: bool,
    pub peer: bool,
    pub bundled: bool,
    pub has_install_script: bool,
    pub skipped: bool,
    pub link: bool,
}

/// A directed edge in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from_location: String,
    pub to_location: String,
    pub install_name: String,
    pub package_name: String,
    pub spec: String,
    pub dep_type: DependencyType,
}

/// A node in the resolved dependency graph representing a package placed in `node_modules`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Node {
    /// Relative POSIX path in the tree (e.g. `""`, `"node_modules/foo"`, `"node_modules/bar/node_modules/foo"`).
    pub location: String,
    /// Directory/folder name under parent's node_modules (or manifest key).
    pub install_name: String,
    /// Physical/real package name.
    pub name: String,
    /// Exact resolved version string.
    pub version: String,
    /// Resolved tarball URL or file path.
    pub resolved: Option<String>,
    /// Integrity hash (SSRI string).
    pub integrity: Option<String>,
    /// Package classification flags.
    pub flags: NodeFlags,
    /// Outgoing dependencies (key -> spec).
    pub dependencies: BTreeMap<String, String>,
    /// Outgoing devDependencies (only present on root node).
    pub dev_dependencies: BTreeMap<String, String>,
    /// Declared peer dependencies.
    pub peer_dependencies: BTreeMap<String, String>,
    /// Declared optional dependencies.
    pub optional_dependencies: BTreeMap<String, String>,
    /// Platform OS constraints.
    pub os: Option<Vec<String>>,
    /// Platform CPU architecture constraints.
    pub cpu: Option<Vec<String>>,
    /// Platform libc constraints.
    pub libc: Option<Vec<String>>,
    /// Executable binaries.
    pub bin: Option<PackageBin>,
    /// Cached parsed semver for fast zero-allocation evaluation.
    #[serde(skip, default)]
    pub parsed_version: Option<rnpm_core::semver::Version>,
    /// Preserved hidden-tree metadata or arbitrary package properties.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Complete resolved dependency graph and tree geometry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DependencyGraph {
    pub root_location: String,
    pub nodes: BTreeMap<String, Node>,
    pub edges: Vec<DependencyEdge>,
    pub skipped: HashSet<String>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            root_location: String::new(),
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            skipped: HashSet::new(),
        }
    }

    pub fn is_skipped(&self, name: &str) -> bool {
        self.skipped.contains(name)
            || self.nodes.values().any(|n| n.name == name && n.flags.skipped)
    }

    pub fn get_node(&self, location: &str) -> Option<&Node> {
        self.nodes.get(location)
    }

    pub fn get_node_mut(&mut self, location: &str) -> Option<&mut Node> {
        self.nodes.get_mut(location)
    }

    pub fn get_outgoing_edges(&self, from_location: &str) -> Vec<&DependencyEdge> {
        self.edges
            .iter()
            .filter(|e| e.from_location == from_location)
            .collect()
    }

    /// Removes a direct dependency from root node by package name and removes the corresponding edge.
    pub fn remove_root_dependency(&mut self, package_name: &str) -> bool {
        let mut removed = false;
        if let Some(root_node) = self.nodes.get_mut(&self.root_location) {
            if root_node.dependencies.remove(package_name).is_some() {
                removed = true;
            }
            if root_node.dev_dependencies.remove(package_name).is_some() {
                removed = true;
            }
            if root_node.optional_dependencies.remove(package_name).is_some() {
                removed = true;
            }
        }
        if removed {
            self.edges.retain(|e| !(e.from_location == self.root_location && e.install_name == package_name));
        }
        removed
    }

    /// Prunes all unreferenced nodes and edges from the dependency graph starting from the root node.
    /// Traverses outgoing edges from root_location (typically "") and removes any nodes and edges
    /// that are no longer reachable.
    /// Returns the set of node locations that were pruned.
    pub fn prune_unreferenced(&mut self) -> std::collections::HashSet<String> {
        use std::collections::{HashMap, HashSet, VecDeque};
        let mut reachable = HashSet::new();
        reachable.insert(self.root_location.clone());

        // Build adjacency index O(E) once to avoid O(V * E) lookups and allocations
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &self.edges {
            adj.entry(edge.from_location.as_str())
                .or_default()
                .push(edge.to_location.as_str());
        }

        let mut queue = VecDeque::new();
        queue.push_back(self.root_location.as_str());

        while let Some(curr) = queue.pop_front() {
            if let Some(targets) = adj.get(curr) {
                for &target in targets {
                    if reachable.insert(target.to_string()) {
                        queue.push_back(target);
                    }
                }
            }
        }

        let mut pruned = HashSet::new();
        let all_locations: Vec<String> = self.nodes.keys().cloned().collect();
        for loc in all_locations {
            if !reachable.contains(&loc) {
                self.nodes.remove(&loc);
                pruned.insert(loc);
            }
        }

        self.edges.retain(|e| reachable.contains(&e.from_location) && reachable.contains(&e.to_location));
        pruned
    }

    /// Converts this resolved graph into an npm lockfile version 3 document.
    pub fn to_lockfile_v3(&self, root_name: &str, root_version: Option<&str>) -> LockfileV3 {
        let mut lockfile = LockfileV3::new(root_name, root_version.map(|v| v.to_string()));

        for (loc, node) in &self.nodes {
            if loc.is_empty() {
                // Update root package entry ""
                if let Some(root_pkg) = lockfile.root_package_mut() {
                    if !node.dependencies.is_empty() {
                        root_pkg.dependencies = Some(node.dependencies.clone());
                    }
                    if !node.dev_dependencies.is_empty() {
                        root_pkg.dev_dependencies = Some(node.dev_dependencies.clone());
                    }
                    if !node.peer_dependencies.is_empty() {
                        root_pkg.peer_dependencies = Some(node.peer_dependencies.clone());
                    }
                    if !node.optional_dependencies.is_empty() {
                        root_pkg.optional_dependencies = Some(node.optional_dependencies.clone());
                    }
                    if let Some(bin) = &node.bin {
                        root_pkg.bin = Some(bin.clone());
                    }
                    root_pkg.extra = node.extra.clone();
                }
            } else {
                let is_dev_and_opt = node.flags.dev && node.flags.optional;
                let pkg = LockfilePackage {
                    name: if node.install_name != node.name {
                        Some(node.name.clone())
                    } else {
                        None
                    },
                    version: Some(node.version.clone()),
                    resolved: node.resolved.clone(),
                    integrity: node.integrity.clone(),
                    link: if node.flags.link { Some(true) } else { None },
                    dev: if node.flags.dev && !is_dev_and_opt { Some(true) } else { None },
                    optional: if node.flags.optional && !is_dev_and_opt { Some(true) } else { None },
                    dev_optional: if is_dev_and_opt { Some(true) } else { None },
                    in_bundle: if node.flags.bundled { Some(true) } else { None },
                    has_install_script: if node.flags.has_install_script {
                        Some(true)
                    } else {
                        None
                    },
                    dependencies: if !node.dependencies.is_empty() {
                        Some(node.dependencies.clone())
                    } else {
                        None
                    },
                    peer_dependencies: if !node.peer_dependencies.is_empty() {
                        Some(node.peer_dependencies.clone())
                    } else {
                        None
                    },
                    optional_dependencies: if !node.optional_dependencies.is_empty() {
                        Some(node.optional_dependencies.clone())
                    } else {
                        None
                    },
                    os: node.os.clone(),
                    cpu: node.cpu.clone(),
                    libc: node.libc.clone(),
                    bin: node.bin.clone(),
                    extra: node.extra.clone(),
                    ..Default::default()
                };
                lockfile.insert_package(loc, pkg);
            }
        }

        lockfile
    }

    /// Constructs an in-memory DependencyGraph from an npm lockfile version 3 document.
    pub fn from_lockfile_v3(lockfile: &LockfileV3) -> Self {
        let mut graph = Self::new();
        graph.root_location = String::new();

        for (loc, pkg) in &lockfile.packages {
            let install_name = if loc.is_empty() {
                pkg.name.clone().unwrap_or_else(|| lockfile.name.clone())
            } else if let Some(idx) = loc.rfind("/node_modules/") {
                loc[idx + 14..].to_string()
            } else if let Some(stripped) = loc.strip_prefix("node_modules/") {
                stripped.to_string()
            } else {
                loc.clone()
            };

            let name = pkg.name.clone().unwrap_or_else(|| install_name.clone());
            let version = pkg.version.clone().unwrap_or_default();
            let parsed_version = rnpm_core::semver::Version::parse(&version).ok();

            let is_dev_opt = pkg.dev_optional.unwrap_or(false);
            let node = Node {
                location: loc.clone(),
                install_name: install_name.clone(),
                name,
                parsed_version,
                version,
                resolved: pkg.resolved.clone(),
                integrity: pkg.integrity.clone(),
                flags: NodeFlags {
                    dev: pkg.dev.unwrap_or(false) || is_dev_opt,
                    optional: pkg.optional.unwrap_or(false) || is_dev_opt,
                    peer: false,
                    bundled: pkg.in_bundle.unwrap_or(false),
                    has_install_script: pkg.has_install_script.unwrap_or(false),
                    skipped: false,
                    link: pkg.link.unwrap_or(false),
                },
                dependencies: pkg.dependencies.clone().unwrap_or_default(),
                dev_dependencies: pkg.dev_dependencies.clone().unwrap_or_default(),
                peer_dependencies: pkg.peer_dependencies.clone().unwrap_or_default(),
                optional_dependencies: pkg.optional_dependencies.clone().unwrap_or_default(),
                os: pkg.os.clone(),
                cpu: pkg.cpu.clone(),
                libc: pkg.libc.clone(),
                bin: pkg.bin.clone(),
                extra: pkg.extra.clone(),
            };
            graph.nodes.insert(loc.clone(), node);
        }

        // Build edges based on dependencies
        for (loc, node) in &graph.nodes {
            let mut all_deps = Vec::new();
            for (dep_name, dep_spec) in &node.dependencies {
                all_deps.push((dep_name.clone(), dep_spec.clone(), DependencyType::Prod));
            }
            for (dep_name, dep_spec) in &node.dev_dependencies {
                all_deps.push((dep_name.clone(), dep_spec.clone(), DependencyType::Dev));
            }
            for (dep_name, dep_spec) in &node.optional_dependencies {
                all_deps.push((dep_name.clone(), dep_spec.clone(), DependencyType::Optional));
            }

            for (dep_name, dep_spec, dep_type) in all_deps {
                let target_loc = if loc.is_empty() {
                    let direct = format!("node_modules/{dep_name}");
                    if graph.nodes.contains_key(&direct) {
                        Some(direct)
                    } else {
                        None
                    }
                } else {
                    let nested = format!("{loc}/node_modules/{dep_name}");
                    let hoisted = format!("node_modules/{dep_name}");
                    if graph.nodes.contains_key(&nested) {
                        Some(nested)
                    } else if graph.nodes.contains_key(&hoisted) {
                        Some(hoisted)
                    } else {
                        // Check ancestor scopes
                        let mut found = None;
                        let parts: Vec<&str> = loc.split("/node_modules/").collect();
                        for i in (1..parts.len()).rev() {
                            let ancestor = parts[..i].join("/node_modules/");
                            let candidate = format!("{ancestor}/node_modules/{dep_name}");
                            if graph.nodes.contains_key(&candidate) {
                                found = Some(candidate);
                                break;
                            }
                        }
                        found
                    }
                };

                if let Some(target) = target_loc {
                    let target_pkg_name = graph.nodes.get(&target).map(|n| n.name.clone()).unwrap_or_else(|| dep_name.clone());
                    graph.edges.push(DependencyEdge {
                        from_location: loc.clone(),
                        to_location: target,
                        install_name: dep_name.clone(),
                        package_name: target_pkg_name,
                        spec: dep_spec,
                        dep_type,
                    });
                }
            }
        }

        graph
    }
}
