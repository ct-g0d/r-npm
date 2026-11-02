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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
                }
            } else {
                let pkg = LockfilePackage {
                    name: if node.install_name != node.name {
                        Some(node.name.clone())
                    } else {
                        None
                    },
                    version: Some(node.version.clone()),
                    resolved: node.resolved.clone(),
                    integrity: node.integrity.clone(),
                    dev: if node.flags.dev { Some(true) } else { None },
                    optional: if node.flags.optional { Some(true) } else { None },
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
                    ..Default::default()
                };
                lockfile.insert_package(loc, pkg);
            }
        }

        lockfile
    }
}
