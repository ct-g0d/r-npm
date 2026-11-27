use crate::fast_util::{fast_map_with_capacity, fast_set_with_capacity, FastMap, FastSet};
use rnpm_core::PlatformList;
use rnpm_lockfile::{LockfilePackage, LockfileV3, PackageBin};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

fn normalize_bin_paths(bin: Option<&PackageBin>, package_name: &str) -> Option<PackageBin> {
    let bin = bin?;
    match bin {
        PackageBin::Single(path) => {
            let clean = path.strip_prefix("./").unwrap_or(path).to_string();
            let bin_name = package_name.rsplit('/').next().unwrap_or(package_name);
            let mut map = BTreeMap::new();
            map.insert(bin_name.to_string(), clean);
            Some(PackageBin::Map(map))
        }
        PackageBin::Map(paths) => {
            // npm-normalize-package-bin drops a bin map with no entries.
            if paths.is_empty() {
                return None;
            }
            if paths.values().all(|p| !p.starts_with("./")) {
                return Some(PackageBin::Map(paths.clone()));
            }
            let map = paths
                .iter()
                .map(|(name, path)| {
                    (
                        name.clone(),
                        path.strip_prefix("./").unwrap_or(path).to_string(),
                    )
                })
                .collect();
            Some(PackageBin::Map(map))
        }
    }
}

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
    #[serde(default)]
    pub dev_optional: bool,
    pub peer: bool,
    pub bundled: bool,
    pub has_install_script: bool,
    pub skipped: bool,
    /// Own platform constraint, separate from skip state inherited from parents.
    /// Unspecified values preserve flags supplied by existing graph callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_skipped: Option<bool>,
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    /// Declared peer dependencies metadata (e.g. optionality).
    pub peer_dependencies_meta: BTreeMap<String, rnpm_core::manifest::PeerDependencyMeta>,
    /// Declared optional dependencies.
    pub optional_dependencies: BTreeMap<String, String>,
    /// Platform OS constraints.
    pub os: Option<PlatformList>,
    /// Platform CPU architecture constraints.
    pub cpu: Option<PlatformList>,
    /// Platform libc constraints.
    pub libc: Option<PlatformList>,
    /// Executable binaries.
    pub bin: Option<PackageBin>,
    /// Package license copied into lockfile metadata.
    pub license: Option<String>,
    /// Package engine constraints copied into lockfile metadata.
    pub engines: BTreeMap<String, String>,
    /// Cached parsed semver for fast zero-allocation evaluation.
    #[serde(skip, default)]
    pub parsed_version: Option<rnpm_core::semver::Version>,
    /// Preserved hidden-tree metadata or arbitrary package properties.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.location == other.location
            && self.install_name == other.install_name
            && self.name == other.name
            && self.version == other.version
            && self.resolved == other.resolved
            && self.integrity == other.integrity
            && self.flags == other.flags
            && self.dependencies == other.dependencies
            && self.dev_dependencies == other.dev_dependencies
            && self.peer_dependencies == other.peer_dependencies
            && self.peer_dependencies_meta == other.peer_dependencies_meta
            && self.optional_dependencies == other.optional_dependencies
            && self.os == other.os
            && self.cpu == other.cpu
            && self.libc == other.libc
            && self.bin == other.bin
            && self.license == other.license
            && self.engines == other.engines
            && self.extra == other.extra
    }
}

impl Eq for Node {}

impl Node {
    /// `$name` override references of this package, in arborist's edge.js
    /// lookup order: dev, optional, dependencies, peer. The first non-empty
    /// spec wins (an empty string is falsy in arborist).
    pub fn all_dependency_specs(&self) -> BTreeMap<String, String> {
        let mut specs = BTreeMap::new();
        for section in [
            &self.peer_dependencies,
            &self.dependencies,
            &self.optional_dependencies,
            &self.dev_dependencies,
        ] {
            for (name, spec) in section {
                if !spec.is_empty() {
                    specs.insert(name.clone(), spec.clone());
                }
            }
        }
        specs
    }

    pub fn bundle_dependencies(&self) -> Option<rnpm_core::manifest::BundledDependencies> {
        if self.extra.is_empty() {
            return None;
        }
        let val = self
            .extra
            .get("bundleDependencies")
            .or_else(|| self.extra.get("bundledDependencies"))?;
        match val {
            serde_json::Value::Bool(b) => Some(rnpm_core::manifest::BundledDependencies::Boolean(*b)),
            serde_json::Value::Array(arr) => {
                let mut list = Vec::with_capacity(arr.len());
                for item in arr {
                    list.push(item.as_str()?.to_string());
                }
                Some(rnpm_core::manifest::BundledDependencies::List(list))
            }
            serde_json::Value::Object(map) => {
                Some(rnpm_core::manifest::BundledDependencies::List(
                    map.keys().cloned().collect(),
                ))
            }
            _ => None,
        }
    }

    pub(crate) fn is_bundled_dependency(&self, name: &str) -> bool {
        if self.extra.is_empty() {
            return false;
        }
        let Some(val) = self
            .extra
            .get("bundleDependencies")
            .or_else(|| self.extra.get("bundledDependencies"))
        else {
            return false;
        };
        match val {
            serde_json::Value::Bool(true) => self.dependencies.contains_key(name),
            serde_json::Value::Array(arr) => {
                arr.iter().all(|v| v.is_string()) && arr.iter().any(|v| v.as_str() == Some(name))
            }
            serde_json::Value::Object(map) => map.contains_key(name),
            _ => false,
        }
    }

    pub fn bundled_package_names(&self) -> Vec<String> {
        match self.bundle_dependencies() {
            None => Vec::new(),
            Some(rnpm_core::manifest::BundledDependencies::Boolean(true)) => {
                self.dependencies.keys().cloned().collect()
            }
            Some(rnpm_core::manifest::BundledDependencies::Boolean(false)) => Vec::new(),
            Some(rnpm_core::manifest::BundledDependencies::List(list)) => list,
        }
    }
}

/// Complete resolved dependency graph and tree geometry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DependencyGraph {
    pub root_location: String,
    pub nodes: BTreeMap<String, Node>,
    pub edges: Vec<DependencyEdge>,
    pub skipped: HashSet<String>,
    /// `legacy-peer-deps`: arborist creates no peer edges at all.
    #[serde(skip)]
    pub legacy_peer_deps: bool,
    /// Incremental index: dependency/install name -> node locations declaring it as a dependency.
    #[serde(skip, default)]
    pub nodes_by_dep_name: HashMap<String, Vec<String>>,
    /// Incremental index: edge install name -> edge indices in self.edges.
    #[serde(skip, default)]
    pub edges_by_install_name: HashMap<String, Vec<usize>>,
    /// Incremental index: parent scope -> child node locations directly under parent's node_modules.
    #[serde(skip, default)]
    pub children_by_parent: HashMap<String, Vec<String>>,
    /// Incremental index: package real name -> node locations.
    #[serde(skip, default)]
    pub nodes_by_name: HashMap<String, Vec<String>>,
    /// Incremental index: folder/install name -> node locations.
    #[serde(skip, default)]
    pub nodes_by_install_name: HashMap<String, Vec<String>>,
    /// Incremental index: target node location -> incoming edge indices.
    #[serde(skip, default)]
    pub incoming_edges_by_location: HashMap<String, Vec<usize>>,
    /// Incremental index: source node location -> outgoing edge indices.
    #[serde(skip, default)]
    pub outgoing_edges_by_location: HashMap<String, Vec<usize>>,
}

impl PartialEq for DependencyGraph {
    fn eq(&self, other: &Self) -> bool {
        self.root_location == other.root_location
            && self.nodes == other.nodes
            && self.edges == other.edges
            && self.skipped == other.skipped
            && self.legacy_peer_deps == other.legacy_peer_deps
    }
}

impl Eq for DependencyGraph {}

impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            root_location: String::new(),
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            skipped: HashSet::new(),
            legacy_peer_deps: false,
            nodes_by_dep_name: HashMap::new(),
            edges_by_install_name: HashMap::new(),
            children_by_parent: HashMap::new(),
            nodes_by_name: HashMap::new(),
            nodes_by_install_name: HashMap::new(),
            incoming_edges_by_location: HashMap::new(),
            outgoing_edges_by_location: HashMap::new(),
        }
    }

    /// Adds or replaces a node in the graph, updating all secondary indices.
    pub fn add_node(&mut self, location: String, node: Node) {
        match self.nodes.entry(location) {
            std::collections::btree_map::Entry::Vacant(e) => {
                Self::add_node_to_indices(
                    &mut self.nodes_by_dep_name,
                    &mut self.nodes_by_name,
                    &mut self.nodes_by_install_name,
                    &mut self.children_by_parent,
                    e.key(),
                    &node,
                );
                e.insert(node);
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                let old = std::mem::replace(e.get_mut(), node);
                Self::remove_node_from_indices(
                    &mut self.nodes_by_dep_name,
                    &mut self.nodes_by_name,
                    &mut self.nodes_by_install_name,
                    &mut self.children_by_parent,
                    e.key(),
                    &old,
                );
                Self::add_node_to_indices(
                    &mut self.nodes_by_dep_name,
                    &mut self.nodes_by_name,
                    &mut self.nodes_by_install_name,
                    &mut self.children_by_parent,
                    e.key(),
                    e.get(),
                );
            }
        }
    }

    /// Removes a node from the graph and updates all secondary indices.
    pub fn remove_node(&mut self, location: &str) -> Option<Node> {
        if let Some(node) = self.nodes.remove(location) {
            Self::remove_node_from_indices(
                &mut self.nodes_by_dep_name,
                &mut self.nodes_by_name,
                &mut self.nodes_by_install_name,
                &mut self.children_by_parent,
                location,
                &node,
            );
            Some(node)
        } else {
            None
        }
    }

    /// Adds an edge to the graph, updating all secondary indices.
    pub fn add_edge(&mut self, edge: DependencyEdge) {
        let idx = self.edges.len();
        Self::add_edge_to_indices(
            &mut self.edges_by_install_name,
            &mut self.incoming_edges_by_location,
            &mut self.outgoing_edges_by_location,
            idx,
            &edge,
        );
        self.edges.push(edge);
    }

    /// Removes an edge by index and rebuilds edge indices.
    pub fn remove_edge(&mut self, index: usize) -> Option<DependencyEdge> {
        if index < self.edges.len() {
            let edge = self.edges.remove(index);
            self.rebuild_edge_indices();
            Some(edge)
        } else {
            None
        }
    }

    /// Checks if a node location has any child packages nested directly under its `node_modules`.
    #[inline]
    pub fn has_children(&self, location: &str) -> bool {
        if self.children_by_parent.is_empty() && !self.nodes.is_empty() {
            return self.nodes.keys().any(|child| {
                if let Some(rest) = child.strip_prefix(location) {
                    if location.is_empty() {
                        rest.starts_with("node_modules/")
                    } else {
                        rest.starts_with("/node_modules/")
                    }
                } else {
                    false
                }
            });
        }
        self.children_by_parent
            .get(location)
            .is_some_and(|children| !children.is_empty())
    }

    #[inline]
    fn push_index_str(map: &mut HashMap<String, Vec<String>>, key: &str, location: &str) {
        if let Some(vec) = map.get_mut(key) {
            vec.push(location.to_string());
        } else {
            map.insert(key.to_string(), vec![location.to_string()]);
        }
    }

    #[inline]
    fn push_index_usize(map: &mut HashMap<String, Vec<usize>>, key: &str, idx: usize) {
        if let Some(vec) = map.get_mut(key) {
            vec.push(idx);
        } else {
            map.insert(key.to_string(), vec![idx]);
        }
    }

    /// Helper to index a node across all node-related secondary maps.
    /// Callers (`add_node` after `remove_node_from_indices`, `rebuild_indices` after `clear`)
    /// guarantee `location` is not currently present in any index bucket.
    fn add_node_to_indices(
        nodes_by_dep_name: &mut HashMap<String, Vec<String>>,
        nodes_by_name: &mut HashMap<String, Vec<String>>,
        nodes_by_install_name: &mut HashMap<String, Vec<String>>,
        children_by_parent: &mut HashMap<String, Vec<String>>,
        location: &str,
        node: &Node,
    ) {
        for name in node.dependencies.keys() {
            Self::push_index_str(nodes_by_dep_name, name, location);
        }
        for name in node.optional_dependencies.keys() {
            if !node.dependencies.contains_key(name) {
                Self::push_index_str(nodes_by_dep_name, name, location);
            }
        }
        for name in node.peer_dependencies.keys() {
            if !node.dependencies.contains_key(name)
                && !node.optional_dependencies.contains_key(name)
            {
                Self::push_index_str(nodes_by_dep_name, name, location);
            }
        }
        for name in node.dev_dependencies.keys() {
            if !node.dependencies.contains_key(name)
                && !node.optional_dependencies.contains_key(name)
                && !node.peer_dependencies.contains_key(name)
            {
                Self::push_index_str(nodes_by_dep_name, name, location);
            }
        }

        Self::push_index_str(nodes_by_name, &node.name, location);
        Self::push_index_str(nodes_by_install_name, &node.install_name, location);

        if let Some(parent) = crate::hoisting::parent_scope(location) {
            Self::push_index_str(children_by_parent, parent, location);
        }
    }

    /// Helper to remove a node from all node-related secondary maps.
    fn remove_node_from_indices(
        nodes_by_dep_name: &mut HashMap<String, Vec<String>>,
        nodes_by_name: &mut HashMap<String, Vec<String>>,
        nodes_by_install_name: &mut HashMap<String, Vec<String>>,
        children_by_parent: &mut HashMap<String, Vec<String>>,
        location: &str,
        node: &Node,
    ) {
        let remove_loc = |map: &mut HashMap<String, Vec<String>>, key: &str| {
            if let Some(vec) = map.get_mut(key) {
                vec.retain(|l| l != location);
                if vec.is_empty() {
                    map.remove(key);
                }
            }
        };

        for name in node.dependencies.keys() {
            remove_loc(nodes_by_dep_name, name);
        }
        for name in node.optional_dependencies.keys() {
            if !node.dependencies.contains_key(name) {
                remove_loc(nodes_by_dep_name, name);
            }
        }
        for name in node.peer_dependencies.keys() {
            if !node.dependencies.contains_key(name)
                && !node.optional_dependencies.contains_key(name)
            {
                remove_loc(nodes_by_dep_name, name);
            }
        }
        for name in node.dev_dependencies.keys() {
            if !node.dependencies.contains_key(name)
                && !node.optional_dependencies.contains_key(name)
                && !node.peer_dependencies.contains_key(name)
            {
                remove_loc(nodes_by_dep_name, name);
            }
        }

        remove_loc(nodes_by_name, &node.name);
        remove_loc(nodes_by_install_name, &node.install_name);

        if let Some(parent) = crate::hoisting::parent_scope(location) {
            remove_loc(children_by_parent, parent);
        }
    }

    /// Helper to index an edge into edge-related secondary maps.
    fn add_edge_to_indices(
        edges_by_install_name: &mut HashMap<String, Vec<usize>>,
        incoming_edges_by_location: &mut HashMap<String, Vec<usize>>,
        outgoing_edges_by_location: &mut HashMap<String, Vec<usize>>,
        idx: usize,
        edge: &DependencyEdge,
    ) {
        Self::push_index_usize(edges_by_install_name, &edge.install_name, idx);
        Self::push_index_usize(incoming_edges_by_location, &edge.to_location, idx);
        Self::push_index_usize(outgoing_edges_by_location, &edge.from_location, idx);
    }

    #[inline]
    fn push_fast<'a, V>(map: &mut FastMap<&'a str, Vec<V>>, key: &'a str, val: V) {
        match map.entry(key) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(vec![val]);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().push(val);
            }
        }
    }

    /// Rebuilds edge secondary indices from scratch.
    pub fn rebuild_edge_indices(&mut self) {
        self.edges_by_install_name.clear();
        self.incoming_edges_by_location.clear();
        self.outgoing_edges_by_location.clear();
        let edge_count = self.edges.len();
        if edge_count == 0 {
            return;
        }
        let mut by_install: FastMap<&str, Vec<usize>> =
            fast_map_with_capacity(edge_count / 4 + 16);
        let mut by_incoming: FastMap<&str, Vec<usize>> =
            fast_map_with_capacity(edge_count / 4 + 16);
        let mut by_outgoing: FastMap<&str, Vec<usize>> =
            fast_map_with_capacity(edge_count / 8 + 16);
        for (idx, edge) in self.edges.iter().enumerate() {
            Self::push_fast(&mut by_install, edge.install_name.as_str(), idx);
            Self::push_fast(&mut by_incoming, edge.to_location.as_str(), idx);
            Self::push_fast(&mut by_outgoing, edge.from_location.as_str(), idx);
        }
        self.edges_by_install_name.reserve(by_install.len());
        for (k, v) in by_install {
            self.edges_by_install_name.insert(k.to_string(), v);
        }
        self.incoming_edges_by_location.reserve(by_incoming.len());
        for (k, v) in by_incoming {
            self.incoming_edges_by_location.insert(k.to_string(), v);
        }
        self.outgoing_edges_by_location.reserve(by_outgoing.len());
        for (k, v) in by_outgoing {
            self.outgoing_edges_by_location.insert(k.to_string(), v);
        }
    }

    /// Rebuilds all secondary graph indices from scratch.
    pub fn rebuild_indices(&mut self) {
        self.nodes_by_dep_name.clear();
        self.nodes_by_name.clear();
        self.nodes_by_install_name.clear();
        self.children_by_parent.clear();
        let node_count = self.nodes.len();
        if node_count > 0 {
            let mut by_dep: FastMap<&str, Vec<String>> =
                fast_map_with_capacity(node_count / 2 + 16);
            let mut by_name: FastMap<&str, Vec<String>> =
                fast_map_with_capacity(node_count / 2 + 16);
            let mut by_install: FastMap<&str, Vec<String>> =
                fast_map_with_capacity(node_count / 2 + 16);
            let mut by_parent: FastMap<&str, Vec<String>> =
                fast_map_with_capacity(node_count / 8 + 16);

            for (loc, node) in &self.nodes {
                let loc_str = loc.as_str();
                for name in node.dependencies.keys() {
                    Self::push_fast(&mut by_dep, name.as_str(), loc_str.to_string());
                }
                for name in node.optional_dependencies.keys() {
                    if !node.dependencies.contains_key(name) {
                        Self::push_fast(&mut by_dep, name.as_str(), loc_str.to_string());
                    }
                }
                for name in node.peer_dependencies.keys() {
                    if !node.dependencies.contains_key(name)
                        && !node.optional_dependencies.contains_key(name)
                    {
                        Self::push_fast(&mut by_dep, name.as_str(), loc_str.to_string());
                    }
                }
                for name in node.dev_dependencies.keys() {
                    if !node.dependencies.contains_key(name)
                        && !node.optional_dependencies.contains_key(name)
                        && !node.peer_dependencies.contains_key(name)
                    {
                        Self::push_fast(&mut by_dep, name.as_str(), loc_str.to_string());
                    }
                }
                Self::push_fast(&mut by_name, node.name.as_str(), loc_str.to_string());
                Self::push_fast(
                    &mut by_install,
                    node.install_name.as_str(),
                    loc_str.to_string(),
                );
                if let Some(parent) = crate::hoisting::parent_scope(loc_str) {
                    Self::push_fast(&mut by_parent, parent, loc_str.to_string());
                }
            }

            self.nodes_by_dep_name.reserve(by_dep.len());
            for (k, v) in by_dep {
                self.nodes_by_dep_name.insert(k.to_string(), v);
            }
            self.nodes_by_name.reserve(by_name.len());
            for (k, v) in by_name {
                self.nodes_by_name.insert(k.to_string(), v);
            }
            self.nodes_by_install_name.reserve(by_install.len());
            for (k, v) in by_install {
                self.nodes_by_install_name.insert(k.to_string(), v);
            }
            self.children_by_parent.reserve(by_parent.len());
            for (k, v) in by_parent {
                self.children_by_parent.insert(k.to_string(), v);
            }
        }
        self.rebuild_edge_indices();
    }

    pub fn is_skipped(&self, name: &str) -> bool {
        self.skipped.contains(name)
            || self
                .nodes
                .values()
                .any(|n| n.name == name && n.flags.skipped)
    }

    pub fn get_node(&self, location: &str) -> Option<&Node> {
        self.nodes.get(location)
    }

    pub fn get_node_mut(&mut self, location: &str) -> Option<&mut Node> {
        self.nodes.get_mut(location)
    }

    pub fn get_outgoing_edges(&self, from_location: &str) -> Vec<&DependencyEdge> {
        if !self.outgoing_edges_by_location.is_empty() {
            if let Some(indices) = self.outgoing_edges_by_location.get(from_location) {
                indices.iter().map(|&i| &self.edges[i]).collect()
            } else {
                Vec::new()
            }
        } else {
            self.edges
                .iter()
                .filter(|e| e.from_location == from_location)
                .collect()
        }
    }

    /// Recomputes dev/optional reachability from the root dependency edges.
    ///
    /// A package is marked `dev` only when every path from the root reaches it
    /// through a dev dependency. This matters for shared transitive packages:
    /// a package first discovered through a dev branch must lose its dev flag
    /// when a production branch also reaches the same node. The same rule is
    /// applied to optional reachability so dependencies below an optional
    /// platform package remain optional in the lockfile.
    /// Arborist keeps an edge for every optional peer and resolves it once a
    /// provider lands in the tree, even if that happens after its owner was
    /// placed. Those late edges keep the provider alive in calc-dep-flags.
    fn link_late_optional_peers(&mut self) {
        if self.legacy_peer_deps {
            return;
        }
        let has_outgoing_index = !self.outgoing_edges_by_location.is_empty() || self.edges.is_empty();
        let mut fallback_existing: Option<FastSet<(&str, &str)>> = None;
        let mut late = Vec::new();
        for (location, node) in &self.nodes {
            if node.peer_dependencies.is_empty()
                || node.peer_dependencies_meta.is_empty()
                || resolves_to_root(node)
            {
                continue;
            }
            for (name, spec) in &node.peer_dependencies {
                if node.dependencies.contains_key(name)
                    || node.optional_dependencies.contains_key(name)
                {
                    continue;
                }
                let optional = node
                    .peer_dependencies_meta
                    .get(name)
                    .is_some_and(|m| m.optional);
                if !optional {
                    continue;
                }
                let already_exists = if has_outgoing_index {
                    self.outgoing_edges_by_location
                        .get(location.as_str())
                        .is_some_and(|idxs| {
                            idxs.iter().any(|&i| self.edges[i].install_name == *name)
                        })
                } else {
                    let set = fallback_existing.get_or_insert_with(|| {
                        let mut s = fast_set_with_capacity(self.edges.len());
                        for e in &self.edges {
                            s.insert((e.from_location.as_str(), e.install_name.as_str()));
                        }
                        s
                    });
                    set.contains(&(location.as_str(), name.as_str()))
                };
                if already_exists {
                    continue;
                }
                if let Some(target) = crate::hoisting::find_visible_node(self, location, name) {
                    if target.location == *location {
                        continue;
                    }
                    let parsed_ver = target
                        .parsed_version
                        .as_ref()
                        .map(std::borrow::Cow::Borrowed)
                        .or_else(|| {
                            crate::hoisting::cached_version_rc(&target.version)
                                .map(|rc| std::borrow::Cow::Owned((*rc).clone()))
                        });
                    let satisfies = parsed_ver.as_ref().is_some_and(|v| {
                        crate::hoisting::cached_target_rc(spec).is_some_and(|t| match &*t {
                            rnpm_core::PackageTarget::Range(r) => r.satisfies(v.as_ref()),
                            rnpm_core::PackageTarget::Version(tv) => tv == v.as_ref(),
                            // PackageTarget::parse classifies wildcard aliases like "x"/"X"/"x.x"
                            // as Tag, while Range::parse accepts them as >=0.0.0.
                            rnpm_core::PackageTarget::Tag(_) => {
                                rnpm_core::semver::Range::parse(spec)
                                    .is_ok_and(|r| r.satisfies(v.as_ref()))
                            }
                            _ => false,
                        })
                    });
                    if satisfies {
                        late.push(DependencyEdge {
                            from_location: location.clone(),
                            to_location: target.location.clone(),
                            install_name: name.clone(),
                            package_name: target.name.clone(),
                            spec: spec.clone(),
                            dep_type: DependencyType::PeerOptional,
                        });
                    }
                }
            }
        }
        if !late.is_empty() {
            if has_outgoing_index {
                for edge in late {
                    self.add_edge(edge);
                }
            } else {
                self.edges.extend(late);
                self.rebuild_edge_indices();
            }
        }
    }

    pub fn normalize_dependency_flags(&mut self) {
        self.link_late_optional_peers();
        const NON_DEV: u8 = 0b01;
        const DEV_ONLY: u8 = 0b10;
        const NON_OPTIONAL: u8 = 0b01;
        const OPTIONAL_ONLY: u8 = 0b10;

        let node_count = self.nodes.len();
        if node_count == 0 && self.edges.is_empty() {
            return;
        }

        // Assign dense integer IDs 0..node_count matching BTreeMap order, plus virtual slots
        // if root_location or synthetic edge endpoints are not in self.nodes.
        let mut loc_to_id: FastMap<&str, u32> = fast_map_with_capacity(node_count + 1);
        let mut locs: Vec<&str> = Vec::with_capacity(node_count + 1);
        let mut initially_skipped: Vec<bool> = Vec::with_capacity(node_count + 1);
        let mut node_resolves_to_root: Vec<bool> = Vec::with_capacity(node_count);
        let mut link_targets: Vec<(u32, &str, &str)> = Vec::new();
        let mut root_id: Option<u32> = None;

        for (idx, (loc, node)) in self.nodes.iter().enumerate() {
            let id = idx as u32;
            let loc_str = loc.as_str();
            loc_to_id.insert(loc_str, id);
            locs.push(loc_str);
            initially_skipped.push(node.flags.platform_skipped.unwrap_or(node.flags.skipped));
            node_resolves_to_root.push(resolves_to_root(node));
            if loc_str == self.root_location.as_str() {
                root_id = Some(id);
            }
            if node.flags.link {
                if let Some(ref target) = node.resolved {
                    link_targets.push((id, loc_str, target.as_str()));
                }
            }
        }

        let root_id = match root_id {
            Some(id) => id,
            None => {
                let id = locs.len() as u32;
                let r = self.root_location.as_str();
                loc_to_id.insert(r, id);
                locs.push(r);
                initially_skipped.push(false);
                id
            }
        };

        let mut raw_edges: Vec<(u32, u32, DependencyType)> =
            Vec::with_capacity(self.edges.len() + link_targets.len());

        for edge in &self.edges {
            let from_id = if let Some(&id) = loc_to_id.get(edge.from_location.as_str()) {
                if (id as usize) < node_count && id != root_id && node_resolves_to_root[id as usize]
                {
                    continue;
                }
                id
            } else {
                let id = locs.len() as u32;
                let s = edge.from_location.as_str();
                loc_to_id.insert(s, id);
                locs.push(s);
                initially_skipped.push(false);
                id
            };
            let to_id = if let Some(&id) = loc_to_id.get(edge.to_location.as_str()) {
                id
            } else {
                let id = locs.len() as u32;
                let s = edge.to_location.as_str();
                loc_to_id.insert(s, id);
                locs.push(s);
                initially_skipped.push(false);
                id
            };
            raw_edges.push((from_id, to_id, edge.dep_type));
        }

        // A link and its target are one node to calc-dep-flags: whatever
        // reaches the link reaches the target (e.g. a workspace member) and its
        // dependencies. A prod pass-through edge carries every state unchanged.
        for (from_id, from_loc, target) in link_targets {
            if target != from_loc {
                if let Some(&target_id) = loc_to_id.get(target) {
                    if (target_id as usize) < node_count {
                        raw_edges.push((from_id, target_id, DependencyType::Prod));
                    }
                }
            }
        }

        let total_nodes = locs.len();
        // Flat CSR adjacency lists replace per-node `Vec` heap allocations.
        let mut offsets: Vec<u32> = vec![0; total_nodes + 1];
        for &(from_id, _, _) in &raw_edges {
            offsets[from_id as usize + 1] += 1;
        }
        for i in 1..=total_nodes {
            offsets[i] += offsets[i - 1];
        }
        let mut cursor = offsets[..total_nodes].to_vec();
        let mut adj: Vec<(u32, DependencyType)> = vec![(0, DependencyType::Prod); raw_edges.len()];
        for (from_id, to_id, dep_type) in raw_edges {
            let slot = &mut cursor[from_id as usize];
            adj[*slot as usize] = (to_id, dep_type);
            *slot += 1;
        }

        // Pack 4x2-bit states per node:
        // bits 0..1: dev, bits 2..3: optional, bits 4..5: peer, bits 6..7: skipped
        let mut states: Vec<u8> = vec![0; total_nodes];
        states[root_id as usize] = NON_DEV | (NON_OPTIONAL << 2) | (NON_DEV << 4) | (NON_DEV << 6);

        let mut in_queue: Vec<bool> = vec![false; total_nodes];
        let mut queue = VecDeque::with_capacity(total_nodes.min(256));
        queue.push_back(root_id);
        in_queue[root_id as usize] = true;

        while let Some(id) = queue.pop_front() {
            in_queue[id as usize] = false;
            let s = states[id as usize];
            let dev_state = s & 0b11;
            let optional_state = (s >> 2) & 0b11;
            let peer_state = (s >> 4) & 0b11;
            let skipped_state = (s >> 6) & 0b11;

            let start = offsets[id as usize] as usize;
            let end = offsets[id as usize + 1] as usize;
            for &(to_id, dep_type) in &adj[start..end] {
                let to_idx = to_id as usize;

                let mut next_dev = dev_state & DEV_ONLY;
                if dev_state & NON_DEV != 0 {
                    next_dev |= if dep_type == DependencyType::Dev {
                        DEV_ONLY
                    } else {
                        NON_DEV
                    };
                }

                let mut next_optional = optional_state & OPTIONAL_ONLY;
                if optional_state & NON_OPTIONAL != 0 {
                    next_optional |= if matches!(
                        dep_type,
                        DependencyType::Optional | DependencyType::PeerOptional
                    ) {
                        OPTIONAL_ONLY
                    } else {
                        NON_OPTIONAL
                    };
                }

                let mut next_peer = peer_state & DEV_ONLY;
                if peer_state & NON_DEV != 0 {
                    next_peer |= if matches!(
                        dep_type,
                        DependencyType::Peer | DependencyType::PeerOptional
                    ) {
                        DEV_ONLY
                    } else {
                        NON_DEV
                    };
                }

                let next_skipped = if (skipped_state & DEV_ONLY) != 0
                    || (initially_skipped[to_idx] && dep_type == DependencyType::Optional)
                {
                    DEV_ONLY
                } else {
                    NON_DEV
                };

                let next_packed = next_dev
                    | (next_optional << 2)
                    | (next_peer << 4)
                    | (next_skipped << 6);
                let prev = states[to_idx];
                let merged = prev | next_packed;
                if merged != prev {
                    states[to_idx] = merged;
                    if !in_queue[to_idx] {
                        in_queue[to_idx] = true;
                        queue.push_back(to_id);
                    }
                }
            }
        }

        // Identify nodes reachable via a pure production path from root
        // (paths containing no dev, optional, or peer-optional edges).
        let mut pure_prod_reachable = vec![false; total_nodes];
        pure_prod_reachable[root_id as usize] = true;
        queue.push_back(root_id);
        while let Some(id) = queue.pop_front() {
            let start = offsets[id as usize] as usize;
            let end = offsets[id as usize + 1] as usize;
            for &(to_id, dep_type) in &adj[start..end] {
                if dep_type != DependencyType::Dev
                    && dep_type != DependencyType::Optional
                    && dep_type != DependencyType::PeerOptional
                    && !pure_prod_reachable[to_id as usize]
                {
                    pure_prod_reachable[to_id as usize] = true;
                    queue.push_back(to_id);
                }
            }
        }

        // Arborist calc-dep-flags keeps nodes reached only through optional
        // peers extraneous. Their ordinary dependencies inherit that state.
        let mut non_extraneous = vec![false; total_nodes];
        non_extraneous[root_id as usize] = true;
        queue.push_back(root_id);
        while let Some(id) = queue.pop_front() {
            let start = offsets[id as usize] as usize;
            let end = offsets[id as usize + 1] as usize;
            for &(to_id, dep_type) in &adj[start..end] {
                if dep_type != DependencyType::PeerOptional && !non_extraneous[to_id as usize] {
                    non_extraneous[to_id as usize] = true;
                    queue.push_back(to_id);
                }
            }
        }
        // Required nested children also keep their physical parents alive.
        for id in 0..total_nodes {
            if !non_extraneous[id] {
                continue;
            }
            let mut scope = locs[id];
            while let Some((parent, _)) = scope.rsplit_once("/node_modules/") {
                if let Some(&pid) = loc_to_id.get(parent) {
                    non_extraneous[pid as usize] = true;
                }
                scope = parent;
            }
        }

        let root_loc = self.root_location.as_str();
        for (idx, (location, node)) in self.nodes.iter_mut().enumerate() {
            if location.as_str() == root_loc {
                continue;
            }
            let packed = states[idx];
            let dev_state = packed & 0b11;
            let optional_state = (packed >> 2) & 0b11;
            let peer_state = (packed >> 4) & 0b11;
            let skipped_state = (packed >> 6) & 0b11;

            if dev_state != 0 && !non_extraneous[idx] {
                node.extra
                    .insert("extraneous".to_string(), serde_json::Value::Bool(true));
            } else if !node.extra.is_empty() {
                node.extra.remove("extraneous");
            }

            let is_dev = dev_state == DEV_ONLY;
            let is_optional = optional_state == OPTIONAL_ONLY;
            let reachable_from_dev = (dev_state & DEV_ONLY) != 0;
            let reachable_from_optional = (optional_state & OPTIONAL_ONLY) != 0;
            let is_pure_prod = pure_prod_reachable[idx];

            node.flags.dev = is_dev;
            node.flags.optional = is_optional;
            node.flags.peer = peer_state == DEV_ONLY;
            node.flags.dev_optional = !is_pure_prod
                && reachable_from_dev
                && reachable_from_optional
                && !is_dev
                && !is_optional;
            node.flags.skipped = skipped_state == DEV_ONLY;
            if node.flags.skipped {
                self.skipped.insert(node.name.clone());
                self.skipped.insert(node.install_name.clone());
            }
        }
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
            if root_node
                .optional_dependencies
                .remove(package_name)
                .is_some()
            {
                removed = true;
            }
        }
        if removed {
            self.edges.retain(|e| {
                !(e.from_location == self.root_location && e.install_name == package_name)
            });
            self.rebuild_indices();
        }
        removed
    }

    /// Prunes all unreferenced nodes and edges from the dependency graph starting from the root node.
    /// Traverses outgoing edges from root_location (typically "") and removes any nodes and edges
    /// that are no longer reachable.
    /// Returns the set of node locations that were pruned.
    pub fn prune_unreferenced(&mut self) -> std::collections::HashSet<String> {
        use std::collections::{HashMap, HashSet, VecDeque};
        let mut reachable: HashSet<String> = HashSet::new();
        reachable.insert(self.root_location.clone());

        {
            // Build adjacency index O(E) once to avoid O(V * E) lookups and allocations
            let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
            for edge in &self.edges {
                adj.entry(edge.from_location.as_str())
                    .or_default()
                    .push(edge.to_location.as_str());
            }

            let mut queue = VecDeque::new();
            queue.push_back(self.root_location.as_str());

            for (loc, node) in &self.nodes {
                if !loc.is_empty()
                    && (!loc.starts_with("node_modules/") || node.flags.link)
                    && reachable.insert(loc.clone())
                {
                    queue.push_back(loc.as_str());
                }
            }

            while let Some(curr) = queue.pop_front() {
                if let Some(targets) = adj.get(curr) {
                    for &target in targets {
                        if reachable.insert(target.to_string()) {
                            queue.push_back(target);
                        }
                    }
                }
            }
        }

        let mut pruned = HashSet::new();
        self.nodes.retain(|loc, _| {
            let is_reachable = reachable.contains(loc);
            if !is_reachable {
                pruned.insert(loc.clone());
            }
            is_reachable
        });

        self.edges
            .retain(|e| reachable.contains(&e.from_location) && reachable.contains(&e.to_location));
        self.rebuild_indices();
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
                    if !node.peer_dependencies_meta.is_empty() {
                        root_pkg.peer_dependencies_meta = Some(
                            node.peer_dependencies_meta
                                .iter()
                                .map(|(k, v)| {
                                    let mut obj = serde_json::Map::with_capacity(1);
                                    obj.insert(
                                        "optional".to_string(),
                                        serde_json::Value::Bool(v.optional),
                                    );
                                    (k.clone(), serde_json::Value::Object(obj))
                                })
                                .collect(),
                        );
                    }
                    if !node.optional_dependencies.is_empty() {
                        root_pkg.optional_dependencies = Some(node.optional_dependencies.clone());
                    }
                    if let Some(bin) = &node.bin {
                        root_pkg.bin = normalize_bin_paths(Some(bin), &node.name);
                    }
                    if node.flags.has_install_script {
                        root_pkg.has_install_script = Some(true);
                    }
                    root_pkg.license = node.license.clone().or_else(|| {
                        node.extra.get("license").and_then(|v| {
                            if let Some(s) = v.as_str() {
                                Some(s.to_string())
                            } else if let Some(obj) = v.as_object() {
                                obj.get("type").and_then(|t| t.as_str()).map(str::to_string)
                            } else {
                                None
                            }
                        })
                    });
                    root_pkg.engines = if node.engines.is_empty() {
                        None
                    } else {
                        Some(rnpm_lockfile::PackageEngines::Map(node.engines.clone()))
                    };
                    if let Some(bundled) = node.bundle_dependencies() {
                        root_pkg.bundle_dependencies = Some(bundled);
                    }
                    let mut filtered_extra = std::collections::BTreeMap::new();
                    for (k, v) in &node.extra {
                        if k == "overrides"
                            || k == "directories"
                            || k == "license"
                            || k == "libc"
                            || k == "bundleDependencies"
                            || k == "bundledDependencies"
                        {
                            continue;
                        }
                        if k == "deprecated"
                            && (v == &serde_json::Value::Bool(false) || v.is_null() || v == "")
                        {
                            continue;
                        }
                        if k == "funding" && v.is_string() {
                            // npm normalizes a string funding to { url }.
                            filtered_extra.insert(k.clone(), serde_json::json!({ "url": v }));
                        } else if matches!(k.as_str(), "funding" | "deprecated") {
                            filtered_extra.insert(k.clone(), v.clone());
                        }
                    }
                    root_pkg.extra = filtered_extra;
                }
            } else {
                // npm represents workspace and file links as a lightweight
                // entry containing only the target and the link marker.  The
                // package metadata belongs to the physical target entry (for
                // example `packages/foo`), rather than being duplicated at
                // `node_modules/foo`.  Keeping link entries minimal is also
                // important for lockfile parity because npm omits version,
                // dependencies, and flags from these nodes.
                if node.flags.link {
                    let clean_resolved = node
                        .resolved
                        .as_ref()
                        .map(|r| r.strip_prefix("./").unwrap_or(r).to_string());
                    lockfile.insert_package(
                        loc,
                        LockfilePackage {
                            resolved: clean_resolved,
                            link: Some(true),
                            ..Default::default()
                        },
                    );
                    continue;
                }

                // npm 11 / Arborist Shrinkwrap.metaFromNode:
                // - When a package node is both dev and optional (`dev && optional`),
                //   emit `dev: true, optional: true` (and DO NOT emit `devOptional`).
                // - When a package node is reachable from both a dev path and an optional path
                //   but is neither exclusively dev nor exclusively optional (`dev_optional && !dev && !optional`),
                //   emit `devOptional: true`.
                // - When neither applies, omit `devOptional`.
                let has_extra = !node.extra.is_empty();
                let extraneous = has_extra
                    && node.extra.get("extraneous") == Some(&serde_json::Value::Bool(true));
                let (dev, optional, dev_optional) = if extraneous {
                    (None, None, None)
                } else if node.flags.dev && node.flags.optional {
                    (Some(true), Some(true), None)
                } else if node.flags.dev_optional && !node.flags.dev && !node.flags.optional {
                    (None, None, Some(true))
                } else {
                    (
                        if node.flags.dev { Some(true) } else { None },
                        if node.flags.optional {
                            Some(true)
                        } else {
                            None
                        },
                        None,
                    )
                };

                let license = node.license.clone().or_else(|| {
                    if !has_extra {
                        return None;
                    }
                    node.extra.get("license").and_then(|v| {
                        if let Some(s) = v.as_str() {
                            Some(s.to_string())
                        } else if let Some(obj) = v.as_object() {
                            obj.get("type").and_then(|t| t.as_str()).map(str::to_string)
                        } else {
                            None
                        }
                    })
                });

                let libc = node
                    .libc
                    .as_ref()
                    .filter(|v| !v.is_empty())
                    .cloned()
                    .or_else(|| {
                        if !has_extra {
                            return None;
                        }
                        node.extra.get("libc").and_then(|v| {
                            if let Some(s) = v.as_str() {
                                Some(PlatformList::from(s.to_string()))
                            } else if let Some(arr) = v.as_array() {
                                let list: Vec<String> = arr
                                    .iter()
                                    .filter_map(|x| x.as_str().map(str::to_string))
                                    .collect();
                                if list.is_empty() {
                                    None
                                } else {
                                    Some(list.into())
                                }
                            } else {
                                None
                            }
                        })
                    });

                let os = node.os.as_ref().filter(|v| !v.is_empty()).cloned();
                let cpu = node.cpu.as_ref().filter(|v| !v.is_empty()).cloned();

                let mut extra = BTreeMap::new();
                if has_extra {
                    for key in ["funding", "deprecated", "extraneous", "workspaces"] {
                        if let Some(v) = node.extra.get(key) {
                            if key == "deprecated"
                                && (v == &serde_json::Value::Bool(false) || v.is_null() || v == "")
                            {
                                continue;
                            }
                            extra.insert(key.to_string(), v.clone());
                        }
                    }
                }

                let is_standard_nm_loc = loc
                    .rsplit("/node_modules/")
                    .next()
                    .and_then(|leaf| leaf.strip_prefix("node_modules/").or(Some(leaf)))
                    == Some(node.name.as_str());
                let pkg = LockfilePackage {
                    preserve_dev_optional_split: true,
                    name: if !is_standard_nm_loc {
                        Some(node.name.clone())
                    } else {
                        None
                    },
                    version: Some(node.version.clone()),
                    resolved: node.resolved.clone(),
                    integrity: node.integrity.clone(),
                    link: None,
                    dev,
                    optional,
                    dev_optional,
                    peer: if node.flags.peer && !extraneous {
                        Some(true)
                    } else {
                        None
                    },
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
                    peer_dependencies_meta: if !node.peer_dependencies_meta.is_empty() {
                        Some(
                            node.peer_dependencies_meta
                                .iter()
                                .map(|(k, v)| {
                                    let mut obj = serde_json::Map::with_capacity(1);
                                    obj.insert(
                                        "optional".to_string(),
                                        serde_json::Value::Bool(v.optional),
                                    );
                                    (k.clone(), serde_json::Value::Object(obj))
                                })
                                .collect(),
                        )
                    } else {
                        None
                    },
                    optional_dependencies: if !node.optional_dependencies.is_empty() {
                        Some(node.optional_dependencies.clone())
                    } else {
                        None
                    },
                    os,
                    cpu,
                    libc,
                    bin: normalize_bin_paths(node.bin.as_ref(), &node.name),
                    license,
                    engines: if let Some(raw) = has_extra
                        .then(|| node.extra.get("engines"))
                        .flatten()
                    {
                        serde_json::from_value(raw.clone()).ok()
                    } else if node.engines.is_empty() {
                        None
                    } else {
                        Some(rnpm_lockfile::PackageEngines::Map(node.engines.clone()))
                    },
                    bundle_dependencies: if has_extra {
                        node.bundle_dependencies()
                    } else {
                        None
                    },
                    extra,
                    ..Default::default()
                };
                let mut pkg = pkg;
                if has_extra {
                    pkg.normalize_flags();
                }
                let posix_loc = if loc.contains('\\') {
                    rnpm_core::to_posix_path(loc)
                } else {
                    loc.clone()
                };
                lockfile.packages.insert(posix_loc, pkg);
            }
        }

        lockfile
    }

    /// Constructs an in-memory DependencyGraph from an npm lockfile version 3 document.
    pub fn from_lockfile_v3(lockfile: &LockfileV3) -> Self {
        let mut graph = Self::new();
        graph.root_location = String::new();
        let mut estimated_edges = 0usize;

        for (loc, pkg) in &lockfile.packages {
            estimated_edges += pkg.dependencies.as_ref().map_or(0, BTreeMap::len)
                + pkg.dev_dependencies.as_ref().map_or(0, BTreeMap::len)
                + pkg.optional_dependencies.as_ref().map_or(0, BTreeMap::len)
                + pkg.peer_dependencies.as_ref().map_or(0, BTreeMap::len);

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

            let is_dev_opt = pkg.dev_optional.unwrap_or(false);
            let peer_dependencies_meta = pkg
                .peer_dependencies_meta
                .as_ref()
                .map(|meta_map| {
                    meta_map
                        .iter()
                        .map(|(k, v)| {
                            let meta = match v.as_object() {
                                Some(obj) if obj.len() == 1 && obj.contains_key("optional") => {
                                    rnpm_core::manifest::PeerDependencyMeta {
                                        optional: obj
                                            .get("optional")
                                            .and_then(|b| b.as_bool())
                                            .unwrap_or(false),
                                    }
                                }
                                _ => serde_json::from_value(v.clone()).unwrap_or_default(),
                            };
                            (k.clone(), meta)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let parsed_version = if version.is_empty() {
                None
            } else {
                rnpm_core::semver::Version::parse(&version).ok()
            };
            let node = Node {
                location: loc.clone(),
                install_name,
                name,
                parsed_version,
                version,
                resolved: pkg.resolved.clone(),
                integrity: pkg.integrity.clone(),
                flags: NodeFlags {
                    dev: pkg.dev.unwrap_or(false),
                    optional: pkg.optional.unwrap_or(false),
                    dev_optional: is_dev_opt,
                    peer: pkg.peer.unwrap_or(false),
                    bundled: pkg.in_bundle.unwrap_or(false),
                    has_install_script: pkg.has_install_script.unwrap_or(false),
                    skipped: false,
                    platform_skipped: None,
                    link: pkg.link.unwrap_or(false),
                },
                dependencies: pkg.dependencies.clone().unwrap_or_default(),
                dev_dependencies: pkg.dev_dependencies.clone().unwrap_or_default(),
                peer_dependencies: pkg.peer_dependencies.clone().unwrap_or_default(),
                peer_dependencies_meta,
                optional_dependencies: pkg.optional_dependencies.clone().unwrap_or_default(),
                os: pkg.os.clone(),
                cpu: pkg.cpu.clone(),
                libc: pkg.libc.clone(),
                bin: pkg.bin.clone(),
                license: pkg.license.clone(),
                engines: pkg.engines_map().unwrap_or_default(),
                extra: {
                    let mut extra = pkg.extra.clone();
                    if let Some(ref bd) = pkg.bundle_dependencies {
                        if let Ok(val) = serde_json::to_value(bd) {
                            extra.insert("bundleDependencies".to_string(), val);
                        }
                    }
                    extra
                },
            };
            graph.nodes.insert(loc.clone(), node);
        }

        // Fast O(1)-per-scope lookup table for resolving lockfile dependency targets into edges.
        let mut node_by_loc: FastMap<&str, &Node> = fast_map_with_capacity(graph.nodes.len());
        let mut parent_scopes: FastSet<&str> = fast_set_with_capacity(graph.nodes.len() / 8 + 8);
        parent_scopes.insert("");
        for (loc, node) in &graph.nodes {
            node_by_loc.insert(loc.as_str(), node);
            if let Some(parent) = crate::hoisting::parent_scope(loc) {
                parent_scopes.insert(parent);
            }
        }

        // Helper buffer to locate package in scope hierarchy without allocations
        let mut candidate_buf = String::with_capacity(128);
        graph.edges.reserve(estimated_edges);

        let node_count = graph.nodes.len();
        let mut by_dep: FastMap<&str, Vec<String>> = fast_map_with_capacity(node_count / 2 + 16);
        let mut by_name: FastMap<&str, Vec<String>> = fast_map_with_capacity(node_count / 2 + 16);
        let mut by_install: FastMap<&str, Vec<String>> =
            fast_map_with_capacity(node_count / 2 + 16);
        let mut by_parent: FastMap<&str, Vec<String>> =
            fast_map_with_capacity(node_count / 8 + 16);
        let mut edge_by_install: FastMap<&str, Vec<usize>> =
            fast_map_with_capacity(estimated_edges / 4 + 16);
        let mut edge_by_incoming: FastMap<&str, Vec<usize>> =
            fast_map_with_capacity(estimated_edges / 4 + 16);
        graph
            .outgoing_edges_by_location
            .reserve(node_count / 2 + 16);

        // Build edges and all 7 secondary indices in one single pass
        for (loc, node) in &graph.nodes {
            let loc_str = loc.as_str();
            Self::push_fast(&mut by_name, node.name.as_str(), loc_str.to_string());
            Self::push_fast(&mut by_install, node.install_name.as_str(), loc_str.to_string());
            if let Some(parent) = crate::hoisting::parent_scope(loc_str) {
                Self::push_fast(&mut by_parent, parent, loc_str.to_string());
            }

            let out_start = graph.edges.len();
            macro_rules! resolve_edge {
                ($dep_name:expr, $dep_spec:expr, $dep_type:expr) => {{
                    let mut found_node: Option<&Node> = None;
                    for scope in crate::hoisting::iter_ancestor_scopes(loc_str) {
                        if !parent_scopes.contains(scope) {
                            continue;
                        }
                        candidate_buf.clear();
                        if scope.is_empty() {
                            candidate_buf.push_str("node_modules/");
                        } else {
                            candidate_buf.push_str(scope);
                            candidate_buf.push_str("/node_modules/");
                        }
                        candidate_buf.push_str($dep_name);
                        if let Some(&target_node) = node_by_loc.get(candidate_buf.as_str()) {
                            found_node = Some(target_node);
                            break;
                        }
                    }

                    if let Some(target_node) = found_node {
                        let idx = graph.edges.len();
                        Self::push_fast(&mut edge_by_install, $dep_name.as_str(), idx);
                        Self::push_fast(&mut edge_by_incoming, target_node.location.as_str(), idx);
                        graph.edges.push(DependencyEdge {
                            from_location: loc.clone(),
                            to_location: target_node.location.clone(),
                            install_name: $dep_name.clone(),
                            package_name: target_node.name.clone(),
                            spec: $dep_spec.clone(),
                            dep_type: $dep_type,
                        });
                    }
                }};
            }

            for (n, s) in &node.dependencies {
                Self::push_fast(&mut by_dep, n.as_str(), loc_str.to_string());
                resolve_edge!(n, s, DependencyType::Prod);
            }
            for (n, s) in &node.dev_dependencies {
                if !node.dependencies.contains_key(n)
                    && !node.optional_dependencies.contains_key(n)
                    && !node.peer_dependencies.contains_key(n)
                {
                    Self::push_fast(&mut by_dep, n.as_str(), loc_str.to_string());
                }
                resolve_edge!(n, s, DependencyType::Dev);
            }
            for (n, s) in &node.optional_dependencies {
                if !node.dependencies.contains_key(n) {
                    Self::push_fast(&mut by_dep, n.as_str(), loc_str.to_string());
                }
                resolve_edge!(n, s, DependencyType::Optional);
            }
            for (name, spec) in &node.peer_dependencies {
                if !node.dependencies.contains_key(name)
                    && !node.optional_dependencies.contains_key(name)
                {
                    Self::push_fast(&mut by_dep, name.as_str(), loc_str.to_string());
                }
                if node.dependencies.contains_key(name)
                    || node.optional_dependencies.contains_key(name)
                    || node.dev_dependencies.contains_key(name)
                {
                    continue;
                }
                let dep_type = if node
                    .peer_dependencies_meta
                    .get(name)
                    .is_some_and(|meta| meta.optional)
                {
                    DependencyType::PeerOptional
                } else {
                    DependencyType::Peer
                };
                resolve_edge!(name, spec, dep_type);
            }
            let out_end = graph.edges.len();
            if out_end > out_start {
                graph
                    .outgoing_edges_by_location
                    .insert(loc.clone(), (out_start..out_end).collect());
            }
        }

        graph.nodes_by_dep_name.reserve(by_dep.len());
        for (k, v) in by_dep {
            graph.nodes_by_dep_name.insert(k.to_string(), v);
        }
        graph.nodes_by_name.reserve(by_name.len());
        for (k, v) in by_name {
            graph.nodes_by_name.insert(k.to_string(), v);
        }
        graph.nodes_by_install_name.reserve(by_install.len());
        for (k, v) in by_install {
            graph.nodes_by_install_name.insert(k.to_string(), v);
        }
        graph.children_by_parent.reserve(by_parent.len());
        for (k, v) in by_parent {
            graph.children_by_parent.insert(k.to_string(), v);
        }
        graph.edges_by_install_name.reserve(edge_by_install.len());
        for (k, v) in edge_by_install {
            graph.edges_by_install_name.insert(k.to_string(), v);
        }
        graph
            .incoming_edges_by_location
            .reserve(edge_by_incoming.len());
        for (k, v) in edge_by_incoming {
            graph.incoming_edges_by_location.insert(k.to_string(), v);
        }
        graph
    }

    /// Locates a dependency in the scope hierarchy (from closest enclosing node_modules up to root).
    /// Returns the exact location key borrowed from `nodes`.
    pub fn find_in_scope_hierarchy<'a>(
        nodes: &'a BTreeMap<String, Node>,
        from_loc: &str,
        dep_name: &str,
        buf: &mut String,
    ) -> Option<&'a str> {
        for scope in crate::hoisting::iter_ancestor_scopes(from_loc) {
            buf.clear();
            if scope.is_empty() {
                buf.push_str("node_modules/");
            } else {
                buf.push_str(scope);
                buf.push_str("/node_modules/");
            }
            buf.push_str(dep_name);
            if let Some((k, _)) = nodes.get_key_value(buf.as_str()) {
                return Some(k.as_str());
            }
        }
        None
    }
}

/// A `file:.` dependency is a link to the root itself. Its target's edges are
/// the root's, already counted, so it adds none of its own.
fn resolves_to_root(node: &Node) -> bool {
    node.resolved.as_deref().is_some_and(|resolved| {
        resolved
            .strip_prefix("file:")
            .is_some_and(|path| matches!(path.trim_end_matches(['/', '\\']), "" | "."))
    })
}
