use rnpm_core::PlatformList;
use rnpm_lockfile::{LockfilePackage, LockfileV3, PackageBin};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

fn normalize_bin_paths(bin: Option<PackageBin>, package_name: &str) -> Option<PackageBin> {
    bin.map(|bin| match bin {
        PackageBin::Single(path) => {
            let clean = path.strip_prefix("./").unwrap_or(&path).to_string();
            let bin_name = package_name.rsplit('/').next().unwrap_or(package_name);
            let mut map = BTreeMap::new();
            map.insert(bin_name.to_string(), clean);
            PackageBin::Map(map)
        }
        PackageBin::Map(paths) => PackageBin::Map(
            paths
                .into_iter()
                .map(|(name, path)| (name, path.strip_prefix("./").unwrap_or(&path).to_string()))
                .collect(),
        ),
    })
    // npm-normalize-package-bin drops a bin map with no entries.
    .filter(|bin| !matches!(bin, PackageBin::Map(map) if map.is_empty()))
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
        self.extra
            .get("bundleDependencies")
            .or_else(|| self.extra.get("bundledDependencies"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
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
        if let Some(old) = self.nodes.remove(&location) {
            Self::remove_node_from_indices(
                &mut self.nodes_by_dep_name,
                &mut self.nodes_by_name,
                &mut self.nodes_by_install_name,
                &mut self.children_by_parent,
                &location,
                &old,
            );
        }
        Self::add_node_to_indices(
            &mut self.nodes_by_dep_name,
            &mut self.nodes_by_name,
            &mut self.nodes_by_install_name,
            &mut self.children_by_parent,
            &location,
            &node,
        );
        self.nodes.insert(location, node);
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
        self.children_by_parent
            .get(location)
            .is_some_and(|children| !children.is_empty())
    }

    /// Helper to index a node across all node-related secondary maps.
    fn add_node_to_indices(
        nodes_by_dep_name: &mut HashMap<String, Vec<String>>,
        nodes_by_name: &mut HashMap<String, Vec<String>>,
        nodes_by_install_name: &mut HashMap<String, Vec<String>>,
        children_by_parent: &mut HashMap<String, Vec<String>>,
        location: &str,
        node: &Node,
    ) {
        let mut dep_names = HashSet::new();
        for name in node.dependencies.keys() {
            dep_names.insert(name);
        }
        for name in node.optional_dependencies.keys() {
            dep_names.insert(name);
        }
        for name in node.peer_dependencies.keys() {
            dep_names.insert(name);
        }
        for name in node.dev_dependencies.keys() {
            dep_names.insert(name);
        }
        for name in dep_names {
            let vec = nodes_by_dep_name.entry(name.clone()).or_default();
            if !vec.iter().any(|l| l == location) {
                vec.push(location.to_string());
            }
        }

        let by_name = nodes_by_name.entry(node.name.clone()).or_default();
        if !by_name.iter().any(|l| l == location) {
            by_name.push(location.to_string());
        }

        let by_install = nodes_by_install_name
            .entry(node.install_name.clone())
            .or_default();
        if !by_install.iter().any(|l| l == location) {
            by_install.push(location.to_string());
        }

        if let Some(parent) = crate::hoisting::parent_scope(location) {
            let children = children_by_parent.entry(parent.to_string()).or_default();
            if !children.iter().any(|l| l == location) {
                children.push(location.to_string());
            }
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
        let mut dep_names = HashSet::new();
        for name in node.dependencies.keys() {
            dep_names.insert(name);
        }
        for name in node.optional_dependencies.keys() {
            dep_names.insert(name);
        }
        for name in node.peer_dependencies.keys() {
            dep_names.insert(name);
        }
        for name in node.dev_dependencies.keys() {
            dep_names.insert(name);
        }
        for name in dep_names {
            if let Some(vec) = nodes_by_dep_name.get_mut(name) {
                vec.retain(|l| l != location);
            }
        }

        if let Some(vec) = nodes_by_name.get_mut(&node.name) {
            vec.retain(|l| l != location);
        }

        if let Some(vec) = nodes_by_install_name.get_mut(&node.install_name) {
            vec.retain(|l| l != location);
        }

        if let Some(parent) = crate::hoisting::parent_scope(location) {
            if let Some(children) = children_by_parent.get_mut(parent) {
                children.retain(|l| l != location);
            }
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
        edges_by_install_name
            .entry(edge.install_name.clone())
            .or_default()
            .push(idx);
        incoming_edges_by_location
            .entry(edge.to_location.clone())
            .or_default()
            .push(idx);
        outgoing_edges_by_location
            .entry(edge.from_location.clone())
            .or_default()
            .push(idx);
    }

    /// Rebuilds edge secondary indices from scratch.
    pub fn rebuild_edge_indices(&mut self) {
        self.edges_by_install_name.clear();
        self.incoming_edges_by_location.clear();
        self.outgoing_edges_by_location.clear();
        for (idx, edge) in self.edges.iter().enumerate() {
            Self::add_edge_to_indices(
                &mut self.edges_by_install_name,
                &mut self.incoming_edges_by_location,
                &mut self.outgoing_edges_by_location,
                idx,
                edge,
            );
        }
    }

    /// Rebuilds all secondary graph indices from scratch.
    pub fn rebuild_indices(&mut self) {
        self.nodes_by_dep_name.clear();
        self.nodes_by_name.clear();
        self.nodes_by_install_name.clear();
        self.children_by_parent.clear();
        for (loc, node) in &self.nodes {
            Self::add_node_to_indices(
                &mut self.nodes_by_dep_name,
                &mut self.nodes_by_name,
                &mut self.nodes_by_install_name,
                &mut self.children_by_parent,
                loc,
                node,
            );
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
        if let Some(indices) = self.outgoing_edges_by_location.get(from_location) {
            indices.iter().map(|&i| &self.edges[i]).collect()
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
        let existing: HashSet<(String, String)> = self
            .edges
            .iter()
            .map(|e| (e.from_location.clone(), e.install_name.clone()))
            .collect();
        let mut late = Vec::new();
        for (location, node) in &self.nodes {
            if resolves_to_root(node) {
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
                if !optional || existing.contains(&(location.clone(), name.clone())) {
                    continue;
                }
                if let Some(target) = crate::hoisting::find_visible_node(self, location, name) {
                    let satisfies = rnpm_core::semver::Range::parse(spec).is_ok_and(|range| {
                        rnpm_core::semver::Version::parse(&target.version)
                            .is_ok_and(|v| range.satisfies(&v))
                    });
                    if satisfies && target.location != *location {
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
        self.edges.extend(late);
    }

    pub fn normalize_dependency_flags(&mut self) {
        self.link_late_optional_peers();
        const NON_DEV: u8 = 0b01;
        const DEV_ONLY: u8 = 0b10;
        const NON_OPTIONAL: u8 = 0b01;
        const OPTIONAL_ONLY: u8 = 0b10;

        let mut dev_states: HashMap<String, u8> = HashMap::new();
        let mut optional_states: HashMap<String, u8> = HashMap::new();
        let mut peer_states: HashMap<String, u8> = HashMap::new();
        let mut skipped_states: HashMap<String, u8> = HashMap::new();
        let initially_skipped: HashSet<String> = self
            .nodes
            .iter()
            .filter_map(|(location, node)| {
                node.flags
                    .platform_skipped
                    .unwrap_or(node.flags.skipped)
                    .then_some(location.clone())
            })
            .collect();
        dev_states.insert(self.root_location.clone(), NON_DEV);
        optional_states.insert(self.root_location.clone(), NON_OPTIONAL);
        peer_states.insert(self.root_location.clone(), NON_DEV);
        skipped_states.insert(self.root_location.clone(), NON_DEV);

        let mut queue = VecDeque::from([self.root_location.clone()]);
        let mut outgoing: HashMap<String, Vec<DependencyEdge>> = HashMap::new();
        for edge in &self.edges {
            if self.nodes.get(&edge.from_location).is_some_and(|node| {
                edge.from_location != self.root_location && resolves_to_root(node)
            }) {
                continue;
            }
            outgoing
                .entry(edge.from_location.clone())
                .or_default()
                .push(edge.clone());
        }
        // A link and its target are one node to calc-dep-flags: whatever
        // reaches the link reaches the target (e.g. a workspace member) and its
        // dependencies. A prod pass-through edge carries every state unchanged.
        for (location, node) in &self.nodes {
            if !node.flags.link {
                continue;
            }
            if let Some(target) = node
                .resolved
                .as_ref()
                .filter(|t| self.nodes.contains_key(*t))
            {
                if target != location {
                    outgoing
                        .entry(location.clone())
                        .or_default()
                        .push(DependencyEdge {
                            from_location: location.clone(),
                            to_location: target.clone(),
                            install_name: node.install_name.clone(),
                            package_name: node.name.clone(),
                            spec: String::new(),
                            dep_type: DependencyType::Prod,
                        });
                }
            }
        }
        while let Some(location) = queue.pop_front() {
            let dev_state = dev_states.get(&location).copied().unwrap_or(0);
            let optional_state = optional_states.get(&location).copied().unwrap_or(0);
            let peer_state = peer_states.get(&location).copied().unwrap_or(0);
            let skipped_state = skipped_states.get(&location).copied().unwrap_or(0);
            let Some(edges) = outgoing.get(&location) else {
                continue;
            };

            for edge in edges {
                let mut next_dev = 0;
                if dev_state & DEV_ONLY != 0 {
                    next_dev |= DEV_ONLY;
                }
                if dev_state & NON_DEV != 0 {
                    next_dev |= if edge.dep_type == DependencyType::Dev {
                        DEV_ONLY
                    } else {
                        NON_DEV
                    };
                }

                let mut next_optional = 0;
                if optional_state & OPTIONAL_ONLY != 0 {
                    next_optional |= OPTIONAL_ONLY;
                }
                if optional_state & NON_OPTIONAL != 0 {
                    next_optional |= if matches!(
                        edge.dep_type,
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
                        edge.dep_type,
                        DependencyType::Peer | DependencyType::PeerOptional
                    ) {
                        DEV_ONLY
                    } else {
                        NON_DEV
                    };
                }

                let next_skipped = if skipped_state & DEV_ONLY != 0
                    || (initially_skipped.contains(&edge.to_location)
                        && edge.dep_type == DependencyType::Optional)
                {
                    DEV_ONLY
                } else {
                    NON_DEV
                };

                let dev_entry = dev_states.entry(edge.to_location.clone()).or_default();
                let optional_entry = optional_states.entry(edge.to_location.clone()).or_default();
                let peer_entry = peer_states.entry(edge.to_location.clone()).or_default();
                let skipped_entry = skipped_states.entry(edge.to_location.clone()).or_default();
                let changed = (*dev_entry | next_dev) != *dev_entry
                    || (*optional_entry | next_optional) != *optional_entry
                    || (*peer_entry | next_peer) != *peer_entry
                    || (*skipped_entry | next_skipped) != *skipped_entry;
                *dev_entry |= next_dev;
                *optional_entry |= next_optional;
                *peer_entry |= next_peer;
                *skipped_entry |= next_skipped;
                if changed {
                    queue.push_back(edge.to_location.clone());
                }
            }
        }

        // Identify nodes reachable via a pure production path from root
        // (paths containing no dev, optional, or peer-optional edges).
        let mut pure_prod_reachable: HashSet<String> = HashSet::new();
        let mut prod_queue = VecDeque::from([self.root_location.clone()]);
        pure_prod_reachable.insert(self.root_location.clone());
        while let Some(loc) = prod_queue.pop_front() {
            if let Some(edges) = outgoing.get(&loc) {
                for edge in edges {
                    if edge.dep_type != DependencyType::Dev
                        && edge.dep_type != DependencyType::Optional
                        && edge.dep_type != DependencyType::PeerOptional
                        && pure_prod_reachable.insert(edge.to_location.clone())
                    {
                        prod_queue.push_back(edge.to_location.clone());
                    }
                }
            }
        }

        // Arborist calc-dep-flags keeps nodes reached only through optional
        // peers extraneous. Their ordinary dependencies inherit that state.
        let mut non_extraneous = HashSet::from([self.root_location.clone()]);
        let mut required_queue = VecDeque::from([self.root_location.clone()]);
        while let Some(location) = required_queue.pop_front() {
            if let Some(edges) = outgoing.get(&location) {
                for edge in edges {
                    if edge.dep_type != DependencyType::PeerOptional
                        && non_extraneous.insert(edge.to_location.clone())
                    {
                        required_queue.push_back(edge.to_location.clone());
                    }
                }
            }
        }
        // Required nested children also keep their physical parents alive.
        for location in non_extraneous.clone() {
            let mut scope = location.as_str();
            while let Some((parent, _)) = scope.rsplit_once("/node_modules/") {
                non_extraneous.insert(parent.to_string());
                scope = parent;
            }
        }

        for (location, node) in &mut self.nodes {
            if location == &self.root_location {
                continue;
            }
            let dev_state = dev_states.get(location).copied().unwrap_or(0);
            let optional_state = optional_states.get(location).copied().unwrap_or(0);
            let skipped_state = skipped_states.get(location).copied().unwrap_or(0);
            if dev_state != 0 && !non_extraneous.contains(location) {
                node.extra
                    .insert("extraneous".to_string(), serde_json::Value::Bool(true));
            } else {
                node.extra.remove("extraneous");
            }

            let is_dev = dev_state == DEV_ONLY;
            let is_optional = optional_state == OPTIONAL_ONLY;
            let reachable_from_dev = (dev_state & DEV_ONLY) != 0;
            let reachable_from_optional = (optional_state & OPTIONAL_ONLY) != 0;
            let is_pure_prod = pure_prod_reachable.contains(location);

            node.flags.dev = is_dev;
            node.flags.optional = is_optional;
            node.flags.peer = peer_states.get(location).copied().unwrap_or(0) == DEV_ONLY;
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
                                    (k.clone(), serde_json::to_value(v).unwrap_or_default())
                                })
                                .collect(),
                        );
                    }
                    if !node.optional_dependencies.is_empty() {
                        root_pkg.optional_dependencies = Some(node.optional_dependencies.clone());
                    }
                    if let Some(bin) = &node.bin {
                        root_pkg.bin = normalize_bin_paths(Some(bin.clone()), &node.name);
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
                let extraneous =
                    node.extra.get("extraneous") == Some(&serde_json::Value::Bool(true));
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
                                    (k.clone(), serde_json::to_value(v).unwrap_or_default())
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
                    bin: normalize_bin_paths(node.bin.clone(), &node.name),
                    license,
                    engines: if let Some(raw) = node.extra.get("engines") {
                        serde_json::from_value(raw.clone()).ok()
                    } else if node.engines.is_empty() {
                        None
                    } else {
                        Some(rnpm_lockfile::PackageEngines::Map(node.engines.clone()))
                    },
                    bundle_dependencies: node.bundle_dependencies(),
                    extra,
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
            let peer_dependencies_meta = pkg
                .peer_dependencies_meta
                .as_ref()
                .map(|meta_map| {
                    meta_map
                        .iter()
                        .map(|(k, v)| {
                            let meta: rnpm_core::manifest::PeerDependencyMeta =
                                serde_json::from_value(v.clone()).unwrap_or_default();
                            (k.clone(), meta)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let node = Node {
                location: loc.clone(),
                install_name: install_name.clone(),
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

        // Helper buffer to locate package in scope hierarchy without allocations
        let mut candidate_buf = String::with_capacity(128);

        // Build edges based on dependencies
        for (loc, node) in &graph.nodes {
            let all_deps = node
                .dependencies
                .iter()
                .map(|(n, s)| (n, s, DependencyType::Prod))
                .chain(
                    node.dev_dependencies
                        .iter()
                        .map(|(n, s)| (n, s, DependencyType::Dev)),
                )
                .chain(
                    node.optional_dependencies
                        .iter()
                        .map(|(n, s)| (n, s, DependencyType::Optional)),
                )
                .chain(
                    node.peer_dependencies
                        .iter()
                        .filter(|(name, _)| {
                            !node.dependencies.contains_key(*name)
                                && !node.optional_dependencies.contains_key(*name)
                                && !node.dev_dependencies.contains_key(*name)
                        })
                        .map(|(name, spec)| {
                            (
                                name,
                                spec,
                                if node
                                    .peer_dependencies_meta
                                    .get(name)
                                    .is_some_and(|meta| meta.optional)
                                {
                                    DependencyType::PeerOptional
                                } else {
                                    DependencyType::Peer
                                },
                            )
                        }),
                );

            for (dep_name, dep_spec, dep_type) in all_deps {
                let target_loc =
                    Self::find_in_scope_hierarchy(&graph.nodes, loc, dep_name, &mut candidate_buf);

                if let Some(target) = target_loc {
                    let target_pkg_name = graph
                        .nodes
                        .get(target)
                        .map(|n| n.name.clone())
                        .unwrap_or_else(|| dep_name.clone());
                    graph.edges.push(DependencyEdge {
                        from_location: loc.clone(),
                        to_location: target.to_string(),
                        install_name: dep_name.clone(),
                        package_name: target_pkg_name,
                        spec: dep_spec.clone(),
                        dep_type,
                    });
                }
            }
        }

        graph.rebuild_indices();
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
