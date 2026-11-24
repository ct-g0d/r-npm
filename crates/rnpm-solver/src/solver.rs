use rnpm_core::manifest::Manifest;
use rnpm_core::semver::Version;
use rnpm_core::spec::PackageTarget;
use std::collections::{BTreeMap, VecDeque};
use tracing::{debug, warn};

use crate::aliases::DependencySpec;
use crate::error::SolverError;
use crate::graph::{DependencyEdge, DependencyGraph, DependencyType, Node, NodeFlags};
use crate::hoisting::{
    cached_parse_package_target, cached_parse_version, determine_placement_with_peers,
    PlacementDecision,
};
use crate::overrides::Overrides;
use crate::peer::PeerContext;
use crate::platform::Platform;
use crate::types::{PackageMetadata, PackageMetadataProvider, PackageVersionMetadata};

/// Configuration options for dependency resolution.
#[derive(Debug, Clone)]
pub struct ResolverOptions {
    /// Target platform for evaluating `os` and `cpu` filters on optional dependencies.
    pub platform: Platform,
    /// Whether to include `devDependencies` from the root project.
    pub dev: bool,
    /// When true, peer dependencies are completely ignored during tree construction.
    pub legacy_peer_deps: bool,
    /// When true, unresolved or conflicting peer dependencies cause an ERESOLVE error.
    pub strict_peers: bool,
    /// When true, fail immediately with npm-compatible ERESOLVE error on any peer dependency conflict/mismatch.
    pub strict_peer_deps: bool,
    /// Revisit newly invalid optional peers during lockfile-mutating operations.
    pub repair_optional_peers: bool,
    /// Optional lockfile v3 to enable fast-path resolution when matching package.json specs.
    pub lockfile: Option<std::sync::Arc<rnpm_lockfile::LockfileV3>>,
    /// Unlocked packages that must be re-resolved to newer versions rather than locked to lockfile.
    pub unlocked_packages: std::collections::HashSet<String>,
    /// Vulnerability constraints to avoid when selecting versions during audit fix.
    pub vulnerability_constraints: std::collections::HashMap<String, Vec<rnpm_core::semver::Range>>,
    /// `--force`: npm-install-checks' checkPlatform returns early, so a
    /// required package for another platform is installed anyway.
    pub force: bool,
    /// npm's `install-strategy` for PlaceDep's target walk.
    pub install_strategy: crate::hoisting::PlacementStrategy,
    /// When true, prefer an already-placed/deduplicatable compatible version in the tree over a newer version when resolving a range.
    pub prefer_dedupe: bool,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            platform: Platform::current(),
            dev: true,
            legacy_peer_deps: false,
            strict_peers: true,
            strict_peer_deps: false,
            repair_optional_peers: true,
            lockfile: None,
            unlocked_packages: std::collections::HashSet::new(),
            vulnerability_constraints: std::collections::HashMap::new(),
            force: false,
            install_strategy: crate::hoisting::PlacementStrategy::Hoisted,
            prefer_dedupe: false,
        }
    }
}

impl ResolverOptions {
    /// Returns true if peer conflicts or mismatches should fail with an ERESOLVE error.
    #[inline]
    pub fn is_strict_peers(&self) -> bool {
        !self.legacy_peer_deps && (self.strict_peers || self.strict_peer_deps)
    }
}

/// Internal task queued for resolution.
#[derive(Debug, Clone)]
struct ResolveTask {
    parent_location: String,
    parent_package_name: String,
    install_name: String,
    raw_spec: String,
    dep_type: DependencyType,
    parent_depth: usize,
    ancestors: std::sync::Arc<Vec<String>>,
    /// A second edge whose range should guide version choice, as
    /// arborist's nodeFromEdge(parentEdge, parent, secondEdge) does.
    advisory: Option<String>,
    is_mine: bool,
    is_root: bool,
}

/// Tiered queue that eliminates O(Q) cross-depth element shifting and maintains
/// strict Arborist collation order within each depth level.
#[derive(Debug, Clone, Default)]
struct TaskQueue {
    levels: Vec<VecDeque<ResolveTask>>,
    len: usize,
    pending_root: std::collections::HashMap<String, usize>,
}

impl TaskQueue {
    fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push_task(&mut self, task: ResolveTask) {
        if task.parent_location.is_empty() {
            *self.pending_root.entry(task.install_name.clone()).or_default() += 1;
        }
        let depth = task.parent_depth;
        if depth >= self.levels.len() {
            self.levels.resize_with(depth + 1, VecDeque::new);
        }
        let level = &mut self.levels[depth];
        let pos = level
            .binary_search_by(|queued| {
                arborist_compare(&queued.parent_location, &task.parent_location)
                    .then_with(|| arborist_compare(&queued.install_name, &task.install_name))
            })
            .unwrap_or_else(|e| e);
        level.insert(pos, task);
        self.len += 1;
    }

    fn push_back(&mut self, task: ResolveTask) {
        if task.parent_location.is_empty() {
            *self.pending_root.entry(task.install_name.clone()).or_default() += 1;
        }
        let depth = task.parent_depth;
        if depth >= self.levels.len() {
            self.levels.resize_with(depth + 1, VecDeque::new);
        }
        self.levels[depth].push_back(task);
        self.len += 1;
    }

    #[inline]
    fn has_pending_root(&self, name: &str) -> bool {
        self.pending_root.get(name).copied().unwrap_or(0) > 0
    }

    fn pop_front(&mut self) -> Option<ResolveTask> {
        for level in &mut self.levels {
            if let Some(task) = level.pop_front() {
                self.len -= 1;
                if task.parent_location.is_empty() {
                    if let Some(count) = self.pending_root.get_mut(&task.install_name) {
                        if *count > 1 {
                            *count -= 1;
                        } else {
                            self.pending_root.remove(&task.install_name);
                        }
                    }
                }
                return Some(task);
            }
        }
        None
    }

    fn front(&self) -> Option<&ResolveTask> {
        for level in &self.levels {
            if let Some(task) = level.front() {
                return Some(task);
            }
        }
        None
    }

    fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&ResolveTask) -> bool,
    {
        for level in &mut self.levels {
            level.retain(|task| {
                let keep = f(task);
                if !keep {
                    self.len = self.len.saturating_sub(1);
                    if task.parent_location.is_empty() {
                        if let Some(count) = self.pending_root.get_mut(&task.install_name) {
                            if *count > 1 {
                                *count -= 1;
                            } else {
                                self.pending_root.remove(&task.install_name);
                            }
                        }
                    }
                }
                keep
            });
        }
    }

    fn drain_all(&mut self) -> Vec<ResolveTask> {
        let mut all = Vec::with_capacity(self.len);
        for level in &mut self.levels {
            all.extend(level.drain(..));
        }
        self.len = 0;
        self.pending_root.clear();
        all
    }
}

/// Main solver coordinator for building the dependency graph.
pub struct Solver<'a, P: PackageMetadataProvider> {
    provider: &'a P,
    options: ResolverOptions,
    overrides: Overrides,
    peer_ctx: PeerContext,
    graph: DependencyGraph,
    queue: TaskQueue,
    /// Link targets normally wait for resolveLinks, but an invalidated edge
    /// can put a workspace into the node queue before that pass.
    deferred_workspaces: BTreeMap<String, Vec<ResolveTask>>,
    /// Missing optional peers become problem edges when a provider arrives.
    deferred_optional_peers: BTreeMap<String, Vec<ResolveTask>>,
    /// Root edges already resolved early for a peer set.
    preplaced: std::collections::HashSet<String>,
}

/// Compares two strings using Arborist-compatible collation.
/// Arborist sorts depsQueue by depth then `a.path.localeCompare(b.path, 'en') || a.name.localeCompare(b.name, 'en')`.
pub fn arborist_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let min_len = a_bytes.len().min(b_bytes.len());
    for i in 0..min_len {
        let ca = a_bytes[i].to_ascii_lowercase();
        let cb = b_bytes[i].to_ascii_lowercase();
        if ca != cb {
            return ca.cmp(&cb);
        }
    }
    match a_bytes.len().cmp(&b_bytes.len()) {
        std::cmp::Ordering::Equal => {
            // Case tie-breaker: in JavaScript 'en' localeCompare, lowercase comes before uppercase ('a' < 'A')
            for i in 0..min_len {
                let ca = a_bytes[i];
                let cb = b_bytes[i];
                if ca != cb {
                    let is_ca_lower = ca.is_ascii_lowercase();
                    let is_cb_lower = cb.is_ascii_lowercase();
                    if is_ca_lower != is_cb_lower {
                        return if is_ca_lower {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Greater
                        };
                    }
                    return ca.cmp(&cb);
                }
            }
            std::cmp::Ordering::Equal
        }
        ord => ord,
    }
}

impl<'a, P: PackageMetadataProvider> Solver<'a, P> {
    pub fn new(provider: &'a P, options: ResolverOptions, overrides: Overrides) -> Self {
        let graph = DependencyGraph {
            legacy_peer_deps: options.legacy_peer_deps,
            ..DependencyGraph::new()
        };
        Self {
            provider,
            options,
            overrides,
            peer_ctx: PeerContext::new(),
            graph,
            queue: TaskQueue::new(),
            deferred_workspaces: BTreeMap::new(),
            deferred_optional_peers: BTreeMap::new(),
            preplaced: std::collections::HashSet::new(),
        }
    }

    /// Attaches an existing LockfileV3 for fast-path resolution.
    pub fn with_lockfile(mut self, lockfile: std::sync::Arc<rnpm_lockfile::LockfileV3>) -> Self {
        self.options.lockfile = Some(lockfile);
        self
    }

    /// Attaches an existing base graph to the solver (e.g. pre-populated workspace graph).
    pub fn with_graph(mut self, mut graph: DependencyGraph) -> Self {
        graph.legacy_peer_deps = self.options.legacy_peer_deps;
        graph.rebuild_indices();
        self.graph = graph;
        self
    }

    pub fn graph(&self) -> &DependencyGraph {
        &self.graph
    }

    pub fn graph_mut(&mut self) -> &mut DependencyGraph {
        &mut self.graph
    }

    /// Enqueue an external dependency resolution task.
    pub fn enqueue_task(
        &mut self,
        parent_location: String,
        parent_package_name: String,
        install_name: String,
        raw_spec: String,
        dep_type: DependencyType,
        ancestors: std::sync::Arc<Vec<String>>,
    ) {
        if self.options.legacy_peer_deps
            && (dep_type == DependencyType::Peer || dep_type == DependencyType::PeerOptional)
        {
            return;
        }
        if dep_type == DependencyType::Peer || dep_type == DependencyType::PeerOptional {
            self.peer_ctx.enter(&parent_package_name, &install_name);
        }
        let parent_depth = if parent_location.is_empty() {
            0
        } else {
            parent_location.matches("node_modules").count()
        };
        let is_mine = !parent_location.contains("node_modules");
        let is_root = !parent_location.contains("node_modules");
        self.push_task(ResolveTask {
            parent_location,
            parent_package_name,
            install_name,
            raw_spec,
            dep_type,
            parent_depth,
            ancestors,
            advisory: None,
            is_mine,
            is_root,
        });
    }

    fn activate_deferred_optional_peers(&mut self, provider_location: &str) {
        let Some(provider_node) = self.graph.nodes.get(provider_location) else {
            return;
        };
        let name = provider_node.install_name.clone();
        let Some(tasks) = self.deferred_optional_peers.remove(&name) else {
            return;
        };
        for task in tasks {
            let visible = crate::hoisting::find_visible_peer_node(
                &self.graph,
                &task.parent_location,
                &name,
                &name,
            );
            if visible.is_some_and(|node| node.location == provider_location) {
                self.push_task(task);
            } else {
                self.deferred_optional_peers
                    .entry(name.clone())
                    .or_default()
                    .push(task);
            }
        }
    }

    fn push_task(&mut self, task: ResolveTask) {
        self.queue.push_task(task);
    }

    /// Hold workspace targets for Arborist's resolveLinks pass. A newly
    /// placed provider may activate one earlier by invalidating its edge.
    pub fn defer_workspace_tasks(&mut self) {
        let mut root_tasks = Vec::new();
        for task in self.queue.drain_all() {
            if !task.parent_location.is_empty() && !task.parent_location.contains("node_modules") {
                self.deferred_workspaces
                    .entry(task.parent_location.clone())
                    .or_default()
                    .push(task);
            } else {
                root_tasks.push(task);
            }
        }
        for task in root_tasks {
            self.queue.push_task(task);
        }
    }

    fn activate_invalidated_workspaces(&mut self, provider_location: &str) {
        let Some(provider) = self.graph.nodes.get(provider_location) else {
            return;
        };
        let mut scope_buffer = String::new();
        let locations: Vec<_> = self
            .deferred_workspaces
            .iter()
            .filter(|(location, tasks)| {
                tasks
                    .iter()
                    .filter(|task| task.install_name == provider.install_name)
                    .any(|task| {
                        let visible = DependencyGraph::find_in_scope_hierarchy(
                            &self.graph.nodes,
                            location,
                            &task.install_name,
                            &mut scope_buffer,
                        );
                        let overridden = if self.overrides.rules.is_empty() {
                            None
                        } else {
                            let caller = self
                                .graph
                                .nodes
                                .get(*location)
                                .map(|n| n.all_dependency_specs())
                                .unwrap_or_default();
                            self.overrides
                                .resolve_override_with_caller(
                                    &task.install_name,
                                    &task.raw_spec,
                                    &task.ancestors,
                                    Some(&caller),
                                )
                                .ok()
                                .flatten()
                        };
                        visible == Some(provider_location)
                            && DependencySpec::parse(
                                &task.install_name,
                                overridden.as_deref().unwrap_or(&task.raw_spec),
                            )
                            .is_ok_and(|spec| {
                                provider.name != spec.package_name
                                    || !crate::hoisting::node_satisfies_target(
                                        provider,
                                        &spec.target,
                                    )
                            })
                    })
            })
            .map(|(location, _)| location.clone())
            .collect();
        for location in locations {
            if let Some(tasks) = self.deferred_workspaces.remove(&location) {
                for task in tasks {
                    self.push_task(task);
                }
            }
        }
    }

    /// Arborist's conflictOK: without --force, a peer conflict is fatal only
    /// for a package placed directly under the root or a workspace, or with
    /// --strict-peer-deps; deeper conflicts are overridden with a warning.
    fn peer_conflict_is_fatal(&self, is_mine: bool) -> bool {
        if self.options.legacy_peer_deps || self.options.force {
            return false;
        }
        if self.options.strict_peer_deps {
            return true;
        }
        self.options.is_strict_peers() && is_mine
    }

    /// Processes all queued dependency resolution tasks until completion.
    pub fn resolve_tasks(&mut self) -> Result<(), SolverError> {
        loop {
            if self.queue.is_empty() {
                if self.deferred_workspaces.is_empty() {
                    break;
                }
                for tasks in std::mem::take(&mut self.deferred_workspaces).into_values() {
                    for task in tasks {
                        self.push_task(task);
                    }
                }
            }
            let task = self.queue.pop_front().unwrap();
            // Arborist queues nodes, then places all of a node's problem
            // edges before visiting another node. A newly hoisted child can
            // sort ahead of its parent, so freeze this batch before placing
            // any edges that might enqueue that child's dependencies.
            let mut siblings = vec![task];
            while self
                .queue
                .front()
                .is_some_and(|queued| queued.parent_location == siblings[0].parent_location)
            {
                siblings.push(self.queue.pop_front().unwrap());
            }
            for task in siblings {
                self.process_task(task)?;
            }
        }
        Ok(())
    }

    /// Extracts the resolved dependency graph.
    pub fn into_graph(mut self) -> DependencyGraph {
        self.graph.normalize_dependency_flags();
        self.graph.rebuild_indices();
        self.graph
    }

    /// Resolves the dependency graph starting from a root manifest.
    pub fn resolve(mut self, root_manifest: &Manifest) -> Result<DependencyGraph, SolverError> {
        // Fast-path: if lockfile v3 matches root_manifest specs, bypass expensive traversal
        if self.options.unlocked_packages.is_empty()
            && self.options.vulnerability_constraints.is_empty()
        {
            if let Some(ref lockfile) = self.options.lockfile {
                if lockfile.matches_manifest(root_manifest, self.options.dev) {
                    debug!(
                        "Fast-path: lockfile v3 matches manifest specs; bypassing tree traversal"
                    );
                    if let Some(graph) = resolve_fast_path(root_manifest, lockfile, &self.options) {
                        return Ok(graph);
                    }
                }
            }
        }

        let root_name = root_manifest
            .name
            .clone()
            .unwrap_or_else(|| "root".to_string());
        let root_version = root_manifest
            .version
            .clone()
            .unwrap_or_else(|| "1.0.0".to_string());

        // Initialize root node at ""
        let root_node = Node {
            location: String::new(),
            install_name: root_name.clone(),
            name: root_name.clone(),
            version: root_version,
            resolved: None,
            integrity: None,
            flags: NodeFlags {
                has_install_script: root_manifest.scripts.contains_key("preinstall")
                    || root_manifest.scripts.contains_key("install")
                    || root_manifest.scripts.contains_key("postinstall"),
                ..Default::default()
            },
            dependencies: root_manifest.dependencies.clone(),
            dev_dependencies: root_manifest.dev_dependencies.clone(),
            peer_dependencies: root_manifest.peer_dependencies.clone(),
            peer_dependencies_meta: root_manifest.peer_dependencies_meta.clone(),
            optional_dependencies: root_manifest.optional_dependencies.clone(),
            os: root_manifest.os.clone(),
            cpu: root_manifest.cpu.clone(),
            libc: root_manifest.libc.clone(),
            bin: root_manifest.bin.clone().map(|b| match b {
                rnpm_core::manifest::PackageBin::Single(s) => rnpm_lockfile::PackageBin::Single(s),
                rnpm_core::manifest::PackageBin::Map(m) => rnpm_lockfile::PackageBin::Map(m),
            }),
            license: root_manifest
                .extra
                .get("license")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            engines: root_manifest.engines.clone(),
            parsed_version: None,
            extra: {
                let mut extra = root_manifest.extra.clone();
                if let Some(ref bd) = root_manifest.bundled_dependencies {
                    if let Ok(val) = serde_json::to_value(bd) {
                        extra.insert("bundleDependencies".to_string(), val);
                    }
                }
                extra
            },
        };
        self.graph.add_node(String::new(), root_node);

        // Collect effective root dependency types, then place their edges
        // in name order. Arborist's node queue uses depth and path rather
        // than giving production subtrees precedence over dev subtrees.
        let mut root_deps: BTreeMap<String, (String, DependencyType)> = BTreeMap::new();

        // 1. devDependencies (if enabled)
        if self.options.dev {
            for (k, v) in &root_manifest.dev_dependencies {
                root_deps.insert(k.clone(), (v.clone(), DependencyType::Dev));
            }
        }

        // 2. dependencies (override devDependencies)
        for (k, v) in &root_manifest.dependencies {
            root_deps.insert(k.clone(), (v.clone(), DependencyType::Prod));
        }

        // 3. optionalDependencies (override dependencies for failure isolation)
        for (k, v) in &root_manifest.optional_dependencies {
            root_deps.insert(k.clone(), (v.clone(), DependencyType::Optional));
        }

        // 4. peerDependencies from root (auto-install if not legacy_peer_deps and not already present)
        if !self.options.legacy_peer_deps {
            for (k, v) in &root_manifest.peer_dependencies {
                let is_opt_peer = root_manifest
                    .peer_dependencies_meta
                    .get(k)
                    .map(|m| m.optional)
                    .unwrap_or(false);
                let p_type = if is_opt_peer {
                    DependencyType::PeerOptional
                } else {
                    DependencyType::Peer
                };
                root_deps
                    .entry(k.clone())
                    .or_insert_with(|| (v.clone(), p_type));
            }
        }

        let mut root_targets = Vec::new();
        for (name, (spec, _)) in &root_deps {
            let Ok(dep_spec) = DependencySpec::parse(name, spec) else {
                continue;
            };
            if matches!(
                dep_spec.target,
                PackageTarget::Range(_) | PackageTarget::Version(_) | PackageTarget::Tag(_)
            ) {
                root_targets.push(dep_spec);
            }
        }
        let root_edges: Vec<(&str, bool)> = root_targets
            .iter()
            .map(|t| (t.package_name.as_str(), true))
            .collect();
        self.provider.prefetch_packages_for_edge(&root_edges);
        if self.options.lockfile.is_none() {
            self.prefetch_closure(&root_deps);
        }

        // A root-held peer conflict is only a candidate: placement can still
        // steer around it (an earlier peer set may pick another version), so
        // it replaces placement's own peer conflict but never fails a tree
        // placement resolves.
        let root_conflict = if self.options.lockfile.is_none()
            && self.options.is_strict_peers()
            && !self.options.force
        {
            self.precheck_root_peer_sets(root_manifest, &root_deps)
        } else {
            None
        };

        let root_ancestors = std::sync::Arc::new(vec![root_name.clone()]);
        let mut queued = std::collections::HashSet::new();
        let enqueue_root =
            |install_name: &str,
             this: &mut Solver<'a, P>,
             queued: &mut std::collections::HashSet<String>| {
                if !queued.insert(install_name.to_string()) {
                    return;
                }
                if let Some((raw_spec, dep_type)) = root_deps.get(install_name).cloned() {
                    this.push_task(ResolveTask {
                        parent_location: String::new(),
                        parent_package_name: root_name.clone(),
                        install_name: install_name.to_string(),
                        raw_spec,
                        dep_type,
                        parent_depth: 0,
                        ancestors: root_ancestors.clone(),
                        advisory: None,
                        is_mine: true,
                        is_root: true,
                    });
                }
            };

        // npm's Arborist normalizes dependency keys lexicographically before
        // walking the root tree. Using the manifest's insertion order here
        // lets an arbitrary package.json edit change which version claims a
        // shared hoisted slot.
        for install_name in root_manifest.dependencies.keys() {
            enqueue_root(install_name, &mut self, &mut queued);
        }
        for install_name in root_manifest.optional_dependencies.keys() {
            enqueue_root(install_name, &mut self, &mut queued);
        }
        if !self.options.legacy_peer_deps {
            for install_name in root_manifest.peer_dependencies.keys() {
                enqueue_root(install_name, &mut self, &mut queued);
            }
        }
        for install_name in root_manifest.dev_dependencies.keys() {
            enqueue_root(install_name, &mut self, &mut queued);
        }
        for install_name in root_deps.keys() {
            enqueue_root(install_name, &mut self, &mut queued);
        }

        // Process resolution queue
        if let Err(error) = self.resolve_tasks() {
            return Err(match root_conflict {
                Some((conflict, version))
                    if error.is_peer_conflict()
                        && self.root_conflict_holds(&conflict, &version) =>
                {
                    conflict
                }
                _ => error,
            });
        }

        self.graph.normalize_dependency_flags();
        self.graph.rebuild_indices();
        Ok(self.graph)
    }

    fn process_task(&mut self, task: ResolveTask) -> Result<(), SolverError> {
        let preplaced_key = if task.parent_location.is_empty() {
            task.install_name.clone()
        } else {
            format!("{}#{}", task.parent_location, task.install_name)
        };
        if task.advisory.is_none() && self.preplaced.contains(&preplaced_key) {
            return Ok(());
        }
        if self.options.legacy_peer_deps
            && (task.dep_type == DependencyType::Peer
                || task.dep_type == DependencyType::PeerOptional)
        {
            return Ok(());
        }

        // 1. Apply overrides without allocations if no rules exist
        let caller_specs = if task.parent_location.is_empty() {
            None
        } else {
            self.graph
                .nodes
                .get(&task.parent_location)
                .map(|node| node.all_dependency_specs())
        };
        let effective_spec = if self.overrides.rules.is_empty() {
            task.raw_spec.clone()
        } else if let Some(overridden) = self.overrides.resolve_override_with_caller(
            &task.install_name,
            &task.raw_spec,
            &task.ancestors,
            caller_specs.as_ref(),
        )? {
            debug!(
                "Overriding dependency '{}': '{}' -> '{}'",
                task.install_name, task.raw_spec, overridden
            );
            overridden
        } else if let Some(alias_str) = task.raw_spec.strip_prefix("npm:") {
            let (real_pkg, inner_spec) = if alias_str.starts_with('@') {
                if let Some(slash) = alias_str.find('/') {
                    let after = &alias_str[slash + 1..];
                    if let Some(at) = after.find('@') {
                        (&alias_str[..slash + 1 + at], &after[at + 1..])
                    } else {
                        (alias_str, "*")
                    }
                } else {
                    (alias_str, "*")
                }
            } else if let Some(at) = alias_str.find('@') {
                (&alias_str[..at], &alias_str[at + 1..])
            } else {
                (alias_str, "*")
            };

            if let Some(overridden) = self.overrides.resolve_override_with_caller(
                real_pkg,
                inner_spec,
                &task.ancestors,
                caller_specs.as_ref(),
            )? {
                debug!(
                    "Overriding aliased package '{}' (install: '{}'): '{}' -> '{}'",
                    real_pkg, task.install_name, inner_spec, overridden
                );
                if overridden.starts_with("npm:") {
                    overridden
                } else {
                    format!("npm:{}@{}", real_pkg, overridden)
                }
            } else {
                task.raw_spec.clone()
            }
        } else {
            task.raw_spec.clone()
        };

        // 2. Parse dependency spec (separating alias and real package name)
        let dep_spec = DependencySpec::parse(&task.install_name, &effective_spec)?;

        // 3. Check for cyclic peer dependencies and existing peer instances
        let is_peer =
            task.dep_type == DependencyType::Peer || task.dep_type == DependencyType::PeerOptional;
        let mut replace_transitive_root_peer = false;
        if is_peer
            && (self.queue.has_pending_root(&task.install_name)
                || self.queue.has_pending_root(&dep_spec.package_name))
        {
            // A depth-first subtree can encounter a peer before the root's
            // direct dependency that is meant to satisfy it.  Defer that
            // peer until the pending root task has been resolved so strict
            // diagnostics and alias satisfaction see the same visible node
            // npm would use.
            self.queue.push_back(task);
            return Ok(());
        }
        if is_peer {
            let dep_alias = if task.install_name != dep_spec.package_name {
                Some(task.install_name.as_str())
            } else {
                None
            };
            if self.peer_ctx.is_cycle_on_path_with_alias(
                &task.ancestors,
                &dep_spec.package_name,
                dep_alias,
            ) {
                let cycle_path_str = self
                    .peer_ctx
                    .find_cycle_path_on_path(&task.ancestors, &dep_spec.package_name, dep_alias)
                    .map(|p| p.join(" -> "))
                    .unwrap_or_else(|| {
                        format!("{} -> {}", task.parent_package_name, dep_spec.package_name)
                    });
                debug!(
                    "Peer cycle detected: {}, resolving to active instance",
                    cycle_path_str
                );
                // Look for existing node with package_name or install_name visible in ancestor scope
                // Peers resolve by folder name, as npm does: an aliased peer is
                // never provided by the real package under its own name.
                if let Some(existing) = crate::hoisting::find_visible_peer_node(
                    &self.graph,
                    &task.parent_location,
                    &task.install_name,
                    &task.install_name,
                ) {
                    if !crate::hoisting::node_satisfies_target(existing, &dep_spec.target) {
                        if task.dep_type == DependencyType::Peer {
                            if self.peer_conflict_is_fatal(task.is_mine) {
                                return Err(SolverError::peer_conflict(
                                    &task.parent_package_name,
                                    &dep_spec.package_name,
                                    &effective_spec,
                                    Some(existing.version.clone()),
                                    Some(existing.location.clone()),
                                    (*task.ancestors).clone(),
                                    format!(
                                        "Installed {}@{} at '{}' does not satisfy peer constraint '{}'",
                                        existing.name, existing.version, existing.location, effective_spec
                                    ),
                                ).with_eresolve(self.explain_peer_set_conflict(&task, &dep_spec, &effective_spec, &existing.location)));
                            } else {
                                warn!(
                                    "Peer dependency conflict in cycle: {} requires {}@{}, but found {}@{} (non-strict mode)",
                                    task.parent_package_name, dep_spec.package_name, effective_spec, existing.name, existing.version
                                );
                            }
                        } else if task.dep_type == DependencyType::PeerOptional {
                            debug!(
                                "Optional peer dependency '{}' for '{}' in cycle conflicts with installed {}@{} at '{}'; omitting optional peer",
                                dep_spec.package_name, task.parent_package_name, existing.name, existing.version, existing.location
                            );
                            return Ok(());
                        }
                    }

                    self.graph.add_edge(DependencyEdge {
                        from_location: task.parent_location,
                        to_location: existing.location.clone(),
                        install_name: task.install_name,
                        package_name: dep_spec.package_name,
                        spec: effective_spec,
                        dep_type: task.dep_type,
                    });
                    return Ok(());
                }
            }

            // Check if peer is already satisfied in ancestor/root scope
            // Peers resolve by folder name, as npm does: an aliased peer is
            // never provided by the real package under its own name.
            if let Some(existing) = crate::hoisting::find_visible_peer_node(
                &self.graph,
                &task.parent_location,
                &task.install_name,
                &task.install_name,
            ) {
                if crate::hoisting::node_matches_peer_name(
                    existing,
                    &task.install_name,
                    &dep_spec.package_name,
                ) {
                    if crate::hoisting::node_satisfies_target(existing, &dep_spec.target) {
                        debug!(
                            "Peer dependency '{}@{}' satisfied by existing node at '{}'",
                            dep_spec.package_name, effective_spec, existing.location
                        );
                        self.graph.add_edge(DependencyEdge {
                            from_location: task.parent_location,
                            to_location: existing.location.clone(),
                            install_name: task.install_name,
                            package_name: dep_spec.package_name,
                            spec: effective_spec,
                            dep_type: task.dep_type,
                        });
                        return Ok(());
                    } else if task.dep_type == DependencyType::Peer {
                        let scope = crate::hoisting::peer_provider_scope(
                            &self.graph,
                            &task.parent_location,
                            &task.install_name,
                        );
                        let sibling = if scope.is_empty() {
                            format!("node_modules/{}", task.install_name)
                        } else {
                            format!("{scope}/node_modules/{}", task.install_name)
                        };
                        if self.peer_conflict_is_fatal(task.is_mine) {
                            return Err(SolverError::peer_conflict(
                                &task.parent_package_name,
                                &dep_spec.package_name,
                                &effective_spec,
                                Some(existing.version.clone()),
                                Some(existing.location.clone()),
                                (*task.ancestors).clone(),
                                format!(
                                    "Installed {}@{} at '{}' does not satisfy peer constraint '{}'",
                                    existing.name,
                                    existing.version,
                                    existing.location,
                                    effective_spec
                                ),
                            )
                            .with_eresolve(
                                self.explain_peer_set_conflict(
                                    &task,
                                    &dep_spec,
                                    &effective_spec,
                                    &existing.location,
                                ),
                            ));
                        } else if self.graph.nodes.contains_key(&sibling) {
                            warn!(
                                "Peer dependency conflict: {} requires {}@{}, but found {}@{} (non-strict mode)",
                                task.parent_package_name, dep_spec.package_name, effective_spec, existing.name, existing.version
                            );
                            // npm warns "ERESOLVE overriding peer dependency"
                            // and keeps the visible node; the edge stays invalid.
                            self.graph.add_edge(DependencyEdge {
                                from_location: task.parent_location,
                                to_location: existing.location.clone(),
                                install_name: task.install_name,
                                package_name: dep_spec.package_name,
                                spec: effective_spec,
                                dep_type: task.dep_type,
                            });
                            return Ok(());
                        }
                        // Otherwise the owner is nested and its sibling slot is
                        // free: npm places the peer there, beside its owner,
                        // instead of keeping the conflicting visible one.
                    } else if task.dep_type == DependencyType::PeerOptional {
                        // loadPeerSet resolves an incompatible optional peer
                        // when its owner can nest with a new sibling provider.
                        // A missing optional peer still never triggers a fetch.
                        let scope = crate::hoisting::peer_provider_scope(
                            &self.graph,
                            &task.parent_location,
                            &task.install_name,
                        );
                        let sibling = (!scope.is_empty())
                            .then(|| format!("{scope}/node_modules/{}", task.install_name));
                        // A top-level owner's provider slot is the root's own
                        // dependency: npm replaces it only when every edge into
                        // it accepts the pinned version (as placement checked);
                        // otherwise it is ERESOLVE.
                        let root_pins_provider = sibling.is_none()
                            && !crate::hoisting::root_provider_replaceable(
                                &self.graph,
                                existing,
                                &task.install_name,
                                &effective_spec,
                            )
                            && existing.location == format!("node_modules/{}", task.install_name)
                            && self.graph.nodes.get(&self.graph.root_location).is_some_and(
                                |root| {
                                    root.dependencies.contains_key(&task.install_name)
                                        || root.dev_dependencies.contains_key(&task.install_name)
                                        || root
                                            .optional_dependencies
                                            .contains_key(&task.install_name)
                                },
                            );
                        if root_pins_provider && self.peer_conflict_is_fatal(task.is_mine) {
                            return Err(SolverError::peer_conflict(
                                &task.parent_package_name,
                                &dep_spec.package_name,
                                &effective_spec,
                                Some(existing.version.clone()),
                                Some(existing.location.clone()),
                                (*task.ancestors).clone(),
                                format!(
                                    "Installed {}@{} at '{}' does not satisfy optional peer constraint '{}'",
                                    existing.name, existing.version, existing.location, effective_spec
                                ),
                            ).with_eresolve(self.explain_placed_peer_conflict(&task, &dep_spec, &effective_spec, &existing.location)));
                        }
                        replace_transitive_root_peer = sibling.is_none() && !root_pins_provider;
                        if !replace_transitive_root_peer
                            && sibling
                                .as_ref()
                                .is_none_or(|location| self.graph.nodes.contains_key(location))
                        {
                            // Keep the invalid edge so the permitted conflict
                            // still produces npm's overridden-peer warning.
                            self.graph.add_edge(DependencyEdge {
                                from_location: task.parent_location,
                                to_location: existing.location.clone(),
                                install_name: task.install_name,
                                package_name: dep_spec.package_name,
                                spec: effective_spec,
                                dep_type: task.dep_type,
                            });
                            return Ok(());
                        }
                    }
                }
            } else if task.dep_type == DependencyType::PeerOptional {
                // If an optional peer is NOT present in the scope, npm does not automatically download/install it
                debug!(
                    "Optional peer dependency '{}@{}' for '{}' is not present in scope; skipping auto-install",
                    dep_spec.package_name, effective_spec, task.parent_package_name
                );
                if self.options.repair_optional_peers {
                    self.deferred_optional_peers
                        .entry(task.install_name.clone())
                        .or_default()
                        .push(task);
                }
                return Ok(());
            }
        }

        // 4. Resolve package metadata and choose matching version
        let pkg_meta_opt = self.provider.get_package_for_edge(
            &dep_spec.package_name,
            &effective_spec,
            task.is_root,
        )?;
        let Some(pkg_meta) = pkg_meta_opt else {
            if task.dep_type == DependencyType::Optional
                || task.dep_type == DependencyType::PeerOptional
            {
                debug!(
                    "Optional dependency '{}' not found, skipping",
                    dep_spec.package_name
                );
                if task.dep_type == DependencyType::Optional {
                    self.graph.skipped.insert(dep_spec.package_name.clone());
                    self.graph.skipped.insert(task.install_name.clone());
                }
                return Ok(());
            }
            if task.dep_type == DependencyType::Peer {
                if !self.options.is_strict_peers() {
                    warn!(
                        "Unresolved peer dependency '{}@{}' (non-strict mode), skipping",
                        dep_spec.package_name, effective_spec
                    );
                    return Ok(());
                }
                return Err(SolverError::peer_conflict(
                    task.parent_package_name,
                    dep_spec.package_name,
                    effective_spec.clone(),
                    None,
                    None,
                    (*task.ancestors).clone(),
                    format!("Peer package '{}' not found in registry", effective_spec),
                ));
            }
            return Err(SolverError::UnresolvedDependency {
                name: dep_spec.package_name,
                spec: effective_spec,
                message: "Package not found in metadata provider".to_string(),
            });
        };

        // Optional peers do not trigger installation, but still constrain a
        // peer set once another member requires that package. Match the
        // advisory parent edge used by Arborist's loadPeerSet/nodeFromEdge.
        let peer_scope = task
            .parent_location
            .rsplit_once("/node_modules/")
            .map(|(scope, _)| scope)
            .unwrap_or("");
        let mut peer_advisories: Vec<PackageTarget> = if is_peer {
            let mut advisories = Vec::new();
            if !self.graph.nodes_by_dep_name.is_empty() {
                if let Some(locs) = self.graph.nodes_by_dep_name.get(&task.install_name) {
                    for loc in locs {
                        if let Some(node) = self.graph.nodes.get(loc) {
                            let scope = node
                                .location
                                .rsplit_once("/node_modules/")
                                .map(|(s, _)| s)
                                .unwrap_or("");
                            if scope == peer_scope
                                && node
                                    .peer_dependencies_meta
                                    .get(&task.install_name)
                                    .is_some_and(|meta| meta.optional)
                            {
                                if let Some(spec) = node.peer_dependencies.get(&task.install_name) {
                                    if let Some(target) = cached_parse_package_target(spec) {
                                        advisories.push(target);
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                for node in self.graph.nodes.values() {
                    let scope = node
                        .location
                        .rsplit_once("/node_modules/")
                        .map(|(s, _)| s)
                        .unwrap_or("");
                    if scope == peer_scope
                        && node
                            .peer_dependencies_meta
                            .get(&task.install_name)
                            .is_some_and(|meta| meta.optional)
                    {
                        if let Some(spec) = node.peer_dependencies.get(&task.install_name) {
                            if let Some(target) = cached_parse_package_target(spec) {
                                advisories.push(target);
                            }
                        }
                    }
                }
            }
            advisories
        } else {
            Vec::new()
        };
        // loadPeerSet resolves the virtual parent's edge first, using the
        // peer edge as an advisory constraint. The incoming dependency
        // identifies that source even when the plugin itself was hoisted.
        if is_peer {
            let mut sources = VecDeque::from([task.parent_location.clone()]);
            let mut seen = std::collections::HashSet::new();
            while let Some(location) = sources.pop_front() {
                if !seen.insert(location.clone()) {
                    continue;
                }
                if !self.graph.incoming_edges_by_location.is_empty() {
                    if let Some(incoming_indices) = self.graph.incoming_edges_by_location.get(&location) {
                        for &idx in incoming_indices {
                            let incoming = &self.graph.edges[idx];
                            if matches!(
                                incoming.dep_type,
                                DependencyType::Peer | DependencyType::PeerOptional
                            ) {
                                sources.push_back(incoming.from_location.clone());
                            } else if let Some(source) = self.graph.nodes.get(&incoming.from_location) {
                                let dev = (!source.location.contains("node_modules") && self.options.dev)
                                    .then(|| source.dev_dependencies.get(&task.install_name))
                                    .flatten();
                                if let Some(spec) = dev
                                    .or_else(|| source.optional_dependencies.get(&task.install_name))
                                    .or_else(|| source.dependencies.get(&task.install_name))
                                {
                                    if let Some(target) = cached_parse_package_target(spec) {
                                        peer_advisories.push(target);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    for incoming in self
                        .graph
                        .edges
                        .iter()
                        .filter(|edge| edge.to_location == location)
                    {
                        if matches!(
                            incoming.dep_type,
                            DependencyType::Peer | DependencyType::PeerOptional
                        ) {
                            sources.push_back(incoming.from_location.clone());
                        } else if let Some(source) = self.graph.nodes.get(&incoming.from_location) {
                            let dev = (!source.location.contains("node_modules") && self.options.dev)
                                .then(|| source.dev_dependencies.get(&task.install_name))
                                .flatten();
                            if let Some(spec) = dev
                                .or_else(|| source.optional_dependencies.get(&task.install_name))
                                .or_else(|| source.dependencies.get(&task.install_name))
                            {
                                if let Some(target) = cached_parse_package_target(spec) {
                                    peer_advisories.push(target);
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(advisory) = task.advisory.as_deref() {
            if let Some(target) = cached_parse_package_target(advisory) {
                peer_advisories.push(target);
            }
        }
        let matched_version_opt = self
            .select_version(
                &task.parent_location,
                &task.install_name,
                &dep_spec.package_name,
                &pkg_meta,
                &dep_spec.target,
                &peer_advisories,
            )
            .or_else(|| {
                self.select_version(
                    &task.parent_location,
                    &task.install_name,
                    &dep_spec.package_name,
                    &pkg_meta,
                    &dep_spec.target,
                    &[],
                )
            });
        let Some(chosen_version) = matched_version_opt else {
            if task.dep_type == DependencyType::Optional
                || task.dep_type == DependencyType::PeerOptional
            {
                debug!(
                    "No matching version for optional dependency '{}@{}', skipping",
                    dep_spec.package_name, effective_spec
                );
                if task.dep_type == DependencyType::Optional {
                    self.graph.skipped.insert(dep_spec.package_name.clone());
                    self.graph.skipped.insert(task.install_name.clone());
                }
                return Ok(());
            }
            if task.dep_type == DependencyType::Peer {
                if !self.options.is_strict_peers() {
                    warn!(
                        "Unresolved peer dependency '{}@{}' (non-strict mode), skipping",
                        dep_spec.package_name, effective_spec
                    );
                    return Ok(());
                }
                return Err(SolverError::peer_conflict(
                    task.parent_package_name,
                    dep_spec.package_name,
                    effective_spec.clone(),
                    None,
                    None,
                    (*task.ancestors).clone(),
                    format!("No version satisfying '{}'", effective_spec),
                ));
            }
            return Err(SolverError::UnresolvedDependency {
                name: dep_spec.package_name,
                spec: effective_spec,
                message: "No matching version found satisfying constraint".to_string(),
            });
        };

        // 5. Platform filtering for optional dependencies
        let compatible = self.options.platform.matches_with_libc(
            chosen_version.os.as_deref(),
            chosen_version.cpu.as_deref(),
            chosen_version.libc.as_deref(),
        );
        let platform_skipped = !compatible && task.dep_type == DependencyType::Optional;
        // Optional packages are still skipped under --force (reify checks
        // them without force); required ones are installed anyway.
        if !compatible && !platform_skipped && !self.options.force {
            let (wanted, current, detail) = crate::platform::npm_platform_report(
                chosen_version.os.as_deref(),
                chosen_version.cpu.as_deref(),
                chosen_version.libc.as_deref(),
                &self.options.platform,
            );
            return Err(SolverError::platform_incompatible(
                &dep_spec.package_name,
                &chosen_version.version,
                wanted,
                current,
                (*task.ancestors).clone(),
                detail,
            ));
        }
        if platform_skipped {
            debug!(
                "Optional package '{}@{}' retained in lockfile but skipped on platform ({:?})",
                dep_spec.package_name, chosen_version.version, self.options.platform
            );
        }

        // Check peers as edges of the candidate's virtual tree. Overrides
        // affect those edges, while the lockfile keeps the manifest's ranges.
        let has_shadowed_peers = chosen_version.peer_dependencies.keys().any(|name| {
            chosen_version.dependencies.contains_key(name)
                || chosen_version.optional_dependencies.contains_key(name)
        });
        let placement_peers = if chosen_version.peer_dependencies.is_empty()
            || (self.overrides.rules.is_empty() && !has_shadowed_peers)
        {
            None
        } else {
            let reference_root = self
                .graph
                .nodes
                .get(&task.parent_location)
                .map(Node::all_dependency_specs)
                .unwrap_or_default();
            let mut caller_specs = BTreeMap::new();
            for section in [
                &chosen_version.peer_dependencies,
                &chosen_version.dependencies,
                &chosen_version.optional_dependencies,
                &chosen_version.dev_dependencies,
            ] {
                for (name, spec) in section {
                    if !spec.is_empty() {
                        caller_specs.insert(name.clone(), spec.clone());
                    }
                }
            }
            let mut ancestors = (*task.ancestors).clone();
            ancestors.push(dep_spec.package_name.clone());
            let mut peers = BTreeMap::new();
            for (name, spec) in &chosen_version.peer_dependencies {
                // Arborist loads prod and optional edges after peers, replacing
                // a peer declaration for the same name before placement.
                if chosen_version.dependencies.contains_key(name)
                    || chosen_version.optional_dependencies.contains_key(name)
                {
                    continue;
                }
                let virtual_override = self.overrides.resolve_override_in_context(
                    name,
                    spec,
                    &ancestors,
                    &reference_root,
                    Some(&caller_specs),
                )?;
                let uses_override = virtual_override.is_some();
                let effective_peer = virtual_override.unwrap_or_else(|| spec.clone());
                if uses_override && !self.peer_conflict_is_fatal(task.is_mine) {
                    if let Some(source) = self.graph.nodes.get(&task.parent_location) {
                        let parent_spec = source
                            .optional_dependencies
                            .get(name)
                            .or_else(|| source.dependencies.get(name))
                            .or_else(|| source.peer_dependencies.get(name));
                        if let Some(parent_spec) = parent_spec {
                            let parent_spec = self
                                .overrides
                                .resolve_override_with_caller(
                                    name,
                                    parent_spec,
                                    &task.ancestors,
                                    Some(&reference_root),
                                )?
                                .unwrap_or_else(|| parent_spec.clone());
                            if let Some(provider) = crate::hoisting::find_visible_peer_node(
                                &self.graph,
                                &task.parent_location,
                                name,
                                name,
                            ) {
                                let parent_target = PackageTarget::parse(&parent_spec)?;
                                let peer_target = PackageTarget::parse(&effective_peer)?;
                                if crate::hoisting::node_satisfies_target(provider, &parent_target)
                                    && !crate::hoisting::node_satisfies_target(
                                        provider,
                                        &peer_target,
                                    )
                                {
                                    // loadPeerSet keeps the parent's provider and marks
                                    // this virtual edge peerConflicted. CanPlaceDep
                                    // excludes such edges from the candidate's peer set.
                                    continue;
                                }
                            }
                        }
                    }
                }
                peers.insert(name.clone(), effective_peer);
            }
            Some(peers)
        };

        // 6. Hoisting & Tree Placement
        let peer_scope = is_peer.then(|| {
            crate::hoisting::peer_provider_scope(
                &self.graph,
                &task.parent_location,
                &task.install_name,
            )
        });
        // The placement routine treats this as an ordinary child of the
        // deepest allowed scope; it must not nest inside its peer owner.
        let placement_parent = peer_scope.unwrap_or(&task.parent_location);
        let no_peers = BTreeMap::new();
        let candidate_peers = if self.options.legacy_peer_deps {
            &no_peers
        } else {
            placement_peers
                .as_ref()
                .unwrap_or(&chosen_version.peer_dependencies)
        };
        let mut placement = determine_placement_with_peers(
            &self.graph,
            placement_parent,
            &dep_spec.install_name,
            &dep_spec.package_name,
            &dep_spec.target,
            &chosen_version.dependencies,
            candidate_peers,
            &chosen_version.peer_dependencies_meta,
            Some(&chosen_version.version),
            chosen_version.dist_tarball.as_deref(),
            chosen_version.dist_integrity.as_deref(),
            is_peer,
            self.options.install_strategy,
        );

        let is_unlocked = self
            .options
            .unlocked_packages
            .contains(&dep_spec.install_name)
            || self
                .options
                .unlocked_packages
                .contains(&dep_spec.package_name)
            || self
                .options
                .vulnerability_constraints
                .contains_key(&dep_spec.install_name)
            || self
                .options
                .vulnerability_constraints
                .contains_key(&dep_spec.package_name);

        if !is_unlocked {
            if let Some(ref lockfile) = self.options.lockfile {
                let mut found_loc = None;
                for scope in crate::hoisting::iter_ancestor_scopes(&task.parent_location) {
                    let cand = if scope.is_empty() {
                        format!("node_modules/{}", dep_spec.install_name)
                    } else {
                        format!("{scope}/node_modules/{}", dep_spec.install_name)
                    };
                    if let Some(pkg) = lockfile.packages.get(&cand) {
                        if pkg.version.as_deref() == Some(&chosen_version.version) {
                            found_loc = Some(cand);
                            break;
                        }
                    }
                }
                if let Some(loc) = found_loc {
                    if let Some(existing) = self.graph.nodes.get(&loc) {
                        if existing.name == dep_spec.package_name
                            && existing.version == chosen_version.version
                        {
                            placement = PlacementDecision::Reuse(loc);
                        }
                    } else if !self.graph.nodes.contains_key(&loc) {
                        placement = PlacementDecision::PlaceNew(loc);
                    }
                }
            }
        }
        let root_slot = format!("node_modules/{}", dep_spec.install_name);
        if replace_transitive_root_peer
            && crate::hoisting::provider_accepts_version(
                &self.graph,
                &root_slot,
                &chosen_version.version,
            )
        {
            // Node#canReplace: every dependent accepts the new version, so it
            // takes the old node's place instead of nesting around it.
            self.detach_subtree(&root_slot);
            placement = PlacementDecision::PlaceNew(root_slot.clone());
        } else if replace_transitive_root_peer {
            if let Some(existing) = self.graph.nodes.get(&root_slot) {
                let pinned_by_peer = if !self.graph.incoming_edges_by_location.is_empty() {
                    if let Some(incoming) = self.graph.incoming_edges_by_location.get(&root_slot) {
                        incoming.iter().any(|&i| {
                            let edge = &self.graph.edges[i];
                            matches!(
                                edge.dep_type,
                                DependencyType::Peer | DependencyType::PeerOptional
                            ) && cached_parse_package_target(&edge.spec).is_some_and(|target| {
                                crate::hoisting::node_satisfies_target(existing, &target)
                            })
                        })
                    } else {
                        false
                    }
                } else {
                    self.graph.edges.iter().any(|edge| {
                        edge.to_location == root_slot
                            && matches!(
                                edge.dep_type,
                                DependencyType::Peer | DependencyType::PeerOptional
                            )
                            && cached_parse_package_target(&edge.spec).is_some_and(|target| {
                                crate::hoisting::node_satisfies_target(existing, &target)
                            })
                    })
                };
                if pinned_by_peer && self.peer_conflict_is_fatal(task.is_mine) {
                    return Err(SolverError::peer_conflict(
                        &task.parent_package_name,
                        &dep_spec.package_name,
                        &effective_spec,
                        Some(existing.version.clone()),
                        Some(existing.location.clone()),
                        (*task.ancestors).clone(),
                        "Cannot move a peer provider beneath its consumer".to_string(),
                    )
                    .with_eresolve(self.explain_placed_peer_conflict(
                        &task,
                        &dep_spec,
                        &effective_spec,
                        &existing.location,
                    )));
                }
            }
            if !self.rehome_transitive_root_node(&root_slot, &dep_spec.install_name) {
                return Ok(());
            }
            placement = PlacementDecision::PlaceNew(root_slot.clone());
        }
        let parent_skipped = self
            .graph
            .nodes
            .get(&task.parent_location)
            .map(|node| node.flags.skipped)
            .unwrap_or(false);

        match placement {
            PlacementDecision::Reuse(existing_loc) => {
                debug!(
                    "Deduplicated '{}': reusing existing node at '{}'",
                    dep_spec.install_name, existing_loc
                );
                if let Some(existing) = self.graph.nodes.get_mut(&existing_loc) {
                    existing.flags.platform_skipped = Some(platform_skipped);
                }
                if parent_skipped {
                    if let Some(existing) = self.graph.nodes.get_mut(&existing_loc) {
                        existing.flags.skipped = true;
                    }
                    self.graph.skipped.insert(dep_spec.package_name.clone());
                    self.graph.skipped.insert(task.install_name.clone());
                }
                self.graph.add_edge(DependencyEdge {
                    from_location: task.parent_location,
                    to_location: existing_loc,
                    install_name: task.install_name,
                    package_name: dep_spec.package_name,
                    spec: effective_spec,
                    dep_type: task.dep_type,
                });
            }
            PlacementDecision::PlaceNew(target_loc) => {
                // Arborist can rehome an earlier transitive occupant when a
                // later branch needs a different version in the shared root
                // slot. Without this repair, traversal order leaves the
                // lower version at the root and nests the higher-priority
                // package, producing the common Jest p-limit mismatch.
                if target_loc == root_slot
                    && self.graph.nodes.get(&target_loc).is_some_and(|existing| {
                        existing.name == dep_spec.package_name
                            && !crate::hoisting::node_satisfies_target(existing, &dep_spec.target)
                    })
                {
                    let _ = self.rehome_transitive_root_node(&target_loc, &dep_spec.install_name);
                }
                debug!(
                    "Placing package '{}' (install: '{}', version: '{}') at '{}'",
                    dep_spec.package_name,
                    dep_spec.install_name,
                    chosen_version.version,
                    target_loc
                );

                let is_bundled = if task.parent_location.is_empty() {
                    self.graph
                        .nodes
                        .get("")
                        .map(|p| {
                            p.bundled_package_names().contains(&task.install_name)
                                || p.bundled_package_names().contains(&dep_spec.package_name)
                        })
                        .unwrap_or(false)
                } else {
                    self.graph
                        .nodes
                        .get(&task.parent_location)
                        .map(|p| {
                            p.flags.bundled
                                || p.bundled_package_names().contains(&task.install_name)
                                || p.bundled_package_names().contains(&dep_spec.package_name)
                        })
                        .unwrap_or(false)
                };

                let flags = NodeFlags {
                    dev: task.dep_type == DependencyType::Dev,
                    optional: task.dep_type == DependencyType::Optional,
                    dev_optional: false,
                    peer: is_peer,
                    bundled: is_bundled,
                    has_install_script: chosen_version.has_install_script,
                    skipped: platform_skipped || parent_skipped,
                    platform_skipped: Some(platform_skipped),
                    link: false,
                };

                let node = Node {
                    location: target_loc.clone(),
                    install_name: task.install_name.clone(),
                    name: dep_spec.package_name.clone(),
                    version: chosen_version.version.clone(),
                    parsed_version: cached_parse_version(&chosen_version.version),
                    resolved: chosen_version.dist_tarball.clone(),
                    integrity: chosen_version.dist_integrity.clone(),
                    flags,
                    dependencies: chosen_version.dependencies.clone(),
                    dev_dependencies: chosen_version.dev_dependencies.clone(),
                    peer_dependencies: chosen_version.peer_dependencies.clone(),
                    peer_dependencies_meta: chosen_version.peer_dependencies_meta.clone(),
                    optional_dependencies: chosen_version.optional_dependencies.clone(),
                    os: chosen_version.os.clone(),
                    cpu: chosen_version.cpu.clone(),
                    libc: chosen_version.libc.clone(),
                    bin: chosen_version.bin.clone(),
                    license: chosen_version.license.clone(),
                    engines: chosen_version.engines.clone(),
                    extra: {
                        let mut extra = chosen_version.extra.clone();
                        if let Some(deprecated) = &chosen_version.deprecated {
                            extra.insert(
                                "deprecated".to_string(),
                                serde_json::Value::String(deprecated.clone()),
                            );
                        }
                        extra
                    },
                };

                self.graph.add_node(target_loc.clone(), node);
                self.activate_invalidated_workspaces(&target_loc);
                self.activate_deferred_optional_peers(&target_loc);
                if target_loc == root_slot {
                    self.dedupe_nested_compatible_nodes(
                        &root_slot,
                        &dep_spec.package_name,
                        &dep_spec.install_name,
                        &dep_spec.target,
                    );
                }

                if platform_skipped || parent_skipped {
                    self.graph.skipped.insert(dep_spec.package_name.clone());
                    self.graph.skipped.insert(task.install_name.clone());
                }

                self.graph.add_edge(DependencyEdge {
                    from_location: task.parent_location,
                    to_location: target_loc.clone(),
                    install_name: task.install_name.clone(),
                    package_name: dep_spec.package_name.clone(),
                    spec: effective_spec,
                    dep_type: task.dep_type,
                });

                // Enqueue child dependencies with Arc ancestors to avoid vector clones.
                // A platform-skipped optional package is retained as a lockfile
                // record together with its dependency metadata. Descendants inherit
                // optional/skipped reachability and therefore remain out of the
                // physical install while preserving cross-platform lockfile parity.

                let mut child_ancestors = (*task.ancestors).clone();
                child_ancestors.push(dep_spec.package_name.clone());
                let child_ancestors = std::sync::Arc::new(child_ancestors);

                let mut child_deps: BTreeMap<String, (String, DependencyType)> = BTreeMap::new();

                for (k, v) in &chosen_version.dependencies {
                    child_deps.insert(k.clone(), (v.clone(), DependencyType::Prod));
                }
                for (k, v) in &chosen_version.optional_dependencies {
                    child_deps.insert(k.clone(), (v.clone(), DependencyType::Optional));
                }

                // Peer dependencies
                if !self.options.legacy_peer_deps {
                    for (k, v) in &chosen_version.peer_dependencies {
                        if let Some((_, DependencyType::Prod | DependencyType::Optional)) =
                            child_deps.get(k)
                        {
                            // Production and optional dependencies replace peer edges.
                            continue;
                        }
                        let is_opt_peer = chosen_version
                            .peer_dependencies_meta
                            .get(k)
                            .map(|m| m.optional)
                            .unwrap_or(false);
                        let p_type = if is_opt_peer {
                            DependencyType::PeerOptional
                        } else {
                            DependencyType::Peer
                        };
                        child_deps.insert(k.clone(), (v.clone(), p_type));
                    }
                }

                // Bundled dependencies ship inside the package tarball; npm
                // never resolves them from the registry.
                let bundled = chosen_version
                    .extra
                    .get("bundleDependencies")
                    .or_else(|| chosen_version.extra.get("bundledDependencies"));
                match bundled {
                    Some(serde_json::Value::Array(names)) => {
                        for name in names.iter().filter_map(|n| n.as_str()) {
                            child_deps.remove(name);
                        }
                    }
                    // `true` bundles every dependency.
                    Some(serde_json::Value::Bool(true)) => {
                        let names: Vec<String> =
                            chosen_version.dependencies.keys().cloned().collect();
                        for name in names {
                            child_deps.remove(&name);
                        }
                    }
                    _ => {}
                }

                // npm's Arborist walks package dependency names in sorted
                // order.  Registry packuments preserve insertion order, but
                // using that order here changes which compatible version wins
                // a shared hoisted slot (for example Express's `ms`).  The
                // BTreeMap keeps traversal deterministic and matches npm's
                // lockfile dependency ordering.
                let child_depth = target_loc.matches("node_modules").count();
                let child_tasks = child_deps
                    .into_iter()
                    .map(|(c_name, (c_spec, c_type))| {
                        let is_peer =
                            matches!(c_type, DependencyType::Peer | DependencyType::PeerOptional);
                        let child_is_mine = if is_peer { task.is_mine } else { false };
                        ResolveTask {
                            parent_location: target_loc.clone(),
                            parent_package_name: dep_spec.package_name.clone(),
                            install_name: c_name,
                            raw_spec: c_spec,
                            dep_type: c_type,
                            parent_depth: child_depth,
                            ancestors: child_ancestors.clone(),
                            advisory: None,
                            is_mine: child_is_mine,
                            is_root: false,
                        }
                    })
                    .collect::<Vec<_>>();
                // Keep a package's direct dependencies ahead of their
                // descendants. This matches Arborist's breadth-first
                // placement pass and lets a later direct dependency claim a
                // compatible root slot before an earlier sibling's nested
                // subtree is expanded.
                let mut child_targets = Vec::new();
                for t in &child_tasks {
                    let Ok(c_dep) = DependencySpec::parse(&t.install_name, &t.raw_spec) else {
                        continue;
                    };
                    if matches!(
                        c_dep.target,
                        PackageTarget::Range(_) | PackageTarget::Version(_) | PackageTarget::Tag(_)
                    ) {
                        child_targets.push(c_dep);
                    }
                }
                let child_edges: Vec<(&str, bool)> = child_targets
                    .iter()
                    .map(|t| (t.package_name.as_str(), false))
                    .collect();
                self.provider.prefetch_packages_for_edge(&child_edges);
                let mut peer_tasks = Vec::new();
                for child_task in child_tasks {
                    // PlaceDep places a candidate together with its required
                    // peer set, before any queued node is expanded. Explicit
                    // root dependencies still own their reserved slots.
                    let peer_scope = target_loc
                        .rsplit_once("/node_modules/")
                        .map(|(scope, _)| scope)
                        .unwrap_or("");
                    let is_peer_scope_mine = !peer_scope.contains("node_modules");
                    let provider_pending = self.graph.nodes.get(peer_scope).is_some_and(|parent| {
                        let mut declared =
                            parent.dependencies.contains_key(&child_task.install_name)
                                || parent
                                    .optional_dependencies
                                    .contains_key(&child_task.install_name)
                                || (parent
                                    .peer_dependencies
                                    .contains_key(&child_task.install_name)
                                    && !parent
                                        .peer_dependencies_meta
                                        .get(&child_task.install_name)
                                        .is_some_and(|m| m.optional));
                        if self.options.dev {
                            declared = declared
                                || parent
                                    .dev_dependencies
                                    .contains_key(&child_task.install_name);
                        }
                        let loc = if peer_scope.is_empty() {
                            format!("node_modules/{}", child_task.install_name)
                        } else {
                            format!("{peer_scope}/node_modules/{}", child_task.install_name)
                        };
                        declared && !self.graph.nodes.contains_key(&loc)
                    });
                    let is_peer_child = matches!(
                        child_task.dep_type,
                        DependencyType::Peer | DependencyType::PeerOptional
                    );
                    if is_peer_child && !provider_pending {
                        peer_tasks.push(child_task);
                    } else if is_peer_child && is_peer_scope_mine {
                        // loadPeerSet: when the peer would land beside a root or workspace
                        // edge for the same name, resolve that edge now,
                        // with the peer range as the advisory second edge.
                        let Some(parent) = self.graph.nodes.get(peer_scope) else {
                            continue;
                        };
                        let name = child_task.install_name.clone();
                        // arborist loads peer, prod, optional, then dev edges, a
                        // later type replacing an earlier one for the same name.
                        let dev_edge = self
                            .options
                            .dev
                            .then(|| {
                                parent
                                    .dev_dependencies
                                    .get(&name)
                                    .map(|s| (s.clone(), DependencyType::Dev))
                            })
                            .flatten();
                        let parent_edge = dev_edge
                            .or_else(|| {
                                parent
                                    .optional_dependencies
                                    .get(&name)
                                    .map(|s| (s.clone(), DependencyType::Optional))
                            })
                            .or_else(|| {
                                parent
                                    .dependencies
                                    .get(&name)
                                    .map(|s| (s.clone(), DependencyType::Prod))
                            })
                            .or_else(|| {
                                parent
                                    .peer_dependencies
                                    .get(&name)
                                    .filter(|_| {
                                        !parent
                                            .peer_dependencies_meta
                                            .get(&name)
                                            .is_some_and(|m| m.optional)
                                    })
                                    .map(|s| (s.clone(), DependencyType::Peer))
                            });
                        if let Some((raw_spec, dep_type)) = parent_edge {
                            let is_peer_scope_root = !peer_scope.contains("node_modules");
                            let root_pkg_name = self
                                .graph
                                .nodes
                                .get("")
                                .map(|n| n.name.clone())
                                .unwrap_or_else(|| "root".to_string());
                            let root_task = ResolveTask {
                                parent_location: peer_scope.to_string(),
                                parent_package_name: parent.name.clone(),
                                install_name: name.clone(),
                                raw_spec,
                                dep_type,
                                parent_depth: if peer_scope.is_empty() {
                                    0
                                } else {
                                    peer_scope.matches("node_modules").count()
                                },
                                ancestors: std::sync::Arc::new(if peer_scope.is_empty() {
                                    vec![parent.name.clone()]
                                } else {
                                    vec![root_pkg_name, parent.name.clone()]
                                }),
                                advisory: Some(child_task.raw_spec.clone()),
                                is_mine: true,
                                is_root: is_peer_scope_root,
                            };
                            let preplaced_key = if peer_scope.is_empty() {
                                name
                            } else {
                                format!("{peer_scope}#{name}")
                            };
                            self.preplaced.insert(preplaced_key);
                            peer_tasks.push(root_task);
                            peer_tasks.push(child_task);
                        } else {
                            self.push_task(child_task);
                        }
                    } else {
                        self.push_task(child_task);
                    }
                }
                for peer_task in peer_tasks {
                    self.process_task(peer_task)?;
                }
            }
        }

        Ok(())
    }

    /// Move a transitive root occupant beneath the sole package that still
    /// requires its version. Direct root dependencies are never moved, and
    /// ambiguous multi-parent occupants are left untouched for the normal
    /// conflict-nesting path.
    /// Removes a node and the nodes nested under it, then every node it
    /// reached that nothing outside that set still reaches (Arborist prunes
    /// them; a dependency cycle does not keep itself alive).
    fn detach_subtree(&mut self, location: &str) {
        use std::collections::{HashSet, VecDeque};
        let nested_under = |loc: &str, key: &str| key.starts_with(&format!("{loc}/node_modules/"));
        let forced: HashSet<String> = self
            .graph
            .nodes
            .keys()
            .filter(|key| key.as_str() == location || nested_under(location, key))
            .cloned()
            .collect();
        // Everything the old node reaches through edges or nesting.
        let mut reached: HashSet<String> = HashSet::new();
        let mut work: VecDeque<String> = forced.iter().cloned().collect();
        while let Some(loc) = work.pop_front() {
            if !reached.insert(loc.clone()) {
                continue;
            }
            for edge in &self.graph.edges {
                if edge.from_location == loc
                    && edge.to_location.contains("node_modules/")
                    && self.graph.nodes.contains_key(&edge.to_location)
                {
                    work.push_back(edge.to_location.clone());
                }
            }
            for key in self.graph.nodes.keys() {
                if nested_under(&loc, key) {
                    work.push_back(key.clone());
                }
            }
        }
        // A reached node survives when a node outside the set depends on it,
        // and so does whatever it reaches.
        let mut kept: HashSet<String> = HashSet::new();
        let mut work: VecDeque<String> = reached
            .iter()
            .filter(|loc| {
                !forced.contains(*loc)
                    && self.graph.edges.iter().any(|edge| {
                        edge.to_location == **loc && !reached.contains(&edge.from_location)
                    })
            })
            .cloned()
            .collect();
        while let Some(loc) = work.pop_front() {
            if forced.contains(&loc) || !kept.insert(loc.clone()) {
                continue;
            }
            for edge in &self.graph.edges {
                if edge.from_location == loc && reached.contains(&edge.to_location) {
                    work.push_back(edge.to_location.clone());
                }
            }
            for key in &reached {
                if nested_under(&loc, key) {
                    work.push_back(key.clone());
                }
            }
        }
        let detached: HashSet<String> = reached.difference(&kept).cloned().collect();
        self.graph.nodes.retain(|key, _| !detached.contains(key));
        self.graph
            .edges
            .retain(|edge| !detached.contains(&edge.from_location));
        self.graph.rebuild_indices();
        // Work queued for the detached nodes belongs to the old version; the
        // replacement enqueues its own dependencies.
        self.queue
            .retain(|task| !detached.contains(&task.parent_location));
        for tasks in self.deferred_workspaces.values_mut() {
            tasks.retain(|task| !detached.contains(&task.parent_location));
        }
        for tasks in self.deferred_optional_peers.values_mut() {
            tasks.retain(|task| !detached.contains(&task.parent_location));
        }
    }

    fn rehome_transitive_root_node(&mut self, root_location: &str, install_name: &str) -> bool {
        if let Some(ref lockfile) = self.options.lockfile {
            if lockfile.packages.contains_key(root_location)
                && !self.options.unlocked_packages.contains(install_name)
                && !self
                    .options
                    .vulnerability_constraints
                    .contains_key(install_name)
            {
                return false;
            }
        }
        let incoming: Vec<_> = self
            .graph
            .edges
            .iter()
            .filter(|edge| edge.to_location == root_location)
            .collect();
        if incoming.is_empty() || incoming.iter().any(|edge| edge.from_location.is_empty()) {
            return false;
        }
        let Some(existing_node) = self.graph.nodes.get(root_location).cloned() else {
            return false;
        };
        let compatible_edges: Vec<_> = incoming
            .iter()
            .filter(|edge| {
                cached_parse_package_target(&edge.spec)
                    .map(|target| crate::hoisting::node_satisfies_target(&existing_node, &target))
                    .unwrap_or(false)
            })
            .collect();
        if compatible_edges.is_empty() {
            return false;
        }
        if compatible_edges.iter().any(|edge| {
            matches!(
                edge.dep_type,
                DependencyType::Peer | DependencyType::PeerOptional
            )
        }) {
            return false;
        }
        let parent = compatible_edges[0].from_location.clone();
        if compatible_edges
            .iter()
            .any(|edge| edge.from_location != parent)
        {
            return false;
        }
        let nested = format!("{parent}/node_modules/{install_name}");
        if self.graph.nodes.contains_key(&nested) {
            return false;
        }
        let Some(mut node) = self.graph.nodes.remove(root_location) else {
            return false;
        };
        node.location = nested.clone();
        self.graph.nodes.insert(nested.clone(), node);

        // Migrate nested child nodes under root_location to nested
        let prefix = format!("{root_location}/node_modules/");
        let child_keys: Vec<String> = self
            .graph
            .nodes
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        for child_key in child_keys {
            if let Some(mut child_node) = self.graph.nodes.remove(&child_key) {
                let suffix = &child_key[root_location.len()..];
                let new_loc = format!("{nested}{suffix}");
                child_node.location = new_loc.clone();
                self.graph.nodes.insert(new_loc, child_node);
            }
        }

        // Update all edges that refer to root_location or any of its nested children
        for edge in &mut self.graph.edges {
            if edge.from_location == root_location {
                edge.from_location = nested.clone();
            } else if edge.from_location.starts_with(&prefix) {
                let suffix = &edge.from_location[root_location.len()..];
                edge.from_location = format!("{nested}{suffix}");
            }

            if edge.to_location == root_location {
                let keep_nested = cached_parse_package_target(&edge.spec)
                    .map(|target| crate::hoisting::node_satisfies_target(&existing_node, &target))
                    .unwrap_or(false);
                if keep_nested {
                    edge.to_location = nested.clone();
                }
            } else if edge.to_location.starts_with(&prefix) {
                let suffix = &edge.to_location[root_location.len()..];
                edge.to_location = format!("{nested}{suffix}");
            }
        }
        self.graph.rebuild_indices();

        // Children waiting to expand still belong to the moved package.
        // Reinsert them because depth and path determine queue ordering.
        for mut task in self.queue.drain_all() {
            if task.parent_location == root_location || task.parent_location.starts_with(&prefix) {
                task.parent_location =
                    format!("{nested}{}", &task.parent_location[root_location.len()..]);
                task.parent_depth = task.parent_location.matches("node_modules").count();
            }
            self.push_task(task);
        }
        for tasks in self.deferred_optional_peers.values_mut() {
            for task in tasks {
                if task.parent_location == root_location
                    || task.parent_location.starts_with(&prefix)
                {
                    task.parent_location =
                        format!("{nested}{}", &task.parent_location[root_location.len()..]);
                    task.parent_depth = task.parent_location.matches("node_modules").count();
                }
            }
        }
        true
    }

    pub(crate) fn dedupe_nested_compatible_nodes(
        &mut self,
        root_location: &str,
        package_name: &str,
        install_name: &str,
        target: &PackageTarget,
    ) {
        let candidates: Vec<String> = if let Some(locs) = self.graph.nodes_by_install_name.get(install_name) {
            locs.iter()
                .filter(|location| {
                    *location != root_location
                        && location
                            .strip_suffix(install_name)
                            .is_some_and(|prefix| prefix.ends_with("/node_modules/"))
                        && self.graph.nodes.get(*location).is_some_and(|node| {
                            node.name == package_name
                                && crate::hoisting::node_satisfies_target(node, target)
                        })
                        && !self.graph.has_children(location)
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

        if candidates.is_empty() {
            return;
        }

        for candidate in &candidates {
            if let Some(edge_indices) = self.graph.incoming_edges_by_location.get(candidate).cloned() {
                for idx in edge_indices {
                    if let Some(edge) = self.graph.edges.get_mut(idx) {
                        edge.to_location = root_location.to_string();
                    }
                }
            }
            self.graph.remove_node(candidate);
        }
        self.graph.rebuild_edge_indices();
    }

    /// Selects the highest version matching target constraint in a single linear pass (O(N), zero Vec allocations, zero metadata clones).
    /// buildIdealTree loads every root edge's peer set (nodeFromEdge) before
    /// placing any of them, so a root dependency whose required peer cannot
    /// agree with the root's own edge to that peer fails first, as "unable to
    /// resolve dependency tree", whatever placement conflicts come later.
    fn precheck_root_peer_sets(
        &self,
        root_manifest: &Manifest,
        root_deps: &BTreeMap<String, (String, DependencyType)>,
    ) -> Option<(SolverError, String)> {
        use crate::explain::{EdgeFrom, EdgeView, Explanation, Subject};
        // Node#loadDeps inserts peer, prod, optional, then dev edges; a name
        // keeps the position of its first appearance.
        let mut order: Vec<&String> = Vec::new();
        for deps in [
            &root_manifest.peer_dependencies,
            &root_manifest.dependencies,
            &root_manifest.optional_dependencies,
            &root_manifest.dev_dependencies,
        ] {
            for name in deps.keys() {
                if root_deps.contains_key(name) && !order.contains(&name) {
                    order.push(name);
                }
            }
        }
        let registry_target = |target: &PackageTarget| {
            matches!(
                target,
                PackageTarget::Range(_) | PackageTarget::Version(_) | PackageTarget::Tag(_)
            )
        };
        for name in order {
            let (spec, dep_type) = &root_deps[name];
            // An absent optional peer is never fetched.
            if *dep_type == DependencyType::PeerOptional {
                continue;
            }
            let Ok(dep_spec) = DependencySpec::parse(name, spec) else {
                continue;
            };
            // Aliases resolve another package's metadata; placement handles them.
            if dep_spec.package_name != *name || !registry_target(&dep_spec.target) {
                continue;
            }
            // Metadata failures belong to placement, which reports them in order.
            let Some(meta) = self
                .provider
                .get_package_for_edge(&dep_spec.package_name, spec, true)
                .ok()
                .flatten()
            else {
                continue;
            };
            let Some(chosen) = self.select_version(
                "",
                &dep_spec.install_name,
                &dep_spec.package_name,
                &meta,
                &dep_spec.target,
                &[],
            ) else {
                continue;
            };
            for (peer, peer_spec) in &chosen.peer_dependencies {
                if chosen
                    .peer_dependencies_meta
                    .get(peer)
                    .is_some_and(|meta| meta.optional)
                    || chosen.dependencies.contains_key(peer)
                    || chosen.optional_dependencies.contains_key(peer)
                    // Overrides rewrite these specs per path; leave them to placement.
                    || self.overrides.mentions(name)
                    || self.overrides.mentions(peer)
                {
                    continue;
                }
                let Some((root_spec, root_type)) = root_deps.get(peer) else {
                    continue;
                };
                if *root_type == DependencyType::PeerOptional {
                    continue;
                }
                let (Some(root_dep), Some(peer_target)) = (
                    DependencySpec::parse(peer, root_spec).ok(),
                    cached_parse_package_target(peer_spec),
                ) else {
                    continue;
                };
                let root_target = root_dep.target;
                if root_dep.package_name != *peer
                    || !registry_target(&root_target)
                    || !registry_target(&peer_target)
                {
                    continue;
                }
                let Some(peer_meta) = self
                    .provider
                    .get_package_for_edge(peer, root_spec, true)
                    .ok()
                    .flatten()
                else {
                    continue;
                };
                // nodeFromEdge(parentEdge, ..., peerEdge): the root's choice,
                // steered by the peer edge, must also satisfy the peer edge.
                let root_choice = self
                    .select_version(
                        "",
                        peer,
                        peer,
                        &peer_meta,
                        &root_target,
                        std::slice::from_ref(&peer_target),
                    )
                    .or_else(|| self.select_version("", peer, peer, &peer_meta, &root_target, &[]));
                let Some(root_choice) = root_choice else {
                    continue;
                };
                let satisfies =
                    crate::hoisting::version_satisfies_target(&root_choice.version, &peer_target);
                if satisfies {
                    continue;
                }
                let root_edge_to = |dep_type: DependencyType, name: &str, spec: &str| EdgeView {
                    dep_type,
                    name: name.to_string(),
                    spec: spec.to_string(),
                    from: EdgeFrom::Root,
                };
                let explanation = Explanation {
                    heading: "unable to resolve dependency tree",
                    while_resolving: self.source_id(&EdgeFrom::Root),
                    found: Subject::Candidate {
                        name: peer.clone(),
                        version: root_choice.version.clone(),
                        location: format!("node_modules/{peer}"),
                        dependents: vec![root_edge_to(*root_type, peer, root_spec)],
                    },
                    edge: EdgeView {
                        dep_type: DependencyType::Peer,
                        name: peer.clone(),
                        spec: peer_spec.clone(),
                        from: EdgeFrom::Virtual {
                            name: name.clone(),
                            version: chosen.version.clone(),
                            incoming: Some(Box::new(root_edge_to(*dep_type, name, spec))),
                        },
                    },
                    conflict: None,
                }
                .render(&self.graph, self.options.strict_peer_deps);
                let root_name = self
                    .graph
                    .nodes
                    .get("")
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| "root".to_string());
                let conflict = SolverError::peer_conflict(
                    name,
                    peer,
                    peer_spec,
                    Some(root_choice.version.clone()),
                    Some(format!("node_modules/{peer}")),
                    vec![root_name, name.clone()],
                    format!(
                        "Root dependency {peer}@{} does not satisfy peer constraint '{peer_spec}'",
                        root_choice.version
                    ),
                )
                .with_eresolve(explanation);
                return Some((conflict, chosen.version.clone()));
            }
        }
        None
    }

    /// Whether a precheck conflict still describes the tree placement built:
    /// placement may have steered the package to another version, or placed
    /// a peer that fits, in which case its own error is the real one.
    fn root_conflict_holds(&self, conflict: &SolverError, version: &str) -> bool {
        let SolverError::PeerConflict {
            parent,
            peer,
            required_spec,
            ..
        } = conflict
        else {
            return true;
        };
        if self
            .graph
            .nodes
            .get(&format!("node_modules/{parent}"))
            .is_some_and(|node| node.version != version)
        {
            return false;
        }
        !self
            .graph
            .nodes
            .get(&format!("node_modules/{peer}"))
            .zip(cached_parse_package_target(required_spec))
            .is_some_and(|(node, target)| crate::hoisting::node_satisfies_target(node, &target))
    }

    /// `name@version` as printNode shows a virtual tree's source; npm prints
    /// a missing root version as `undefined`.
    fn source_id(&self, from: &crate::explain::EdgeFrom) -> Option<String> {
        use crate::explain::EdgeFrom;
        let location = match from {
            EdgeFrom::Root => self.graph.root_location.as_str(),
            EdgeFrom::Node(location) => location.as_str(),
            EdgeFrom::Virtual { name, version, .. } => return Some(format!("{name}@{version}")),
        };
        let node = self.graph.nodes.get(location)?;
        let or_undefined = |s: &str| {
            if s.is_empty() {
                "undefined".to_string()
            } else {
                s.to_string()
            }
        };
        Some(format!(
            "{}@{}",
            or_undefined(&node.name),
            or_undefined(&node.version)
        ))
    }

    /// The edge that first placed `location`: the source of Arborist's
    /// virtual peer-set tree.
    fn placing_edge(&self, location: &str) -> Option<crate::explain::EdgeView> {
        self.graph
            .edges
            .iter()
            .find(|edge| edge.to_location == location)
            .map(|edge| {
                crate::explain::graph_edge(
                    &self.graph,
                    &edge.from_location,
                    edge.dep_type,
                    &edge.install_name,
                    &edge.spec,
                )
            })
    }

    /// The version npm would pick for the conflicting peer.
    fn candidate_version(&self, parent_location: &str, dep_spec: &DependencySpec) -> String {
        let is_root = !parent_location.contains("node_modules");
        self.provider
            .get_package_for_edge(&dep_spec.package_name, &dep_spec.raw_spec, is_root)
            .ok()
            .flatten()
            .and_then(|meta| {
                self.select_version(
                    parent_location,
                    &dep_spec.install_name,
                    &dep_spec.package_name,
                    &meta,
                    &dep_spec.target,
                    &[],
                )
                .map(|v| v.version.clone())
            })
            .unwrap_or_default()
    }

    /// A required peer of a newly placed package conflicts with a visible node.
    /// Arborist's loadPeerSet reports "unable to resolve dependency tree" when
    /// the root itself holds that node; otherwise place-dep fails placing the
    /// owner ("could not resolve") and names the peer it would have needed.
    fn explain_peer_set_conflict(
        &self,
        task: &ResolveTask,
        dep_spec: &DependencySpec,
        effective_spec: &str,
        existing_location: &str,
    ) -> crate::explain::Eresolve {
        use crate::explain::{EdgeFrom, EdgeView, Explanation, Subject};
        let owner = self.graph.nodes.get(&task.parent_location);
        let placing = self.placing_edge(&task.parent_location);
        let peer_edge = EdgeView {
            dep_type: task.dep_type,
            name: task.install_name.clone(),
            spec: effective_spec.to_string(),
            from: EdgeFrom::Virtual {
                name: owner
                    .map(|o| o.install_name.clone())
                    .unwrap_or_else(|| task.parent_package_name.clone()),
                version: owner.map(|o| o.version.clone()).unwrap_or_default(),
                incoming: placing.clone().map(Box::new),
            },
        };
        let while_resolving = placing.as_ref().and_then(|edge| self.source_id(&edge.from));
        let root_holds = self.graph.edges.iter().any(|edge| {
            edge.from_location == self.graph.root_location && edge.to_location == existing_location
        });
        let explanation = match placing {
            Some(placing) if !root_holds => Explanation {
                heading: "could not resolve",
                while_resolving,
                found: Subject::Graph(existing_location.to_string()),
                edge: placing,
                conflict: Some(Subject::Candidate {
                    name: task.install_name.clone(),
                    version: self.candidate_version(&task.parent_location, dep_spec),
                    location: format!("node_modules/{}", task.install_name),
                    dependents: vec![peer_edge],
                }),
            },
            _ => {
                // Arborist resolves the peer inside the virtual tree, where the
                // root's copy of the node has only the root's edges.
                let found = match self.graph.nodes.get(existing_location) {
                    Some(existing) if root_holds => Subject::Candidate {
                        name: existing.install_name.clone(),
                        version: existing.version.clone(),
                        location: existing_location.to_string(),
                        dependents: crate::explain::graph_dependents(
                            &self.graph,
                            existing_location,
                        )
                        .into_iter()
                        .filter(|edge| matches!(edge.from, EdgeFrom::Root))
                        .collect(),
                    },
                    _ => Subject::Graph(existing_location.to_string()),
                };
                Explanation {
                    heading: "unable to resolve dependency tree",
                    while_resolving,
                    found,
                    edge: peer_edge,
                    conflict: None,
                }
            }
        };
        explanation.render(&self.graph, self.options.strict_peer_deps)
    }

    /// A peer edge of an already placed package is invalid and cannot be
    /// fixed: place-dep fails on that edge ("could not resolve").
    fn explain_placed_peer_conflict(
        &self,
        task: &ResolveTask,
        dep_spec: &DependencySpec,
        effective_spec: &str,
        existing_location: &str,
    ) -> crate::explain::Eresolve {
        use crate::explain::{graph_edge, Explanation, Subject};
        let peer_edge = graph_edge(
            &self.graph,
            &task.parent_location,
            task.dep_type,
            &task.install_name,
            effective_spec,
        );
        Explanation {
            heading: "could not resolve",
            while_resolving: self.source_id(&peer_edge.from),
            found: Subject::Graph(existing_location.to_string()),
            edge: peer_edge.clone(),
            conflict: Some(Subject::Candidate {
                name: task.install_name.clone(),
                version: self.candidate_version(&task.parent_location, dep_spec),
                location: format!("node_modules/{}", task.install_name),
                dependents: vec![peer_edge],
            }),
        }
        .render(&self.graph, self.options.strict_peer_deps)
    }

    /// Warms the metadata cache for the likely dependency closure, one
    /// parallel batch per depth level, so placement (which visits one node at
    /// a time) rarely waits on the network. Only a cache warm-up: lookups that
    /// fail here are left for placement to report, and over-fetching a range
    /// placement ends up not using is harmless.
    fn prefetch_closure(&self, root_deps: &BTreeMap<String, (String, DependencyType)>) {
        // A work queue, not level-by-level waves: a package's children are
        // fetched as soon as it arrives, so one slow request no longer holds
        // back every package at the next depth.
        struct Work {
            queue: Vec<(String, String, bool)>,
            in_flight: usize,
            seen: std::collections::HashSet<String>,
        }
        let work = std::sync::Mutex::new(Work {
            // An absent optional peer is never fetched by placement.
            queue: root_deps
                .iter()
                .filter(|(_, (_, dep_type))| *dep_type != DependencyType::PeerOptional)
                .map(|(name, (spec, _))| (name.clone(), spec.clone(), true))
                .collect(),
            in_flight: 0,
            seen: root_deps.keys().cloned().collect(),
        });
        let ready = std::sync::Condvar::new();
        let workers = std::thread::available_parallelism()
            .map_or(8, |n| n.get())
            .clamp(8, 32);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let batch = {
                        let Ok(mut state) = work.lock() else { return };
                        loop {
                            if !state.queue.is_empty() {
                                break;
                            }
                            if state.in_flight == 0 {
                                ready.notify_all();
                                return;
                            }
                            state = match ready.wait(state) {
                                Ok(state) => state,
                                Err(_) => return,
                            };
                        }
                        let take = state.queue.len().min(4);
                        let at = state.queue.len() - take;
                        let batch = state.queue.split_off(at);
                        state.in_flight += 1;
                        batch
                    };
                    let children = self.closure_children(&batch);
                    let Ok(mut state) = work.lock() else { return };
                    for (child, spec, is_root) in children {
                        if state.seen.insert(child.clone()) {
                            state.queue.push((child, spec, is_root));
                        }
                    }
                    state.in_flight -= 1;
                    ready.notify_all();
                });
            }
        });
    }

    /// Prefetches one batch of the closure and returns the edges placement
    /// would follow from the versions it picks.
    fn closure_children(&self, batch: &[(String, String, bool)]) -> Vec<(String, String, bool)> {
        let mut targets = Vec::new();
        for (name, spec, is_root) in batch {
            let Ok(dep_spec) = DependencySpec::parse(name, spec) else {
                continue;
            };
            if matches!(
                dep_spec.target,
                PackageTarget::Range(_) | PackageTarget::Version(_) | PackageTarget::Tag(_)
            ) {
                targets.push((dep_spec, *is_root));
            }
        }
        let edges: Vec<(&str, bool)> = targets
            .iter()
            .map(|(t, is_root)| (t.package_name.as_str(), *is_root))
            .collect();
        self.provider.prefetch_packages_for_edge(&edges);
        let mut out = Vec::new();
        for (dep_spec, _) in &targets {
            // Only what the prefetch brought in: a failed prefetch is not
            // retried here, placement looks it up again.
            let Some(meta) = self.provider.cached_package(&dep_spec.package_name) else {
                continue;
            };
            let Some(version) = self.select_version(
                "",
                &dep_spec.install_name,
                &dep_spec.package_name,
                &meta,
                &dep_spec.target,
                &[],
            ) else {
                continue;
            };
            // Follow the edges placement follows: no peers under
            // legacy-peer-deps, and no bundled names (they ship inside
            // the parent's tarball).
            let bundled: Vec<&str> = match version
                .extra
                .get("bundleDependencies")
                .or_else(|| version.extra.get("bundledDependencies"))
            {
                Some(serde_json::Value::Array(names)) => {
                    names.iter().filter_map(|n| n.as_str()).collect()
                }
                Some(serde_json::Value::Bool(true)) => {
                    version.dependencies.keys().map(String::as_str).collect()
                }
                _ => Vec::new(),
            };
            let peers = (!self.options.legacy_peer_deps)
                .then_some(&version.peer_dependencies)
                .into_iter()
                .flatten()
                .filter(|(peer, _)| {
                    !version
                        .peer_dependencies_meta
                        .get(*peer)
                        .is_some_and(|meta| meta.optional)
                });
            for (child, child_spec) in version
                .dependencies
                .iter()
                .chain(&version.optional_dependencies)
                .chain(peers)
            {
                // Bundled names ship in the tarball; overridden names may
                // resolve elsewhere, so placement fetches those itself.
                if bundled.contains(&child.as_str()) || self.overrides.mentions(child) {
                    continue;
                }
                out.push((child.clone(), child_spec.clone(), false));
            }
        }
        out
    }

    fn select_version<'b>(
        &self,
        parent_location: &str,
        install_name: &str,
        pkg_name: &str,
        meta: &'b PackageMetadata,
        target: &PackageTarget,
        advisories: &[PackageTarget],
    ) -> Option<&'b PackageVersionMetadata> {
        let is_unlocked = self.options.unlocked_packages.contains(install_name)
            || self.options.unlocked_packages.contains(pkg_name)
            || self
                .options
                .vulnerability_constraints
                .contains_key(install_name)
            || self
                .options
                .vulnerability_constraints
                .contains_key(pkg_name);
        if !is_unlocked {
            if let Some(ref lockfile) = self.options.lockfile {
                let mut found_pkg = None;
                for scope in crate::hoisting::iter_ancestor_scopes(parent_location) {
                    let cand = if scope.is_empty() {
                        format!("node_modules/{install_name}")
                    } else {
                        format!("{scope}/node_modules/{install_name}")
                    };
                    if let Some(pkg) = lockfile.packages.get(&cand) {
                        let entry_name = pkg.name.as_deref().unwrap_or(install_name);
                        if entry_name == pkg_name {
                            found_pkg = Some(pkg);
                            break;
                        }
                    }
                }
                if let Some(pkg) = found_pkg {
                    if let Some(ref ver_str) = pkg.version {
                        if crate::hoisting::version_satisfies_target(ver_str, target) {
                            if let Some(v_meta) = meta.versions.get(ver_str) {
                                return Some(v_meta);
                            }
                        }
                    }
                }
            }
        }

        match target {
            PackageTarget::Version(expected) => {
                let v_str = expected.to_string();
                if let Some(v) = meta.versions.get(&v_str) {
                    Some(v)
                } else {
                    meta.versions.iter().find_map(|(ver_str, v_meta)| {
                        if let Some(cv) = cached_parse_version(ver_str) {
                            if &cv == expected {
                                return Some(v_meta);
                            }
                        }
                        None
                    })
                }
            }
            PackageTarget::Tag(tag) => {
                if let Some(tagged_version) = meta.dist_tags.get(tag) {
                    if let Some(v) = meta.versions.get(tagged_version) {
                        return Some(v);
                    }
                }
                // Fallback for "latest" when dist_tags.latest was published after a --before / min-release-age cutoff
                // or omitted in filtered metadata: pick highest available version.
                if tag == "latest" {
                    let mut versions: Vec<(&PackageVersionMetadata, Version)> = meta
                        .versions
                        .values()
                        .filter_map(|vm| {
                            cached_parse_version(&vm.version).map(|parsed| (vm, parsed))
                        })
                        .collect();
                    versions.sort_by(|a, b| b.1.cmp(&a.1));
                    if let Some((vm, _)) = versions.iter().find(|(_, parsed)| !parsed.is_prerelease()) {
                        return Some(*vm);
                    }
                    if let Some((vm, _)) = versions.first() {
                        return Some(*vm);
                    }
                }
                None
            }
            PackageTarget::Range(range) => {
                let vuln_ranges = self
                    .options
                    .vulnerability_constraints
                    .get(install_name)
                    .or_else(|| self.options.vulnerability_constraints.get(pkg_name));
                let is_safe = |ver: &Version| -> bool {
                    if let Some(ranges) = vuln_ranges {
                        !ranges.iter().any(|r| r.satisfies(ver))
                    } else {
                        true
                    }
                };

                if self.options.prefer_dedupe {
                    let mut scope_buf = String::new();
                    if let Some(loc) = DependencyGraph::find_in_scope_hierarchy(
                        &self.graph.nodes,
                        parent_location,
                        install_name,
                        &mut scope_buf,
                    ) {
                        if let Some(existing_node) = self.graph.nodes.get(loc) {
                            if existing_node.name == pkg_name {
                                if let Some(parsed) = cached_parse_version(&existing_node.version) {
                                    if range.satisfies(&parsed)
                                        && is_safe(&parsed)
                                        && advisories.iter().all(|target| {
                                            crate::hoisting::version_satisfies_target(
                                                &existing_node.version,
                                                target,
                                            )
                                        })
                                    {
                                        if let Some(v_meta) = meta.versions.get(&existing_node.version) {
                                            if v_meta.deprecated.is_none() {
                                                return Some(v_meta);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let mut best_placed_undeprecated: Option<(&'b PackageVersionMetadata, Version)> =
                        None;
                    let mut best_placed: Option<(&'b PackageVersionMetadata, Version)> = None;

                    let mut consider_node = |node: &Node| {
                        if node.name == pkg_name {
                            if let Some(parsed) = cached_parse_version(&node.version) {
                                if range.satisfies(&parsed)
                                    && is_safe(&parsed)
                                    && advisories.iter().all(|target| {
                                        crate::hoisting::version_satisfies_target(
                                            &node.version,
                                            target,
                                        )
                                    })
                                {
                                    if let Some(v_meta) = meta.versions.get(&node.version) {
                                        if v_meta.deprecated.is_none() {
                                            match &best_placed_undeprecated {
                                                Some((_, best_v)) => {
                                                    if &parsed > best_v {
                                                        best_placed_undeprecated =
                                                            Some((v_meta, parsed.clone()));
                                                    }
                                                }
                                                None => {
                                                    best_placed_undeprecated =
                                                        Some((v_meta, parsed.clone()));
                                                }
                                            }
                                        }
                                        match &best_placed {
                                            Some((_, best_v)) => {
                                                if &parsed > best_v {
                                                    best_placed = Some((v_meta, parsed));
                                                }
                                            }
                                            None => {
                                                best_placed = Some((v_meta, parsed));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    };

                    if !self.graph.nodes_by_name.is_empty() {
                        if let Some(locs) = self.graph.nodes_by_name.get(pkg_name) {
                            for loc in locs {
                                if let Some(node) = self.graph.nodes.get(loc) {
                                    consider_node(node);
                                }
                            }
                        }
                    } else {
                        for node in self.graph.nodes.values() {
                            consider_node(node);
                        }
                    }

                    if let Some((v_meta, _)) = best_placed_undeprecated {
                        return Some(v_meta);
                    } else if let Some((v_meta, _)) = best_placed {
                        return Some(v_meta);
                    }
                }

                // npm resolves registry ranges through the `latest` dist-tag
                // when that tagged version satisfies the requested range. This
                // matters when a registry intentionally keeps a newer version
                // outside the default channel or leaves `latest` on an older
                // compatible release.
                if let Some(latest_version) = meta.dist_tags.get("latest") {
                    if let Some(latest) = meta.versions.get(latest_version) {
                        if let Some(v) = cached_parse_version(&latest.version) {
                            if range.satisfies(&v)
                                && is_safe(&v)
                                && latest.deprecated.is_none()
                                && advisories.iter().all(|target| {
                                    crate::hoisting::version_satisfies_target(
                                        &latest.version,
                                        target,
                                    )
                                })
                            {
                                return Some(latest);
                            }
                        }
                    }
                }

                let mut best_safe_undeprecated: Option<(&'b PackageVersionMetadata, Version)> =
                    None;
                let mut best_safe: Option<(&'b PackageVersionMetadata, Version)> = None;
                let mut best_any: Option<(&'b PackageVersionMetadata, Version)> = None;

                for (ver_str, v_meta) in &meta.versions {
                    if let Some(parsed) = cached_parse_version(ver_str) {
                        if range.satisfies(&parsed)
                            && advisories.iter().all(|target| {
                                crate::hoisting::version_satisfies_target(ver_str, target)
                            })
                        {
                            let safe = is_safe(&parsed);
                            if safe {
                                if v_meta.deprecated.is_none() {
                                    match &best_safe_undeprecated {
                                        Some((_, best_v)) => {
                                            if &parsed > best_v {
                                                best_safe_undeprecated =
                                                    Some((v_meta, parsed.clone()));
                                            }
                                        }
                                        None => {
                                            best_safe_undeprecated = Some((v_meta, parsed.clone()));
                                        }
                                    }
                                }
                                match &best_safe {
                                    Some((_, best_v)) => {
                                        if &parsed > best_v {
                                            best_safe = Some((v_meta, parsed.clone()));
                                        }
                                    }
                                    None => {
                                        best_safe = Some((v_meta, parsed.clone()));
                                    }
                                }
                            }
                            match &best_any {
                                Some((_, best_v)) => {
                                    if &parsed > best_v {
                                        best_any = Some((v_meta, parsed));
                                    }
                                }
                                None => {
                                    best_any = Some((v_meta, parsed));
                                }
                            }
                        }
                    }
                }

                if let Some((v_meta, _)) = best_safe_undeprecated {
                    Some(v_meta)
                } else if let Some((v_meta, _)) = best_safe {
                    Some(v_meta)
                } else {
                    best_any.map(|(v_meta, _)| v_meta)
                }
            }
            PackageTarget::Alias { name: ref aliased_name, ref target } => {
                self.select_version(parent_location, install_name, aliased_name, meta, target, advisories)
            }
            PackageTarget::Url(u) => {
                let u_str = u.as_str();
                meta.versions
                    .values()
                    .find(|v| v.dist_tarball.as_deref() == Some(u_str))
                    .or_else(|| {
                        if meta.versions.len() == 1 {
                            meta.versions.values().next()
                        } else {
                            None
                        }
                    })
            }
            PackageTarget::File(p) => meta
                .versions
                .values()
                .find(|v| {
                    v.dist_tarball.as_deref().is_some_and(|resolved| {
                        crate::hoisting::file_target_matches_resolved(p, resolved)
                    })
                })
                .or_else(|| {
                    if meta.versions.len() == 1 {
                        meta.versions.values().next()
                    } else {
                        None
                    }
                }),
            PackageTarget::Git {
                url, committish, ..
            } => meta
                .versions
                .values()
                .find(|v| {
                    if let Some(ref dt) = v.dist_tarball {
                        crate::hoisting::git_target_matches_resolved(url, committish.as_deref(), dt)
                    } else {
                        false
                    }
                })
                .or_else(|| {
                    if meta.versions.len() == 1 {
                        meta.versions.values().next()
                    } else {
                        None
                    }
                }),
            PackageTarget::Workspace(ws_spec) => {
                let s = ws_spec.trim();
                if s == "*" || s == "^" || s == "~" || s.is_empty() {
                    select_max_semver_version(meta)
                } else if let Ok(range) = rnpm_core::semver::Range::parse(s) {
                    let mut best: Option<(&'b PackageVersionMetadata, Version)> = None;
                    for (ver_str, v_meta) in &meta.versions {
                        if let Some(parsed) = cached_parse_version(ver_str) {
                            if range.satisfies(&parsed) {
                                match &best {
                                    Some((_, best_v)) => {
                                        if &parsed > best_v {
                                            best = Some((v_meta, parsed));
                                        }
                                    }
                                    None => {
                                        best = Some((v_meta, parsed));
                                    }
                                }
                            }
                        }
                    }
                    best.map(|(v_meta, _)| v_meta)
                } else {
                    select_max_semver_version(meta)
                }
            }
        }
    }
}

/// Returns the highest version in `meta.versions` by SemVer comparison,
/// falling back to the last entry if no versions parse as valid SemVer.
fn select_max_semver_version<'b>(meta: &'b PackageMetadata) -> Option<&'b PackageVersionMetadata> {
    let mut best: Option<(&'b PackageVersionMetadata, Version)> = None;
    for (ver_str, v_meta) in &meta.versions {
        if let Some(parsed) = cached_parse_version(ver_str) {
            match &best {
                Some((_, best_v)) => {
                    if &parsed > best_v {
                        best = Some((v_meta, parsed));
                    }
                }
                None => {
                    best = Some((v_meta, parsed));
                }
            }
        }
    }
    best.map(|(v_meta, _)| v_meta)
        .or_else(|| meta.versions.values().last())
}

/// Attempts fast-path dependency graph construction from a lockfile v3 without tree traversal.
/// Returns `Some(DependencyGraph)` if the lockfile matches the manifest and all dependencies
/// and constraints are verified, or `None` if any lockfile drift is detected.
pub fn resolve_fast_path(
    manifest: &Manifest,
    lockfile: &rnpm_lockfile::LockfileV3,
    options: &ResolverOptions,
) -> Option<DependencyGraph> {
    if !lockfile.matches_manifest(manifest, options.dev) {
        return None;
    }

    if manifest.extra.contains_key("overrides")
        && lockfile
            .root_package()
            .and_then(|r| r.extra.get("overrides"))
            != manifest.extra.get("overrides")
    {
        return None;
    }

    let overrides = Overrides::from_json_value(
        manifest.extra.get("overrides"),
        Overrides::reference_specs(manifest),
    );

    let mut graph = DependencyGraph::from_lockfile_v3(lockfile);
    graph.legacy_peer_deps = options.legacy_peer_deps;

    // Apply platform filters for optional dependencies
    for node in graph.nodes.values_mut() {
        if node.flags.optional || node.flags.dev_optional {
            let compatible = options.platform.matches_with_libc(
                node.os.as_deref(),
                node.cpu.as_deref(),
                node.libc.as_deref(),
            );
            if !compatible {
                node.flags.skipped = true;
                graph.skipped.insert(node.name.clone());
                graph.skipped.insert(node.install_name.clone());
            }
        } else if !node.location.is_empty() {
            let compatible = options.platform.matches_with_libc(
                node.os.as_deref(),
                node.cpu.as_deref(),
                node.libc.as_deref(),
            );
            if !compatible {
                return None;
            }
        }
    }

    // Propagate skipped status from incompatible optional packages to exclusive descendants
    graph.normalize_dependency_flags();

    // Comprehensive lockfile drift check: verify that all non-skipped dependencies
    // exist in the lockfile and satisfy their version/override constraints.
    if !validate_fast_path_graph(&graph, options, &overrides) {
        debug!("Fast-path: lockfile drift detected; falling back to full resolution");
        return None;
    }

    Some(graph)
}

fn validate_fast_path_graph(
    graph: &DependencyGraph,
    options: &ResolverOptions,
    overrides: &Overrides,
) -> bool {
    let mut buf = String::with_capacity(128);

    for (loc, node) in &graph.nodes {
        if node.flags.skipped {
            continue;
        }

        // Direct prod dependencies
        for (dep_name, dep_spec) in &node.dependencies {
            if !validate_fast_path_dep(
                graph,
                loc,
                dep_name,
                dep_spec,
                DependencyType::Prod,
                options,
                overrides,
                &mut buf,
            ) {
                return false;
            }
        }

        // devDependencies (only checked on root node if options.dev)
        if loc.is_empty() && options.dev {
            for (dep_name, dep_spec) in &node.dev_dependencies {
                if !validate_fast_path_dep(
                    graph,
                    loc,
                    dep_name,
                    dep_spec,
                    DependencyType::Dev,
                    options,
                    overrides,
                    &mut buf,
                ) {
                    return false;
                }
            }
        }

        // optionalDependencies (if target exists and is not skipped, must satisfy constraint)
        for (dep_name, dep_spec) in &node.optional_dependencies {
            if !validate_fast_path_dep(
                graph,
                loc,
                dep_name,
                dep_spec,
                DependencyType::Optional,
                options,
                overrides,
                &mut buf,
            ) {
                return false;
            }
        }

        // peerDependencies (if !options.legacy_peer_deps)
        if !options.legacy_peer_deps {
            for (dep_name, dep_spec) in &node.peer_dependencies {
                if node.dependencies.contains_key(dep_name)
                    || node.optional_dependencies.contains_key(dep_name)
                {
                    continue;
                }
                if !validate_fast_path_dep(
                    graph,
                    loc,
                    dep_name,
                    dep_spec,
                    DependencyType::Peer,
                    options,
                    overrides,
                    &mut buf,
                ) {
                    return false;
                }
            }
        }
    }

    true
}

fn validate_fast_path_dep(
    graph: &DependencyGraph,
    from_loc: &str,
    dep_name: &str,
    raw_spec: &str,
    dep_type: DependencyType,
    options: &ResolverOptions,
    overrides: &Overrides,
    buf: &mut String,
) -> bool {
    let target_loc =
        DependencyGraph::find_in_scope_hierarchy(&graph.nodes, from_loc, dep_name, buf);

    let Some(target) = target_loc else {
        // Missing target
        if dep_type == DependencyType::Optional {
            return true;
        }
        if dep_type == DependencyType::Peer {
            return !options.is_strict_peers();
        }
        // Required dependency missing in lockfile -> drift!
        return false;
    };

    let Some(target_node) = graph.nodes.get(target) else {
        return false;
    };

    if target_node.flags.skipped {
        return dep_type == DependencyType::Optional;
    }

    // Determine effective spec taking overrides into account
    let effective_spec = if overrides.rules.is_empty() {
        raw_spec
    } else {
        let mut ancestors = Vec::new();
        if !from_loc.is_empty() {
            for scope in crate::hoisting::iter_ancestor_scopes(from_loc) {
                if let Some(n) = graph.nodes.get(scope) {
                    ancestors.push(n.name.as_str());
                }
            }
            ancestors.reverse();
        }
        if let Ok(Some(overridden)) = overrides.resolve_override(dep_name, raw_spec, &ancestors) {
            if let Ok(parsed_override) = DependencySpec::parse(dep_name, &overridden) {
                return target_node.name == parsed_override.package_name
                    && crate::hoisting::node_satisfies_target(
                        target_node,
                        &parsed_override.target,
                    );
            }
            return false;
        }
        raw_spec
    };

    let Ok(parsed_spec) = DependencySpec::parse(dep_name, effective_spec) else {
        return false;
    };

    if target_node.name != parsed_spec.package_name {
        return false;
    }

    if !crate::hoisting::node_satisfies_target(target_node, &parsed_spec.target) {
        if dep_type == DependencyType::Peer {
            return !options.is_strict_peers();
        }
        return false;
    }

    true
}

/// Convenience function to resolve a dependency graph from a manifest and package provider.
pub fn resolve_dependency_graph<P: PackageMetadataProvider>(
    manifest: &Manifest,
    provider: &P,
    options: &ResolverOptions,
) -> Result<DependencyGraph, SolverError> {
    resolve_dependency_graph_with_lockfile(manifest, provider, options, None)
}

/// Resolves a dependency graph with optional lockfile fast-path bypass.
pub fn resolve_dependency_graph_with_lockfile<P: PackageMetadataProvider>(
    manifest: &Manifest,
    provider: &P,
    options: &ResolverOptions,
    lockfile: Option<&rnpm_lockfile::LockfileV3>,
) -> Result<DependencyGraph, SolverError> {
    let mut opts = options.clone();
    if let Some(lf) = lockfile {
        opts.lockfile = Some(std::sync::Arc::new(lf.clone()));
    }
    let overrides = Overrides::from_json_value(
        manifest.extra.get("overrides"),
        Overrides::reference_specs(manifest),
    );
    let solver = Solver::new(provider, opts, overrides);
    solver.resolve(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arborist_compare_collation() {
        assert_eq!(arborist_compare("a", "b"), std::cmp::Ordering::Less);
        assert_eq!(arborist_compare("b", "a"), std::cmp::Ordering::Greater);
        assert_eq!(arborist_compare("a", "a"), std::cmp::Ordering::Equal);

        // Lowercase comes before uppercase in en locale collation tie-break
        assert_eq!(arborist_compare("a", "A"), std::cmp::Ordering::Less);
        assert_eq!(arborist_compare("A", "b"), std::cmp::Ordering::Less);

        // Scoped package vs unscoped package
        assert_eq!(
            arborist_compare("@eslint/js", "axios"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            arborist_compare("@eslint-community/regexpp", "@eslint/js"),
            std::cmp::Ordering::Less
        );
    }
}
