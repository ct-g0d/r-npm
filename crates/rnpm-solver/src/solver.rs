use rnpm_core::manifest::Manifest;
use rnpm_core::semver::Version;
use rnpm_core::spec::PackageTarget;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::aliases::DependencySpec;
use crate::error::SolverError;
use crate::fast_util::{
    fast_map_with_capacity, fast_set_with_capacity, AncestorArena, FastMap, FastSet,
    StringInterner, SymId, NO_ANCESTOR,
};
use crate::graph::{DependencyEdge, DependencyGraph, DependencyType, Node, NodeFlags};
use crate::hoisting::{
    cached_parse_package_target, cached_target_rc, cached_version_rc,
    determine_placement_with_peers, parsed_version_satisfies_target, PlacementDecision,
};
use crate::overrides::Overrides;
use crate::platform::Platform;
use crate::types::{PackageMetadata, PackageMetadataProvider, PackageVersionMetadata};

const NO_SYM: SymId = SymId(u32::MAX);
const EMPTY_SYM: SymId = SymId(0);

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

/// Compact internal task queued for resolution (`Copy`, zero heap allocations).
#[derive(Debug, Clone, Copy)]
struct ResolveTask {
    parent_location: SymId,
    parent_package_name: SymId,
    install_name: SymId,
    raw_spec: SymId,
    dep_type: DependencyType,
    parent_depth: u16,
    ancestor_head: u32,
    /// A second edge whose range should guide version choice (`NO_SYM` if none).
    advisory: SymId,
    is_mine: bool,
    is_root: bool,
}

/// Tiered queue that eliminates O(Q) cross-depth element shifting and maintains
/// strict Arborist collation order within each depth level.
#[derive(Debug, Clone, Default)]
struct TaskQueue {
    levels: Vec<VecDeque<ResolveTask>>,
    level_unsorted_back: Vec<bool>,
    len: usize,
    pending_root: FastMap<SymId, usize>,
}

impl TaskQueue {
    fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push_task(&mut self, task: ResolveTask, interner: &StringInterner) {
        if task.parent_location == EMPTY_SYM {
            *self.pending_root.entry(task.install_name).or_default() += 1;
        }
        let depth = task.parent_depth as usize;
        if depth >= self.levels.len() {
            self.levels.resize_with(depth + 1, VecDeque::new);
            self.level_unsorted_back.resize(depth + 1, false);
        }
        let level = &mut self.levels[depth];
        if !self.level_unsorted_back[depth] {
            if let Some(back) = level.back() {
                let cmp_parent = if back.parent_location == task.parent_location {
                    std::cmp::Ordering::Equal
                } else {
                    arborist_compare(
                        interner.get(back.parent_location),
                        interner.get(task.parent_location),
                    )
                };
                let cmp = cmp_parent.then_with(|| {
                    if back.install_name == task.install_name {
                        std::cmp::Ordering::Equal
                    } else {
                        arborist_compare(
                            interner.get(back.install_name),
                            interner.get(task.install_name),
                        )
                    }
                });
                if cmp == std::cmp::Ordering::Less {
                    level.push_back(task);
                    self.len += 1;
                    return;
                }
            } else {
                level.push_back(task);
                self.len += 1;
                return;
            }
        }
        let p_loc = interner.get(task.parent_location);
        let i_name = interner.get(task.install_name);
        let pos = level
            .binary_search_by(|queued| {
                let cmp_parent = if queued.parent_location == task.parent_location {
                    std::cmp::Ordering::Equal
                } else {
                    arborist_compare(interner.get(queued.parent_location), p_loc)
                };
                cmp_parent.then_with(|| {
                    if queued.install_name == task.install_name {
                        std::cmp::Ordering::Equal
                    } else {
                        arborist_compare(interner.get(queued.install_name), i_name)
                    }
                })
            })
            .unwrap_or_else(|e| e);
        level.insert(pos, task);
        self.len += 1;
    }

    fn push_sorted_sibling_batch(&mut self, tasks: &[ResolveTask], interner: &StringInterner) {
        if tasks.is_empty() {
            return;
        }
        if tasks.len() == 1 {
            self.push_task(tasks[0], interner);
            return;
        }
        let first = tasks[0];
        let depth = first.parent_depth as usize;
        if depth >= self.levels.len() {
            self.levels.resize_with(depth + 1, VecDeque::new);
            self.level_unsorted_back.resize(depth + 1, false);
        }
        if first.parent_location == EMPTY_SYM {
            for t in tasks {
                *self.pending_root.entry(t.install_name).or_default() += 1;
            }
        }
        let level = &mut self.levels[depth];
        let can_append_all = !self.level_unsorted_back[depth]
            && level.back().is_none_or(|back| {
                back.parent_location != first.parent_location
                    && arborist_compare(
                        interner.get(back.parent_location),
                        interner.get(first.parent_location),
                    ) == std::cmp::Ordering::Less
            });
        if can_append_all {
            level.extend(tasks.iter().copied());
            self.len += tasks.len();
            return;
        }
        // Revert pending_root increment if falling back to per-task insertion, or insert via push_task
        if first.parent_location == EMPTY_SYM {
            for t in tasks {
                if let Some(c) = self.pending_root.get_mut(&t.install_name) {
                    if *c > 1 {
                        *c -= 1;
                    } else {
                        self.pending_root.remove(&t.install_name);
                    }
                }
            }
        }
        for &t in tasks {
            self.push_task(t, interner);
        }
    }

    fn push_back(&mut self, task: ResolveTask) {
        if task.parent_location == EMPTY_SYM {
            *self.pending_root.entry(task.install_name).or_default() += 1;
        }
        let depth = task.parent_depth as usize;
        if depth >= self.levels.len() {
            self.levels.resize_with(depth + 1, VecDeque::new);
            self.level_unsorted_back.resize(depth + 1, false);
        }
        self.levels[depth].push_back(task);
        self.level_unsorted_back[depth] = true;
        self.len += 1;
    }

    #[inline]
    fn has_pending_root(&self, name: SymId) -> bool {
        self.pending_root.get(&name).copied().unwrap_or(0) > 0
    }

    fn pop_front(&mut self) -> Option<ResolveTask> {
        for (depth, level) in self.levels.iter_mut().enumerate() {
            if let Some(task) = level.pop_front() {
                if level.is_empty() {
                    self.level_unsorted_back[depth] = false;
                }
                self.len -= 1;
                if task.parent_location == EMPTY_SYM {
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
        for (depth, level) in self.levels.iter_mut().enumerate() {
            level.retain(|task| {
                let keep = f(task);
                if !keep {
                    self.len = self.len.saturating_sub(1);
                    if task.parent_location == EMPTY_SYM {
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
            if level.is_empty() {
                self.level_unsorted_back[depth] = false;
            }
        }
    }

    fn drain_all(&mut self) -> Vec<ResolveTask> {
        let mut all = Vec::with_capacity(self.len);
        for (depth, level) in self.levels.iter_mut().enumerate() {
            all.extend(level.drain(..));
            self.level_unsorted_back[depth] = false;
        }
        self.len = 0;
        self.pending_root.clear();
        all
    }
}

/// Pre-parsed and descending-sorted view of a package's registry metadata so repeated
/// version selection avoids cloning `PackageMetadata`, re-parsing SemVer strings, or
/// scanning full version lists on every edge.
struct CachedPackageMeta {
    dist_tags: BTreeMap<String, String>,
    /// Version metadata kept in original `BTreeMap` ascending key order.
    entries: Vec<PackageVersionMetadata>,
    /// Pre-parsed SemVer version per entry in `entries`.
    parsed_versions: Vec<Option<Version>>,
    /// Exact version key -> index in `entries`.
    by_key: FastMap<String, usize>,
    /// `(parsed_semver, entry_idx)` stably sorted DESCENDING by SemVer.
    descending: Vec<(Version, usize)>,
    /// Rare fallback when `v_meta.version != key` so prerelease/advisory checks still match `v_meta.version`.
    val_versions: FastMap<usize, Version>,
}

impl CachedPackageMeta {
    fn from_meta(meta: PackageMetadata) -> Self {
        let len = meta.versions.len();
        let mut entries = Vec::with_capacity(len);
        let mut parsed_versions = Vec::with_capacity(len);
        let mut by_key = fast_map_with_capacity(len);
        let mut descending = Vec::with_capacity(len);
        let mut val_versions = FastMap::default();
        for (idx, (ver_str, v_meta)) in meta.versions.into_iter().enumerate() {
            let key_parsed = Version::parse(&ver_str).ok();
            let entry_parsed = if v_meta.version != ver_str {
                let pv = Version::parse(&v_meta.version).ok();
                if let Some(ref p) = pv {
                    val_versions.insert(idx, p.clone());
                }
                pv
            } else {
                key_parsed.clone()
            };
            if let Some(parsed) = key_parsed {
                descending.push((parsed, idx));
            }
            parsed_versions.push(entry_parsed);
            by_key.insert(ver_str, idx);
            entries.push(v_meta);
        }
        // Stable sort preserves ascending BTreeMap tie-break order on equal SemVer values.
        descending.sort_by(|a, b| b.0.cmp(&a.0));
        Self {
            dist_tags: meta.dist_tags,
            entries,
            parsed_versions,
            by_key,
            descending,
            val_versions,
        }
    }

    #[inline]
    fn parsed_by_key(&self, key: &str) -> Option<&Version> {
        self.by_key
            .get(key)
            .and_then(|&idx| self.parsed_versions[idx].as_ref())
    }

    #[inline]
    fn entry_version<'b>(&'b self, idx: usize, key_parsed: &'b Version) -> &'b Version {
        if self.val_versions.is_empty() {
            key_parsed
        } else {
            self.val_versions.get(&idx).unwrap_or(key_parsed)
        }
    }

    #[inline]
    fn get_by_key(&self, key: &str) -> Option<&PackageVersionMetadata> {
        self.by_key.get(key).map(|&idx| &self.entries[idx])
    }

    #[inline]
    fn max_semver_version(&self) -> Option<&PackageVersionMetadata> {
        self.descending
            .first()
            .map(|(_, idx)| &self.entries[*idx])
            .or_else(|| self.entries.last())
    }
}

struct CachedPkgEntry {
    meta: Arc<CachedPackageMeta>,
    allowed_root: bool,
    allowed_transitive: bool,
}

/// Main solver coordinator for building the dependency graph.
pub struct Solver<'a, P: PackageMetadataProvider> {
    provider: &'a P,
    options: ResolverOptions,
    overrides: Overrides,
    graph: DependencyGraph,
    strings: StringInterner,
    ancestor_arena: AncestorArena,
    queue: TaskQueue,
    pkg_cache: FastMap<String, CachedPkgEntry>,
    /// Link targets normally wait for resolveLinks, but an invalidated edge
    /// can put a workspace into the node queue before that pass.
    deferred_workspaces: BTreeMap<String, Vec<ResolveTask>>,
    /// Reference-counted set of `install_name`s currently waiting in `deferred_workspaces`.
    deferred_ws_install_names: FastMap<SymId, usize>,
    /// Missing optional peers become problem edges when a provider arrives.
    deferred_optional_peers: FastMap<SymId, Vec<ResolveTask>>,
    /// Root/workspace edges already resolved early for a peer set (`(parent_location, install_name)`).
    preplaced: FastSet<(SymId, SymId)>,
    /// Per-`raw_spec` `SymId` parsed target cache to avoid TLS/RefCell/Range clones on repeated specs.
    target_cache: Vec<Option<Arc<PackageTarget>>>,
    /// Tracks whether any pass mutated `self.graph` without updating all 7 secondary maps.
    indices_dirty: bool,
}

/// Compares two strings using Arborist-compatible collation.
/// Arborist sorts depsQueue by depth then `a.path.localeCompare(b.path, 'en') || a.name.localeCompare(b.name, 'en')`.
#[inline]
pub fn arborist_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let min_len = a_bytes.len().min(b_bytes.len());
    let mut first_case_diff: Option<usize> = None;
    for i in 0..min_len {
        let ba = a_bytes[i];
        let bb = b_bytes[i];
        if ba == bb {
            continue;
        }
        let ca = ba.to_ascii_lowercase();
        let cb = bb.to_ascii_lowercase();
        if ca != cb {
            return ca.cmp(&cb);
        }
        if first_case_diff.is_none() {
            first_case_diff = Some(i);
        }
    }
    match a_bytes.len().cmp(&b_bytes.len()) {
        std::cmp::Ordering::Equal => match first_case_diff {
            None => std::cmp::Ordering::Equal,
            Some(i) => {
                // Case tie-breaker: in JavaScript 'en' localeCompare, lowercase comes before uppercase ('a' < 'A')
                let ca = a_bytes[i];
                let cb = b_bytes[i];
                let is_ca_lower = ca.is_ascii_lowercase();
                let is_cb_lower = cb.is_ascii_lowercase();
                if is_ca_lower != is_cb_lower {
                    if is_ca_lower {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    }
                } else {
                    ca.cmp(&cb)
                }
            }
        },
        ord => ord,
    }
}

impl<'a, P: PackageMetadataProvider> Solver<'a, P> {
    pub fn new(provider: &'a P, options: ResolverOptions, mut overrides: Overrides) -> Self {
        overrides.refresh_compiled();
        let graph = DependencyGraph {
            legacy_peer_deps: options.legacy_peer_deps,
            ..DependencyGraph::new()
        };
        let mut strings = StringInterner::with_capacity(512);
        let empty = strings.intern("");
        debug_assert_eq!(empty, EMPTY_SYM);
        Self {
            provider,
            options,
            overrides,
            graph,
            strings,
            ancestor_arena: AncestorArena::with_capacity(512),
            queue: TaskQueue::new(),
            pkg_cache: fast_map_with_capacity(128),
            deferred_workspaces: BTreeMap::new(),
            deferred_ws_install_names: fast_map_with_capacity(16),
            deferred_optional_peers: fast_map_with_capacity(16),
            preplaced: fast_set_with_capacity(16),
            target_cache: Vec::new(),
            indices_dirty: false,
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
        self.indices_dirty = false;
        self
    }

    pub fn graph(&self) -> &DependencyGraph {
        &self.graph
    }

    pub fn graph_mut(&mut self) -> &mut DependencyGraph {
        self.indices_dirty = true;
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
        let parent_depth = if parent_location.is_empty() {
            0
        } else {
            parent_location.matches("node_modules").count() as u16
        };
        let is_mine = !parent_location.contains("node_modules");
        let is_root = is_mine;
        let ancestor_head = self
            .ancestor_arena
            .push_slice(&ancestors, &mut self.strings);
        let parent_location_sym = self.strings.intern_owned(parent_location);
        let parent_package_name_sym = self.strings.intern_owned(parent_package_name);
        let install_name_sym = self.strings.intern_owned(install_name);
        let raw_spec_sym = self.strings.intern_owned(raw_spec);
        self.push_task(ResolveTask {
            parent_location: parent_location_sym,
            parent_package_name: parent_package_name_sym,
            install_name: install_name_sym,
            raw_spec: raw_spec_sym,
            dep_type,
            parent_depth,
            ancestor_head,
            advisory: NO_SYM,
            is_mine,
            is_root,
        });
    }

    fn activate_deferred_optional_peers(&mut self, provider_location: &str) {
        if self.deferred_optional_peers.is_empty() {
            return;
        }
        let Some(provider_node) = self.graph.nodes.get(provider_location) else {
            return;
        };
        let name_sym = self.strings.intern(&provider_node.install_name);
        let Some(tasks) = self.deferred_optional_peers.remove(&name_sym) else {
            return;
        };
        let name = self.strings.get(name_sym);
        let mut requeue = Vec::new();
        for task in tasks {
            let visible = crate::hoisting::find_visible_peer_node(
                &self.graph,
                self.strings.get(task.parent_location),
                name,
                name,
            );
            if visible.is_some_and(|node| node.location == provider_location) {
                self.queue.push_task(task, &self.strings);
            } else {
                requeue.push(task);
            }
        }
        if !requeue.is_empty() {
            self.deferred_optional_peers.insert(name_sym, requeue);
        }
    }

    #[inline]
    fn push_task(&mut self, task: ResolveTask) {
        self.queue.push_task(task, &self.strings);
    }

    /// Hold workspace targets for Arborist's resolveLinks pass. A newly
    /// placed provider may activate one earlier by invalidating its edge.
    pub fn defer_workspace_tasks(&mut self) {
        let mut root_tasks = Vec::new();
        for task in self.queue.drain_all() {
            let parent_loc = self.strings.get(task.parent_location);
            if !parent_loc.is_empty() && !parent_loc.contains("node_modules") {
                *self
                    .deferred_ws_install_names
                    .entry(task.install_name)
                    .or_default() += 1;
                if let Some(vec) = self.deferred_workspaces.get_mut(parent_loc) {
                    vec.push(task);
                } else {
                    self.deferred_workspaces
                        .insert(parent_loc.to_string(), vec![task]);
                }
            } else {
                root_tasks.push(task);
            }
        }
        for task in root_tasks {
            self.queue.push_task(task, &self.strings);
        }
    }

    fn activate_invalidated_workspaces(&mut self, provider_location: &str) {
        if self.deferred_workspaces.is_empty() {
            return;
        }
        let Some(provider) = self.graph.nodes.get(provider_location) else {
            return;
        };
        let provider_sym = self.strings.intern(&provider.install_name);
        if self
            .deferred_ws_install_names
            .get(&provider_sym)
            .copied()
            .unwrap_or(0)
            == 0
        {
            return;
        }
        let has_overrides = !self.overrides.rules.is_empty();
        let mut scope_buffer = String::new();
        let mut ancestor_buf: Vec<String> = Vec::new();
        let locations: Vec<_> = self
            .deferred_workspaces
            .iter()
            .filter(|(location, tasks)| {
                tasks
                    .iter()
                    .filter(|task| task.install_name == provider_sym)
                    .any(|task| {
                        let visible = DependencyGraph::find_in_scope_hierarchy(
                            &self.graph.nodes,
                            location,
                            &provider.install_name,
                            &mut scope_buffer,
                        );
                        if visible != Some(provider_location) {
                            return false;
                        }
                        let raw_spec = self.strings.get(task.raw_spec);
                        let overridden = if !has_overrides {
                            None
                        } else {
                            let caller = self
                                .graph
                                .nodes
                                .get(*location)
                                .map(|n| n.all_dependency_specs())
                                .unwrap_or_default();
                            ancestor_buf = self
                                .ancestor_arena
                                .to_vec(task.ancestor_head, &self.strings);
                            self.overrides
                                .resolve_override_precompiled_with_caller(
                                    &provider.install_name,
                                    raw_spec,
                                    &ancestor_buf,
                                    Some(&caller),
                                )
                                .ok()
                                .flatten()
                        };
                        DependencySpec::parse(
                            &provider.install_name,
                            overridden.as_deref().unwrap_or(raw_spec),
                        )
                        .is_ok_and(|spec| {
                            provider.name != spec.package_name
                                || !crate::hoisting::node_satisfies_target(provider, &spec.target)
                        })
                    })
            })
            .map(|(location, _)| location.clone())
            .collect();
        for location in locations {
            if let Some(tasks) = self.deferred_workspaces.remove(&location) {
                for task in tasks {
                    if let Some(cnt) = self.deferred_ws_install_names.get_mut(&task.install_name) {
                        if *cnt > 1 {
                            *cnt -= 1;
                        } else {
                            self.deferred_ws_install_names.remove(&task.install_name);
                        }
                    }
                    self.queue.push_task(task, &self.strings);
                }
            }
        }
    }

    fn get_cached_meta(
        &mut self,
        pkg_name: &str,
        raw_spec: &str,
        target: &PackageTarget,
        is_root: bool,
    ) -> Result<Option<Arc<CachedPackageMeta>>, SolverError> {
        let cacheable = Self::is_cacheable_target(target);
        if cacheable {
            if let Some(entry) = self.pkg_cache.get(pkg_name) {
                let allowed = if is_root {
                    entry.allowed_root
                } else {
                    entry.allowed_transitive
                };
                if allowed {
                    return Ok(Some(Arc::clone(&entry.meta)));
                }
            }
        }
        let Some(raw) = self
            .provider
            .get_package_for_edge(pkg_name, raw_spec, is_root)?
        else {
            return Ok(None);
        };
        let arc_meta = Arc::new(CachedPackageMeta::from_meta(raw));
        if cacheable {
            if let Some(entry) = self.pkg_cache.get_mut(pkg_name) {
                if is_root {
                    entry.allowed_root = true;
                } else {
                    entry.allowed_transitive = true;
                }
                if arc_meta.entries.len() >= entry.meta.entries.len()
                    || arc_meta.dist_tags != entry.meta.dist_tags
                {
                    entry.meta = Arc::clone(&arc_meta);
                }
            } else {
                self.pkg_cache.insert(
                    pkg_name.to_string(),
                    CachedPkgEntry {
                        meta: Arc::clone(&arc_meta),
                        allowed_root: is_root,
                        allowed_transitive: !is_root,
                    },
                );
            }
        }
        Ok(Some(arc_meta))
    }

    #[inline]
    fn is_cacheable_target(target: &PackageTarget) -> bool {
        match target {
            PackageTarget::Range(_) | PackageTarget::Version(_) => true,
            PackageTarget::Alias { target, .. } => Self::is_cacheable_target(target),
            _ => false,
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
        let mut siblings: Vec<ResolveTask> = Vec::with_capacity(16);
        loop {
            if self.queue.is_empty() {
                if self.deferred_workspaces.is_empty() {
                    break;
                }
                self.deferred_ws_install_names.clear();
                for tasks in std::mem::take(&mut self.deferred_workspaces).into_values() {
                    for task in tasks {
                        self.queue.push_task(task, &self.strings);
                    }
                }
            }
            let first = self.queue.pop_front().unwrap();
            let first_parent = first.parent_location;
            // Arborist queues nodes, then places all of a node's problem
            // edges before visiting another node. A newly hoisted child can
            // sort ahead of its parent, so freeze this batch before placing
            // any edges that might enqueue that child's dependencies.
            siblings.clear();
            siblings.push(first);
            while self
                .queue
                .front()
                .is_some_and(|queued| queued.parent_location == first_parent)
            {
                siblings.push(self.queue.pop_front().unwrap());
            }
            for &task in &siblings {
                self.process_task(task)?;
            }
        }
        Ok(())
    }

    /// Extracts the resolved dependency graph.
    pub fn into_graph(mut self) -> DependencyGraph {
        self.graph.normalize_dependency_flags();
        if self.indices_dirty {
            self.graph.rebuild_indices();
        }
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
        if self.provider.needs_closure_prefetch() {
            self.provider.prefetch_packages_for_edge(&root_edges);
            if self.options.lockfile.is_none() {
                self.prefetch_closure(&root_deps);
            }
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

        let root_name_sym = self.strings.intern_owned(root_name);
        let root_ancestor_head = self.ancestor_arena.push(NO_ANCESTOR, root_name_sym);
        let mut queued: FastSet<SymId> = fast_set_with_capacity(root_deps.len());
        let enqueue_root =
            |install_name: &str, this: &mut Solver<'a, P>, queued: &mut FastSet<SymId>| {
                let install_sym = this.strings.intern(install_name);
                if !queued.insert(install_sym) {
                    return;
                }
                if let Some((raw_spec, dep_type)) = root_deps.get(install_name) {
                    let spec_sym = this.strings.intern(raw_spec);
                    this.push_task(ResolveTask {
                        parent_location: EMPTY_SYM,
                        parent_package_name: root_name_sym,
                        install_name: install_sym,
                        raw_spec: spec_sym,
                        dep_type: *dep_type,
                        parent_depth: 0,
                        ancestor_head: root_ancestor_head,
                        advisory: NO_SYM,
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
        Ok(self.graph)
    }

    fn process_task(&mut self, task: ResolveTask) -> Result<(), SolverError> {
        if task.advisory == NO_SYM
            && !self.preplaced.is_empty()
            && self
                .preplaced
                .contains(&(task.parent_location, task.install_name))
        {
            return Ok(());
        }
        if self.options.legacy_peer_deps
            && (task.dep_type == DependencyType::Peer
                || task.dep_type == DependencyType::PeerOptional)
        {
            return Ok(());
        }

        // 1. Apply overrides without allocations if no rules exist
        struct TaskDepSpec {
            install_name: String,
            package_name: String,
            target: Arc<PackageTarget>,
            is_alias: bool,
        }

        let has_overrides = !self.overrides.rules.is_empty();
        let (effective_spec, dep_spec) = if !has_overrides {
            let raw_spec_str = self.strings.get(task.raw_spec);
            let trimmed_spec = raw_spec_str.trim();
            if !trimmed_spec.starts_with("npm:") {
                let sym_idx = task.raw_spec.0 as usize;
                let target_arc = if let Some(cached) = self
                    .target_cache
                    .get(sym_idx)
                    .and_then(|opt| opt.as_ref())
                {
                    Arc::clone(cached)
                } else {
                    let parsed = PackageTarget::parse(trimmed_spec)?;
                    let arc = Arc::new(parsed);
                    if sym_idx >= self.target_cache.len() {
                        self.target_cache.resize(sym_idx + 64, None);
                    }
                    self.target_cache[sym_idx] = Some(Arc::clone(&arc));
                    arc
                };
                let install_name_trimmed = self.strings.get(task.install_name).trim().to_string();
                let package_name = install_name_trimmed.clone();
                let eff = raw_spec_str.to_string();
                (
                    eff,
                    TaskDepSpec {
                        install_name: install_name_trimmed,
                        package_name,
                        target: target_arc,
                        is_alias: false,
                    },
                )
            } else {
                let eff = raw_spec_str.to_string();
                let parsed = DependencySpec::parse(self.strings.get(task.install_name), &eff)?;
                (
                    eff,
                    TaskDepSpec {
                        install_name: parsed.install_name,
                        package_name: parsed.package_name,
                        target: Arc::new(parsed.target),
                        is_alias: parsed.is_alias,
                    },
                )
            }
        } else {
            let parent_loc = self.strings.get(task.parent_location);
            let caller_specs = if parent_loc.is_empty() {
                None
            } else {
                self.graph
                    .nodes
                    .get(parent_loc)
                    .map(|node| node.all_dependency_specs())
            };
            let install_name = self.strings.get(task.install_name);
            let raw_spec = self.strings.get(task.raw_spec);
            let task_ancestors = self
                .ancestor_arena
                .to_vec(task.ancestor_head, &self.strings);
            let effective_spec = if let Some(overridden) = self
                .overrides
                .resolve_override_precompiled_with_caller(
                    install_name,
                    raw_spec,
                    &task_ancestors,
                    caller_specs.as_ref(),
                )? {
                debug!(
                    "Overriding dependency '{}': '{}' -> '{}'",
                    install_name, raw_spec, overridden
                );
                overridden
            } else if let Some(alias_str) = raw_spec.strip_prefix("npm:") {
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

                if let Some(overridden) = self.overrides.resolve_override_precompiled_with_caller(
                    real_pkg,
                    inner_spec,
                    &task_ancestors,
                    caller_specs.as_ref(),
                )? {
                    debug!(
                        "Overriding aliased package '{}' (install: '{}'): '{}' -> '{}'",
                        real_pkg, install_name, inner_spec, overridden
                    );
                    if overridden.starts_with("npm:") {
                        overridden
                    } else {
                        format!("npm:{}@{}", real_pkg, overridden)
                    }
                } else {
                    raw_spec.to_string()
                }
            } else {
                raw_spec.to_string()
            };
            let parsed = DependencySpec::parse(install_name, &effective_spec)?;
            (
                effective_spec,
                TaskDepSpec {
                    install_name: parsed.install_name,
                    package_name: parsed.package_name,
                    target: Arc::new(parsed.target),
                    is_alias: parsed.is_alias,
                },
            )
        };
        let pkg_sym = if dep_spec.is_alias {
            self.strings.intern(&dep_spec.package_name)
        } else {
            task.install_name
        };

        // 3. Check for cyclic peer dependencies and existing peer instances
        let is_peer =
            task.dep_type == DependencyType::Peer || task.dep_type == DependencyType::PeerOptional;
        let mut replace_transitive_root_peer = false;
        if is_peer
            && (self.queue.has_pending_root(task.install_name)
                || self.queue.has_pending_root(pkg_sym))
        {
            // A depth-first subtree can encounter a peer before the root's
            // direct dependency that is meant to satisfy it. Defer that
            // peer until the pending root task has been resolved so strict
            // diagnostics and alias satisfaction see the same visible node
            // npm would use.
            self.queue.push_back(task);
            return Ok(());
        }
        if is_peer {
            let alias_sym = (task.install_name != pkg_sym).then_some(task.install_name);
            if self
                .ancestor_arena
                .contains_any(task.ancestor_head, pkg_sym, alias_sym)
            {
                let cycle_path_str = self
                    .ancestor_arena
                    .find_cycle_path(task.ancestor_head, pkg_sym, alias_sym, &self.strings)
                    .map(|p| p.join(" -> "))
                    .unwrap_or_else(|| {
                        format!(
                            "{} -> {}",
                            self.strings.get(task.parent_package_name),
                            dep_spec.package_name
                        )
                    });
                debug!(
                    "Peer cycle detected: {}, resolving to active instance",
                    cycle_path_str
                );
                let parent_loc = self.strings.get(task.parent_location);
                let existing_opt = crate::hoisting::find_visible_peer_node(
                    &self.graph,
                    parent_loc,
                    &dep_spec.install_name,
                    &dep_spec.install_name,
                );
                if let Some(existing) = existing_opt {
                    let existing_loc = existing.location.clone();
                    let satisfies =
                        crate::hoisting::node_satisfies_target(existing, &dep_spec.target);
                    if !satisfies {
                        if task.dep_type == DependencyType::Peer {
                            if self.peer_conflict_is_fatal(task.is_mine) {
                                let existing_ver = existing.version.clone();
                                let existing_name = existing.name.clone();
                                let ancestors = self
                                    .ancestor_arena
                                    .to_vec(task.ancestor_head, &self.strings);
                                let parent_pkg = self.strings.get(task.parent_package_name).to_string();
                                return Err(SolverError::peer_conflict(
                                    parent_pkg,
                                    &dep_spec.package_name,
                                    &effective_spec,
                                    Some(existing_ver.clone()),
                                    Some(existing_loc.clone()),
                                    ancestors,
                                    format!(
                                        "Installed {}@{} at '{}' does not satisfy peer constraint '{}'",
                                        existing_name, existing_ver, existing_loc, effective_spec
                                    ),
                                )
                                .with_eresolve({
                                    let full_dep_spec = DependencySpec {
                                        install_name: dep_spec.install_name.clone(),
                                        package_name: dep_spec.package_name.clone(),
                                        target: (*dep_spec.target).clone(),
                                        raw_spec: effective_spec.clone(),
                                        is_alias: dep_spec.is_alias,
                                    };
                                    self.explain_peer_set_conflict(
                                        task,
                                        &full_dep_spec,
                                        &effective_spec,
                                        &existing_loc,
                                    )
                                }));
                            } else {
                                warn!(
                                    "Peer dependency conflict in cycle: {} requires {}@{}, but found {}@{} (non-strict mode)",
                                    self.strings.get(task.parent_package_name),
                                    dep_spec.package_name,
                                    effective_spec,
                                    existing.name,
                                    existing.version
                                );
                            }
                        } else if task.dep_type == DependencyType::PeerOptional {
                            debug!(
                                "Optional peer dependency '{}' for '{}' in cycle conflicts with installed {}@{} at '{}'; omitting optional peer",
                                dep_spec.package_name,
                                self.strings.get(task.parent_package_name),
                                existing.name,
                                existing.version,
                                existing.location
                            );
                            return Ok(());
                        }
                    }

                    self.graph.add_edge(DependencyEdge {
                        from_location: parent_loc.to_string(),
                        to_location: existing_loc,
                        install_name: dep_spec.install_name,
                        package_name: dep_spec.package_name,
                        spec: effective_spec,
                        dep_type: task.dep_type,
                    });
                    return Ok(());
                }
            }

            // Check if peer is already satisfied in ancestor/root scope
            let parent_loc = self.strings.get(task.parent_location);
            if let Some(existing) = crate::hoisting::find_visible_peer_node(
                &self.graph,
                parent_loc,
                &dep_spec.install_name,
                &dep_spec.install_name,
            ) {
                if crate::hoisting::node_matches_peer_name(
                    existing,
                    &dep_spec.install_name,
                    &dep_spec.package_name,
                ) {
                    if crate::hoisting::node_satisfies_target(existing, &dep_spec.target) {
                        debug!(
                            "Peer dependency '{}@{}' satisfied by existing node at '{}'",
                            dep_spec.package_name, effective_spec, existing.location
                        );
                        self.graph.add_edge(DependencyEdge {
                            from_location: parent_loc.to_string(),
                            to_location: existing.location.clone(),
                            install_name: dep_spec.install_name,
                            package_name: dep_spec.package_name,
                            spec: effective_spec,
                            dep_type: task.dep_type,
                        });
                        return Ok(());
                    } else if task.dep_type == DependencyType::Peer {
                        let scope = crate::hoisting::peer_provider_scope(
                            &self.graph,
                            parent_loc,
                            &dep_spec.install_name,
                        );
                        let sibling = if scope.is_empty() {
                            format!("node_modules/{}", dep_spec.install_name)
                        } else {
                            format!("{scope}/node_modules/{}", dep_spec.install_name)
                        };
                        if self.peer_conflict_is_fatal(task.is_mine) {
                            let existing_ver = existing.version.clone();
                            let existing_loc = existing.location.clone();
                            let existing_name = existing.name.clone();
                            let ancestors = self
                                .ancestor_arena
                                .to_vec(task.ancestor_head, &self.strings);
                            let parent_pkg = self.strings.get(task.parent_package_name).to_string();
                            return Err(SolverError::peer_conflict(
                                parent_pkg,
                                &dep_spec.package_name,
                                &effective_spec,
                                Some(existing_ver.clone()),
                                Some(existing_loc.clone()),
                                ancestors,
                                format!(
                                    "Installed {}@{} at '{}' does not satisfy peer constraint '{}'",
                                    existing_name, existing_ver, existing_loc, effective_spec
                                ),
                            )
                            .with_eresolve({
                                let full_dep_spec = DependencySpec {
                                    install_name: dep_spec.install_name.clone(),
                                    package_name: dep_spec.package_name.clone(),
                                    target: (*dep_spec.target).clone(),
                                    raw_spec: effective_spec.clone(),
                                    is_alias: dep_spec.is_alias,
                                };
                                self.explain_peer_set_conflict(
                                    task,
                                    &full_dep_spec,
                                    &effective_spec,
                                    &existing_loc,
                                )
                            }));
                        } else if self.graph.nodes.contains_key(&sibling) {
                            warn!(
                                "Peer dependency conflict: {} requires {}@{}, but found {}@{} (non-strict mode)",
                                self.strings.get(task.parent_package_name),
                                dep_spec.package_name,
                                effective_spec,
                                existing.name,
                                existing.version
                            );
                            self.graph.add_edge(DependencyEdge {
                                from_location: parent_loc.to_string(),
                                to_location: existing.location.clone(),
                                install_name: dep_spec.install_name,
                                package_name: dep_spec.package_name,
                                spec: effective_spec,
                                dep_type: task.dep_type,
                            });
                            return Ok(());
                        }
                    } else if task.dep_type == DependencyType::PeerOptional {
                        let scope = crate::hoisting::peer_provider_scope(
                            &self.graph,
                            parent_loc,
                            &dep_spec.install_name,
                        );
                        let sibling = (!scope.is_empty())
                            .then(|| format!("{scope}/node_modules/{}", dep_spec.install_name));
                        let root_pins_provider = sibling.is_none()
                            && !crate::hoisting::root_provider_replaceable(
                                &self.graph,
                                existing,
                                &dep_spec.install_name,
                                &effective_spec,
                            )
                            && existing.location
                                == format!("node_modules/{}", dep_spec.install_name)
                            && self.graph.nodes.get(&self.graph.root_location).is_some_and(
                                |root| {
                                    root.dependencies.contains_key(&dep_spec.install_name)
                                        || root.dev_dependencies.contains_key(&dep_spec.install_name)
                                        || root
                                            .optional_dependencies
                                            .contains_key(&dep_spec.install_name)
                                },
                            );
                        if root_pins_provider && self.peer_conflict_is_fatal(task.is_mine) {
                            let existing_ver = existing.version.clone();
                            let existing_loc = existing.location.clone();
                            let existing_name = existing.name.clone();
                            let ancestors = self
                                .ancestor_arena
                                .to_vec(task.ancestor_head, &self.strings);
                            let parent_pkg = self.strings.get(task.parent_package_name).to_string();
                            return Err(SolverError::peer_conflict(
                                parent_pkg,
                                &dep_spec.package_name,
                                &effective_spec,
                                Some(existing_ver.clone()),
                                Some(existing_loc.clone()),
                                ancestors,
                                format!(
                                    "Installed {}@{} at '{}' does not satisfy optional peer constraint '{}'",
                                    existing_name, existing_ver, existing_loc, effective_spec
                                ),
                            )
                            .with_eresolve({
                                let full_dep_spec = DependencySpec {
                                    install_name: dep_spec.install_name.clone(),
                                    package_name: dep_spec.package_name.clone(),
                                    target: (*dep_spec.target).clone(),
                                    raw_spec: effective_spec.clone(),
                                    is_alias: dep_spec.is_alias,
                                };
                                self.explain_placed_peer_conflict(
                                    task,
                                    &full_dep_spec,
                                    &effective_spec,
                                    &existing_loc,
                                )
                            }));
                        }
                        replace_transitive_root_peer = sibling.is_none() && !root_pins_provider;
                        if !replace_transitive_root_peer
                            && sibling
                                .as_ref()
                                .is_none_or(|location| self.graph.nodes.contains_key(location))
                        {
                            self.graph.add_edge(DependencyEdge {
                                from_location: parent_loc.to_string(),
                                to_location: existing.location.clone(),
                                install_name: dep_spec.install_name,
                                package_name: dep_spec.package_name,
                                spec: effective_spec,
                                dep_type: task.dep_type,
                            });
                            return Ok(());
                        }
                    }
                }
            } else if task.dep_type == DependencyType::PeerOptional {
                debug!(
                    "Optional peer dependency '{}@{}' for '{}' is not present in scope; skipping auto-install",
                    dep_spec.package_name,
                    effective_spec,
                    self.strings.get(task.parent_package_name)
                );
                if self.options.repair_optional_peers {
                    self.deferred_optional_peers
                        .entry(task.install_name)
                        .or_default()
                        .push(task);
                }
                return Ok(());
            }
        }

        // 4. Resolve package metadata and choose matching version
        let used_pkg_cache = Self::is_cacheable_target(&dep_spec.target)
            && self.pkg_cache.get(&dep_spec.package_name).is_some_and(|e| {
                if task.is_root {
                    e.allowed_root
                } else {
                    e.allowed_transitive
                }
            });
        let pkg_meta_opt = self.get_cached_meta(
            &dep_spec.package_name,
            &effective_spec,
            &dep_spec.target,
            task.is_root,
        )?;
        let Some(mut pkg_meta) = pkg_meta_opt else {
            if task.dep_type == DependencyType::Optional
                || task.dep_type == DependencyType::PeerOptional
            {
                debug!(
                    "Optional dependency '{}' not found, skipping",
                    dep_spec.package_name
                );
                if task.dep_type == DependencyType::Optional {
                    self.graph.skipped.insert(dep_spec.package_name);
                    self.graph.skipped.insert(dep_spec.install_name);
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
                let ancestors = self
                    .ancestor_arena
                    .to_vec(task.ancestor_head, &self.strings);
                return Err(SolverError::peer_conflict(
                    self.strings.get(task.parent_package_name),
                    dep_spec.package_name,
                    effective_spec.clone(),
                    None,
                    None,
                    ancestors,
                    format!("Peer package '{}' not found in registry", effective_spec),
                ));
            }
            return Err(SolverError::UnresolvedDependency {
                name: dep_spec.package_name,
                spec: effective_spec,
                message: "Package not found in metadata provider".to_string(),
            });
        };

        let parent_loc = self.strings.get(task.parent_location);
        let peer_scope = parent_loc
            .rsplit_once("/node_modules/")
            .map(|(scope, _)| scope)
            .unwrap_or("");
        let mut peer_advisories: Vec<PackageTarget> = if is_peer {
            let mut advisories = Vec::new();
            if !self.graph.nodes_by_dep_name.is_empty() {
                if let Some(locs) = self.graph.nodes_by_dep_name.get(&dep_spec.install_name) {
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
                                    .get(&dep_spec.install_name)
                                    .is_some_and(|meta| meta.optional)
                            {
                                if let Some(spec) = node.peer_dependencies.get(&dep_spec.install_name)
                                {
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
                            .get(&dep_spec.install_name)
                            .is_some_and(|meta| meta.optional)
                    {
                        if let Some(spec) = node.peer_dependencies.get(&dep_spec.install_name) {
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
        if is_peer {
            let mut sources = VecDeque::from([parent_loc.to_string()]);
            let mut seen: FastSet<String> = fast_set_with_capacity(8);
            while let Some(location) = sources.pop_front() {
                if !seen.insert(location.clone()) {
                    continue;
                }
                if !self.graph.incoming_edges_by_location.is_empty() {
                    if let Some(incoming_indices) =
                        self.graph.incoming_edges_by_location.get(&location)
                    {
                        for &idx in incoming_indices {
                            let incoming = &self.graph.edges[idx];
                            if matches!(
                                incoming.dep_type,
                                DependencyType::Peer | DependencyType::PeerOptional
                            ) {
                                sources.push_back(incoming.from_location.clone());
                            } else if let Some(source) = self.graph.nodes.get(&incoming.from_location)
                            {
                                let dev = (!source.location.contains("node_modules")
                                    && self.options.dev)
                                    .then(|| source.dev_dependencies.get(&dep_spec.install_name))
                                    .flatten();
                                if let Some(spec) = dev
                                    .or_else(|| {
                                        source.optional_dependencies.get(&dep_spec.install_name)
                                    })
                                    .or_else(|| source.dependencies.get(&dep_spec.install_name))
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
                            let dev = (!source.location.contains("node_modules")
                                && self.options.dev)
                                .then(|| source.dev_dependencies.get(&dep_spec.install_name))
                                .flatten();
                            if let Some(spec) = dev
                                .or_else(|| source.optional_dependencies.get(&dep_spec.install_name))
                                .or_else(|| source.dependencies.get(&dep_spec.install_name))
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
        if task.advisory != NO_SYM {
            if let Some(target) = cached_parse_package_target(self.strings.get(task.advisory)) {
                peer_advisories.push(target);
            }
        }
        let mut matched_version_opt = self
            .select_version_cached(
                parent_loc,
                &dep_spec.install_name,
                &dep_spec.package_name,
                &pkg_meta,
                &dep_spec.target,
                &peer_advisories,
            )
            .or_else(|| {
                self.select_version_cached(
                    parent_loc,
                    &dep_spec.install_name,
                    &dep_spec.package_name,
                    &pkg_meta,
                    &dep_spec.target,
                    &[],
                )
            });
        // If served from cache on a partial disk provider and nothing matched, allow one fresh provider lookup.
        if matched_version_opt.is_none() && used_pkg_cache {
            if let Some(fresh_raw) = self.provider.get_package_for_edge(
                &dep_spec.package_name,
                &effective_spec,
                task.is_root,
            )? {
                let fresh_arc = Arc::new(CachedPackageMeta::from_meta(fresh_raw));
                let retried = self
                    .select_version_cached(
                        parent_loc,
                        &dep_spec.install_name,
                        &dep_spec.package_name,
                        &fresh_arc,
                        &dep_spec.target,
                        &peer_advisories,
                    )
                    .or_else(|| {
                        self.select_version_cached(
                            parent_loc,
                            &dep_spec.install_name,
                            &dep_spec.package_name,
                            &fresh_arc,
                            &dep_spec.target,
                            &[],
                        )
                    });
                if retried.is_some()
                    || fresh_arc.entries.len() >= pkg_meta.entries.len()
                    || fresh_arc.dist_tags != pkg_meta.dist_tags
                {
                    if let Some(entry) = self.pkg_cache.get_mut(&dep_spec.package_name) {
                        entry.meta = Arc::clone(&fresh_arc);
                    }
                    pkg_meta = fresh_arc;
                    let parent_loc = self.strings.get(task.parent_location);
                    matched_version_opt = self
                        .select_version_cached(
                            parent_loc,
                            &dep_spec.install_name,
                            &dep_spec.package_name,
                            &pkg_meta,
                            &dep_spec.target,
                            &peer_advisories,
                        )
                        .or_else(|| {
                            self.select_version_cached(
                                parent_loc,
                                &dep_spec.install_name,
                                &dep_spec.package_name,
                                &pkg_meta,
                                &dep_spec.target,
                                &[],
                            )
                        });
                }
            }
        }
        let Some(chosen_version) = matched_version_opt else {
            if task.dep_type == DependencyType::Optional
                || task.dep_type == DependencyType::PeerOptional
            {
                debug!(
                    "No matching version for optional dependency '{}@{}', skipping",
                    dep_spec.package_name, effective_spec
                );
                if task.dep_type == DependencyType::Optional {
                    self.graph.skipped.insert(dep_spec.package_name);
                    self.graph.skipped.insert(dep_spec.install_name);
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
                let ancestors = self
                    .ancestor_arena
                    .to_vec(task.ancestor_head, &self.strings);
                return Err(SolverError::peer_conflict(
                    self.strings.get(task.parent_package_name),
                    dep_spec.package_name,
                    effective_spec.clone(),
                    None,
                    None,
                    ancestors,
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
            let ancestors = self
                .ancestor_arena
                .to_vec(task.ancestor_head, &self.strings);
            return Err(SolverError::platform_incompatible(
                &dep_spec.package_name,
                &chosen_version.version,
                wanted,
                current,
                ancestors,
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
        let has_shadowed_peers = !chosen_version.peer_dependencies.is_empty()
            && chosen_version.peer_dependencies.keys().any(|name| {
                chosen_version.dependencies.contains_key(name)
                    || chosen_version.optional_dependencies.contains_key(name)
            });
        let placement_peers = if chosen_version.peer_dependencies.is_empty()
            || (!has_overrides && !has_shadowed_peers)
        {
            None
        } else if !has_overrides {
            let mut peers = BTreeMap::new();
            for (name, spec) in &chosen_version.peer_dependencies {
                if chosen_version.dependencies.contains_key(name)
                    || chosen_version.optional_dependencies.contains_key(name)
                {
                    continue;
                }
                peers.insert(name.clone(), spec.clone());
            }
            Some(peers)
        } else {
            let parent_loc = self.strings.get(task.parent_location);
            let reference_root = self
                .graph
                .nodes
                .get(parent_loc)
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
            let child_ancestor_head = self.ancestor_arena.push(task.ancestor_head, pkg_sym);
            let ancestors = self
                .ancestor_arena
                .to_vec(child_ancestor_head, &self.strings);
            let task_ancestors = self
                .ancestor_arena
                .to_vec(task.ancestor_head, &self.strings);
            let mut peers = BTreeMap::new();
            for (name, spec) in &chosen_version.peer_dependencies {
                // Arborist loads prod and optional edges after peers, replacing
                // a peer declaration for the same name before placement.
                if chosen_version.dependencies.contains_key(name)
                    || chosen_version.optional_dependencies.contains_key(name)
                {
                    continue;
                }
                let virtual_override = self.overrides.resolve_override_precompiled_in_context(
                    name,
                    spec,
                    &ancestors,
                    &reference_root,
                    Some(&caller_specs),
                )?;
                let uses_override = virtual_override.is_some();
                let effective_peer = virtual_override.unwrap_or_else(|| spec.clone());
                if uses_override && !self.peer_conflict_is_fatal(task.is_mine) {
                    if let Some(source) = self.graph.nodes.get(parent_loc) {
                        let parent_spec = source
                            .optional_dependencies
                            .get(name)
                            .or_else(|| source.dependencies.get(name))
                            .or_else(|| source.peer_dependencies.get(name));
                        if let Some(parent_spec) = parent_spec {
                            let parent_spec = self
                                .overrides
                                .resolve_override_precompiled_with_caller(
                                    name,
                                    parent_spec,
                                    &task_ancestors,
                                    Some(&reference_root),
                                )?
                                .unwrap_or_else(|| parent_spec.clone());
                            if let Some(provider) = crate::hoisting::find_visible_peer_node(
                                &self.graph,
                                parent_loc,
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
        let parent_loc = self.strings.get(task.parent_location);
        let peer_scope = is_peer.then(|| {
            crate::hoisting::peer_provider_scope(&self.graph, parent_loc, &dep_spec.install_name)
        });
        // The placement routine treats this as an ordinary child of the
        // deepest allowed scope; it must not nest inside its peer owner.
        let placement_parent = peer_scope.unwrap_or(parent_loc);
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
                let parent_loc = self.strings.get(task.parent_location);
                let mut cand_buf =
                    String::with_capacity(parent_loc.len() + dep_spec.install_name.len() + 16);
                for scope in crate::hoisting::iter_ancestor_scopes(parent_loc) {
                    cand_buf.clear();
                    if scope.is_empty() {
                        cand_buf.push_str("node_modules/");
                    } else {
                        cand_buf.push_str(scope);
                        cand_buf.push_str("/node_modules/");
                    }
                    cand_buf.push_str(&dep_spec.install_name);
                    if let Some(pkg) = lockfile.packages.get(cand_buf.as_str()) {
                        if pkg.version.as_deref() == Some(&chosen_version.version) {
                            found_loc = Some(cand_buf.clone());
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
                            ) && cached_parse_package_target(&edge.spec).is_some_and(|target| {
                                crate::hoisting::node_satisfies_target(existing, &target)
                            })
                    })
                };
                if pinned_by_peer && self.peer_conflict_is_fatal(task.is_mine) {
                    let existing_ver = existing.version.clone();
                    let existing_loc = existing.location.clone();
                    let ancestors = self
                        .ancestor_arena
                        .to_vec(task.ancestor_head, &self.strings);
                    let parent_pkg = self.strings.get(task.parent_package_name).to_string();
                    return Err(SolverError::peer_conflict(
                        parent_pkg,
                        &dep_spec.package_name,
                        &effective_spec,
                        Some(existing_ver),
                        Some(existing_loc.clone()),
                        ancestors,
                        "Cannot move a peer provider beneath its consumer".to_string(),
                    )
                    .with_eresolve({
                        let full_dep_spec = DependencySpec {
                            install_name: dep_spec.install_name.clone(),
                            package_name: dep_spec.package_name.clone(),
                            target: (*dep_spec.target).clone(),
                            raw_spec: effective_spec.clone(),
                            is_alias: dep_spec.is_alias,
                        };
                        self.explain_placed_peer_conflict(
                            task,
                            &full_dep_spec,
                            &effective_spec,
                            &existing_loc,
                        )
                    }));
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
            .get(self.strings.get(task.parent_location))
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
                    self.graph.skipped.insert(dep_spec.install_name.clone());
                }
                self.graph.add_edge(DependencyEdge {
                    from_location: self.strings.get(task.parent_location).to_string(),
                    to_location: existing_loc,
                    install_name: dep_spec.install_name,
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

                let parent_loc = self.strings.get(task.parent_location);
                let is_bundled = if parent_loc.is_empty() {
                    self.graph.nodes.get("").is_some_and(|p| {
                        p.is_bundled_dependency(&dep_spec.install_name)
                            || p.is_bundled_dependency(&dep_spec.package_name)
                    })
                } else {
                    self.graph.nodes.get(parent_loc).is_some_and(|p| {
                        p.flags.bundled
                            || p.is_bundled_dependency(&dep_spec.install_name)
                            || p.is_bundled_dependency(&dep_spec.package_name)
                    })
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

                let parsed_ver = if pkg_meta.val_versions.is_empty() {
                    pkg_meta.parsed_by_key(&chosen_version.version).cloned()
                } else {
                    Version::parse(&chosen_version.version).ok()
                };
                let node = Node {
                    location: target_loc.clone(),
                    install_name: dep_spec.install_name.clone(),
                    name: dep_spec.package_name.clone(),
                    version: chosen_version.version.clone(),
                    parsed_version: parsed_ver,
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
                    self.graph.skipped.insert(dep_spec.install_name.clone());
                }

                self.graph.add_edge(DependencyEdge {
                    from_location: self.strings.get(task.parent_location).to_string(),
                    to_location: target_loc.clone(),
                    install_name: dep_spec.install_name,
                    package_name: dep_spec.package_name,
                    spec: effective_spec,
                    dep_type: task.dep_type,
                });

                // Arena-backed ancestor chain: 1 push instead of cloning Vec<String> + Arc.
                let child_ancestor_head = self.ancestor_arena.push(task.ancestor_head, pkg_sym);
                let target_loc_sym = self.strings.intern(&target_loc);
                let child_depth = target_loc.matches("node_modules").count() as u16;

                let has_peers = !self.options.legacy_peer_deps
                    && !chosen_version.peer_dependencies.is_empty();
                let bundled_val = chosen_version
                    .extra
                    .get("bundleDependencies")
                    .or_else(|| chosen_version.extra.get("bundledDependencies"));

                // Collect child dependencies without intermediate String clones whenever possible.
                let mut child_tasks: Vec<ResolveTask> = Vec::with_capacity(
                    chosen_version.dependencies.len()
                        + chosen_version.optional_dependencies.len()
                        + if has_peers {
                            chosen_version.peer_dependencies.len()
                        } else {
                            0
                        },
                );
                let mut has_upper = false;
                if chosen_version.optional_dependencies.is_empty()
                    && !has_peers
                    && bundled_val.is_none()
                {
                    // Fast path: `chosen_version.dependencies` is already a sorted BTreeMap.
                    for (c_name, c_spec) in &chosen_version.dependencies {
                        has_upper |= c_name.bytes().any(|b| b.is_ascii_uppercase());
                        let c_name_sym = self.strings.intern(c_name);
                        let c_spec_sym = self.strings.intern(c_spec);
                        child_tasks.push(ResolveTask {
                            parent_location: target_loc_sym,
                            parent_package_name: pkg_sym,
                            install_name: c_name_sym,
                            raw_spec: c_spec_sym,
                            dep_type: DependencyType::Prod,
                            parent_depth: child_depth,
                            ancestor_head: child_ancestor_head,
                            advisory: NO_SYM,
                            is_mine: false,
                            is_root: false,
                        });
                    }
                } else {
                    let mut child_deps: BTreeMap<&str, (&str, DependencyType)> = BTreeMap::new();
                    for (k, v) in &chosen_version.dependencies {
                        child_deps.insert(k.as_str(), (v.as_str(), DependencyType::Prod));
                    }
                    for (k, v) in &chosen_version.optional_dependencies {
                        child_deps.insert(k.as_str(), (v.as_str(), DependencyType::Optional));
                    }
                    if has_peers {
                        for (k, v) in &chosen_version.peer_dependencies {
                            if let Some((_, DependencyType::Prod | DependencyType::Optional)) =
                                child_deps.get(k.as_str())
                            {
                                continue;
                            }
                            let is_opt_peer = chosen_version
                                .peer_dependencies_meta
                                .get(k)
                                .is_some_and(|m| m.optional);
                            let p_type = if is_opt_peer {
                                DependencyType::PeerOptional
                            } else {
                                DependencyType::Peer
                            };
                            child_deps.insert(k.as_str(), (v.as_str(), p_type));
                        }
                    }
                    match bundled_val {
                        Some(serde_json::Value::Array(names)) => {
                            for name in names.iter().filter_map(|n| n.as_str()) {
                                child_deps.remove(name);
                            }
                        }
                        Some(serde_json::Value::Bool(true)) => {
                            for name in chosen_version.dependencies.keys() {
                                child_deps.remove(name.as_str());
                            }
                        }
                        _ => {}
                    }
                    for (c_name, (c_spec, c_type)) in child_deps {
                        has_upper |= c_name.bytes().any(|b| b.is_ascii_uppercase());
                        let is_peer_dep =
                            matches!(c_type, DependencyType::Peer | DependencyType::PeerOptional);
                        let child_is_mine = if is_peer_dep { task.is_mine } else { false };
                        let c_name_sym = self.strings.intern(c_name);
                        let c_spec_sym = self.strings.intern(c_spec);
                        child_tasks.push(ResolveTask {
                            parent_location: target_loc_sym,
                            parent_package_name: pkg_sym,
                            install_name: c_name_sym,
                            raw_spec: c_spec_sym,
                            dep_type: c_type,
                            parent_depth: child_depth,
                            ancestor_head: child_ancestor_head,
                            advisory: NO_SYM,
                            is_mine: child_is_mine,
                            is_root: false,
                        });
                    }
                }

                if self.provider.needs_closure_prefetch() && !child_tasks.is_empty() {
                    let mut child_targets = Vec::with_capacity(child_tasks.len());
                    for t in &child_tasks {
                        let Ok(c_dep) = DependencySpec::parse(
                            self.strings.get(t.install_name),
                            self.strings.get(t.raw_spec),
                        ) else {
                            continue;
                        };
                        if matches!(
                            c_dep.target,
                            PackageTarget::Range(_)
                                | PackageTarget::Version(_)
                                | PackageTarget::Tag(_)
                        ) {
                            child_targets.push(c_dep);
                        }
                    }
                    let child_edges: Vec<(&str, bool)> = child_targets
                        .iter()
                        .map(|t| (t.package_name.as_str(), false))
                        .collect();
                    self.provider.prefetch_packages_for_edge(&child_edges);
                }

                if has_upper && child_tasks.len() > 1 {
                    let strings = &self.strings;
                    child_tasks.sort_by(|a, b| {
                        arborist_compare(
                            strings.get(a.install_name),
                            strings.get(b.install_name),
                        )
                    });
                }

                let peer_tasks = if !has_peers {
                    self.queue
                        .push_sorted_sibling_batch(&child_tasks, &self.strings);
                    Vec::new()
                } else {
                    let peer_scope = target_loc
                        .rsplit_once("/node_modules/")
                        .map(|(scope, _)| scope)
                        .unwrap_or("");
                    let is_peer_scope_mine = !peer_scope.contains("node_modules");
                    let mut batch_tasks = Vec::with_capacity(child_tasks.len());
                    let mut peer_tasks = Vec::new();
                    let mut loc_buf = String::with_capacity(peer_scope.len() + 48);
                    for child_task in child_tasks {
                        let is_peer_child = matches!(
                            child_task.dep_type,
                            DependencyType::Peer | DependencyType::PeerOptional
                        );
                        if !is_peer_child {
                            batch_tasks.push(child_task);
                            continue;
                        }
                        let c_name = self.strings.get(child_task.install_name);
                        let provider_pending =
                            self.graph.nodes.get(peer_scope).is_some_and(|parent| {
                                let mut declared = parent.dependencies.contains_key(c_name)
                                    || parent.optional_dependencies.contains_key(c_name)
                                    || (parent.peer_dependencies.contains_key(c_name)
                                        && !parent
                                            .peer_dependencies_meta
                                            .get(c_name)
                                            .is_some_and(|m| m.optional));
                                if self.options.dev {
                                    declared =
                                        declared || parent.dev_dependencies.contains_key(c_name);
                                }
                                loc_buf.clear();
                                if peer_scope.is_empty() {
                                    loc_buf.push_str("node_modules/");
                                } else {
                                    loc_buf.push_str(peer_scope);
                                    loc_buf.push_str("/node_modules/");
                                }
                                loc_buf.push_str(c_name);
                                declared && !self.graph.nodes.contains_key(loc_buf.as_str())
                            });
                        if !provider_pending {
                            peer_tasks.push(child_task);
                        } else if is_peer_scope_mine {
                            let Some(parent) = self.graph.nodes.get(peer_scope) else {
                                continue;
                            };
                            let dev_edge = self
                                .options
                                .dev
                                .then(|| {
                                    parent
                                        .dev_dependencies
                                        .get(c_name)
                                        .map(|s| (s.as_str(), DependencyType::Dev))
                                })
                                .flatten();
                            let parent_edge = dev_edge
                                .or_else(|| {
                                    parent
                                        .optional_dependencies
                                        .get(c_name)
                                        .map(|s| (s.as_str(), DependencyType::Optional))
                                })
                                .or_else(|| {
                                    parent
                                        .dependencies
                                        .get(c_name)
                                        .map(|s| (s.as_str(), DependencyType::Prod))
                                })
                                .or_else(|| {
                                    parent
                                        .peer_dependencies
                                        .get(c_name)
                                        .filter(|_| {
                                            !parent
                                                .peer_dependencies_meta
                                                .get(c_name)
                                                .is_some_and(|m| m.optional)
                                        })
                                        .map(|s| (s.as_str(), DependencyType::Peer))
                                });
                            if let Some((raw_spec_str, dep_type)) = parent_edge {
                                let parent_name = parent.name.clone();
                                let raw_spec_copied = raw_spec_str.to_string();
                                let is_peer_scope_root = !peer_scope.contains("node_modules");
                                let root_pkg_name = self
                                    .graph
                                    .nodes
                                    .get("")
                                    .map(|n| n.name.as_str())
                                    .unwrap_or("root");
                                let peer_scope_sym = self.strings.intern(peer_scope);
                                let parent_name_sym = self.strings.intern(&parent_name);
                                let raw_spec_sym = self.strings.intern(&raw_spec_copied);
                                let root_anc_head = if peer_scope.is_empty() {
                                    self.ancestor_arena.push(NO_ANCESTOR, parent_name_sym)
                                } else {
                                    let root_pkg_sym = self.strings.intern(root_pkg_name);
                                    let h = self.ancestor_arena.push(NO_ANCESTOR, root_pkg_sym);
                                    self.ancestor_arena.push(h, parent_name_sym)
                                };
                                let root_task = ResolveTask {
                                    parent_location: peer_scope_sym,
                                    parent_package_name: parent_name_sym,
                                    install_name: child_task.install_name,
                                    raw_spec: raw_spec_sym,
                                    dep_type,
                                    parent_depth: if peer_scope.is_empty() {
                                        0
                                    } else {
                                        peer_scope.matches("node_modules").count() as u16
                                    },
                                    ancestor_head: root_anc_head,
                                    advisory: child_task.raw_spec,
                                    is_mine: true,
                                    is_root: is_peer_scope_root,
                                };
                                self.preplaced
                                    .insert((peer_scope_sym, child_task.install_name));
                                peer_tasks.push(root_task);
                                peer_tasks.push(child_task);
                            } else {
                                batch_tasks.push(child_task);
                            }
                        } else {
                            batch_tasks.push(child_task);
                        }
                    }
                    self.queue
                        .push_sorted_sibling_batch(&batch_tasks, &self.strings);
                    peer_tasks
                };
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
        use std::ops::Bound::{Included, Unbounded};
        let root_prefix = format!("{location}/node_modules/");
        let mut forced: FastSet<String> = fast_set_with_capacity(8);
        if self.graph.nodes.contains_key(location) {
            forced.insert(location.to_string());
        }
        for (k, _) in self
            .graph
            .nodes
            .range::<str, _>((Included(root_prefix.as_str()), Unbounded))
            .take_while(|(k, _)| k.starts_with(&root_prefix))
        {
            forced.insert(k.clone());
        }

        // Everything the old node reaches through edges or nesting.
        let mut reached: FastSet<String> = fast_set_with_capacity(forced.len() * 2 + 4);
        let mut work: VecDeque<String> = forced.iter().cloned().collect();
        let has_outgoing_index = !self.graph.outgoing_edges_by_location.is_empty();
        let mut nested_buf = String::with_capacity(64);
        while let Some(loc) = work.pop_front() {
            if !reached.insert(loc.clone()) {
                continue;
            }
            if has_outgoing_index {
                if let Some(indices) = self.graph.outgoing_edges_by_location.get(&loc) {
                    for &idx in indices {
                        let edge = &self.graph.edges[idx];
                        if edge.to_location.contains("node_modules/")
                            && self.graph.nodes.contains_key(&edge.to_location)
                        {
                            work.push_back(edge.to_location.clone());
                        }
                    }
                }
            } else {
                for edge in &self.graph.edges {
                    if edge.from_location == loc
                        && edge.to_location.contains("node_modules/")
                        && self.graph.nodes.contains_key(&edge.to_location)
                    {
                        work.push_back(edge.to_location.clone());
                    }
                }
            }
            nested_buf.clear();
            nested_buf.push_str(&loc);
            nested_buf.push_str("/node_modules/");
            for (k, _) in self
                .graph
                .nodes
                .range::<str, _>((Included(nested_buf.as_str()), Unbounded))
                .take_while(|(k, _)| k.starts_with(nested_buf.as_str()))
            {
                work.push_back(k.clone());
            }
        }

        // A reached node survives when a node outside the set depends on it,
        // and so does whatever it reaches.
        let mut kept: FastSet<String> = fast_set_with_capacity(reached.len());
        let has_incoming_index = !self.graph.incoming_edges_by_location.is_empty();
        let mut work: VecDeque<String> = VecDeque::new();
        for loc in &reached {
            if forced.contains(loc) {
                continue;
            }
            let has_external_incoming = if has_incoming_index {
                self.graph
                    .incoming_edges_by_location
                    .get(loc)
                    .is_some_and(|indices| {
                        indices
                            .iter()
                            .any(|&idx| !reached.contains(&self.graph.edges[idx].from_location))
                    })
            } else {
                self.graph
                    .edges
                    .iter()
                    .any(|edge| edge.to_location == *loc && !reached.contains(&edge.from_location))
            };
            if has_external_incoming {
                work.push_back(loc.clone());
            }
        }
        while let Some(loc) = work.pop_front() {
            if forced.contains(&loc) || !kept.insert(loc.clone()) {
                continue;
            }
            if has_outgoing_index {
                if let Some(indices) = self.graph.outgoing_edges_by_location.get(&loc) {
                    for &idx in indices {
                        let edge = &self.graph.edges[idx];
                        if reached.contains(&edge.to_location) {
                            work.push_back(edge.to_location.clone());
                        }
                    }
                }
            } else {
                for edge in &self.graph.edges {
                    if edge.from_location == loc && reached.contains(&edge.to_location) {
                        work.push_back(edge.to_location.clone());
                    }
                }
            }
            nested_buf.clear();
            nested_buf.push_str(&loc);
            nested_buf.push_str("/node_modules/");
            for key in &reached {
                if key.starts_with(nested_buf.as_str()) {
                    work.push_back(key.clone());
                }
            }
        }
        let mut detached: FastSet<String> = fast_set_with_capacity(reached.len());
        for loc in reached {
            if !kept.contains(&loc) {
                detached.insert(loc);
            }
        }
        self.graph.nodes.retain(|key, _| !detached.contains(key));
        self.graph
            .edges
            .retain(|edge| !detached.contains(&edge.from_location));
        self.graph.rebuild_indices();
        let strings = &self.strings;
        self.queue
            .retain(|task| !detached.contains(strings.get(task.parent_location)));
        for tasks in self.deferred_workspaces.values_mut() {
            tasks.retain(|task| !detached.contains(strings.get(task.parent_location)));
        }
        for tasks in self.deferred_optional_peers.values_mut() {
            tasks.retain(|task| !detached.contains(strings.get(task.parent_location)));
        }
    }

    fn rehome_transitive_root_node(&mut self, root_location: &str, install_name: &str) -> bool {
        use std::ops::Bound::{Included, Unbounded};
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
        let incoming: Vec<&DependencyEdge> = if !self.graph.incoming_edges_by_location.is_empty() {
            self.graph
                .incoming_edges_by_location
                .get(root_location)
                .map(|idxs| idxs.iter().map(|&i| &self.graph.edges[i]).collect())
                .unwrap_or_default()
        } else {
            self.graph
                .edges
                .iter()
                .filter(|edge| edge.to_location == root_location)
                .collect()
        };
        if incoming.is_empty() || incoming.iter().any(|edge| edge.from_location.is_empty()) {
            return false;
        }
        let Some(existing_node) = self.graph.nodes.get(root_location).cloned() else {
            return false;
        };
        let mut parent: Option<&str> = None;
        let mut any_compatible = false;
        for edge in &incoming {
            let compatible = cached_target_rc(&edge.spec)
                .is_some_and(|target| crate::hoisting::node_satisfies_target(&existing_node, &target));
            if !compatible {
                continue;
            }
            any_compatible = true;
            if matches!(
                edge.dep_type,
                DependencyType::Peer | DependencyType::PeerOptional
            ) {
                return false;
            }
            match parent {
                None => parent = Some(edge.from_location.as_str()),
                Some(p) if p == edge.from_location.as_str() => {}
                Some(_) => return false,
            }
        }
        if !any_compatible {
            return false;
        }
        let parent = parent.unwrap().to_string();
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
            .range::<str, _>((Included(prefix.as_str()), Unbounded))
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
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
                let keep_nested = cached_target_rc(&edge.spec).is_some_and(|target| {
                    crate::hoisting::node_satisfies_target(&existing_node, &target)
                });
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
        for mut task in self.queue.drain_all() {
            let new_loc = {
                let old_loc = self.strings.get(task.parent_location);
                if old_loc == root_location || old_loc.starts_with(&prefix) {
                    Some(format!("{nested}{}", &old_loc[root_location.len()..]))
                } else {
                    None
                }
            };
            if let Some(nl) = new_loc {
                task.parent_depth = nl.matches("node_modules").count() as u16;
                task.parent_location = self.strings.intern_owned(nl);
            }
            self.queue.push_task(task, &self.strings);
        }
        for tasks in self.deferred_optional_peers.values_mut() {
            for task in tasks {
                let new_loc = {
                    let old_loc = self.strings.get(task.parent_location);
                    if old_loc == root_location || old_loc.starts_with(&prefix) {
                        Some(format!("{nested}{}", &old_loc[root_location.len()..]))
                    } else {
                        None
                    }
                };
                if let Some(nl) = new_loc {
                    task.parent_depth = nl.matches("node_modules").count() as u16;
                    task.parent_location = self.strings.intern_owned(nl);
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
        self.indices_dirty = true;

        let has_incoming_index = !self.graph.incoming_edges_by_location.is_empty();
        for candidate in &candidates {
            if has_incoming_index {
                if let Some(mut edge_indices) =
                    self.graph.incoming_edges_by_location.remove(candidate)
                {
                    for &idx in &edge_indices {
                        if let Some(edge) = self.graph.edges.get_mut(idx) {
                            edge.to_location = root_location.to_string();
                        }
                    }
                    if let Some(root_incoming) =
                        self.graph.incoming_edges_by_location.get_mut(root_location)
                    {
                        root_incoming.extend(edge_indices);
                        root_incoming.sort_unstable();
                    } else {
                        edge_indices.sort_unstable();
                        self.graph
                            .incoming_edges_by_location
                            .insert(root_location.to_string(), edge_indices);
                    }
                }
            } else {
                for edge in &mut self.graph.edges {
                    if edge.to_location == *candidate {
                        edge.to_location = root_location.to_string();
                    }
                }
            }
            self.graph.remove_node(candidate);
        }
    }

    /// Selects the highest version matching target constraint in a single linear pass (O(N), zero Vec allocations, zero metadata clones).
    /// buildIdealTree loads every root edge's peer set (nodeFromEdge) before
    /// placing any of them, so a root dependency whose required peer cannot
    /// agree with the root's own edge to that peer fails first, as "unable to
    /// resolve dependency tree", whatever placement conflicts come later.
    fn precheck_root_peer_sets(
        &mut self,
        root_manifest: &Manifest,
        root_deps: &BTreeMap<String, (String, DependencyType)>,
    ) -> Option<(SolverError, String)> {
        use crate::explain::{EdgeFrom, EdgeView, Explanation, Subject};
        let mut seen_order: FastSet<&str> = fast_set_with_capacity(root_deps.len());
        let mut order: Vec<&String> = Vec::with_capacity(root_deps.len());
        for deps in [
            &root_manifest.peer_dependencies,
            &root_manifest.dependencies,
            &root_manifest.optional_dependencies,
            &root_manifest.dev_dependencies,
        ] {
            for name in deps.keys() {
                if root_deps.contains_key(name) && seen_order.insert(name.as_str()) {
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
                .get_cached_meta(&dep_spec.package_name, spec, &dep_spec.target, true)
                .ok()
                .flatten()
            else {
                continue;
            };
            let Some(chosen_owned) = self
                .select_version_cached(
                    "",
                    &dep_spec.install_name,
                    &dep_spec.package_name,
                    &meta,
                    &dep_spec.target,
                    &[],
                )
                .cloned()
            else {
                continue;
            };
            for (peer, peer_spec) in &chosen_owned.peer_dependencies {
                if chosen_owned
                    .peer_dependencies_meta
                    .get(peer)
                    .is_some_and(|meta| meta.optional)
                    || chosen_owned.dependencies.contains_key(peer)
                    || chosen_owned.optional_dependencies.contains_key(peer)
                    // Overrides rewrite these specs per path; leave them to placement.
                    || self.overrides.mentions_precompiled(name)
                    || self.overrides.mentions_precompiled(peer)
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
                    cached_target_rc(peer_spec),
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
            let peer_used_cache = Self::is_cacheable_target(&root_target)
                && self.pkg_cache.get(peer).is_some_and(|e| e.allowed_root);
            let Some(mut peer_meta) = self
                .get_cached_meta(peer, root_spec, &root_target, true)
                .ok()
                .flatten()
            else {
                continue;
            };
            // nodeFromEdge(parentEdge, ..., peerEdge): the root's choice,
            // steered by the peer edge, must also satisfy the peer edge.
            let peer_target_slice = std::slice::from_ref(peer_target.as_ref());
            let mut root_choice_opt = self
                .select_version_cached("", peer, peer, &peer_meta, &root_target, peer_target_slice)
                .or_else(|| {
                    self.select_version_cached("", peer, peer, &peer_meta, &root_target, &[])
                });
            if root_choice_opt.is_none() && peer_used_cache {
                if let Ok(Some(fresh_raw)) =
                    self.provider.get_package_for_edge(peer, root_spec, true)
                {
                    let fresh_arc = Arc::new(CachedPackageMeta::from_meta(fresh_raw));
                    let retried = self
                        .select_version_cached(
                            "",
                            peer,
                            peer,
                            &fresh_arc,
                            &root_target,
                            peer_target_slice,
                        )
                        .or_else(|| {
                            self.select_version_cached(
                                "",
                                peer,
                                peer,
                                &fresh_arc,
                                &root_target,
                                &[],
                            )
                        });
                    if retried.is_some()
                        || fresh_arc.entries.len() >= peer_meta.entries.len()
                        || fresh_arc.dist_tags != peer_meta.dist_tags
                    {
                        if let Some(entry) = self.pkg_cache.get_mut(peer) {
                            entry.meta = Arc::clone(&fresh_arc);
                        }
                        peer_meta = fresh_arc;
                        root_choice_opt = self
                            .select_version_cached(
                                "",
                                peer,
                                peer,
                                &peer_meta,
                                &root_target,
                                peer_target_slice,
                            )
                            .or_else(|| {
                                self.select_version_cached(
                                    "",
                                    peer,
                                    peer,
                                    &peer_meta,
                                    &root_target,
                                    &[],
                                )
                            });
                    }
                }
            }
            let Some(root_choice) = root_choice_opt else {
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
                            version: chosen_owned.version.clone(),
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
                return Some((conflict, chosen_owned.version.clone()));
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
        let edge = if !self.graph.incoming_edges_by_location.is_empty() {
            self.graph
                .incoming_edges_by_location
                .get(location)
                .and_then(|idxs| idxs.iter().min())
                .map(|&idx| &self.graph.edges[idx])
        } else {
            self.graph.edges.iter().find(|e| e.to_location == location)
        };
        edge.map(|edge| {
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
                let cached = CachedPackageMeta::from_meta(meta);
                self.select_version_cached(
                    parent_location,
                    &dep_spec.install_name,
                    &dep_spec.package_name,
                    &cached,
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
        task: ResolveTask,
        dep_spec: &DependencySpec,
        effective_spec: &str,
        existing_location: &str,
    ) -> crate::explain::Eresolve {
        use crate::explain::{EdgeFrom, EdgeView, Explanation, Subject};
        let parent_loc = self.strings.get(task.parent_location);
        let install_name = self.strings.get(task.install_name);
        let parent_pkg_name = self.strings.get(task.parent_package_name);
        let owner = self.graph.nodes.get(parent_loc);
        let placing = self.placing_edge(parent_loc);
        let peer_edge = EdgeView {
            dep_type: task.dep_type,
            name: install_name.to_string(),
            spec: effective_spec.to_string(),
            from: EdgeFrom::Virtual {
                name: owner
                    .map(|o| o.install_name.clone())
                    .unwrap_or_else(|| parent_pkg_name.to_string()),
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
                    name: install_name.to_string(),
                    version: self.candidate_version(parent_loc, dep_spec),
                    location: format!("node_modules/{install_name}"),
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
        task: ResolveTask,
        dep_spec: &DependencySpec,
        effective_spec: &str,
        existing_location: &str,
    ) -> crate::explain::Eresolve {
        use crate::explain::{graph_edge, Explanation, Subject};
        let parent_loc = self.strings.get(task.parent_location);
        let install_name = self.strings.get(task.install_name);
        let peer_edge = graph_edge(
            &self.graph,
            parent_loc,
            task.dep_type,
            install_name,
            effective_spec,
        );
        Explanation {
            heading: "could not resolve",
            while_resolving: self.source_id(&peer_edge.from),
            found: Subject::Graph(existing_location.to_string()),
            edge: peer_edge.clone(),
            conflict: Some(Subject::Candidate {
                name: install_name.to_string(),
                version: self.candidate_version(parent_loc, dep_spec),
                location: format!("node_modules/{install_name}"),
                dependents: vec![peer_edge],
            }),
        }
        .render(&self.graph, self.options.strict_peer_deps)
    }

    /// Warms the metadata cache for the likely dependency closure, one
    /// parallel batch per depth level, so placement (which visits one node at
    /// a time) rarely waits on the network.
    fn prefetch_closure(&self, root_deps: &BTreeMap<String, (String, DependencyType)>) {
        struct Work {
            queue: Vec<(String, String, bool)>,
            in_flight: usize,
            seen: FastSet<String>,
        }
        let mut seen = fast_set_with_capacity(root_deps.len() * 4);
        for k in root_deps.keys() {
            seen.insert(k.clone());
        }
        let work = std::sync::Mutex::new(Work {
            queue: root_deps
                .iter()
                .filter(|(_, (_, dep_type))| *dep_type != DependencyType::PeerOptional)
                .map(|(name, (spec, _))| (name.clone(), spec.clone(), true))
                .collect(),
            in_flight: 0,
            seen,
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
            let Some(meta) = self.provider.cached_package(&dep_spec.package_name) else {
                continue;
            };
            let cached = CachedPackageMeta::from_meta(meta);
            let Some(version) = self.select_version_cached(
                "",
                &dep_spec.install_name,
                &dep_spec.package_name,
                &cached,
                &dep_spec.target,
                &[],
            ) else {
                continue;
            };
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
                if bundled.contains(&child.as_str()) || self.overrides.mentions_precompiled(child) {
                    continue;
                }
                out.push((child.clone(), child_spec.clone(), false));
            }
        }
        out
    }

    fn select_version_cached<'b>(
        &self,
        parent_location: &str,
        install_name: &str,
        pkg_name: &str,
        meta: &'b CachedPackageMeta,
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
                let mut cand_buf = String::with_capacity(parent_location.len() + install_name.len() + 16);
                for scope in crate::hoisting::iter_ancestor_scopes(parent_location) {
                    cand_buf.clear();
                    if scope.is_empty() {
                        cand_buf.push_str("node_modules/");
                    } else {
                        cand_buf.push_str(scope);
                        cand_buf.push_str("/node_modules/");
                    }
                    cand_buf.push_str(install_name);
                    if let Some(pkg) = lockfile.packages.get(cand_buf.as_str()) {
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
                            if let Some(v_meta) = meta.get_by_key(ver_str) {
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
                if let Some(v) = meta.get_by_key(&v_str) {
                    Some(v)
                } else {
                    meta.descending
                        .iter()
                        .find_map(|(parsed, idx)| (parsed == expected).then_some(&meta.entries[*idx]))
                }
            }
            PackageTarget::Tag(tag) => {
                if let Some(tagged_version) = meta.dist_tags.get(tag) {
                    if let Some(v) = meta.get_by_key(tagged_version) {
                        return Some(v);
                    }
                }
                if tag == "latest" {
                    if let Some((_, idx)) = meta
                        .descending
                        .iter()
                        .find(|(parsed, idx)| !meta.entry_version(*idx, parsed).is_prerelease())
                    {
                        return Some(&meta.entries[*idx]);
                    }
                    if let Some((_, idx)) = meta.descending.first() {
                        return Some(&meta.entries[*idx]);
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
                    let mut scope_buf =
                        String::with_capacity(parent_location.len() + install_name.len() + 16);
                    if let Some(loc) = DependencyGraph::find_in_scope_hierarchy(
                        &self.graph.nodes,
                        parent_location,
                        install_name,
                        &mut scope_buf,
                    ) {
                        if let Some(existing_node) = self.graph.nodes.get(loc) {
                            if existing_node.name == pkg_name {
                                let parsed_opt = existing_node
                                    .parsed_version
                                    .as_ref()
                                    .map(std::borrow::Cow::Borrowed)
                                    .or_else(|| {
                                        cached_version_rc(&existing_node.version)
                                            .map(|rc| std::borrow::Cow::Owned((*rc).clone()))
                                    });
                                if let Some(parsed) = parsed_opt {
                                    if range.satisfies(parsed.as_ref())
                                        && is_safe(parsed.as_ref())
                                        && advisories.iter().all(|target| {
                                            parsed_version_satisfies_target(
                                                parsed.as_ref(),
                                                Some(&existing_node.version),
                                                target,
                                            )
                                        })
                                    {
                                        if let Some(v_meta) = meta.get_by_key(&existing_node.version) {
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
                            let parsed_opt = node
                                .parsed_version
                                .as_ref()
                                .map(std::borrow::Cow::Borrowed)
                                .or_else(|| {
                                    cached_version_rc(&node.version)
                                        .map(|rc| std::borrow::Cow::Owned((*rc).clone()))
                                });
                            if let Some(parsed) = parsed_opt {
                                if range.satisfies(parsed.as_ref())
                                    && is_safe(parsed.as_ref())
                                    && advisories.iter().all(|target| {
                                        parsed_version_satisfies_target(
                                            parsed.as_ref(),
                                            Some(&node.version),
                                            target,
                                        )
                                    })
                                {
                                    if let Some(v_meta) = meta.get_by_key(&node.version) {
                                        if v_meta.deprecated.is_none() {
                                            match &best_placed_undeprecated {
                                                Some((_, best_v)) => {
                                                    if parsed.as_ref() > best_v {
                                                        best_placed_undeprecated =
                                                            Some((v_meta, parsed.as_ref().clone()));
                                                    }
                                                }
                                                None => {
                                                    best_placed_undeprecated =
                                                        Some((v_meta, parsed.as_ref().clone()));
                                                }
                                            }
                                        }
                                        match &best_placed {
                                            Some((_, best_v)) => {
                                                if parsed.as_ref() > best_v {
                                                    best_placed =
                                                        Some((v_meta, parsed.into_owned()));
                                                }
                                            }
                                            None => {
                                                best_placed = Some((v_meta, parsed.into_owned()));
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
                // when that tagged version satisfies the requested range.
                if let Some(latest_version) = meta.dist_tags.get("latest") {
                    if let Some(&latest_idx) = meta.by_key.get(latest_version) {
                        let latest = &meta.entries[latest_idx];
                        if latest.deprecated.is_none() {
                            if let Some(ref v) = meta.parsed_versions[latest_idx] {
                                if range.satisfies(v)
                                    && is_safe(v)
                                    && advisories.iter().all(|target| {
                                        parsed_version_satisfies_target(
                                            v,
                                            Some(&latest.version),
                                            target,
                                        )
                                    })
                                {
                                    return Some(latest);
                                }
                            }
                        }
                    }
                }

                // `meta.descending` is stably sorted highest SemVer first (with ties preserving
                // ascending BTreeMap order), so the first safe + undeprecated match wins immediately.
                let mut first_safe: Option<&'b PackageVersionMetadata> = None;
                let mut first_any: Option<&'b PackageVersionMetadata> = None;
                let (min_major, max_major) = if meta.val_versions.is_empty() {
                    range.major_bounds_hint()
                } else {
                    (None, None)
                };
                let slice = meta.descending.as_slice();
                let start = if let Some(max_m) = max_major {
                    slice.partition_point(|(v, _)| v.major > max_m)
                } else {
                    0
                };
                for (parsed, idx) in &slice[start..] {
                    if let Some(min_m) = min_major {
                        if parsed.major < min_m {
                            break;
                        }
                    }
                    let check_ver = meta.entry_version(*idx, parsed);
                    if !range.satisfies(check_ver) {
                        continue;
                    }
                    let v_meta = &meta.entries[*idx];
                    if !advisories.iter().all(|target| {
                        parsed_version_satisfies_target(check_ver, Some(&v_meta.version), target)
                    }) {
                        continue;
                    }
                    if is_safe(check_ver) {
                        if v_meta.deprecated.is_none() {
                            return Some(v_meta);
                        }
                        if first_safe.is_none() {
                            first_safe = Some(v_meta);
                        }
                    } else if first_any.is_none() {
                        first_any = Some(v_meta);
                    }
                }
                first_safe.or(first_any)
            }
            PackageTarget::Alias {
                name: ref aliased_name,
                ref target,
            } => self.select_version_cached(
                parent_location,
                install_name,
                aliased_name,
                meta,
                target,
                advisories,
            ),
            PackageTarget::Url(u) => {
                let u_str = u.as_str();
                meta.entries
                    .iter()
                    .find(|v| v.dist_tarball.as_deref() == Some(u_str))
                    .or_else(|| {
                        if meta.entries.len() == 1 {
                            meta.entries.first()
                        } else {
                            None
                        }
                    })
            }
            PackageTarget::File(p) => meta
                .entries
                .iter()
                .find(|v| {
                    v.dist_tarball.as_deref().is_some_and(|resolved| {
                        crate::hoisting::file_target_matches_resolved(p, resolved)
                    })
                })
                .or_else(|| {
                    if meta.entries.len() == 1 {
                        meta.entries.first()
                    } else {
                        None
                    }
                }),
            PackageTarget::Git {
                url, committish, ..
            } => meta
                .entries
                .iter()
                .find(|v| {
                    v.dist_tarball.as_deref().is_some_and(|dt| {
                        crate::hoisting::git_target_matches_resolved(url, committish.as_deref(), dt)
                    })
                })
                .or_else(|| {
                    if meta.entries.len() == 1 {
                        meta.entries.first()
                    } else {
                        None
                    }
                }),
            PackageTarget::Workspace(ws_spec) => {
                let s = ws_spec.trim();
                if s == "*" || s == "^" || s == "~" || s.is_empty() {
                    meta.max_semver_version()
                } else if let Ok(range) = rnpm_core::semver::Range::parse(s) {
                    meta.descending
                        .iter()
                        .find(|(parsed, _)| range.satisfies(parsed))
                        .map(|(_, idx)| &meta.entries[*idx])
                } else {
                    meta.max_semver_version()
                }
            }
        }
    }
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

    let overrides_val = manifest.extra.get("overrides");
    let overrides = if overrides_val.is_some() {
        Overrides::from_json_value(overrides_val, Overrides::reference_specs(manifest))
    } else {
        Overrides::default()
    };

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
    let mut node_by_loc: FastMap<&str, &Node> = fast_map_with_capacity(graph.nodes.len());
    for (loc, node) in &graph.nodes {
        node_by_loc.insert(loc.as_str(), node);
    }
    let mut buf = String::with_capacity(128);
    let has_overrides = !overrides.rules.is_empty();

    for (loc, node) in &graph.nodes {
        if node.flags.skipped {
            continue;
        }

        // Direct prod dependencies
        for (dep_name, dep_spec) in &node.dependencies {
            if !validate_fast_path_dep(
                graph,
                &node_by_loc,
                loc,
                dep_name,
                dep_spec,
                DependencyType::Prod,
                options,
                overrides,
                has_overrides,
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
                    &node_by_loc,
                    loc,
                    dep_name,
                    dep_spec,
                    DependencyType::Dev,
                    options,
                    overrides,
                    has_overrides,
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
                &node_by_loc,
                loc,
                dep_name,
                dep_spec,
                DependencyType::Optional,
                options,
                overrides,
                has_overrides,
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
                    &node_by_loc,
                    loc,
                    dep_name,
                    dep_spec,
                    DependencyType::Peer,
                    options,
                    overrides,
                    has_overrides,
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
    node_by_loc: &FastMap<&str, &Node>,
    from_loc: &str,
    dep_name: &str,
    raw_spec: &str,
    dep_type: DependencyType,
    options: &ResolverOptions,
    overrides: &Overrides,
    has_overrides: bool,
    buf: &mut String,
) -> bool {
    let mut target_node_opt: Option<&Node> = None;
    for scope in crate::hoisting::iter_ancestor_scopes(from_loc) {
        buf.clear();
        if scope.is_empty() {
            buf.push_str("node_modules/");
        } else {
            buf.push_str(scope);
            buf.push_str("/node_modules/");
        }
        buf.push_str(dep_name);
        if let Some(&n) = node_by_loc.get(buf.as_str()) {
            target_node_opt = Some(n);
            break;
        }
    }

    let Some(target_node) = target_node_opt else {
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

    if target_node.flags.skipped {
        return dep_type == DependencyType::Optional;
    }

    // Determine effective spec taking overrides into account
    let overridden_spec = if !has_overrides {
        None
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
        if let Ok(Some(overridden)) =
            overrides.resolve_override_precompiled_with_caller(dep_name, raw_spec, &ancestors, None)
        {
            if let Ok(parsed_override) = DependencySpec::parse(dep_name, &overridden) {
                return target_node.name == parsed_override.package_name
                    && crate::hoisting::node_satisfies_target(
                        target_node,
                        &parsed_override.target,
                    );
            }
            return false;
        }
        None::<String>
    };
    let effective_spec = overridden_spec.as_deref().unwrap_or(raw_spec).trim();

    let (expected_pkg, target_rc) = if let Some(alias_str) = effective_spec.strip_prefix("npm:") {
        let Ok((real_name, sub_spec)) = crate::aliases::split_npm_alias(alias_str) else {
            return false;
        };
        let sub = sub_spec.unwrap_or("*");
        let Some(t) = cached_target_rc(sub) else {
            return false;
        };
        (real_name, t)
    } else {
        let Some(t) = cached_target_rc(effective_spec) else {
            return false;
        };
        (dep_name.trim(), t)
    };

    if target_node.name != expected_pkg {
        return false;
    }

    if !crate::hoisting::node_satisfies_target(target_node, &target_rc) {
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
    let overrides_val = manifest.extra.get("overrides");
    let overrides = if overrides_val.is_some() {
        Overrides::from_json_value(overrides_val, Overrides::reference_specs(manifest))
    } else {
        Overrides::default()
    };
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

    #[test]
    fn test_dedupe_multi_candidate_placing_edge_uses_first_graph_edge() {
        let provider = crate::types::InMemoryPackageProvider::new();
        let mut solver = Solver::new(&provider, ResolverOptions::default(), Overrides::default());
        {
            let g = solver.graph_mut();
            for (loc, name) in [
                ("", "root"),
                ("node_modules/b-later-edge", "b-later-edge"),
                ("node_modules/a-first-edge", "a-first-edge"),
                ("node_modules/b-later-edge/node_modules/shared", "shared"),
                ("node_modules/a-first-edge/node_modules/shared", "shared"),
                ("node_modules/shared", "shared"),
            ] {
                g.add_node(
                    loc.to_string(),
                    Node {
                        location: loc.to_string(),
                        install_name: name.to_string(),
                        name: name.to_string(),
                        version: "1.0.0".to_string(),
                        parsed_version: Some(Version::parse("1.0.0").unwrap()),
                        ..Default::default()
                    },
                );
            }
            // Edge 0 is from a-first-edge; Edge 1 is from b-later-edge (whose candidate was indexed first).
            g.add_edge(DependencyEdge {
                from_location: "node_modules/a-first-edge".to_string(),
                to_location: "node_modules/a-first-edge/node_modules/shared".to_string(),
                install_name: "shared".to_string(),
                package_name: "shared".to_string(),
                spec: "^1.0.0".to_string(),
                dep_type: DependencyType::Prod,
            });
            g.add_edge(DependencyEdge {
                from_location: "node_modules/b-later-edge".to_string(),
                to_location: "node_modules/b-later-edge/node_modules/shared".to_string(),
                install_name: "shared".to_string(),
                package_name: "shared".to_string(),
                spec: "^1.0.0".to_string(),
                dep_type: DependencyType::Prod,
            });
        }
        let target = PackageTarget::Range(rnpm_core::semver::Range::parse("^1.0.0").unwrap());
        solver.dedupe_nested_compatible_nodes("node_modules/shared", "shared", "shared", &target);
        assert_eq!(
            solver.graph().incoming_edges_by_location["node_modules/shared"],
            vec![0, 1]
        );
        let placed_from = solver.placing_edge("node_modules/shared").unwrap().from;
        assert!(matches!(
            placed_from,
            crate::explain::EdgeFrom::Node(ref loc) if loc == "node_modules/a-first-edge"
        ));
    }

    #[test]
    fn test_solver_new_refreshes_mutated_overrides() {
        let provider = crate::types::InMemoryPackageProvider::new();
        let mut overrides = Overrides::default();
        overrides.rules.insert(
            "foo".to_string(),
            rnpm_core::overrides::OverrideValue::Exact("2.0.0".to_string()),
        );
        let solver = Solver::new(&provider, ResolverOptions::default(), overrides);
        assert_eq!(
            solver
                .overrides
                .resolve_override_precompiled_with_caller("foo", "^1.0.0", &["root"], None)
                .unwrap(),
            Some("2.0.0".to_string())
        );
    }
}
