//! Workspace dependency graph resolution, topological sorting, protocol handling,
//! and cycle detection for monorepos.

use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_core::workspace::WorkspaceMember;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use tracing::debug;

use crate::error::SolverError;
use crate::fast_util::{fast_map_with_capacity, FastMap};
use crate::graph::{DependencyEdge, DependencyGraph, DependencyType, Node, NodeFlags};
use crate::hoisting::{cached_target_rc, cached_version_rc};
use crate::overrides::Overrides;
use crate::solver::{ResolverOptions, Solver};
use crate::types::PackageMetadataProvider;

/// A directed workspace dependency graph among monorepo member packages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDependencyGraph {
    /// Workspace members indexed by package name.
    pub members: BTreeMap<String, WorkspaceMember>,
    /// Directed production dependencies among workspace members:
    /// member_name -> (sibling_name -> resolved_constraint)
    pub dependencies: BTreeMap<String, BTreeMap<String, String>>,
    /// Directed development dependencies among workspace members:
    /// member_name -> (sibling_name -> resolved_constraint)
    pub dev_dependencies: BTreeMap<String, BTreeMap<String, String>>,
    /// Directed peer dependencies among workspace members:
    /// member_name -> (sibling_name -> resolved_constraint)
    pub peer_dependencies: BTreeMap<String, BTreeMap<String, String>>,
    /// Deterministic topological order of workspace members (leaf dependencies first).
    pub topological_order: Vec<String>,
}

impl WorkspaceDependencyGraph {
    /// Construct and validate the workspace dependency graph from discovered members.
    ///
    /// Validates `workspace:*`, `workspace:^`, `workspace:~`, `workspace:<range>`, and `workspace:<version>`
    /// constraints, separates production dependencies from development dependencies, performs topological sorting,
    /// and gracefully breaks circular devDependency back-edges while detecting invalid production dependency cycles.
    pub fn construct(members: &[WorkspaceMember]) -> Result<Self, SolverError> {
        let mut member_map: BTreeMap<String, WorkspaceMember> = BTreeMap::new();
        for m in members {
            member_map.insert(m.name.clone(), m.clone());
        }

        let mut prod_deps: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut dev_deps: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut peer_deps: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

        // 1. Resolve workspace dependencies for each member (avoid cloning non-workspace specs)
        for member in members {
            let mut member_prod: BTreeMap<String, String> = BTreeMap::new();
            let mut member_dev: BTreeMap<String, String> = BTreeMap::new();
            let mut member_peer: BTreeMap<String, String> = BTreeMap::new();

            // Production dependencies: dependencies take priority over optional_dependencies.
            for (dep_name, dep_spec) in &member.manifest.dependencies {
                let trimmed_spec = dep_spec.trim();
                if let Some(ws_spec) = trimmed_spec.strip_prefix("workspace:") {
                    let sibling = member_map.get(dep_name).ok_or_else(|| {
                        SolverError::UnresolvedDependency {
                            name: dep_name.clone(),
                            spec: dep_spec.clone(),
                            message: format!(
                                "Workspace package '{}' not found in monorepo, requested by '{}' via '{}'",
                                dep_name, member.name, dep_spec
                            ),
                        }
                    })?;
                    validate_workspace_protocol_constraint(member, sibling, ws_spec, dep_spec)?;
                    member_prod.insert(dep_name.clone(), dep_spec.clone());
                } else if let Some(sibling) = member_map.get(dep_name) {
                    if is_sibling_compatible(sibling, trimmed_spec) {
                        member_prod.insert(dep_name.clone(), dep_spec.clone());
                    }
                }
            }
            for (dep_name, dep_spec) in &member.manifest.optional_dependencies {
                if member.manifest.dependencies.contains_key(dep_name) {
                    continue;
                }
                let trimmed_spec = dep_spec.trim();
                if let Some(ws_spec) = trimmed_spec.strip_prefix("workspace:") {
                    let sibling = member_map.get(dep_name).ok_or_else(|| {
                        SolverError::UnresolvedDependency {
                            name: dep_name.clone(),
                            spec: dep_spec.clone(),
                            message: format!(
                                "Workspace package '{}' not found in monorepo, requested by '{}' via '{}'",
                                dep_name, member.name, dep_spec
                            ),
                        }
                    })?;
                    validate_workspace_protocol_constraint(member, sibling, ws_spec, dep_spec)?;
                    member_prod.insert(dep_name.clone(), dep_spec.clone());
                } else if let Some(sibling) = member_map.get(dep_name) {
                    if is_sibling_compatible(sibling, trimmed_spec) {
                        member_prod.insert(dep_name.clone(), dep_spec.clone());
                    }
                }
            }

            // Collect dev_dependencies
            for (dep_name, dep_spec) in &member.manifest.dev_dependencies {
                // If already declared in production dependencies, skip adding to dev
                if member_prod.contains_key(dep_name) {
                    continue;
                }

                let trimmed_spec = dep_spec.trim();

                if let Some(ws_spec) = trimmed_spec.strip_prefix("workspace:") {
                    let sibling = member_map.get(dep_name).ok_or_else(|| {
                        SolverError::UnresolvedDependency {
                            name: dep_name.clone(),
                            spec: dep_spec.clone(),
                            message: format!(
                                "Workspace package '{}' not found in monorepo, requested by '{}' via '{}'",
                                dep_name, member.name, dep_spec
                            ),
                        }
                    })?;

                    validate_workspace_protocol_constraint(member, sibling, ws_spec, dep_spec)?;

                    member_dev.insert(dep_name.clone(), dep_spec.clone());
                } else if let Some(sibling) = member_map.get(dep_name) {
                    if is_sibling_compatible(sibling, trimmed_spec) {
                        member_dev.insert(dep_name.clone(), dep_spec.clone());
                    }
                }
            }

            // Collect peer_dependencies
            for (dep_name, dep_spec) in &member.manifest.peer_dependencies {
                let trimmed_spec = dep_spec.trim();

                if let Some(ws_spec) = trimmed_spec.strip_prefix("workspace:") {
                    if let Some(sibling) = member_map.get(dep_name) {
                        validate_workspace_protocol_constraint(member, sibling, ws_spec, dep_spec)?;
                        member_peer.insert(dep_name.clone(), dep_spec.clone());
                    }
                } else if let Some(sibling) = member_map.get(dep_name) {
                    if is_sibling_compatible(sibling, trimmed_spec) {
                        member_peer.insert(dep_name.clone(), dep_spec.clone());
                    }
                }
            }

            prod_deps.insert(member.name.clone(), member_prod);
            dev_deps.insert(member.name.clone(), member_dev);
            peer_deps.insert(member.name.clone(), member_peer);
        }

        // 2. Topological order. npm installs cyclic workspaces, so a
        // production cycle only loses its back-edges, as dev cycles do.
        let topological_order = topological_sort_with_dev_deps(&member_map, &prod_deps, &dev_deps)
            .or_else(|_| {
                let mut merged = dev_deps.clone();
                for (name, deps) in &prod_deps {
                    merged.entry(name.clone()).or_default().extend(deps.clone());
                }
                topological_sort_with_dev_deps(&member_map, &BTreeMap::new(), &merged)
            })?;

        Ok(Self {
            members: member_map,
            dependencies: prod_deps,
            dev_dependencies: dev_deps,
            peer_dependencies: peer_deps,
            topological_order,
        })
    }

    /// Check if a given package name is a member of this workspace.
    pub fn is_member(&self, name: &str) -> bool {
        self.members.contains_key(name)
    }

    /// Get a member by name.
    pub fn get_member(&self, name: &str) -> Option<&WorkspaceMember> {
        self.members.get(name)
    }

    /// Check whether a specific dependency spec on `sibling_name` is satisfied by the local workspace sibling.
    pub fn has_compatible_sibling(&self, sibling_name: &str, raw_spec: &str) -> bool {
        let trimmed = raw_spec.trim();
        if trimmed.starts_with("workspace:") {
            return true;
        }
        self.members
            .get(sibling_name)
            .is_some_and(|sibling| is_sibling_compatible(sibling, trimmed))
    }

    /// Check if member has an inter-workspace sibling dependency on sibling_name.
    pub fn has_sibling_edge(&self, member: &str, sibling_name: &str) -> bool {
        self.dependencies
            .get(member)
            .map(|d| d.contains_key(sibling_name))
            .unwrap_or(false)
            || self
                .dev_dependencies
                .get(member)
                .map(|d| d.contains_key(sibling_name))
                .unwrap_or(false)
            || self
                .peer_dependencies
                .get(member)
                .map(|d| d.contains_key(sibling_name))
                .unwrap_or(false)
    }

    /// Returns all sibling dependencies (both prod and dev) declared by member.
    pub fn all_dependencies_of(&self, member: &str) -> BTreeMap<String, String> {
        let mut all = BTreeMap::new();
        if let Some(deps) = self.dependencies.get(member) {
            all.extend(deps.clone());
        }
        if let Some(dev_deps) = self.dev_dependencies.get(member) {
            for (k, v) in dev_deps {
                all.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        if let Some(peer_deps) = self.peer_dependencies.get(member) {
            for (k, v) in peer_deps {
                all.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        all
    }
}

fn normalize_path_str(p: &str) -> String {
    p.replace('\\', "/").trim_matches('/').to_string()
}

fn normalize_relative_path(base: &str, relative: &str) -> String {
    let mut parts: Vec<&str> = base
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    for seg in relative.split(['/', '\\']) {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if parts.is_empty() {
                return String::new(); // Escaped root!
            }
            parts.pop();
        } else {
            parts.push(seg);
        }
    }
    parts.join("/")
}

fn is_safe_workspace_path(p: &str) -> bool {
    !p.is_empty() && !p.starts_with("../") && !p.starts_with('/') && !p.contains(':')
}

/// Validate `workspace:*`, `workspace:^`, `workspace:~`, `workspace:<range>`, and `workspace:<version>`
/// against sibling package version, handling relative path constraints safely.
fn validate_workspace_protocol_constraint(
    requester: &WorkspaceMember,
    sibling: &WorkspaceMember,
    ws_spec: &str,
    raw_spec: &str,
) -> Result<(), SolverError> {
    let clean = ws_spec.trim();

    // workspace:* allows any sibling version
    if clean == "*" || clean.is_empty() {
        return Ok(());
    }

    // Relative path check: workspace:../foo, workspace:./foo, or paths containing slashes
    if clean.starts_with('.')
        || clean.starts_with('/')
        || clean.contains('/')
        || clean.contains('\\')
    {
        let normalized = normalize_relative_path(&requester.relative_path, clean);
        let sibling_norm = normalize_path_str(&sibling.relative_path);

        if normalized.is_empty() || !is_safe_workspace_path(&normalized) {
            return Err(SolverError::UnresolvedDependency {
                name: sibling.name.clone(),
                spec: raw_spec.to_string(),
                message: format!(
                    "Workspace path constraint '{}' from '{}' references an invalid or escaping path",
                    clean, requester.name
                ),
            });
        }

        if normalized != sibling_norm {
            return Err(SolverError::UnresolvedDependency {
                name: sibling.name.clone(),
                spec: raw_spec.to_string(),
                message: format!(
                    "Workspace path constraint '{}' from '{}' does not resolve to sibling '{}' (resolved to '{}', but '{}' is at '{}')",
                    clean, requester.name, sibling.name, normalized, sibling.name, sibling.relative_path
                ),
            });
        }

        return Ok(());
    }

    let sibling_version_str = sibling.version.as_deref().ok_or_else(|| {
        SolverError::UnresolvedDependency {
            name: sibling.name.clone(),
            spec: raw_spec.to_string(),
            message: format!(
                "Workspace package '{}' has no version declared in its manifest, but '{}' requires '{}'",
                sibling.name, requester.name, raw_spec
            ),
        }
    })?;

    let sibling_ver =
        Version::parse(sibling_version_str).map_err(|e| SolverError::UnresolvedDependency {
            name: sibling.name.clone(),
            spec: raw_spec.to_string(),
            message: format!(
                "Invalid version '{}' in workspace package '{}': {e}",
                sibling_version_str, sibling.name
            ),
        })?;

    if clean == "^" {
        // workspace:^ resolves to ^<sibling_version>
        let range_str = format!("^{sibling_version_str}");
        let range = Range::parse(&range_str).map_err(SolverError::Semver)?;
        if !range.satisfies(&sibling_ver) {
            return Err(SolverError::UnresolvedDependency {
                name: sibling.name.clone(),
                spec: raw_spec.to_string(),
                message: format!(
                    "Workspace package '{}@{}' does not satisfy range '{range_str}' required by '{}'",
                    sibling.name, sibling_version_str, requester.name
                ),
            });
        }
    } else if clean == "~" {
        // workspace:~ resolves to ~<sibling_version>
        let range_str = format!("~{sibling_version_str}");
        let range = Range::parse(&range_str).map_err(SolverError::Semver)?;
        if !range.satisfies(&sibling_ver) {
            return Err(SolverError::UnresolvedDependency {
                name: sibling.name.clone(),
                spec: raw_spec.to_string(),
                message: format!(
                    "Workspace package '{}@{}' does not satisfy range '{range_str}' required by '{}'",
                    sibling.name, sibling_version_str, requester.name
                ),
            });
        }
    } else {
        // Explicit range or version, e.g. "workspace:^1.2.0" or "workspace:1.2.0"
        if let Ok(range) = Range::parse(clean) {
            if !range.satisfies(&sibling_ver) {
                return Err(SolverError::UnresolvedDependency {
                    name: sibling.name.clone(),
                    spec: raw_spec.to_string(),
                    message: format!(
                        "Workspace package '{}' version '{}' does not satisfy constraint '{}' required by '{}'",
                        sibling.name, sibling_version_str, clean, requester.name
                    ),
                });
            }
        } else if let Ok(expected_ver) = Version::parse(clean) {
            if sibling_ver != expected_ver {
                return Err(SolverError::UnresolvedDependency {
                    name: sibling.name.clone(),
                    spec: raw_spec.to_string(),
                    message: format!(
                        "Workspace package '{}' version '{}' does not match exact version '{}' required by '{}'",
                        sibling.name, sibling_version_str, clean, requester.name
                    ),
                });
            }
        } else {
            return Err(SolverError::UnresolvedDependency {
                name: sibling.name.clone(),
                spec: raw_spec.to_string(),
                message: format!(
                    "Invalid workspace constraint '{}' for package '{}' required by '{}'",
                    clean, sibling.name, requester.name
                ),
            });
        }
    }

    Ok(())
}

/// Check if a sibling's declared version satisfies a standard semver range specifier.
fn is_sibling_compatible(sibling: &WorkspaceMember, spec: &str) -> bool {
    if spec == "*" || spec == "latest" || spec.is_empty() {
        return true;
    }
    if let Some(ref ver_str) = sibling.version {
        if let Some(ver) = cached_version_rc(ver_str) {
            if let Some(target) = cached_target_rc(spec) {
                match target.as_ref() {
                    rnpm_core::spec::PackageTarget::Range(range) => return range.satisfies(&ver),
                    rnpm_core::spec::PackageTarget::Version(expected) => {
                        return ver.as_ref() == expected;
                    }
                    _ => {}
                }
            }
            if let Ok(range) = Range::parse(spec) {
                return range.satisfies(&ver);
            }
            if let Ok(expected) = Version::parse(spec) {
                return ver.as_ref() == &expected;
            }
        }
    }
    false
}

/// Performs topological sort across workspace members and detects circular dependencies.
///
/// Returns members ordered with leaf packages first (dependencies before dependents).
pub fn topological_sort(
    members: &BTreeMap<String, WorkspaceMember>,
    deps: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<Vec<String>, SolverError> {
    let empty_dev = BTreeMap::new();
    topological_sort_with_dev_deps(members, deps, &empty_dev)
}

/// Performs topological sort across workspace members with support for circular devDependencies.
///
/// 1. Verifies that the production dependency graph is an acyclic DAG.
///    Any cycle strictly among production dependencies returns an `Err(SolverError::CycleDetected)`.
/// 2. Merges devDependencies into the execution graph, gracefully breaking any back-edges that
///    would introduce cycles.
/// 3. Returns members ordered with leaf packages first (dependencies before dependents).
pub fn topological_sort_with_dev_deps(
    members: &BTreeMap<String, WorkspaceMember>,
    prod_deps: &BTreeMap<String, BTreeMap<String, String>>,
    dev_deps: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<Vec<String>, SolverError> {
    // 1. Check for self-cycles in production dependencies
    for (name, dep_map) in prod_deps {
        if dep_map.contains_key(name) {
            return Err(SolverError::CycleDetected(format!(
                "Circular workspace dependency detected: {name} -> {name}"
            )));
        }
    }

    // Collect deterministic lexicographically sorted node table (`BTreeSet` preserves exact DFS order).
    let mut name_set: BTreeSet<&str> = BTreeSet::new();
    for k in members.keys() {
        name_set.insert(k.as_str());
    }
    for (u, deps) in prod_deps.iter().chain(dev_deps.iter()) {
        name_set.insert(u.as_str());
        for v in deps.keys() {
            name_set.insert(v.as_str());
        }
    }
    let id_to_name: Vec<&str> = name_set.into_iter().collect();
    let total = id_to_name.len();
    let member_limit = members.len();
    let mut name_to_id: FastMap<&str, usize> = fast_map_with_capacity(total);
    for (i, &n) in id_to_name.iter().enumerate() {
        name_to_id.insert(n, i);
    }

    let mut prod_adj: Vec<Vec<usize>> = vec![Vec::new(); total];
    for (u, dep_map) in prod_deps {
        if let Some(&u_id) = name_to_id.get(u.as_str()) {
            let list = &mut prod_adj[u_id];
            list.reserve(dep_map.len());
            for v in dep_map.keys() {
                if let Some(&v_id) = name_to_id.get(v.as_str()) {
                    list.push(v_id);
                }
            }
        }
    }

    // 2. Cycle detection strictly on production dependencies
    let mut state: Vec<u8> = vec![0; total];
    let mut stack: Vec<usize> = Vec::with_capacity(total.min(64));
    let mut dummy_order: Vec<usize> = Vec::with_capacity(total);

    fn dfs_visit_id(
        node: usize,
        adj: &[Vec<usize>],
        id_to_name: &[&str],
        state: &mut [u8],
        stack: &mut Vec<usize>,
        order: &mut Vec<usize>,
    ) -> Result<(), SolverError> {
        state[node] = 1;
        stack.push(node);

        for &dep in &adj[node] {
            match state[dep] {
                1 => {
                    let start_idx = stack.iter().position(|&s| s == dep).unwrap_or(0);
                    let mut cycle: Vec<&str> =
                        stack[start_idx..].iter().map(|&id| id_to_name[id]).collect();
                    cycle.push(id_to_name[dep]);
                    return Err(SolverError::CycleDetected(format!(
                        "Circular workspace dependency detected: {}",
                        cycle.join(" -> ")
                    )));
                }
                0 => {
                    dfs_visit_id(dep, adj, id_to_name, state, stack, order)?;
                }
                _ => {}
            }
        }

        state[node] = 2;
        stack.pop();
        order.push(node);
        Ok(())
    }

    for name in members.keys() {
        let id = name_to_id[name.as_str()];
        if state[id] == 0 {
            dfs_visit_id(id, &prod_adj, &id_to_name, &mut state, &mut stack, &mut dummy_order)?;
        }
    }

    // 3. Construct combined graph adding dev dependencies that do not create cycles
    let mut combined_adj = prod_adj;
    let mut visited_gen: Vec<u32> = vec![0; total];
    let mut gen_counter: u32 = 0;
    let mut bfs_queue: VecDeque<usize> = VecDeque::with_capacity(32.min(total));

    fn has_path_id(
        from: usize,
        to: usize,
        adj: &[Vec<usize>],
        visited_gen: &mut [u32],
        gen_counter: &mut u32,
        queue: &mut VecDeque<usize>,
    ) -> bool {
        if from == to {
            return true;
        }
        *gen_counter = gen_counter.wrapping_add(1);
        if *gen_counter == 0 {
            visited_gen.fill(0);
            *gen_counter = 1;
        }
        let stamp = *gen_counter;
        queue.clear();
        visited_gen[from] = stamp;
        queue.push_back(from);

        while let Some(curr) = queue.pop_front() {
            for &next in &adj[curr] {
                if next == to {
                    return true;
                }
                if visited_gen[next] != stamp {
                    visited_gen[next] = stamp;
                    queue.push_back(next);
                }
            }
        }
        false
    }

    for (u, v_map) in dev_deps {
        let Some(&u_id) = name_to_id.get(u.as_str()) else {
            continue;
        };
        for v in v_map.keys() {
            let Some(&v_id) = name_to_id.get(v.as_str()) else {
                continue;
            };
            if u_id == v_id {
                continue;
            }
            if has_path_id(
                v_id,
                u_id,
                &combined_adj,
                &mut visited_gen,
                &mut gen_counter,
                &mut bfs_queue,
            ) {
                debug!(
                    "Gracefully broke circular workspace devDependency back-edge: {} -> {}",
                    u, v
                );
            } else if !combined_adj[u_id].contains(&v_id) {
                combined_adj[u_id].push(v_id);
            }
        }
    }

    // Preserve deterministic lexicographical neighbor traversal matching BTreeSet.
    if !dev_deps.is_empty() {
        for list in &mut combined_adj {
            if list.len() > 1 {
                list.sort_unstable();
            }
        }
    }

    // 4. Run topological sort on the combined acyclic graph
    state.fill(0);
    stack.clear();
    let mut final_order_ids: Vec<usize> = Vec::with_capacity(member_limit);

    for name in members.keys() {
        let id = name_to_id[name.as_str()];
        if state[id] == 0 {
            dfs_visit_id(
                id,
                &combined_adj,
                &id_to_name,
                &mut state,
                &mut stack,
                &mut final_order_ids,
            )?;
        }
    }

    Ok(final_order_ids
        .into_iter()
        .map(|id| id_to_name[id].to_string())
        .collect())
}

/// Resolves a full workspace dependency graph including sibling linking and cross-workspace external package hoisting.
pub fn resolve_workspace_graph<P: PackageMetadataProvider>(
    root_manifest: &Manifest,
    members: &[WorkspaceMember],
    provider: &P,
    options: &ResolverOptions,
) -> Result<DependencyGraph, SolverError> {
    // 1. Index workspace members by name without cloning WorkspaceMember / Manifest structs
    let mut member_by_name: crate::fast_util::FastMap<&str, &WorkspaceMember> =
        crate::fast_util::fast_map_with_capacity(members.len());
    for m in members {
        member_by_name.insert(m.name.as_str(), m);
    }

    let mut graph = DependencyGraph::new();

    let root_name = root_manifest
        .name
        .clone()
        .unwrap_or_else(|| "root".to_string());
    let root_version = root_manifest
        .version
        .clone()
        .unwrap_or_else(|| "1.0.0".to_string());

    let root_parsed_ver = cached_version_rc(&root_version).map(|rc| (*rc).clone());
    // 2. Insert root package node at ""
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
        libc: None,
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
        parsed_version: root_parsed_ver,
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
    graph.nodes.insert(String::new(), root_node);

    // 3. Insert workspace members at their relative paths and create link nodes in node_modules
    for member in members {
        let member_loc = member.relative_path.clone();
        let link_loc = format!("node_modules/{}", member.name);
        let mem_ver = member
            .version
            .clone()
            .unwrap_or_else(|| "0.0.0".to_string());
        let mem_parsed_ver = cached_version_rc(&mem_ver).map(|rc| (*rc).clone());

        let member_node = Node {
            location: member_loc.clone(),
            install_name: member.name.clone(),
            name: member.name.clone(),
            version: mem_ver.clone(),
            parsed_version: mem_parsed_ver.clone(),
            resolved: None,
            integrity: None,
            flags: NodeFlags {
                has_install_script: member.manifest.scripts.contains_key("install")
                    || member.manifest.scripts.contains_key("preinstall")
                    || member.manifest.scripts.contains_key("postinstall"),
                ..Default::default()
            },
            dependencies: member.manifest.dependencies.clone(),
            dev_dependencies: member.manifest.dev_dependencies.clone(),
            peer_dependencies: member.manifest.peer_dependencies.clone(),
            peer_dependencies_meta: member.manifest.peer_dependencies_meta.clone(),
            optional_dependencies: member.manifest.optional_dependencies.clone(),
            os: member.manifest.os.clone(),
            cpu: member.manifest.cpu.clone(),
            libc: None,
            bin: member.manifest.bin.clone().map(|b| match b {
                rnpm_core::manifest::PackageBin::Single(s) => rnpm_lockfile::PackageBin::Single(s),
                rnpm_core::manifest::PackageBin::Map(m) => rnpm_lockfile::PackageBin::Map(m),
            }),
            license: member
                .manifest
                .extra
                .get("license")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            engines: member.manifest.engines.clone(),
            extra: {
                let mut extra = member.manifest.extra.clone();
                if let Some(ref bd) = member.manifest.bundled_dependencies {
                    if let Ok(val) = serde_json::to_value(bd) {
                        extra.insert("bundleDependencies".to_string(), val);
                    }
                }
                extra
            },
        };
        graph.nodes.insert(member_loc.clone(), member_node);

        // Link node in root node_modules/<member.name>
        let link_node = Node {
            location: link_loc.clone(),
            install_name: member.name.clone(),
            name: member.name.clone(),
            version: mem_ver,
            parsed_version: mem_parsed_ver,
            resolved: Some(member_loc.clone()),
            integrity: None,
            flags: NodeFlags {
                link: true,
                ..Default::default()
            },
            dependencies: member.manifest.dependencies.clone(),
            ..Default::default()
        };
        graph.nodes.insert(link_loc.clone(), link_node);

        // Edge from root to workspace member link
        graph.edges.push(DependencyEdge {
            from_location: String::new(),
            to_location: link_loc.clone(),
            install_name: member.name.clone(),
            package_name: member.name.clone(),
            spec: format!("workspace:{}", member.version.as_deref().unwrap_or("*")),
            dep_type: DependencyType::Prod,
        });

        let mut sibling_prod: BTreeMap<&str, &str> = BTreeMap::new();
        for (dep_name, dep_spec) in &member.manifest.dependencies {
            let trimmed_spec = dep_spec.trim();
            if let Some(ws_spec) = trimmed_spec.strip_prefix("workspace:") {
                let sibling = member_by_name.get(dep_name.as_str()).copied().ok_or_else(|| {
                    SolverError::UnresolvedDependency {
                        name: dep_name.clone(),
                        spec: dep_spec.clone(),
                        message: format!(
                            "Workspace package '{}' not found in monorepo, requested by '{}' via '{}'",
                            dep_name, member.name, dep_spec
                        ),
                    }
                })?;
                validate_workspace_protocol_constraint(member, sibling, ws_spec, dep_spec)?;
                sibling_prod.insert(dep_name.as_str(), dep_spec.as_str());
            } else if let Some(&sibling) = member_by_name.get(dep_name.as_str()) {
                if is_sibling_compatible(sibling, trimmed_spec) {
                    sibling_prod.insert(dep_name.as_str(), dep_spec.as_str());
                }
            }
        }
        for (dep_name, dep_spec) in &member.manifest.optional_dependencies {
            if member.manifest.dependencies.contains_key(dep_name) {
                continue;
            }
            let trimmed_spec = dep_spec.trim();
            if let Some(ws_spec) = trimmed_spec.strip_prefix("workspace:") {
                let sibling = member_by_name.get(dep_name.as_str()).copied().ok_or_else(|| {
                    SolverError::UnresolvedDependency {
                        name: dep_name.clone(),
                        spec: dep_spec.clone(),
                        message: format!(
                            "Workspace package '{}' not found in monorepo, requested by '{}' via '{}'",
                            dep_name, member.name, dep_spec
                        ),
                    }
                })?;
                validate_workspace_protocol_constraint(member, sibling, ws_spec, dep_spec)?;
                sibling_prod.insert(dep_name.as_str(), dep_spec.as_str());
            } else if let Some(&sibling) = member_by_name.get(dep_name.as_str()) {
                if is_sibling_compatible(sibling, trimmed_spec) {
                    sibling_prod.insert(dep_name.as_str(), dep_spec.as_str());
                }
            }
        }
        for (&sibling_name, &spec) in &sibling_prod {
            let sibling_link_loc = format!("node_modules/{sibling_name}");
            graph.edges.push(DependencyEdge {
                from_location: member_loc.clone(),
                to_location: sibling_link_loc,
                install_name: sibling_name.to_string(),
                package_name: sibling_name.to_string(),
                spec: spec.to_string(),
                dep_type: DependencyType::Prod,
            });
        }

        let mut sibling_dev: BTreeMap<&str, &str> = BTreeMap::new();
        for (dep_name, dep_spec) in &member.manifest.dev_dependencies {
            if sibling_prod.contains_key(dep_name.as_str()) {
                continue;
            }
            let trimmed_spec = dep_spec.trim();
            if let Some(ws_spec) = trimmed_spec.strip_prefix("workspace:") {
                let sibling = member_by_name.get(dep_name.as_str()).copied().ok_or_else(|| {
                    SolverError::UnresolvedDependency {
                        name: dep_name.clone(),
                        spec: dep_spec.clone(),
                        message: format!(
                            "Workspace package '{}' not found in monorepo, requested by '{}' via '{}'",
                            dep_name, member.name, dep_spec
                        ),
                    }
                })?;
                validate_workspace_protocol_constraint(member, sibling, ws_spec, dep_spec)?;
                sibling_dev.insert(dep_name.as_str(), dep_spec.as_str());
            } else if let Some(&sibling) = member_by_name.get(dep_name.as_str()) {
                if is_sibling_compatible(sibling, trimmed_spec) {
                    sibling_dev.insert(dep_name.as_str(), dep_spec.as_str());
                }
            }
        }
        for (&sibling_name, &spec) in &sibling_dev {
            let sibling_link_loc = format!("node_modules/{sibling_name}");
            graph.edges.push(DependencyEdge {
                from_location: member_loc.clone(),
                to_location: sibling_link_loc,
                install_name: sibling_name.to_string(),
                package_name: sibling_name.to_string(),
                spec: spec.to_string(),
                dep_type: DependencyType::Dev,
            });
        }

        for (dep_name, dep_spec) in &member.manifest.peer_dependencies {
            if sibling_prod.contains_key(dep_name.as_str())
                || sibling_dev.contains_key(dep_name.as_str())
            {
                continue;
            }
            let Some(&sibling) = member_by_name.get(dep_name.as_str()) else {
                continue;
            };
            let trimmed_spec = dep_spec.trim();
            let compatible = if let Some(ws_spec) = trimmed_spec.strip_prefix("workspace:") {
                validate_workspace_protocol_constraint(member, sibling, ws_spec, dep_spec)?;
                true
            } else {
                is_sibling_compatible(sibling, trimmed_spec)
            };
            if compatible {
                let sibling_link_loc = format!("node_modules/{dep_name}");
                let is_opt = member
                    .manifest
                    .peer_dependencies_meta
                    .get(dep_name)
                    .map(|m| m.optional)
                    .unwrap_or(false);
                let dep_type = if is_opt {
                    DependencyType::PeerOptional
                } else {
                    DependencyType::Peer
                };
                graph.edges.push(DependencyEdge {
                    from_location: member_loc.clone(),
                    to_location: sibling_link_loc,
                    install_name: dep_name.clone(),
                    package_name: dep_name.clone(),
                    spec: dep_spec.clone(),
                    dep_type,
                });
            }
        }
    }

    // 4. Resolve external third-party dependencies from root and all workspace members
    let overrides_val = root_manifest.extra.get("overrides");
    let overrides = if overrides_val.is_some() {
        let mut root_refs = Overrides::reference_specs(root_manifest);
        for member in members {
            let mem_ver = member.version.as_deref().unwrap_or("*");
            root_refs
                .entry(member.name.clone())
                .or_insert_with(|| format!("workspace:{mem_ver}"));
        }
        Overrides::from_json_value(overrides_val, root_refs)
    } else {
        Overrides::default()
    };
    let mut solver = Solver::new(provider, options.clone(), overrides).with_graph_defer_indices(graph);

    let root_ancestor_head = solver.intern_ancestor_chain(&[&root_name]);

    // Enqueue root external dependencies borrowing manifest strings in sorted order
    let mut root_deps: BTreeMap<&str, (&str, DependencyType)> = BTreeMap::new();
    let is_ws_member = |name: &str, spec: &str| {
        member_by_name.contains_key(name) || spec.trim().starts_with("workspace:")
    };
    if options.dev {
        for (k, v) in &root_manifest.dev_dependencies {
            if !is_ws_member(k, v) {
                root_deps.insert(k.as_str(), (v.as_str(), DependencyType::Dev));
            }
        }
    }
    for (k, v) in &root_manifest.dependencies {
        if !is_ws_member(k, v) {
            root_deps.insert(k.as_str(), (v.as_str(), DependencyType::Prod));
        }
    }
    for (k, v) in &root_manifest.optional_dependencies {
        if !is_ws_member(k, v) {
            root_deps.insert(k.as_str(), (v.as_str(), DependencyType::Optional));
        }
    }
    if !options.legacy_peer_deps {
        for (k, v) in &root_manifest.peer_dependencies {
            if !is_ws_member(k, v) {
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
                root_deps.entry(k.as_str()).or_insert((v.as_str(), p_type));
            }
        }
    }

    for (install_name, (raw_spec, dep_type)) in root_deps {
        solver.enqueue_root_task_borrowed(
            "",
            &root_name,
            install_name,
            raw_spec,
            dep_type,
            root_ancestor_head,
        );
    }

    // Enqueue member external dependencies directly into deferred workspace storage
    let has_compatible_sibling = |sibling_name: &str, raw_spec: &str| {
        let trimmed = raw_spec.trim();
        if trimmed.starts_with("workspace:") {
            return true;
        }
        member_by_name
            .get(sibling_name)
            .is_some_and(|sibling| is_sibling_compatible(sibling, trimmed))
    };
    let mut member_deps: BTreeMap<&str, (&str, DependencyType)> = BTreeMap::new();
    for member in members {
        let member_ancestor_head = solver.intern_ancestor_chain(&[&root_name, &member.name]);
        member_deps.clear();

        if options.dev {
            for (k, v) in &member.manifest.dev_dependencies {
                if !has_compatible_sibling(k, v) {
                    member_deps.insert(k.as_str(), (v.as_str(), DependencyType::Dev));
                }
            }
        }
        for (k, v) in &member.manifest.dependencies {
            if !has_compatible_sibling(k, v) {
                member_deps.insert(k.as_str(), (v.as_str(), DependencyType::Prod));
            }
        }
        for (k, v) in &member.manifest.optional_dependencies {
            if !has_compatible_sibling(k, v) {
                member_deps.insert(k.as_str(), (v.as_str(), DependencyType::Optional));
            }
        }
        if !options.legacy_peer_deps {
            for (k, v) in &member.manifest.peer_dependencies {
                if !has_compatible_sibling(k, v) {
                    let is_opt_peer = member
                        .manifest
                        .peer_dependencies_meta
                        .get(k)
                        .map(|m| m.optional)
                        .unwrap_or(false);
                    let p_type = if is_opt_peer {
                        DependencyType::PeerOptional
                    } else {
                        DependencyType::Peer
                    };
                    member_deps.entry(k.as_str()).or_insert((v.as_str(), p_type));
                }
            }
        }

        for (install_name, (raw_spec, dep_type)) in &member_deps {
            solver.enqueue_deferred_workspace_task(
                &member.relative_path,
                &member.name,
                install_name,
                raw_spec,
                *dep_type,
                member_ancestor_head,
            );
        }
    }

    // Process external dependency queue
    solver.resolve_tasks()?;

    Ok(solver.into_graph())
}
