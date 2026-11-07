//! Workspace dependency graph resolution, topological sorting, protocol handling,
//! and cycle detection for monorepos.

use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_core::workspace::WorkspaceMember;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use tracing::debug;

use crate::error::SolverError;
use crate::graph::{DependencyEdge, DependencyGraph, DependencyType, Node, NodeFlags};
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

        // 1. Resolve workspace dependencies for each member
        for member in members {
            let mut member_prod: BTreeMap<String, String> = BTreeMap::new();
            let mut member_dev: BTreeMap<String, String> = BTreeMap::new();

            // Collect production dependencies (dependencies + optional_dependencies)
            let mut raw_prod = BTreeMap::new();
            for (k, v) in &member.manifest.dependencies {
                raw_prod.insert(k.clone(), v.clone());
            }
            for (k, v) in &member.manifest.optional_dependencies {
                raw_prod.entry(k.clone()).or_insert_with(|| v.clone());
            }

            for (dep_name, dep_spec) in raw_prod {
                let trimmed_spec = dep_spec.trim();

                if let Some(ws_spec) = trimmed_spec.strip_prefix("workspace:") {
                    let sibling = member_map.get(&dep_name).ok_or_else(|| {
                        SolverError::UnresolvedDependency {
                            name: dep_name.clone(),
                            spec: dep_spec.clone(),
                            message: format!(
                                "Workspace package '{}' not found in monorepo, requested by '{}' via '{}'",
                                dep_name, member.name, dep_spec
                            ),
                        }
                    })?;

                    // Validate version constraint
                    validate_workspace_protocol_constraint(member, sibling, ws_spec, &dep_spec)?;

                    member_prod.insert(dep_name, dep_spec);
                } else if let Some(sibling) = member_map.get(&dep_name) {
                    // Check if a normal semver spec satisfies the local sibling version
                    if is_sibling_compatible(sibling, trimmed_spec) {
                        member_prod.insert(dep_name, dep_spec);
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

            prod_deps.insert(member.name.clone(), member_prod);
            dev_deps.insert(member.name.clone(), member_dev);
        }

        // 2. Perform topological sorting and cycle detection
        let topological_order = topological_sort_with_dev_deps(&member_map, &prod_deps, &dev_deps)?;

        Ok(Self {
            members: member_map,
            dependencies: prod_deps,
            dev_dependencies: dev_deps,
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
        if let Ok(ver) = Version::parse(ver_str) {
            if let Ok(range) = Range::parse(spec) {
                return range.satisfies(&ver);
            }
            if let Ok(expected) = Version::parse(spec) {
                return ver == expected;
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

    // 2. Cycle detection strictly on production dependencies
    let mut state: BTreeMap<String, u8> = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();
    let mut dummy_order: Vec<String> = Vec::new();

    for name in members.keys() {
        state.insert(name.clone(), 0);
    }

    for name in members.keys() {
        if state.get(name) == Some(&0) {
            dfs_visit(name, prod_deps, &mut state, &mut stack, &mut dummy_order)?;
        }
    }

    // 3. Construct combined graph for execution ordering by adding dev dependencies that do not create cycles
    let mut adj: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for name in members.keys() {
        let mut targets = BTreeSet::new();
        if let Some(p_deps) = prod_deps.get(name) {
            for dep in p_deps.keys() {
                targets.insert(dep.clone());
            }
        }
        adj.insert(name.clone(), targets);
    }

    fn has_path(from: &str, to: &str, adj: &BTreeMap<String, BTreeSet<String>>) -> bool {
        if from == to {
            return true;
        }
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        visited.insert(from.to_string());
        queue.push_back(from.to_string());

        while let Some(curr) = queue.pop_front() {
            if let Some(neighbors) = adj.get(&curr) {
                for next in neighbors {
                    if next == to {
                        return true;
                    }
                    if visited.insert(next.clone()) {
                        queue.push_back(next.clone());
                    }
                }
            }
        }
        false
    }

    // For each dev dependency edge (u -> v, meaning u depends on v):
    // If v can reach u, then adding u -> v creates a cycle. So we gracefully skip (break) it!
    for (u, v_map) in dev_deps {
        for v in v_map.keys() {
            if u == v {
                continue;
            }
            if has_path(v, u, &adj) {
                debug!(
                    "Gracefully broke circular workspace devDependency back-edge: {} -> {}",
                    u, v
                );
            } else {
                adj.entry(u.clone()).or_default().insert(v.clone());
            }
        }
    }

    // 4. Run topological sort on the combined acyclic graph
    let mut combined_deps: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (name, targets) in &adj {
        let mut m = BTreeMap::new();
        for target in targets {
            m.insert(target.clone(), String::new());
        }
        combined_deps.insert(name.clone(), m);
    }

    let mut final_state: BTreeMap<String, u8> = BTreeMap::new();
    let mut final_stack: Vec<String> = Vec::new();
    let mut final_order: Vec<String> = Vec::new();

    for name in members.keys() {
        final_state.insert(name.clone(), 0);
    }

    for name in members.keys() {
        if final_state.get(name) == Some(&0) {
            dfs_visit(
                name,
                &combined_deps,
                &mut final_state,
                &mut final_stack,
                &mut final_order,
            )?;
        }
    }

    Ok(final_order)
}

fn dfs_visit(
    node: &str,
    deps: &BTreeMap<String, BTreeMap<String, String>>,
    state: &mut BTreeMap<String, u8>,
    stack: &mut Vec<String>,
    order: &mut Vec<String>,
) -> Result<(), SolverError> {
    state.insert(node.to_string(), 1);
    stack.push(node.to_string());

    if let Some(node_deps) = deps.get(node) {
        for dep_name in node_deps.keys() {
            match state.get(dep_name).copied().unwrap_or(0) {
                1 => {
                    // Cycle detected!
                    let start_idx = stack.iter().position(|s| s == dep_name).unwrap_or(0);
                    let mut cycle: Vec<String> = stack[start_idx..].to_vec();
                    cycle.push(dep_name.clone());
                    return Err(SolverError::CycleDetected(format!(
                        "Circular workspace dependency detected: {}",
                        cycle.join(" -> ")
                    )));
                }
                0 => {
                    dfs_visit(dep_name, deps, state, stack, order)?;
                }
                _ => {}
            }
        }
    }

    state.insert(node.to_string(), 2);
    stack.pop();
    order.push(node.to_string());
    Ok(())
}

/// Resolves a full workspace dependency graph including sibling linking and cross-workspace external package hoisting.
pub fn resolve_workspace_graph<P: PackageMetadataProvider>(
    root_manifest: &Manifest,
    members: &[WorkspaceMember],
    provider: &P,
    options: &ResolverOptions,
) -> Result<DependencyGraph, SolverError> {
    // 1. Construct and validate workspace graph
    let ws_graph = WorkspaceDependencyGraph::construct(members)?;

    let mut graph = DependencyGraph::new();

    let root_name = root_manifest
        .name
        .clone()
        .unwrap_or_else(|| "root".to_string());
    let root_version = root_manifest
        .version
        .clone()
        .unwrap_or_else(|| "1.0.0".to_string());
    let parsed_root_version = Version::parse(&root_version).ok();

    // 2. Insert root package node at ""
    let root_node = Node {
        location: String::new(),
        install_name: root_name.clone(),
        name: root_name.clone(),
        version: root_version,
        resolved: None,
        integrity: None,
        flags: NodeFlags::default(),
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
        parsed_version: parsed_root_version,
        extra: root_manifest.extra.clone(),
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
        let parsed_mem_ver = Version::parse(&mem_ver).ok();

        let member_node = Node {
            location: member_loc.clone(),
            install_name: member.name.clone(),
            name: member.name.clone(),
            version: mem_ver.clone(),
            parsed_version: parsed_mem_ver.clone(),
            resolved: None,
            integrity: None,
            flags: NodeFlags::default(),
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
            ..Default::default()
        };
        graph.nodes.insert(member_loc.clone(), member_node);

        // Link node in root node_modules/<member.name>
        let link_node = Node {
            location: link_loc.clone(),
            install_name: member.name.clone(),
            name: member.name.clone(),
            version: mem_ver,
            parsed_version: parsed_mem_ver,
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

        // Add production edges between workspace members
        if let Some(sibling_deps) = ws_graph.dependencies.get(&member.name) {
            for (sibling_name, spec) in sibling_deps {
                let sibling_link_loc = format!("node_modules/{sibling_name}");
                graph.edges.push(DependencyEdge {
                    from_location: member_loc.clone(),
                    to_location: sibling_link_loc,
                    install_name: sibling_name.clone(),
                    package_name: sibling_name.clone(),
                    spec: spec.clone(),
                    dep_type: DependencyType::Prod,
                });
            }
        }

        // Add development edges between workspace members
        if let Some(sibling_dev_deps) = ws_graph.dev_dependencies.get(&member.name) {
            for (sibling_name, spec) in sibling_dev_deps {
                let sibling_link_loc = format!("node_modules/{sibling_name}");
                if !graph.edges.iter().any(|e| {
                    e.from_location == member_loc
                        && e.to_location == sibling_link_loc
                        && e.install_name == *sibling_name
                }) {
                    graph.edges.push(DependencyEdge {
                        from_location: member_loc.clone(),
                        to_location: sibling_link_loc,
                        install_name: sibling_name.clone(),
                        package_name: sibling_name.clone(),
                        spec: spec.clone(),
                        dep_type: DependencyType::Dev,
                    });
                }
            }
        }
    }

    // 4. Resolve external third-party dependencies from root and all workspace members
    let overrides = Overrides::from_manifest(root_manifest)?;
    let mut solver = Solver::new(provider, options.clone(), overrides).with_graph(graph);

    let root_ancestors = std::sync::Arc::new(vec![root_name.clone()]);

    // Enqueue root external dependencies
    let mut root_deps: BTreeMap<String, (String, DependencyType)> = BTreeMap::new();
    if options.dev {
        for (k, v) in &root_manifest.dev_dependencies {
            let is_ws = ws_graph.is_member(k) || v.trim().starts_with("workspace:");
            if !is_ws {
                root_deps.insert(k.clone(), (v.clone(), DependencyType::Dev));
            }
        }
    }
    for (k, v) in &root_manifest.dependencies {
        let is_ws = ws_graph.is_member(k) || v.trim().starts_with("workspace:");
        if !is_ws {
            root_deps.insert(k.clone(), (v.clone(), DependencyType::Prod));
        }
    }
    for (k, v) in &root_manifest.optional_dependencies {
        let is_ws = ws_graph.is_member(k) || v.trim().starts_with("workspace:");
        if !is_ws {
            root_deps.insert(k.clone(), (v.clone(), DependencyType::Optional));
        }
    }
    if !options.legacy_peer_deps {
        for (k, v) in &root_manifest.peer_dependencies {
            let is_ws = ws_graph.is_member(k) || v.trim().starts_with("workspace:");
            if !is_ws {
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
    }

    for (install_name, (raw_spec, dep_type)) in root_deps {
        solver.enqueue_task(
            String::new(),
            root_name.clone(),
            install_name,
            raw_spec,
            dep_type,
            root_ancestors.clone(),
        );
    }

    // Enqueue member external dependencies
    for member in members {
        let member_ancestors = std::sync::Arc::new(vec![root_name.clone(), member.name.clone()]);
        let mut member_deps: BTreeMap<String, (String, DependencyType)> = BTreeMap::new();

        if options.dev {
            for (k, v) in &member.manifest.dev_dependencies {
                let is_ws = ws_graph.has_sibling_edge(&member.name, k)
                    || v.trim().starts_with("workspace:");
                if !is_ws {
                    member_deps.insert(k.clone(), (v.clone(), DependencyType::Dev));
                }
            }
        }
        for (k, v) in &member.manifest.dependencies {
            let is_ws =
                ws_graph.has_sibling_edge(&member.name, k) || v.trim().starts_with("workspace:");
            if !is_ws {
                member_deps.insert(k.clone(), (v.clone(), DependencyType::Prod));
            }
        }
        for (k, v) in &member.manifest.optional_dependencies {
            let is_ws =
                ws_graph.has_sibling_edge(&member.name, k) || v.trim().starts_with("workspace:");
            if !is_ws {
                member_deps.insert(k.clone(), (v.clone(), DependencyType::Optional));
            }
        }
        if !options.legacy_peer_deps {
            for (k, v) in &member.manifest.peer_dependencies {
                let is_ws = ws_graph.has_sibling_edge(&member.name, k)
                    || v.trim().starts_with("workspace:");
                if !is_ws {
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
                    member_deps
                        .entry(k.clone())
                        .or_insert_with(|| (v.clone(), p_type));
                }
            }
        }

        for (install_name, (raw_spec, dep_type)) in member_deps {
            solver.enqueue_task(
                member.relative_path.clone(),
                member.name.clone(),
                install_name,
                raw_spec,
                dep_type,
                member_ancestors.clone(),
            );
        }
    }

    // Process external dependency queue
    solver.resolve_tasks()?;

    Ok(solver.into_graph())
}
