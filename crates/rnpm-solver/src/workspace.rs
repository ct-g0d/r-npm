//! Workspace dependency graph resolution, topological sorting, protocol handling,
//! and cycle detection for monorepos.

use std::collections::BTreeMap;
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_core::workspace::WorkspaceMember;

use crate::error::SolverError;
use crate::graph::{DependencyEdge, DependencyGraph, DependencyType, Node, NodeFlags};
use crate::solver::ResolverOptions;
use crate::types::PackageMetadataProvider;

/// A directed workspace dependency graph among monorepo member packages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDependencyGraph {
    /// Workspace members indexed by package name.
    pub members: BTreeMap<String, WorkspaceMember>,
    /// Directed dependencies among workspace members:
    /// member_name -> (sibling_name -> resolved_constraint)
    pub dependencies: BTreeMap<String, BTreeMap<String, String>>,
    /// Deterministic topological order of workspace members (leaf dependencies first).
    pub topological_order: Vec<String>,
}

impl WorkspaceDependencyGraph {
    /// Construct and validate the workspace dependency graph from discovered members.
    ///
    /// Validates `workspace:*`, `workspace:^`, `workspace:~` and semver protocol constraints,
    /// performs topological sorting, and detects circular workspace dependencies.
    pub fn construct(members: &[WorkspaceMember]) -> Result<Self, SolverError> {
        let mut member_map: BTreeMap<String, WorkspaceMember> = BTreeMap::new();
        for m in members {
            member_map.insert(m.name.clone(), m.clone());
        }

        let mut dependencies: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

        // 1. Resolve workspace dependencies for each member
        for member in members {
            let mut member_deps: BTreeMap<String, String> = BTreeMap::new();

            // Collect all declared dependencies in member manifest
            let all_deps = collect_all_declared_dependencies(&member.manifest);

            for (dep_name, dep_spec) in all_deps {
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
                    validate_workspace_protocol_constraint(
                        &member.name,
                        sibling,
                        ws_spec,
                        &dep_spec,
                    )?;

                    member_deps.insert(dep_name, dep_spec);
                } else if let Some(sibling) = member_map.get(&dep_name) {
                    // Check if a normal semver spec satisfies the local sibling version
                    if is_sibling_compatible(sibling, trimmed_spec) {
                        member_deps.insert(dep_name, dep_spec);
                    }
                }
            }

            dependencies.insert(member.name.clone(), member_deps);
        }

        // 2. Perform topological sorting and cycle detection
        let topological_order = topological_sort(&member_map, &dependencies)?;

        Ok(Self {
            members: member_map,
            dependencies,
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
}

/// Collect dependencies, devDependencies, optionalDependencies, and peerDependencies from manifest.
fn collect_all_declared_dependencies(manifest: &Manifest) -> BTreeMap<String, String> {
    let mut all = BTreeMap::new();
    for (k, v) in &manifest.dependencies {
        all.insert(k.clone(), v.clone());
    }
    for (k, v) in &manifest.dev_dependencies {
        all.insert(k.clone(), v.clone());
    }
    for (k, v) in &manifest.optional_dependencies {
        all.insert(k.clone(), v.clone());
    }
    for (k, v) in &manifest.peer_dependencies {
        all.insert(k.clone(), v.clone());
    }
    all
}

/// Validate `workspace:*`, `workspace:^`, `workspace:~`, and `workspace:<range>` against sibling version.
fn validate_workspace_protocol_constraint(
    requester: &str,
    sibling: &WorkspaceMember,
    ws_spec: &str,
    raw_spec: &str,
) -> Result<(), SolverError> {
    let clean = ws_spec.trim();

    // workspace:* allows any sibling version
    if clean == "*" || clean.is_empty() {
        return Ok(());
    }

    let sibling_version_str = sibling.version.as_deref().ok_or_else(|| {
        SolverError::UnresolvedDependency {
            name: sibling.name.clone(),
            spec: raw_spec.to_string(),
            message: format!(
                "Workspace package '{}' has no version declared in its manifest, but '{}' requires '{}'",
                sibling.name, requester, raw_spec
            ),
        }
    })?;

    let sibling_ver = Version::parse(sibling_version_str).map_err(|e| {
        SolverError::UnresolvedDependency {
            name: sibling.name.clone(),
            spec: raw_spec.to_string(),
            message: format!(
                "Invalid version '{}' in workspace package '{}': {e}",
                sibling_version_str, sibling.name
            ),
        }
    })?;

    if clean == "^" {
        // workspace:^ resolves to ^<sibling_version>
        let range_str = format!("^{sibling_version_str}");
        let range = Range::parse(&range_str).map_err(|e| SolverError::Semver(e))?;
        if !range.satisfies(&sibling_ver) {
            return Err(SolverError::UnresolvedDependency {
                name: sibling.name.clone(),
                spec: raw_spec.to_string(),
                message: format!(
                    "Workspace package '{}@{}' does not satisfy range '{range_str}' required by '{requester}'",
                    sibling.name, sibling_version_str
                ),
            });
        }
    } else if clean == "~" {
        // workspace:~ resolves to ~<sibling_version>
        let range_str = format!("~{sibling_version_str}");
        let range = Range::parse(&range_str).map_err(|e| SolverError::Semver(e))?;
        if !range.satisfies(&sibling_ver) {
            return Err(SolverError::UnresolvedDependency {
                name: sibling.name.clone(),
                spec: raw_spec.to_string(),
                message: format!(
                    "Workspace package '{}@{}' does not satisfy range '{range_str}' required by '{requester}'",
                    sibling.name, sibling_version_str
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
                        sibling.name, sibling_version_str, clean, requester
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
                        sibling.name, sibling_version_str, clean, requester
                    ),
                });
            }
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
    // Check for direct self-dependency cycles
    for (name, dep_map) in deps {
        if dep_map.contains_key(name) {
            return Err(SolverError::CycleDetected(format!(
                "Circular workspace dependency detected: {name} -> {name}"
            )));
        }
    }

    // 0: Unvisited, 1: Visiting (in recursion stack), 2: Visited
    let mut state: BTreeMap<String, u8> = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();
    let mut order: Vec<String> = Vec::new();

    for name in members.keys() {
        state.insert(name.clone(), 0);
    }

    for name in members.keys() {
        if state.get(name) == Some(&0) {
            dfs_visit(name, deps, &mut state, &mut stack, &mut order)?;
        }
    }

    Ok(order)
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

/// Resolves a full workspace dependency graph including sibling linking and external package hoisting.
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
        optional_dependencies: root_manifest.optional_dependencies.clone(),
        os: root_manifest.os.clone(),
        cpu: root_manifest.cpu.clone(),
        bin: root_manifest.bin.clone().map(|b| match b {
            rnpm_core::manifest::PackageBin::Single(s) => rnpm_lockfile::PackageBin::Single(s),
            rnpm_core::manifest::PackageBin::Map(m) => rnpm_lockfile::PackageBin::Map(m),
        }),
    };
    graph.nodes.insert(String::new(), root_node);

    // 3. Insert workspace members at their relative paths and create link nodes in node_modules
    for member in members {
        let member_loc = member.relative_path.clone();
        let link_loc = format!("node_modules/{}", member.name);

        let member_node = Node {
            location: member_loc.clone(),
            install_name: member.name.clone(),
            name: member.name.clone(),
            version: member.version.clone().unwrap_or_else(|| "0.0.0".to_string()),
            resolved: None,
            integrity: None,
            flags: NodeFlags::default(),
            dependencies: member.manifest.dependencies.clone(),
            dev_dependencies: member.manifest.dev_dependencies.clone(),
            peer_dependencies: member.manifest.peer_dependencies.clone(),
            optional_dependencies: member.manifest.optional_dependencies.clone(),
            os: member.manifest.os.clone(),
            cpu: member.manifest.cpu.clone(),
            bin: member.manifest.bin.clone().map(|b| match b {
                rnpm_core::manifest::PackageBin::Single(s) => rnpm_lockfile::PackageBin::Single(s),
                rnpm_core::manifest::PackageBin::Map(m) => rnpm_lockfile::PackageBin::Map(m),
            }),
        };
        graph.nodes.insert(member_loc.clone(), member_node);

        // Link node in root node_modules/<member.name>
        let link_node = Node {
            location: link_loc.clone(),
            install_name: member.name.clone(),
            name: member.name.clone(),
            version: member.version.clone().unwrap_or_else(|| "0.0.0".to_string()),
            resolved: Some(member_loc.clone()),
            integrity: None,
            flags: NodeFlags {
                link: true,
                ..Default::default()
            },
            dependencies: member.manifest.dependencies.clone(),
            dev_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            os: None,
            cpu: None,
            bin: None,
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

        // Add edges between workspace members
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
    }

    // 4. Resolve external third-party dependencies from root and all workspace members
    // Combine all external dependencies into synthetic root for hoisting
    let mut combined_manifest = root_manifest.clone();

    for member in members {
        for (k, v) in &member.manifest.dependencies {
            if !ws_graph.is_member(k) && !v.starts_with("workspace:") {
                combined_manifest.dependencies.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        for (k, v) in &member.manifest.dev_dependencies {
            if !ws_graph.is_member(k) && !v.starts_with("workspace:") {
                combined_manifest.dev_dependencies.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }

    // Solve external dependencies
    let external_graph = crate::solver::resolve_dependency_graph(
        &combined_manifest,
        provider,
        options,
    )?;

    // Merge external nodes and edges into workspace graph (excluding root "")
    for (loc, node) in external_graph.nodes {
        if !loc.is_empty() && !graph.nodes.contains_key(&loc) {
            graph.nodes.insert(loc, node);
        }
    }
    for edge in external_graph.edges {
        if !graph.edges.iter().any(|e| e.from_location == edge.from_location && e.to_location == edge.to_location && e.install_name == edge.install_name) {
            graph.edges.push(edge);
        }
    }

    Ok(graph)
}
