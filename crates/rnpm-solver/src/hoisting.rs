use rnpm_core::semver::Version;
use rnpm_core::spec::PackageTarget;
use crate::graph::DependencyGraph;

/// Placement decision made by the deduplication and hoisting engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlacementDecision {
    /// Reuse an existing node in an ancestor scope (deduplicated).
    Reuse(String),
    /// Place a newly resolved node at the given location in the tree.
    PlaceNew(String),
}

/// Checks if an exact version string satisfies a package target specification.
pub fn version_satisfies_target(version_str: &str, target: &PackageTarget) -> bool {
    let Ok(v) = Version::parse(version_str) else {
        return false;
    };
    match target {
        PackageTarget::Version(expected) => &v == expected,
        PackageTarget::Range(range) => range.satisfies(&v),
        PackageTarget::Tag(_) => true,
        PackageTarget::Alias { target, .. } => version_satisfies_target(version_str, target),
        PackageTarget::File(_) => true,
        PackageTarget::Git { .. } => true,
        PackageTarget::Url(_) => true,
        PackageTarget::Workspace(ws_spec) => {
            let s = ws_spec.trim();
            if s == "*" || s == "^" || s == "~" || s.is_empty() {
                true
            } else if let Ok(range) = rnpm_core::semver::Range::parse(s) {
                range.satisfies(&v)
            } else if let Ok(expected) = Version::parse(s) {
                v == expected
            } else {
                true
            }
        }
    }
}

/// Fast check if a node satisfies target constraint, leveraging cached parsed_version.
#[inline]
pub fn node_satisfies_target(node: &crate::graph::Node, target: &PackageTarget) -> bool {
    if let Some(parsed) = &node.parsed_version {
        match target {
            PackageTarget::Version(expected) => parsed == expected,
            PackageTarget::Range(range) => range.satisfies(parsed),
            PackageTarget::Tag(_) => true,
            PackageTarget::Alias { target, .. } => node_satisfies_target(node, target),
            PackageTarget::File(_) => true,
            PackageTarget::Git { .. } => true,
            PackageTarget::Url(_) => true,
            PackageTarget::Workspace(ws_spec) => {
                let s = ws_spec.trim();
                if s == "*" || s == "^" || s == "~" || s.is_empty() {
                    true
                } else if let Ok(range) = rnpm_core::semver::Range::parse(s) {
                    range.satisfies(parsed)
                } else if let Ok(expected) = Version::parse(s) {
                    parsed == &expected
                } else {
                    true
                }
            }
        }
    } else {
        version_satisfies_target(&node.version, target)
    }
}

/// Determines the tree placement for a dependency according to npm/Arborist hoisting rules:
/// 1. Top-Level Hoisting: Try to place at root `node_modules/<install_name>`.
/// 2. Deduplication: If already occupied by a compatible version, reuse the existing node.
/// 3. Intermediate Hoisting: If root is occupied by an incompatible version, hoist/deduplicate to
///    an intermediate ancestor scope if valid and unshadowed.
/// 4. Conflict Nesting: If all ancestor scopes are blocked by conflicts, nest at
///    `<parent_location>/node_modules/<install_name>`.
pub fn determine_placement(
    graph: &DependencyGraph,
    parent_location: &str,
    install_name: &str,
    package_name: &str,
    target: &PackageTarget,
) -> PlacementDecision {
    let mut root_target = String::with_capacity(14 + install_name.len());
    root_target.push_str("node_modules/");
    root_target.push_str(install_name);

    // If parent is root (""), location is directly under root
    if parent_location.is_empty() {
        if let Some(existing) = graph.nodes.get(&root_target) {
            if existing.name == package_name && node_satisfies_target(existing, target) {
                return PlacementDecision::Reuse(root_target);
            }
        }
        return PlacementDecision::PlaceNew(root_target);
    }

    // Attempt 1: Check root node_modules
    if let Some(existing) = graph.nodes.get(&root_target) {
        if existing.name == package_name && node_satisfies_target(existing, target) {
            // Check if there is an intermediate shadowing conflict between parent and root
            if !is_shadowed_by_incompatible_between(graph, parent_location, "", install_name, target) {
                return PlacementDecision::Reuse(root_target);
            }
        }
        // Root is occupied and either incompatible or shadowed -> conflict!
    } else {
        // Root is vacant. Check if vacant root is shadowed by an incompatible intermediate node
        if !is_shadowed_by_incompatible_between(graph, parent_location, "", install_name, target) {
            return PlacementDecision::PlaceNew(root_target);
        }
    }

    // Attempt 2: Check intermediate ancestor scopes from root towards parent
    let mut ancestors = Vec::new();
    let mut curr = parent_location;
    while let Some(idx) = curr.rfind("/node_modules/") {
        curr = &curr[..idx];
        if !curr.is_empty() {
            ancestors.push(curr);
        }
    }

    for ancestor in ancestors.into_iter().rev() {
        let mut candidate = String::with_capacity(ancestor.len() + 14 + install_name.len());
        candidate.push_str(ancestor);
        candidate.push_str("/node_modules/");
        candidate.push_str(install_name);

        if let Some(existing) = graph.nodes.get(&candidate) {
            if existing.name == package_name && node_satisfies_target(existing, target)
                && !is_shadowed_by_incompatible_between(graph, parent_location, ancestor, install_name, target) {
                    return PlacementDecision::Reuse(candidate);
                }
        } else if !is_shadowed_by_incompatible_between(graph, parent_location, ancestor, install_name, target) {
            return PlacementDecision::PlaceNew(candidate);
        }
    }

    // Attempt 3: Conflict nesting under parent
    let mut nested_target = String::with_capacity(parent_location.len() + 14 + install_name.len());
    nested_target.push_str(parent_location);
    nested_target.push_str("/node_modules/");
    nested_target.push_str(install_name);

    if let Some(existing) = graph.nodes.get(&nested_target) {
        if existing.name == package_name && node_satisfies_target(existing, target) {
            return PlacementDecision::Reuse(nested_target);
        }
    }

    PlacementDecision::PlaceNew(nested_target)
}

/// Checks if any intermediate scope between `from_scope` and `to_ancestor` has a node for `install_name`
/// that does NOT satisfy `target`.
fn is_shadowed_by_incompatible_between(
    graph: &DependencyGraph,
    from_scope: &str,
    to_ancestor: &str,
    install_name: &str,
    target: &PackageTarget,
) -> bool {
    let mut current = from_scope;
    let mut candidate_buf = String::with_capacity(from_scope.len() + 14 + install_name.len());
    while !current.is_empty() && current != to_ancestor {
        candidate_buf.clear();
        candidate_buf.push_str(current);
        candidate_buf.push_str("/node_modules/");
        candidate_buf.push_str(install_name);
        if let Some(node) = graph.nodes.get(&candidate_buf) {
            if !node_satisfies_target(node, target) {
                return true;
            }
        }
        if let Some(idx) = current.rfind("/node_modules/") {
            current = &current[..idx];
        } else {
            break;
        }
    }
    false
}

/// Helper check if a node matches either `install_name` or physical `name`.
#[inline]
pub fn node_matches_peer_name(node: &crate::graph::Node, install_name: &str, package_name: &str) -> bool {
    node.name == package_name
        || node.install_name == install_name
        || node.name == install_name
        || node.install_name == package_name
}

/// Finds all immediate children in `scope`'s node_modules directory that match peer name.
fn find_matching_node_in_scope<'a>(
    graph: &'a DependencyGraph,
    scope: &str,
    install_name: &str,
    package_name: &str,
) -> Option<&'a crate::graph::Node> {
    let prefix = if scope.is_empty() {
        "node_modules/".to_string()
    } else {
        format!("{scope}/node_modules/")
    };

    for (loc, node) in graph.nodes.range(prefix.clone()..) {
        if !loc.starts_with(&prefix) {
            break;
        }
        let rest = &loc[prefix.len()..];
        // Ensure this node is directly in `scope`, not inside a nested sub-node_modules
        if rest.contains("/node_modules/") {
            continue;
        }
        if node_matches_peer_name(node, install_name, package_name) {
            return Some(node);
        }
    }

    None
}

/// Finds the closest visible node for a peer requirement matching either its `install_name`
/// OR its physical `package_name` (e.g. for aliased packages `install_name != package_name`).
pub fn find_visible_peer_node<'a>(
    graph: &'a DependencyGraph,
    from_location: &str,
    install_name: &str,
    package_name: &str,
) -> Option<&'a crate::graph::Node> {
    let mut current = from_location;
    let max_len = install_name.len().max(package_name.len());
    let mut candidate_buf = String::with_capacity(from_location.len() + 14 + max_len);

    while !current.is_empty() {
        // 1. Direct check: <current>/node_modules/<install_name>
        candidate_buf.clear();
        candidate_buf.push_str(current);
        candidate_buf.push_str("/node_modules/");
        candidate_buf.push_str(install_name);
        if let Some(node) = graph.nodes.get(&candidate_buf) {
            if node_matches_peer_name(node, install_name, package_name) {
                return Some(node);
            }
        }

        // 2. Direct check: <current>/node_modules/<package_name>
        if package_name != install_name {
            candidate_buf.clear();
            candidate_buf.push_str(current);
            candidate_buf.push_str("/node_modules/");
            candidate_buf.push_str(package_name);
            if let Some(node) = graph.nodes.get(&candidate_buf) {
                if node_matches_peer_name(node, install_name, package_name) {
                    return Some(node);
                }
            }
        }

        // 3. Aliased packages search in scope: e.g. <current>/node_modules/<alias> where node.name == package_name
        if let Some(node) = find_matching_node_in_scope(graph, current, install_name, package_name) {
            return Some(node);
        }

        // Ascend one directory level in node_modules hierarchy
        if let Some(idx) = current.rfind("/node_modules/") {
            current = &current[..idx];
        } else if let Some(idx) = current.rfind('/') {
            // For workspace packages like "packages/app", ascend to parent directory
            current = &current[..idx];
        } else {
            break;
        }
    }

    // Finally, check root scope ("")
    // 1. Direct check by install_name
    let root_install = format!("node_modules/{install_name}");
    if let Some(node) = graph.nodes.get(&root_install) {
        if node_matches_peer_name(node, install_name, package_name) {
            return Some(node);
        }
    }

    // 2. Direct check by package_name
    if package_name != install_name {
        let root_pkg = format!("node_modules/{package_name}");
        if let Some(node) = graph.nodes.get(&root_pkg) {
            if node_matches_peer_name(node, install_name, package_name) {
                return Some(node);
            }
        }
    }

    // 3. Root scope scan for aliased packages
    find_matching_node_in_scope(graph, "", install_name, package_name)
}

/// Finds the closest visible node for `install_name` starting from `from_location`
/// and walking up the `node_modules` hierarchy to root.
pub fn find_visible_node<'a>(
    graph: &'a DependencyGraph,
    from_location: &str,
    install_name: &str,
) -> Option<&'a crate::graph::Node> {
    find_visible_peer_node(graph, from_location, install_name, install_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Node;
    use rnpm_core::semver::Range;

    fn make_test_node(location: &str, name: &str, version: &str) -> Node {
        Node {
            location: location.to_string(),
            install_name: name.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            parsed_version: Version::parse(version).ok(),
            ..Default::default()
        }
    }

    #[test]
    fn test_hoisting_vacant_root() {
        let graph = DependencyGraph::new();
        let target = PackageTarget::Range(Range::parse("^1.0.0").unwrap());

        let decision = determine_placement(&graph, "node_modules/A", "B", "B", &target);
        assert_eq!(decision, PlacementDecision::PlaceNew("node_modules/B".to_string()));
    }

    #[test]
    fn test_deduplication_compatible_root() {
        let mut graph = DependencyGraph::new();
        graph.nodes.insert("node_modules/B".to_string(), make_test_node("node_modules/B", "B", "1.2.0"));

        let target = PackageTarget::Range(Range::parse("^1.0.0").unwrap());
        let decision = determine_placement(&graph, "node_modules/A", "B", "B", &target);
        assert_eq!(decision, PlacementDecision::Reuse("node_modules/B".to_string()));
    }

    #[test]
    fn test_conflict_nesting() {
        let mut graph = DependencyGraph::new();
        // Root has B@1.2.0
        graph.nodes.insert("node_modules/B".to_string(), make_test_node("node_modules/B", "B", "1.2.0"));

        // Dependent requires B@^2.0.0
        let target = PackageTarget::Range(Range::parse("^2.0.0").unwrap());
        let decision = determine_placement(&graph, "node_modules/A", "B", "B", &target);
        assert_eq!(
            decision,
            PlacementDecision::PlaceNew("node_modules/A/node_modules/B".to_string())
        );
    }

    #[test]
    fn test_find_visible_node() {
        let mut graph = DependencyGraph::new();
        // Root node_modules/react
        graph.nodes.insert("node_modules/react".to_string(), make_test_node("node_modules/react", "react", "18.2.0"));
        // Nested node_modules/nested-lib/node_modules/local-dep
        graph.nodes.insert(
            "node_modules/nested-lib/node_modules/local-dep".to_string(),
            make_test_node("node_modules/nested-lib/node_modules/local-dep", "local-dep", "1.0.0"),
        );

        // From root: can see react
        let vis1 = find_visible_node(&graph, "", "react");
        assert!(vis1.is_some());
        assert_eq!(vis1.unwrap().version, "18.2.0");

        // From nested-lib: can see react from ancestor root
        let vis2 = find_visible_node(&graph, "node_modules/nested-lib", "react");
        assert!(vis2.is_some());
        assert_eq!(vis2.unwrap().version, "18.2.0");

        // From nested-lib: can see local-dep under itself
        let vis3 = find_visible_node(&graph, "node_modules/nested-lib", "local-dep");
        assert!(vis3.is_some());
        assert_eq!(vis3.unwrap().location, "node_modules/nested-lib/node_modules/local-dep");

        // From root: CANNOT see nested-lib's local-dep
        let vis4 = find_visible_node(&graph, "", "local-dep");
        assert!(vis4.is_none());
    }

    #[test]
    fn test_find_visible_peer_node_aliased() {
        let mut graph = DependencyGraph::new();
        // Package installed with alias: install_name="my-react", name="react"
        let mut aliased_node = make_test_node("node_modules/my-react", "react", "18.2.0");
        aliased_node.install_name = "my-react".to_string();
        graph.nodes.insert("node_modules/my-react".to_string(), aliased_node);

        // Nested consumer: node_modules/react-redux
        graph.nodes.insert(
            "node_modules/react-redux".to_string(),
            make_test_node("node_modules/react-redux", "react-redux", "8.0.0"),
        );

        // 1. Peer requirement asking for physical name "react"
        let found_by_pkg_name = find_visible_peer_node(&graph, "node_modules/react-redux", "react", "react");
        assert!(found_by_pkg_name.is_some());
        assert_eq!(found_by_pkg_name.unwrap().location, "node_modules/my-react");
        assert_eq!(found_by_pkg_name.unwrap().name, "react");

        // 2. Peer requirement asking for alias name "my-react"
        let found_by_alias = find_visible_peer_node(&graph, "node_modules/react-redux", "my-react", "my-react");
        assert!(found_by_alias.is_some());
        assert_eq!(found_by_alias.unwrap().location, "node_modules/my-react");
    }
}
