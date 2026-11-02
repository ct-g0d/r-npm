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
        PackageTarget::Workspace(ws_spec) => {
            let s = ws_spec.trim();
            if s == "*" || s == "^" || s == "~" || s.is_empty() {
                true
            } else if let Ok(range) = rnpm_core::semver::Range::parse(s) {
                range.satisfies(&v)
            } else if let Ok(expected) = Version::parse(s) {
                &v == &expected
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
            if existing.name == package_name && node_satisfies_target(existing, target) {
                if !is_shadowed_by_incompatible_between(graph, parent_location, ancestor, install_name, target) {
                    return PlacementDecision::Reuse(candidate);
                }
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
}
