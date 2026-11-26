use crate::fast_util::{fast_map_with_capacity, FastMap};
use crate::graph::DependencyGraph;
use rnpm_core::semver::Version;
use rnpm_core::spec::PackageTarget;
use std::cell::RefCell;
use std::rc::Rc;

const MAX_CACHE_ENTRIES: usize = 65536;

thread_local! {
    static TARGET_CACHE: RefCell<FastMap<String, Option<Rc<PackageTarget>>>> =
        RefCell::new(fast_map_with_capacity(1024));
    static VERSION_CACHE: RefCell<FastMap<String, Option<Rc<Version>>>> =
        RefCell::new(fast_map_with_capacity(2048));
}

#[inline]
pub(crate) fn cached_target_rc(spec: &str) -> Option<Rc<PackageTarget>> {
    TARGET_CACHE.with(|cache| {
        {
            let map = cache.borrow();
            if let Some(target) = map.get(spec) {
                return target.clone();
            }
        }
        let parsed = PackageTarget::parse(spec).ok().map(Rc::new);
        let mut map = cache.borrow_mut();
        if map.len() >= MAX_CACHE_ENTRIES {
            map.clear();
        }
        map.insert(spec.to_string(), parsed.clone());
        parsed
    })
}

#[inline]
pub(crate) fn cached_version_rc(version_str: &str) -> Option<Rc<Version>> {
    VERSION_CACHE.with(|cache| {
        {
            let map = cache.borrow();
            if let Some(v) = map.get(version_str) {
                return v.clone();
            }
        }
        let parsed = Version::parse(version_str).ok().map(Rc::new);
        let mut map = cache.borrow_mut();
        if map.len() >= MAX_CACHE_ENTRIES {
            map.clear();
        }
        map.insert(version_str.to_string(), parsed.clone());
        parsed
    })
}

/// Cached parser for PackageTarget, avoiding repeated parse calls on identical specs like "^1.0.0".
#[inline]
pub fn cached_parse_package_target(spec: &str) -> Option<PackageTarget> {
    cached_target_rc(spec).map(|rc| (*rc).clone())
}

/// Cached parser for SemVer Version, avoiding repeated parses of package version strings.
#[inline]
pub fn cached_parse_version(version_str: &str) -> Option<Version> {
    cached_version_rc(version_str).map(|rc| (*rc).clone())
}

/// Placement decision made by the deduplication and hoisting engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlacementDecision {
    /// Reuse an existing node in an ancestor scope (deduplicated).
    Reuse(String),
    /// Place a newly resolved node at the given location in the tree.
    PlaceNew(String),
}

/// npm's `install-strategy` as it affects PlaceDep's target walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlacementStrategy {
    /// Hoist as high as possible (the default).
    #[default]
    Hoisted,
    /// `nested` (`--legacy-bundling`): place under the dependent itself.
    Nested,
    /// `shallow` (`--global-style`): never hoist above a top-level node.
    Shallow,
}

/// A peer provider cannot nest inside a package that itself peers on that name.
/// Follow the peer group up to npm's deepestNestingTarget.
pub fn peer_provider_scope<'a>(graph: &DependencyGraph, owner: &'a str, name: &str) -> &'a str {
    let mut scope = owner.rsplit_once("/node_modules/").map_or("", |(p, _)| p);
    while !scope.is_empty()
        && graph.nodes.get(scope).is_some_and(|node| {
            node.peer_dependencies.contains_key(name)
                && !node.dependencies.contains_key(name)
                && !node.optional_dependencies.contains_key(name)
        })
    {
        scope = scope.rsplit_once("/node_modules/").map_or("", |(p, _)| p);
    }
    scope
}

/// File specs can retain an older spelling in installed metadata and lockfiles.
pub(crate) fn file_target_matches_resolved(target: &std::path::Path, resolved: &str) -> bool {
    matches!(
        PackageTarget::parse(resolved),
        Ok(PackageTarget::File(path)) if path == target
    )
}

/// Checks if a pre-parsed `Version` satisfies a `PackageTarget`, avoiding string conversions and re-parses.
#[inline]
pub(crate) fn parsed_version_satisfies_target(
    v: &Version,
    version_str: Option<&str>,
    target: &PackageTarget,
) -> bool {
    match target {
        PackageTarget::Version(expected) => v == expected,
        PackageTarget::Range(range) => range.satisfies(v),
        PackageTarget::Tag(_) => true,
        PackageTarget::Alias { target, .. } => {
            parsed_version_satisfies_target(v, version_str, target)
        }
        PackageTarget::File(p) => version_str.is_some_and(|vs| {
            let expected = format!("file:{}", rnpm_core::to_posix_path(&p.to_string_lossy()));
            vs == expected
        }),
        PackageTarget::Git {
            url,
            committish,
            subdir,
        } => version_str.is_some_and(|vs| {
            let expected = match (committish, subdir) {
                (Some(c), Some(s)) => format!("{url}#{c}::path:{s}"),
                (Some(c), None) => format!("{url}#{c}"),
                (None, Some(s)) => format!("{url}#path:{s}"),
                (None, None) => url.clone(),
            };
            vs == expected
                || git_target_matches_resolved(url, committish.as_deref(), vs)
                || committish
                    .as_ref()
                    .map(|c| c.trim_start_matches('v') == vs)
                    .unwrap_or(false)
        }),
        PackageTarget::Url(u) => version_str.is_some_and(|vs| vs == u.as_str()),
        PackageTarget::Workspace(ws_spec) => {
            let s = ws_spec.trim();
            if s == "*" || s == "^" || s == "~" || s.is_empty() {
                true
            } else if let Some(cached) = cached_target_rc(s) {
                match cached.as_ref() {
                    PackageTarget::Range(range) => range.satisfies(v),
                    PackageTarget::Version(expected) => v == expected,
                    _ => true,
                }
            } else {
                true
            }
        }
    }
}

/// Checks if a version entry (with optional pre-parsed SemVer) satisfies a target constraint.
#[inline]
pub(crate) fn version_entry_satisfies_target(
    version_str: &str,
    parsed: Option<&Version>,
    target: &PackageTarget,
) -> bool {
    if let Some(v) = parsed {
        parsed_version_satisfies_target(v, Some(version_str), target)
    } else {
        version_satisfies_target(version_str, target)
    }
}

/// Checks if an exact version string satisfies a package target specification.
pub fn version_satisfies_target(version_str: &str, target: &PackageTarget) -> bool {
    let Some(v) = cached_version_rc(version_str) else {
        return false;
    };
    parsed_version_satisfies_target(&v, Some(version_str), target)
}

/// Extracts (host, normalized_path) from a git URL.
fn git_url_repo_key(url: &str) -> Option<(String, String)> {
    let clean = url.split('#').next()?.trim();
    let clean = clean.strip_prefix("git+").unwrap_or(clean);
    if let Some(rest) = clean.strip_prefix("github:") {
        let repo = rest.trim_end_matches(".git").trim_matches('/');
        return Some(("github.com".to_string(), repo.to_string()));
    }
    if let Some(rest) = clean.strip_prefix("gitlab:") {
        let repo = rest.trim_end_matches(".git").trim_matches('/');
        return Some(("gitlab.com".to_string(), repo.to_string()));
    }
    if let Some(rest) = clean.strip_prefix("bitbucket:") {
        let repo = rest.trim_end_matches(".git").trim_matches('/');
        return Some(("bitbucket.org".to_string(), repo.to_string()));
    }
    let clean = clean
        .strip_prefix("ssh://")
        .or_else(|| clean.strip_prefix("https://"))
        .or_else(|| clean.strip_prefix("http://"))
        .or_else(|| clean.strip_prefix("file://"))
        .or_else(|| clean.strip_prefix("git://"))
        .unwrap_or(clean);
    let clean = clean.strip_prefix("git@").unwrap_or(clean);
    let (host, path) = if let Some((h, p)) = clean.split_once(':') {
        (h, p)
    } else if let Some((h, p)) = clean.split_once('/') {
        (h, p)
    } else {
        return None;
    };
    let path = path.trim_end_matches(".git").trim_matches('/');
    Some((host.to_lowercase(), path.to_string()))
}

/// Checks if two git URLs point to the same repository.
pub fn git_urls_match_repo(url_a: &str, url_b: &str) -> bool {
    let a_clean = url_a.split('#').next().unwrap_or(url_a).trim();
    let b_clean = url_b.split('#').next().unwrap_or(url_b).trim();
    if a_clean == b_clean {
        return true;
    }
    match (git_url_repo_key(a_clean), git_url_repo_key(b_clean)) {
        (Some(key_a), Some(key_b)) => key_a == key_b,
        _ => {
            let norm = |s: &str| {
                s.strip_prefix("git+")
                    .unwrap_or(s)
                    .strip_prefix("file://")
                    .unwrap_or(s)
                    .replace('\\', "/")
                    .trim_end_matches(".git")
                    .trim_matches('/')
                    .to_lowercase()
            };
            norm(a_clean) == norm(b_clean)
        }
    }
}

/// Checks if a resolved git URL matches a target Git specification.
pub fn git_target_matches_resolved(
    target_url: &str,
    committish: Option<&str>,
    resolved: &str,
) -> bool {
    let expected = format!(
        "{}{}",
        target_url,
        committish.map(|c| format!("#{c}")).unwrap_or_default()
    );
    if resolved == expected || resolved.starts_with(target_url) {
        return true;
    }
    if !git_urls_match_repo(target_url, resolved) {
        return false;
    }
    if let Some(c) = committish {
        if let Some(resolved_hash) = resolved.split('#').nth(1) {
            if resolved_hash == c || resolved_hash.starts_with(c) || c.starts_with(resolved_hash) {
                return true;
            }
        }
    }
    true
}

/// Fast check if a node satisfies target constraint, leveraging cached parsed_version.
#[inline]
pub fn node_satisfies_target(node: &crate::graph::Node, target: &PackageTarget) -> bool {
    match target {
        PackageTarget::Url(u) => {
            return node.resolved.as_deref() == Some(u.as_str());
        }
        PackageTarget::File(p) => {
            return node
                .resolved
                .as_deref()
                .is_some_and(|resolved| file_target_matches_resolved(p, resolved));
        }
        PackageTarget::Git {
            url, committish, ..
        } => {
            return node
                .resolved
                .as_deref()
                .is_some_and(|r| git_target_matches_resolved(url, committish.as_deref(), r));
        }
        _ => {}
    }

    if let Some(ref parsed) = node.parsed_version {
        return match target {
            PackageTarget::Alias { name, target } => {
                node.name == *name && node_satisfies_target(node, target)
            }
            _ => parsed_version_satisfies_target(parsed, Some(&node.version), target),
        };
    }

    if let Some(parsed) = cached_version_rc(&node.version) {
        match target {
            PackageTarget::Alias { name, target } => {
                node.name == *name && node_satisfies_target(node, target)
            }
            _ => parsed_version_satisfies_target(&parsed, Some(&node.version), target),
        }
    } else {
        version_satisfies_target(&node.version, target)
    }
}

/// Returns the next ancestor scope in the node_modules directory hierarchy,
/// walking from `scope` towards the project root `""`.
///
/// For packages nested under node_modules (e.g. `packages/a/node_modules/b` or `node_modules/a/node_modules/b`),
/// the ancestor is the enclosing package scope (`packages/a` or `node_modules/a`).
/// For packages directly under root node_modules (e.g. `node_modules/a` or `node_modules/@scope/a`),
/// the ancestor is `""` (the root).
/// For workspace packages (e.g. `packages/parent/nested`), the ancestor is the parent
/// directory `packages/parent`, then `packages`, then `""`.
/// Returns `None` once `scope` is already the root `""`.
#[inline]
pub fn parent_scope(scope: &str) -> Option<&str> {
    if scope.is_empty() {
        return None;
    }
    if let Some(idx) = scope.rfind("/node_modules/") {
        Some(&scope[..idx])
    } else if scope.starts_with("node_modules/") {
        Some("")
    } else if let Some(idx) = scope.rfind('/') {
        Some(&scope[..idx])
    } else {
        Some("")
    }
}

/// Returns an iterator over ancestor scopes starting from `from_scope` up to and including root `""`.
#[inline]
pub fn iter_ancestor_scopes(from_scope: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(from_scope), |&s| parent_scope(s))
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
    determine_placement_with_peers(
        graph,
        parent_location,
        install_name,
        package_name,
        target,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        None,
        None,
        None,
        true,
        PlacementStrategy::Hoisted,
    )
}

/// Determines placement while preserving peer visibility. A candidate scope
/// that already exposes an incompatible peer must not claim the package: npm
/// nests the package so its parent or a nearer scope can provide the peer.
pub fn determine_placement_with_peers(
    graph: &DependencyGraph,
    parent_location: &str,
    install_name: &str,
    package_name: &str,
    target: &PackageTarget,
    dependencies: &std::collections::BTreeMap<String, String>,
    peer_dependencies: &std::collections::BTreeMap<String, String>,
    peer_dependencies_meta: &std::collections::BTreeMap<
        String,
        rnpm_core::manifest::PeerDependencyMeta,
    >,
    resolved_version: Option<&str>,
    resolved: Option<&str>,
    integrity: Option<&str>,
    placing_peer: bool,
    strategy: PlacementStrategy,
) -> PlacementDecision {
    let mut path_buf = String::with_capacity(parent_location.len() + 14 + install_name.len());
    path_buf.push_str("node_modules/");
    path_buf.push_str(install_name);

    let reuse_peer_set = |existing: &crate::graph::Node, location: &str| {
        // CanPlaceDep checks dep.matches(current) before checking candidate
        // peers. A matching installed node keeps its attached peer context;
        // the incoming candidate's virtual overrides must not force a copy.
        let same_package = if let (Some(a), Some(b)) = (integrity, existing.integrity.as_deref()) {
            a == b
        } else if let (Some(a), Some(b)) = (resolved, existing.resolved.as_deref()) {
            a == b
        } else {
            resolved_version == Some(existing.version.as_str())
        };
        same_package
            || !candidate_peer_conflict(
                graph,
                location,
                parent_location,
                dependencies,
                peer_dependencies,
                peer_dependencies_meta,
                placing_peer,
            )
    };

    // If parent is root (""), location is directly under root
    if parent_location.is_empty() {
        if let Some(existing) = graph.nodes.get(&path_buf) {
            if existing.name == package_name
                && node_satisfies_target(existing, target)
                && reuse_peer_set(existing, &path_buf)
            {
                return PlacementDecision::Reuse(path_buf);
            }
        }
        return PlacementDecision::PlaceNew(path_buf);
    }

    // PlaceDep leaves an edge alone when its nearest visible node already
    // satisfies it; nested placement then stops at the dependent itself.
    if strategy == PlacementStrategy::Nested {
        if let Some(existing) = find_visible_node(graph, parent_location, install_name) {
            if existing.name == package_name
                && node_satisfies_target(existing, target)
                && reuse_peer_set(existing, &existing.location)
            {
                return PlacementDecision::Reuse(existing.location.clone());
            }
        }
        path_buf.clear();
        path_buf.push_str(parent_location);
        path_buf.push_str("/node_modules/");
        path_buf.push_str(install_name);
        return PlacementDecision::PlaceNew(path_buf);
    }

    // Attempt 1: Check root node_modules
    if let Some(existing) = graph.nodes.get(&path_buf) {
        if existing.name == package_name
            && node_satisfies_target(existing, target)
            && reuse_peer_set(existing, &path_buf)
        {
            // Check if there is an intermediate shadowing conflict between parent and root
            if !is_shadowed_by_incompatible_between(
                graph,
                parent_location,
                "",
                install_name,
                target,
            ) {
                return PlacementDecision::Reuse(path_buf);
            }
        }
        // Root is occupied and either incompatible or shadowed -> conflict!
    } else if strategy != PlacementStrategy::Shallow {
        // Shallow placement never hoists a transitive dependency to the root.
        // Root is vacant. Check if vacant root is shadowed by an incompatible intermediate node
        if !is_shadowed_by_incompatible_between(graph, parent_location, "", install_name, target)
            && !candidate_peer_conflict(
                graph,
                &path_buf,
                parent_location,
                dependencies,
                peer_dependencies,
                peer_dependencies_meta,
                placing_peer,
            )
        {
            return PlacementDecision::PlaceNew(path_buf);
        }
    }

    // Attempt 2: Check intermediate ancestor scopes from root towards parent
    if let Some(first_parent) = parent_scope(parent_location) {
        if !first_parent.is_empty() {
            let mut ancestors = Vec::new();
            let mut curr = parent_location;
            while let Some(next) = parent_scope(curr) {
                if next.is_empty() {
                    break;
                }
                if next.contains("/node_modules/")
                    || next.starts_with("node_modules/")
                    || graph.nodes.contains_key(next)
                {
                    ancestors.push(next);
                }
                curr = next;
            }

            let resolved_parsed = resolved_version.and_then(cached_version_rc);
            for ancestor in ancestors.into_iter().rev() {
                path_buf.clear();
                path_buf.push_str(ancestor);
                path_buf.push_str("/node_modules/");
                path_buf.push_str(install_name);

                if let Some(existing) = graph.nodes.get(&path_buf) {
                    if existing.name == package_name
                        && node_satisfies_target(existing, target)
                        && reuse_peer_set(existing, &path_buf)
                        && !is_shadowed_by_incompatible_between(
                            graph,
                            parent_location,
                            ancestor,
                            install_name,
                            target,
                        )
                    {
                        return PlacementDecision::Reuse(path_buf);
                    }
                } else if !is_shadowed_by_incompatible_between(
                    graph,
                    parent_location,
                    ancestor,
                    install_name,
                    target,
                ) && !candidate_peer_conflict(
                    graph,
                    &path_buf,
                    parent_location,
                    dependencies,
                    peer_dependencies,
                    peer_dependencies_meta,
                    placing_peer,
                ) && !candidate_shadows_ancestor_dep(
                    graph,
                    ancestor,
                    install_name,
                    package_name,
                    target,
                    resolved_version,
                    resolved_parsed.as_deref(),
                ) && !candidate_shadows_descendant_dep_parsed(
                    graph,
                    ancestor,
                    install_name,
                    resolved_version,
                    resolved_parsed.as_deref(),
                ) {
                    return PlacementDecision::PlaceNew(path_buf);
                }
            }
        }
    }

    // Attempt 3: Conflict nesting under parent
    path_buf.clear();
    path_buf.push_str(parent_location);
    path_buf.push_str("/node_modules/");
    path_buf.push_str(install_name);

    if let Some(existing) = graph.nodes.get(&path_buf) {
        if existing.name == package_name && node_satisfies_target(existing, target) {
            return PlacementDecision::Reuse(path_buf);
        }
    }

    PlacementDecision::PlaceNew(path_buf)
}

fn candidate_shadows_ancestor_dep(
    graph: &DependencyGraph,
    ancestor: &str,
    install_name: &str,
    package_name: &str,
    target: &PackageTarget,
    resolved_version: Option<&str>,
    resolved_parsed: Option<&Version>,
) -> bool {
    let Some(ancestor_node) = graph.nodes.get(ancestor) else {
        return false;
    };
    let is_top = ancestor.is_empty()
        || !ancestor
            .split(['/', '\\'])
            .any(|segment| segment == "node_modules");
    let dep_spec = ancestor_node
        .dependencies
        .get(install_name)
        .or_else(|| ancestor_node.dependencies.get(package_name))
        .or_else(|| ancestor_node.optional_dependencies.get(install_name))
        .or_else(|| ancestor_node.optional_dependencies.get(package_name))
        .or_else(|| {
            if is_top {
                ancestor_node
                    .dev_dependencies
                    .get(install_name)
                    .or_else(|| ancestor_node.dev_dependencies.get(package_name))
            } else {
                None
            }
        })
        .or_else(|| ancestor_node.peer_dependencies.get(install_name))
        .or_else(|| ancestor_node.peer_dependencies.get(package_name));

    let Some(spec) = dep_spec else {
        return false;
    };

    if let Some(req_target) = cached_target_rc(spec) {
        if let Some(version) = resolved_version {
            return !version_entry_satisfies_target(version, resolved_parsed, &req_target);
        }
        if let Some(visible) = find_visible_peer_node(graph, ancestor, install_name, package_name) {
            if node_satisfies_target(visible, &req_target)
                && !node_satisfies_target(visible, target)
            {
                return true;
            }
        }
        match target {
            PackageTarget::Version(v) => {
                if !parsed_version_satisfies_target(v, None, &req_target) {
                    return true;
                }
            }
            PackageTarget::Range(range) => {
                if let Some(v) = cached_version_rc(&range.raw) {
                    if !parsed_version_satisfies_target(&v, Some(&range.raw), &req_target) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

#[inline]
fn is_in_scope_subtree(loc: &str, scope: &str) -> bool {
    if loc == scope {
        return false;
    }
    if scope.is_empty() {
        loc.starts_with("node_modules/")
    } else {
        if !loc.starts_with(scope) {
            return false;
        }
        let rest = &loc.as_bytes()[scope.len()..];
        if rest.first() != Some(&b'/') {
            return false;
        }
        if rest.starts_with(b"/node_modules/") {
            return true;
        }
        iter_ancestor_scopes(loc).any(|s| s == scope)
    }
}

#[cfg(test)]
fn candidate_shadows_descendant_dep(
    graph: &DependencyGraph,
    scope: &str,
    install_name: &str,
    resolved_version: Option<&str>,
) -> bool {
    let parsed = resolved_version.and_then(cached_version_rc);
    candidate_shadows_descendant_dep_parsed(
        graph,
        scope,
        install_name,
        resolved_version,
        parsed.as_deref(),
    )
}

// CanPlaceDep.checkCanPlaceNoCurrent: introducing a node in an empty slot
// must not intercept a valid descendant edge that currently resolves above
// this scope. Otherwise a later sibling silently breaks an earlier branch.
fn candidate_shadows_descendant_dep_parsed(
    graph: &DependencyGraph,
    scope: &str,
    install_name: &str,
    resolved_version: Option<&str>,
    resolved_parsed: Option<&Version>,
) -> bool {
    let Some(version) = resolved_version else {
        return false;
    };
    // Arborist attaches edgesOut when a node enters the tree, before that
    // node's turn in depsQueue. Our graph.edges only contains processed
    // tasks, so also inspect pending edges from the manifest.
    let check_node = |loc: &str| -> bool {
        if !is_in_scope_subtree(loc, scope) {
            return false;
        }
        let Some(node) = graph.nodes.get(loc) else {
            return false;
        };
        let Some(spec) = node
            .optional_dependencies
            .get(install_name)
            .or_else(|| node.dependencies.get(install_name))
            .or_else(|| node.peer_dependencies.get(install_name))
        else {
            return false;
        };
        let Some(target) = cached_target_rc(spec) else {
            return false;
        };
        // Fast exit: if the candidate satisfies this descendant's constraint, it cannot shadow incompatibly.
        if version_entry_satisfies_target(version, resolved_parsed, &target) {
            return false;
        }
        find_visible_node(graph, &node.location, install_name).is_some_and(|current| {
            !is_in_scope_subtree(&current.location, scope)
                && node_satisfies_target(current, &target)
        })
    };

    if !graph.nodes_by_dep_name.is_empty() {
        if let Some(relevant) = graph.nodes_by_dep_name.get(install_name) {
            if relevant.iter().any(|loc| check_node(loc)) {
                return true;
            }
        }
    } else if graph.nodes.values().any(|node| check_node(&node.location)) {
        return true;
    }

    let check_edge = |edge: &crate::graph::DependencyEdge| -> bool {
        if edge.install_name != install_name
            || !is_in_scope_subtree(&edge.from_location, scope)
            || is_in_scope_subtree(&edge.to_location, scope)
        {
            return false;
        }
        let Some(target) = cached_target_rc(&edge.spec) else {
            return false;
        };
        if version_entry_satisfies_target(version, resolved_parsed, &target) {
            return false;
        }
        graph
            .nodes
            .get(&edge.to_location)
            .is_some_and(|current| node_satisfies_target(current, &target))
    };

    if !graph.edges_by_install_name.is_empty() {
        if let Some(relevant_edges) = graph.edges_by_install_name.get(install_name) {
            relevant_edges.iter().any(|&idx| check_edge(&graph.edges[idx]))
        } else {
            false
        }
    } else {
        graph.edges.iter().any(check_edge)
    }
}

fn candidate_peer_conflict(
    graph: &DependencyGraph,
    candidate_location: &str,
    parent_location: &str,
    dependencies: &std::collections::BTreeMap<String, String>,
    peer_dependencies: &std::collections::BTreeMap<String, String>,
    peer_dependencies_meta: &std::collections::BTreeMap<
        String,
        rnpm_core::manifest::PeerDependencyMeta,
    >,
    placing_peer: bool,
) -> bool {
    if peer_dependencies.is_empty() {
        return false;
    }
    peer_dependencies.iter().any(|(peer_name, peer_spec)| {
        let is_dep = !dependencies.is_empty() && dependencies.contains_key(peer_name);
        let optional = !peer_dependencies_meta.is_empty()
            && peer_dependencies_meta
                .get(peer_name)
                .is_some_and(|meta| meta.optional);
        if is_dep && (placing_peer || optional) {
            return false;
        }
        let Some(existing) =
            find_visible_peer_node(graph, candidate_location, peer_name, peer_name)
        else {
            return false;
        };
        let Some(target) = cached_target_rc(peer_spec) else {
            return false;
        };
        if node_satisfies_target(existing, &target) {
            return false;
        }

        if !placing_peer && !optional {
            return true;
        }
        if is_dep {
            return false;
        }
        // Optional peers constrain placement when an incompatible visible
        // version exists. Required peers retain the existing conflict
        // diagnostics and resolution path.
        if optional {
            return !root_provider_replaceable(graph, existing, peer_name, peer_spec);
        }

        // For required peers: if parent scope has a satisfying peer visible,
        // or if parent declares a direct dependency on the peer package,
        // do not hoist to candidate_location where the visible peer is incompatible.
        if !parent_location.is_empty() {
            if let Some(parent_peer) =
                find_visible_peer_node(graph, parent_location, peer_name, peer_name)
            {
                if node_satisfies_target(parent_peer, &target) {
                    return true;
                }
            }
            if let Some(parent_node) = graph.nodes.get(parent_location) {
                if parent_node.dependencies.contains_key(peer_name) {
                    return true;
                }
            }
        }

        false
    })
}

#[cfg(test)]
fn candidate_has_incompatible_peer(
    graph: &DependencyGraph,
    candidate_location: &str,
    parent_location: &str,
    dependencies: &std::collections::BTreeMap<String, String>,
    peer_dependencies: &std::collections::BTreeMap<String, String>,
    peer_dependencies_meta: &std::collections::BTreeMap<
        String,
        rnpm_core::manifest::PeerDependencyMeta,
    >,
) -> bool {
    candidate_peer_conflict(
        graph,
        candidate_location,
        parent_location,
        dependencies,
        peer_dependencies,
        peer_dependencies_meta,
        true,
    )
}

/// can-place-dep: a top-level provider can be REPLACEd by a pinned version when
/// every edge into it accepts that version (Node#canReplace). The replacement
/// happens when the optional peer edge is resolved.
pub fn root_provider_replaceable(
    graph: &DependencyGraph,
    existing: &crate::graph::Node,
    peer_name: &str,
    peer_spec: &str,
) -> bool {
    if existing.location.len() != 13 + peer_name.len()
        || !existing.location.starts_with("node_modules/")
        || &existing.location[13..] != peer_name
    {
        return false;
    }
    let Some(version) = cached_version_rc(peer_spec) else {
        return false;
    };
    provider_accepts_parsed_version(graph, &existing.location, &version.to_string(), Some((*version).clone()))
}

/// Every edge into `location` accepts `version` in place of the current node,
/// and there is at least one.
pub fn provider_accepts_version(graph: &DependencyGraph, location: &str, version: &str) -> bool {
    let parsed = cached_parse_version(version);
    provider_accepts_parsed_version(graph, location, version, parsed)
}

fn provider_accepts_parsed_version(
    graph: &DependencyGraph,
    location: &str,
    version: &str,
    parsed_version: Option<Version>,
) -> bool {
    let Some(existing) = graph.nodes.get(location) else {
        return false;
    };
    let replacement = crate::graph::Node {
        version: version.to_string(),
        parsed_version,
        resolved: None,
        integrity: None,
        ..existing.clone()
    };
    // A provider whose placing edge is not recorded yet (a late optional peer
    // activated while it is being placed) has dependents this cannot see.
    if !graph.incoming_edges_by_location.is_empty() {
        if let Some(incoming) = graph.incoming_edges_by_location.get(location) {
            if incoming.is_empty() {
                return false;
            }
            incoming.iter().all(|&idx| {
                let edge = &graph.edges[idx];
                cached_target_rc(&edge.spec)
                    .is_some_and(|target| node_satisfies_target(&replacement, &target))
            })
        } else {
            false
        }
    } else {
        let mut incoming = graph
            .edges
            .iter()
            .filter(|edge| edge.to_location == location)
            .peekable();
        incoming.peek().is_some()
            && incoming.all(|edge| {
                cached_target_rc(&edge.spec)
                    .is_some_and(|target| node_satisfies_target(&replacement, &target))
            })
    }
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
    if !graph.nodes_by_install_name.is_empty() {
        let Some(locs) = graph.nodes_by_install_name.get(install_name) else {
            return false;
        };
        // Fast exit: if every copy of `install_name` is at root (`node_modules/<pkg>`)
        // or not nested along an ancestor scope of `from_scope`, no intermediate node can shadow.
        let suffix_len = 14 + install_name.len();
        let any_potential_intermediate = locs.iter().any(|loc| {
            if loc.len() <= suffix_len {
                return false;
            }
            let Some((scope, leaf)) = loc.rsplit_once("/node_modules/") else {
                return false;
            };
            leaf == install_name
                && !scope.is_empty()
                && scope != to_ancestor
                && (from_scope == scope
                    || (from_scope.len() > scope.len()
                        && from_scope.starts_with(scope)
                        && from_scope.as_bytes()[scope.len()] == b'/'))
        });
        if !any_potential_intermediate {
            return false;
        }
    }
    let mut current = from_scope;
    let mut candidate_buf = String::with_capacity(from_scope.len() + 14 + install_name.len());
    while !current.is_empty() && current != to_ancestor {
        candidate_buf.clear();
        candidate_buf.push_str(current);
        candidate_buf.push_str("/node_modules/");
        candidate_buf.push_str(install_name);
        if let Some(node) = graph.nodes.get(&candidate_buf) {
            return !node_satisfies_target(node, target);
        }
        current = match parent_scope(current) {
            Some(p) => p,
            None => break,
        };
    }
    false
}

/// Helper check if a node matches either `install_name` or physical `name`.
#[inline]
pub fn node_matches_peer_name(
    node: &crate::graph::Node,
    install_name: &str,
    package_name: &str,
) -> bool {
    node.name == package_name
        || node.install_name == install_name
        || node.name == install_name
        || node.install_name == package_name
}

/// Finds the closest visible node for a peer requirement matching either its `install_name`
/// OR its physical `package_name` (e.g. for aliased packages `install_name != package_name`).
pub fn find_visible_peer_node<'a>(
    graph: &'a DependencyGraph,
    from_location: &str,
    install_name: &str,
    package_name: &str,
) -> Option<&'a crate::graph::Node> {
    if !graph.nodes_by_install_name.is_empty() {
        let by_install = graph.nodes_by_install_name.get(install_name);
        if package_name == install_name {
            let locs = by_install?;
            if locs.is_empty() {
                return None;
            }
            if locs.len() == 1 {
                let only_loc = &locs[0];
                if let Some(leaf) = only_loc.strip_prefix("node_modules/") {
                    if !leaf.contains("/node_modules/") && leaf == install_name {
                        let node = graph.nodes.get(only_loc)?;
                        return node_matches_peer_name(node, install_name, package_name)
                            .then_some(node);
                    }
                }
                if let Some((scope, leaf)) = only_loc.rsplit_once("/node_modules/") {
                    if leaf == install_name {
                        if from_location == scope || is_in_scope_subtree(from_location, scope) {
                            let node = graph.nodes.get(only_loc)?;
                            return node_matches_peer_name(node, install_name, package_name)
                                .then_some(node);
                        }
                        return None;
                    }
                }
            }
        } else {
            let by_pkg = graph.nodes_by_install_name.get(package_name);
            if by_install.is_none_or(Vec::is_empty) && by_pkg.is_none_or(Vec::is_empty) {
                return None;
            }
        }
    }

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

        // Ascend one directory level in node_modules hierarchy
        current = match parent_scope(current) {
            Some(p) if !p.is_empty() => p,
            _ => break,
        };
    }

    // Finally, check root scope ("")
    // 1. Direct check by install_name
    candidate_buf.clear();
    candidate_buf.push_str("node_modules/");
    candidate_buf.push_str(install_name);
    if let Some(node) = graph.nodes.get(&candidate_buf) {
        if node_matches_peer_name(node, install_name, package_name) {
            return Some(node);
        }
    }

    // 2. Direct check by package_name
    if package_name != install_name {
        candidate_buf.clear();
        candidate_buf.push_str("node_modules/");
        candidate_buf.push_str(package_name);
        if let Some(node) = graph.nodes.get(&candidate_buf) {
            if node_matches_peer_name(node, install_name, package_name) {
                return Some(node);
            }
        }
    }

    None
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
            ..Default::default()
        }
    }

    #[test]
    fn test_hoisting_vacant_root() {
        let graph = DependencyGraph::new();
        let target = PackageTarget::Range(Range::parse("^1.0.0").unwrap());

        let decision = determine_placement(&graph, "node_modules/A", "B", "B", &target);
        assert_eq!(
            decision,
            PlacementDecision::PlaceNew("node_modules/B".to_string())
        );
    }

    #[test]
    fn test_deduplication_compatible_root() {
        let mut graph = DependencyGraph::new();
        graph.nodes.insert(
            "node_modules/B".to_string(),
            make_test_node("node_modules/B", "B", "1.2.0"),
        );

        let target = PackageTarget::Range(Range::parse("^1.0.0").unwrap());
        let decision = determine_placement(&graph, "node_modules/A", "B", "B", &target);
        assert_eq!(
            decision,
            PlacementDecision::Reuse("node_modules/B".to_string())
        );
    }

    #[test]
    fn test_conflict_nesting() {
        let mut graph = DependencyGraph::new();
        // Root has B@1.2.0
        graph.nodes.insert(
            "node_modules/B".to_string(),
            make_test_node("node_modules/B", "B", "1.2.0"),
        );

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
        graph.nodes.insert(
            "node_modules/react".to_string(),
            make_test_node("node_modules/react", "react", "18.2.0"),
        );
        // Nested node_modules/nested-lib/node_modules/local-dep
        graph.nodes.insert(
            "node_modules/nested-lib/node_modules/local-dep".to_string(),
            make_test_node(
                "node_modules/nested-lib/node_modules/local-dep",
                "local-dep",
                "1.0.0",
            ),
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
        assert_eq!(
            vis3.unwrap().location,
            "node_modules/nested-lib/node_modules/local-dep"
        );

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
        graph
            .nodes
            .insert("node_modules/my-react".to_string(), aliased_node);

        // Nested consumer: node_modules/react-redux
        graph.nodes.insert(
            "node_modules/react-redux".to_string(),
            make_test_node("node_modules/react-redux", "react-redux", "8.0.0"),
        );

        // 1. A peer on "react" resolves by folder name, like arborist: the
        //    "my-react" alias folder does not satisfy it.
        let found_by_pkg_name =
            find_visible_peer_node(&graph, "node_modules/react-redux", "react", "react");
        assert!(found_by_pkg_name.is_none());

        // 2. Peer requirement asking for alias name "my-react"
        let found_by_alias =
            find_visible_peer_node(&graph, "node_modules/react-redux", "my-react", "my-react");
        assert!(found_by_alias.is_some());
        assert_eq!(found_by_alias.unwrap().location, "node_modules/my-react");
    }

    #[test]
    fn test_candidate_peer_satisfied_by_direct_dependency() {
        let mut graph = DependencyGraph::new();
        // Visible at root is peer-pkg@1.0.0 (incompatible with ^2.0.0)
        graph.nodes.insert(
            "node_modules/peer-pkg".to_string(),
            make_test_node("node_modules/peer-pkg", "peer-pkg", "1.0.0"),
        );

        let mut direct_deps = std::collections::BTreeMap::new();
        direct_deps.insert("peer-pkg".to_string(), "^2.0.0".to_string());
        let mut peer_deps = std::collections::BTreeMap::new();
        peer_deps.insert("peer-pkg".to_string(), "^2.0.0".to_string());
        let mut peer_meta = std::collections::BTreeMap::new();
        peer_meta.insert(
            "peer-pkg".to_string(),
            rnpm_core::manifest::PeerDependencyMeta { optional: true },
        );

        // When package declares peer-pkg in its own direct dependencies,
        // it satisfies the peer itself, so candidate_has_incompatible_peer must be false
        let has_conflict = candidate_has_incompatible_peer(
            &graph,
            "node_modules/my-pkg",
            "",
            &direct_deps,
            &peer_deps,
            &peer_meta,
        );
        assert!(!has_conflict);

        // Without direct dependency providing it, candidate_has_incompatible_peer is true
        let empty_deps = std::collections::BTreeMap::new();
        let has_conflict_without = candidate_has_incompatible_peer(
            &graph,
            "node_modules/my-pkg",
            "",
            &empty_deps,
            &peer_deps,
            &peer_meta,
        );
        assert!(has_conflict_without);
    }

    #[test]
    fn file_target_reuses_equivalent_relative_resolution() {
        let mut node = make_test_node("node_modules/test", "test", "1.0.0");
        node.resolved = Some("file:./pkgs/test.tgz".to_string());
        let target = PackageTarget::parse("file:pkgs/test.tgz").unwrap();
        assert!(node_satisfies_target(&node, &target));
        node.resolved = Some("file:./other/test.tgz".to_string());
        assert!(!node_satisfies_target(&node, &target));
    }

    #[test]
    fn test_node_satisfies_target_tightened() {
        let mut node = make_test_node("node_modules/test", "test", "1.0.0");
        node.resolved = None; // e.g. root or uninitialized node

        let url_target = PackageTarget::parse("https://example.com/test-1.0.0.tgz").unwrap();
        assert!(!node_satisfies_target(&node, &url_target));

        let file_target = PackageTarget::parse("file:../test.tgz").unwrap();
        assert!(!node_satisfies_target(&node, &file_target));

        let git_target = PackageTarget::parse("git+https://github.com/foo/bar.git").unwrap();
        assert!(!node_satisfies_target(&node, &git_target));

        // When resolved matches exactly
        node.resolved = Some("https://example.com/test-1.0.0.tgz".to_string());
        assert!(node_satisfies_target(&node, &url_target));
    }

    #[test]
    fn test_nested_workspace_intermediate_ancestor_scope_traversal() {
        let mut graph = DependencyGraph::new();
        // Root has conflicting lib@2.0.0
        graph.nodes.insert(
            "node_modules/lib".to_string(),
            make_test_node("node_modules/lib", "lib", "2.0.0"),
        );
        // Parent workspace node
        graph.nodes.insert(
            "packages/parent".to_string(),
            make_test_node("packages/parent", "parent-ws", "1.0.0"),
        );
        // Nested workspace node
        graph.nodes.insert(
            "packages/parent/nested".to_string(),
            make_test_node("packages/parent/nested", "nested-ws", "1.0.0"),
        );

        let target = PackageTarget::Range(Range::parse("^1.0.0").unwrap());
        // Vacant intermediate scope in parent workspace is chosen over nesting inside nested workspace
        let decision = determine_placement(
            &graph,
            "packages/parent/nested",
            "lib",
            "lib",
            &target,
        );
        assert_eq!(
            decision,
            PlacementDecision::PlaceNew("packages/parent/node_modules/lib".to_string())
        );

        // If parent workspace already has a compatible lib@1.2.0, it is reused
        graph.nodes.insert(
            "packages/parent/node_modules/lib".to_string(),
            make_test_node("packages/parent/node_modules/lib", "lib", "1.2.0"),
        );
        let decision_reuse = determine_placement(
            &graph,
            "packages/parent/nested",
            "lib",
            "lib",
            &target,
        );
        assert_eq!(
            decision_reuse,
            PlacementDecision::Reuse("packages/parent/node_modules/lib".to_string())
        );
    }

    #[test]
    fn test_candidate_shadows_ancestor_dev_and_peer_dependencies() {
        let mut graph = DependencyGraph::new();
        // Workspace member or root package honors devDependencies
        let mut ws_ancestor = make_test_node("packages/parent", "parent", "1.0.0");
        ws_ancestor
            .dev_dependencies
            .insert("dev-dep".to_string(), "^1.0.0".to_string());
        graph
            .nodes
            .insert("packages/parent".to_string(), ws_ancestor);

        // Installed package in node_modules honors peerDependencies, but never devDependencies
        let mut installed_ancestor = make_test_node("node_modules/parent", "parent", "1.0.0");
        installed_ancestor
            .dev_dependencies
            .insert("dev-dep".to_string(), "^1.0.0".to_string());
        installed_ancestor
            .peer_dependencies
            .insert("peer-dep".to_string(), "^1.0.0".to_string());
        graph
            .nodes
            .insert("node_modules/parent".to_string(), installed_ancestor);

        let target_v2 = PackageTarget::Range(Range::parse("^2.0.0").unwrap());
        let target_v1 = PackageTarget::Range(Range::parse("^1.0.0").unwrap());

        // devDependencies shadowing guard for workspace package
        assert!(candidate_shadows_ancestor_dep(
            &graph,
            "packages/parent",
            "dev-dep",
            "dev-dep",
            &target_v2,
            Some("2.0.0"),
            None,
        ));
        assert!(!candidate_shadows_ancestor_dep(
            &graph,
            "packages/parent",
            "dev-dep",
            "dev-dep",
            &target_v1,
            Some("1.1.0"),
            None,
        ));

        // devDependencies on installed packages in node_modules are ignored and never shadow
        assert!(!candidate_shadows_ancestor_dep(
            &graph,
            "node_modules/parent",
            "dev-dep",
            "dev-dep",
            &target_v2,
            Some("2.0.0"),
            None,
        ));

        // peerDependencies shadowing guard on installed packages
        assert!(candidate_shadows_ancestor_dep(
            &graph,
            "node_modules/parent",
            "peer-dep",
            "peer-dep",
            &target_v2,
            Some("2.0.0"),
            None,
        ));
        assert!(!candidate_shadows_ancestor_dep(
            &graph,
            "node_modules/parent",
            "peer-dep",
            "peer-dep",
            &target_v1,
            Some("1.5.0"),
            None,
        ));
    }

    #[test]
    fn test_candidate_shadows_descendant_dep_root_empty_scope() {
        use crate::graph::{DependencyEdge, DependencyType};

        let mut graph = DependencyGraph::new();
        let child_node =
            make_test_node("node_modules/parent/node_modules/child", "child", "1.0.0");
        graph.nodes.insert(
            "node_modules/parent/node_modules/child".to_string(),
            child_node,
        );

        // Workspace package outside node_modules (e.g. packages/shared-lib@1.0.0)
        let ws_node = make_test_node("packages/shared-lib", "shared-lib", "1.0.0");
        graph
            .nodes
            .insert("packages/shared-lib".to_string(), ws_node);

        // Edge from descendant child pointing to workspace package outside node_modules
        graph.edges.push(DependencyEdge {
            from_location: "node_modules/parent/node_modules/child".to_string(),
            to_location: "packages/shared-lib".to_string(),
            install_name: "shared-lib".to_string(),
            package_name: "shared-lib".to_string(),
            spec: "^1.0.0".to_string(),
            dep_type: DependencyType::Prod,
        });

        // When placing at root scope "" (prefix "node_modules/"):
        // Introducing shared-lib@2.0.0 shadows child's requirement ^1.0.0 -> returns true
        assert!(candidate_shadows_descendant_dep(
            &graph,
            "",
            "shared-lib",
            Some("2.0.0"),
        ));

        // Introducing shared-lib@1.2.0 is compatible -> returns false
        assert!(!candidate_shadows_descendant_dep(
            &graph,
            "",
            "shared-lib",
            Some("1.2.0"),
        ));
    }

    #[test]
    fn test_is_shadowed_by_incompatible_between_nested_workspace_boundaries() {
        let mut graph = DependencyGraph::new();
        // Intermediate node at packages/parent/node_modules/pkg has version 2.0.0
        graph.nodes.insert(
            "packages/parent/node_modules/pkg".to_string(),
            make_test_node("packages/parent/node_modules/pkg", "pkg", "2.0.0"),
        );

        let target_v1 = PackageTarget::Range(Range::parse("^1.0.0").unwrap());
        let target_v2 = PackageTarget::Range(Range::parse("^2.0.0").unwrap());

        // From packages/parent/nested to root "": traverses through packages/parent
        // Finds incompatible pkg@2.0.0 when target is ^1.0.0
        assert!(is_shadowed_by_incompatible_between(
            &graph,
            "packages/parent/nested",
            "",
            "pkg",
            &target_v1,
        ));

        // When target is ^2.0.0, pkg@2.0.0 satisfies target -> not shadowed by incompatible
        assert!(!is_shadowed_by_incompatible_between(
            &graph,
            "packages/parent/nested",
            "",
            "pkg",
            &target_v2,
        ));
    }

    #[test]
    fn test_parent_scope_and_iter_ancestor_scopes() {
        assert_eq!(parent_scope(""), None);
        assert_eq!(parent_scope("node_modules/foo"), Some(""));
        assert_eq!(parent_scope("node_modules/@scope/pkg"), Some(""));
        assert_eq!(
            parent_scope("node_modules/foo/node_modules/bar"),
            Some("node_modules/foo")
        );
        assert_eq!(
            parent_scope("packages/parent/nested"),
            Some("packages/parent")
        );
        assert_eq!(parent_scope("packages/parent"), Some("packages"));
        assert_eq!(parent_scope("packages"), Some(""));
        assert_eq!(
            parent_scope("packages/parent/nested/node_modules/dep"),
            Some("packages/parent/nested")
        );
        assert_eq!(
            parent_scope("packages/parent/nested/node_modules/@scope/dep"),
            Some("packages/parent/nested")
        );

        let scopes: Vec<&str> = iter_ancestor_scopes("packages/parent/nested").collect();
        assert_eq!(
            scopes,
            vec!["packages/parent/nested", "packages/parent", "packages", ""]
        );

        let root_scopes: Vec<&str> = iter_ancestor_scopes("node_modules/foo").collect();
        assert_eq!(root_scopes, vec!["node_modules/foo", ""]);

        let empty_scopes: Vec<&str> = iter_ancestor_scopes("").collect();
        assert_eq!(empty_scopes, vec![""]);
    }

    #[test]
    fn test_candidate_shadows_descendant_in_nested_workspace() {
        use crate::graph::{DependencyEdge, DependencyType};

        let mut graph = DependencyGraph::new();
        // A node inside nested workspace packages/parent/nested
        let nested_dep = make_test_node(
            "packages/parent/nested/node_modules/leaf",
            "leaf",
            "1.0.0",
        );
        graph.nodes.insert(
            "packages/parent/nested/node_modules/leaf".to_string(),
            nested_dep,
        );

        // Outside dependency at root node_modules/shared-pkg@1.0.0
        let root_dep = make_test_node("node_modules/shared-pkg", "shared-pkg", "1.0.0");
        graph
            .nodes
            .insert("node_modules/shared-pkg".to_string(), root_dep);

        // Edge from leaf in nested workspace pointing to root shared-pkg
        graph.edges.push(DependencyEdge {
            from_location: "packages/parent/nested/node_modules/leaf".to_string(),
            to_location: "node_modules/shared-pkg".to_string(),
            install_name: "shared-pkg".to_string(),
            package_name: "shared-pkg".to_string(),
            spec: "^1.0.0".to_string(),
            dep_type: DependencyType::Prod,
        });

        // Introducing incompatible shared-pkg@2.0.0 at intermediate ancestor scope "packages/parent"
        // must be detected as shadowing descendant leaf's dependency!
        assert!(candidate_shadows_descendant_dep(
            &graph,
            "packages/parent",
            "shared-pkg",
            Some("2.0.0"),
        ));

        // Introducing compatible shared-pkg@1.5.0 at "packages/parent" does not shadow
        assert!(!candidate_shadows_descendant_dep(
            &graph,
            "packages/parent",
            "shared-pkg",
            Some("1.5.0"),
        ));
    }

    #[test]
    fn test_nearest_shadowing_intermediate_scopes() {
        let mut graph = DependencyGraph::new();
        // Nearest intermediate node at packages/parent/node_modules/pkg has compatible 1.0.0
        graph.nodes.insert(
            "packages/parent/node_modules/pkg".to_string(),
            make_test_node("packages/parent/node_modules/pkg", "pkg", "1.0.0"),
        );
        // Higher intermediate node at packages/node_modules/pkg has incompatible 2.0.0
        graph.nodes.insert(
            "packages/node_modules/pkg".to_string(),
            make_test_node("packages/node_modules/pkg", "pkg", "2.0.0"),
        );

        let target = PackageTarget::Range(Range::parse("^1.0.0").unwrap());

        // Nearest intermediate node is 1.0.0 which satisfies ^1.0.0,
        // so it shadows the higher 2.0.0 and returns false (not shadowed by incompatible)
        assert!(!is_shadowed_by_incompatible_between(
            &graph,
            "packages/parent/nested",
            "",
            "pkg",
            &target,
        ));

        // If nearest intermediate node is 0.5.0 (incompatible), it returns true
        graph.nodes.insert(
            "packages/parent/node_modules/pkg".to_string(),
            make_test_node("packages/parent/node_modules/pkg", "pkg", "0.5.0"),
        );
        assert!(is_shadowed_by_incompatible_between(
            &graph,
            "packages/parent/nested",
            "",
            "pkg",
            &target,
        ));
    }
}
