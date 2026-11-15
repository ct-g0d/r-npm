//! The audit report `npm audit fix --dry-run` prints.
//!
//! npm never re-audits a dry run: it prints the report it loaded from the old
//! tree, as mutated while arborist built the ideal tree. Replaced nodes are
//! detached (empty location, no incoming edges), and `Vuln.isVulnerable(node)`
//! adds a replacement node to the vulnerability only when some later-processed
//! dependent checks an edge that already resolves to it. This replays
//! build-ideal-tree's depth/path-ordered dependency queue over the old and
//! ideal lockfiles to reproduce that node set.

use std::collections::{BTreeMap, HashMap, HashSet};

use rnpm_core::semver::{Range, Version};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use rnpm_solver::arborist_compare;

use crate::audit::AuditReport;

/// A tree node: its location and whether it comes from the ideal tree.
type NodeId = (String, bool);

fn depth(loc: &str) -> usize {
    loc.matches("node_modules/").count()
}

fn package_name(loc: &str, pkg: &LockfilePackage) -> String {
    pkg.name.clone().unwrap_or_else(|| {
        loc.rsplit_once("node_modules/")
            .map_or(loc, |(_, n)| n)
            .to_string()
    })
}

fn edge_names(loc: &str, pkg: &LockfilePackage) -> Vec<String> {
    let mut maps = vec![
        &pkg.dependencies,
        &pkg.optional_dependencies,
        &pkg.peer_dependencies,
    ];
    if loc.is_empty() {
        maps.push(&pkg.dev_dependencies);
    }
    let mut names: Vec<String> = maps
        .into_iter()
        .flatten()
        .flat_map(|m| m.keys().cloned())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// node_modules resolution from `from` for `name` in the current tree.
fn resolve<'a>(
    tree: &'a BTreeMap<String, (bool, &LockfilePackage)>,
    from: &str,
    name: &str,
) -> Option<&'a str> {
    let mut base = from;
    loop {
        let cand = if base.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{base}/node_modules/{name}")
        };
        if let Some((key, _)) = tree.get_key_value(&cand) {
            return Some(key.as_str());
        }
        if base.is_empty() {
            return None;
        }
        base = base.rfind("/node_modules/").map_or("", |i| &base[..i]);
    }
}

pub(crate) fn apply(report: &mut AuditReport, old: &LockfileV3, ideal: &LockfileV3) {
    let mut tree: BTreeMap<String, (bool, &LockfilePackage)> = old
        .packages
        .iter()
        .map(|(loc, pkg)| (loc.clone(), (false, pkg)))
        .collect();
    let ranges: HashMap<String, Option<Range>> = report
        .vulnerabilities
        .iter()
        .map(|(name, v)| (name.clone(), Range::parse(&v.range).ok()))
        .collect();
    let mut vuln_nodes: HashMap<String, Vec<NodeId>> = report
        .vulnerabilities
        .iter()
        .map(|(name, v)| {
            let ids = v.nodes.iter().map(|loc| (loc.clone(), false)).collect();
            (name.clone(), ids)
        })
        .collect();
    let mut detached: HashSet<String> = HashSet::new();

    // Vuln.isVulnerable: a member, or a node whose version is in range (which
    // then joins the vulnerability).
    let mut is_vulnerable = |id: &NodeId, pkg: &LockfilePackage| -> bool {
        let name = package_name(&id.0, pkg);
        let Some(nodes) = vuln_nodes.get_mut(&name) else {
            return false;
        };
        if nodes.contains(id) {
            return true;
        }
        let in_range = ranges.get(&name).and_then(Option::as_ref).is_some_and(|r| {
            pkg.version
                .as_deref()
                .and_then(|v| Version::parse(v).ok())
                .is_some_and(|v| r.satisfies(&v))
        });
        if in_range {
            nodes.push(id.clone());
        }
        in_range
    };

    // #queueVulnDependents: every node with an edge into a vulnerable node.
    let mut queue: Vec<NodeId> = Vec::new();
    let vulnerable: HashSet<&str> = report
        .vulnerabilities
        .values()
        .flat_map(|v| v.nodes.iter().map(String::as_str))
        .collect();
    for (loc, (_, pkg)) in &tree {
        if edge_names(loc, pkg)
            .iter()
            .any(|n| resolve(&tree, loc, n).is_some_and(|to| vulnerable.contains(to)))
        {
            queue.push((loc.clone(), false));
        }
    }

    let mut seen: HashSet<NodeId> = HashSet::new();
    while !queue.is_empty() {
        queue.sort_by(|a, b| {
            depth(&a.0)
                .cmp(&depth(&b.0))
                .then_with(|| arborist_compare(&a.0, &b.0))
        });
        let id = queue.remove(0);
        let current = tree.get(&id.0).is_some_and(|(new, _)| *new == id.1);
        if !current || !seen.insert(id.clone()) {
            continue;
        }
        let pkg = tree[&id.0].1;
        for name in edge_names(&id.0, pkg) {
            let Some(to) = resolve(&tree, &id.0, &name).map(str::to_string) else {
                continue;
            };
            let (to_new, to_pkg) = tree[&to];
            let to_id = (to.clone(), to_new);
            if !is_vulnerable(&to_id, to_pkg) || to_new {
                continue;
            }
            // A vulnerable old node the ideal tree replaces: detach it and
            // queue the replacement.
            match ideal.packages.get(&to) {
                Some(next)
                    if next.version == to_pkg.version && next.resolved == to_pkg.resolved => {}
                Some(next) => {
                    detached.insert(to.clone());
                    tree.insert(to.clone(), (true, next));
                    queue.push((to, true));
                }
                None => {
                    detached.insert(to.clone());
                    tree.remove(&to);
                }
            }
        }
    }

    // The finished ideal tree prunes every old node it no longer holds (for
    // example a dependency a replaced parent dropped); those are detached too.
    let pruned: Vec<String> =
        tree.iter()
            .filter(|(loc, (new, pkg))| {
                !loc.is_empty()
                    && !*new
                    && ideal.packages.get(*loc).is_none_or(|next| {
                        next.version != pkg.version || next.resolved != pkg.resolved
                    })
            })
            .map(|(loc, _)| loc.clone())
            .collect();
    for loc in pruned {
        tree.remove(&loc);
        detached.insert(loc);
    }

    // npm counts the inventory of the (now ideal) tree it audited.
    report.metadata.dependencies = crate::audit::dependency_counts(ideal);

    let root = &tree[""];
    let direct: HashSet<&str> = edge_names("", root.1)
        .iter()
        .filter_map(|n| resolve(&tree, "", n))
        .collect();
    for (name, vuln) in report.vulnerabilities.iter_mut() {
        let ids = &vuln_nodes[name];
        let live = |(loc, new): &NodeId| !(!new && detached.contains(loc));
        vuln.is_direct = ids
            .iter()
            .any(|id| live(id) && direct.contains(id.0.as_str()));
        let mut nodes: Vec<String> = ids
            .iter()
            .map(|id| {
                if live(id) {
                    id.0.clone()
                } else {
                    String::new()
                }
            })
            .collect();
        nodes.sort_by(|a, b| arborist_compare(a, b));
        vuln.nodes = nodes;
    }
}
