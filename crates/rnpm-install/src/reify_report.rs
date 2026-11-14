//! The add/change/remove report npm prints after reify, ported from
//! arborist's lib/diff.js (tree order and action rules) as consumed by
//! npm's lib/utils/reify-output.js.

use rnpm_lockfile::LockfilePackage;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// One package as reify-output reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReifyEntry {
    pub name: String,
    pub version: String,
    /// Lockfile location relative to the project root.
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReifyChange {
    Add(ReifyEntry),
    Change { from: ReifyEntry, to: ReifyEntry },
    Remove(ReifyEntry),
}

/// Diff between the actual tree before reify and the ideal tree, plus the
/// size of the resulting tree inventory (npm's `audited` count).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReifyReport {
    pub changes: Vec<ReifyChange>,
    pub inventory: usize,
}

/// Splits a location into its parent location and child name. Returns None
/// for locations that are not inside a node_modules folder.
fn split_location(location: &str) -> Option<(&str, &str)> {
    let (parent, name) = match location.rfind("node_modules/") {
        Some(idx) => (&location[..idx], &location[idx + "node_modules/".len()..]),
        None => return None,
    };
    let parent = parent.strip_suffix('/').unwrap_or(parent);
    if name.is_empty() {
        return None;
    }
    // A scoped name keeps its scope segment: node_modules/@s/n.
    Some((parent, name))
}

fn entry(location: &str, pkg: &LockfilePackage, all: &BTreeMap<String, LockfilePackage>) -> ReifyEntry {
    let folder = split_location(location).map(|(_, n)| n).unwrap_or(location);
    let version = if pkg.link == Some(true) {
        pkg.resolved
            .as_ref()
            .and_then(|target| all.get(target))
            .and_then(|t| t.version.clone())
            .unwrap_or_default()
    } else {
        pkg.version.clone().unwrap_or_default()
    };
    // Node.name is the folder name; aliases keep their alias as the name.
    ReifyEntry { name: folder.to_string(), version, location: location.to_string() }
}

/// ssri's `match`: the integrities share at least one identical hash.
fn integrity_matches(a: &str, b: &str) -> bool {
    let left: BTreeSet<&str> = a.split_whitespace().collect();
    b.split_whitespace().any(|h| left.contains(h))
}

fn is_dep_bundled(location: &str, pkg: &LockfilePackage) -> bool {
    pkg.in_bundle == Some(true)
        && split_location(location).is_some_and(|(parent, _)| split_location(parent).is_some())
}

/// arborist diff.js getAction.
fn action(location: &str, actual: Option<&LockfilePackage>, ideal: Option<&LockfilePackage>) -> Option<&'static str> {
    let Some(ideal) = ideal else {
        return actual.map(|_| "REMOVE");
    };
    let Some(actual) = actual else {
        return (!is_dep_bundled(location, ideal)).then_some("ADD");
    };
    if ideal.link == Some(true) || actual.link == Some(true) {
        return (ideal.link != actual.link || ideal.resolved != actual.resolved).then_some("CHANGE");
    }
    if ideal.version != actual.version {
        return Some("CHANGE");
    }
    if ideal.integrity.is_none() && actual.integrity.is_none() {
        let no_resolved = ideal.resolved.is_none() && actual.resolved.is_none();
        let resolved_match = ideal.resolved.is_some() && ideal.resolved == actual.resolved;
        return (!(no_resolved || resolved_match)).then_some("CHANGE");
    }
    match (&ideal.integrity, &actual.integrity) {
        (Some(i), Some(a)) if integrity_matches(i, a) => None,
        _ => Some("CHANGE"),
    }
}

/// Computes the reify diff. `inert` marks ideal nodes that will not be
/// placed on disk (omitted or platform-incompatible), which arborist
/// treats as absent from the ideal tree. `include` limits a filtered reify.
pub fn compute(
    ideal: &BTreeMap<String, LockfilePackage>,
    actual: &BTreeMap<String, LockfilePackage>,
    inert: impl Fn(&str, &LockfilePackage) -> bool,
    include: impl Fn(&str) -> bool,
) -> ReifyReport {
    let ideal_live: BTreeMap<&str, &LockfilePackage> = ideal
        .iter()
        .filter(|(loc, pkg)| split_location(loc).is_some() && !inert(loc, pkg))
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    let actual_live: BTreeMap<&str, &LockfilePackage> = actual
        .iter()
        .filter(|(loc, _)| split_location(loc).is_some())
        .map(|(k, v)| (k.as_str(), v))
        .collect();

    // Children are keyed by their parent's location. A workspace folder's
    // dependencies belong to the root (arborist's allChildren over fsChildren).
    let parent_of = |loc: &str| -> String {
        let (parent, _) = split_location(loc).unwrap_or(("", loc));
        if split_location(parent).is_some() { parent.to_string() } else { String::new() }
    };
    let mut actual_kids: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for loc in actual_live.keys() {
        actual_kids.entry(parent_of(loc)).or_default().push(loc);
    }
    let mut ideal_kids: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for loc in ideal_live.keys() {
        ideal_kids.entry(parent_of(loc)).or_default().push(loc);
    }

    let mut changes = Vec::new();
    let mut order: Vec<&str> = Vec::new();
    // Pre-order walk: actual children first, then ideal-only children.
    fn walk<'a>(
        parent: &str,
        actual_kids: &BTreeMap<String, Vec<&'a str>>,
        ideal_kids: &BTreeMap<String, Vec<&'a str>>,
        order: &mut Vec<&'a str>,
    ) {
        let mut seen = BTreeSet::new();
        let mut kids: Vec<&'a str> = Vec::new();
        for list in [actual_kids.get(parent), ideal_kids.get(parent)].into_iter().flatten() {
            for loc in list {
                if seen.insert(*loc) {
                    kids.push(loc);
                }
            }
        }
        for loc in kids {
            order.push(loc);
            walk(loc, actual_kids, ideal_kids, order);
        }
    }
    walk("", &actual_kids, &ideal_kids, &mut order);

    for loc in order {
        if !include(loc) {
            continue;
        }
        let actual_pkg = actual_live.get(loc).copied();
        let ideal_pkg = ideal_live.get(loc).copied();
        match action(loc, actual_pkg, ideal_pkg) {
            Some("ADD") => changes.push(ReifyChange::Add(entry(loc, ideal_pkg.unwrap(), ideal))),
            Some("REMOVE") => changes.push(ReifyChange::Remove(entry(loc, actual_pkg.unwrap(), actual))),
            Some(_) => changes.push(ReifyChange::Change {
                from: entry(loc, actual_pkg.unwrap(), actual),
                to: entry(loc, ideal_pkg.unwrap(), ideal),
            }),
            None => {}
        }
    }

    ReifyReport { changes, inventory: ideal.len().max(1) }
}

/// Loads the actual tree the way arborist's loadActual does for reporting:
/// the hidden lockfile when it is current, otherwise the package folders on
/// disk with resolved/integrity filled from the project lockfile when the
/// versions agree.
pub fn load_actual(
    project_dir: &Path,
    hidden_valid: bool,
    project_lock: Option<&BTreeMap<String, LockfilePackage>>,
) -> BTreeMap<String, LockfilePackage> {
    let node_modules = project_dir.join("node_modules");
    if !node_modules.is_dir() {
        return BTreeMap::new();
    }
    if hidden_valid {
        if let Ok(hidden) = rnpm_lockfile::LockfileV3::load_from_file(&node_modules.join(".package-lock.json")) {
            return hidden.packages;
        }
    }
    let mut out = BTreeMap::new();
    scan(project_dir, &node_modules, "node_modules", project_lock, &mut out);
    out
}

fn scan(
    project_dir: &Path,
    dir: &Path,
    prefix: &str,
    project_lock: Option<&BTreeMap<String, LockfilePackage>>,
    out: &mut BTreeMap<String, LockfilePackage>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut names: Vec<_> = entries.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
    names.sort();
    for name in names {
        if name.starts_with('.') {
            continue;
        }
        let path = dir.join(&name);
        if name.starts_with('@') {
            scan(project_dir, &path, &format!("{prefix}/{name}"), project_lock, out);
            continue;
        }
        // Scoped packages arrive here as prefix ".../@scope".
        let location = format!("{prefix}/{name}");
        let is_link = std::fs::symlink_metadata(&path).map(|m| m.file_type().is_symlink()).unwrap_or(false)
            || junction_target(&path).is_some();
        if is_link {
            let target = std::fs::canonicalize(&path)
                .ok()
                .and_then(|t| {
                    let base = std::fs::canonicalize(project_dir).ok()?;
                    t.strip_prefix(&base).ok().map(|r| r.to_string_lossy().replace('\\', "/"))
                });
            out.insert(location, LockfilePackage { link: Some(true), resolved: target, ..Default::default() });
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path.join("package.json")) else { continue };
        let Ok(manifest) = serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}')) else { continue };
        let version = manifest["version"].as_str().map(str::to_string);
        let mut pkg = LockfilePackage { version: version.clone(), ..Default::default() };
        if let Some(locked) = project_lock.and_then(|l| l.get(&location)) {
            if locked.version == version {
                pkg.resolved = locked.resolved.clone();
                pkg.integrity = locked.integrity.clone();
                pkg.in_bundle = locked.in_bundle;
            }
        }
        out.insert(location.clone(), pkg);
        let nested = path.join("node_modules");
        if nested.is_dir() {
            scan(project_dir, &nested, &format!("{location}/node_modules"), project_lock, out);
        }
    }
}

#[cfg(windows)]
fn junction_target(path: &Path) -> Option<std::path::PathBuf> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    use std::os::windows::fs::MetadataExt;
    // FILE_ATTRIBUTE_REPARSE_POINT
    (meta.file_attributes() & 0x400 != 0).then(|| path.to_path_buf())
}

#[cfg(not(windows))]
fn junction_target(_path: &Path) -> Option<std::path::PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(version: &str, integrity: &str) -> LockfilePackage {
        LockfilePackage {
            version: Some(version.into()),
            integrity: Some(integrity.into()),
            resolved: Some(format!("https://r/{version}.tgz")),
            ..Default::default()
        }
    }

    #[test]
    fn orders_actual_children_before_ideal_only_children_preorder() {
        let mut ideal = BTreeMap::new();
        ideal.insert(String::new(), LockfilePackage::default());
        ideal.insert("node_modules/a".into(), pkg("1.0.0", "sha512-a"));
        ideal.insert("node_modules/a/node_modules/x".into(), pkg("1.0.0", "sha512-x"));
        ideal.insert("node_modules/b".into(), pkg("2.0.0", "sha512-b2"));
        let mut actual = BTreeMap::new();
        actual.insert("node_modules/b".into(), pkg("1.0.0", "sha512-b1"));
        actual.insert("node_modules/c".into(), pkg("1.0.0", "sha512-c"));
        let report = compute(&ideal, &actual, |_, _| false, |_| true);
        let kinds: Vec<String> = report
            .changes
            .iter()
            .map(|c| match c {
                ReifyChange::Add(e) => format!("add {}", e.location),
                ReifyChange::Change { to, .. } => format!("change {}", to.location),
                ReifyChange::Remove(e) => format!("remove {}", e.location),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "change node_modules/b",
                "remove node_modules/c",
                "add node_modules/a",
                "add node_modules/a/node_modules/x"
            ]
        );
        assert_eq!(report.inventory, 4);
    }

    #[test]
    fn unchanged_integrity_and_inert_and_dep_bundled_nodes_are_not_reported() {
        let mut ideal = BTreeMap::new();
        ideal.insert("node_modules/same".into(), pkg("1.0.0", "sha512-s sha1-t"));
        ideal.insert("node_modules/dev".into(), pkg("1.0.0", "sha512-d"));
        let mut bundled = pkg("1.0.0", "sha512-n");
        bundled.in_bundle = Some(true);
        ideal.insert("node_modules/same/node_modules/inner".into(), bundled);
        let mut actual = BTreeMap::new();
        actual.insert("node_modules/same".into(), pkg("1.0.0", "sha1-t"));
        let report = compute(&ideal, &actual, |loc, _| loc == "node_modules/dev", |_| true);
        assert!(report.changes.is_empty(), "{:?}", report.changes);
    }
}
