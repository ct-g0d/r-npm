//! Tree diffing engine for partial installs.
//!
//! Diffs the ideal dependency tree (from the resolver/lockfile) against the actual
//! dependency tree (from `node_modules/.package-lock.json` if present and valid).
//!
//! Produces change actions:
//! - Add: package path in ideal tree but not in actual tree.
//! - Remove: package path in actual tree but not in ideal tree.
//! - Replace: package path in both trees, but version, resolved URL, or integrity differs.
//! - Unchanged: package path in both trees with matching version, resolved URL, and integrity.

use rnpm_lockfile::{LockfilePackage, LockfileV3};
use std::collections::BTreeMap;

/// The category of change action between trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionType {
    Add,
    Remove,
    Replace,
    Unchanged,
}

/// A diff action for a specific package path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeAction {
    Add {
        package: Box<LockfilePackage>,
    },
    Remove {
        package: Box<LockfilePackage>,
    },
    Replace {
        actual: Box<LockfilePackage>,
        ideal: Box<LockfilePackage>,
    },
    Unchanged {
        package: Box<LockfilePackage>,
    },
}

impl TreeAction {
    pub fn action_type(&self) -> ActionType {
        match self {
            Self::Add { .. } => ActionType::Add,
            Self::Remove { .. } => ActionType::Remove,
            Self::Replace { .. } => ActionType::Replace,
            Self::Unchanged { .. } => ActionType::Unchanged,
        }
    }

    pub fn is_add(&self) -> bool {
        matches!(self, Self::Add { .. })
    }

    pub fn is_remove(&self) -> bool {
        matches!(self, Self::Remove { .. })
    }

    pub fn is_replace(&self) -> bool {
        matches!(self, Self::Replace { .. })
    }

    pub fn is_unchanged(&self) -> bool {
        matches!(self, Self::Unchanged { .. })
    }

    pub fn ideal_package(&self) -> Option<&LockfilePackage> {
        match self {
            Self::Add { package } => Some(package.as_ref()),
            Self::Replace { ideal, .. } => Some(ideal.as_ref()),
            Self::Unchanged { package } => Some(package.as_ref()),
            Self::Remove { .. } => None,
        }
    }

    pub fn actual_package(&self) -> Option<&LockfilePackage> {
        match self {
            Self::Remove { package } => Some(package.as_ref()),
            Self::Replace { actual, .. } => Some(actual.as_ref()),
            Self::Unchanged { package } => Some(package.as_ref()),
            Self::Add { .. } => None,
        }
    }
}

/// The result of diffing an ideal tree against an actual tree.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreeDiff {
    pub actions: BTreeMap<String, TreeAction>,
}

impl TreeDiff {
    pub fn new() -> Self {
        Self {
            actions: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, path: String, action: TreeAction) {
        self.actions.insert(path, action);
    }

    pub fn get(&self, path: &str) -> Option<&TreeAction> {
        self.actions.get(path)
    }

    pub fn contains_key(&self, path: &str) -> bool {
        self.actions.contains_key(path)
    }

    pub fn adds(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.actions.iter().filter_map(|(k, a)| match a {
            TreeAction::Add { package } => Some((k, package.as_ref())),
            _ => None,
        })
    }

    pub fn removes(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.actions.iter().filter_map(|(k, a)| match a {
            TreeAction::Remove { package } => Some((k, package.as_ref())),
            _ => None,
        })
    }

    pub fn replaces(&self) -> impl Iterator<Item = (&String, &LockfilePackage, &LockfilePackage)> {
        self.actions.iter().filter_map(|(k, a)| match a {
            TreeAction::Replace { actual, ideal } => Some((k, actual.as_ref(), ideal.as_ref())),
            _ => None,
        })
    }

    pub fn unchanged(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.actions.iter().filter_map(|(k, a)| match a {
            TreeAction::Unchanged { package } => Some((k, package.as_ref())),
            _ => None,
        })
    }

    pub fn add_count(&self) -> usize {
        self.adds().count()
    }

    pub fn remove_count(&self) -> usize {
        self.removes().count()
    }

    pub fn replace_count(&self) -> usize {
        self.replaces().count()
    }

    pub fn unchanged_count(&self) -> usize {
        self.unchanged().count()
    }

    pub fn has_changes(&self) -> bool {
        self.actions.values().any(|a| !a.is_unchanged())
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }
}

/// Helper function to check if two package definitions differ.
///
/// Per specification:
/// Replace when version or resolved URL or integrity differs.
pub fn package_differs(ideal: &LockfilePackage, actual: &LockfilePackage) -> bool {
    if ideal.version != actual.version {
        return true;
    }
    if ideal.resolved != actual.resolved {
        return true;
    }
    if ideal.integrity != actual.integrity {
        return true;
    }
    if ideal.link != actual.link {
        return true;
    }
    false
}

/// Diffs the ideal lockfile against the actual lockfile.
///
/// Skips the root package (`""`) which represents the project itself.
pub fn diff_trees(ideal: &LockfileV3, actual: &LockfileV3) -> TreeDiff {
    diff_package_maps(&ideal.packages, &actual.packages)
}

/// Checks if a package path in the lockfile refers to an installed package folder inside `node_modules`.
pub fn is_node_modules_package_path(path: &str) -> bool {
    !path.is_empty() && (path.starts_with("node_modules/") || path.contains("/node_modules/"))
}

/// Diffs two maps of package path -> LockfilePackage.
pub fn diff_package_maps(
    ideal: &BTreeMap<String, LockfilePackage>,
    actual: &BTreeMap<String, LockfilePackage>,
) -> TreeDiff {
    let mut diff = TreeDiff::new();

    for (path, ideal_pkg) in ideal {
        if !is_node_modules_package_path(path) {
            continue;
        }
        if let Some(actual_pkg) = actual.get(path) {
            if package_differs(ideal_pkg, actual_pkg) {
                diff.insert(
                    path.clone(),
                    TreeAction::Replace {
                        actual: Box::new(actual_pkg.clone()),
                        ideal: Box::new(ideal_pkg.clone()),
                    },
                );
            } else {
                diff.insert(
                    path.clone(),
                    TreeAction::Unchanged {
                        package: Box::new(ideal_pkg.clone()),
                    },
                );
            }
        } else {
            diff.insert(
                path.clone(),
                TreeAction::Add {
                    package: Box::new(ideal_pkg.clone()),
                },
            );
        }
    }

    for (path, actual_pkg) in actual {
        if !is_node_modules_package_path(path) {
            continue;
        }
        if !ideal.contains_key(path) {
            diff.insert(
                path.clone(),
                TreeAction::Remove {
                    package: Box::new(actual_pkg.clone()),
                },
            );
        }
    }

    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkg(version: &str, resolved: &str, integrity: &str) -> LockfilePackage {
        LockfilePackage {
            version: Some(version.to_string()),
            resolved: Some(resolved.to_string()),
            integrity: Some(integrity.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_tree_diff_add_action() {
        let mut ideal = LockfileV3::new("test-app", Some("1.0.0".to_string()));
        let actual = LockfileV3::new("test-app", Some("1.0.0".to_string()));

        ideal.insert_package(
            "node_modules/foo",
            make_pkg("1.0.0", "https://reg/foo.tgz", "sha512-aaa"),
        );

        let diff = diff_trees(&ideal, &actual);
        assert_eq!(diff.add_count(), 1);
        assert_eq!(diff.remove_count(), 0);
        assert_eq!(diff.replace_count(), 0);
        assert_eq!(diff.unchanged_count(), 0);

        let action = diff.get("node_modules/foo").unwrap();
        assert!(action.is_add());
        assert_eq!(
            action.ideal_package().unwrap().version.as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn test_tree_diff_remove_action() {
        let ideal = LockfileV3::new("test-app", Some("1.0.0".to_string()));
        let mut actual = LockfileV3::new("test-app", Some("1.0.0".to_string()));

        actual.insert_package(
            "node_modules/bar",
            make_pkg("2.0.0", "https://reg/bar.tgz", "sha512-bbb"),
        );

        let diff = diff_trees(&ideal, &actual);
        assert_eq!(diff.add_count(), 0);
        assert_eq!(diff.remove_count(), 1);
        assert_eq!(diff.replace_count(), 0);
        assert_eq!(diff.unchanged_count(), 0);

        let action = diff.get("node_modules/bar").unwrap();
        assert!(action.is_remove());
        assert_eq!(
            action.actual_package().unwrap().version.as_deref(),
            Some("2.0.0")
        );
    }

    #[test]
    fn test_tree_diff_replace_on_version() {
        let mut ideal = LockfileV3::new("test-app", Some("1.0.0".to_string()));
        let mut actual = LockfileV3::new("test-app", Some("1.0.0".to_string()));

        actual.insert_package(
            "node_modules/baz",
            make_pkg("1.0.0", "https://reg/baz.tgz", "sha512-ccc"),
        );
        ideal.insert_package(
            "node_modules/baz",
            make_pkg("1.1.0", "https://reg/baz.tgz", "sha512-ccc"),
        );

        let diff = diff_trees(&ideal, &actual);
        assert_eq!(diff.replace_count(), 1);
        let action = diff.get("node_modules/baz").unwrap();
        assert!(action.is_replace());
        assert_eq!(
            action.actual_package().unwrap().version.as_deref(),
            Some("1.0.0")
        );
        assert_eq!(
            action.ideal_package().unwrap().version.as_deref(),
            Some("1.1.0")
        );
    }

    #[test]
    fn test_tree_diff_replace_on_resolved_url() {
        let mut ideal = LockfileV3::new("test-app", Some("1.0.0".to_string()));
        let mut actual = LockfileV3::new("test-app", Some("1.0.0".to_string()));

        actual.insert_package(
            "node_modules/baz",
            make_pkg("1.0.0", "https://reg-a/baz.tgz", "sha512-ccc"),
        );
        ideal.insert_package(
            "node_modules/baz",
            make_pkg("1.0.0", "https://reg-b/baz.tgz", "sha512-ccc"),
        );

        let diff = diff_trees(&ideal, &actual);
        assert_eq!(diff.replace_count(), 1);
        let action = diff.get("node_modules/baz").unwrap();
        assert!(action.is_replace());
    }

    #[test]
    fn test_tree_diff_replace_on_integrity() {
        let mut ideal = LockfileV3::new("test-app", Some("1.0.0".to_string()));
        let mut actual = LockfileV3::new("test-app", Some("1.0.0".to_string()));

        actual.insert_package(
            "node_modules/baz",
            make_pkg("1.0.0", "https://reg/baz.tgz", "sha512-hash1"),
        );
        ideal.insert_package(
            "node_modules/baz",
            make_pkg("1.0.0", "https://reg/baz.tgz", "sha512-hash2"),
        );

        let diff = diff_trees(&ideal, &actual);
        assert_eq!(diff.replace_count(), 1);
        let action = diff.get("node_modules/baz").unwrap();
        assert!(action.is_replace());
    }

    #[test]
    fn test_tree_diff_unchanged() {
        let mut ideal = LockfileV3::new("test-app", Some("1.0.0".to_string()));
        let mut actual = LockfileV3::new("test-app", Some("1.0.0".to_string()));

        actual.insert_package(
            "node_modules/qux",
            make_pkg("3.0.0", "https://reg/qux.tgz", "sha512-quxhash"),
        );
        ideal.insert_package(
            "node_modules/qux",
            make_pkg("3.0.0", "https://reg/qux.tgz", "sha512-quxhash"),
        );

        let diff = diff_trees(&ideal, &actual);
        assert_eq!(diff.unchanged_count(), 1);
        assert!(!diff.has_changes());
        let action = diff.get("node_modules/qux").unwrap();
        assert!(action.is_unchanged());
    }

    #[test]
    fn test_tree_diff_matrix_all_actions() {
        let mut ideal = LockfileV3::new("test-app", Some("1.0.0".to_string()));
        let mut actual = LockfileV3::new("test-app", Some("1.0.0".to_string()));

        // Unchanged
        actual.insert_package("node_modules/pkg-same", make_pkg("1.0.0", "url", "hash"));
        ideal.insert_package("node_modules/pkg-same", make_pkg("1.0.0", "url", "hash"));

        // Add
        ideal.insert_package("node_modules/pkg-new", make_pkg("2.0.0", "url2", "hash2"));

        // Remove
        actual.insert_package("node_modules/pkg-old", make_pkg("0.9.0", "url0", "hash0"));

        // Replace
        actual.insert_package(
            "node_modules/pkg-upgraded",
            make_pkg("1.0.0", "url1", "hash1"),
        );
        ideal.insert_package(
            "node_modules/pkg-upgraded",
            make_pkg("2.0.0", "url1-v2", "hash1-v2"),
        );

        let diff = diff_trees(&ideal, &actual);
        assert_eq!(diff.add_count(), 1);
        assert_eq!(diff.remove_count(), 1);
        assert_eq!(diff.replace_count(), 1);
        assert_eq!(diff.unchanged_count(), 1);
        assert!(diff.has_changes());

        assert!(diff.get("node_modules/pkg-new").unwrap().is_add());
        assert!(diff.get("node_modules/pkg-old").unwrap().is_remove());
        assert!(diff.get("node_modules/pkg-upgraded").unwrap().is_replace());
        assert!(diff.get("node_modules/pkg-same").unwrap().is_unchanged());
    }

    #[test]
    fn test_tree_diff_ignores_root_and_external_paths() {
        let mut ideal = LockfileV3::new("test-app", Some("1.0.0".to_string()));
        let mut actual = LockfileV3::new("test-app", Some("1.0.0".to_string()));

        // Root entry ""
        ideal.insert_package("", make_pkg("1.0.0", "", ""));
        actual.insert_package("", make_pkg("1.0.0", "", ""));

        // External targets
        actual.insert_package("packages/member-a", make_pkg("1.0.0", "", ""));
        ideal.insert_package("packages/member-b", make_pkg("1.0.0", "", ""));

        let diff = diff_trees(&ideal, &actual);
        assert_eq!(diff.len(), 0);
    }
}
