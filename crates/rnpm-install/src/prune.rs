//! Dependency pruning engine: reachability analysis and extraneous package discovery.
//!
//! Provides root manifest analysis, production dependency traversal,
//! node_modules filesystem scanning (including scopes and nested node_modules),
//! and detection of extraneous package directories on disk.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use anyhow::{anyhow, Context, Result};
use tracing::{debug, info};

use rnpm_core::manifest::Manifest;
use rnpm_core::to_posix_path;
use rnpm_core::workspace::discover_workspaces_from_manifest;
use rnpm_fs::junction::{is_junction, remove_dir_all_safe, remove_junction};
use rnpm_lockfile::LockfileV3;

/// Options controlling reachability analysis and dependency pruning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneOptions {
    /// Project root directory containing package.json and node_modules. Defaults to ".".
    pub project_dir: PathBuf,
    /// If true, omit devDependencies regardless of NODE_ENV.
    pub omit_dev: bool,
    /// If true, omit optionalDependencies.
    pub omit_optional: bool,
    /// If true, omit peerDependencies.
    pub omit_peer: bool,
}

impl Default for PruneOptions {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::from("."),
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
        }
    }
}

impl PruneOptions {
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            ..Default::default()
        }
    }

    pub fn with_omit_dev(mut self, omit: bool) -> Self {
        self.omit_dev = omit;
        self
    }

    pub fn with_omit_optional(mut self, omit: bool) -> Self {
        self.omit_optional = omit;
        self
    }

    pub fn with_omit_peer(mut self, omit: bool) -> Self {
        self.omit_peer = omit;
        self
    }

    /// Whether devDependencies should be omitted.
    /// Returns true if `omit_dev` is true or environment variable `NODE_ENV=production`.
    pub fn should_omit_dev(&self) -> bool {
        if self.omit_dev {
            return true;
        }
        if let Ok(env_val) = std::env::var("NODE_ENV") {
            env_val.trim().eq_ignore_ascii_case("production")
        } else {
            false
        }
    }

    /// Whether optionalDependencies should be omitted.
    pub fn should_omit_optional(&self) -> bool {
        self.omit_optional
    }

    /// Whether peerDependencies should be omitted.
    pub fn should_omit_peer(&self) -> bool {
        self.omit_peer
    }
}

/// Information about an extraneous package discovered on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraneousPackage {
    /// Package name (e.g. "express", "@types/node", "sub-dep").
    pub name: String,
    /// Normalized relative POSIX path from project_dir (e.g. "node_modules/foo", "node_modules/@scope/bar", "node_modules/parent/node_modules/child").
    pub path: String,
    /// Absolute or resolved path on disk.
    pub full_path: PathBuf,
    /// Version extracted from package.json if present on disk.
    pub version: Option<String>,
}

/// Structured outcome of reachability analysis and extraneous discovery.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PruneAnalysis {
    /// All reachable package paths in node_modules (e.g. "node_modules/foo").
    pub reachable_packages: HashSet<String>,
    /// All discovered package directories on disk.
    pub discovered_packages: Vec<String>,
    /// Extraneous packages on disk that are NOT reachable.
    pub extraneous_packages: Vec<ExtraneousPackage>,
}

impl PruneAnalysis {
    /// Returns true if no extraneous packages were found.
    pub fn is_clean(&self) -> bool {
        self.extraneous_packages.is_empty()
    }

    /// Returns the list of extraneous POSIX paths.
    pub fn extraneous_paths(&self) -> Vec<String> {
        self.extraneous_packages.iter().map(|p| p.path.clone()).collect()
    }
}

/// Summary of an executed pruning operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PruneSummary {
    /// Relative POSIX paths of removed packages.
    pub removed_packages: Vec<String>,
    /// Lockfile path updated, if any.
    pub lockfile_path: Option<PathBuf>,
}

/// Builds candidate paths in order: from most nested to hoisted root.
pub fn get_candidate_paths(current_pkg_path: &str, dep_name: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if current_pkg_path.is_empty() {
        candidates.push(format!("node_modules/{dep_name}"));
        return candidates;
    }

    // 1. Nested directly inside current package
    candidates.push(format!("{current_pkg_path}/node_modules/{dep_name}"));

    // 2. Ancestor packages up the tree
    let mut curr = current_pkg_path;
    while let Some(idx) = curr.rfind("/node_modules/") {
        let ancestor = &curr[..idx];
        candidates.push(format!("{ancestor}/node_modules/{dep_name}"));
        curr = ancestor;
    }

    // 3. Hoisted root level
    let root_cand = format!("node_modules/{dep_name}");
    if !candidates.contains(&root_cand) {
        candidates.push(root_cand);
    }

    candidates
}

/// Resolves a dependency name required by `current_pkg_path` to its relative POSIX path in `node_modules`.
pub fn resolve_dependency_path(
    project_dir: &Path,
    current_pkg_path: &str,
    dep_name: &str,
    lockfile: Option<&LockfileV3>,
) -> String {
    let candidates = get_candidate_paths(current_pkg_path, dep_name);

    if let Some(lock) = lockfile {
        for cand in &candidates {
            if lock.packages.contains_key(cand) {
                return cand.clone();
            }
        }
    }

    for cand in &candidates {
        let full_path = project_dir.join(cand);
        if full_path.is_dir() || is_junction(&full_path).unwrap_or(false) {
            return cand.clone();
        }
    }

    // Fall back to hoisted root candidate
    candidates.last().cloned().unwrap_or_else(|| format!("node_modules/{dep_name}"))
}

/// Collects required dependencies for a transitive package node.
/// Transitive devDependencies are never included as production dependencies.
fn collect_transitive_dependencies(
    project_dir: &Path,
    pkg_path: &str,
    lockfile: Option<&LockfileV3>,
    omit_optional: bool,
    omit_peer: bool,
) -> HashSet<String> {
    let mut deps = HashSet::new();

    // Source A: on-disk package.json
    let disk_manifest_path = project_dir.join(pkg_path).join("package.json");
    if let Ok(m) = Manifest::from_file(&disk_manifest_path) {
        for name in m.dependencies.keys() {
            deps.insert(name.clone());
        }
        if !omit_optional {
            for name in m.optional_dependencies.keys() {
                deps.insert(name.clone());
            }
        }
        if !omit_peer {
            for name in m.peer_dependencies.keys() {
                deps.insert(name.clone());
            }
        }
        for name in m.bundled_package_names() {
            deps.insert(name);
        }
    }

    // Source B: lockfile entry
    if let Some(lock) = lockfile {
        if let Some(lock_pkg) = lock.packages.get(pkg_path) {
            if lock_pkg.link == Some(true) {
                if let Some(target_rel) = &lock_pkg.resolved {
                    let target_manifest = project_dir.join(target_rel).join("package.json");
                    if let Ok(m) = Manifest::from_file(&target_manifest) {
                        for name in m.dependencies.keys() {
                            deps.insert(name.clone());
                        }
                        if !omit_optional {
                            for name in m.optional_dependencies.keys() {
                                deps.insert(name.clone());
                            }
                        }
                        if !omit_peer {
                            for name in m.peer_dependencies.keys() {
                                deps.insert(name.clone());
                            }
                        }
                        for name in m.bundled_package_names() {
                            deps.insert(name);
                        }
                    }
                }
            }

            if let Some(d) = &lock_pkg.dependencies {
                for name in d.keys() {
                    deps.insert(name.clone());
                }
            }
            if !omit_optional {
                if let Some(opt_d) = &lock_pkg.optional_dependencies {
                    for name in opt_d.keys() {
                        deps.insert(name.clone());
                    }
                }
            }
            if !omit_peer {
                if let Some(peer_d) = &lock_pkg.peer_dependencies {
                    for name in peer_d.keys() {
                        deps.insert(name.clone());
                    }
                }
            }
        }
    }

    deps
}

/// Builds the set of expected package paths in `node_modules` starting from the root manifest.
///
/// Follows transitive production dependencies through installed package `package.json` manifests
/// or lockfile entries.
pub fn analyze_reachability(
    project_dir: &Path,
    manifest: &Manifest,
    options: &PruneOptions,
    lockfile: Option<&LockfileV3>,
) -> Result<HashSet<String>> {
    let omit_dev = options.should_omit_dev();
    let omit_optional = options.should_omit_optional();
    let omit_peer = options.should_omit_peer();

    // 1. Collect direct dependencies from root manifest
    let mut root_dep_names = HashSet::new();

    // Always include production dependencies
    for name in manifest.dependencies.keys() {
        root_dep_names.insert(name.clone());
    }

    // Include devDependencies unless omitted
    if !omit_dev {
        for name in manifest.dev_dependencies.keys() {
            root_dep_names.insert(name.clone());
        }
    }

    // Include optionalDependencies unless omitted
    if !omit_optional {
        for name in manifest.optional_dependencies.keys() {
            root_dep_names.insert(name.clone());
        }
    }

    // Include peerDependencies unless omitted
    if !omit_peer {
        for name in manifest.peer_dependencies.keys() {
            root_dep_names.insert(name.clone());
        }
    }

    // Include workspace members if any are linked in node_modules
    if let Ok(workspace_members) = discover_workspaces_from_manifest(project_dir, manifest) {
        for member in workspace_members {
            root_dep_names.insert(member.name);
        }
    }

    // 2. BFS traversal to build the reachability set of expected node_modules paths
    let mut reachable_packages = HashSet::new();
    let mut queue = VecDeque::new();

    // Direct dependencies resolve to "node_modules/<name>"
    for dep_name in &root_dep_names {
        let expected_key = resolve_dependency_path(project_dir, "", dep_name, lockfile);
        if reachable_packages.insert(expected_key.clone()) {
            queue.push_back(expected_key);
        }
    }

    while let Some(current_pkg_path) = queue.pop_front() {
        let deps = collect_transitive_dependencies(
            project_dir,
            &current_pkg_path,
            lockfile,
            omit_optional,
            omit_peer,
        );

        for child_dep in deps {
            let child_pkg_path = resolve_dependency_path(
                project_dir,
                &current_pkg_path,
                &child_dep,
                lockfile,
            );
            if reachable_packages.insert(child_pkg_path.clone()) {
                queue.push_back(child_pkg_path);
            }
        }
    }

    Ok(reachable_packages)
}

/// Walks `<project_dir>/node_modules` on disk and returns relative POSIX paths of all discovered package directories.
/// Handles standard packages, `@scope/*` namespaces, and nested `node_modules`.
/// Skips dot-entries (such as `.bin`, `.cache`, `.package-lock.json`).
pub fn scan_node_modules(project_dir: &Path) -> Result<Vec<String>> {
    let mut discovered = Vec::new();
    let root_nm = project_dir.join("node_modules");
    if !root_nm.is_dir() {
        return Ok(discovered);
    }

    scan_nm_directory(project_dir, "node_modules", &mut discovered)?;
    Ok(discovered)
}

fn scan_nm_directory(
    project_dir: &Path,
    nm_rel_posix: &str,
    discovered: &mut Vec<String>,
) -> Result<()> {
    let full_nm_path = project_dir.join(nm_rel_posix);
    let entries = match std::fs::read_dir(&full_nm_path) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Skip internal/dot entries (.bin, .package-lock.json, .cache, etc.)
        if name_str.starts_with('.') {
            continue;
        }

        let entry_path = entry.path();
        let is_junc = is_junction(&entry_path).unwrap_or(false);
        let is_dir = entry_path.is_dir() || is_junc;
        if !is_dir {
            continue;
        }

        if name_str.starts_with('@') {
            // Scoped directory (e.g. "@types"): scan its child packages
            let scope_entries = match std::fs::read_dir(&entry_path) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for scope_entry in scope_entries.flatten() {
                let sub_name = scope_entry.file_name();
                let sub_name_str = sub_name.to_string_lossy();
                if sub_name_str.starts_with('.') {
                    continue;
                }

                let sub_path = scope_entry.path();
                let sub_junc = is_junction(&sub_path).unwrap_or(false);
                let sub_is_dir = sub_path.is_dir() || sub_junc;
                if !sub_is_dir {
                    continue;
                }

                let pkg_rel = format!("{nm_rel_posix}/{name_str}/{sub_name_str}");
                discovered.push(pkg_rel.clone());

                // Check for nested node_modules inside this scoped package
                if !sub_junc {
                    let nested_nm = sub_path.join("node_modules");
                    if nested_nm.is_dir() {
                        let nested_rel = format!("{pkg_rel}/node_modules");
                        scan_nm_directory(project_dir, &nested_rel, discovered)?;
                    }
                }
            }
        } else {
            // Standard package
            let pkg_rel = format!("{nm_rel_posix}/{name_str}");
            discovered.push(pkg_rel.clone());

            // Check for nested node_modules inside this package
            if !is_junc {
                let nested_nm = entry_path.join("node_modules");
                if nested_nm.is_dir() {
                    let nested_rel = format!("{pkg_rel}/node_modules");
                    scan_nm_directory(project_dir, &nested_rel, discovered)?;
                }
            }
        }
    }

    Ok(())
}

/// Performs reachability analysis and filesystem scan, identifying extraneous packages for pruning.
pub fn discover_extraneous_packages(
    project_dir: &Path,
    options: &PruneOptions,
) -> Result<PruneAnalysis> {
    debug!("Discovering extraneous packages in {}", project_dir.display());
    let manifest_path = project_dir.join("package.json");
    if !manifest_path.is_file() {
        return Err(anyhow!(
            "Root package.json manifest not found at {}",
            manifest_path.display()
        ));
    }
    let manifest = Manifest::from_file(&manifest_path)
        .with_context(|| format!("Failed to read root manifest at {}", manifest_path.display()))?;

    // Attempt to load lockfile if present
    let lockfile = load_lockfile_if_exists(project_dir);

    // 1. Compute reachable set
    let reachable_packages = analyze_reachability(project_dir, &manifest, options, lockfile.as_ref())?;

    // 2. Scan node_modules on disk
    let discovered_packages = scan_node_modules(project_dir)?;
    debug!("Discovered {} packages on disk", discovered_packages.len());

    // 3. Find extraneous packages
    let mut extraneous_packages = Vec::new();
    for pkg_path in &discovered_packages {
        let normalized_path = to_posix_path(pkg_path);
        if !reachable_packages.contains(&normalized_path) {
            let full_path = project_dir.join(&normalized_path);
            let manifest_file = full_path.join("package.json");
            let (name, version) = if let Ok(m) = Manifest::from_file(&manifest_file) {
                let pkg_name = m.name.unwrap_or_else(|| extract_package_name_from_path(&normalized_path));
                (pkg_name, m.version)
            } else {
                let pkg_name = extract_package_name_from_path(&normalized_path);
                (pkg_name, None)
            };

            extraneous_packages.push(ExtraneousPackage {
                name,
                path: normalized_path,
                full_path,
                version,
            });
        }
    }

    // Sort extraneous packages descending by path depth/length so nested are listed before parents
        let depth = |p: &str| p.matches('/').count();
    extraneous_packages.sort_by(|a, b| {
        depth(&b.path)
            .cmp(&depth(&a.path))
            .then_with(|| b.path.len().cmp(&a.path.len()))
            .then_with(|| a.path.cmp(&b.path))
    });
    debug!("Found {} extraneous packages", extraneous_packages.len());

    Ok(PruneAnalysis {
        reachable_packages,
        discovered_packages,
        extraneous_packages,
    })
}

/// Helper to load package-lock.json if it exists at root or in node_modules/.package-lock.json.
pub fn load_lockfile_if_exists(project_dir: &Path) -> Option<LockfileV3> {
    let lockfile_path = project_dir.join("package-lock.json");
    if lockfile_path.is_file() {
        if let Ok(lock) = LockfileV3::load_from_file(&lockfile_path) {
            return Some(lock);
        }
    }
    LockfileV3::load_hidden(project_dir).ok()
}

/// Extracts the package name from a relative node_modules POSIX path.
pub fn extract_package_name_from_path(posix_path: &str) -> String {
    let clean = to_posix_path(posix_path);
    let parts: Vec<&str> = clean.split('/').collect();
    if parts.len() >= 2 && parts[parts.len() - 2].starts_with('@') {
        format!("{}/{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else if let Some(last) = parts.last() {
        last.to_string()
    } else {
        clean
    }
}

/// Executes pruning: removes all extraneous packages from disk, cleans shims from `.bin`,
/// cleans empty scope folders, and updates `package-lock.json` if present.
pub fn execute_prune(
    project_dir: &Path,
    extraneous: &[ExtraneousPackage],
) -> Result<PruneSummary> {
    let node_modules_dir = project_dir.join("node_modules");
    let bin_dir = node_modules_dir.join(".bin");
    let mut removed_packages = Vec::new();

    // Remove extraneous packages (already ordered deepest first)
    for pkg in extraneous {
        let is_junc = is_junction(&pkg.full_path).unwrap_or(false);
        if pkg.full_path.exists() || is_junc {
            info!("Pruning package {}", pkg.path);
            // Remove binary shims from enclosing .bin if package had bin entries
            let pkg_manifest = pkg.full_path.join("package.json");
            if let Ok(m) = Manifest::from_file(&pkg_manifest) {
                let enclosing_bin_dir = if let Some(parent) = pkg.full_path.parent() {
                    let maybe_scoped = parent.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with('@')).unwrap_or(false);
                    if maybe_scoped {
                        parent.parent().map(|p| p.join(".bin")).unwrap_or_else(|| bin_dir.clone())
                    } else {
                        parent.join(".bin")
                    }
                } else {
                    bin_dir.clone()
                };

                for (bin_name, _) in m.bin_entries() {
                    let shim_path = enclosing_bin_dir.join(&bin_name);
                    let _ = std::fs::remove_file(&shim_path);
                    #[cfg(windows)]
                    {
                        let _ = std::fs::remove_file(enclosing_bin_dir.join(format!("{bin_name}.cmd")));
                        let _ = std::fs::remove_file(enclosing_bin_dir.join(format!("{bin_name}.ps1")));
                    }
                }
            }

            // Remove junction or directory safely
            let removed = if is_junc {
                remove_junction(&pkg.full_path).is_ok()
            } else if pkg.full_path.is_dir() {
                remove_dir_all_safe(&pkg.full_path).is_ok()
            } else {
                std::fs::remove_file(&pkg.full_path).is_ok()
            };

            if removed || !pkg.full_path.exists() {
                removed_packages.push(pkg.path.clone());
            }

            // If parent is a scoped directory (e.g. @scope) and empty, remove it
            if let Some(parent) = pkg.full_path.parent() {
                if let Some(parent_name) = parent.file_name().and_then(|n| n.to_str()) {
                    if parent_name.starts_with('@') && parent.is_dir() {
                        if let Ok(mut entries) = std::fs::read_dir(parent) {
                            if entries.next().is_none() {
                                let _ = std::fs::remove_dir(parent);
                            }
                        }
                    }
                }
            }

            // Clean up empty enclosing nested node_modules if empty
            if let Some(parent) = pkg.full_path.parent() {
                let parent_dir = if parent.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with('@')).unwrap_or(false) {
                    parent.parent()
                } else {
                    Some(parent)
                };
                if let Some(nm_dir) = parent_dir {
                    if nm_dir != node_modules_dir && nm_dir.file_name().and_then(|n| n.to_str()) == Some("node_modules") && nm_dir.is_dir() {
                        if let Ok(mut entries) = std::fs::read_dir(nm_dir) {
                            if entries.next().is_none() {
                                let _ = std::fs::remove_dir(nm_dir);
                            }
                        }
                    }
                }
            }
        }
    }

    // Clean up .bin if empty
    if bin_dir.exists() {
        if let Ok(mut entries) = std::fs::read_dir(&bin_dir) {
            if entries.next().is_none() {
                let _ = std::fs::remove_dir(&bin_dir);
            }
        }
    }

    // Update package-lock.json if present
    let lockfile_path = project_dir.join("package-lock.json");
    let updated_lockfile_path = if lockfile_path.is_file() {
        if let Ok(mut lockfile) = LockfileV3::load_from_file(&lockfile_path) {
            let manifest_path = project_dir.join("package.json");
            if let Ok(manifest) = Manifest::from_file(&manifest_path) {
                crate::prune_lockfile(&mut lockfile, &manifest);
                let _ = lockfile.save_to_file(&lockfile_path);
                let _ = lockfile.save_hidden(project_dir);
                Some(lockfile_path)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    Ok(PruneSummary {
        removed_packages,
        lockfile_path: updated_lockfile_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_candidate_paths_root() {
        let candidates = get_candidate_paths("", "foo");
        assert_eq!(candidates, vec!["node_modules/foo"]);
    }

    #[test]
    fn test_candidate_paths_nested() {
        let candidates = get_candidate_paths("node_modules/a", "b");
        assert_eq!(
            candidates,
            vec!["node_modules/a/node_modules/b", "node_modules/b"]
        );
    }

    #[test]
    fn test_candidate_paths_deeply_nested() {
        let candidates = get_candidate_paths("node_modules/a/node_modules/b", "c");
        assert_eq!(
            candidates,
            vec![
                "node_modules/a/node_modules/b/node_modules/c",
                "node_modules/a/node_modules/c",
                "node_modules/c"
            ]
        );
    }

    #[test]
    fn test_candidate_paths_scoped() {
        let candidates = get_candidate_paths("node_modules/@scope1/a", "@scope2/b");
        assert_eq!(
            candidates,
            vec![
                "node_modules/@scope1/a/node_modules/@scope2/b",
                "node_modules/@scope2/b"
            ]
        );
    }

    #[test]
    fn test_extract_package_name() {
        assert_eq!(extract_package_name_from_path("node_modules/foo"), "foo");
        assert_eq!(
            extract_package_name_from_path("node_modules/@scope/foo"),
            "@scope/foo"
        );
        assert_eq!(
            extract_package_name_from_path("node_modules/parent/node_modules/child"),
            "child"
        );
        assert_eq!(
            extract_package_name_from_path("node_modules/parent/node_modules/@scope/child"),
            "@scope/child"
        );
    }

    #[test]
    fn test_prune_options_omit_flags() {
        let opts = PruneOptions::new("my-project")
            .with_omit_dev(true)
            .with_omit_optional(true)
            .with_omit_peer(true);
        assert!(opts.should_omit_dev());
        assert!(opts.should_omit_optional());
        assert!(opts.should_omit_peer());
    }

    #[test]
    fn test_reachability_and_extraneous_discovery() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        // 1. Root package.json
        let root_manifest_content = r#"{
            "name": "test-root",
            "version": "1.0.0",
            "dependencies": {
                "prod-a": "^1.0.0"
            },
            "devDependencies": {
                "dev-b": "^1.0.0"
            },
            "optionalDependencies": {
                "opt-c": "^1.0.0"
            }
        }"#;
        fs::write(root.join("package.json"), root_manifest_content).unwrap();

        // 2. node_modules layout
        let nm = root.join("node_modules");
        fs::create_dir_all(nm.join("prod-a")).unwrap();
        fs::create_dir_all(nm.join("dev-b")).unwrap();
        fs::create_dir_all(nm.join("opt-c")).unwrap();
        fs::create_dir_all(nm.join("trans-d")).unwrap();
        fs::create_dir_all(nm.join("extraneous-x")).unwrap();
        fs::create_dir_all(nm.join("@scope").join("extraneous-y")).unwrap();
        fs::create_dir_all(nm.join(".bin")).unwrap();

        // prod-a has transitive dependency on trans-d
        let prod_a_manifest = r#"{
            "name": "prod-a",
            "version": "1.0.0",
            "dependencies": {
                "trans-d": "^1.0.0"
            }
        }"#;
        fs::write(nm.join("prod-a/package.json"), prod_a_manifest).unwrap();
        fs::write(nm.join("dev-b/package.json"), r#"{"name": "dev-b", "version": "1.0.0"}"#).unwrap();
        fs::write(nm.join("opt-c/package.json"), r#"{"name": "opt-c", "version": "1.0.0"}"#).unwrap();
        fs::write(nm.join("trans-d/package.json"), r#"{"name": "trans-d", "version": "1.0.0"}"#).unwrap();
        fs::write(nm.join("extraneous-x/package.json"), r#"{"name": "extraneous-x", "version": "0.1.0"}"#).unwrap();
        fs::write(nm.join("@scope/extraneous-y/package.json"), r#"{"name": "@scope/extraneous-y", "version": "0.2.0"}"#).unwrap();

        // Standard analysis (keep dev, optional, peer)
        let opts = PruneOptions::default();
        let analysis = discover_extraneous_packages(root, &opts).unwrap();

        assert!(analysis.reachable_packages.contains("node_modules/prod-a"));
        assert!(analysis.reachable_packages.contains("node_modules/dev-b"));
        assert!(analysis.reachable_packages.contains("node_modules/opt-c"));
        assert!(analysis.reachable_packages.contains("node_modules/trans-d"));

        let ext_paths = analysis.extraneous_paths();
        assert!(ext_paths.contains(&"node_modules/extraneous-x".to_string()));
        assert!(ext_paths.contains(&"node_modules/@scope/extraneous-y".to_string()));
        assert!(!ext_paths.contains(&"node_modules/prod-a".to_string()));
        assert!(!ext_paths.contains(&"node_modules/dev-b".to_string()));
        assert!(!ext_paths.contains(&"node_modules/opt-c".to_string()));
        assert!(!ext_paths.contains(&"node_modules/trans-d".to_string()));

        // Analysis with omit_dev: true
        let prod_opts = PruneOptions::default().with_omit_dev(true);
        let prod_analysis = discover_extraneous_packages(root, &prod_opts).unwrap();
        let prod_ext = prod_analysis.extraneous_paths();
        assert!(prod_ext.contains(&"node_modules/dev-b".to_string()));
        assert!(prod_ext.contains(&"node_modules/extraneous-x".to_string()));
        assert!(prod_ext.contains(&"node_modules/@scope/extraneous-y".to_string()));
        assert!(!prod_ext.contains(&"node_modules/prod-a".to_string()));

        // Analysis with omit_optional: true
        let opt_opts = PruneOptions::default().with_omit_optional(true);
        let opt_analysis = discover_extraneous_packages(root, &opt_opts).unwrap();
        let opt_ext = opt_analysis.extraneous_paths();
        assert!(opt_ext.contains(&"node_modules/opt-c".to_string()));

        // Test execution: pruning extraneous packages
        let summary = execute_prune(root, &analysis.extraneous_packages).unwrap();
        assert!(summary.removed_packages.contains(&"node_modules/extraneous-x".to_string()));
        assert!(summary.removed_packages.contains(&"node_modules/@scope/extraneous-y".to_string()));
        assert!(!nm.join("extraneous-x").exists());
        assert!(!nm.join("@scope").exists()); // Empty scope cleaned up
        assert!(nm.join("prod-a").exists());
        assert!(nm.join("dev-b").exists());
    }

    #[test]
    fn test_nested_node_modules_extraneous() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        let root_manifest_content = r#"{
            "name": "test-nested",
            "version": "1.0.0",
            "dependencies": {
                "parent-pkg": "1.0.0"
            }
        }"#;
        fs::write(root.join("package.json"), root_manifest_content).unwrap();

        let parent_nm = root.join("node_modules/parent-pkg/node_modules");
        fs::create_dir_all(parent_nm.join("nested-unused")).unwrap();
        fs::write(
            root.join("node_modules/parent-pkg/package.json"),
            r#"{"name": "parent-pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            parent_nm.join("nested-unused/package.json"),
            r#"{"name": "nested-unused", "version": "0.1.0"}"#,
        )
        .unwrap();

        let analysis = discover_extraneous_packages(root, &PruneOptions::default()).unwrap();
        assert!(analysis.reachable_packages.contains("node_modules/parent-pkg"));
        assert!(analysis
            .extraneous_paths()
            .contains(&"node_modules/parent-pkg/node_modules/nested-unused".to_string()));
    }
}
