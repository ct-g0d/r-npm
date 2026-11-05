use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_fs::junction::{is_junction, remove_dir_all_safe};
use rnpm_lockfile::LockfileV3;
use crate::prune::{extract_package_name_from_path, scan_node_modules};

/// Options controlling `npm dedupe` and `npm find-dupes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupeOptions {
    /// Project root directory. Defaults to ".".
    pub project_dir: PathBuf,
    /// Report deduplication actions without modifying files or lockfile.
    pub dry_run: bool,
    /// Specific package names to deduplicate. If empty, dedupes all packages.
    pub packages: Vec<String>,
}

impl Default for DedupeOptions {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::from("."),
            dry_run: false,
            packages: Vec::new(),
        }
    }
}

impl DedupeOptions {
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            ..Default::default()
        }
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn with_packages(mut self, packages: Vec<String>) -> Self {
        self.packages = packages;
        self
    }
}

/// Type of deduplication action taken for a package.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DedupeActionType {
    /// Redundant duplicate deleted because an existing shallowest ancestor satisfies the semver requirement.
    DeleteDuplicate,
    /// Duplicate hoisted to shallowest ancestor level and redundant copies deleted.
    HoistAndDedupe,
}

/// A specific deduplication action performed or simulated.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DedupeAction {
    pub package_name: String,
    pub original_path: String,
    pub target_path: String,
    pub version: String,
    pub action_type: DedupeActionType,
    pub reason: String,
}

/// Structured summary of deduplication execution.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DedupeSummary {
    /// List of relative POSIX paths of redundant packages removed.
    pub removed_packages: Vec<String>,
    /// List of packages hoisted: (from_path, to_path).
    pub hoisted_packages: Vec<(String, String)>,
    /// List of all deduplication actions.
    pub actions: Vec<DedupeAction>,
}

#[derive(Debug, Clone)]
struct InstalledPackage {
    path: String,
    name: String,
    version: Option<String>,
    parent_path: String,
    #[allow(dead_code)]
    dependencies: HashMap<String, String>,
    depth: usize,
    is_link: bool,
}

/// Helper to check if a version string satisfies a declared semver range string.
pub fn version_matches_range(ver_str: &str, range_str: &str) -> bool {
    let clean_range = range_str.trim();
    if clean_range == "*" || clean_range.is_empty() || clean_range == "latest" {
        return true;
    }

    let Ok(v) = Version::parse(ver_str) else {
        return false;
    };

    if let Ok(r) = Range::parse(clean_range) {
        r.satisfies(&v)
    } else if let Ok(expected) = Version::parse(clean_range) {
        v == expected
    } else {
        // Fallback exact match or loose acceptance
        clean_range == ver_str
    }
}

/// Cleans up empty parent directories up to `stop_dir`.
fn clean_empty_ancestor_dirs(mut dir: PathBuf, stop_dir: &Path) {
    while dir != stop_dir && dir.starts_with(stop_dir) {
        if let Ok(mut entries) = std::fs::read_dir(&dir) {
            if entries.next().is_none() {
                let _ = std::fs::remove_dir(&dir);
            } else {
                break;
            }
        } else {
            break;
        }
        if let Some(parent) = dir.parent() {
            dir = parent.to_path_buf();
        } else {
            break;
        }
    }
}

/// Recursively moves or copies a directory from `src` to `dst`.
fn move_or_copy_directory(src: &Path, dst: &Path) -> Result<()> {
    if src == dst {
        return Ok(());
    }

    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Attempt fast atomic rename first
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }

    // Fallback: recursive copy and delete
    copy_dir_recursive(src, dst)?;
    remove_dir_all_safe(src)?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_name = entry.file_name();
        let target_path = dst.join(file_name);

        if entry_path.is_dir() {
            copy_dir_recursive(&entry_path, &target_path)?;
        } else {
            std::fs::copy(&entry_path, &target_path)?;
        }
    }
    Ok(())
}

/// Extracts parent location from a `node_modules` path:
/// e.g. "node_modules/foo" -> ""
/// e.g. "node_modules/bar/node_modules/foo" -> "node_modules/bar"
fn get_parent_location(path: &str) -> String {
    if let Some(idx) = path.rfind("/node_modules/") {
        path[..idx].to_string()
    } else {
        "".to_string()
    }
}

/// Traverses installed packages and package-lock.json to find and apply deduplication.
pub fn execute_dedupe(options: &DedupeOptions) -> Result<DedupeSummary> {
    let project_dir = &options.project_dir;
    let node_modules_dir = project_dir.join("node_modules");

    if !node_modules_dir.is_dir() {
        return Ok(DedupeSummary::default());
    }

    // 1. Load root manifest
    let root_manifest_path = project_dir.join("package.json");
    let root_manifest = if root_manifest_path.is_file() {
        Manifest::from_file(&root_manifest_path).ok()
    } else {
        None
    };

    // 2. Load lockfile if present
    let lockfile_path = project_dir.join("package-lock.json");
    let mut lockfile = if lockfile_path.is_file() {
        LockfileV3::load_from_file(&lockfile_path).ok()
    } else {
        None
    };

    // 3. Scan all installed packages on disk
    let discovered = scan_node_modules(project_dir)
        .with_context(|| format!("Failed to scan node_modules in {}", project_dir.display()))?;

    let mut installed_map: HashMap<String, InstalledPackage> = HashMap::new();

    // Map of (parent_path, dep_name) -> requested range
    let mut requirements_map: HashMap<(String, String), String> = HashMap::new();

    // Collect requirements from root manifest
    if let Some(ref m) = root_manifest {
        for (dep, range) in &m.dependencies {
            requirements_map.insert(("".to_string(), dep.clone()), range.clone());
        }
        for (dep, range) in &m.dev_dependencies {
            requirements_map.insert(("".to_string(), dep.clone()), range.clone());
        }
        for (dep, range) in &m.optional_dependencies {
            requirements_map.insert(("".to_string(), dep.clone()), range.clone());
        }
    }

    // Inspect each installed package
    for pkg_rel_path in &discovered {
        let full_path = project_dir.join(pkg_rel_path);
        let is_link = is_junction(&full_path).unwrap_or(false);

        let manifest_path = full_path.join("package.json");
        let manifest = if manifest_path.is_file() {
            Manifest::from_file(&manifest_path).ok()
        } else {
            None
        };

        let name = manifest
            .as_ref()
            .and_then(|m| m.name.clone())
            .or_else(|| {
                lockfile
                    .as_ref()
                    .and_then(|l| l.get_package(pkg_rel_path))
                    .and_then(|p| p.name.clone())
            })
            .unwrap_or_else(|| extract_package_name_from_path(pkg_rel_path));

        let version = manifest
            .as_ref()
            .and_then(|m| m.version.clone())
            .or_else(|| {
                lockfile
                    .as_ref()
                    .and_then(|l| l.get_package(pkg_rel_path))
                    .and_then(|p| p.version.clone())
            });

        let mut deps = HashMap::new();
        if let Some(ref m) = manifest {
            for (d, r) in &m.dependencies {
                deps.insert(d.clone(), r.clone());
                requirements_map.insert((pkg_rel_path.clone(), d.clone()), r.clone());
            }
            for (d, r) in &m.optional_dependencies {
                deps.insert(d.clone(), r.clone());
                requirements_map.insert((pkg_rel_path.clone(), d.clone()), r.clone());
            }
        } else if let Some(ref l) = lockfile {
            if let Some(lp) = l.get_package(pkg_rel_path) {
                if let Some(ref d_map) = lp.dependencies {
                    for (d, r) in d_map {
                        deps.insert(d.clone(), r.clone());
                        requirements_map.insert((pkg_rel_path.clone(), d.clone()), r.clone());
                    }
                }
            }
        }

        let parent_path = get_parent_location(pkg_rel_path);
        let depth = pkg_rel_path.matches("/node_modules/").count();

        installed_map.insert(
            pkg_rel_path.clone(),
            InstalledPackage {
                path: pkg_rel_path.clone(),
                name,
                version,
                parent_path,
                dependencies: deps,
                depth,
                is_link,
            },
        );
    }

    // 4. Group packages by package_name to find duplicates across nesting levels
    let mut by_name: HashMap<String, Vec<InstalledPackage>> = HashMap::new();
    for pkg in installed_map.values() {
        // Skip symlinks / workspace junctions from deduplication
        if pkg.is_link {
            continue;
        }

        // Apply package filter if specified
        if !options.packages.is_empty() {
            let filter_matches = options.packages.iter().any(|f| {
                f == &pkg.name
                    || f == pkg.name.strip_prefix('@').unwrap_or(&pkg.name)
                    || (pkg.name.contains('/') && f == pkg.name.rsplit('/').next().unwrap_or(&pkg.name))
            });
            if !filter_matches {
                continue;
            }
        }

        by_name
            .entry(pkg.name.clone())
            .or_default()
            .push(pkg.clone());
    }

    let mut actions = Vec::new();
    let mut already_removed: HashSet<String> = HashSet::new();

    // 5. Evaluate deduplication opportunities for duplicated packages
    for (pkg_name, mut instances) in by_name {
        if instances.len() <= 1 {
            continue; // No duplicate across nesting levels
        }

        // Sort by nesting depth ascending: shallowest ancestor level first
        instances.sort_by_key(|p| p.depth);

        let root_install_path = format!("node_modules/{pkg_name}");
        let root_instance_opt = instances.iter().find(|p| p.path == root_install_path);

        if let Some(root_pkg) = root_instance_opt {
            let root_ver = root_pkg.version.clone().unwrap_or_default();

            // Scenario 1: Root node_modules/<pkg> is occupied.
            // Check each nested duplicate. If root version satisfies the parent's declared range,
            // the nested copy is redundant and can be deleted!
            for nested in &instances {
                if nested.path == root_install_path {
                    continue;
                }
                if already_removed.contains(&nested.path) {
                    continue;
                }

                // Look up range required by nested.parent_path
                let req_range = requirements_map
                    .get(&(nested.parent_path.clone(), pkg_name.clone()))
                    .cloned()
                    .unwrap_or_else(|| "*".to_string());

                let satisfies = if !root_ver.is_empty() {
                    version_matches_range(&root_ver, &req_range)
                } else {
                    nested.version.as_deref() == Some(&root_ver)
                };

                if satisfies {
                    actions.push(DedupeAction {
                        package_name: pkg_name.clone(),
                        original_path: nested.path.clone(),
                        target_path: root_install_path.clone(),
                        version: root_ver.clone(),
                        action_type: DedupeActionType::DeleteDuplicate,
                        reason: format!(
                            "Existing {}@{} at {} satisfies parent requirement '{}'",
                            pkg_name, root_ver, root_install_path, req_range
                        ),
                    });
                    already_removed.insert(nested.path.clone());
                }
            }
        } else {
            // Scenario 2: Root node_modules/<pkg> is VACANT.
            // Multiple nested copies exist. Find if a satisfying version can be hoisted
            // to the shallowest level (root node_modules/<pkg>).
            // First collect all requirements that would look up root_install_path:
            let root_range_opt = requirements_map.get(&("".to_string(), pkg_name.clone()));

            // Find candidate version among nested instances that satisfies root requirement (if any)
            // and as many nested parents as possible.
            let mut candidates: Vec<&InstalledPackage> = instances
                .iter()
                .filter(|p| {
                    if let Some(r) = root_range_opt {
                        if let Some(ref v) = p.version {
                            version_matches_range(v, r)
                        } else {
                            false
                        }
                    } else {
                        true
                    }
                })
                .collect();

            // Pick candidate with highest semver version
            candidates.sort_by(|a, b| {
                let v_a = a.version.as_deref().and_then(|v| Version::parse(v).ok());
                let v_b = b.version.as_deref().and_then(|v| Version::parse(v).ok());
                v_b.cmp(&v_a)
            });

            if let Some(best_candidate) = candidates.first() {
                let best_ver = best_candidate.version.clone().unwrap_or_default();

                // Check if best_ver satisfies all other nested instances' parent requirements
                let all_satisfied = instances.iter().all(|nested| {
                    let req_range = requirements_map
                        .get(&(nested.parent_path.clone(), pkg_name.clone()))
                        .cloned()
                        .unwrap_or_else(|| "*".to_string());
                    version_matches_range(&best_ver, &req_range)
                });

                if all_satisfied {
                    // Hoist best_candidate to root
                    actions.push(DedupeAction {
                        package_name: pkg_name.clone(),
                        original_path: best_candidate.path.clone(),
                        target_path: root_install_path.clone(),
                        version: best_ver.clone(),
                        action_type: DedupeActionType::HoistAndDedupe,
                        reason: format!(
                            "Hoisting {}@{} from {} to {} to satisfy common ranges",
                            pkg_name, best_ver, best_candidate.path, root_install_path
                        ),
                    });
                    already_removed.insert(best_candidate.path.clone());

                    // Delete other redundant nested copies
                    for other in &instances {
                        if other.path == best_candidate.path {
                            continue;
                        }
                        if already_removed.contains(&other.path) {
                            continue;
                        }

                        actions.push(DedupeAction {
                            package_name: pkg_name.clone(),
                            original_path: other.path.clone(),
                            target_path: root_install_path.clone(),
                            version: best_ver.clone(),
                            action_type: DedupeActionType::DeleteDuplicate,
                            reason: format!(
                                "Redundant nested copy replaced by hoisted {}@{}",
                                pkg_name, best_ver
                            ),
                        });
                        already_removed.insert(other.path.clone());
                    }
                }
            }
        }
    }

    // 6. Apply actions to filesystem and lockfile (unless dry-run)
    let mut summary = DedupeSummary {
        removed_packages: Vec::new(),
        hoisted_packages: Vec::new(),
        actions: actions.clone(),
    };

    if !options.dry_run {
        for action in &actions {
            match action.action_type {
                DedupeActionType::HoistAndDedupe => {
                    let src_full = project_dir.join(&action.original_path);
                    let dst_full = project_dir.join(&action.target_path);

                    if src_full.exists() {
                        move_or_copy_directory(&src_full, &dst_full)?;
                        clean_empty_ancestor_dirs(
                            src_full.parent().unwrap_or(&src_full).to_path_buf(),
                            &node_modules_dir,
                        );
                    }

                    // Update lockfile: move entry to hoisted location
                    if let Some(ref mut l) = lockfile {
                        if let Some(pkg_meta) = l.remove_package(&action.original_path) {
                            l.insert_package(&action.target_path, pkg_meta);
                        }
                    }

                    summary
                        .hoisted_packages
                        .push((action.original_path.clone(), action.target_path.clone()));
                }
                DedupeActionType::DeleteDuplicate => {
                    let src_full = project_dir.join(&action.original_path);
                    if src_full.exists() || is_junction(&src_full).unwrap_or(false) {
                        remove_dir_all_safe(&src_full)?;
                        clean_empty_ancestor_dirs(
                            src_full.parent().unwrap_or(&src_full).to_path_buf(),
                            &node_modules_dir,
                        );
                    }

                    // Update lockfile: remove nested entry
                    if let Some(ref mut l) = lockfile {
                        l.remove_package(&action.original_path);
                    }

                    summary.removed_packages.push(action.original_path.clone());
                }
            }
        }

        // Persist updated lockfiles
        if let Some(ref l) = lockfile {
            l.save_to_file(&lockfile_path)?;
            l.save_hidden(project_dir)?;
        }
    } else {
        // In dry-run mode, populate summary lists as preview
        for action in &actions {
            match action.action_type {
                DedupeActionType::HoistAndDedupe => {
                    summary
                        .hoisted_packages
                        .push((action.original_path.clone(), action.target_path.clone()));
                }
                DedupeActionType::DeleteDuplicate => {
                    summary.removed_packages.push(action.original_path.clone());
                }
            }
        }
    }

    Ok(summary)
}
