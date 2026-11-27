use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::prune::{extract_package_name_from_path, scan_node_modules};
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_fs::junction::{is_junction, remove_dir_all_safe};
use rnpm_lockfile::LockfileV3;

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

    // 1. Load root manifest (read-only mode)
    let root_manifest_path = project_dir.join("package.json");
    let root_manifest = Manifest::from_file_readonly(&root_manifest_path).ok();

    // 2. Load lockfile if present
    let (lockfile_path, _) = crate::resolve_lockfile_path(project_dir);
    let mut lockfile = if lockfile_path.is_file() {
        LockfileV3::load_from_file(&lockfile_path).ok()
    } else {
        None
    };

    // 3. Scan all installed packages on disk
    let discovered = scan_node_modules(project_dir)
        .with_context(|| format!("Failed to scan node_modules in {}", project_dir.display()))?;

    let mut installed_map: HashMap<String, InstalledPackage> = HashMap::new();

    // Map of parent_path -> (dep_name -> requested range)
    let mut requirements_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    // Collect requirements from root manifest
    if let Some(ref m) = root_manifest {
        let root_entry = requirements_map.entry("".to_string()).or_default();
        for (dep, range) in &m.dependencies {
            root_entry.insert(dep.clone(), range.clone());
        }
        for (dep, range) in &m.dev_dependencies {
            root_entry.insert(dep.clone(), range.clone());
        }
        for (dep, range) in &m.optional_dependencies {
            root_entry.insert(dep.clone(), range.clone());
        }
    }

    // Inspect each installed package
    for pkg_rel_path in &discovered {
        let full_path = project_dir.join(pkg_rel_path);
        let is_link = is_junction(&full_path).unwrap_or(false);

        let manifest_path = full_path.join("package.json");
        let manifest = Manifest::from_file_readonly(&manifest_path).ok();

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
            let req_entry = requirements_map.entry(pkg_rel_path.clone()).or_default();
            for (d, r) in &m.dependencies {
                deps.insert(d.clone(), r.clone());
                req_entry.insert(d.clone(), r.clone());
            }
            for (d, r) in &m.optional_dependencies {
                deps.insert(d.clone(), r.clone());
                req_entry.insert(d.clone(), r.clone());
            }
        } else if let Some(ref l) = lockfile {
            if let Some(lp) = l.get_package(pkg_rel_path) {
                if let Some(ref d_map) = lp.dependencies {
                    let req_entry = requirements_map.entry(pkg_rel_path.clone()).or_default();
                    for (d, r) in d_map {
                        deps.insert(d.clone(), r.clone());
                        req_entry.insert(d.clone(), r.clone());
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

    // 4. Group packages by package_name to find duplicates across nesting levels (deterministic order)
    let mut by_name: BTreeMap<String, Vec<InstalledPackage>> = BTreeMap::new();
    for pkg in installed_map.values() {
        // Skip symlinks / workspace junctions AND aliased installs (folder name != package name)
        if pkg.is_link || extract_package_name_from_path(&pkg.path) != pkg.name {
            continue;
        }

        // Apply package filter if specified
        if !options.packages.is_empty() {
            let filter_matches = options.packages.iter().any(|f| {
                f == &pkg.name
                    || f == pkg.name.strip_prefix('@').unwrap_or(&pkg.name)
                    || (pkg.name.contains('/')
                        && f == pkg.name.rsplit('/').next().unwrap_or(&pkg.name))
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

    // Check whether an intermediate ancestor package between `parent_path` and root `""`
    // holds a different, unremoved copy of `pkg_name` that would shadow root `node_modules/<pkg>`.
    let is_shadowed_by_ancestor =
        |parent_path: &str,
         pkg_name: &str,
         installed: &HashMap<String, InstalledPackage>,
         removed: &HashSet<String>| {
            let mut cur = get_parent_location(parent_path);
            while !cur.is_empty() {
                let candidate = format!("{cur}/node_modules/{pkg_name}");
                if installed.contains_key(&candidate) && !removed.contains(&candidate) {
                    return true;
                }
                cur = get_parent_location(&cur);
            }
            false
        };

    let dep_graph = lockfile
        .as_ref()
        .map(rnpm_solver::graph::DependencyGraph::from_lockfile_v3);

    // Pre-index incoming dependency edges by target location for O(1) lookups
    let incoming_edges_by_target: Option<HashMap<&str, Vec<&rnpm_solver::graph::DependencyEdge>>> =
        dep_graph.as_ref().map(|graph| {
            let mut map: HashMap<&str, Vec<&rnpm_solver::graph::DependencyEdge>> =
                HashMap::with_capacity(graph.edges.len());
            for edge in &graph.edges {
                map.entry(edge.to_location.as_str()).or_default().push(edge);
            }
            map
        });

    let get_req_range = |parent: &str, dep: &str| -> Option<&str> {
        requirements_map
            .get(parent)
            .and_then(|m| m.get(dep))
            .map(|s| s.as_str())
    };

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
            if root_ver.is_empty() {
                continue;
            }

            // Scenario 1: Root node_modules/<pkg> is occupied.
            // Check each nested duplicate. If root version satisfies all consumers' declared ranges,
            // the nested copy is redundant and can be deleted!
            for nested in &instances {
                if nested.path == root_install_path {
                    continue;
                }
                if already_removed.contains(&nested.path) {
                    continue;
                }

                let satisfies = if let Some(ref incoming_map) = incoming_edges_by_target {
                    let incoming = incoming_map
                        .get(nested.path.as_str())
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]);

                    if incoming.is_empty() {
                        // If there are no incoming edges in the lockfile graph, verify with requirements_map
                        if let Some(req_range) = get_req_range(&nested.parent_path, &pkg_name) {
                            version_matches_range(&root_ver, req_range)
                        } else {
                            false
                        }
                    } else {
                        incoming
                            .iter()
                            .all(|e| version_matches_range(&root_ver, &e.spec))
                    }
                } else if let Some(req_range) = get_req_range(&nested.parent_path, &pkg_name) {
                    version_matches_range(&root_ver, req_range)
                } else {
                    false
                };

                if satisfies
                    && !is_shadowed_by_ancestor(
                        &nested.parent_path,
                        &pkg_name,
                        &installed_map,
                        &already_removed,
                    )
                {
                    actions.push(DedupeAction {
                        package_name: pkg_name.clone(),
                        original_path: nested.path.clone(),
                        target_path: root_install_path.clone(),
                        version: root_ver.clone(),
                        action_type: DedupeActionType::DeleteDuplicate,
                        reason: format!(
                            "Existing {}@{} at {} satisfies consumers of {}",
                            pkg_name, root_ver, root_install_path, nested.path
                        ),
                    });
                    already_removed.insert(nested.path.clone());
                }
            }
        } else {
            // Scenario 2: Root node_modules/<pkg> is VACANT.
            // Skip hoisting if something else (e.g. a symlink/junction or alias) already occupies `root_install_path`.
            let root_target_disk = project_dir.join(&root_install_path);
            if installed_map.contains_key(&root_install_path)
                || root_target_disk.exists()
                || is_junction(&root_target_disk).unwrap_or(false)
            {
                continue;
            }
            // Multiple nested copies exist. Find if a satisfying version can be hoisted
            // to the shallowest level (root node_modules/<pkg>).
            // First collect all requirements that would look up root_install_path:
            let root_range_opt = get_req_range("", &pkg_name);

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

            // Verify every outgoing dependency of a hoist candidate will still resolve to a
            // compatible version once the candidate moves from its nested parent to root.
            let outgoing_deps_safe_at_root = |cand: &InstalledPackage| -> bool {
                for (dep_name, dep_range) in &cand.dependencies {
                    // Own nested dependency moves along with `cand` when hoisted.
                    let own_nested = format!("{}/node_modules/{dep_name}", cand.path);
                    if installed_map.contains_key(&own_nested)
                        && !already_removed.contains(&own_nested)
                    {
                        continue;
                    }

                    // Check whether `dep_name` was resolvable in `cand`'s original ancestor chain.
                    let mut resolved_originally = false;
                    let mut scope = cand.parent_path.clone();
                    loop {
                        let probe = if scope.is_empty() {
                            format!("node_modules/{dep_name}")
                        } else {
                            format!("{scope}/node_modules/{dep_name}")
                        };
                        if installed_map.contains_key(&probe) {
                            resolved_originally = true;
                            break;
                        }
                        if scope.is_empty() {
                            break;
                        }
                        scope = get_parent_location(&scope);
                    }
                    if !resolved_originally {
                        // Uninstalled optional dependency; hoisting cannot regress it.
                        continue;
                    }

                    // At root `node_modules/<pkg>`, Node only resolves from root `node_modules/<dep>`.
                    let root_dep_key = format!("node_modules/{dep_name}");
                    let root_dep_ver = installed_map
                        .get(&root_dep_key)
                        .filter(|_| !already_removed.contains(&root_dep_key))
                        .and_then(|p| p.version.as_deref())
                        .or_else(|| {
                            actions.iter().find_map(|a| {
                                (a.action_type == DedupeActionType::HoistAndDedupe
                                    && a.target_path == root_dep_key)
                                    .then_some(a.version.as_str())
                            })
                        });
                    let Some(ver) = root_dep_ver else {
                        return false;
                    };
                    if !version_matches_range(ver, dep_range) {
                        return false;
                    }
                }
                true
            };

            let chosen = candidates.into_iter().find(|cand| {
                let Some(ref cand_ver) = cand.version else {
                    return false;
                };
                if cand_ver.is_empty() {
                    return false;
                }
                if is_shadowed_by_ancestor(
                    &cand.parent_path,
                    &pkg_name,
                    &installed_map,
                    &already_removed,
                ) {
                    return false;
                }
                if !outgoing_deps_safe_at_root(cand) {
                    return false;
                }
                if let Some(ref incoming_map) = incoming_edges_by_target {
                    instances.iter().all(|nested| {
                        let incoming = incoming_map
                            .get(nested.path.as_str())
                            .map(|v| v.as_slice())
                            .unwrap_or(&[]);
                        if incoming.is_empty() {
                            if let Some(req_range) = get_req_range(&nested.parent_path, &pkg_name) {
                                version_matches_range(cand_ver, req_range)
                            } else {
                                false
                            }
                        } else {
                            incoming
                                .iter()
                                .all(|e| version_matches_range(cand_ver, &e.spec))
                        }
                    })
                } else {
                    instances.iter().all(|nested| {
                        if let Some(req_range) = get_req_range(&nested.parent_path, &pkg_name) {
                            version_matches_range(cand_ver, req_range)
                        } else {
                            false
                        }
                    })
                }
            });

            if let Some(best_candidate) = chosen {
                let best_ver = best_candidate.version.clone().unwrap_or_default();
                {
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

                    // Delete other redundant nested copies (unless shadowed by an intermediate copy)
                    for other in &instances {
                        if other.path == best_candidate.path {
                            continue;
                        }
                        if already_removed.contains(&other.path) {
                            continue;
                        }
                        if is_shadowed_by_ancestor(
                            &other.parent_path,
                            &pkg_name,
                            &installed_map,
                            &already_removed,
                        ) {
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

    // Never delete a nested package in `DeleteDuplicate` if it still hosts surviving
    // nested `node_modules` children that were not themselves deleted or hoisted away,
    // and drop any deeper `DeleteDuplicate` that becomes shadowed by a retained parent.
    loop {
        let mut to_drop: HashSet<String> = HashSet::new();
        for a in actions
            .iter()
            .filter(|a| a.action_type == DedupeActionType::DeleteDuplicate)
        {
            let child_prefix = format!("{}/node_modules/", a.original_path);
            let has_surviving_child = installed_map.keys().any(|k| {
                k.starts_with(&child_prefix)
                    && !already_removed.contains(k)
                    && !actions.iter().any(|h| {
                        h.action_type == DedupeActionType::HoistAndDedupe
                            && (k == &h.original_path
                                || k.starts_with(&format!("{}/", h.original_path)))
                    })
            });
            let parent_path = get_parent_location(&a.original_path);
            let shadowed_after_drop = is_shadowed_by_ancestor(
                &parent_path,
                &a.package_name,
                &installed_map,
                &already_removed,
            );
            if has_surviving_child || shadowed_after_drop {
                to_drop.insert(a.original_path.clone());
            }
        }
        if to_drop.is_empty() {
            break;
        }
        for dropped in &to_drop {
            already_removed.remove(dropped);
        }
        actions.retain(|a| {
            !(a.action_type == DedupeActionType::DeleteDuplicate
                && to_drop.contains(&a.original_path))
        });
    }

    // 6. Apply actions to filesystem and lockfile (unless dry-run)
    let mut summary = DedupeSummary {
        removed_packages: Vec::new(),
        hoisted_packages: Vec::new(),
        actions: actions.clone(),
    };

    if !options.dry_run {
        // Apply HoistAndDedupe deepest-first so nested children are re-homed before
        // outer ancestor directories move, and record path remaps for subsequent moves/deletes.
        let mut hoist_actions: Vec<&DedupeAction> = actions
            .iter()
            .filter(|a| a.action_type == DedupeActionType::HoistAndDedupe)
            .collect();
        hoist_actions.sort_by(|a, b| {
            b.original_path
                .len()
                .cmp(&a.original_path.len())
                .then_with(|| a.original_path.cmp(&b.original_path))
        });

        let remap_path = |orig: &str, remaps: &[(String, String)]| -> String {
            let mut cur = orig.to_string();
            for (old_p, new_p) in remaps {
                if cur == *old_p {
                    cur = new_p.clone();
                } else if let Some(suffix) = cur.strip_prefix(&format!("{old_p}/")) {
                    cur = format!("{new_p}/{suffix}");
                }
            }
            cur
        };

        let mut hoist_remaps: Vec<(String, String)> = Vec::new();
        for action in hoist_actions {
            let effective_src = remap_path(&action.original_path, &hoist_remaps);
            let src_full = project_dir.join(&effective_src);
            let dst_full = project_dir.join(&action.target_path);

            if dst_full.exists() || is_junction(&dst_full).unwrap_or(false) {
                continue;
            }

            if src_full.exists() {
                move_or_copy_directory(&src_full, &dst_full)?;
                clean_empty_ancestor_dirs(
                    src_full.parent().unwrap_or(&src_full).to_path_buf(),
                    &node_modules_dir,
                );
            }

            // Update lockfile: move the hoisted entry AND all nested sub-entries under its prefix
            if let Some(ref mut l) = lockfile {
                let prefix = format!("{effective_src}/");
                let keys_to_move: Vec<String> = l
                    .packages
                    .keys()
                    .filter(|k| *k == &effective_src || k.starts_with(&prefix))
                    .cloned()
                    .collect();
                for old_key in keys_to_move {
                    if let Some(pkg_meta) = l.remove_package(&old_key) {
                        let new_key = if old_key == effective_src {
                            action.target_path.clone()
                        } else {
                            let suffix = &old_key[effective_src.len()..];
                            format!("{}{}", action.target_path, suffix)
                        };
                        l.insert_package(&new_key, pkg_meta);
                    }
                }
            }

            hoist_remaps.push((effective_src, action.target_path.clone()));
            summary
                .hoisted_packages
                .push((action.original_path.clone(), action.target_path.clone()));
        }

        let mut delete_actions: Vec<&DedupeAction> = actions
            .iter()
            .filter(|a| a.action_type == DedupeActionType::DeleteDuplicate)
            .collect();
        delete_actions.sort_by(|a, b| {
            b.original_path
                .len()
                .cmp(&a.original_path.len())
                .then_with(|| a.original_path.cmp(&b.original_path))
        });

        for action in delete_actions {
            let effective_src = remap_path(&action.original_path, &hoist_remaps);
            let src_full = project_dir.join(&effective_src);
            // Defense-in-depth: skip deletion if any surviving child directory remains inside `node_modules`
            let nested_nm = src_full.join("node_modules");
            let has_live_disk_child = nested_nm.is_dir()
                && std::fs::read_dir(&nested_nm)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .any(|e| {
                        let name = e.file_name();
                        let name_str = name.to_string_lossy();
                        name_str != ".bin" && (e.path().is_dir() || is_junction(&e.path()).unwrap_or(false))
                    });
            if has_live_disk_child {
                continue;
            }
            if src_full.exists() || is_junction(&src_full).unwrap_or(false) {
                remove_dir_all_safe(&src_full)?;
                clean_empty_ancestor_dirs(
                    src_full.parent().unwrap_or(&src_full).to_path_buf(),
                    &node_modules_dir,
                );
            }

            // Update lockfile: remove nested entry
            if let Some(ref mut l) = lockfile {
                l.remove_package(&effective_src);
            }

            summary.removed_packages.push(action.original_path.clone());
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
