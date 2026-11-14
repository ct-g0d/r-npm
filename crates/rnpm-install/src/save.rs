use anyhow::{Context, Result};
use rnpm_core::manifest::Manifest;
use rnpm_core::spec::PackageTarget;
use rnpm_core::workspace::WorkspaceMember;
use rnpm_lockfile::LockfilePackage;
use std::path::Path;

/// Resolves targeted workspace indices and whether the workspace root is targeted.
pub fn resolve_targeted_workspaces(
    workspace_members: &[WorkspaceMember],
    workspace_filter: &[String],
    workspaces_flag: bool,
    workspace_root_flag: bool,
) -> (Vec<usize>, bool) {
    let has_workspace_filter = !workspace_filter.is_empty();
    let is_workspace_mode = has_workspace_filter || workspaces_flag;

    let mut targeted_indices = Vec::new();
    if has_workspace_filter {
        for (idx, m) in workspace_members.iter().enumerate() {
            if workspace_filter.iter().any(|target| {
                let root = m
                    .path
                    .ancestors()
                    .nth(std::path::Path::new(&m.relative_path).components().count())
                    .unwrap_or(&m.path);
                rnpm_lifecycle::matches_filter(target, &m.name, &m.path, root)
            }) {
                targeted_indices.push(idx);
            }
        }
    } else if workspaces_flag {
        targeted_indices = (0..workspace_members.len()).collect();
    }

    let target_root = !is_workspace_mode || workspace_root_flag;
    (targeted_indices, target_root)
}

/// Computes the exact save spec string for writing into package.json.
pub fn compute_save_spec(
    target: &PackageTarget,
    resolved_version: &str,
    save_exact: bool,
    save_prefix: Option<&str>,
) -> String {
    let prefix = if save_exact {
        ""
    } else {
        save_prefix.unwrap_or("^")
    };

    match target {
        PackageTarget::File(p) => {
            let s = rnpm_core::to_posix_path(&p.to_string_lossy());
            let clean = s.strip_prefix("./").unwrap_or(&s);
            format!("file:{clean}")
        }
        PackageTarget::Git { url, committish } => {
            format!(
                "{}{}",
                url,
                committish
                    .as_ref()
                    .map(|c| format!("#{c}"))
                    .unwrap_or_default()
            )
        }
        PackageTarget::Workspace(ws) => format!("workspace:{}", ws),
        PackageTarget::Url(u) => u.to_string(),
        PackageTarget::Alias {
            name: real_name,
            target,
        } => format!(
            "npm:{}@{}",
            real_name,
            compute_save_spec(target, resolved_version, save_exact, save_prefix)
        ),
        PackageTarget::Range(range) if range.raw != "*" && !range.raw.is_empty() => {
            let proposed = format!("{prefix}{resolved_version}");
            if range_contains_saved_range(range, &proposed) {
                proposed
            } else {
                range.raw.clone()
            }
        }
        _ => {
            if save_exact {
                resolved_version.to_string()
            } else {
                format!("{}{}", prefix, resolved_version)
            }
        }
    }
}

// Arborist retains a requested range when the save-prefix range would allow
// versions outside it. Compare the parsed comparator bounds, not string prefixes.
fn range_contains_saved_range(requested: &rnpm_core::semver::Range, proposed: &str) -> bool {
    use rnpm_core::semver::comparator::Op;
    let Ok(candidate) = rnpm_core::semver::Range::parse(proposed) else {
        return false;
    };
    candidate.sets.iter().all(|sub| {
        requested.sets.iter().any(|sup| {
            sup.comparators.iter().all(|required| {
                sub.comparators.iter().any(|bound| {
                    use Op::*;
                    match (required.op, bound.op) {
                        (_, Eq) => required.matches(&bound.version),
                        (Gte, Gte | Gt) => bound.version >= required.version,
                        (Gt, Gt) => bound.version >= required.version,
                        (Gt, Gte) => bound.version > required.version,
                        (Lte, Lte | Lt) => bound.version <= required.version,
                        (Lt, Lt) => bound.version <= required.version,
                        (Lt, Lte) => bound.version < required.version,
                        _ => false,
                    }
                })
            })
        })
    })
}

/// Re-expresses a root-relative `file:` save spec relative to a workspace
/// member directory, matching npm, which saves local specs relative to the
/// package.json they are written into. Non-file and absolute specs are
/// returned unchanged.
pub fn member_relative_file_spec(spec: &str, member_relative_path: &str) -> String {
    let Some(path) = spec.strip_prefix("file:") else {
        return spec.to_string();
    };
    let is_absolute = path.starts_with('/')
        || path.starts_with('\\')
        || path.as_bytes().get(1) == Some(&b':');
    if is_absolute {
        return spec.to_string();
    }
    let parts = |s: &str| -> Vec<String> {
        s.split(['/', '\\'])
            .filter(|c| !c.is_empty() && *c != ".")
            .map(str::to_string)
            .collect()
    };
    let target = parts(path);
    let member = parts(member_relative_path);
    let common = target
        .iter()
        .zip(member.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut rel: Vec<String> = vec!["..".to_string(); member.len() - common];
    rel.extend(target[common..].iter().cloned());
    if rel.is_empty() {
        "file:.".to_string()
    } else {
        format!("file:{}", rel.join("/"))
    }
}

/// Inserts a dependency into the appropriate section of a Manifest.
pub fn insert_manifest_dep(
    m: &mut Manifest,
    name: &str,
    spec: &str,
    save_dev: bool,
    save_optional: bool,
    save_peer: bool,
) {
    if save_dev {
        m.dev_dependencies
            .insert(name.to_string(), spec.to_string());
    } else if save_optional {
        m.optional_dependencies
            .insert(name.to_string(), spec.to_string());
    } else if save_peer {
        m.peer_dependencies
            .insert(name.to_string(), spec.to_string());
    } else {
        m.dependencies.insert(name.to_string(), spec.to_string());
    }
}

/// npm's add-rm-pkg-deps keeps the bundle list sorted and unique.
pub fn bundle_manifest_dep(manifest: &mut Manifest, name: &str) {
    let mut names = manifest.bundled_package_names();
    names.push(name.to_string());
    // npm uses an English collator. These are the punctuation characters
    // permitted in npm names, in their English collation order.
    names.sort_by_cached_key(|name| name.bytes().map(|byte| match byte {
        b'_' => 0,
        b'-' => 1,
        b'.' => 2,
        b'@' => 3,
        b'/' => 4,
        other => other.to_ascii_lowercase(),
    }).collect::<Vec<_>>());
    names.dedup();
    manifest.bundled_dependencies = Some(rnpm_core::BundledDependencies::List(names));
}

/// Root bundles are still installed normally, but carry inBundle in lockfiles.
pub fn mark_root_bundles(
    lockfile: &mut rnpm_lockfile::LockfileV3,
    graph: &rnpm_solver::DependencyGraph,
    manifest: &Manifest,
) {
    let names = manifest.bundled_package_names();
    let mut queue: Vec<_> = graph.get_outgoing_edges("").iter()
        .filter(|edge| names.contains(&edge.install_name))
        .map(|edge| edge.to_location.clone()).collect();
    let mut seen = std::collections::HashSet::new();
    while let Some(location) = queue.pop() {
        if !seen.insert(location.clone()) { continue; }
        if let Some(package) = lockfile.packages.get_mut(&location) {
            package.in_bundle = Some(true);
        }
        queue.extend(graph.get_outgoing_edges(&location).iter().map(|edge| edge.to_location.clone()));
    }
}

/// Syncs a lockfile package entry's dependencies with a Manifest, clearing `raw_value`
/// so serialization faithfully reflects the updated fields.
pub fn sync_lockfile_package_entry(pkg_entry: &mut LockfilePackage, manifest: &Manifest) {
    pkg_entry.raw_value = None;
    pkg_entry.bundle_dependencies = manifest.bundled_dependencies.clone();
    if manifest.dependencies.is_empty() {
        pkg_entry.dependencies = None;
    } else {
        pkg_entry.dependencies = Some(manifest.dependencies.clone());
    }
    if manifest.dev_dependencies.is_empty() {
        pkg_entry.dev_dependencies = None;
    } else {
        pkg_entry.dev_dependencies = Some(manifest.dev_dependencies.clone());
    }
    if manifest.optional_dependencies.is_empty() {
        pkg_entry.optional_dependencies = None;
    } else {
        pkg_entry.optional_dependencies = Some(manifest.optional_dependencies.clone());
    }
    if manifest.peer_dependencies.is_empty() {
        pkg_entry.peer_dependencies = None;
    } else {
        pkg_entry.peer_dependencies = Some(manifest.peer_dependencies.clone());
    }
}

/// Saves the root manifest and targeted workspace manifests to disk.
pub fn save_manifests(
    project_dir: &Path,
    manifest: &Manifest,
    target_root: bool,
    workspace_members: &[WorkspaceMember],
    targeted_indices: &[usize],
) -> Result<()> {
    if target_root {
        manifest
            .save_to_file(project_dir.join("package.json"))
            .context("Failed to save updated root package.json")?;
    }
    for &idx in targeted_indices {
        let member = &workspace_members[idx];
        let member_pkg_path = project_dir.join(&member.relative_path).join("package.json");
        member
            .manifest
            .save_to_file(&member_pkg_path)
            .with_context(|| format!("Failed to save {}", member_pkg_path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod replacement_tests {
    use super::*;
    #[test]
    fn save_range_stays_within_requested_versions() {
        for (spec, prefix, exact, expected) in [
            ("~1.0.0", None, false, "~1.0.0"),
            (">=1 <2", None, false, "^1.0.3"),
            ("^1.0.0", Some("~"), false, "~1.0.3"),
            ("~1.0.0", None, true, "1.0.3"),
            ("npm:real@~1.0.0", None, false, "npm:real@~1.0.0"),
            ("npm:real@next", None, false, "npm:real@^1.0.3"),
        ] {
            assert_eq!(
                compute_save_spec(&PackageTarget::parse(spec).unwrap(), "1.0.3", exact, prefix),
                expected,
                "{spec}"
            );
        }
    }
    #[test]
    fn workspace_parent_directory_selects_children_without_suffix_matching() {
        let root = std::env::temp_dir().join("workspace-select");
        let members = ["packages/a", "packages/b", "other/a"].map(|relative| WorkspaceMember {
            name: format!("pkg-{}", relative.replace('/', "-")),
            version: Some("1.0.0".into()),
            path: root.join(relative),
            relative_path: relative.into(),
            manifest: Manifest::default(),
        });
        assert_eq!(
            resolve_targeted_workspaces(&members, &["packages".into()], false, false),
            (vec![0, 1], false)
        );
        assert_eq!(
            resolve_targeted_workspaces(&members, &["a".into()], false, false),
            (vec![], false)
        );
    }
}
