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
                target == &m.name
                    || target == &m.relative_path
                    || m.relative_path.ends_with(target)
                    || target.trim_start_matches("./") == m.relative_path
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
            name: real_name, ..
        } => {
            if save_exact {
                format!("npm:{}@{}", real_name, resolved_version)
            } else {
                format!("npm:{}@{}{}", real_name, prefix, resolved_version)
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

/// Syncs a lockfile package entry's dependencies with a Manifest, clearing `raw_value`
/// so serialization faithfully reflects the updated fields.
pub fn sync_lockfile_package_entry(pkg_entry: &mut LockfilePackage, manifest: &Manifest) {
    pkg_entry.raw_value = None;
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
