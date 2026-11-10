use crate::PkgAction;
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

pub(crate) fn run(
    action: PkgAction,
    prefix: PathBuf,
    json: bool,
    workspace: Vec<String>,
    workspaces: bool,
    current_dir: PathBuf,
) -> Result<()> {
    let base_path = if prefix.is_absolute() {
        prefix
    } else {
        current_dir.join(&prefix)
    };
    let root_manifest_path = if base_path.file_name().is_some_and(|f| f == "package.json") {
        base_path.clone()
    } else {
        base_path.join("package.json")
    };
    let project_root = if base_path.file_name().is_some_and(|f| f == "package.json") {
        base_path.parent().unwrap_or(&base_path).to_path_buf()
    } else {
        base_path.clone()
    };

    if !root_manifest_path.exists() {
        return Err(anyhow!(
            "code ENOENT: package.json not found in {}",
            project_root.display()
        ));
    }

    let is_workspace_mode = workspaces || !workspace.is_empty();
    if is_workspace_mode {
        let discovered = rnpm_core::workspace::discover_workspaces(&project_root)
            .map_err(|e| anyhow!("Failed to discover workspaces: {e}"))?;

        if discovered.is_empty() {
            return Err(anyhow!(
                "npm error code ENOWORKSPACES\nnpm error No workspaces found in {}",
                project_root.display()
            ));
        }

        let matched_members: Vec<rnpm_core::workspace::WorkspaceMember> = if workspaces
            && workspace.is_empty()
        {
            discovered
        } else {
            let mut matched = Vec::new();
            for ws_filter in &workspace {
                let matches: Vec<_> = discovered
                    .iter()
                    .filter(|m| {
                        rnpm_lifecycle::matches_filter(
                            ws_filter,
                            &m.name,
                            &m.path,
                            &project_root,
                        )
                    })
                    .cloned()
                    .collect();
                if matches.is_empty() {
                    return Err(anyhow!(
                        "npm error code ENOWORKSPACE\nnpm error No workspaces found for: {ws_filter}"
                    ));
                }
                for m in matches {
                    if !matched.iter().any(|existing: &rnpm_core::workspace::WorkspaceMember| {
                        existing.name == m.name
                    }) {
                        matched.push(m);
                    }
                }
            }
            matched
        };

        match action {
            PkgAction::Get { fields } => {
                let member_refs: Vec<(&str, &Path)> = matched_members
                    .iter()
                    .map(|m| (m.name.as_str(), m.path.as_path()))
                    .collect();
                let output = rnpm_core::pkg::pkg_get_workspaces(&member_refs, &fields)?;
                println!("{output}");
            }
            PkgAction::Set { assignments } => {
                for m in &matched_members {
                    rnpm_core::pkg::pkg_set(&m.manifest_path(), &assignments)?;
                }
            }
            PkgAction::Delete { fields } => {
                for m in &matched_members {
                    rnpm_core::pkg::pkg_delete(&m.manifest_path(), &fields)?;
                }
            }
            PkgAction::Fix => {
                for m in &matched_members {
                    fix_manifest(&m.manifest_path())?;
                }
            }
        }
    } else {
        match action {
            PkgAction::Get { fields } => {
                let output = rnpm_core::pkg::pkg_get(&root_manifest_path, &fields, json)?;
                println!("{output}");
            }
            PkgAction::Set { assignments } => {
                rnpm_core::pkg::pkg_set(&root_manifest_path, &assignments)?;
            }
            PkgAction::Delete { fields } => {
                rnpm_core::pkg::pkg_delete(&root_manifest_path, &fields)?;
            }
            PkgAction::Fix => {
                fix_manifest(&root_manifest_path)?;
            }
        }
    }

    Ok(())
}

fn fix_manifest(path: &Path) -> Result<()> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let val: serde_json::Value = serde_json::from_str(&content)?;
        let formatted = serde_json::to_string_pretty(&val)?;
        std::fs::write(path, formatted + "\n")?;
    }
    Ok(())
}
