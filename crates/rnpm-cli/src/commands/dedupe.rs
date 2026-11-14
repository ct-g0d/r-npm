use anyhow::Result;
use rnpm_install::{InstallOptions, Installer};
use std::path::PathBuf;

/// `npm dedupe`; `npm find-dupes` is the same reify in dry-run mode.
pub(crate) async fn run_dedupe(packages: Vec<String>, dry_run: bool, current_dir: PathBuf) -> Result<()> {
    let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
    let dry_run = dry_run || config.get_bool("dry-run").unwrap_or(false);
    let json = config.get_bool("json").unwrap_or(false);
    let start_time = std::time::Instant::now();
    let before = crate::reify_output::snapshot(&current_dir);
    let nm_dir = current_dir.join("node_modules");
    let needs_reify = !nm_dir.exists() && has_declared_dependencies(&current_dir)?;

    let mut report = rnpm_install::ReifyReport::default();
    if needs_reify {
        let mut installer = Installer::new(InstallOptions {
            project_dir: current_dir.clone(),
            dry_run,
            ..Default::default()
        })?;
        if let Some(r) = installer.run().await?.reify {
            report = r;
        }
    }

    let dedupe_options = rnpm_install::DedupeOptions {
        project_dir: current_dir.clone(),
        dry_run,
        packages,
    };
    let installer = Installer::new(InstallOptions {
        project_dir: current_dir.clone(),
        dry_run,
        ..Default::default()
    })?;
    let summary = installer.dedupe(&dedupe_options)?;

    if dry_run {
        for action in &summary.actions {
            let entry = |location: &str| rnpm_install::ReifyEntry {
                name: action.package_name.clone(),
                version: action.version.clone(),
                location: location.to_string(),
            };
            report.changes.push(rnpm_install::ReifyChange::Remove(entry(&action.original_path)));
            if action.action_type == rnpm_install::DedupeActionType::HoistAndDedupe && !before.contains_key(&action.target_path) {
                report.changes.push(rnpm_install::ReifyChange::Add(entry(&action.target_path)));
            }
        }
        report.inventory = before.len() + 1;
    } else {
        report = crate::reify_output::report_between(&before, &crate::reify_output::snapshot(&current_dir));
    }
    crate::reify_output::finish(&current_dir, &report, json, dry_run, false, start_time.elapsed()).await
}

pub(crate) async fn run_find_dupes(packages: Vec<String>, current_dir: PathBuf) -> Result<()> {
    run_dedupe(packages, true, current_dir).await
}

fn has_declared_dependencies(dir: &std::path::Path) -> Result<bool> {
    let m = rnpm_core::manifest::Manifest::from_file(dir.join("package.json"))?;
    Ok(!m.dependencies.is_empty()
        || !m.dev_dependencies.is_empty()
        || !m.optional_dependencies.is_empty()
        || !m.peer_dependencies.is_empty()
        || !m.workspace_patterns().is_empty())
}
