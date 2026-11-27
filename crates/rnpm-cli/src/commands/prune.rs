use anyhow::Result;
use rnpm_install::{InstallOptions, Installer};
use std::path::PathBuf;

pub(crate) struct PruneCommandArgs {
    pub omit: Vec<String>,
    pub include: Vec<String>,
    pub production: bool,
    pub dry_run: bool,
    pub json: bool,
    pub silent: bool,
    pub workspace_root: bool,
    pub workspace: Vec<String>,
    pub workspaces: bool,
}

#[allow(dead_code)]
pub(crate) async fn run(args: PruneCommandArgs, current_dir: PathBuf) -> Result<()> {
    run_with_config(args, current_dir, None).await
}

pub(crate) async fn run_with_config(
    args: PruneCommandArgs,
    current_dir: PathBuf,
    preloaded_config: Option<&rnpm_config::Config>,
) -> Result<()> {
    let start_time = std::time::Instant::now();
    let (mut omit_dev, omit_optional, omit_peer) =
        crate::parse_omit_and_include_options(&args.omit, &args.include);
    if args.production {
        let has_dev_included = args.include.iter().any(|val| {
            val.split(',').any(|part| {
                let t = part.trim().to_ascii_lowercase();
                t == "dev" || t == "development"
            })
        });
        if !has_dev_included {
            omit_dev = true;
        }
    }

    let nm_dir = current_dir.join("node_modules");
    let had_nm = nm_dir.exists();

    let install_options = InstallOptions {
        project_dir: current_dir.clone(),
        omit_dev,
        omit_optional,
        omit_peer,
        dry_run: args.dry_run,
        workspace_root: args.workspace_root,
        workspace: args.workspace,
        workspaces: args.workspaces,
        config_override: preloaded_config.cloned(),
        ..Default::default()
    };

    let mut installer = Installer::new(install_options)?;
    let install_summary = installer.run().await?;

    let prune_options = rnpm_install::prune::PruneOptions {
        project_dir: current_dir.clone(),
        omit_dev,
        omit_optional,
        omit_peer,
    };

    let analysis = installer.analyze_prune(&prune_options)?;
    let mut report = install_summary.reify.unwrap_or_default();
    if args.dry_run {
        for pkg in &analysis.extraneous_packages {
            report.changes.push(rnpm_install::ReifyChange::Remove(
                rnpm_install::ReifyEntry {
                    name: pkg
                        .path
                        .rsplit("node_modules/")
                        .next()
                        .unwrap_or(&pkg.name)
                        .to_string(),
                    version: pkg.version.clone().unwrap_or_default(),
                    location: pkg.path.clone(),
                },
            ));
        }
    } else {
        let summary = installer.prune_with_analysis(&analysis)?;
        if !had_nm && install_summary.packages_installed == 0 && nm_dir.exists() {
            let _ = std::fs::remove_dir_all(&nm_dir);
        }
        let removed_set: std::collections::HashSet<&str> = summary
            .removed_packages
            .iter()
            .map(String::as_str)
            .collect();
        for pkg in &analysis.extraneous_packages {
            if removed_set.contains(pkg.path.as_str()) {
                report.changes.push(rnpm_install::ReifyChange::Remove(
                    rnpm_install::ReifyEntry {
                        name: pkg
                            .path
                            .rsplit("node_modules/")
                            .next()
                            .unwrap_or(&pkg.name)
                            .to_string(),
                        version: pkg.version.clone().unwrap_or_default(),
                        location: pkg.path.clone(),
                    },
                ));
            }
        }
        report.inventory = analysis
            .discovered_packages
            .len()
            .saturating_sub(summary.removed_packages.len())
            + 1;
    }

    crate::reify_output::finish_with_config_and_lockfile(
        &current_dir,
        &report,
        args.json,
        args.dry_run,
        args.silent,
        start_time.elapsed(),
        preloaded_config,
        installer.last_lockfile(),
    )
    .await
}
