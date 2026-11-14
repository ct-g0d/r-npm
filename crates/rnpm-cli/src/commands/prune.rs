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
}

pub(crate) async fn run(args: PruneCommandArgs, current_dir: PathBuf) -> Result<()> {
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
    let before = crate::reify_output::snapshot(&current_dir);

    let install_options = InstallOptions {
        project_dir: current_dir.clone(),
        omit_dev,
        omit_optional,
        omit_peer,
        dry_run: args.dry_run,
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

    let report = if args.dry_run {
        let analysis = installer.analyze_prune(&prune_options)?;
        let mut report = install_summary.reify.unwrap_or_default();
        for pkg in analysis.extraneous_packages {
            report.changes.push(rnpm_install::ReifyChange::Remove(rnpm_install::ReifyEntry {
                name: pkg.path.rsplit("node_modules/").next().unwrap_or(&pkg.name).to_string(),
                version: pkg.version.unwrap_or_default(),
                location: pkg.path,
            }));
        }
        report
    } else {
        installer.prune(&prune_options)?;
        if !had_nm && install_summary.packages_installed == 0 && nm_dir.exists() {
            let _ = std::fs::remove_dir_all(&nm_dir);
        }
        crate::reify_output::report_between(&before, &crate::reify_output::snapshot(&current_dir))
    };

    crate::reify_output::finish(&current_dir, &report, args.json, args.dry_run, args.silent, start_time.elapsed()).await
}
