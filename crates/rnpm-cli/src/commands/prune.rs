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

pub(crate) fn run(args: PruneCommandArgs, current_dir: PathBuf) -> Result<()> {
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
    let prune_options = rnpm_install::prune::PruneOptions {
        project_dir: current_dir.clone(),
        omit_dev,
        omit_optional,
        omit_peer,
    };

    let installer = Installer::new(InstallOptions {
        project_dir: current_dir,
        ..Default::default()
    })?;

    if args.dry_run {
        let analysis = installer.analyze_prune(&prune_options)?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&analysis)?);
        } else if args.silent {
            return Ok(());
        } else if analysis.extraneous_packages.is_empty() {
            println!("rnpm: dry-run: no packages would be pruned");
        } else {
            for pkg in &analysis.extraneous_packages {
                println!("rnpm: would remove {}", pkg.path);
            }
            println!(
                "rnpm: dry-run: {} package(s) would be removed",
                analysis.extraneous_packages.len()
            );
        }
    } else {
        let summary = installer.prune(&prune_options)?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else if args.silent {
            return Ok(());
        } else if summary.removed_packages.is_empty() {
            println!("rnpm: no extraneous packages pruned");
        } else {
            for pkg in &summary.removed_packages {
                println!("rnpm: removed {pkg}");
            }
            println!(
                "rnpm: successfully pruned {} package(s)",
                summary.removed_packages.len()
            );
        }
    }

    Ok(())
}
