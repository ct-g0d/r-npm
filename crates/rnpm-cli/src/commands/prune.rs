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

    let removed = if args.dry_run {
        let analysis = installer.analyze_prune(&prune_options)?;
        analysis.extraneous_packages.len()
    } else {
        let summary = installer.prune(&prune_options)?;
        summary.removed_packages.len()
    };

    if !had_nm && install_summary.packages_installed == 0 && nm_dir.exists() {
        let _ = std::fs::remove_dir_all(&nm_dir);
    }

    let total_added = install_summary.packages_installed;
    let total_removed = removed;

    if args.json {
        let json_output = serde_json::json!({
            "added": total_added,
            "removed": total_removed,
            "changed": 0,
            "audited": 0,
            "funding": 0
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else if !args.silent {
        let elapsed = start_time.elapsed();
        let elapsed_sec = elapsed.as_secs_f64();
        let time_str = if elapsed_sec < 1.0 {
            format!("{}ms", elapsed.as_millis())
        } else {
            format!("{:.1}s", elapsed_sec)
        };
        if total_added > 0 {
            let pkg_word = if total_added == 1 { "package" } else { "packages" };
            println!("\nadded {total_added} {pkg_word} in {time_str}");
        } else if total_removed > 0 {
            let pkg_word = if total_removed == 1 { "package" } else { "packages" };
            println!("\nremoved {total_removed} {pkg_word} in {time_str}");
        } else {
            println!("\nup to date in {time_str}");
        }
    }

    Ok(())
}
