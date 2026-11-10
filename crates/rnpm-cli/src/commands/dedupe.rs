use anyhow::Result;
use rnpm_install::{InstallOptions, Installer};
use std::path::PathBuf;

pub(crate) async fn run_dedupe(packages: Vec<String>, dry_run: bool, current_dir: PathBuf) -> Result<()> {
    let start_time = std::time::Instant::now();
    let install_options = InstallOptions {
        project_dir: current_dir.clone(),
        dry_run,
        ..Default::default()
    };
    let mut installer = Installer::new(install_options)?;
    let install_summary = installer.run().await?;

    let dedupe_options = rnpm_install::DedupeOptions {
        project_dir: current_dir.clone(),
        dry_run,
        packages,
    };
    let summary = installer.dedupe(&dedupe_options)?;

    let total_added = install_summary.packages_installed;
    let total_removed = summary.actions.len();

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

    Ok(())
}

pub(crate) async fn run_find_dupes(packages: Vec<String>, current_dir: PathBuf) -> Result<()> {
    let start_time = std::time::Instant::now();
    let nm_dir = current_dir.join("node_modules");
    let needs_reify = !nm_dir.exists();

    let total_added = if needs_reify {
        let install_options = InstallOptions {
            project_dir: current_dir.clone(),
            dry_run: true,
            ..Default::default()
        };
        let mut installer = Installer::new(install_options)?;
        let summary = installer.run().await?;
        summary.packages_installed
    } else {
        0
    };

    let dedupe_options = rnpm_install::DedupeOptions {
        project_dir: current_dir.clone(),
        dry_run: true,
        packages,
    };
    let installer = Installer::new(InstallOptions {
        project_dir: current_dir,
        ..Default::default()
    })?;
    let summary = installer.find_dupes(&dedupe_options)?;

    let total_removed = summary.actions.len();

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

    Ok(())
}
