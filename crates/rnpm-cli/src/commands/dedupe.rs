use anyhow::Result;
use rnpm_install::{InstallOptions, Installer};
use std::path::PathBuf;

pub(crate) async fn run_dedupe(packages: Vec<String>, dry_run: bool, current_dir: PathBuf) -> Result<()> {
    let start_time = std::time::Instant::now();
    let nm_dir = current_dir.join("node_modules");
    let needs_reify = !nm_dir.exists();

    let total_added = if needs_reify {
        let install_options = InstallOptions {
            project_dir: current_dir.clone(),
            dry_run,
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
        dry_run,
        packages,
    };
    let installer = Installer::new(InstallOptions {
        project_dir: current_dir,
        dry_run,
        ..Default::default()
    })?;
    let summary = installer.dedupe(&dedupe_options)?;

    let elapsed = start_time.elapsed();
    let elapsed_sec = elapsed.as_secs_f64();
    let time_str = if elapsed_sec < 1.0 {
        format!("{}ms", elapsed.as_millis())
    } else {
        format!("{:.1}s", elapsed_sec)
    };

    if dry_run {
        if summary.actions.is_empty() {
            if total_added > 0 {
                let pkg_word = if total_added == 1 { "package" } else { "packages" };
                println!("\nadded {total_added} {pkg_word} in {time_str}");
            } else {
                println!("rnpm: dedupe dry-run: tree is already deduplicated, no duplicates found");
                println!("\nup to date in {time_str}");
            }
        } else {
            for action in &summary.actions {
                match action.action_type {
                    rnpm_install::DedupeActionType::DeleteDuplicate => {
                        println!(
                            "rnpm: dedupe: would remove {} ({})",
                            action.original_path, action.reason
                        );
                    }
                    rnpm_install::DedupeActionType::HoistAndDedupe => {
                        println!(
                            "rnpm: dedupe: would hoist {} -> {} ({})",
                            action.original_path, action.target_path, action.reason
                        );
                    }
                }
            }
            println!(
                "rnpm: dedupe dry-run: {} action(s) would be performed",
                summary.actions.len()
            );
        }
    } else if summary.actions.is_empty() {
        if total_added > 0 {
            let pkg_word = if total_added == 1 { "package" } else { "packages" };
            println!("\nadded {total_added} {pkg_word} in {time_str}");
        } else {
            println!("rnpm: tree is already deduplicated");
            println!("\nup to date in {time_str}");
        }
    } else {
        for action in &summary.actions {
            match action.action_type {
                rnpm_install::DedupeActionType::DeleteDuplicate => {
                    println!("rnpm: dedupe: removed {}", action.original_path);
                }
                rnpm_install::DedupeActionType::HoistAndDedupe => {
                    println!(
                        "rnpm: dedupe: hoisted {} -> {}",
                        action.original_path, action.target_path
                    );
                }
            }
        }
        println!(
            "rnpm: successfully deduplicated {} package(s)",
            summary.actions.len()
        );
        let pkg_word = if summary.actions.len() == 1 { "package" } else { "packages" };
        println!("\nremoved {} {pkg_word} in {time_str}", summary.actions.len());
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

    let elapsed = start_time.elapsed();
    let elapsed_sec = elapsed.as_secs_f64();
    let time_str = if elapsed_sec < 1.0 {
        format!("{}ms", elapsed.as_millis())
    } else {
        format!("{:.1}s", elapsed_sec)
    };

    if summary.actions.is_empty() {
        if total_added > 0 {
            let pkg_word = if total_added == 1 { "package" } else { "packages" };
            println!("\nadded {total_added} {pkg_word} in {time_str}");
        } else {
            println!("rnpm: find-dupes: no duplicate packages found");
            println!("\nup to date in {time_str}");
        }
    } else {
        for action in &summary.actions {
            println!(
                "rnpm: find-dupes: duplicate found: {} ({})",
                action.original_path, action.reason
            );
        }
        println!(
            "rnpm: find-dupes: {} duplicate package(s) detected",
            summary.actions.len()
        );
    }

    Ok(())
}
