use anyhow::Result;
use rnpm_install::{InstallOptions, Installer};
use std::path::PathBuf;

pub(crate) fn run_dedupe(packages: Vec<String>, dry_run: bool, current_dir: PathBuf) -> Result<()> {
    let dedupe_options = rnpm_install::DedupeOptions {
        project_dir: current_dir.clone(),
        dry_run,
        packages,
    };
    let installer = Installer::new(InstallOptions {
        project_dir: current_dir,
        ..Default::default()
    })?;
    let summary = installer.dedupe(&dedupe_options)?;

    if dry_run {
        if summary.actions.is_empty() {
            println!("rnpm: dedupe dry-run: tree is already deduplicated, no duplicates found");
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
        println!("rnpm: tree is already deduplicated");
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
    }

    Ok(())
}

pub(crate) fn run_find_dupes(packages: Vec<String>, current_dir: PathBuf) -> Result<()> {
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

    if summary.actions.is_empty() {
        println!("rnpm: find-dupes: no duplicate packages found");
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
