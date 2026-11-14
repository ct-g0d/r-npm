use anyhow::Result;
use std::path::PathBuf;

pub(crate) fn run_link(package: Option<String>, current_dir: PathBuf) -> Result<()> {
    let global_prefix = rnpm_config::find_global_prefix();
    let start_time = std::time::Instant::now();
    match package {
        None => {
            let _target_link = rnpm_install::link_package(&current_dir, &global_prefix)?;
            let elapsed_str = crate::format_duration(start_time.elapsed());
            println!("\nadded 1 package in {elapsed_str}");
        }
        Some(pkg) => {
            let _target_link =
                rnpm_install::link_package_from_global(&current_dir, &pkg, &global_prefix)?;
            let elapsed_str = crate::format_duration(start_time.elapsed());
            println!("\nadded 1 package in {elapsed_str}");
        }
    }
    Ok(())
}

pub(crate) fn run_unlink(package: Option<String>, current_dir: PathBuf) -> Result<()> {
    let global_prefix = rnpm_config::find_global_prefix();
    let start_time = std::time::Instant::now();
    match package {
        None => {
            if rnpm_install::unlink_package(&current_dir, &global_prefix)?.is_some() {
                let elapsed_str = crate::format_duration(start_time.elapsed());
                println!("removed 1 package in {elapsed_str}");
            }
        }
        Some(pkg) => {
            if rnpm_install::unlink_package_from_consumer(&current_dir, &pkg)?.is_some() {
                let elapsed_str = crate::format_duration(start_time.elapsed());
                println!("removed 1 package in {elapsed_str}");
            }
        }
    }
    Ok(())
}
