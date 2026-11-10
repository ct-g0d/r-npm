use anyhow::Result;
use std::path::PathBuf;

pub(crate) fn run_link(package: Option<String>, current_dir: PathBuf) -> Result<()> {
    let global_prefix = rnpm_config::find_global_prefix();
    match package {
        None => {
            let target_link = rnpm_install::link_package(&current_dir, &global_prefix)?;
            println!("{} -> {}", target_link.display(), current_dir.display());
        }
        Some(pkg) => {
            let target_link =
                rnpm_install::link_package_from_global(&current_dir, &pkg, &global_prefix)?;
            let global_nm = rnpm_config::find_global_node_modules(&global_prefix);
            println!(
                "{} -> {}",
                target_link.display(),
                global_nm.join(&pkg).display()
            );
        }
    }
    Ok(())
}

pub(crate) fn run_unlink(package: Option<String>, current_dir: PathBuf) -> Result<()> {
    let global_prefix = rnpm_config::find_global_prefix();
    match package {
        None => {
            if let Some(target) =
                rnpm_install::unlink_package(&current_dir, &global_prefix)?
            {
                println!("unlinked {}", target.display());
            }
        }
        Some(pkg) => {
            if let Some(target) =
                rnpm_install::unlink_package_from_consumer(&current_dir, &pkg)?
            {
                println!("unlinked {}", target.display());
            }
        }
    }
    Ok(())
}
