use anyhow::Result;
use rnpm_install::{InstallOptions, Installer};
use std::path::PathBuf;

pub(crate) async fn run_install_test(args: Vec<String>, current_dir: PathBuf) -> Result<()> {
    let start_time = std::time::Instant::now();
    let mut installer = Installer::new(InstallOptions {
        project_dir: current_dir.clone(),
        ..Default::default()
    })?;
    let summary = installer.run().await?;
    let elapsed_str = crate::format_duration(start_time.elapsed());
    if summary.packages_installed > 0 {
        let pkg_str = if summary.packages_installed == 1 { "package" } else { "packages" };
        println!("added {} {} in {}", summary.packages_installed, pkg_str, elapsed_str);
    } else {
        println!("up to date in {}", elapsed_str);
    }
    crate::execute_run(
        current_dir,
        Some("test".into()),
        args,
        false,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
        false,
        false,
        false,
        false,
    )
    .await?;
    Ok(())
}

pub(crate) async fn run_install_ci_test(args: Vec<String>, current_dir: PathBuf) -> Result<()> {
    let start_time = std::time::Instant::now();
    let mut installer = Installer::new(InstallOptions {
        project_dir: current_dir.clone(),
        ..Default::default()
    })?;
    let summary = installer.run_ci().await?;
    let elapsed_str = crate::format_duration(start_time.elapsed());
    if summary.packages_installed > 0 {
        let pkg_str = if summary.packages_installed == 1 { "package" } else { "packages" };
        println!("added {} {} in {}", summary.packages_installed, pkg_str, elapsed_str);
    } else {
        println!("up to date in {}", elapsed_str);
    }
    crate::execute_run(
        current_dir,
        Some("test".into()),
        args,
        false,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
        false,
        false,
        false,
        false,
    )
    .await?;
    Ok(())
}
