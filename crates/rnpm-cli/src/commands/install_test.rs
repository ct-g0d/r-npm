use anyhow::Result;
use rnpm_install::{InstallOptions, Installer};
use std::path::PathBuf;

pub(crate) async fn run_install_test(args: Vec<String>, current_dir: PathBuf) -> Result<()> {
    let mut installer = Installer::new(InstallOptions {
        project_dir: current_dir.clone(),
        ..Default::default()
    })?;
    installer.run().await?;
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
    let mut installer = Installer::new(InstallOptions {
        project_dir: current_dir.clone(),
        ..Default::default()
    })?;
    installer.run_ci().await?;
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
