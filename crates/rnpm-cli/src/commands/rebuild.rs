use anyhow::Result;
use rnpm_install::{InstallOptions, Installer};
use std::path::PathBuf;

pub(crate) struct RebuildOptions {
    pub packages: Vec<String>,
    pub ignore_scripts: bool,
    pub foreground_scripts: bool,
    pub strict_sandbox: bool,
}

pub(crate) async fn run(opts: RebuildOptions, current_dir: PathBuf) -> Result<()> {
    let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
    let effective_ignore =
        opts.ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false);
    let effective_foreground =
        opts.foreground_scripts || config.get_bool("foreground-scripts").unwrap_or(false);
    let effective_strict =
        opts.strict_sandbox || config.get_bool("strict-sandbox").unwrap_or(false);

    let rebuild_options = rnpm_install::RebuildOptions {
        project_dir: current_dir.clone(),
        packages: opts.packages,
        ignore_scripts: effective_ignore,
        foreground_scripts: effective_foreground,
        strict_sandbox: effective_strict,
    };

    let installer = Installer::new(InstallOptions {
        project_dir: current_dir,
        ignore_scripts: effective_ignore,
        foreground_scripts: effective_foreground,
        strict_sandbox: effective_strict,
        ..Default::default()
    })?;

    let summary = installer.rebuild(&rebuild_options).await?;
    for pkg in &summary.rebuilt_packages {
        println!("rnpm: rebuilt {pkg}");
    }
    println!("rebuilt dependencies successfully");

    Ok(())
}
