use anyhow::Result;
use rnpm_core::manifest::Manifest;
use rnpm_install::{InstallOptions, Installer};
use std::path::PathBuf;

pub(crate) struct UpdateOptions {
    pub packages: Vec<String>,
    pub registry: Option<String>,
    pub cache: Option<PathBuf>,
    pub offline: bool,
    pub ignore_scripts: bool,
    pub foreground_scripts: bool,
    pub strict_sandbox: bool,
    pub legacy_peer_deps: bool,
    pub strict_peer_deps: bool,
    pub silent: bool,
    pub json: bool,
}

pub(crate) async fn run(opts: UpdateOptions, current_dir: PathBuf) -> Result<()> {
    let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
    let effective_ignore =
        opts.ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false);
    let effective_foreground =
        opts.foreground_scripts || config.get_bool("foreground-scripts").unwrap_or(false);
    let effective_strict =
        opts.strict_sandbox || config.get_bool("strict-sandbox").unwrap_or(false);

    let dry_run = config.get_bool("dry-run").unwrap_or(false);
    let mut unlocked_packages = std::collections::HashSet::new();
    if dry_run {
        if opts.packages.is_empty() {
            let manifest = Manifest::from_file(current_dir.join("package.json"))?;
            unlocked_packages.extend(manifest.dependencies.into_keys());
            unlocked_packages.extend(manifest.dev_dependencies.into_keys());
            unlocked_packages.extend(manifest.optional_dependencies.into_keys());
        } else {
            for package in &opts.packages {
                let name = package.rsplit("node_modules/").next().unwrap_or(package);
                unlocked_packages.insert(rnpm_core::spec::PackageSpec::parse(name)?.name);
            }
        }
    }

    let options = InstallOptions {
        project_dir: current_dir.clone(),
        registry_url: opts.registry,
        cache_dir: opts.cache,
        offline: opts.offline,
        ignore_scripts: effective_ignore,
        foreground_scripts: effective_foreground,
        strict_sandbox: effective_strict,
        legacy_peer_deps: opts.legacy_peer_deps,
        strict_peer_deps: opts.strict_peer_deps,
        dry_run,
        silent: opts.silent,
        unlocked_packages,
        ..Default::default()
    };

    let start_time = std::time::Instant::now();
    let mut installer = Installer::new(options)?;
    if dry_run {
        let summary = installer.run().await?;
        let report = summary.reify.unwrap_or_default();
        return crate::reify_output::finish(&current_dir, &report, opts.json, true, opts.silent, start_time.elapsed()).await;
    }
    let before = crate::reify_output::snapshot(&current_dir);
    installer.update(&opts.packages).await?;
    let report = crate::reify_output::report_between(&before, &crate::reify_output::snapshot(&current_dir));
    crate::reify_output::finish(&current_dir, &report, opts.json, false, opts.silent, start_time.elapsed()).await
}
