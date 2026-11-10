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
        project_dir: current_dir,
        registry_url: opts.registry,
        cache_dir: opts.cache,
        offline: opts.offline,
        ignore_scripts: effective_ignore,
        foreground_scripts: effective_foreground,
        strict_sandbox: effective_strict,
        legacy_peer_deps: opts.legacy_peer_deps,
        strict_peer_deps: opts.strict_peer_deps,
        dry_run,
        unlocked_packages,
        ..Default::default()
    };

    let mut installer = Installer::new(options)?;
    if dry_run {
        let summary = installer.run().await?;
        if !opts.silent {
            println!(
                "rnpm: dry-run: would install {} package(s)",
                summary.packages_installed
            );
        }
        return Ok(());
    }
    let summary = installer.update(&opts.packages).await?;

    if opts.silent {
        return Ok(());
    } else if summary.packages_updated == 0 {
        println!("rnpm: up to date");
    } else {
        for pkg in &summary.updated_packages {
            let old_v = summary
                .old_versions
                .get(pkg)
                .map(|s| s.as_str())
                .unwrap_or("none");
            let new_v = summary
                .new_versions
                .get(pkg)
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            println!("rnpm: updated {pkg} {old_v} -> {new_v}");
        }
        println!(
            "rnpm: successfully updated {} package(s) (cache hits: {}, misses: {})",
            summary.packages_updated, summary.cache_hits, summary.cache_misses
        );
    }

    Ok(())
}
