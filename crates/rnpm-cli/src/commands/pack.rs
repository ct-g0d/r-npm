use anyhow::{anyhow, Result};
use rnpm_core::manifest::Manifest;
use std::path::PathBuf;

pub(crate) struct PackCommandArgs {
    pub target: PathBuf,
    pub dry_run: bool,
    pub json: bool,
    pub pack_destination: Option<PathBuf>,
    pub ignore_scripts: bool,
    pub foreground_scripts: bool,
}

pub(crate) async fn run(args: PackCommandArgs, current_dir: PathBuf) -> Result<()> {
    let package_dir = if args.target.is_absolute() {
        args.target
    } else {
        current_dir.join(args.target)
    };

    let manifest_path = package_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow!(
            "package.json not found in {}",
            package_dir.display()
        ));
    }

    let manifest = Manifest::from_file(&manifest_path)?;
    let config = rnpm_config::Config::load(Some(&package_dir)).ok();
    let cli_overrides = rnpm_config::get_process_cli_overrides();
    let effective_ignore = args.ignore_scripts
        || cli_overrides.as_ref().and_then(|o| o.get("ignore-scripts")).map(|v| v == "true" || v == "1").unwrap_or(false)
        || config.as_ref().and_then(|c| c.get_bool("ignore-scripts")).unwrap_or(false);
    let effective_foreground = args.foreground_scripts
        || cli_overrides.as_ref().and_then(|o| o.get("foreground-scripts")).map(|v| v == "true" || v == "1").unwrap_or(false)
        || config.as_ref().and_then(|c| c.get_bool("foreground-scripts")).unwrap_or(true);
    let is_silent = cli_overrides.as_ref().and_then(|o| o.get("loglevel")).map(|s| s == "silent").unwrap_or(false)
        || config.as_ref().and_then(|c| c.get("loglevel")).map(|s| s == "silent").unwrap_or(false);

    if !package_dir.join(".npmignore").is_file() && package_dir.join(".gitignore").is_file()
        && config.as_ref().and_then(|c| c.get("loglevel")) != Some("silent") {
        eprintln!("npm warn gitignore-fallback No .npmignore file found, using .gitignore for file exclusion. Consider creating a .npmignore file to explicitly control published files.");
    }

    crate::run_lifecycle_hook(&package_dir, &manifest, "prepack", effective_ignore, effective_foreground, is_silent, args.json)?;
    crate::run_lifecycle_hook(&package_dir, &manifest, "prepare", effective_ignore, effective_foreground, is_silent, args.json)?;

    let (summary, tarball_bytes) = match rnpm_fs::pack_directory(&package_dir, None) {
        Ok(res) => res,
        Err(e) => {
            return Err(anyhow!("pack failed: {e}"));
        }
    };

    crate::run_lifecycle_hook(&package_dir, &manifest, "postpack", effective_ignore, effective_foreground, is_silent, args.json)?;

    let dest_dir = args.pack_destination.unwrap_or_else(|| current_dir.clone());
    let final_tarball_path = dest_dir.join(&summary.filename);

    if !args.dry_run {
        if let Err(e) = std::fs::write(&final_tarball_path, &tarball_bytes) {
            return Err(anyhow!(
                "failed to write {}: {e}",
                final_tarball_path.display()
            ));
        }
    }

    if args.json {
        let json_output = serde_json::json!([
            {
                "id": format!("{}@{}", summary.name, summary.version),
                "name": summary.name,
                "version": summary.version,
                "size": summary.package_size,
                "unpackedSize": summary.unpacked_size,
                "shasum": summary.shasum,
                "integrity": summary.integrity,
                "filename": summary.filename,
                "files": summary.files.iter().map(|f| serde_json::json!({
                    "path": f.path,
                    "size": f.size,
                    "mode": f.mode,
                })).collect::<Vec<_>>(),
                "entryCount": summary.entry_count,
                "bundled": summary.bundled,
            }
        ]);
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        if !is_silent {
            crate::print_pack_notices(&summary);
        }
        println!("{}", summary.filename);
    }

    Ok(())
}
