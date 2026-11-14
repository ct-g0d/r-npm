use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct UnpublishArgs {
    pub package: Option<String>,
    pub version: Option<String>,
    pub force: bool,
    pub dry_run: bool,
    pub registry: Option<String>,
    pub otp: Option<String>,
}

pub(crate) async fn run(args: UnpublishArgs, current_dir: PathBuf) -> Result<()> {
    let raw_package = match args.package {
        Some(pkg) => pkg,
        None => crate::package_name_from_manifest(&current_dir)?,
    };

    let (package, version) = if let Some(v) = args.version {
        (raw_package, Some(v))
    } else if let Ok((pkg, ver)) = crate::split_package_version(&raw_package) {
        (pkg.to_string(), Some(ver.to_string()))
    } else {
        (raw_package, None)
    };

    if !args.force && version.is_none() {
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\nnpm error\nnpm error Refusing to delete entire project.\nnpm error Run with --force to do this."
        ));
    }

    let target_display = if let Some(ref ver) = version {
        format!("{package}@{ver}")
    } else {
        package.clone()
    };

    if args.dry_run {
        println!("- {target_display}");
        return Ok(());
    }

    let (registry_url, client) = crate::make_registry_client(&current_dir, args.registry)?;
    super::client_helper::with_registry_otp(&current_dir, "PUT", args.otp, async |otp| {
        client.unpublish(Some(&registry_url), &package, version.as_deref(), otp.as_deref()).await
    }).await?;

    println!("- {target_display}");
    Ok(())
}
