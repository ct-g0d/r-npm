use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct DeprecateArgs {
    pub package: String,
    pub message: String,
    pub otp: Option<String>,
    pub registry: Option<String>,
}

pub(crate) async fn run(args: DeprecateArgs, current_dir: PathBuf) -> Result<()> {
    let (name, version) = crate::split_package_version(&args.package)?;
    let (registry_url, client) = crate::make_registry_client(&current_dir, args.registry)?;
    client
        .deprecate(Some(&registry_url), name, version, &args.message, args.otp.as_deref())
        .await?;
    eprintln!(
        "npm notice deprecating {name}@{version} with message \"{}\"",
        args.message
    );
    Ok(())
}
