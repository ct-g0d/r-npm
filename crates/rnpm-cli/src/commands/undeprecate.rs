use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct UndeprecateArgs {
    pub package: String,
    pub version: Option<String>,
    pub registry: Option<String>,
}

pub(crate) async fn run(args: UndeprecateArgs, current_dir: PathBuf) -> Result<()> {
    let (name, parsed_version): (&str, String) = if let Some(version) = args.version {
        (args.package.as_str(), version)
    } else {
        let (name, version) = crate::split_package_version(&args.package)?;
        (name, version.to_string())
    };
    let (registry_url, client) = crate::make_registry_client(&current_dir, args.registry)?;
    client
        .deprecate(Some(&registry_url), name, &parsed_version, "", None)
        .await?;
    eprintln!("npm notice undeprecating {name}@{parsed_version}");
    Ok(())
}
