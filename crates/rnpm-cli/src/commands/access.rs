use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct AccessArgs {
    pub args: Vec<String>,
    pub registry: Option<String>,
    pub json: bool,
    pub otp: Option<String>,
}

pub(crate) async fn run(args: AccessArgs, current_dir: PathBuf) -> Result<()> {
    let action = args.args.first().map(String::as_str).unwrap_or("get");
    let package = args
        .args
        .last()
        .filter(|value| !value.contains('='))
        .cloned()
        .or_else(|| crate::package_name_from_manifest(&current_dir).ok())
        .ok_or_else(|| {
            anyhow::anyhow!("npm error code EUSAGE\nnpm error access requires a package name")
        })?;
    let level = args
        .args
        .iter()
        .find_map(|value| value.strip_prefix("status="))
        .or_else(|| {
            args.args
                .get(1)
                .map(String::as_str)
                .filter(|value| *value == "public" || *value == "restricted")
        })
        .or(match action {
            "public" | "restricted" => Some(action),
            _ => None,
        });
    let (registry_url, client) = crate::make_registry_client(&current_dir, args.registry)?;
    let value = match action {
        "public" | "restricted" => {
            client
                .package_access(Some(&registry_url), &package, Some(action), args.otp.as_deref())
                .await?
        }
        "get" | "set"
            if args.args.get(1).is_some_and(|value| {
                value == "status"
                    || value.starts_with("status=")
                    || value == "public"
                    || value == "restricted"
            }) =>
        {
            client
                .package_access(Some(&registry_url), &package, level, args.otp.as_deref())
                .await?
        }
        "list" if args.args.get(1).is_some_and(|value| value == "collaborators") => {
            client.package_owners(Some(&registry_url), &package).await?
        }
        _ => {
            return Err(anyhow::anyhow!(
                "npm error code ENOTSUP\nnpm error this access operation is not supported by the configured registry"
            ))
        }
    };
    if args.json || level.is_none() {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if let Some(level) = level {
        println!("{level}");
    }
    Ok(())
}
