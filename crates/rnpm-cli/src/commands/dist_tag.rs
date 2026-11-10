use anyhow::Result;
use std::path::PathBuf;

pub(crate) async fn run(
    current_dir: PathBuf,
    action: crate::DistTagAction,
    registry: Option<String>,
    json: bool,
    otp: Option<String>,
) -> Result<()> {
    let (registry_url, client) = crate::make_registry_client(&current_dir, registry)?;
    match action {
        crate::DistTagAction::Ls { package } => {
            let package = match package {
                Some(p) => p,
                None => crate::package_name_from_manifest(&current_dir)?,
            };
            let value = client.dist_tags(Some(&registry_url), &package).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(tags) = value.as_object() {
                for (tag, version) in tags {
                    let v_str = version.as_str().map(|s| s.to_string()).unwrap_or_else(|| version.to_string());
                    println!("{tag}: {v_str}");
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
        }
        crate::DistTagAction::Add { package, tag } => {
            let (name, version) = crate::split_package_version(&package)?;
            let tag = tag.unwrap_or_else(|| "latest".to_string());
            client
                .dist_tag_add(Some(&registry_url), name, &tag, version, otp.as_deref())
                .await?;
            println!("+ {name}@{version} ({tag})");
        }
        crate::DistTagAction::Rm { package, tag } => {
            let name = crate::package_name_from_spec(&package);
            client
                .dist_tag_remove(Some(&registry_url), name, &tag, otp.as_deref())
                .await?;
            println!("- {name} {tag}");
        }
    }
    Ok(())
}
