use anyhow::Result;
use std::path::PathBuf;

pub(crate) async fn run(
    current_dir: PathBuf,
    action: crate::OwnerAction,
    registry: Option<String>,
    json: bool,
    otp: Option<String>,
) -> Result<()> {
    let (registry_url, client) = crate::make_registry_client(&current_dir, registry)?;
    match action {
        crate::OwnerAction::Ls { package } => {
            let value = client.package_owners(Some(&registry_url), &package).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(map) = value.as_object() {
                for (name, role) in map {
                    println!("{name}\t{}", role.as_str().unwrap_or("owner"));
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
        }
        crate::OwnerAction::Add { user, package } => {
            client
                .package_owner_add(Some(&registry_url), &package, &user, otp.as_deref())
                .await?;
            println!("added {user} to {package}");
        }
        crate::OwnerAction::Rm { user, package } => {
            client
                .package_owner_remove(Some(&registry_url), &package, &user, otp.as_deref())
                .await?;
            println!("removed {user} from {package}");
        }
    }
    Ok(())
}
