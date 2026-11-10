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
            } else if let Some(maintainers) = value.get("maintainers").and_then(|v| v.as_array()) {
                if maintainers.is_empty() {
                    println!("no admin found");
                } else {
                    for m in maintainers {
                        let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        if let Some(email) = m.get("email").and_then(|v| v.as_str()) {
                            println!("{name} <{email}>");
                        } else {
                            println!("{name}");
                        }
                    }
                }
            } else if let Some(arr) = value.as_array() {
                if arr.is_empty() {
                    println!("no admin found");
                } else {
                    for m in arr {
                        if let Some(obj) = m.as_object() {
                            let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            if let Some(email) = obj.get("email").and_then(|v| v.as_str()) {
                                println!("{name} <{email}>");
                            } else {
                                println!("{name}");
                            }
                        } else if let Some(s) = m.as_str() {
                            println!("{s}");
                        }
                    }
                }
            } else if let Some(map) = value.as_object() {
                if map.is_empty() {
                    println!("no admin found");
                } else {
                    for (name, role_val) in map {
                        if let Some(email) = role_val.get("email").and_then(|v| v.as_str()) {
                            println!("{name} <{email}>");
                        } else if let Some(s) = role_val.as_str() {
                            println!("{name} <{s}>");
                        } else {
                            println!("{name}");
                        }
                    }
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
