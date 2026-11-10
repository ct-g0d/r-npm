use anyhow::Result;
use std::path::PathBuf;

pub(crate) async fn run_star(
    packages: Vec<String>,
    registry: Option<String>,
    otp: Option<String>,
    current_dir: PathBuf,
) -> Result<()> {
    let (registry_url, client) = crate::make_registry_client(&current_dir, registry)?;
    if packages.is_empty() {
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\nnpm error star requires at least one package"
        ));
    }
    for package in packages {
        client
            .star_package(Some(&registry_url), &package, otp.as_deref())
            .await?;
        println!("starred {package}");
    }
    Ok(())
}

pub(crate) async fn run_unstar(
    packages: Vec<String>,
    registry: Option<String>,
    otp: Option<String>,
    current_dir: PathBuf,
) -> Result<()> {
    let (registry_url, client) = crate::make_registry_client(&current_dir, registry)?;
    if packages.is_empty() {
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\nnpm error unstar requires at least one package"
        ));
    }
    for package in packages {
        client
            .unstar_package(Some(&registry_url), &package, otp.as_deref())
            .await?;
        println!("unstarred {package}");
    }
    Ok(())
}

pub(crate) async fn run_stars(
    user: Option<String>,
    json: bool,
    registry: Option<String>,
    current_dir: PathBuf,
) -> Result<()> {
    let (registry_url, client) = crate::make_registry_client(&current_dir, registry)?;
    let value = client
        .starred_packages(Some(&registry_url), user.as_deref())
        .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if let Some(packages) = value.as_array() {
        for package in packages {
            if let Some(name) = package.as_str() {
                println!("{name}");
            } else if let Some(name) = package.get("name").and_then(|v| v.as_str()) {
                println!("{name}");
            }
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}
