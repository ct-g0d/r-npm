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
        println!("(*) {package}");
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
        println!("( ) {package}");
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
    let packages: Vec<String> = if let Some(arr) = value.as_array() {
        arr.iter()
            .filter_map(|v| {
                if let Some(s) = v.as_str() {
                    Some(s.to_string())
                } else {
                    v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())
                }
            })
            .collect()
    } else if let Some(rows) = value.get("rows").and_then(|r| r.as_array()) {
        rows.iter()
            .filter_map(|r| {
                if let Some(s) = r.get("value").and_then(|v| v.as_str()) {
                    Some(s.to_string())
                } else if let Some(s) = r.as_str() {
                    Some(s.to_string())
                } else {
                    None
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&packages)?);
    } else {
        for package in &packages {
            println!("{package}");
        }
    }
    Ok(())
}
