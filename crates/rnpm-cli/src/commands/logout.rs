use anyhow::Result;
use reqwest::Url;
use std::path::Path;

pub(crate) async fn run(
    current_dir: &Path,
    registry: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    let registry_url = if let Some(ref reg_str) = registry {
        Url::parse(reg_str).map_err(|e| {
            anyhow::anyhow!(
                "npm error code EINVALIDURL\nnpm error Invalid registry URL '{reg_str}': {e}"
            )
        })?
    } else if let Some(ref sc) = scope {
        let sc_norm = if sc.starts_with('@') {
            sc.clone()
        } else {
            format!("@{sc}")
        };
        config
            .npmrc
            .scoped_registries
            .get(&sc_norm.to_ascii_lowercase())
            .cloned()
            .unwrap_or_else(|| config.npmrc.registry.clone())
    } else {
        config.npmrc.registry.clone()
    };

    let token = config.npmrc.get_auth_token(&registry_url);
    let token = match token {
        Some(t) => t.to_string(),
        None => {
            return Err(anyhow::anyhow!(
                "npm error code ENEEDAUTH\nnpm error need auth not logged in to {registry_url}, so can't log out"
            ));
        }
    };

    // Revoke token on registry via DELETE /-/user/token/{token}
    let target = Url::parse(&format!(
        "{}/-/user/token/{}",
        registry_url.as_str().trim_end_matches('/'),
        token
    ))
    .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let client = reqwest::Client::builder().build()?;
    let resp = client
        .delete(target.clone())
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "npm error code E{}\nnpm error {} {} - DELETE {} - {}",
            status.as_u16(),
            status.as_u16(),
            status.canonical_reason().unwrap_or("Error"),
            target,
            body
        ));
    }

    let auth_key = auth_key_for_registry(&registry_url);
    let user_npmrc = rnpm_config::get_default_user_npmrc();
    if user_npmrc.is_file() {
        rnpm_config::delete_config_value_from_file(&user_npmrc, &auth_key)?;
        if std::fs::read_to_string(&user_npmrc)?.trim().is_empty() { std::fs::remove_file(&user_npmrc)?; }
    }
    let local_npmrc = current_dir.join(".npmrc");
    if local_npmrc.is_file() {
        let _ = rnpm_config::delete_config_value_from_file(&local_npmrc, &auth_key);
    }

    Ok(())
}

fn auth_key_for_registry(registry: &Url) -> String {
    let host = registry.host_str().unwrap_or_default();
    let port = registry.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = if registry.path().is_empty() {
        "/".to_string()
    } else {
        format!("{}/", registry.path().trim_end_matches('/'))
    };
    format!("//{host}{port}{path}:_authToken")
}
