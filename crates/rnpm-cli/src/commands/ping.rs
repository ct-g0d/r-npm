use anyhow::Result;
use reqwest::Url;
use std::path::PathBuf;

pub(crate) async fn run(
    registry: Option<String>,
    json: bool,
    current_dir: PathBuf,
) -> Result<()> {
    let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
    let registry_url = if let Some(ref reg_str) = registry {
        Url::parse(reg_str).map_err(|e| {
            anyhow::anyhow!(
                "npm error code EINVALIDURL\nnpm error Invalid registry URL '{reg_str}': {e}"
            )
        })?
    } else {
        config.npmrc.registry.clone()
    };

    let mut client_config = rnpm_registry::RegistryClientConfig {
        default_registry: registry_url.clone(),
        scoped_registries: config.npmrc.scoped_registries.clone(),
        auth_tokens: config.npmrc.auth_tokens.clone(),
        ..Default::default()
    };
    if let Some(tok) = config.npmrc.get_auth_token(&registry_url) {
        client_config.auth_token = Some(tok.to_string());
    }

    let client = rnpm_registry::RegistryClient::with_config(client_config)?;
    eprintln!("npm notice PING {registry_url}");
    let duration = client.ping(Some(&registry_url)).await?;
    eprintln!("npm notice PONG {}ms", duration.as_millis());

    if json {
        let json_out = serde_json::json!({
            "registry": registry_url.to_string(),
            "time": duration.as_millis(),
            "details": {}
        });
        println!("{}", serde_json::to_string_pretty(&json_out)?);
    }

    Ok(())
}
