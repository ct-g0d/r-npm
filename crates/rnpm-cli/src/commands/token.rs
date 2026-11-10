use anyhow::Result;
use reqwest::Url;
use std::path::PathBuf;

pub(crate) async fn run(
    action: Option<crate::TokenAction>,
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

    let token = config.npmrc.get_auth_token(&registry_url);
    if token.is_none() {
        return Err(anyhow::anyhow!(
            "npm error code ENEEDAUTH\nnpm error This command requires you to be logged in to {registry_url}\nnpm error You need to authorize this machine using `npm adduser` or `npm login`"
        ));
    }

    let mut client_config = rnpm_registry::RegistryClientConfig {
        default_registry: registry_url.clone(),
        scoped_registries: config.npmrc.scoped_registries.clone(),
        auth_tokens: config.npmrc.auth_tokens.clone(),
        ..Default::default()
    };
    if let Some(tok) = token {
        client_config.auth_token = Some(tok.to_string());
    }

    let client = rnpm_registry::RegistryClient::with_config(client_config)?;

    match action.unwrap_or(crate::TokenAction::List) {
        crate::TokenAction::List => match client.token_list(Some(&registry_url)).await {
            Ok(val) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else if let Some(tokens) = val.get("objects").and_then(|o| o.as_array()) {
                    println!("id\ttoken\tcreated\tread-only\tCIDR whitelist");
                    for t in tokens {
                        let id = t.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let tok = t.get("token").and_then(|v| v.as_str()).unwrap_or("");
                        let created = t.get("created").and_then(|v| v.as_str()).unwrap_or("");
                        let ro = t.get("readonly").and_then(|v| v.as_bool()).unwrap_or(false);
                        println!("{id}\t{tok}…\t{created}\t{ro}");
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                }
            }
            Err(e) => {
                if json {
                    println!("{}", serde_json::json!({ "error": e.to_string() }));
                } else {
                    eprintln!("npm notice Token management API not available or returned: {e}");
                    eprintln!("npm notice Please manage security tokens via the web dashboard at {registry_url}");
                }
            }
        },
        crate::TokenAction::Revoke { token_id } => {
            client.token_revoke(Some(&registry_url), &token_id).await?;
            println!("rnpm: successfully revoked token {token_id}");
        }
    }

    Ok(())
}
