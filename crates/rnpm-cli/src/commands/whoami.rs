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

    let token = config.npmrc.get_auth_token(&registry_url);
    if token.is_none() {
        if json {
            #[derive(serde::Serialize)]
            struct AuthError<'a> {
                code: &'a str,
                summary: &'a str,
                detail: &'a str,
            }
            #[derive(serde::Serialize)]
            struct ErrorOutput<'a> {
                error: AuthError<'a>,
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&ErrorOutput {
                    error: AuthError {
                        code: "ENEEDAUTH",
                        summary: "This command requires you to be logged in.",
                        detail: "You need to authorize this machine using `npm adduser`",
                    }
                })?
            );
        }
        return Err(anyhow::anyhow!(
            "npm error code ENEEDAUTH\nnpm error need auth This command requires you to be logged in.\nnpm error need auth You need to authorize this machine using `npm adduser`"
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
    let username = client.whoami(Some(&registry_url)).await?;

    if json {
        println!("{}", serde_json::to_string(&username)?);
    } else {
        println!("{username}");
    }

    Ok(())
}
