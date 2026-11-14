use anyhow::Result;
use reqwest::Url;
use std::path::PathBuf;

fn generate_token_ids(tokens: &mut [serde_json::Value], min_length: usize) {
    let keys: Vec<String> = tokens
        .iter()
        .map(|t| {
            t.get("key")
                .and_then(|v| v.as_str())
                .or_else(|| t.get("id").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string()
        })
        .collect();

    for i in 0..tokens.len() {
        let key = &keys[i];
        let mut id = key.clone();
        for len in min_length..key.len() {
            let prefix = &key[..len];
            let has_other_match = keys
                .iter()
                .enumerate()
                .any(|(j, other)| j != i && other.starts_with(prefix));
            if !has_other_match {
                id = prefix.to_string();
                break;
            }
        }
        if let Some(obj) = tokens[i].as_object_mut() {
            obj.insert("id".to_string(), serde_json::Value::String(id));
        }
    }
}

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
        basic_auths: config.npmrc.basic_auths(),
        ..Default::default()
    };
    if let Some(tok) = token {
        client_config.auth_token = Some(tok.to_string());
    }

    let client = rnpm_registry::RegistryClient::with_config(client_config)?;
    match action.unwrap_or(crate::TokenAction::List) {
        crate::TokenAction::List => {
            let val = client.token_list(Some(&registry_url)).await?;
            let mut tokens: Vec<serde_json::Value> = if let Some(objs) = val.get("objects").and_then(|o| o.as_array()) {
                objs.clone()
            } else if let Some(arr) = val.as_array() {
                arr.clone()
            } else {
                Vec::new()
            };

            generate_token_ids(&mut tokens, 6);

            if json {
                println!("{}", serde_json::to_string_pretty(&tokens)?);
            } else {
                for t in &tokens {
                    let tok = t.get("token").and_then(|v| v.as_str()).unwrap_or("");
                    let id = t.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let created = t.get("created").and_then(|v| v.as_str()).unwrap_or("");
                    let created_date = if created.len() >= 10 { &created[..10] } else { created };
                    println!("Token {tok}… with id {id} name {name} created {created_date}");
                    if let Some(cidr) = t.get("cidr_whitelist").and_then(|v| v.as_array()) {
                        let cidr_strs: Vec<_> = cidr.iter().filter_map(|c| c.as_str()).collect();
                        if !cidr_strs.is_empty() {
                            println!("with IP whitelist: {}", cidr_strs.join(","));
                        }
                    }
                    println!();
                }
            }
        }
        crate::TokenAction::Revoke { token_id } => {
            let val = client.token_list(Some(&registry_url)).await.unwrap_or_default();
            let tokens: Vec<serde_json::Value> = if let Some(objs) = val.get("objects").and_then(|o| o.as_array()) {
                objs.clone()
            } else if let Some(arr) = val.as_array() {
                arr.clone()
            } else {
                Vec::new()
            };

            let key_to_remove = tokens
                .iter()
                .find_map(|t| {
                    let k = t.get("key").and_then(|v| v.as_str()).unwrap_or("");
                    let tok = t.get("token").and_then(|v| v.as_str()).unwrap_or("");
                    if k.starts_with(&token_id) || tok.starts_with(&token_id) {
                        Some(k.to_string())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("npm error Unknown token id or value \"{token_id}\"."))?;

            let command_client = super::client_helper::CommandClient::new(&current_dir, Some(registry_url.as_str()))?;
            let url = registry_url.join(&format!("-/npm/v1/tokens/token/{key_to_remove}"))?;
            command_client.send_text(&current_dir, reqwest::Method::DELETE, url, None, None).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&vec![key_to_remove])?);
            } else {
                println!("Removed 1 token");
            }
        }
    }

    Ok(())
}
