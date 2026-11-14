use anyhow::Result;
use reqwest::Url;
use std::path::{Path, PathBuf};

pub(crate) async fn run(
    current_dir: PathBuf,
    action: crate::OwnerAction,
    registry: Option<String>,
    json: bool,
    otp: Option<String>,
) -> Result<()> {
    let (registry_url, client) = crate::make_registry_client(&current_dir, registry.clone())?;
    let action = match action {
        crate::OwnerAction::Ls { package } => crate::OwnerAction::Ls { package: Some(get_pkg(&current_dir, package)?) },
        crate::OwnerAction::Add { user, package } => crate::OwnerAction::Add { user, package: Some(get_pkg(&current_dir, package)?) },
        crate::OwnerAction::Rm { user, package } => crate::OwnerAction::Rm { user, package: Some(get_pkg(&current_dir, package)?) },
    };
    match action {
        crate::OwnerAction::Ls { package: Some(package) } => {
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
        crate::OwnerAction::Add { user, package: Some(package) } => {
            change_owners(&current_dir, registry.as_deref(), &user, &package, true, otp).await?;
        }
        crate::OwnerAction::Rm { user, package: Some(package) } => {
            change_owners(&current_dir, registry.as_deref(), &user, &package, false, otp).await?;
        }
        _ => unreachable!("package resolved above"),
    }
    Ok(())
}

const USAGE: &str = "Manage package owners\n\nUsage:\nnpm owner add <user> <package-spec>\nnpm owner rm <user> <package-spec>\nnpm owner ls <package-spec>\n\nOptions:\n[--registry <registry>] [--otp <otp>]\n[-w|--workspace <workspace-name> [-w|--workspace <workspace-name> ...]]\n[--workspaces]\n\n  --registry\n    The base URL of the npm registry.\n\n  --otp\n    This is a one-time password from a two-factor authenticator.  It's needed\n\n  -w|--workspace\n    Enable running a command in the context of the configured workspaces of the\n\n  --workspaces\n    Set to true to run the command in the context of **all** configured\n\n\nalias: author\n\nRun \"npm help owner\" for more info";

/// npm's owner getPkg: an omitted spec falls back to the local package name.
fn get_pkg(current_dir: &Path, package: Option<String>) -> Result<String> {
    if let Some(package) = package {
        return Ok(package);
    }
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    if config.get_bool("global").unwrap_or(false) {
        return Err(super::stage::usage_error(None, USAGE));
    }
    std::fs::read_to_string(current_dir.join("package.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}')).ok())
        .and_then(|v| v["name"].as_str().filter(|n| !n.is_empty()).map(str::to_string))
        .ok_or_else(|| super::stage::usage_error(None, USAGE))
}

/// The message npm-registry-fetch gives a failed response; EOWNERMUTATE wraps it.
fn fetch_error_message(method: &str, url: &Url, status: reqwest::StatusCode, www: Option<&str>, body: &str) -> String {
    let has = |scheme: &str| www.is_some_and(|w| w.split(',').any(|s| s.trim().eq_ignore_ascii_case(scheme)));
    if status != reqwest::StatusCode::UNAUTHORIZED {
        return crate::http_errors::general_message(method, url.as_str(), status, body);
    }
    if has("ipaddress") {
        "Login is not allowed from your IP address".to_string()
    } else if has("otp") || (www.is_none() && body.contains("one-time pass")) {
        "OTP required for authentication".to_string()
    } else if let Some(www) = www {
        format!("Unable to authenticate, need: {www}")
    } else {
        crate::http_errors::general_message(method, url.as_str(), status, body)
    }
}

async fn get_json(client: &crate::commands::client_helper::CommandClient, url: &Url) -> Result<std::result::Result<serde_json::Value, (reqwest::StatusCode, Option<String>, String)>> {
    let response = client.request(reqwest::Method::GET, url.clone(), None).header("accept", "application/json").send().await?;
    let status = response.status();
    let www = response.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).map(str::to_string);
    let text = response.text().await?;
    if !status.is_success() {
        return Ok(Err((status, www, text)));
    }
    Ok(Ok(crate::commands::client_helper::parse_json_response(&text, url)?))
}

/// `npm owner add|rm`, ported from npm's lib/commands/owner.js changeOwners:
/// read the user document, then PUT the packument's maintainers at its revision.
async fn change_owners(current_dir: &Path, registry: Option<&str>, user: &str, package: &str, add: bool, otp: Option<String>) -> Result<()> {
    use crate::commands::client_helper::{format_http_error_with_auth, CommandClient};
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    let (name, pkgid) = match crate::split_package_version(package) {
        Ok((name, _)) => (name.to_string(), package.to_string()),
        Err(_) => (package.to_string(), format!("{package}@*")),
    };
    let base = match registry {
        Some(r) => Url::parse(r)?,
        None => config.npmrc.registry_for_package(&name).clone(),
    };
    let client = CommandClient::new(current_dir, Some(base.as_str()))?;
    let fail = |method: &str, url: &Url, (status, www, body): (reqwest::StatusCode, Option<String>, String)| {
        if status.as_u16() == 404 {
            let message = crate::http_errors::general_message(method, url.as_str(), status, &body);
            anyhow::anyhow!(crate::http_errors::e404_block(&message, Some(&pkgid)))
        } else {
            format_http_error_with_auth(method, url, status, www.as_deref(), &body)
        }
    };

    let user_url = base.join(&format!("-/user/org.couchdb.user:{}", crate::http_errors::encode_uri_component(user)))?;
    let u = match get_json(&client, &user_url).await? {
        Ok(u) => u,
        Err(e) => {
            let err = fail("GET", &user_url, e);
            anyhow::bail!("npm error owner mutate Error getting user data for {user}\n{err}");
        }
    };
    let u = serde_json::json!({ "name": u["name"], "email": u["email"] });

    let pkg_url = base.join(&rnpm_config::encode_package_name(&name))?;
    let data = get_json(&client, &pkg_url).await?.map_err(|e| fail("GET", &pkg_url, e))?;
    let owners = data["maintainers"].as_array().cloned().unwrap_or_default();
    let maintainers: Vec<serde_json::Value> = if add {
        if owners.iter().any(|o| o["name"] == u["name"]) {
            return Ok(());
        }
        owners.iter().cloned().chain(std::iter::once(u)).collect()
    } else {
        let kept: Vec<_> = owners.iter().filter(|o| o["name"] != u["name"]).cloned().collect();
        if kept.len() == owners.len() {
            return Ok(());
        }
        if kept.is_empty() {
            anyhow::bail!("npm error code EOWNERRM\nnpm error Cannot remove all owners of a package. Add someone else first.");
        }
        kept
    };

    let rev = data["_rev"].as_str().unwrap_or_default();
    let put_url = base.join(&format!(
        "{}/-rev/{}",
        rnpm_config::encode_package_name(&name),
        crate::http_errors::encode_uri_component(rev)
    ))?;
    let body = serde_json::json!({ "_id": data["_id"], "_rev": data["_rev"], "maintainers": maintainers });
    let mut otp = otp;
    for attempt in 0..2 {
        let response = client.request(reqwest::Method::PUT, put_url.clone(), otp.as_deref()).json(&body).send().await?;
        let status = response.status();
        let www = response.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).map(str::to_string);
        let text = response.text().await?;
        if status.is_success() {
            println!("{} {user} ({name})", if add { "+" } else { "-" });
            return Ok(());
        }
        let err = format_http_error_with_auth("PUT", &put_url, status, www.as_deref(), &text);
        if attempt == 0 {
            if let Some(code) = crate::http_errors::retry_otp(current_dir, &err).await? {
                otp = Some(code);
                continue;
            }
        }
        let message = fetch_error_message("PUT", &put_url, status, www.as_deref(), &text);
        anyhow::bail!("npm error code EOWNERMUTATE\nnpm error Failed to update package: {}", serde_json::to_string(&message)?);
    }
    unreachable!()
}
