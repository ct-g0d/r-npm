use anyhow::Result;
use reqwest::Url;
use std::path::Path;

pub(crate) struct TeamArgs {
    pub action: Option<String>,
    pub args: Vec<String>,
    pub otp: Option<String>,
    pub description: Option<String>,
    pub registry: Option<String>,
    pub json: bool,
    pub parseable: bool,
}

fn resolve_registry_and_token(
    current_dir: &Path,
    registry: Option<&str>,
) -> Result<(Url, String)> {
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    let registry_url = if let Some(reg_str) = registry {
        Url::parse(reg_str).map_err(|e| {
            anyhow::anyhow!(
                "npm error code EINVALIDURL\nnpm error Invalid registry URL '{reg_str}': {e}"
            )
        })?
    } else {
        config.npmrc.registry.clone()
    };

    let token = config.npmrc.get_auth_token(&registry_url);
    let token = match token {
        Some(t) => t.to_string(),
        None => {
            return Err(anyhow::anyhow!(
                "npm error code ENEEDAUTH\nnpm error This command requires you to be logged in to {registry_url}\nnpm error You need to authorize this machine using `npm adduser` or `npm login`"
            ));
        }
    };

    Ok((registry_url, token))
}

fn format_http_error(
    method: &str,
    target_url: &Url,
    status: reqwest::StatusCode,
    body: &str,
) -> anyhow::Error {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    let msg = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("error"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            if body.trim().is_empty() {
                reason.to_ascii_lowercase()
            } else {
                body.trim().to_string()
            }
        });

    anyhow::anyhow!("npm error code E{code}\nnpm error {code} {reason} - {method} {target_url} - {msg}")
}

fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", b));
            }
        }
    }
    encoded
}

fn split_entity(raw: &str) -> Option<(String, String)> {
    let stripped = raw.trim_start_matches('@');
    let (scope, team) = stripped.split_once(':')?;
    if scope.is_empty() || team.is_empty() {
        None
    } else {
        Some((scope.to_string(), team.to_string()))
    }
}

pub(crate) async fn run(args: TeamArgs, current_dir: &Path) -> Result<()> {
    let action_str = match &args.action {
        Some(a) => a.as_str(),
        None => {
            return Err(anyhow::anyhow!(
                "npm error code EUSAGE\nnpm error\nnpm error Manage organization teams and team memberships\nnpm error\nnpm error Usage:\nnpm error npm team create <scope:team> [--otp <otpcode>]\nnpm error npm team destroy <scope:team> [--otp <otpcode>]\nnpm error npm team add <scope:team> <user> [--otp <otpcode>]\nnpm error npm team rm <scope:team> <user> [--otp <otpcode>]\nnpm error npm team ls <scope>|<scope:team>\nnpm error\nnpm error Options:\nnpm error [--registry <registry>] [--otp <otp>] [-p|--parseable] [--json]\nnpm error\nnpm error Run \"npm help team\" for more info"
            ));
        }
    };

    match action_str {
        "create" => run_create(&args, current_dir).await,
        "destroy" => run_destroy(&args, current_dir).await,
        "add" => run_add(&args, current_dir).await,
        "rm" | "remove" => run_rm(&args, current_dir).await,
        "ls" => run_ls(&args, current_dir).await,
        _ => Err(anyhow::anyhow!(
            "npm error code EUSAGE\nnpm error\nnpm error Manage organization teams and team memberships\nnpm error\nnpm error Usage:\nnpm error npm team create <scope:team> [--otp <otpcode>]\nnpm error npm team destroy <scope:team> [--otp <otpcode>]\nnpm error npm team add <scope:team> <user> [--otp <otpcode>]\nnpm error npm team rm <scope:team> <user> [--otp <otpcode>]\nnpm error npm team ls <scope>|<scope:team>\nnpm error\nnpm error Options:\nnpm error [--registry <registry>] [--otp <otp>] [-p|--parseable] [--json]\nnpm error\nnpm error Run \"npm help team\" for more info"
        )),
    }
}

async fn run_create(args: &TeamArgs, current_dir: &Path) -> Result<()> {
    let raw_entity = args
        .args
        .first()
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team create <scope:team>"))?;
    let (scope, team) = split_entity(raw_entity)
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team create <scope:team>"))?;
    let entity = format!("{scope}:{team}");

    let (registry_url, token) = resolve_registry_and_token(current_dir, args.registry.as_deref())?;
    let base = registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/org/{}/team", url_encode(&scope)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let payload = serde_json::json!({
        "name": team,
        "description": args.description.as_deref(),
    });

    let client = reqwest::Client::builder().build()?;
    let mut req = client
        .put(target.clone())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .json(&payload);
    if let Some(otp) = &args.otp {
        req = req.header("npm-otp", otp);
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format_http_error("PUT", &target, status, &body));
    }

    if args.json {
        let out = serde_json::json!({
            "created": true,
            "team": entity,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if args.parseable {
        println!("{entity}\tcreated");
    } else {
        println!("+@{entity}");
    }

    Ok(())
}

async fn run_destroy(args: &TeamArgs, current_dir: &Path) -> Result<()> {
    let raw_entity = args
        .args
        .first()
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team destroy <scope:team>"))?;
    let (scope, team) = split_entity(raw_entity)
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team destroy <scope:team>"))?;
    let entity = format!("{scope}:{team}");

    let (registry_url, token) = resolve_registry_and_token(current_dir, args.registry.as_deref())?;
    let base = registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/team/{}/{}", url_encode(&scope), url_encode(&team)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let client = reqwest::Client::builder().build()?;
    let mut req = client
        .delete(target.clone())
        .header("authorization", format!("Bearer {token}"));
    if let Some(otp) = &args.otp {
        req = req.header("npm-otp", otp);
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format_http_error("DELETE", &target, status, &body));
    }

    if args.json {
        let out = serde_json::json!({
            "deleted": true,
            "team": entity,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if args.parseable {
        println!("{entity}\tdeleted");
    } else {
        println!("-@{entity}");
    }

    Ok(())
}

async fn run_add(args: &TeamArgs, current_dir: &Path) -> Result<()> {
    let raw_entity = args
        .args
        .first()
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team add <scope:team> <user>"))?;
    let (scope, team) = split_entity(raw_entity)
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team add <scope:team> <user>"))?;
    let user = args
        .args
        .get(1)
        .map(|u| u.trim_start_matches('@'))
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team add <scope:team> <user>"))?;
    let entity = format!("{scope}:{team}");

    let (registry_url, token) = resolve_registry_and_token(current_dir, args.registry.as_deref())?;
    let base = registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/team/{}/{}/user", url_encode(&scope), url_encode(&team)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let payload = serde_json::json!({
        "user": user,
    });

    let client = reqwest::Client::builder().build()?;
    let mut req = client
        .put(target.clone())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .json(&payload);
    if let Some(otp) = &args.otp {
        req = req.header("npm-otp", otp);
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format_http_error("PUT", &target, status, &body));
    }

    if args.json {
        let out = serde_json::json!({
            "added": true,
            "team": entity,
            "user": user,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if args.parseable {
        println!("{user}\t{entity}\tadded");
    } else {
        println!("{user} added to @{entity}");
    }

    Ok(())
}

async fn run_rm(args: &TeamArgs, current_dir: &Path) -> Result<()> {
    let raw_entity = args
        .args
        .first()
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team rm <scope:team> <user>"))?;
    let (scope, team) = split_entity(raw_entity)
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team rm <scope:team> <user>"))?;
    let user = args
        .args
        .get(1)
        .map(|u| u.trim_start_matches('@'))
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team rm <scope:team> <user>"))?;
    let entity = format!("{scope}:{team}");

    let (registry_url, token) = resolve_registry_and_token(current_dir, args.registry.as_deref())?;
    let base = registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/team/{}/{}/user", url_encode(&scope), url_encode(&team)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let payload = serde_json::json!({
        "user": user,
    });

    let client = reqwest::Client::builder().build()?;
    let mut req = client
        .delete(target.clone())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .json(&payload);
    if let Some(otp) = &args.otp {
        req = req.header("npm-otp", otp);
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format_http_error("DELETE", &target, status, &body));
    }

    if args.json {
        let out = serde_json::json!({
            "removed": true,
            "team": entity,
            "user": user,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if args.parseable {
        println!("{user}\t{entity}\tremoved");
    } else {
        println!("{user} removed from @{entity}");
    }

    Ok(())
}

async fn run_ls(args: &TeamArgs, current_dir: &Path) -> Result<()> {
    let raw_entity = args
        .args
        .first()
        .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team ls <scope>|<scope:team>"))?;
    let entity = raw_entity.trim_start_matches('@');

    let (registry_url, token) = resolve_registry_and_token(current_dir, args.registry.as_deref())?;
    let base = registry_url.as_str().trim_end_matches('/');
    let client = reqwest::Client::builder().build()?;

    if entity.contains(':') {
        let (scope, team) = split_entity(entity)
            .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team ls <scope>|<scope:team>"))?;
        let target = Url::parse(&format!(
            "{base}/-/team/{}/{}/user?format=cli",
            url_encode(&scope),
            url_encode(&team)
        ))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

        let mut req = client
            .get(target.clone())
            .header("authorization", format!("Bearer {token}"));
        if let Some(otp) = &args.otp {
            req = req.header("npm-otp", otp);
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format_http_error("GET", &target, status, &body));
        }

        let mut users: Vec<String> = resp.json().await.unwrap_or_default();
        users.sort();

        if args.json {
            println!("{}", serde_json::to_string_pretty(&users)?);
        } else if args.parseable {
            for user in &users {
                println!("{user}");
            }
        } else {
            let plural = if users.len() == 1 { "" } else { "s" };
            let more = if users.is_empty() { "" } else { ":" };
            println!("@{scope}:{team} has {} user{plural}{more}", users.len());
            for user in &users {
                println!("{user}");
            }
        }
    } else {
        let scope = entity;
        let target = Url::parse(&format!("{base}/-/org/{}/team?format=cli", url_encode(scope)))
            .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

        let mut req = client
            .get(target.clone())
            .header("authorization", format!("Bearer {token}"));
        if let Some(otp) = &args.otp {
            req = req.header("npm-otp", otp);
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format_http_error("GET", &target, status, &body));
        }

        let mut teams: Vec<String> = resp.json().await.unwrap_or_default();
        teams.sort();

        if args.json {
            println!("{}", serde_json::to_string_pretty(&teams)?);
        } else if args.parseable {
            for team in &teams {
                println!("{team}");
            }
        } else {
            let plural = if teams.len() == 1 { "" } else { "s" };
            let more = if teams.is_empty() { "" } else { ":" };
            println!("@{scope} has {} team{plural}{more}", teams.len());
            for team in &teams {
                println!("@{team}");
            }
        }
    }

    Ok(())
}
