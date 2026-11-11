use crate::commands::client_helper::{
    format_http_error, parse_json_response, url_encode, CommandClient,
};
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

    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/org/{}/team", url_encode(&scope)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let mut payload_map = serde_json::Map::new();
    payload_map.insert("name".to_string(), serde_json::Value::String(team.clone()));
    if let Some(desc) = &args.description {
        payload_map.insert(
            "description".to_string(),
            serde_json::Value::String(desc.clone()),
        );
    }
    let payload = serde_json::Value::Object(payload_map);

    let req = client
        .request(reqwest::Method::PUT, target.clone(), args.otp.as_deref())
        .header("content-type", "application/json")
        .json(&payload);

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
    } else if !client.silent {
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

    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!(
        "{base}/-/team/{}/{}",
        url_encode(&scope),
        url_encode(&team)
    ))
    .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let req = client.request(
        reqwest::Method::DELETE,
        target.clone(),
        args.otp.as_deref(),
    );
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
    } else if !client.silent {
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

    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!(
        "{base}/-/team/{}/{}/user",
        url_encode(&scope),
        url_encode(&team)
    ))
    .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let payload = serde_json::json!({
        "user": user,
    });

    let req = client
        .request(reqwest::Method::PUT, target.clone(), args.otp.as_deref())
        .header("content-type", "application/json")
        .json(&payload);

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
    } else if !client.silent {
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

    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!(
        "{base}/-/team/{}/{}/user",
        url_encode(&scope),
        url_encode(&team)
    ))
    .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let payload = serde_json::json!({
        "user": user,
    });

    let req = client
        .request(reqwest::Method::DELETE, target.clone(), args.otp.as_deref())
        .header("content-type", "application/json")
        .json(&payload);

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
    } else if !client.silent {
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

    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');

    if entity.contains(':') {
        let (scope, team) = split_entity(entity)
            .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error team ls <scope>|<scope:team>"))?;
        let target = Url::parse(&format!(
            "{base}/-/team/{}/{}/user?format=cli",
            url_encode(&scope),
            url_encode(&team)
        ))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

        let req = client.request(reqwest::Method::GET, target.clone(), args.otp.as_deref());
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format_http_error("GET", &target, status, &body));
        }

        let body = resp.text().await.unwrap_or_default();
        let json_val = parse_json_response(&body, &target)?;
        let arr = json_val.as_array().ok_or_else(|| {
            anyhow::anyhow!(
                "npm error code FETCH_ERROR\nnpm error errno FETCH_ERROR\nnpm error invalid json response body at {target} reason: expected json array"
            )
        })?;
        let mut users: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        users.sort();

        if args.json {
            println!("{}", serde_json::to_string_pretty(&users)?);
        } else if args.parseable {
            for user in &users {
                println!("{user}");
            }
        } else if !client.silent {
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

        let req = client.request(reqwest::Method::GET, target.clone(), args.otp.as_deref());
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format_http_error("GET", &target, status, &body));
        }

        let body = resp.text().await.unwrap_or_default();
        let json_val = parse_json_response(&body, &target)?;
        let arr = json_val.as_array().ok_or_else(|| {
            anyhow::anyhow!(
                "npm error code FETCH_ERROR\nnpm error errno FETCH_ERROR\nnpm error invalid json response body at {target} reason: expected json array"
            )
        })?;
        let mut teams: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        teams.sort();

        if args.json {
            println!("{}", serde_json::to_string_pretty(&teams)?);
        } else if args.parseable {
            for team in &teams {
                println!("{team}");
            }
        } else if !client.silent {
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
