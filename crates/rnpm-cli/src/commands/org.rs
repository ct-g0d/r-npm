use anyhow::Result;
use reqwest::Url;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) struct OrgArgs {
    pub action: Option<String>,
    pub args: Vec<String>,
    pub otp: Option<String>,
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

pub(crate) async fn run(args: OrgArgs, current_dir: &Path) -> Result<()> {
    let action_str = match &args.action {
        Some(a) => a.as_str(),
        None => {
            return Err(anyhow::anyhow!(
                "npm error code EUSAGE\nnpm error\nnpm error Manage orgs\nnpm error\nnpm error Usage:\nnpm error npm org set orgname username [developer | admin | owner]\nnpm error npm org rm orgname username\nnpm error npm org ls orgname [<username>]\nnpm error\nnpm error Options:\nnpm error [--registry <registry>] [--otp <otp>] [--json] [-p|--parseable]\nnpm error\nnpm error alias: ogr\nnpm error\nnpm error Run \"npm help org\" for more info"
            ));
        }
    };

    match action_str {
        "ls" => run_ls(&args, current_dir).await,
        "set" | "add" => run_set(&args, current_dir).await,
        "rm" | "remove" => run_rm(&args, current_dir).await,
        _ => Err(anyhow::anyhow!(
            "npm error code EUSAGE\nnpm error\nnpm error Manage orgs\nnpm error\nnpm error Usage:\nnpm error npm org set orgname username [developer | admin | owner]\nnpm error npm org rm orgname username\nnpm error npm org ls orgname [<username>]\nnpm error\nnpm error Options:\nnpm error [--registry <registry>] [--otp <otp>] [--json] [-p|--parseable]\nnpm error\nnpm error alias: ogr\nnpm error\nnpm error Run \"npm help org\" for more info"
        )),
    }
}

async fn run_ls(args: &OrgArgs, current_dir: &Path) -> Result<()> {
    let raw_org = args
        .args
        .first()
        .ok_or_else(|| anyhow::anyhow!("npm error First argument `orgname` is required."))?;
    let org = raw_org.trim_start_matches('@').trim_start_matches('~');
    let filter_user = args.args.get(1).map(|u| u.trim_start_matches('@'));

    let (registry_url, token) = resolve_registry_and_token(current_dir, args.registry.as_deref())?;
    let base = registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/org/{}/user", url_encode(org)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let client = reqwest::Client::builder().build()?;
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

    let roster: BTreeMap<String, String> = resp.json().await.unwrap_or_default();
    let display_roster: BTreeMap<String, String> = if let Some(user) = filter_user {
        if let Some(role) = roster.get(user) {
            let mut map = BTreeMap::new();
            map.insert(user.to_string(), role.clone());
            map
        } else {
            BTreeMap::new()
        }
    } else {
        roster
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&display_roster)?);
    } else if args.parseable {
        println!("user\trole");
        for (user, role) in &display_roster {
            println!("{user}\t{role}");
        }
    } else {
        for (user, role) in &display_roster {
            println!("{user} - {role}");
        }
    }

    Ok(())
}

async fn run_set(args: &OrgArgs, current_dir: &Path) -> Result<()> {
    let raw_org = args
        .args
        .first()
        .ok_or_else(|| anyhow::anyhow!("npm error First argument `orgname` is required."))?;
    let raw_user = args
        .args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("npm error Second argument `username` is required."))?;
    let role = args
        .args
        .get(2)
        .map(String::as_str)
        .unwrap_or("developer");

    if !matches!(role, "developer" | "admin" | "owner") {
        return Err(anyhow::anyhow!(
            "npm error Third argument `role` must be one of `owner`, `admin`, or `developer`, with `developer` being the default value if omitted."
        ));
    }

    let org = raw_org.trim_start_matches('@').trim_start_matches('~');
    let user = raw_user.trim_start_matches('@').trim_start_matches('~');

    let (registry_url, token) = resolve_registry_and_token(current_dir, args.registry.as_deref())?;
    let base = registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/org/{}/user", url_encode(org)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let payload = serde_json::json!({
        "user": user,
        "role": role,
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

    let result_json: serde_json::Value = resp.json().await.unwrap_or_default();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result_json)?);
    } else if args.parseable {
        let org_name = result_json
            .get("org")
            .and_then(|o| o.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or(org);
        let org_size = result_json
            .get("org")
            .and_then(|o| o.get("size"))
            .and_then(|s| s.as_u64())
            .unwrap_or(1);
        let res_user = result_json
            .get("user")
            .and_then(|u| u.as_str())
            .unwrap_or(user);
        let res_role = result_json
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or(role);
        println!("org\torgsize\tuser\trole");
        println!("{org_name}\t{org_size}\t{res_user}\t{res_role}");
    } else {
        let org_name = result_json
            .get("org")
            .and_then(|o| o.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or(org);
        let org_size = result_json
            .get("org")
            .and_then(|o| o.get("size"))
            .and_then(|s| s.as_u64())
            .unwrap_or(1);
        let res_user = result_json
            .get("user")
            .and_then(|u| u.as_str())
            .unwrap_or(user);
        let res_role = result_json
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or(role);
        let plural = if org_size == 1 { "" } else { "s" };
        println!("Added {res_user} as {res_role} to {org_name}. You now have {org_size} member{plural} in this org.");
    }

    Ok(())
}

async fn run_rm(args: &OrgArgs, current_dir: &Path) -> Result<()> {
    let raw_org = args
        .args
        .first()
        .ok_or_else(|| anyhow::anyhow!("npm error First argument `orgname` is required."))?;
    let raw_user = args
        .args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("npm error Second argument `username` is required."))?;

    let org = raw_org.trim_start_matches('@').trim_start_matches('~');
    let user = raw_user.trim_start_matches('@').trim_start_matches('~');

    let (registry_url, token) = resolve_registry_and_token(current_dir, args.registry.as_deref())?;
    let base = registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/org/{}/user", url_encode(org)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let payload = serde_json::json!({
        "user": user,
    });

    let client = reqwest::Client::builder().build()?;
    let mut del_req = client
        .delete(target.clone())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .json(&payload);
    if let Some(otp) = &args.otp {
        del_req = del_req.header("npm-otp", otp);
    }

    let del_resp = del_req.send().await?;
    if !del_resp.status().is_success() {
        let status = del_resp.status();
        let body = del_resp.text().await.unwrap_or_default();
        return Err(format_http_error("DELETE", &target, status, &body));
    }

    // Now query the updated roster to match npm's userCount reporting
    let mut get_req = client
        .get(target.clone())
        .header("authorization", format!("Bearer {token}"));
    if let Some(otp) = &args.otp {
        get_req = get_req.header("npm-otp", otp);
    }
    let get_resp = get_req.send().await?;
    let user_count = if get_resp.status().is_success() {
        let roster: BTreeMap<String, String> = get_resp.json().await.unwrap_or_default();
        roster.len()
    } else {
        0
    };

    if args.json {
        let out = serde_json::json!({
            "user": user,
            "org": org,
            "userCount": user_count,
            "deleted": true,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if args.parseable {
        println!("user\torg\tuserCount\tdeleted");
        println!("{user}\t{org}\t{user_count}\ttrue");
    } else {
        let plural = if user_count == 1 { "" } else { "s" };
        println!("Successfully removed {user} from {org}. You now have {user_count} member{plural} in this org.");
    }

    Ok(())
}
