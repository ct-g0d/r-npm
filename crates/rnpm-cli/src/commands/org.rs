use crate::commands::client_helper::{
    format_http_error, parse_json_response, url_encode, CommandClient,
};
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

    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/org/{}/user", url_encode(org)))
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
    let roster_obj = json_val.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "npm error code FETCH_ERROR\nnpm error errno FETCH_ERROR\nnpm error invalid json response body at {target} reason: expected json object"
        )
    })?;

    let mut roster: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in roster_obj {
        let role = v.as_str().unwrap_or("developer").to_string();
        roster.insert(k.clone(), role);
    }

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
    } else if !client.silent {
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

    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/org/{}/user", url_encode(org)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let payload = serde_json::json!({
        "user": user,
        "role": role,
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

    let body = resp.text().await.unwrap_or_default();
    let result_json = parse_json_response(&body, &target)?;

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
    } else if !client.silent {
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

    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/org/{}/user", url_encode(org)))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    let payload = serde_json::json!({
        "user": user,
    });

    let del_req = client
        .request(reqwest::Method::DELETE, target.clone(), args.otp.as_deref())
        .header("content-type", "application/json")
        .json(&payload);

    let del_resp = del_req.send().await?;
    if !del_resp.status().is_success() {
        let status = del_resp.status();
        let body = del_resp.text().await.unwrap_or_default();
        return Err(format_http_error("DELETE", &target, status, &body));
    }

    // Now query the updated roster to match npm's userCount reporting
    let get_req = client.request(reqwest::Method::GET, target.clone(), args.otp.as_deref());
    let get_resp = get_req.send().await?;
    if !get_resp.status().is_success() {
        let status = get_resp.status();
        let body = get_resp.text().await.unwrap_or_default();
        return Err(format_http_error("GET", &target, status, &body));
    }

    let get_body = get_resp.text().await.unwrap_or_default();
    let get_val = parse_json_response(&get_body, &target)?;
    let roster_obj = get_val.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "npm error code FETCH_ERROR\nnpm error errno FETCH_ERROR\nnpm error invalid json response body at {target} reason: expected json object"
        )
    })?;
    let user_count = roster_obj.len();

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
    } else if !client.silent {
        let plural = if user_count == 1 { "" } else { "s" };
        println!("Successfully removed {user} from {org}. You now have {user_count} member{plural} in this org.");
    }

    Ok(())
}
