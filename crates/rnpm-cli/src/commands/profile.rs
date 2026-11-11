use crate::commands::client_helper::{format_http_error, parse_json_response, CommandClient};
use anyhow::Result;
use reqwest::Url;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) struct ProfileArgs {
    pub action: Option<String>,
    pub args: Vec<String>,
    pub otp: Option<String>,
    pub registry: Option<String>,
    pub json: bool,
    pub parseable: bool,
}

const KNOWN_PROFILE_KEYS: &[&str] = &[
    "name",
    "email",
    "two-factor auth",
    "fullname",
    "homepage",
    "freenode",
    "twitter",
    "github",
    "created",
    "updated",
];

const WRITABLE_PROFILE_KEYS: &[&str] = &[
    "email",
    "password",
    "fullname",
    "homepage",
    "freenode",
    "twitter",
    "github",
];

pub(crate) async fn run(args: ProfileArgs, current_dir: &Path) -> Result<()> {
    let action_str = match &args.action {
        Some(a) => a.as_str(),
        None => {
            return Err(anyhow::anyhow!(
                "npm error code EUSAGE\nnpm error\nnpm error Change settings on your registry profile\nnpm error\nnpm error Usage:\nnpm error npm profile enable-2fa [auth-only|auth-and-writes]\nnpm error npm profile disable-2fa\nnpm error npm profile get [<key>]\nnpm error npm profile set <key> <value>\nnpm error\nnpm error Options:\nnpm error [--registry <registry>] [--json] [-p|--parseable] [--otp <otp>]\nnpm error\nnpm error Run \"npm help profile\" for more info"
            ));
        }
    };

    match action_str {
        "get" => run_get(&args, current_dir).await,
        "set" => run_set(&args, current_dir).await,
        "enable-2fa" | "enable-tfa" | "enable2fa" | "enabletfa" | "disable-2fa" | "disable-tfa"
        | "disable2fa" | "disabletfa" => {
            Err(anyhow::anyhow!(
                "npm error code ENOTSUP\nnpm error profile 2FA operations require interactive terminal sessions for authenticator QR scanning and OTP verification"
            ))
        }
        unknown => Err(anyhow::anyhow!("npm error Unknown profile command: {unknown}")),
    }
}

async fn run_get(args: &ProfileArgs, current_dir: &Path) -> Result<()> {
    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/npm/v1/user"))
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
    let mut info = json_val
        .as_object()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "npm error code FETCH_ERROR\nnpm error errno FETCH_ERROR\nnpm error invalid json response body at {target} reason: expected json object"
            )
        })?
        .clone();

    if let Some(val) = info.get("cidr_whitelist") {
        if val.is_null() || val.as_array().is_some_and(|a| a.is_empty()) {
            info.remove("cidr_whitelist");
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    // Cleaned map construction matching npm
    let mut cleaned: BTreeMap<String, String> = BTreeMap::new();
    for key in KNOWN_PROFILE_KEYS {
        let val = info
            .get(*key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        cleaned.insert(key.to_string(), val);
    }
    for (k, v) in &info {
        if !cleaned.contains_key(k) && k != "tfa" && k != "email_verified" {
            let s = if let Some(s) = v.as_str() {
                s.to_string()
            } else {
                v.to_string()
            };
            cleaned.insert(k.clone(), s);
        }
    }

    let email_raw = info
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let email_verified = info
        .get("email_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let email_suffix = if email_verified {
        " (verified)"
    } else {
        "(unverified)"
    };
    cleaned.insert("email".to_string(), format!("{email_raw}{email_suffix}"));

    let tfa_mode = if let Some(tfa_obj) = info.get("tfa").and_then(|v| v.as_object()) {
        let pending = tfa_obj
            .get("pending")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !pending {
            tfa_obj
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("disabled")
                .to_string()
        } else {
            "disabled".to_string()
        }
    } else {
        "disabled".to_string()
    };
    cleaned.insert("two-factor auth".to_string(), tfa_mode.clone());

    if !args.args.is_empty() {
        let mut keys_to_show = Vec::new();
        for arg in &args.args {
            for part in arg.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    keys_to_show.push(trimmed);
                }
            }
        }
        let values: Vec<String> = keys_to_show
            .iter()
            .map(|k| cleaned.get(*k).cloned().unwrap_or_default())
            .collect();
        if !client.silent {
            println!("{}", values.join("\t"));
        }
    } else if args.parseable {
        for (k, v) in &info {
            if k == "tfa" {
                println!("{k}\t{tfa_mode}");
            } else if let Some(s) = v.as_str() {
                println!("{k}\t{s}");
            } else {
                println!("{k}\t{v}");
            }
        }
    } else if !client.silent {
        for key in KNOWN_PROFILE_KEYS {
            if let Some(val) = cleaned.get(*key) {
                println!("{key}: {val}");
            }
        }
        for (k, val) in &cleaned {
            if !KNOWN_PROFILE_KEYS.contains(&k.as_str()) {
                println!("{k}: {val}");
            }
        }
    }

    Ok(())
}

async fn run_set(args: &ProfileArgs, current_dir: &Path) -> Result<()> {
    if args.args.is_empty() {
        return Err(anyhow::anyhow!("npm error npm profile set <prop> <value>"));
    }

    let prop = args.args[0].to_ascii_lowercase();
    if prop == "password" {
        if args.args.len() > 1 {
            return Err(anyhow::anyhow!(
                "npm error npm profile set password\nnpm error Do not include your current or new passwords on the command line."
            ));
        } else {
            return Err(anyhow::anyhow!(
                "npm error code ENOTSUP\nnpm error Setting password requires interactive terminal input which is not supported in non-interactive mode"
            ));
        }
    }

    if args.args.len() < 2 {
        return Err(anyhow::anyhow!("npm error npm profile set <prop> <value>"));
    }

    if !WRITABLE_PROFILE_KEYS.contains(&prop.as_str()) {
        let valid = WRITABLE_PROFILE_KEYS.join(", ");
        return Err(anyhow::anyhow!(
            "npm error \"{prop}\" is not a property we can set. Valid properties are: {valid}"
        ));
    }

    let value = args.args[1..].join(" ");

    let client = CommandClient::new(current_dir, args.registry.as_deref())?;
    let base = client.registry_url.as_str().trim_end_matches('/');
    let target = Url::parse(&format!("{base}/-/npm/v1/user"))
        .map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error {e}"))?;

    // 1. Fetch current profile to preserve existing fields
    let get_req = client.request(reqwest::Method::GET, target.clone(), args.otp.as_deref());
    let get_resp = get_req.send().await?;
    if !get_resp.status().is_success() {
        let status = get_resp.status();
        let body = get_resp.text().await.unwrap_or_default();
        return Err(format_http_error("GET", &target, status, &body));
    }

    let get_body = get_resp.text().await.unwrap_or_default();
    let get_val = parse_json_response(&get_body, &target)?;
    let current_profile = get_val.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "npm error code FETCH_ERROR\nnpm error errno FETCH_ERROR\nnpm error invalid json response body at {target} reason: expected json object"
        )
    })?;

    // 2. Build updated object preserving writable keys and setting new value
    let mut new_user = serde_json::Map::new();
    for key in WRITABLE_PROFILE_KEYS {
        if *key == "password" {
            continue;
        }
        if let Some(val) = current_profile.get(*key) {
            new_user.insert(key.to_string(), val.clone());
        }
    }
    new_user.insert(prop.clone(), serde_json::Value::String(value));

    // Profile keys cannot be empty strings, convert to null
    for (_, v) in new_user.iter_mut() {
        if let Some(s) = v.as_str() {
            if s.is_empty() {
                *v = serde_json::Value::Null;
            }
        }
    }

    let post_req = client
        .request(reqwest::Method::POST, target.clone(), args.otp.as_deref())
        .header("content-type", "application/json")
        .json(&serde_json::Value::Object(new_user));

    let post_resp = post_req.send().await?;
    if !post_resp.status().is_success() {
        let status = post_resp.status();
        let body = post_resp.text().await.unwrap_or_default();
        return Err(format_http_error("POST", &target, status, &body));
    }

    let post_body = post_resp.text().await.unwrap_or_default();
    let post_val = parse_json_response(&post_body, &target)?;
    let result_obj = post_val.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "npm error code FETCH_ERROR\nnpm error errno FETCH_ERROR\nnpm error invalid json response body at {target} reason: expected json object"
        )
    })?;

    if args.json {
        let prop_val = result_obj
            .get(&prop)
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let out = serde_json::json!({
            &prop: prop_val
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if args.parseable {
        let prop_str = result_obj
            .get(&prop)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!("{prop}\t{prop_str}");
    } else if !client.silent {
        if let Some(prop_str) = result_obj.get(&prop).and_then(|v| v.as_str()) {
            println!("Set {prop} to {prop_str}");
        } else {
            println!("Set {prop}");
        }
    }

    Ok(())
}
