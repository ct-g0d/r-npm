//! `npm access`, ported from npm's lib/commands/access.js and libnpmaccess.
use super::client_helper::CommandClient;
use crate::http_errors::encode_uri_component;
use anyhow::Result;
use reqwest::{Method, Url};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

pub(crate) struct AccessArgs {
    pub args: Vec<String>,
    pub registry: Option<String>,
    pub json: bool,
    pub otp: Option<String>,
}

const USAGE: &str = "Set access level on published packages\n\nUsage:\nnpm access list packages [<user>|<scope>|<scope:team>] [<package>]\nnpm access list collaborators [<package> [<user>]]\nnpm access get status [<package>]\nnpm access set status=public|private [<package>]\nnpm access set mfa=none|publish|automation [<package>]\nnpm access grant <read-only|read-write> <scope:team> [<package>]\nnpm access revoke <scope:team> [<package>]\n\nOptions:\n[--json] [--otp <otp>] [--registry <registry>]\n\n  --json\n    Whether or not to output JSON data, rather than the normal output.\n\n  --otp\n    This is a one-time password from a two-factor authenticator.  It's needed\n\n  --registry\n    The base URL of the npm registry.\n\n\nRun \"npm help access\" for more info";
const COMMANDS: [&str; 5] = ["get", "grant", "list", "revoke", "set"];
const SET_COMMANDS: [&str; 8] = [
    "status=public",
    "status=private",
    "mfa=none",
    "mfa=publish",
    "mfa=automation",
    "2fa=none",
    "2fa=publish",
    "2fa=automation",
];

fn usage(message: Option<&str>) -> anyhow::Error {
    super::stage::usage_error(message, USAGE)
}

/// npm-package-arg's escapedName: only the scope separator is encoded.
fn escaped(name: &str) -> String {
    name.replacen('/', "%2f", 1)
}

fn parse_team(scope_team: &str) -> (String, Option<String>) {
    let s = scope_team.strip_prefix('@').unwrap_or(scope_team);
    let mut parts = s.split(':');
    let scope = encode_uri_component(parts.next().unwrap_or_default());
    (scope, parts.next().map(encode_uri_component))
}

struct Ctx<'a> {
    dir: &'a Path,
    client: CommandClient,
    base: Url,
    json: bool,
    otp: Option<String>,
}

impl Ctx<'_> {
    fn url(&self, path: &str) -> Result<Url> {
        Ok(self.base.join(path.trim_start_matches('/'))?)
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let url = self.url(path)?;
        self.client.send_json(self.dir, Method::GET, url, None, None).await
    }

    async fn mutate(&self, method: Method, path: &str, body: Value) -> Result<()> {
        let url = self.url(path)?;
        self.client
            .send_text(self.dir, method, url, Some(body), self.otp.clone())
            .await
            .map(|_| ())
    }

    fn output(&self, items: &Map<String, Value>, limiter: Option<&str>) -> Result<()> {
        let mut outputs = Map::new();
        for (key, value) in items {
            let mapped = match value.as_str() {
                Some("read") => "read-only".into(),
                Some("write") => "read-write".into(),
                _ => value.clone(),
            };
            outputs.insert(key.clone(), mapped);
        }
        if self.json {
            println!("{}", serde_json::to_string_pretty(&Value::Object(outputs))?);
            return Ok(());
        }
        let mut keys: Vec<_> = outputs.keys().cloned().collect();
        keys.sort_by(|a, b| rnpm_solver::solver::arborist_compare(a, b));
        for key in keys {
            if limiter.is_none_or(|l| l == key) {
                let v = &outputs[&key];
                let text = v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
                println!("{key}: {text}");
            }
        }
        Ok(())
    }

    fn package(&self, name: Option<&str>, require_scope: bool) -> Result<String> {
        let name = match name {
            Some(n) => n.to_string(),
            None => {
                let text = std::fs::read_to_string(self.dir.join("package.json")).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        anyhow::anyhow!("npm error code ENOENT\nnpm error no package name given and no package.json found")
                    } else {
                        e.into()
                    }
                })?;
                let value: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))?;
                value["name"].as_str().unwrap_or_default().to_string()
            }
        };
        if require_scope && !name.starts_with('@') {
            return Err(usage(Some("This command is only available for scoped packages.")));
        }
        Ok(name)
    }

    async fn get_status(&self, pkg: Option<&str>) -> Result<()> {
        let name = self.package(pkg, false)?;
        let visibility = self.get(&format!("/-/package/{}/visibility", escaped(&name))).await?;
        let status = if visibility["public"].as_bool().unwrap_or(false) { "public" } else { "private" };
        let mut items = Map::new();
        items.insert(name, status.into());
        self.output(&items, None)
    }
}

pub(crate) async fn run(args: AccessArgs, current_dir: PathBuf) -> Result<()> {
    let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
    let json = args.json || config.get_bool("json").unwrap_or(false);
    let base = match &args.registry {
        Some(r) => Url::parse(r)?,
        None => config.npmrc.registry.clone(),
    };
    let client = CommandClient::new(&current_dir, Some(base.as_str()))?;
    let ctx = Ctx { dir: &current_dir, client, base, json, otp: args.otp.clone() };

    let mut it = args.args.iter().map(String::as_str);
    let cmd = it.next().ok_or_else(|| usage(None))?;
    if !COMMANDS.contains(&cmd) {
        return Err(usage(Some(&format!("{cmd} is not a valid access command"))));
    }
    let subcmd = it.next().ok_or_else(|| usage(None))?;
    let rest: Vec<&str> = it.collect();

    match cmd {
        "grant" => {
            if !["read-only", "read-write"].contains(&subcmd) {
                return Err(usage(Some("grant must be either `read-only` or `read-write`")));
            }
            let scope_team = rest.first().ok_or_else(|| usage(Some("`<scope:team>` argument is required")))?;
            let pkg = rest.get(1).copied().unwrap_or_default();
            let (scope, team) = parse_team(scope_team);
            let team = team
                .filter(|t| !t.is_empty())
                .ok_or_else(|| anyhow::anyhow!("npm error team must be in format `scope:team`"))?;
            ctx.mutate(
                Method::PUT,
                &format!("/-/team/{scope}/{team}/package"),
                serde_json::json!({ "package": pkg, "permissions": subcmd }),
            )
            .await
        }
        "revoke" => {
            let pkg = rest.first().copied().unwrap_or_default();
            let (scope, team) = parse_team(subcmd);
            ctx.mutate(
                Method::DELETE,
                &format!("/-/team/{scope}/{}/package", team.unwrap_or_default()),
                serde_json::json!({ "package": pkg }),
            )
            .await
        }
        "list" => match subcmd {
            "packages" => {
                let owner = match rest.first() {
                    Some(o) => o.to_string(),
                    None => ctx.get("/-/whoami").await?["username"].as_str().unwrap_or_default().to_string(),
                };
                let (scope, team) = parse_team(&owner);
                let first = match team {
                    Some(team) => ctx.get(&format!("/-/team/{scope}/{team}/package")).await,
                    None => ctx.get(&format!("/-/org/{scope}/package")).await,
                };
                let pkgs = match first {
                    Err(e) if e.to_string().starts_with("npm error code E404") => {
                        ctx.get(&format!("/-/user/{scope}/package")).await?
                    }
                    other => other?,
                };
                ctx.output(pkgs.as_object().unwrap_or(&Map::new()), rest.get(1).copied())
            }
            "collaborators" => {
                let name = ctx.package(rest.first().copied(), false)?;
                let collabs = ctx.get(&format!("/-/package/{}/collaborators", escaped(&name))).await?;
                ctx.output(collabs.as_object().unwrap_or(&Map::new()), rest.get(1).copied())
            }
            other => Err(usage(Some(&format!("list {other} is not a valid access command")))),
        },
        "get" => {
            if subcmd != "status" {
                return Err(usage(Some(&format!("get {subcmd} is not a valid access command"))));
            }
            ctx.get_status(rest.first().copied()).await
        }
        _ => {
            if !SET_COMMANDS.contains(&subcmd) {
                return Err(usage(Some(&format!("set {subcmd} is not a valid access command"))));
            }
            let (key, value) = subcmd.split_once('=').unwrap_or((subcmd, ""));
            let pkg = rest.first().copied();
            if key == "status" {
                let name = ctx.package(pkg, true)?;
                let status = if value == "private" { "restricted" } else { value };
                ctx.mutate(
                    Method::POST,
                    &format!("/-/package/{}/access", escaped(&name)),
                    serde_json::json!({ "access": status }),
                )
                .await?;
                ctx.get_status(Some(&name)).await
            } else {
                let name = ctx.package(pkg, false)?;
                let body = match value {
                    "none" => serde_json::json!({ "publish_requires_tfa": false }),
                    "publish" => serde_json::json!({ "publish_requires_tfa": true, "automation_token_overrides_tfa": false }),
                    _ => serde_json::json!({ "publish_requires_tfa": true, "automation_token_overrides_tfa": true }),
                };
                ctx.mutate(Method::POST, &format!("/-/package/{}/access", escaped(&name)), body).await
            }
        }
    }
}
