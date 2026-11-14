//! `npm dist-tag`, ported from npm's lib/commands/dist-tag.js.

use super::client_helper::CommandClient;
use crate::http_errors::{auth_error_block, e404_block, encode_uri_component, general_message, is_otp_error};
use anyhow::Result;
use std::path::PathBuf;

const USAGE: &str = "Modify package distribution tags

Usage:
npm dist-tag add <package-spec (with version)> [<tag>]
npm dist-tag rm <package-spec> <tag>
npm dist-tag ls [<package-spec>]

Options:
[-w|--workspace <workspace-name> [-w|--workspace <workspace-name> ...]]
[--workspaces] [--include-workspace-root]

  -w|--workspace
    Enable running a command in the context of the configured workspaces of the

  --workspaces
    Set to true to run the command in the context of **all** configured

  --include-workspace-root
    Include the workspace root when workspaces are enabled for a command.


alias: dist-tags

Run \"npm help dist-tag\" for more info";

fn usage_error(message: Option<&str>) -> anyhow::Error {
    super::stage::usage_error(message, USAGE)
}

/// The parts of an npm-package-arg registry spec that dist-tag uses.
struct Spec {
    name: String,
    raw_spec: String,
}

impl Spec {
    fn parse(raw: &str) -> Self {
        let at = match raw.strip_prefix('@') {
            Some(rest) => rest.find('@').map(|i| i + 1),
            None => raw.find('@'),
        };
        let (name, spec) = match at {
            Some(i) => (&raw[..i], &raw[i + 1..]),
            None => (raw, ""),
        };
        let spec = spec.trim();
        Spec {
            name: name.to_string(),
            raw_spec: if spec.is_empty() { "*".to_string() } else { spec.to_string() },
        }
    }

    fn escaped_name(&self) -> String {
        match self.name.strip_prefix('@') {
            Some(_) => format!("@{}", encode_uri_component(&self.name[1..])),
            None => self.name.clone(),
        }
    }

    fn pkgid(&self) -> String {
        format!("{}@{}", self.name, self.raw_spec)
    }

    fn spec_type(&self) -> &'static str {
        if rnpm_core::semver::Version::parse(&self.raw_spec).is_ok() {
            "version"
        } else if rnpm_core::semver::Range::parse(&self.raw_spec).is_ok() {
            "range"
        } else {
            "tag"
        }
    }

    /// `util.inspect` of the npm-package-arg `Result`, as `log.error` prints it.
    fn inspect(&self) -> String {
        let q = |s: &str| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"));
        let scope = match self.name.strip_prefix('@').and_then(|r| r.split_once('/')) {
            Some((scope, _)) => q(&format!("@{scope}")),
            None => "undefined".to_string(),
        };
        let fetch_spec = if self.spec_type() == "version" {
            rnpm_core::semver::Version::parse(&self.raw_spec)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| self.raw_spec.clone())
        } else {
            self.raw_spec.clone()
        };
        let raw = if self.raw_spec == "*" { self.name.clone() } else { self.pkgid() };
        [
            "Result {".to_string(),
            format!("  type: {},", q(self.spec_type())),
            "  registry: true,".to_string(),
            "  where: undefined,".to_string(),
            format!("  raw: {},", q(&raw)),
            format!("  name: {},", q(&self.name)),
            format!("  escapedName: {},", q(&self.escaped_name())),
            format!("  scope: {scope},"),
            format!("  rawSpec: {},", q(&self.raw_spec)),
            "  saveSpec: null,".to_string(),
            format!("  fetchSpec: {},", q(&fetch_spec)),
            "  gitRange: undefined,".to_string(),
            "  gitCommittish: undefined,".to_string(),
            "  gitSubdir: undefined,".to_string(),
            "  hosted: undefined".to_string(),
            "}".to_string(),
        ]
        .join("\n")
    }
}

pub(crate) async fn run(
    current_dir: PathBuf,
    args: Vec<String>,
    registry: Option<String>,
    otp: Option<String>,
    tag: Option<String>,
) -> Result<()> {
    let client = CommandClient::new(&current_dir, registry.as_deref())?;
    let cmd = args.first().map(String::as_str);
    let pkg = args.get(1).map(String::as_str);
    let tag_arg = args.get(2).map(String::as_str);
    match cmd {
        Some("add" | "a" | "set" | "s") => {
            let default_tag = tag_arg.map(str::to_string).or(tag).unwrap_or_else(|| {
                rnpm_config::Config::load(Some(&current_dir))
                    .ok()
                    .and_then(|c| c.get("tag").map(str::to_string))
                    .unwrap_or_else(|| "latest".to_string())
            });
            add(&client, pkg.unwrap_or(""), &default_tag, otp).await
        }
        Some("rm" | "r" | "del" | "d" | "remove") => remove(&client, pkg.unwrap_or(""), tag_arg, otp).await,
        Some("ls" | "l" | "sl" | "list") => list(&client, &current_dir, pkg).await,
        _ if pkg.is_none() => list(&client, &current_dir, cmd).await,
        _ => Err(usage_error(None)),
    }
}

fn request_error(method: &str, url: &reqwest::Url, status: reqwest::StatusCode, www: Option<&str>, body: &str, spec: &Spec) -> anyhow::Error {
    if let Some(block) = auth_error_block(method, url.as_str(), status, www, body) {
        return anyhow::anyhow!(block);
    }
    let message = general_message(method, url.as_str(), status, body);
    match status.as_u16() {
        404 => anyhow::anyhow!(e404_block(&message, Some(&spec.pkgid()))),
        code => anyhow::anyhow!("npm error code E{code}\nnpm error {message}"),
    }
}

async fn fetch_tags(client: &CommandClient, spec: &Spec) -> Result<serde_json::Map<String, serde_json::Value>> {
    let url = client
        .registry_url
        .join(&format!("-/package/{}/dist-tags", spec.escaped_name()))?;
    let resp = client.request(reqwest::Method::GET, url.clone(), None).send().await?;
    let status = resp.status();
    let www = resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).map(str::to_string);
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(request_error("GET", &url, status, www.as_deref(), &body, spec));
    }
    let mut tags = match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    tags.remove("_etag");
    if tags.is_empty() {
        anyhow::bail!("npm error No dist-tags found for {}", spec.name);
    }
    Ok(tags)
}

/// Sends a dist-tag mutation, retrying once with a prompted OTP on an
/// interactive terminal (npm's `otplease`).
async fn mutate(
    client: &CommandClient,
    method: reqwest::Method,
    url: &reqwest::Url,
    body: Option<String>,
    otp: Option<String>,
    spec: &Spec,
) -> Result<()> {
    let send = |otp: Option<String>| {
        let method = method.clone();
        let body = body.clone();
        async move {
            let mut req = client.request(method.clone(), url.clone(), otp.as_deref());
            if let Some(body) = body {
                req = req.header("content-type", "application/json").body(body);
            }
            let resp = req.send().await?;
            let status = resp.status();
            if status.is_success() {
                return Ok(());
            }
            let www = resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).map(str::to_string);
            let text = resp.text().await.unwrap_or_default();
            Err(request_error(method.as_str(), url, status, www.as_deref(), &text, spec))
        }
    };
    match send(otp).await {
        Err(err) if is_otp_error(&err) => match crate::http_errors::retry_otp(&std::env::current_dir()?, &err).await? {
            Some(code) => send(Some(code)).await,
            None => Err(err),
        },
        other => other,
    }
}

async fn add(client: &CommandClient, raw: &str, default_tag: &str, otp: Option<String>) -> Result<()> {
    let spec = Spec::parse(raw);
    let version = spec.raw_spec.clone();
    if spec.name.is_empty() || default_tag.is_empty() {
        return Err(usage_error(Some("must provide a spec with a name and version, and a tag to add")));
    }
    let t = default_tag.trim();
    if rnpm_core::semver::Range::parse(t).is_ok() {
        anyhow::bail!("npm error Tag name must not be a valid SemVer range: {t}");
    }
    let tags = fetch_tags(client, &spec).await?;
    if tags.get(t).and_then(|v| v.as_str()) == Some(version.as_str()) {
        eprintln!("npm warn dist-tag add {t} is already set to version {version}");
        return Ok(());
    }
    let url = client.registry_url.join(&format!(
        "-/package/{}/dist-tags/{}",
        spec.escaped_name(),
        encode_uri_component(t)
    ))?;
    mutate(client, reqwest::Method::PUT, &url, Some(serde_json::to_string(&version)?), otp, &spec).await?;
    println!("+{t}: {}@{version}", spec.name);
    Ok(())
}

async fn remove(client: &CommandClient, raw: &str, tag: Option<&str>, otp: Option<String>) -> Result<()> {
    let spec = Spec::parse(raw);
    if spec.name.is_empty() {
        return Err(usage_error(None));
    }
    let tag = tag.unwrap_or("undefined");
    let tags = fetch_tags(client, &spec).await?;
    let Some(version) = tags.get(tag).filter(|v| !v.is_null() && v.as_str() != Some("")) else {
        anyhow::bail!("npm error {tag} is not a dist-tag on {}", spec.name);
    };
    let version = version.as_str().map(str::to_string).unwrap_or_else(|| version.to_string());
    let url = client.registry_url.join(&format!(
        "-/package/{}/dist-tags/{}",
        spec.escaped_name(),
        encode_uri_component(tag)
    ))?;
    mutate(client, reqwest::Method::DELETE, &url, None, otp, &spec).await?;
    println!("-{tag}: {}@{version}", spec.name);
    Ok(())
}

async fn list(client: &CommandClient, current_dir: &std::path::Path, raw: Option<&str>) -> Result<()> {
    let raw = match raw {
        Some(raw) => raw.to_string(),
        None => {
            let global = rnpm_config::Config::load(Some(current_dir))
                .ok()
                .and_then(|c| c.get_bool("global"))
                .unwrap_or(false);
            if global {
                return Err(usage_error(None));
            }
            let name = std::fs::read_to_string(current_dir.join("package.json"))
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string));
            match name {
                Some(name) if !name.is_empty() => name,
                _ => return Err(usage_error(None)),
            }
        }
    };
    let spec = Spec::parse(&raw);
    match fetch_tags(client, &spec).await {
        Ok(tags) => {
            let mut lines: Vec<String> = tags
                .iter()
                .map(|(k, v)| format!("{k}: {}", v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
                .collect();
            lines.sort();
            println!("{}", lines.join("\n"));
            Ok(())
        }
        Err(err) => {
            for line in format!("Couldn't get dist-tag data for {}", spec.inspect()).lines() {
                eprintln!("npm error dist-tag ls {line}");
            }
            Err(err)
        }
    }
}
