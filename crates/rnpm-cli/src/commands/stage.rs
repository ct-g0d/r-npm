//! `npm stage` and the read/revoke halves of `npm trust`, following
//! npm's lib/commands/stage/*, lib/commands/trust/{list,revoke}.js,
//! lib/trust-cmd.js and lib/utils/key-values.js.

use anyhow::Result;
use serde_json::Value;
use std::path::Path;

const STAGE_LIST_USAGE: &str = "List all staged package versions

Usage:
npm stage list [<package-spec>]

Options:
[--json] [--registry <registry>]

  --json
    Whether or not to output JSON data, rather than the normal output.

  --registry
    The base URL of the npm registry.


Run \"npm help stage\" for more info";

const STAGE_VIEW_USAGE: &str = "View details of a specific staged package

Usage:
npm stage view <stage-id>

Options:
[--json] [--registry <registry>]

  --json
    Whether or not to output JSON data, rather than the normal output.

  --registry
    The base URL of the npm registry.


aliases: info, show, v

Run \"npm help stage\" for more info";

const STAGE_OTP_OPTIONS: &str = "Options:
[--otp <otp>] [--registry <registry>]

  --otp
    This is a one-time password from a two-factor authenticator.  It's needed

  --registry
    The base URL of the npm registry.


Run \"npm help stage\" for more info";

const STAGE_USAGE: &str =
    "Stage packages for publishing, deferring proof-of-presence (2FA) to a later point in time

Usage:
npm stage
npm stage publish <package-spec>
npm stage list [<package-spec>]
npm stage view <stage-id>
npm stage approve <stage-id>
npm stage reject <stage-id>
npm stage download <stage-id>

Subcommands:
  publish
    Stage a package for publishing, deferring proof-of-presence (2FA) to a later point in time

  list
    List all staged package versions

  view
    View details of a specific staged package

  approve
    Approve a staged package, publishing it to the npm registry

  reject
    Reject a staged package, removing it from the registry

  download
    Download the tarball of a staged package for inspection

Run \"npm stage <subcommand> --help\" for more info on a subcommand.

Run \"npm help stage\" for more info";

pub(crate) const TRUST_USAGE: &str = "Create a trusted relationship between a package and a OIDC provider

Usage:
npm trust github [package] --file [--repo|--repository] [--env|--environment] [--allow-publish] [--allow-stage-publish] [-y|--yes]
npm trust gitlab [package] --file [--project|--repo|--repository] [--env|--environment] [--allow-publish] [--allow-stage-publish] [-y|--yes]
npm trust circleci [package] --org-id <uuid> --project-id <uuid> --pipeline-definition-id <uuid> --vcs-origin <origin> [--context-id <uuid>...] [--allow-publish] [--allow-stage-publish] [-y|--yes]
npm trust list [package]
npm trust revoke [package] --id=<trust-id>

Subcommands:
  github
    Create a trusted relationship between a package and GitHub Actions

  gitlab
    Create a trusted relationship between a package and GitLab CI/CD

  circleci
    Create a trusted relationship between a package and CircleCI

  list
    List trusted relationships for a package

  revoke
    Revoke a trusted relationship for a package

Run \"npm trust <subcommand> --help\" for more info on a subcommand.

Run \"npm help trust\" for more info";

/// Renders npm's `usageError`: the message (if any) followed by the usage.
pub(crate) fn usage_error(message: Option<&str>, usage: &str) -> anyhow::Error {
    let mut out = String::from("npm error code EUSAGE\nnpm error");
    if let Some(message) = message {
        out.push_str(&format!("\nnpm error {message}\nnpm error"));
    }
    for line in usage.lines() {
        out.push_str("\nnpm error");
        if !line.is_empty() {
            out.push(' ');
            out.push_str(line);
        }
    }
    anyhow::anyhow!(out)
}

fn otp_usage(description: &str, name: &str) -> String {
    format!("{description}\n\nUsage:\nnpm stage {name} <stage-id>\n\n{STAGE_OTP_OPTIONS}")
}

pub(super) fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, len)| g.len() == len && g.chars().all(|c| c.is_ascii_hexdigit()))
}

fn require_stage_id<'a>(args: &'a [String], usage: &str) -> Result<&'a str> {
    let id = args
        .first()
        .ok_or_else(|| usage_error(Some("Missing required <stage-id>"), usage))?;
    if !is_uuid(id) {
        anyhow::bail!("npm error stage-id must be a valid UUID");
    }
    Ok(id)
}

/// `String(value)` as chalk would print it.
fn js_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".to_string(),
        other => other.to_string(),
    }
}

fn pretty(value: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// key-values.js `logStageItem`.
fn stage_item_lines(item: &Value) -> Vec<String> {
    let get = |k: &str| item.get(k).filter(|v| !v.is_null()).cloned();
    let staged_by = match (get("actor"), get("actorType")) {
        (actor, Some(kind)) if !js_string(&kind).is_empty() => Some(Value::String(format!(
            "{} ({})",
            actor
                .as_ref()
                .map(js_string)
                .unwrap_or_else(|| "undefined".into()),
            js_string(&kind)
        ))),
        (actor, _) => actor,
    };
    let mut fields: Vec<(String, Option<Value>)> = vec![
        ("id".into(), get("id")),
        ("package name".into(), get("packageName")),
        ("version".into(), get("version")),
        ("status".into(), get("status")),
        ("tag".into(), get("tag")),
        ("date staged".into(), get("createdAt")),
        ("staged by".into(), staged_by),
        ("shasum".into(), get("shasum")),
    ];
    const KNOWN: &[&str] = &[
        "id",
        "packageName",
        "version",
        "tag",
        "createdAt",
        "actor",
        "actorType",
        "shasum",
        "status",
    ];
    if let Some(obj) = item.as_object() {
        for (k, v) in obj {
            if !KNOWN.contains(&k.as_str()) {
                fields.push((k.clone(), Some(v.clone()).filter(|v| !v.is_null())));
            }
        }
    }
    fields
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| format!("{k}: {}", js_string(&v))))
        .collect()
}

pub(crate) async fn run_stage(
    action: Option<&str>,
    args: &[String],
    registry: Option<String>,
    otp: Option<&str>,
    json: bool,
    current_dir: &Path,
) -> Result<()> {
    let Some(action) = action else {
        return Err(usage_error(None, STAGE_USAGE));
    };
    let (registry_url, client) = crate::make_registry_client(current_dir, registry)?;
    match action {
        "list" | "ls" => {
            let mut filter = None;
            if let Some(spec) = args.first() {
                let (name, raw_spec) = split_spec(spec);
                if raw_spec != "*" {
                    return Err(usage_error(
                        Some("Version specifiers are not supported for listing staged packages"),
                        STAGE_LIST_USAGE,
                    ));
                }
                filter = Some(name);
            }
            const PER_PAGE: u64 = 100;
            let mut items: Vec<Value> = Vec::new();
            let mut page = 0;
            loop {
                let res = client
                    .stage_list_page(Some(&registry_url), page, PER_PAGE, filter.as_deref())
                    .await?;
                let batch = res
                    .get("items")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let total = res.get("total").and_then(Value::as_u64).unwrap_or(0);
                let short = (batch.len() as u64) < PER_PAGE;
                items.extend(batch);
                if items.len() as u64 >= total || short {
                    break;
                }
                page += 1;
            }
            if json {
                println!("{}", pretty(&Value::Array(items))?);
                return Ok(());
            }
            if items.is_empty() {
                match filter {
                    Some(name) => println!("No staged versions of package name \"{name}\"."),
                    None => println!("No staged packages found."),
                }
                return Ok(());
            }
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                let lines = stage_item_lines(item);
                if !lines.is_empty() {
                    println!("{}", lines.join("\n"));
                }
            }
        }
        "view" | "info" | "show" | "v" => {
            let id = require_stage_id(args, STAGE_VIEW_USAGE)?;
            let item = client.stage_view(Some(&registry_url), id).await?;
            if json {
                println!("{}", pretty(&item)?);
            } else {
                let lines = stage_item_lines(&item);
                if !lines.is_empty() {
                    println!("{}", lines.join("\n"));
                }
            }
        }
        "approve" => {
            let usage = otp_usage(
                "Approve a staged package, publishing it to the npm registry",
                "approve",
            );
            let id = require_stage_id(args, &usage)?;
            eprintln!("npm notice Approving staged package {id}");
            client.stage_approve(Some(&registry_url), id, otp).await?;
            println!("Staged package {id} approved and published successfully.");
        }
        "reject" => {
            let usage = otp_usage(
                "Reject a staged package, removing it from the registry",
                "reject",
            );
            let id = require_stage_id(args, &usage)?;
            eprintln!("npm notice Rejecting staged package {id}");
            eprintln!("npm warn Rejecting will permanently delete this staged publish record and tarball from the registry.");
            client.stage_reject(Some(&registry_url), id, otp).await?;
            println!("Staged package {id} has been rejected.");
        }
        "download" => {
            let usage = STAGE_VIEW_USAGE
                .replace(
                    "View details of a specific staged package",
                    "Download the tarball of a staged package for inspection",
                )
                .replace("npm stage view", "npm stage download")
                .replace("\n\naliases: info, show, v", "");
            let id = require_stage_id(args, &usage)?;
            let client =
                super::client_helper::CommandClient::new(current_dir, Some(registry_url.as_str()))?;
            if !client.silent {
                eprintln!("npm notice Downloading staged package {id}");
            }
            let target = registry_url.join(&format!("-/stage/{id}/tarball"))?;
            let response = client
                .request(reqwest::Method::GET, target, None)
                .send()
                .await?
                .error_for_status()?;
            let bytes = response.bytes().await?;
            let summary = archive_summary(&bytes)?;
            if !json && !client.silent {
                crate::print_pack_notices(&summary);
            }
            let filename = format!("{}-{id}.tgz", summary.filename.trim_end_matches(".tgz"));
            std::fs::write(current_dir.join(&filename), &bytes)?;
            if json {
                println!(
                    "{}",
                    pretty(&serde_json::json!({summary.name.clone(): summary_json(&summary)}))?
                );
            } else {
                println!("{filename}");
            }
        }
        "publish" => publish(args, registry_url.as_str(), json, current_dir).await?,
        other => {
            return Err(anyhow::anyhow!(
                "npm error code EUSAGE\nnpm error Unknown subcommand: {other}"
            ));
        }
    }
    Ok(())
}

fn summary_json(summary: &rnpm_fs::PackSummary) -> Value {
    serde_json::json!({
        "id":format!("{}@{}",summary.name,summary.version),"name":summary.name,"version":summary.version,
        "size":summary.package_size,"unpackedSize":summary.unpacked_size,"shasum":summary.shasum,
        "integrity":summary.integrity,"filename":summary.filename,
        "files":summary.files.iter().map(|f|serde_json::json!({"path":f.path,"size":f.size,"mode":f.mode})).collect::<Vec<_>>(),
        "entryCount":summary.entry_count,"bundled":summary.bundled
    })
}

fn archive_summary(bytes: &[u8]) -> Result<rnpm_fs::PackSummary> {
    use rnpm_core::integrity::{Algorithm, Integrity};
    use std::io::Read;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    let mut files = Vec::new();
    let mut bundled = Vec::new();
    let mut manifest = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.to_string_lossy().to_string();
        let path = raw_path
            .strip_prefix("package/")
            .unwrap_or(&raw_path)
            .to_string();
        let size = entry.size();
        let mode = entry.header().mode()?;
        if path == "package.json" {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            manifest = Some(serde_json::from_str::<Value>(&content)?);
        }
        if let Some(rest) = path.strip_prefix("node_modules/").filter(|r| !r.is_empty()) {
            let parts: Vec<_> = rest.split('/').collect();
            let name = if rest.starts_with('@') && parts.len() > 1 {
                format!("{}/{}", parts[0], parts[1])
            } else {
                parts[0].to_string()
            };
            if !bundled.contains(&name) {
                bundled.push(name);
            }
        }
        files.push(rnpm_fs::PackedFileEntry { path, size, mode });
    }
    let manifest = manifest
        .ok_or_else(|| anyhow::anyhow!("npm error Could not read package.json from tarball"))?;
    let name = manifest["name"].as_str().unwrap_or_default().to_string();
    let version = manifest["version"].as_str().unwrap_or_default().to_string();
    files.sort_by(|a, b| {
        let upper = |s: &str| s.chars().next().is_some_and(|c| !c.is_lowercase());
        upper(&b.path)
            .cmp(&upper(&a.path))
            .then_with(|| a.path.to_lowercase().cmp(&b.path.to_lowercase()))
            .then_with(|| a.path.cmp(&b.path))
    });
    let shasum = Algorithm::Sha1
        .compute_digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(rnpm_fs::PackSummary {
        filename: rnpm_fs::compute_tarball_filename(&name, &version),
        name,
        version,
        package_size: bytes.len() as u64,
        unpacked_size: files.iter().map(|f| f.size).sum(),
        shasum,
        integrity: Integrity::from_bytes(bytes, Algorithm::Sha512).to_string(),
        entry_count: files.len(),
        files,
        bundled,
    })
}

async fn publish(args: &[String], registry: &str, json: bool, current_dir: &Path) -> Result<()> {
    use rnpm_core::manifest::Manifest;
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    let package_dir = current_dir.join(args.first().map(String::as_str).unwrap_or("."));
    let manifest = Manifest::from_file(package_dir.join("package.json"))?;
    let ignore = config.get_bool("ignore-scripts").unwrap_or(false);
    let foreground = config.get_bool("foreground-scripts").unwrap_or(true);
    let silent = config.get("loglevel") == Some("silent");
    let dry_run = config.get_bool("dry-run").unwrap_or(false);
    for event in ["prepublishOnly", "prepack", "prepare"] {
        crate::run_lifecycle_hook(
            &package_dir,
            &manifest,
            event,
            ignore,
            foreground,
            silent,
            json,
        )?;
    }
    let (summary, bytes) = rnpm_fs::pack_directory(&package_dir, None)?;
    crate::run_lifecycle_hook(
        &package_dir,
        &manifest,
        "postpack",
        ignore,
        foreground,
        silent,
        json,
    )?;
    let mut manifest = crate::package_manifest_value(&package_dir)?;
    let client = super::client_helper::CommandClient::new(current_dir, Some(registry))?;
    let registry = &client.registry_url;
    let tag = config
        .get("tag")
        .or_else(|| manifest.get("publishConfig")?.get("tag")?.as_str())
        .unwrap_or("latest")
        .to_string();
    let access_value = config
        .get("access")
        .or_else(|| manifest.get("publishConfig")?.get("access")?.as_str())
        .map(str::to_string);
    let access = access_value.as_deref();
    if !json && !silent {
        crate::print_pack_notices(&summary);
    }
    if client.auth.is_none() {
        if !dry_run {
            anyhow::bail!("npm error code ENEEDAUTH\nnpm error This command requires you to be logged in to {registry}");
        }
        if !silent {
            eprintln!(
                "npm warn stage This command requires you to be logged in to {registry} (dry-run)"
            );
        }
    }
    if !silent {
        eprintln!(
            "npm notice Staging to {registry} with tag {tag} and {} access{}",
            access.unwrap_or("default"),
            if dry_run { " (dry-run)" } else { "" }
        );
    }
    let mut details = summary_json(&summary);
    let mut stage_id = None;
    if !dry_run {
        if manifest.get("readme").is_none() {
            let readme = std::fs::read_dir(&package_dir)?
                .flatten()
                .find(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .eq_ignore_ascii_case("readme.md")
                })
                .and_then(|e| std::fs::read_to_string(e.path()).ok())
                .unwrap_or_else(|| "ERROR: No README data found!".into());
            manifest["readme"] = readme.into();
        }
        let node = std::process::Command::new("node")
            .arg("--version")
            .output()?;
        manifest["_nodeVersion"] = String::from_utf8_lossy(&node.stdout)
            .trim()
            .trim_start_matches('v')
            .into();
        manifest["_npmVersion"] = crate::version::NPM_VERSION.into();
        let options = rnpm_registry::PublishPayloadOptions {
            name: &summary.name,
            version: &summary.version,
            description: manifest.get("description").and_then(Value::as_str),
            tag: &tag,
            access,
            manifest: &manifest,
            tarball: rnpm_registry::PublishTarballData {
                filename: &summary.filename,
                bytes: &bytes,
                shasum: &summary.shasum,
                integrity: &summary.integrity,
            },
            registry_url: registry,
            provenance_attestation: None,
        };
        let mut payload = rnpm_registry::create_publish_payload(&options);
        if manifest.get("description").is_none() {
            payload.as_object_mut().unwrap().remove("description");
        }
        payload["access"] = access.map(Value::from).unwrap_or(Value::Null);
        if let Some(attachments) = payload["_attachments"].as_object_mut() {
            for attachment in attachments.values_mut() {
                attachment.as_object_mut().unwrap().remove("shasum");
                attachment.as_object_mut().unwrap().remove("integrity");
            }
        }
        let target = registry.join(&format!(
            "-/stage/package/{}",
            rnpm_config::encode_package_name(&summary.name)
        ))?;
        let response = client
            .request(reqwest::Method::POST, target, None)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        stage_id = response
            .get("stageId")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(id) = &stage_id {
            details["stageId"] = id.clone().into();
        }
    }
    if json {
        println!(
            "{}",
            pretty(&serde_json::json!({summary.name.clone():details}))?
        );
    }
    let updated = Manifest::from_file(package_dir.join("package.json"))?;
    for event in ["publish", "postpublish"] {
        crate::run_lifecycle_hook(
            &package_dir,
            &updated,
            event,
            ignore,
            foreground,
            silent,
            json,
        )?;
    }
    if !json && !silent {
        println!(
            "+ {}@{} (staged{})",
            summary.name,
            summary.version,
            stage_id
                .map(|id| format!(" with id {id}"))
                .unwrap_or_default()
        );
        eprintln!(
            "npm notice stage package {}@{} has been staged with tag {tag}",
            summary.name, summary.version
        );
    }
    Ok(())
}

/// Splits `name@spec` like npm-package-arg; a bare name has raw spec `*`.
fn split_spec(spec: &str) -> (String, String) {
    let at = if let Some(rest) = spec.strip_prefix('@') {
        rest.find('@').map(|i| i + 1)
    } else {
        spec.find('@')
    };
    match at {
        Some(i) => {
            let raw = &spec[i + 1..];
            (
                spec[..i].to_string(),
                if raw.is_empty() {
                    "*".into()
                } else {
                    raw.into()
                },
            )
        }
        None => (spec.to_string(), "*".into()),
    }
}

/// `bodyToOptions` of the provider that created the trust configuration.
pub(super) fn trust_body_to_options(body: &Value) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = Vec::new();
    let mut put = |k: &str, v: Option<&Value>| {
        if let Some(v) = v.filter(|v| is_truthy(v)) {
            out.push((k.to_string(), v.clone()));
        }
    };
    put("id", body.get("id"));
    put("type", body.get("type"));
    let claims = body.get("claims");
    let claim = |k: &str| claims.and_then(|c| c.get(k));
    match body.get("type").and_then(Value::as_str) {
        Some("github") => {
            put("file", claim("workflow_ref").and_then(|w| w.get("file")));
            put("repository", claim("repository"));
            put("environment", claim("environment"));
        }
        Some("gitlab") => {
            put(
                "file",
                claim("ci_config_ref_uri").and_then(|w| w.get("file")),
            );
            put("project", claim("project_path"));
            put("environment", claim("environment"));
        }
        Some("circleci") => {
            put("orgId", claim("oidc.circleci.com/org-id"));
            put("projectId", claim("oidc.circleci.com/project-id"));
            put(
                "pipelineDefinitionId",
                claim("oidc.circleci.com/pipeline-definition-id"),
            );
            put("vcsOrigin", claim("oidc.circleci.com/vcs-origin"));
            put("contextIds", claim("oidc.circleci.com/context-ids"));
        }
        _ => {}
    }
    out
}

fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        _ => true,
    }
}

pub(super) fn format_permissions(permissions: Option<&Value>) -> Option<String> {
    let list = permissions?.as_array().filter(|l| !l.is_empty())?;
    Some(
        list.iter()
            .map(|p| match p.as_str() {
                Some("createPackage") => "publish".to_string(),
                Some("createStagedPackage") => "stage publish".to_string(),
                _ => js_string(p),
            })
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn trust_package_name(args: &[String], current_dir: &Path) -> Result<String> {
    args.first()
        .cloned()
        .or_else(|| crate::package_name_from_manifest(current_dir).ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "npm error Package name must be specified either as an argument or in the package.json file"
            )
        })
}

pub(crate) async fn run_trust_list(
    args: &[String],
    registry: Option<String>,
    json: bool,
    current_dir: &Path,
) -> Result<()> {
    let package = trust_package_name(args, current_dir)?;
    let (registry_url, client) = crate::make_registry_client(current_dir, registry)?;
    let body = client.trust_list(Some(&registry_url), &package).await?;
    let items: Vec<Value> = match &body {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    };
    if items.is_empty() {
        if !json {
            println!("No trust configurations found for package ({package})");
        }
        return Ok(());
    }
    for config in &items {
        let values = trust_body_to_options(config);
        let permissions = config.get("permissions");
        println!();
        if json {
            let mut obj = serde_json::Map::new();
            for (k, v) in values {
                obj.insert(k, v);
            }
            if let Some(p) = permissions.filter(|p| !p.is_null()) {
                obj.insert("permissions".into(), p.clone());
            }
            println!("{}", pretty(&Value::Object(obj))?);
            continue;
        }
        let mut lines = Vec::new();
        for key in ["type", "id"] {
            if let Some((_, v)) = values.iter().find(|(k, _)| k == key) {
                lines.push(format!("{key}: {}", js_string(v)));
            }
        }
        for (k, v) in values.iter().filter(|(k, _)| k != "type" && k != "id") {
            lines.push(format!("{k}: {}", js_string(v)));
        }
        if let Some(p) = format_permissions(permissions) {
            lines.push(format!("permissions: {p}"));
        }
        println!("{}", lines.join("\n"));
    }
    println!();
    Ok(())
}

pub(crate) async fn run_trust_revoke(
    args: &[String],
    id: Option<String>,
    registry: Option<String>,
    otp: Option<&str>,
    dry_run: bool,
    json: bool,
    current_dir: &Path,
) -> Result<()> {
    let package = trust_package_name(args, current_dir)?;
    let id = id.ok_or_else(|| {
        anyhow::anyhow!(
            "npm error ID of the trusted relationship to revoke must be specified with the --id option"
        )
    })?;
    if !json {
        println!("Attempting to revoke trusted configuration for package {package} with id {id}");
    }
    if dry_run {
        return Ok(());
    }
    let (registry_url, client) = crate::make_registry_client(current_dir, registry)?;
    client
        .trust_revoke(Some(&registry_url), &package, &id, otp)
        .await?;
    if !json {
        println!("Revoked trusted configuration for package {package} with id {id}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stage_item_uses_npm_labels_and_order() {
        let item = json!({
            "shasum": "abc",
            "id": "6d8ce1e2-9bca-496a-b8b5-3e0fa10728ed",
            "packageName": "dep",
            "version": "1.0.0",
            "status": "pending",
            "createdAt": "2026-11-13",
            "actor": "mock-user",
            "actorType": "user",
            "extra": 3
        });
        assert_eq!(
            stage_item_lines(&item),
            vec![
                "id: 6d8ce1e2-9bca-496a-b8b5-3e0fa10728ed",
                "package name: dep",
                "version: 1.0.0",
                "status: pending",
                "date staged: 2026-11-13",
                "staged by: mock-user (user)",
                "shasum: abc",
                "extra: 3",
            ]
        );
    }

    #[test]
    fn split_spec_matches_npa_raw_spec() {
        assert_eq!(split_spec("dep"), ("dep".into(), "*".into()));
        assert_eq!(split_spec("@s/dep"), ("@s/dep".into(), "*".into()));
        assert_eq!(split_spec("dep@1"), ("dep".into(), "1".into()));
        assert_eq!(split_spec("@s/dep@^2"), ("@s/dep".into(), "^2".into()));
    }

    #[test]
    fn github_trust_body_maps_to_npm_options() {
        let body = json!({
            "id": "t1",
            "type": "github",
            "claims": {"repository": "o/r", "workflow_ref": {"file": "ci.yml"}},
            "permissions": ["createPackage", "createStagedPackage"]
        });
        let keys: Vec<String> = trust_body_to_options(&body)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(keys, ["id", "type", "file", "repository"]);
        assert_eq!(
            format_permissions(body.get("permissions")).as_deref(),
            Some("publish, stage publish")
        );
    }

    #[test]
    fn uuid_validation_matches_npm() {
        assert!(is_uuid("6d8ce1e2-9bca-496a-b8b5-3e0fa10728ed"));
        assert!(!is_uuid("not-a-uuid"));
    }
}
