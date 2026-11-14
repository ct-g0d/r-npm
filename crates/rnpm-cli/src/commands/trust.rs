//! Create trusted publishers using npm's trust-cmd.js and provider claim schemas.
use anyhow::Result;
use serde_json::{json, Map, Value};
use std::path::Path;

pub(crate) struct CreateArgs {
    pub provider: String,
    pub package: Option<String>,
    pub registry: Option<String>,
    pub otp: Option<String>,
    pub file: Option<String>,
    pub repository: Option<String>,
    pub environment: Option<String>,
    pub project: Option<String>,
    pub org_id: Option<String>,
    pub project_id: Option<String>,
    pub pipeline_definition_id: Option<String>,
    pub vcs_origin: Option<String>,
    pub context_ids: Vec<String>,
    pub allow_publish: bool,
    pub allow_stage_publish: bool,
    pub yes: bool,
    pub json: bool,
    pub dry_run: bool,
}

fn required(value: Option<String>, message: &str) -> Result<String> {
    value
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("npm error {message}"))
}

fn hosted_repository(manifest: &Value) -> Option<(String, String)> {
    let repository = manifest.get("repository")?;
    let raw = repository
        .as_str()
        .or_else(|| repository.get("url")?.as_str())?;
    let raw = raw.trim_start_matches("git+").trim_end_matches(".git");
    for provider in ["github", "gitlab", "bitbucket"] {
        if let Some(repo) = raw.strip_prefix(&format!("{provider}:")) {
            return Some((provider.into(), repo.into()));
        }
        if let Some((_, repo)) = raw.split_once(&format!("{provider}.com/")) {
            return Some((provider.into(), repo.into()));
        }
        if let Some((_, repo)) = raw.split_once(&format!("{provider}.com:")) {
            return Some((provider.into(), repo.into()));
        }
    }
    if raw.split('/').count() == 2 && !raw.contains(':') {
        return Some(("github".into(), raw.into()));
    }
    None
}

fn log_values(
    values: &Map<String, Value>,
    permissions: &Value,
    json: bool,
    inferred: &[&str],
) -> Result<()> {
    if json {
        let mut values = values.clone();
        values.insert("permissions".into(), permissions.clone());
        println!("{}", serde_json::to_string_pretty(&values)?);
    } else {
        for key in ["type", "id"].into_iter().chain(
            values
                .keys()
                .map(String::as_str)
                .filter(|k| *k != "type" && *k != "id"),
        ) {
            if let Some(value) = values.get(key) {
                let text = value.as_str().map(str::to_string).unwrap_or_else(|| {
                    value
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .map(|v| v.as_str().unwrap_or_default())
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_else(|| value.to_string())
                });
                println!(
                    "{key}: {text}{}",
                    if inferred.contains(&key) {
                        " (from package.json)"
                    } else {
                        ""
                    }
                );
            }
        }
        if let Some(labels) = super::stage::format_permissions(Some(permissions)) {
            println!("permissions: {labels}");
        }
    }
    Ok(())
}

pub(crate) async fn run(args: CreateArgs, current_dir: &Path) -> Result<()> {
    if !args.allow_publish && !args.allow_stage_publish {
        anyhow::bail!("npm error At least one permission flag is required (--allow-publish, --allow-stage-publish)");
    }
    let manifest = crate::package_manifest_value(current_dir).unwrap_or_else(|_| json!({}));
    let manifest_name = manifest.get("name").and_then(Value::as_str);
    let matched = args
        .package
        .as_deref()
        .is_none_or(|p| Some(p) == manifest_name);
    let inferred_package = args.package.is_none() && manifest_name.is_some();
    let package = required(
        args.package.or_else(|| manifest_name.map(str::to_string)),
        "Package name must be specified either as an argument or in package.json file",
    )?;
    let mut permissions = Vec::new();
    if args.allow_publish {
        permissions.push("createPackage");
    }
    if args.allow_stage_publish {
        permissions.push("createStagedPackage");
    }
    let permissions = json!(permissions);
    let mut values = Map::new();
    values.insert("package".into(), package.clone().into());
    let mut claims = Map::new();
    let mut inferred = Vec::new();
    let mut urls = Vec::new();
    let (provider_name, provider_entity) = match args.provider.as_str() {
        "github" => ("GitHub Actions", "GitHub repository"),
        "gitlab" => ("GitLab CI/CD", "GitLab project"),
        "circleci" => ("CircleCI", "CircleCI pipeline"),
        other => anyhow::bail!("npm error code EUSAGE\nnpm error Unknown trust command: {other}"),
    };
    let mut warnings = Vec::new();
    if args.provider == "circleci" {
        for (flag, key, value) in [
            ("org-id", "orgId", args.org_id),
            ("project-id", "projectId", args.project_id),
            (
                "pipeline-definition-id",
                "pipelineDefinitionId",
                args.pipeline_definition_id,
            ),
            ("vcs-origin", "vcsOrigin", args.vcs_origin),
        ] {
            let value = required(value, &format!("{flag} is required"))?;
            if flag != "vcs-origin" && !super::stage::is_uuid(&value) {
                anyhow::bail!("npm error {flag} must be a valid UUID");
            }
            if flag == "vcs-origin" {
                if value.contains("://") {
                    anyhow::bail!("npm error vcs-origin must not include a scheme (e.g., use 'github.com/owner/repo' not 'https://github.com/owner/repo')");
                }
                if value.split('/').count() < 3 {
                    anyhow::bail!("npm error vcs-origin must be in format 'provider/owner/repo'");
                }
                urls.push(format!("https://{value}"));
            }
            values.insert(key.into(), value.clone().into());
            claims.insert(format!("oidc.circleci.com/{flag}"), value.into());
        }
        if !args.context_ids.is_empty() {
            for id in &args.context_ids {
                if !super::stage::is_uuid(id) {
                    anyhow::bail!("npm error context-id must be a valid UUID");
                }
            }
            values.insert("contextIds".into(), json!(args.context_ids));
            claims.insert(
                "oidc.circleci.com/context-ids".into(),
                json!(args.context_ids),
            );
        }
    } else {
        let github = args.provider == "github";
        let provider_file = if github {
            "GitHub Actions workflow"
        } else {
            "GitLab CI/CD pipeline file"
        };
        let provider_label = if github {
            "GitHub Actions Workflow"
        } else {
            "GitLab CI/CD Pipeline"
        };
        let file = required(
            args.file,
            &format!("{provider_label} must be specified with the file option"),
        )?;
        if !file.ends_with(".yml") && !file.ends_with(".yaml") {
            anyhow::bail!("npm error {provider_label} must end in .yml or .yaml");
        }
        if Path::new(&file).file_name().and_then(|n| n.to_str()) != Some(&file) {
            anyhow::bail!("npm error {provider_file} must be just a file not a path");
        }
        let git = hosted_repository(&manifest);
        let invalid_provider = matched
            && git
                .as_ref()
                .is_some_and(|(provider, _)| provider != &args.provider);
        let flag_entity = if github {
            args.repository
        } else {
            args.project.or(args.repository)
        };
        let inferred_entity = flag_entity.is_none() && !invalid_provider && git.is_some();
        let entity = flag_entity.clone().or_else(|| {
            (!invalid_provider)
                .then(|| git.as_ref().map(|(_, repo)| repo.clone()))
                .flatten()
        });
        if invalid_provider {
            let message = format!("Repository in package.json is not a {provider_entity}");
            if flag_entity.is_none() {
                anyhow::bail!("npm error {message}");
            }
            warnings.push(message);
        } else if matched
            && git
                .as_ref()
                .is_some_and(|(_, repo)| entity.as_ref() != Some(repo))
        {
            warnings.push(format!(
                "Repository in package.json ({}) differs from provided {provider_entity} ({})",
                git.as_ref().unwrap().1,
                entity.as_deref().unwrap_or_default()
            ));
        }
        let entity_key = if github { "repository" } else { "project" };
        let entity = required(
            entity,
            &format!(
                "{provider_entity} must be specified with {entity_key} option{}",
                if matched {
                    " or inferred from the package.json repository field"
                } else {
                    ""
                }
            ),
        )?;
        if (github && entity.split('/').count() != 2) || (!github && entity.split('/').count() < 2)
        {
            anyhow::bail!(
                "npm error {provider_entity} must be specified in the format {}",
                if github {
                    "owner/repository"
                } else {
                    "group/project or group/subgroup/project"
                }
            );
        }
        values.insert("file".into(), file.clone().into());
        values.insert(entity_key.into(), entity.clone().into());
        if inferred_package {
            inferred.push("package");
        }
        if inferred_entity {
            inferred.push(entity_key);
        }
        let host = format!("https://{}.com", args.provider);
        urls.push(if github {
            format!("{host}/{entity}/blob/HEAD/.github/workflows/{file}")
        } else {
            format!("{host}/{entity}/-/blob/HEAD/{file}")
        });
        urls.push(format!("{host}/{entity}"));
        claims.insert(
            if github { "repository" } else { "project_path" }.into(),
            entity.into(),
        );
        claims.insert(
            if github {
                "workflow_ref"
            } else {
                "ci_config_ref_uri"
            }
            .into(),
            json!({"file":file}),
        );
        if let Some(environment) = args.environment.filter(|s| !s.is_empty()) {
            values.insert("environment".into(), environment.clone().into());
            claims.insert("environment".into(), environment.into());
        }
    }
    let (registry, client) = crate::make_registry_client(current_dir, args.registry)?;
    if !args.json {
        println!("Establishing trust between {package} package and {provider_name}\nAnyone with {provider_entity} write access can publish to {package}\nTwo-factor authentication is required for this operation");
    }
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    if config.get("loglevel") != Some("silent") {
        if registry.as_str() != "https://registry.npmjs.org/" {
            eprintln!("npm warn trust Registry {registry} may not support trusted publishing");
        }
        for warning in warnings {
            eprintln!("npm warn trust {warning}");
        }
    }
    if !args.json {
        println!();
    }
    log_values(&values, &permissions, args.json, &inferred)?;
    if !args.json {
        if !urls.is_empty() {
            println!("\n{}", urls.join("\n"));
        }
        println!();
    }
    if args.dry_run {
        return Ok(());
    }
    if !args.yes {
        if config.get_bool("yes") == Some(false) {
            anyhow::bail!("npm error User cancelled operation");
        }
        let confirmation = super::login::prompt("Do you want to proceed? (y/N)", Some("n"), false)?;
        if !matches!(confirmation.to_lowercase().as_str(), "y" | "yes") {
            anyhow::bail!("npm error User cancelled operation");
        }
    }
    let body = json!([{"type":args.provider,"claims":claims,"permissions":permissions}]);
    let body = client
        .trust_create(Some(&registry), &package, body, args.otp.as_deref())
        .await?;
    if !args.json {
        println!(
            "Trust configuration created successfully for {package} with the following settings:"
        );
    }
    let items = if let Value::Array(items) = body {
        items
    } else {
        vec![body]
    };
    for item in items {
        println!();
        let values = super::stage::trust_body_to_options(&item)
            .into_iter()
            .collect();
        log_values(
            &values,
            item.get("permissions").unwrap_or(&Value::Null),
            args.json,
            &[],
        )?;
    }
    println!();
    Ok(())
}
