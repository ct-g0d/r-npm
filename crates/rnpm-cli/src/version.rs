use anyhow::{Context, Result};
use rnpm_core::semver::Version;
use rnpm_lifecycle::{execute_lifecycle_script, LifecycleContext};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct VersionOptions {
    pub newversion: Option<String>,
    pub preid: Option<String>,
    pub message: Option<String>,
    pub allow_same_version: bool,
    pub git_tag_version: bool,
    pub commit_hooks: bool,
    pub sign_git_tag: bool,
    pub force: bool,
    pub ignore_scripts: bool,
    pub json: bool,
}

pub async fn execute_version(project_dir: &Path, options: VersionOptions) -> Result<()> {
    if options.newversion.is_none() {
        return execute_bare_version(project_dir, options.json);
    }

    let target = options.newversion.as_deref().unwrap();
    execute_version_bump(project_dir, target, &options).await
}

fn execute_bare_version(project_dir: &Path, json_mode: bool) -> Result<()> {
    let pkg_path = project_dir.join("package.json");
    let mut results = serde_json::Map::new();

    if pkg_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&pkg_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let (Some(name), Some(ver)) = (
                    val.get("name").and_then(|v| v.as_str()),
                    val.get("version").and_then(|v| v.as_str()),
                ) {
                    results.insert(name.to_string(), serde_json::Value::String(ver.to_string()));
                }
            }
        }
    }

    results.insert(
        "npm".to_string(),
        serde_json::Value::String("11.20.0".to_string()),
    );

    let mut node_versions_found = false;
    if let Ok(output) = Command::new("node")
        .args(["-p", "JSON.stringify(process.versions)"])
        .output()
    {
        if output.status.success() {
            if let Ok(serde_json::Value::Object(map)) =
                serde_json::from_slice::<serde_json::Value>(&output.stdout)
            {
                for (k, v) in map {
                    results.insert(k, v);
                }
                node_versions_found = true;
            }
        }
    }

    if !node_versions_found {
        results.insert(
            "node".to_string(),
            serde_json::Value::String("20.18.0".to_string()),
        );
        results.insert(
            "v8".to_string(),
            serde_json::Value::String("11.3.244.8-node.23".to_string()),
        );
        results.insert(
            "uv".to_string(),
            serde_json::Value::String("1.44.2".to_string()),
        );
        results.insert(
            "zlib".to_string(),
            serde_json::Value::String("1.2.13.1-motley".to_string()),
        );
    }

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(results))?
        );
    } else {
        let mut entries = Vec::new();
        for (k, v) in &results {
            let key_str = if k
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
                && !k.is_empty()
                && !k.chars().next().unwrap().is_ascii_digit()
            {
                k.clone()
            } else {
                format!("'{k}'")
            };
            let val_str = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            entries.push(format!("  {}: '{}'", key_str, val_str));
        }
        println!("{{\n{}\n}}", entries.join(",\n"));
    }

    Ok(())
}

async fn execute_version_bump(
    project_dir: &Path,
    target: &str,
    options: &VersionOptions,
) -> Result<()> {
    let pkg_path = project_dir.join("package.json");
    if !pkg_path.exists() {
        return Err(anyhow::anyhow!(
            "package.json not found in {}",
            project_dir.display()
        ));
    }

    let pkg_content = std::fs::read_to_string(&pkg_path)
        .with_context(|| format!("Failed to read {}", pkg_path.display()))?;
    let format = rnpm_core::manifest::ManifestFormat::detect(&pkg_content);
    let clean_str = pkg_content.strip_prefix('\u{feff}').unwrap_or(&pkg_content);
    let mut pkg_json: rnpm_core::OrderedJsonValue = serde_json::from_str(clean_str)
        .with_context(|| format!("Failed to parse {}", pkg_path.display()))?;

    let old_version_raw = pkg_json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0");
    let old_ver_parsed =
        Version::parse_loose(old_version_raw).unwrap_or_else(|_| Version::new(0, 0, 0));
    let old_version = old_ver_parsed.to_string();

    let new_version = match target {
        "major" | "minor" | "patch" | "premajor" | "preminor" | "prepatch" | "prerelease" => {
            let bumped = old_ver_parsed
                .inc(target, options.preid.as_deref())
                .map_err(|e| anyhow::anyhow!("Failed to increment version: {e}"))?;
            bumped.to_string()
        }
        "from-git" => {
            let output = Command::new("git")
                .args(["describe", "--tags", "--abbrev=0"])
                .current_dir(project_dir)
                .output()
                .context("Failed to run git describe for from-git")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to get version from git: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }

            let tag_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let parsed = Version::parse_loose(&tag_str)
                .map_err(|_| anyhow::anyhow!("Tag is not a valid version: \"{}\"", tag_str))?;
            parsed.to_string()
        }
        explicit => {
            let parsed = Version::parse_loose(explicit)
                .map_err(|_| anyhow::anyhow!("Invalid version: {explicit}"))?;
            parsed.to_string()
        }
    };

    if new_version == old_version && !options.allow_same_version {
        return Err(anyhow::anyhow!("Version not changed"));
    }

    let in_git = is_in_git_repo(project_dir);
    let do_git = options.git_tag_version && in_git;

    if do_git {
        check_git_clean(project_dir, options.force)?;
    }

    let pkg_name = pkg_json
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("project")
        .to_string();

    let scripts_map: BTreeMap<String, String> = pkg_json
        .get("scripts")
        .and_then(|s| s.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|cmd| (k.clone(), cmd.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // a) preversion: run BEFORE bumping version and git operations
    if !options.ignore_scripts {
        if let Some(cmd) = scripts_map.get("preversion") {
            run_lifecycle_step(
                project_dir,
                &pkg_name,
                "preversion",
                cmd,
                &old_version,
                &new_version,
                &old_version,
            )?;
        }
    }

    // b) Version bump in package.json and package-lock.json
    if let rnpm_core::OrderedJsonValue::Object(ref mut map) = pkg_json {
        map.insert(
            "version".to_string(),
            rnpm_core::OrderedJsonValue::String(new_version.clone()),
        );
    }
    let formatted_pkg = rnpm_core::manifest::Manifest::format_json_value(&pkg_json, &format)?;
    std::fs::write(&pkg_path, formatted_pkg)
        .with_context(|| format!("Failed to write {}", pkg_path.display()))?;

    for lock_name in &["package-lock.json", "npm-shrinkwrap.json"] {
        let lock_path = project_dir.join(lock_name);
        if lock_path.exists() {
            if let Ok(mut lockfile) = rnpm_lockfile::LockfileV3::load_from_file(&lock_path) {
                lockfile.version = Some(new_version.clone());
                if let Some(root_pkg) = lockfile.root_package_mut() {
                    root_pkg.version = Some(new_version.clone());
                    root_pkg.raw_value = None;
                }
                let _ = lockfile.save_to_file(&lock_path);
            }
        }
    }

    // c) version: run AFTER version bump, BEFORE git commit/tag
    if !options.ignore_scripts {
        if let Some(cmd) = scripts_map.get("version") {
            run_lifecycle_step(
                project_dir,
                &pkg_name,
                "version",
                cmd,
                &old_version,
                &new_version,
                &new_version,
            )?;
        }
    }

    // d) Git commit & tag created
    if do_git {
        let mut add_args = vec!["add".to_string(), "package.json".to_string()];
        if project_dir.join("package-lock.json").exists() {
            add_args.push("package-lock.json".to_string());
        }
        if project_dir.join("npm-shrinkwrap.json").exists() {
            add_args.push("npm-shrinkwrap.json".to_string());
        }

        let add_output = Command::new("git")
            .args(&add_args)
            .current_dir(project_dir)
            .output()
            .context("Failed to stage files with git add")?;

        if !add_output.status.success() {
            return Err(anyhow::anyhow!(
                "git add failed: {}",
                String::from_utf8_lossy(&add_output.stderr)
            ));
        }

        let msg_template = options.message.as_deref().unwrap_or("%s");
        let commit_msg = msg_template.replace("%s", &new_version);

        let mut commit_args = vec!["commit".to_string()];
        if !options.commit_hooks {
            commit_args.push("--no-verify".to_string());
        }
        if options.allow_same_version {
            commit_args.push("--allow-empty".to_string());
        }
        commit_args.push("-m".to_string());
        commit_args.push(commit_msg.clone());

        let commit_output = Command::new("git")
            .args(&commit_args)
            .current_dir(project_dir)
            .output()
            .context("Failed to create git commit")?;

        if !commit_output.status.success() {
            return Err(anyhow::anyhow!(
                "git commit failed: {}",
                String::from_utf8_lossy(&commit_output.stderr)
            ));
        }

        let tag_name = format!("v{new_version}");
        let mut tag_args = vec!["tag".to_string()];
        if options.sign_git_tag {
            tag_args.push("-s".to_string());
        } else {
            tag_args.push("-a".to_string());
        }
        if options.allow_same_version || options.force || target == "from-git" {
            tag_args.push("-f".to_string());
        }
        tag_args.push("-m".to_string());
        tag_args.push(commit_msg);
        tag_args.push(tag_name);

        let tag_output = Command::new("git")
            .args(&tag_args)
            .current_dir(project_dir)
            .output()
            .context("Failed to create git tag")?;

        if !tag_output.status.success() {
            return Err(anyhow::anyhow!(
                "git tag failed: {}",
                String::from_utf8_lossy(&tag_output.stderr)
            ));
        }
    }

    // e) postversion: run AFTER git commit/tag
    if !options.ignore_scripts {
        if let Some(cmd) = scripts_map.get("postversion") {
            run_lifecycle_step(
                project_dir,
                &pkg_name,
                "postversion",
                cmd,
                &old_version,
                &new_version,
                &new_version,
            )?;
        }
    }

    // 5. Prints the new version tag (e.g. v1.2.4) to stdout
    println!("v{new_version}");

    Ok(())
}

fn run_lifecycle_step(
    project_dir: &Path,
    pkg_name: &str,
    script_name: &str,
    script_cmd: &str,
    old_version: &str,
    new_version: &str,
    current_ver: &str,
) -> Result<()> {
    let mut ctx =
        LifecycleContext::new(project_dir, project_dir, pkg_name, script_name, script_cmd);
    ctx.package_version = Some(current_ver.to_string());
    ctx.extra_env
        .insert("npm_old_version".to_string(), old_version.to_string());
    ctx.extra_env
        .insert("npm_new_version".to_string(), new_version.to_string());
    if let Ok(cwd) = std::env::current_dir() {
        ctx.extra_env.insert("INIT_CWD".into(), cwd.to_string_lossy().into_owned());
    }

    if rnpm_config::Config::load(Some(project_dir))?.get("loglevel") != Some("silent") {
        println!("\n> {script_name}\n> {script_cmd}\n");
    }

    let status = execute_lifecycle_script(&ctx)?;
    if !status.success() {
        let code = rnpm_lifecycle::extract_exit_status_code(&status);
        return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
            exit_code: code,
            message: format!("Lifecycle script '{script_name}' failed with exit code: {code}"),
        }));
    }
    Ok(())
}

pub fn is_in_git_repo(project_dir: &Path) -> bool {
    Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(project_dir)
        .output()
        .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "true")
        .unwrap_or(false)
}

pub fn check_git_clean(project_dir: &Path, force: bool) -> Result<()> {
    let output = Command::new("git")
        .args(["status", "--porcelain", "-uno"])
        .current_dir(project_dir)
        .output()
        .context("Failed to run git status")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to check git status: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().is_empty() && !force {
        return Err(anyhow::anyhow!("Git working directory not clean."));
    }

    Ok(())
}
