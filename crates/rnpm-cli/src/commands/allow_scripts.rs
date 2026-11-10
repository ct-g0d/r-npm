use anyhow::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn installed_install_script_packages(
    current_dir: &Path,
) -> Result<BTreeMap<String, PathBuf>> {
    let node_modules = current_dir.join("node_modules");
    let lock = current_dir.join("package-lock.json");
    let lock_value = std::fs::read_to_string(lock)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    let mut found = BTreeMap::new();

    fn walk(
        dir: &Path,
        root: &Path,
        lock: Option<&serde_json::Value>,
        found: &mut BTreeMap<String, PathBuf>,
    ) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }
        for entry in std::fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some(".bin") {
                continue;
            }
            let manifest_path = path.join("package.json");
            if manifest_path.is_file() {
                let manifest: serde_json::Value = match std::fs::read_to_string(&manifest_path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                {
                    Some(v) => v,
                    None => continue,
                };
                let name = manifest
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let version = manifest
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if name.is_empty() || version.is_empty() {
                    continue;
                }
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let lock_entry = lock
                    .and_then(|v| v.get("packages"))
                    .and_then(|p| p.get(&rel));
                let resolved = lock_entry
                    .and_then(|v| v.get("resolved"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let scripts = manifest.get("scripts").and_then(|v| v.as_object());
                let declared = scripts
                    .map(|s| {
                        ["preinstall", "install", "postinstall"]
                            .iter()
                            .any(|k| s.contains_key(*k))
                    })
                    .unwrap_or(false);
                let prepare = scripts
                    .map(|s| {
                        s.contains_key("prepare")
                            && (resolved.starts_with("git") || resolved.starts_with("file:"))
                    })
                    .unwrap_or(false);
                let implicit_node_gyp = path.join("binding.gyp").is_file();
                if declared || prepare || implicit_node_gyp {
                    found.insert(format!("{name}@{version}"), path.clone());
                }
                let nested = path.join("node_modules");
                if nested.is_dir() {
                    walk(&nested, root, lock, found)?;
                }
            } else {
                walk(&path, root, lock, found)?;
            }
        }
        Ok(())
    }

    walk(
        &node_modules,
        &current_dir.join("node_modules"),
        lock_value.as_ref(),
        &mut found,
    )?;
    Ok(found)
}

fn allow_scripts_matches(entry: &str, identity: &str, value: &serde_json::Value) -> bool {
    if entry == "*" {
        return value.as_bool() == Some(true);
    }
    let name = identity
        .rsplit_once('@')
        .map(|(name, _)| name)
        .unwrap_or(identity);
    (entry == identity || entry == name) && value.as_bool() == Some(true)
}

pub(crate) fn list_pending_install_scripts(current_dir: &Path, json: bool) -> Result<()> {
    let installed = installed_install_script_packages(current_dir)?;
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(current_dir.join("package.json"))?)?;
    let allow = document.get("allowScripts").and_then(|v| v.as_object());
    let pending: Vec<String> = installed
        .keys()
        .filter(|identity| {
            !allow
                .map(|entries| {
                    entries
                        .iter()
                        .any(|(key, value)| allow_scripts_matches(key, identity, value))
                })
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    if json {
        println!("{}", serde_json::json!({ "pending": pending }));
    } else {
        for item in pending {
            println!("{item}");
        }
    }
    Ok(())
}

pub(crate) fn prune_install_scripts_policy(
    current_dir: &Path,
    json: bool,
    dry_run: bool,
) -> Result<()> {
    let installed = installed_install_script_packages(current_dir)?;
    let path = current_dir.join("package.json");
    let mut document: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let allow = document
        .get_mut("allowScripts")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "npm error code ENOENT\nnpm error package.json has no allowScripts entries"
            )
        })?;
    let before = allow.clone();
    let keys: Vec<String> = allow.keys().cloned().collect();
    for key in keys {
        if key.is_empty() || key.contains("||") || key.contains(' ') {
            continue;
        }
        let keep = if key == "*" {
            !installed.is_empty()
        } else if key.contains('@') && !key.starts_with('@') {
            installed.contains_key(&key)
        } else {
            installed
                .keys()
                .any(|identity| identity.starts_with(&format!("{key}@")))
        };
        if !keep {
            allow.remove(&key);
        }
    }
    let removed: Vec<String> = before
        .keys()
        .filter(|k| !allow.contains_key(*k))
        .cloned()
        .collect();
    if !dry_run {
        std::fs::write(&path, serde_json::to_string_pretty(&document)? + "\n")?;
    }
    if json {
        println!(
            "{}",
            serde_json::json!({ "removed": removed, "dryRun": dry_run })
        );
    } else {
        for item in removed {
            println!("removed {item}");
        }
    }
    Ok(())
}

fn apply_policy_changes(
    current_dir: &Path,
    packages: &[String],
    approved: bool,
    all: bool,
    json: bool,
    _cmd_name: &str,
) -> Result<()> {
    if !all && packages.is_empty() {
        let usage = if approved {
            "Approve install scripts for specific dependencies\n\nUsage:\nnpm approve-scripts <pkg> [<pkg> ...]\nnpm approve-scripts --all\nnpm approve-scripts --allow-scripts-pending\n\nOptions:\n[-a|--all] [--allow-scripts-pending] [--no-allow-scripts-pin] [--json]\n\n  -a|--all\n    Show or act on all packages, not just the ones your project directly\n\n  --allow-scripts-pending\n    List packages with install scripts that are not yet covered by the\n\n  --allow-scripts-pin\n    Write pinned (`pkg@version`) entries when approving install scripts.\n\n  --json\n    Whether or not to output JSON data, rather than the normal output.\n\n\nRun \"npm help approve-scripts\" for more info"
        } else {
            "Deny install scripts for specific dependencies\n\nUsage:\nnpm deny-scripts <pkg> [<pkg> ...]\nnpm deny-scripts --all\n\nOptions:\n[-a|--all] [--allow-scripts-pending] [--no-allow-scripts-pin] [--json]\n\n  -a|--all\n    Show or act on all packages, not just the ones your project directly\n\n  --allow-scripts-pending\n    List packages with install scripts that are not yet covered by the\n\n  --allow-scripts-pin\n    Write pinned (`pkg@version`) entries when approving install scripts.\n\n  --json\n    Whether or not to output JSON data, rather than the normal output.\n\n\nRun \"npm help deny-scripts\" for more info"
        };
        let err_lines = usage.lines().map(|l| format!("npm error {l}")).collect::<Vec<_>>().join("\n");
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\n{err_lines}"
        ));
    }

    let installed = installed_install_script_packages(current_dir)?;

    let mut unmatched = Vec::new();
    let mut targets: Vec<(String, String)> = Vec::new(); // (group_name, pinned_key)

    if all {
        for identity in installed.keys() {
            let group_name = identity
                .rsplit_once('@')
                .map(|(n, _)| n)
                .unwrap_or(identity)
                .to_string();
            targets.push((group_name, identity.clone()));
        }
    } else {
        for requested in packages {
            let mut matches: Vec<String> = installed
                .keys()
                .filter(|identity| {
                    *identity == requested
                        || identity
                            .rsplit_once('@')
                            .map(|(n, _)| n == requested)
                            .unwrap_or(false)
                })
                .cloned()
                .collect();
            if matches.is_empty() {
                unmatched.push(requested.clone());
            } else {
                for m in matches.drain(..) {
                    let group_name = requested.rsplit_once('@').map(|(n, _)| n).unwrap_or(requested).to_string();
                    targets.push((group_name, m));
                }
            }
        }
    }

    if !unmatched.is_empty() {
        return Err(anyhow::anyhow!(
            "npm error code ENOMATCH\nnpm error No installed packages match: {}",
            unmatched.join(", ")
        ));
    }

    let path = current_dir.join("package.json");
    let mut document: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let map = document.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("npm error code EJSONPARSE\nnpm error package.json must contain an object")
    })?;
    let allow = map
        .entry("allowScripts")
        .or_insert_with(|| serde_json::json!({}));
    let allow = allow.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("npm error code EJSONPARSE\nnpm error package.json allowScripts must be an object")
    })?;

    // Apply changes grouped by package name
    let mut summary = Vec::new();
    let mut touched_any = false;

    // Group targets by group_name
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (group, key) in targets {
        groups.entry(group).or_default().push(key);
    }

    for (group_name, keys) in groups {
        let mut changes = Vec::new();
        for key in keys {
            if approved {
                // Pin package: key is name@version
                let current_val = allow.get(&key).and_then(|v| v.as_bool());
                if current_val != Some(true) {
                    allow.insert(key.clone(), serde_json::Value::Bool(true));
                    changes.push(serde_json::json!({
                        "key": key,
                        "change": "added"
                    }));
                    touched_any = true;
                }
            } else {
                // Deny package: key is bare name
                let current_val = allow.get(&group_name).and_then(|v| v.as_bool());
                if current_val != Some(false) {
                    allow.insert(group_name.clone(), serde_json::Value::Bool(false));
                    changes.push(serde_json::json!({
                        "key": group_name,
                        "change": "added"
                    }));
                    touched_any = true;
                }
            }
        }
        summary.push(serde_json::json!({
            "name": group_name,
            "changes": changes
        }));
    }

    if touched_any {
        std::fs::write(&path, serde_json::to_string_pretty(&document)? + "\n")?;
    }

    if json {
        println!("{}", serde_json::json!({ "allowScripts": summary }));
    } else {
        let verb = if approved { "Approved" } else { "Denied" };
        let action_verb = if approved { "approve" } else { "deny" };
        let mut printed_group = false;
        for item in &summary {
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(changes) = item.get("changes").and_then(|v| v.as_array()) {
                if !changes.is_empty() {
                    println!("{verb} {name}:");
                    for c in changes {
                        let key = c.get("key").and_then(|v| v.as_str()).unwrap_or("");
                        let change = c.get("change").and_then(|v| v.as_str()).unwrap_or("");
                        println!("  {change} {key}");
                    }
                    printed_group = true;
                }
            }
        }
        if !printed_group {
            println!("Nothing to {action_verb}; allowScripts unchanged.");
        }
    }

    Ok(())
}

pub(crate) fn run_approve(
    current_dir: &Path,
    packages: &[String],
    all: bool,
    pending: bool,
    json: bool,
) -> Result<()> {
    if pending {
        list_pending_install_scripts(current_dir, json)
    } else {
        apply_policy_changes(current_dir, packages, true, all, json, "approve-scripts")
    }
}

pub(crate) fn run_deny(
    current_dir: &Path,
    packages: &[String],
    all: bool,
    pending: bool,
    json: bool,
) -> Result<()> {
    if pending {
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\nnpm error `npm deny-scripts --allow-scripts-pending` is not supported; run `npm install-scripts ls` to list unreviewed packages."
        ));
    }
    apply_policy_changes(current_dir, packages, false, all, json, "deny-scripts")
}

pub(crate) fn run_install_scripts(
    current_dir: &Path,
    action: Option<&str>,
    packages: &[String],
    all: bool,
    json: bool,
    dry_run: bool,
) -> Result<()> {
    match action.unwrap_or("") {
        "approve" => apply_policy_changes(current_dir, packages, true, all, json, "install-scripts"),
        "deny" => apply_policy_changes(current_dir, packages, false, all, json, "install-scripts"),
        "ls" | "list" => list_pending_install_scripts(current_dir, json),
        "prune" => prune_install_scripts_policy(current_dir, json, dry_run),
        _ => {
            let usage = "Manage install-script approvals for dependencies\n\nUsage:\nnpm install-scripts approve <pkg> [<pkg> ...]\nnpm install-scripts approve --all\nnpm install-scripts deny <pkg> [<pkg> ...]\nnpm install-scripts deny --all\nnpm install-scripts ls\nnpm install-scripts prune\n\nOptions:\n[-a|--all] [--no-allow-scripts-pin] [--dry-run] [--json]\n\n  -a|--all\n    Show or act on all packages, not just the ones your project directly\n\n  --allow-scripts-pin\n    Write pinned (`pkg@version`) entries when approving install scripts.\n\n  --dry-run\n    Indicates that you don't want npm to make any changes and that it should\n\n  --json\n    Whether or not to output JSON data, rather than the normal output.\n\n\nRun \"npm help install-scripts\" for more info";
            let err_lines = usage.lines().map(|l| format!("npm error {l}")).collect::<Vec<_>>().join("\n");
            Err(anyhow::anyhow!(
                "npm error code EUSAGE\n{err_lines}"
            ))
        }
    }
}
