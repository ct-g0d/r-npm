use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

pub(crate) struct InitCommandArgs {
    pub initializer: Option<String>,
    pub args: Vec<String>,
    pub yes: bool,
    pub scope: Option<String>,
    pub registry: Option<String>,
    pub cache: Option<PathBuf>,
    pub offline: bool,
    pub workspace: Vec<String>,
    pub workspaces: bool,
    pub workspace_root: bool,
}

pub(crate) async fn run(args: InitCommandArgs, current_dir: PathBuf) -> Result<()> {
    let has_ws = !args.workspace.is_empty() || args.workspaces;
    if !has_ws {
        return run_single(args, current_dir).await;
    }

    run_workspaces(args, current_dir).await
}

async fn run_single(args: InitCommandArgs, target_dir: PathBuf) -> Result<()> {
    if let Some(init_pkg) = args.initializer {
        let transformed = crate::init::transform_initializer(&init_pkg);
        // `npm init vite app -- --template x`: the separator belongs to npm,
        // the initializer only sees `app --template x`.
        let mut forwarded = args.args.clone();
        if let Some(pos) = forwarded.iter().position(|a| a == "--") {
            forwarded.remove(pos);
        }
        let consent = crate::resolve_npx_consent(&target_dir, args.yes, false);
        crate::execute_exec(
            &target_dir,
            &transformed,
            &[],
            &forwarded,
            args.registry,
            args.cache,
            args.offline,
            true,
            consent,
        )
        .await?;
    } else {
        let init_opts = crate::init::InitOptions {
            yes: args.yes,
            scope: args.scope,
            directory: target_dir,
        };
        let stdin = std::io::stdin();
        let mut stdin_lock = stdin.lock();
        let stdout = std::io::stdout();
        let mut stdout_lock = stdout.lock();
        crate::init::run_init(&init_opts, &mut stdin_lock, &mut stdout_lock)?;
    }
    Ok(())
}

async fn run_workspaces(args: InitCommandArgs, current_dir: PathBuf) -> Result<()> {
    let start_time = std::time::Instant::now();
    let root_manifest_path = current_dir.join("package.json");

    if args.workspace_root {
        if !root_manifest_path.exists() {
            let root_args = InitCommandArgs {
                initializer: args.initializer.clone(),
                args: args.args.clone(),
                yes: args.yes,
                scope: args.scope.clone(),
                registry: args.registry.clone(),
                cache: args.cache.clone(),
                offline: args.offline,
                workspace: Vec::new(),
                workspaces: false,
                workspace_root: false,
            };
            run_single(root_args, current_dir.clone()).await?;
        }
    } else if !root_manifest_path.exists() {
        eprintln!("npm warn init Missing package.json. Try with `--include-workspace-root`.");
        return Err(anyhow!(
            "npm error code ENOENT\nnpm error syscall open\nnpm error path {}\nnpm error errno -4058\nnpm error enoent Could not read package.json: Error: ENOENT: no such file or directory, open '{}'\nnpm error enoent This is related to npm not being able to find a file.",
            root_manifest_path.display(),
            root_manifest_path.display(),
        ));
    }

    // Determine target workspace directories
    let target_workspaces: Vec<PathBuf> = if !args.workspace.is_empty() {
        args.workspace
            .iter()
            .map(|w| current_dir.join(w))
            .collect()
    } else {
        let members = rnpm_core::workspace::discover_workspaces(&current_dir).unwrap_or_default();
        members.into_iter().map(|m| m.path).collect()
    };

    if target_workspaces.is_empty() {
        return Ok(());
    }

    let mut created_or_updated = 0;
    for ws_path in &target_workspaces {
        std::fs::create_dir_all(ws_path).with_context(|| {
            format!("Failed to create workspace directory at '{}'", ws_path.display())
        })?;

        let single_args = InitCommandArgs {
            initializer: args.initializer.clone(),
            args: args.args.clone(),
            yes: args.yes,
            scope: args.scope.clone(),
            registry: args.registry.clone(),
            cache: args.cache.clone(),
            offline: args.offline,
            workspace: Vec::new(),
            workspaces: false,
            workspace_root: false,
        };
        run_single(single_args, ws_path.clone()).await?;

        // Register in root package.json if not already covered
        register_workspace_in_root(&current_dir, ws_path)?;
        created_or_updated += 1;
    }

    let elapsed_str = crate::format_duration(start_time.elapsed());
    let pkg_str = if created_or_updated == 1 { "package" } else { "packages" };
    println!("\nadded {created_or_updated} {pkg_str} in {elapsed_str}");

    Ok(())
}

pub(crate) fn register_workspace_in_root(root_dir: &Path, workspace_path: &Path) -> Result<()> {
    let root_manifest_path = root_dir.join("package.json");
    if !root_manifest_path.exists() {
        return Ok(());
    }
    if !workspace_path.join("package.json").exists() {
        return Ok(());
    }

    let root_manifest = rnpm_core::manifest::Manifest::from_file(&root_manifest_path)
        .context("Failed to read root package.json")?;

    let rel_path = workspace_path
        .strip_prefix(root_dir)
        .unwrap_or(workspace_path);
    let posix_rel = rel_path.to_string_lossy().replace('\\', "/");
    let clean_rel = posix_rel
        .trim_start_matches("./")
        .trim_end_matches('/')
        .to_string();

    let patterns = root_manifest.workspace_patterns();

    // 1. Direct pattern check
    let already_in_patterns = patterns.iter().any(|p| {
        let norm_p = p.replace('\\', "/");
        let norm_p = norm_p.trim_start_matches("./").trim_end_matches('/');
        norm_p == clean_rel
    });
    if already_in_patterns {
        return Ok(());
    }

    // 2. Glob match check
    if let Ok(matched_dirs) = rnpm_core::workspace::match_glob_patterns(root_dir, &patterns) {
        let ws_canon = workspace_path.canonicalize().ok();
        if matched_dirs.iter().any(|d| {
            d == workspace_path || (ws_canon.is_some() && d.canonicalize().ok() == ws_canon)
        }) {
            return Ok(());
        }
    }

    // 3. Not covered: add clean_rel to root package.json preserving formatting and key order
    let mut raw_val = root_manifest.raw_json.unwrap_or_else(|| {
        rnpm_core::ordered_json::OrderedJsonValue::Object(rnpm_core::ordered_json::OrderedJsonMap::new())
    });
    let map = raw_val
        .as_object_mut()
        .ok_or_else(|| anyhow!("Root package.json root is not an object"))?;

    let new_entry = rnpm_core::ordered_json::OrderedJsonValue::String(clean_rel);

    if let Some(ws_val) = map.get_mut("workspaces") {
        match ws_val {
            rnpm_core::ordered_json::OrderedJsonValue::Array(arr) => {
                arr.push(new_entry);
            }
            rnpm_core::ordered_json::OrderedJsonValue::Object(obj) => {
                if let Some(rnpm_core::ordered_json::OrderedJsonValue::Array(pkg_arr)) =
                    obj.get_mut("packages")
                {
                    pkg_arr.push(new_entry);
                } else {
                    obj.insert(
                        "packages".to_string(),
                        rnpm_core::ordered_json::OrderedJsonValue::Array(vec![new_entry]),
                    );
                }
            }
            _ => {
                map.insert(
                    "workspaces".to_string(),
                    rnpm_core::ordered_json::OrderedJsonValue::Array(vec![new_entry]),
                );
            }
        }
    } else {
        map.insert(
            "workspaces".to_string(),
            rnpm_core::ordered_json::OrderedJsonValue::Array(vec![new_entry]),
        );
    }

    let formatted =
        rnpm_core::manifest::Manifest::format_json_value(&raw_val, &root_manifest.format)
            .context("Failed to serialize root package.json")?;
    std::fs::write(&root_manifest_path, formatted)?;
    Ok(())
}
