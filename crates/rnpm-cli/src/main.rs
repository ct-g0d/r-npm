mod audit;
pub mod diagnostics;

use std::path::PathBuf;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use rnpm_core::manifest::Manifest;
use rnpm_install::{InstallOptions, Installer, UninstallOptions};
use rnpm_lifecycle::{execute_lifecycle_script, LifecycleContext};

#[derive(Parser, Debug)]
#[command(name = "rnpm", version, about = "High performance Rust implementation of npm workflows")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Install project dependencies or packages
    #[command(alias = "i", alias = "add", alias = "isntall")]
    Install {
        /// Packages to install
        packages: Vec<String>,

        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,

        /// Offline mode (only use cache)
        #[arg(long)]
        offline: bool,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,
    },

    /// Install dependencies directly from package-lock.json (clean slate)
    #[command(alias = "clean-install", alias = "ic")]
    Ci {
        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,

        /// Offline mode (only use cache)
        #[arg(long)]
        offline: bool,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,
    },

    /// Run package test script
    #[command(alias = "t")]
    Test {
        /// Additional arguments passed to the script
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run package start script
    Start {
        /// Additional arguments passed to the script
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run package restart script
    Restart {
        /// Additional arguments passed to the script
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run package stop script
    Stop {
        /// Additional arguments passed to the script
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run arbitrary package scripts
    #[command(alias = "run-script")]
    Run {
        /// Script name declared in package.json
        script: Option<String>,

        /// Additional arguments passed to the script
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Run script across all workspace packages in topological order
        #[arg(long = "workspaces", short = 'w', alias = "ws")]
        workspaces: bool,

        /// Run script in specific workspace package(s)
        #[arg(long = "workspace")]
        workspace: Vec<String>,

        /// Filter workspace packages by name, scope (@scope, @scope/*), glob (ui-*), or path
        #[arg(long = "filter")]
        filter: Vec<String>,

        /// Filter workspace packages by scope or name (alias of filter)
        #[arg(long = "scope")]
        scope: Vec<String>,

        /// If true, do not fail if a package does not declare the script
        #[arg(long)]
        if_present: bool,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,
    },

    /// Run arbitrary package binaries dynamically (npx equivalent)
    #[command(alias = "npx", alias = "x")]
    Exec {
        /// Package name or binary to execute
        package: String,

        /// Additional arguments passed to the binary
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,

        /// Offline mode (only use cache)
        #[arg(long)]
        offline: bool,
    },

    /// Pack project into a tarball archive
    Pack {
        /// Target package directory or spec (defaults to current directory)
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Dry-run mode: do not write the tarball archive to disk
        #[arg(long)]
        dry_run: bool,

        /// Output JSON summary instead of standard text notices
        #[arg(long)]
        json: bool,

        /// Directory where the tarball should be created
        #[arg(long)]
        pack_destination: Option<PathBuf>,
    },

    /// Remove a package from project dependencies
    #[command(alias = "remove", alias = "rm", alias = "r", alias = "un")]
    Uninstall {
        /// Package names to uninstall
        #[arg(required = true)]
        packages: Vec<String>,

        /// Remove only from devDependencies
        #[arg(short = 'D', long = "save-dev")]
        save_dev: bool,

        /// Remove only from optionalDependencies
        #[arg(short = 'O', long = "save-optional")]
        save_optional: bool,

        /// Remove only from regular dependencies
        #[arg(short = 'P', long = "save-prod", alias = "save")]
        save_prod: bool,
    },

    /// Update packages
    #[command(alias = "up")]
    Update {
        /// Specific package names to update
        packages: Vec<String>,

        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,

        /// Offline mode (only use cache)
        #[arg(long)]
        offline: bool,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,
    },

    /// Perform a security audit of dependency vulnerabilities
    Audit {
        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Output audit results as structured JSON
        #[arg(long)]
        json: bool,

        /// Minimum vulnerability level to exit with an error (info, low, moderate, high, critical)
        #[arg(long = "audit-level", default_value = "low")]
        audit_level: String,

        /// Dry-run mode
        #[arg(long)]
        dry_run: bool,
    },

    /// Manage the package cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,

        /// Custom cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,
    },

    /// List installed packages (deferred command)
    #[command(alias = "ls", alias = "la", alias = "ll")]
    List {
        /// Additional arguments passed to list
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Check for outdated packages (deferred command)
    Outdated {
        /// Additional arguments passed to outdated
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// View package information from registry (deferred command)
    #[command(alias = "info", alias = "v", alias = "show")]
    View {
        /// Additional arguments passed to view
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Publish a package to the registry (deferred command)
    Publish {
        /// Additional arguments passed to publish
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum CacheAction {
    /// Delete all data out of the cache folder
    Clean {
        /// Force clean without warning
        #[arg(long, short = 'f')]
        force: bool,

        /// Custom cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,
    },

    /// Verify the contents of the cache folder, garbage collect unneeded data, and validate integrity
    Verify {
        /// Custom cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,
    },
}

pub(crate) fn check_unsupported_cli_invocation<I, T>(raw_args: I) -> Option<(String, String)>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<String> = raw_args
        .into_iter()
        .map(|a| a.into().to_string_lossy().to_string())
        .collect();

    if args.len() < 2 {
        return None;
    }

    let first = &args[1];

    let unsupported_commands = [
        "publish", "login", "adduser", "logout", "token", "team",
        "fix", "outdated", "deprecate",
        "access", "profile", "org", "doctor", "fund", "explain",
        "view", "info", "v", "show", "search", "stars", "star", "unstar",
        "ping", "whoami", "version", "init", "create",
        "list", "ls", "la", "ll",
    ];

    if unsupported_commands.contains(&first.as_str()) {
        return Some((
            "ERR_UNSUPPORTED_COMMAND".to_string(),
            format!(
                "npm error code ERR_UNSUPPORTED_COMMAND\n\
                 npm error The command '{}' is not currently implemented in rnpm.\n\
                 npm error See docs/compatibility-contract.md for the active compatibility surface.",
                first
            ),
        ));
    }

    // Determine the slice of arguments to check for unsupported flags.
    // 1. Any arguments after "--" are forwarded payloads and never scanned.
    let pre_dash_dash = if let Some(dash_dash_idx) = args.iter().position(|a| a == "--") {
        &args[1..dash_dash_idx]
    } else {
        &args[1..]
    };

    // 2. For `run` / `run-script` and `exec` / `x` / `npx`, stop scanning once the script/binary positional target is reached.
    let mut args_to_scan = Vec::new();
    if first == "run" || first == "run-script" {
        let mut idx = 1;
        while idx < pre_dash_dash.len() {
            let arg = &pre_dash_dash[idx];
            if arg.starts_with('-') {
                args_to_scan.push(arg.clone());
                if (arg == "--workspace" || arg == "--filter" || arg == "--scope")
                    && idx + 1 < pre_dash_dash.len()
                    && !pre_dash_dash[idx + 1].starts_with('-')
                {
                    idx += 1;
                }
            } else {
                break;
            }
            idx += 1;
        }
    } else if first == "exec" || first == "x" || first == "npx" {
        let mut idx = 1;
        while idx < pre_dash_dash.len() {
            let arg = &pre_dash_dash[idx];
            if arg.starts_with('-') {
                args_to_scan.push(arg.clone());
                if (arg == "--registry" || arg == "--cache")
                    && idx + 1 < pre_dash_dash.len()
                    && !pre_dash_dash[idx + 1].starts_with('-')
                {
                    idx += 1;
                }
            } else {
                break;
            }
            idx += 1;
        }
    } else if first == "test" || first == "t" || first == "start" || first == "restart" || first == "stop" {
        // Trailing arguments for script shortcuts are forwarded payloads to the script
    } else {
        args_to_scan.extend_from_slice(pre_dash_dash);
    }

    let unsupported_flags = [
        "--legacy-peer-deps",
        "--global",
        "-g",
        "--package-lock-only",
        "--save-bundle",
        "--save-exact",
        "-E",
        "--no-save",
        "--save-peer",
        "--production",
        "--omit=dev",
        "--omit=optional",
        "--omit=peer",
    ];

    let mut i = 0;
    while i < args_to_scan.len() {
        let arg = &args_to_scan[i];
        if unsupported_flags.contains(&arg.as_str()) {
            return Some((
                "ERR_UNSUPPORTED_FLAG".to_string(),
                format!(
                    "npm error code ERR_UNSUPPORTED_FLAG\n\
                     npm error The flag '{}' is not supported by rnpm.\n\
                     npm error See docs/compatibility-contract.md for supported options.",
                    arg
                ),
            ));
        }

        if arg == "--omit" {
            let flag_str = if i + 1 < args_to_scan.len() && !args_to_scan[i + 1].starts_with('-') {
                format!("--omit {}", args_to_scan[i + 1])
            } else {
                "--omit".to_string()
            };
            return Some((
                "ERR_UNSUPPORTED_FLAG".to_string(),
                format!(
                    "npm error code ERR_UNSUPPORTED_FLAG\n\
                     npm error The flag '{}' is not supported by rnpm.\n\
                     npm error See docs/compatibility-contract.md for supported options.",
                    flag_str
                ),
            ));
        }
        i += 1;
    }

    None
}

pub(crate) fn print_structured_error(err: &anyhow::Error) {
    let diag = diagnostics::classify_error(err);
    eprintln!("{}", diag.format_npm());
}

fn is_lifecycle_script(name: &str) -> bool {
    const LIFECYCLE_NAMES: &[&str] = &[
        "test", "start", "restart", "stop",
        "prepare", "prepublishOnly", "prepack", "postpack",
        "dependencies", "preinstall", "install", "postinstall",
        "prepublish", "publish", "postpublish",
        "prerestart", "postrestart",
        "prestart", "poststart",
        "prestop", "poststop",
        "pretest", "posttest",
        "preuninstall", "uninstall", "postuninstall",
        "preversion", "version", "postversion",
    ];
    LIFECYCLE_NAMES.contains(&name) || name.starts_with("pre") || name.starts_with("post")
}

#[allow(clippy::too_many_arguments)]
async fn execute_run(
    current_dir: PathBuf,
    script: Option<String>,
    args: Vec<String>,
    workspaces: bool,
    workspace: Vec<String>,
    filter: Vec<String>,
    scope: Vec<String>,
    if_present: bool,
    ignore_scripts: bool,
) -> anyhow::Result<()> {
    let manifest_path = current_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow::anyhow!("code ENOENT: package.json not found in {}", current_dir.display()));
    }

    let manifest = Manifest::from_file(&manifest_path)?;

    let script = match script {
        Some(s) => s,
        None => {
            if manifest.scripts.is_empty() {
                println!("No scripts found in package.json");
                return Ok(());
            }

            let mut lifecycle_scripts = Vec::new();
            let mut available_scripts = Vec::new();

            for (name, cmd) in &manifest.scripts {
                if is_lifecycle_script(name) {
                    lifecycle_scripts.push((name, cmd));
                } else {
                    available_scripts.push((name, cmd));
                }
            }

            let pkg_id = match (&manifest.name, &manifest.version) {
                (Some(name), Some(version)) => format!("{name}@{version}"),
                (Some(name), None) => name.clone(),
                (None, Some(version)) => format!("project@{version}"),
                (None, None) => "project".to_string(),
            };

            if !lifecycle_scripts.is_empty() {
                println!("Lifecycle scripts included in {pkg_id}:");
                for (name, cmd) in &lifecycle_scripts {
                    println!("  {name}");
                    println!("    {cmd}");
                }
            }

            if !available_scripts.is_empty() {
                println!("Available scripts via `rnpm run-script <name>`:");
                for (name, cmd) in &available_scripts {
                    println!("  {name}");
                    println!("    {cmd}");
                }
            }

            return Ok(());
        }
    };

    let has_filter = !workspace.is_empty() || !filter.is_empty() || !scope.is_empty();
    if workspaces || has_filter {
        let discovered = rnpm_core::workspace::discover_workspaces_from_manifest(&current_dir, &manifest)
            .map_err(|e| anyhow::anyhow!("Failed to discover workspaces: {e}"))?;

        if discovered.is_empty() {
            return Err(anyhow::anyhow!("npm error code ENOWORKSPACES\nnpm error No workspaces found in {}", current_dir.display()));
        }

        let graph = rnpm_solver::WorkspaceDependencyGraph::construct(&discovered)
            .map_err(|e| anyhow::anyhow!("Workspace dependency graph error: {e}"))?;

        let members: Vec<rnpm_lifecycle::WorkspaceScriptMember> = discovered
            .into_iter()
            .map(|m| rnpm_lifecycle::WorkspaceScriptMember {
                name: m.name,
                path: m.path,
                manifest: m.manifest,
            })
            .collect();

        let mut combined_filters = Vec::new();
        combined_filters.extend(workspace);
        combined_filters.extend(filter);
        combined_filters.extend(scope);

        let filter_opt = if combined_filters.is_empty() {
            None
        } else {
            Some(combined_filters)
        };

        let ws_opts = rnpm_lifecycle::WorkspaceRunOptions {
            script,
            args,
            ignore_scripts,
            if_present,
            filter_members: filter_opt,
        };

        let summary = rnpm_lifecycle::execute_workspace_scripts_topological(
            &current_dir,
            &members,
            &graph.topological_order,
            &ws_opts,
        ).await?;

        println!(
            "rnpm: executed script in {} workspace package(s) ({} skipped)",
            summary.executed_packages.len(),
            summary.skipped_packages.len()
        );
    } else {
        let script_cmd = match manifest.scripts.get(&script) {
            Some(cmd) => cmd,
            None => {
                return Err(anyhow::anyhow!("missing script: {script}"));
            }
        };

        let full_cmd = if args.is_empty() {
            script_cmd.clone()
        } else {
            format!("{script_cmd} {}", args.join(" "))
        };

        let pkg_name = manifest.name.clone().unwrap_or_else(|| "project".to_string());
        let mut ctx = LifecycleContext::new(&current_dir, &current_dir, &pkg_name, &script, &full_cmd);
        ctx.package_version = manifest.version.clone();

        if !ignore_scripts {
            let status = execute_lifecycle_script(&ctx)?;
            if !status.success() {
                let code = rnpm_lifecycle::extract_exit_status_code(&status);
                return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                    exit_code: code,
                    message: format!("Lifecycle script '{}' failed with exit code: {}", script, code),
                }));
            }
        }
    }

    Ok(())
}

pub(crate) async fn run_cli(cli: Cli, dir: Option<PathBuf>) -> anyhow::Result<()> {
    let current_dir = match dir {
        Some(d) => d,
        None => std::env::current_dir()?,
    };

    match cli.command {
        Commands::Install { registry, cache, offline, ignore_scripts, .. } => {
            let options = InstallOptions {
                project_dir: current_dir,
                registry_url: registry,
                cache_dir: cache,
                offline,
                ignore_scripts,
            };

            let mut installer = Installer::new(options)?;
            let summary = installer.run().await?;

            println!(
                "rnpm: successfully installed {} package(s) (cache hits: {}, misses: {})",
                summary.packages_installed, summary.cache_hits, summary.cache_misses
            );
        }
        Commands::Ci { registry, cache, offline, ignore_scripts } => {
            let options = InstallOptions {
                project_dir: current_dir,
                registry_url: registry,
                cache_dir: cache,
                offline,
                ignore_scripts,
            };

            let mut installer = Installer::new(options)?;
            let summary = installer.run_ci().await?;

            println!(
                "rnpm: successfully verified and installed {} package(s) from lockfile",
                summary.packages_installed
            );
        }
        Commands::Test { args } => {
            execute_run(
                current_dir,
                Some("test".to_string()),
                args,
                false,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
                false,
            ).await?;
        }
        Commands::Start { args } => {
            execute_run(
                current_dir,
                Some("start".to_string()),
                args,
                false,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
                false,
            ).await?;
        }
        Commands::Restart { args } => {
            execute_run(
                current_dir,
                Some("restart".to_string()),
                args,
                false,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
                false,
            ).await?;
        }
        Commands::Stop { args } => {
            execute_run(
                current_dir,
                Some("stop".to_string()),
                args,
                false,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
                false,
            ).await?;
        }
        Commands::Run {
            script,
            args,
            workspaces,
            workspace,
            filter,
            scope,
            if_present,
            ignore_scripts,
        } => {
            execute_run(
                current_dir,
                script,
                args,
                workspaces,
                workspace,
                filter,
                scope,
                if_present,
                ignore_scripts,
            ).await?;
        }
        Commands::Exec {
            package,
            args,
            registry,
            cache,
            offline,
        } => {
            // 1. Check local node_modules/.bin first
            let local_bin = rnpm_lifecycle::find_local_binary(&current_dir, &package);
            let binary_to_run = if let Some(bin_path) = local_bin {
                bin_path
            } else {
                // Not found locally: resolve and install into ephemeral _npx cache
                let cache_path = cache.clone().unwrap_or_else(|| {
                    if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
                        PathBuf::from(appdata).join("rnpm").join("cache")
                    } else {
                        std::env::temp_dir().join(".rnpm-cache")
                    }
                });

                let safe_spec: String = package
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
                    .collect();

                let npx_env_dir = cache_path.join("_npx").join(&safe_spec);
                let bin_target = rnpm_lifecycle::find_local_binary(&npx_env_dir, &package);

                if let Some(target) = bin_target {
                    target
                } else {
                    if offline {
                        return Err(anyhow::anyhow!(
                            "Package '{}' is not installed locally and offline mode prevents dynamic fetching",
                            package
                        ));
                    }

                    std::fs::create_dir_all(&npx_env_dir)?;

                    // Parse package and version/range
                    let (pkg_name, version_req) = if let Some(stripped) = package.strip_prefix('@') {
                        if let Some(idx) = stripped.find('@') {
                            (format!("@{}", &stripped[..idx]), stripped[idx + 1..].to_string())
                        } else {
                            (package.clone(), "*".to_string())
                        }
                    } else if let Some(idx) = package.find('@') {
                        (package[..idx].to_string(), package[idx + 1..].to_string())
                    } else {
                        (package.clone(), "*".to_string())
                    };

                    let minimal_manifest = serde_json::json!({
                        "name": "rnpm-exec-env",
                        "version": "1.0.0",
                        "dependencies": {
                            pkg_name.clone(): version_req
                        }
                    });

                    std::fs::write(
                        npx_env_dir.join("package.json"),
                        serde_json::to_string_pretty(&minimal_manifest)?,
                    )?;

                    let install_options = InstallOptions {
                        project_dir: npx_env_dir.clone(),
                        registry_url: registry,
                        cache_dir: Some(cache_path.clone()),
                        offline: false,
                        ignore_scripts: false,
                    };

                    let mut installer = Installer::new(install_options)?;
                    installer.run().await?;

                    // Now locate binary in npx_env_dir
                    if let Some(target) = rnpm_lifecycle::find_local_binary(&npx_env_dir, &package) {
                        target
                    } else if let Some(target) = rnpm_lifecycle::find_local_binary(&npx_env_dir, &pkg_name) {
                        target
                    } else {
                        // Scan .bin folder in npx_env_dir for any executable
                        let bin_dir = npx_env_dir.join("node_modules").join(".bin");
                        let mut found = None;
                        if bin_dir.is_dir() {
                            if let Ok(entries) = std::fs::read_dir(&bin_dir) {
                                for entry in entries.flatten() {
                                    let p = entry.path();
                                    if p.is_file() {
                                        found = Some(p);
                                        break;
                                    }
                                }
                            }
                        }
                        found.ok_or_else(|| anyhow::anyhow!(
                            "Could not determine binary to run for package '{}'",
                            package
                        ))?
                    }
                }
            };

            // Execute the resolved binary with ancestor bin directories prepended to PATH
            let mut path_entries = rnpm_lifecycle::collect_ancestor_bin_dirs(&current_dir);
            if let Some(parent_bin) = binary_to_run.parent() {
                if !path_entries.contains(&parent_bin.to_path_buf()) {
                    path_entries.insert(0, parent_bin.to_path_buf());
                }
            }

            let status = rnpm_lifecycle::execute_binary_async(
                &binary_to_run,
                &args,
                &current_dir,
                &path_entries,
                &std::collections::HashMap::new(),
            ).await?;

            if !status.success() {
                let code = rnpm_lifecycle::extract_exit_status_code(&status);
                return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                    exit_code: code,
                    message: format!("Process exited with status code: {}", code),
                }));
            }
        }
        Commands::Pack {
            target,
            dry_run,
            json,
            pack_destination,
        } => {
            let package_dir = if target.is_absolute() {
                target
            } else {
                current_dir.join(target)
            };

            let manifest_path = package_dir.join("package.json");
            if !manifest_path.exists() {
                return Err(anyhow::anyhow!(
                    "code ENOENT: package.json not found in {}",
                    package_dir.display()
                ));
            }

            let (summary, tarball_bytes) = match rnpm_fs::pack_directory(
                &package_dir,
                None,
            ) {
                Ok(res) => res,
                Err(e) => {
                    return Err(anyhow::anyhow!("pack failed: {e}"));
                }
            };

            let dest_dir = pack_destination.unwrap_or_else(|| current_dir.clone());
            let final_tarball_path = dest_dir.join(&summary.filename);

            if !dry_run {
                if let Err(e) = std::fs::write(&final_tarball_path, &tarball_bytes) {
                    return Err(anyhow::anyhow!(
                        "failed to write {}: {e}",
                        final_tarball_path.display()
                    ));
                }
            }

            if json {
                let json_output = serde_json::json!([
                    {
                        "id": format!("{}@{}", summary.name, summary.version),
                        "name": summary.name,
                        "version": summary.version,
                        "size": summary.package_size,
                        "unpackedSize": summary.unpacked_size,
                        "shasum": summary.shasum,
                        "integrity": summary.integrity,
                        "filename": summary.filename,
                        "files": summary.files.iter().map(|f| serde_json::json!({
                            "path": f.path,
                            "size": f.size,
                            "mode": f.mode,
                        })).collect::<Vec<_>>(),
                        "entryCount": summary.entry_count,
                        "bundled": summary.bundled,
                    }
                ]);
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            } else {
                print_pack_notices(&summary);
                println!("{}", summary.filename);
            }
        }
        Commands::Uninstall {
            packages,
            save_dev,
            save_optional,
            save_prod,
        } => {
            let options = InstallOptions {
                project_dir: current_dir,
                ..Default::default()
            };
            let installer = Installer::new(options)?;
            let uninstall_options = UninstallOptions {
                packages,
                save_dev,
                save_optional,
                save_prod,
            };
            let summary = installer.uninstall(&uninstall_options)?;
            println!(
                "rnpm: removed {} package(s), pruned {} unreferenced dependencies",
                summary.removed_packages.len(),
                summary.pruned_dependencies.len()
            );
        }
        Commands::Update {
            packages,
            registry,
            cache,
            offline,
            ignore_scripts,
        } => {
            let options = InstallOptions {
                project_dir: current_dir,
                registry_url: registry,
                cache_dir: cache,
                offline,
                ignore_scripts,
            };

            let mut installer = Installer::new(options)?;
            let summary = installer.update(&packages).await?;

            if summary.packages_updated == 0 {
                println!("rnpm: up to date");
            } else {
                for pkg in &summary.updated_packages {
                    let old_v = summary.old_versions.get(pkg).map(|s| s.as_str()).unwrap_or("none");
                    let new_v = summary.new_versions.get(pkg).map(|s| s.as_str()).unwrap_or("unknown");
                    println!("rnpm: updated {pkg} {old_v} -> {new_v}");
                }
                println!(
                    "rnpm: successfully updated {} package(s) (cache hits: {}, misses: {})",
                    summary.packages_updated, summary.cache_hits, summary.cache_misses
                );
            }
        }
        Commands::Audit {
            registry,
            json,
            audit_level,
            ..
        } => {
            audit::run_audit(&current_dir, registry, json, &audit_level).await?;
        }
        Commands::Cache { action, cache } => {
            let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
            let cache_path = cache
                .or_else(|| match &action {
                    CacheAction::Clean { cache: c, .. } => c.clone(),
                    CacheAction::Verify { cache: c } => c.clone(),
                })
                .unwrap_or_else(|| {
                    if let Some(user_cache) = config.npmrc.settings.get("cache") {
                        PathBuf::from(user_cache)
                    } else if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
                        PathBuf::from(appdata).join("rnpm").join("cache")
                    } else {
                        std::env::temp_dir().join(".rnpm-cache")
                    }
                });

            let cache = rnpm_cache::Cache::new(&cache_path)?;

            match action {
                CacheAction::Clean { force, .. } => {
                    if !force {
                        eprintln!("npm error code EUSAGE");
                        eprintln!("npm error As of npm@5, the npm cache self-heals from corruption issues");
                        eprintln!("npm error and data extracted from the cache is guaranteed to be valid.");
                        eprintln!("npm error If you want to make sure everything is healthy, use 'rnpm cache verify' instead.");
                        eprintln!("npm error If you are sure you want to delete the entire cache, run:");
                        eprintln!("npm error   rnpm cache clean --force");
                        std::process::exit(1);
                    }
                    cache.clean()?;
                    println!("rnpm: cache cleared successfully ({})", cache_path.display());
                }
                CacheAction::Verify { .. } => {
                    let start = std::time::Instant::now();
                    let report = cache.verify()?;
                    let elapsed = start.elapsed().as_secs_f64();
                    println!("Cache verified and compacted ({})", cache_path.display());
                    println!("Content verified: {} ({} bytes)", report.verified_blobs, report.total_blob_bytes);
                    println!("Index entries: {}", report.verified_indices);
                    if report.corrupted_blobs > 0 || report.corrupted_indices > 0 || report.orphaned_indices > 0 || report.stale_temp_files_cleaned > 0 {
                        println!(
                            "Cleaned: {} corrupt blob(s), {} corrupt index file(s), {} orphaned index pointer(s), {} stale temp file(s)",
                            report.corrupted_blobs, report.corrupted_indices, report.orphaned_indices, report.stale_temp_files_cleaned
                        );
                    }
                    println!("Finished in {:.3}s", elapsed);
                }
            }
        }
        Commands::List { .. } => {
            return Err(anyhow::anyhow!(
                "npm error code ERR_UNSUPPORTED_COMMAND\n\
                 npm error The command 'list' is not currently implemented in rnpm.\n\
                 npm error See docs/compatibility-contract.md for the active compatibility surface."
            ));
        }
        Commands::Outdated { .. } => {
            return Err(anyhow::anyhow!(
                "npm error code ERR_UNSUPPORTED_COMMAND\n\
                 npm error The command 'outdated' is not currently implemented in rnpm.\n\
                 npm error See docs/compatibility-contract.md for the active compatibility surface."
            ));
        }
        Commands::View { .. } => {
            return Err(anyhow::anyhow!(
                "npm error code ERR_UNSUPPORTED_COMMAND\n\
                 npm error The command 'view' is not currently implemented in rnpm.\n\
                 npm error See docs/compatibility-contract.md for the active compatibility surface."
            ));
        }
        Commands::Publish { .. } => {
            return Err(anyhow::anyhow!(
                "npm error code ERR_UNSUPPORTED_COMMAND\n\
                 npm error The command 'publish' is not currently implemented in rnpm.\n\
                 npm error See docs/compatibility-contract.md for the active compatibility surface."
            ));
        }
    }

    Ok(())
}

fn print_pack_notices(summary: &rnpm_fs::PackSummary) {
    eprintln!("npm notice");
    eprintln!("npm notice package: {}@{}", summary.name, summary.version);
    eprintln!("npm notice Tarball Contents");
    for file in &summary.files {
        eprintln!("npm notice {} {}", format_bytes(file.size, false), file.path);
    }
    if !summary.bundled.is_empty() {
        eprintln!("npm notice Bundled Dependencies");
        for b in &summary.bundled {
            eprintln!("npm notice {b}");
        }
    }
    eprintln!("npm notice Tarball Details");
    eprintln!("npm notice name: {}", summary.name);
    eprintln!("npm notice version: {}", summary.version);
    eprintln!("npm notice filename: {}", summary.filename);
    eprintln!("npm notice package size: {}", format_bytes(summary.package_size, true));
    eprintln!("npm notice unpacked size: {}", format_bytes(summary.unpacked_size, true));
    eprintln!("npm notice shasum: {}", summary.shasum);
    let integrity_short = if summary.integrity.len() >= 80 {
        format!("{}[...]{}", &summary.integrity[..20], &summary.integrity[summary.integrity.len().saturating_sub(14)..])
    } else {
        summary.integrity.clone()
    };
    eprintln!("npm notice integrity: {}", integrity_short);
    if !summary.bundled.is_empty() {
        eprintln!("npm notice bundled deps: {}", summary.bundled.len());
        eprintln!("npm notice bundled files: {}", summary.entry_count.saturating_sub(summary.files.len()));
        eprintln!("npm notice own files: {}", summary.files.len());
    }
    eprintln!("npm notice total files: {}", summary.entry_count);
    eprintln!("npm notice");
}

fn format_bytes(bytes: u64, space: bool) -> String {
    let spacer = if space { " " } else { "" };
    if bytes < 1000 {
        format!("{bytes}{spacer}B")
    } else if bytes < 999_950 {
        format!("{:.1}{spacer}kB", bytes as f64 / 1000.0)
    } else if bytes < 999_950_000 {
        format!("{:.1}{spacer}MB", bytes as f64 / 1_000_000.0)
    } else {
        format!("{:.1}{spacer}GB", bytes as f64 / 1_000_000_000.0)
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    if let Some((_, msg)) = check_unsupported_cli_invocation(std::env::args_os()) {
        eprintln!("{msg}");
        std::process::exit(1);
    }

    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            if !e.use_stderr() {
                print!("{e}");
                std::process::exit(0);
            }
            let rendered = e.render().to_string();
            if rendered.contains("unrecognized subcommand") {
                let first_arg = std::env::args().nth(1).unwrap_or_default();
                eprintln!("npm error code ERR_UNSUPPORTED_COMMAND");
                eprintln!("npm error The command '{first_arg}' is not currently implemented in rnpm.");
                eprintln!("npm error See docs/compatibility-contract.md for the active compatibility surface.");
            } else {
                eprintln!("{rendered}");
            }
            std::process::exit(1);
        }
    };

    if let Err(err) = run_cli(cli, None).await {
        if let Some(exit_err) = err.downcast_ref::<rnpm_lifecycle::ScriptExitError>() {
            std::process::exit(exit_err.exit_code);
        }
        if err.is::<audit::AuditThresholdError>() {
            std::process::exit(1);
        }
        print_structured_error(&err);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests;
