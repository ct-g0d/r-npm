mod audit;
pub mod diagnostics;

use reqwest::Url;
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

        /// Bypass peer dependency installation conflicts
        #[arg(long = "legacy-peer-deps")]
        legacy_peer_deps: bool,

        /// Fail installation if any peer dependencies are missing or invalid
        #[arg(long = "strict-peer-deps")]
        strict_peer_deps: bool,

        /// Resolve and write package-lock.json without extracting or modifying node_modules
        #[arg(long = "package-lock-only")]
        package_lock_only: bool,

        /// Dependency types to omit (dev, optional, peer)
        #[arg(long, value_delimiter = ',')]
        omit: Vec<String>,

        /// Dependency types to include (dev, prod, optional, peer)
        #[arg(long, value_delimiter = ',')]
        include: Vec<String>,

        /// Do not read or write package-lock.json
        #[arg(long = "no-package-lock")]
        no_package_lock: bool,

        /// Ignore or enable package-lock.json
        #[arg(long = "package-lock", num_args = 0..=1, default_missing_value = "true")]
        package_lock: Option<bool>,

        /// Simulate installation without modifying filesystem
        #[arg(long = "dry-run")]
        dry_run: bool,

        /// Override target OS for platform evaluation
        #[arg(long = "os")]
        os: Option<String>,

        /// Override target CPU architecture for platform evaluation
        #[arg(long = "cpu")]
        cpu: Option<String>,

        /// Override target libc for platform evaluation
        #[arg(long = "libc")]
        libc: Option<String>,

        /// Suppress post-install vulnerability checks
        #[arg(long = "no-audit")]
        no_audit: bool,

        /// Submit or suppress audit reports
        #[arg(long = "audit", num_args = 0..=1, default_missing_value = "true")]
        audit: Option<bool>,

        /// Suppress funding notices after install
        #[arg(long = "no-fund")]
        no_fund: bool,

        /// Display or suppress funding notices
        #[arg(long = "fund", num_args = 0..=1, default_missing_value = "true")]
        fund: Option<bool>,

        /// Run against workspace root in addition to specified workspaces
        #[arg(long = "workspace-root", alias = "include-workspace-root")]
        workspace_root: bool,

        /// Specific workspace(s) to target
        #[arg(long = "workspace", short = 'w')]
        workspace: Vec<String>,

        /// Run across all workspaces
        #[arg(long = "workspaces")]
        workspaces: bool,

        /// Save added dependencies to devDependencies
        #[arg(short = 'D', long = "save-dev")]
        save_dev: bool,

        /// Save exact version string (no ^ or ~)
        #[arg(short = 'E', long = "save-exact")]
        save_exact: bool,

        /// Save to dependencies
        #[arg(short = 'P', short_alias = 'S', long = "save-prod", alias = "save")]
        save_prod: bool,

        /// Save to optionalDependencies
        #[arg(short = 'O', long = "save-optional")]
        save_optional: bool,

        /// Save to peerDependencies
        #[arg(long = "save-peer")]
        save_peer: bool,

        /// Do not write or mutate package.json
        #[arg(long = "no-save")]
        no_save: bool,
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

        /// Bypass peer dependency installation conflicts
        #[arg(long = "legacy-peer-deps")]
        legacy_peer_deps: bool,

        /// Fail installation if any peer dependencies are missing or invalid
        #[arg(long = "strict-peer-deps")]
        strict_peer_deps: bool,

        /// Resolve and write package-lock.json without extracting or modifying node_modules
        #[arg(long = "package-lock-only")]
        package_lock_only: bool,

        /// Dependency types to omit (dev, optional, peer)
        #[arg(long, value_delimiter = ',')]
        omit: Vec<String>,

        /// Dependency types to include (dev, prod, optional, peer)
        #[arg(long, value_delimiter = ',')]
        include: Vec<String>,

        /// Do not read or write package-lock.json
        #[arg(long = "no-package-lock")]
        no_package_lock: bool,

        /// Ignore or enable package-lock.json
        #[arg(long = "package-lock", num_args = 0..=1, default_missing_value = "true")]
        package_lock: Option<bool>,

        /// Simulate installation without modifying filesystem
        #[arg(long = "dry-run")]
        dry_run: bool,

        /// Override target OS for platform evaluation
        #[arg(long = "os")]
        os: Option<String>,

        /// Override target CPU architecture for platform evaluation
        #[arg(long = "cpu")]
        cpu: Option<String>,

        /// Override target libc for platform evaluation
        #[arg(long = "libc")]
        libc: Option<String>,

        /// Suppress post-install vulnerability checks
        #[arg(long = "no-audit")]
        no_audit: bool,

        /// Submit or suppress audit reports
        #[arg(long = "audit", num_args = 0..=1, default_missing_value = "true")]
        audit: Option<bool>,

        /// Suppress funding notices after install
        #[arg(long = "no-fund")]
        no_fund: bool,

        /// Display or suppress funding notices
        #[arg(long = "fund", num_args = 0..=1, default_missing_value = "true")]
        fund: Option<bool>,

        /// Run against workspace root in addition to specified workspaces
        #[arg(long = "workspace-root", alias = "include-workspace-root")]
        workspace_root: bool,

        /// Specific workspace(s) to target
        #[arg(long = "workspace", short = 'w')]
        workspace: Vec<String>,

        /// Run across all workspaces
        #[arg(long = "workspaces")]
        workspaces: bool,
    },

    /// Run package test script
    #[command(alias = "t", alias = "tst")]
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

        /// Include workspace root when workspaces are enabled
        #[arg(long = "workspace-root", alias = "include-workspace-root")]
        workspace_root: bool,
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

        /// Bypass peer dependency installation conflicts
        #[arg(long = "legacy-peer-deps")]
        legacy_peer_deps: bool,
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

    /// Remove extraneous packages from node_modules
    Prune {
        /// Dependency types to omit: dev, optional, peer
        #[arg(long, value_name = "TYPE", value_delimiter = ',', num_args = 1..)]
        omit: Vec<String>,

        /// Dependency types to include: dev, prod, optional, peer
        #[arg(long, value_name = "TYPE", value_delimiter = ',', num_args = 1..)]
        include: Vec<String>,

        /// Remove devDependencies (alias for --omit=dev)
        #[arg(long, short = 'p')]
        production: bool,

        /// Report what would be removed without modifying disk
        #[arg(long)]
        dry_run: bool,

        /// Output report in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Manage package.json properties
    Pkg {
        #[command(subcommand)]
        action: PkgAction,
        /// Directory containing package.json (defaults to current dir)
        #[arg(long, default_value = ".", global = true)]
        prefix: PathBuf,
        /// Force JSON output format
        #[arg(long, global = true)]
        json: bool,
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

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum PkgAction {
    /// Retrieve values from package.json
    Get {
        /// Fields to retrieve
        fields: Vec<String>,
    },
    /// Set values in package.json
    Set {
        /// Key=value assignments
        #[arg(required = true)]
        assignments: Vec<String>,
    },
    /// Delete values from package.json
    Delete {
        /// Fields to delete
        #[arg(required = true)]
        fields: Vec<String>,
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
    } else if first == "test" || first == "t" || first == "tst" || first == "start" || first == "restart" || first == "stop" {
        // Trailing arguments for script shortcuts are forwarded payloads to the script
    } else {
        args_to_scan.extend_from_slice(pre_dash_dash);
    }

    let unsupported_flags = [
        "--legacy-peer-deps",
        "--global",
        "-g",
        "--save-bundle",
        "--production",
    ];

    let mut i = 0;
    while i < args_to_scan.len() {
        let arg = &args_to_scan[i];
        // For prune, --production, -p, --omit=..., and --include=... are supported options.
        if first == "prune" && (arg == "--production" || arg == "-p" || arg.starts_with("--omit") || arg.starts_with("--include")) {
            i += 1;
            continue;
        }
        if first == "pkg" {
            i += 1;
            continue;
        }
        // --legacy-peer-deps is supported on install, ci, update (and their aliases)
        if matches!(
            first.as_str(),
            "install" | "i" | "add" | "isntall" | "ci" | "clean-install" | "ic" | "update" | "up"
        ) && (arg == "--legacy-peer-deps" || arg.starts_with("--legacy-peer-deps="))
        {
            i += 1;
            continue;
        }
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

        i += 1;
    }

    None
}

pub(crate) fn parse_omit_and_include_options(omit: &[String], include: &[String]) -> (bool, bool, bool) {
    let mut omit_dev = false;
    let mut omit_optional = false;
    let mut omit_peer = false;

    if let Ok(node_env) = std::env::var("NODE_ENV") {
        if node_env == "production" {
            omit_dev = true;
        }
    }

    for val in omit {
        for part in val.split(',') {
            let trimmed = part.trim().to_ascii_lowercase();
            match trimmed.as_str() {
                "dev" | "development" | "prod" | "production" => omit_dev = true,
                "optional" => omit_optional = true,
                "peer" => omit_peer = true,
                _ => {}
            }
        }
    }

    // --include takes absolute precedence over --omit and NODE_ENV according to npm 11.x semantics
    for val in include {
        for part in val.split(',') {
            let trimmed = part.trim().to_ascii_lowercase();
            match trimmed.as_str() {
                "dev" | "development" | "prod" | "production" => omit_dev = false,
                "optional" => omit_optional = false,
                "peer" => omit_peer = false,
                _ => {}
            }
        }
    }

    (omit_dev, omit_optional, omit_peer)
}

#[allow(dead_code)]
pub(crate) fn parse_omit_options(omit: &[String]) -> (bool, bool, bool) {
    parse_omit_and_include_options(omit, &[])
}

/// Parse a scoped registry flag or argument, e.g. `--@scope:registry=https://...`,
/// `@scope:registry=https://...`, `--scope:registry=https://...`, or `scope:registry=https://...`.
pub(crate) fn parse_scoped_registry_arg(arg: &str) -> Option<(String, Url)> {
    let (key, val_str) = arg.split_once('=')?;
    let clean_key = key.strip_prefix("--").unwrap_or(key).trim();
    let raw_scope = clean_key
        .strip_suffix(":registry")
        .or_else(|| clean_key.strip_suffix("/registry"))?;
    let s = raw_scope.trim();
    if s.is_empty() {
        return None;
    }
    let scope = if !s.starts_with('@') {
        format!("@{s}")
    } else {
        s.to_string()
    };
    let mut parsed_url = Url::parse(val_str.trim()).ok()?;
    if !parsed_url.path().ends_with('/') {
        let new_path = format!("{}/", parsed_url.path());
        parsed_url.set_path(&new_path);
    }
    Some((scope.to_ascii_lowercase(), parsed_url))
}

/// Extract scoped registry flags/arguments from CLI arguments.
///
/// Returns a tuple of `(remaining_arguments, map_of_scope_to_url)`.
/// This strips `--@scope:registry=...` and `@scope:registry=...` from the command line
/// so that positional package lists and clap flag parsing are not polluted.
pub(crate) fn extract_scoped_registries<I, T>(
    raw_args: I,
) -> (Vec<String>, std::collections::BTreeMap<String, Url>)
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<String> = raw_args
        .into_iter()
        .map(|a| a.into().to_string_lossy().to_string())
        .collect();

    let mut remaining = Vec::with_capacity(args.len());
    let mut scoped = std::collections::BTreeMap::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        // 1. Check combined form: `--@scope:registry=https://...` or `@scope:registry=https://...`
        if let Some((scope, url)) = parse_scoped_registry_arg(arg) {
            scoped.insert(scope, url);
            i += 1;
            continue;
        }

        // 2. Check separated form: `--@scope:registry https://...` or `@scope:registry https://...`
        let clean = arg.strip_prefix("--").unwrap_or(arg).trim();
        if (clean.starts_with('@') || clean.contains(':'))
            && (clean.ends_with(":registry") || clean.ends_with("/registry"))
            && i + 1 < args.len()
        {
            let raw_scope = clean
                .strip_suffix(":registry")
                .or_else(|| clean.strip_suffix("/registry"))
                .unwrap();
            let s = raw_scope.trim();
            if !s.is_empty() {
                let scope = if !s.starts_with('@') {
                    format!("@{s}")
                } else {
                    s.to_string()
                };
                if let Ok(mut url) = Url::parse(args[i + 1].trim()) {
                    if !url.path().ends_with('/') {
                        let new_path = format!("{}/", url.path());
                        url.set_path(&new_path);
                    }
                    scoped.insert(scope.to_ascii_lowercase(), url);
                    i += 2;
                    continue;
                }
            }
        }

        remaining.push(arg.clone());
        i += 1;
    }

    (remaining, scoped)
}

/// Resolve the registry URL for a package using a default registry and scoped registries map.
#[allow(dead_code)]
pub(crate) fn resolve_registry_for_package<'a>(
    package_name: &str,
    default_registry: &'a Url,
    scoped_registries: &'a std::collections::BTreeMap<String, Url>,
) -> &'a Url {
    let pkg_trimmed = package_name.trim();
    if pkg_trimmed.starts_with('@') {
        let scope_part = if let Some(slash_idx) = pkg_trimmed.find('/') {
            &pkg_trimmed[..slash_idx]
        } else if let Some(enc_idx) = pkg_trimmed.to_ascii_lowercase().find("%2f") {
            &pkg_trimmed[..enc_idx]
        } else {
            pkg_trimmed
        };
        let scope_lower = scope_part.to_ascii_lowercase();
        if let Some(scoped_url) = scoped_registries.get(&scope_lower) {
            return scoped_url;
        }
    }
    default_registry
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
    LIFECYCLE_NAMES.contains(&name)
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
    workspace_root: bool,
) -> anyhow::Result<()> {
    let manifest_path = current_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow::anyhow!("package.json not found in {}", current_dir.display()));
    }

    let manifest = Manifest::from_file(&manifest_path)?;

    let script = match script {
        Some(s) => s,
        None => {
            if manifest.scripts.is_empty() {
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
                if lifecycle_scripts.is_empty() {
                    println!("Scripts available in {pkg_id} via `rnpm run`:");
                } else {
                    println!("available via `rnpm run`:");
                }
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

        if workspace_root {
            if let Some(cmd) = manifest.scripts.get(&ws_opts.script) {
                let full_cmd = if ws_opts.args.is_empty() {
                    cmd.clone()
                } else {
                    let formatted_args: Vec<String> = ws_opts
                        .args
                        .iter()
                        .map(|a| {
                            if a.contains(' ') || a.contains('\t') || a.contains('"') {
                                format!("\"{}\"", a.replace('"', "\\\""))
                            } else {
                                a.clone()
                            }
                        })
                        .collect();
                    format!("{cmd} {}", formatted_args.join(" "))
                };

                let pkg_name = manifest.name.clone().unwrap_or_else(|| "project".to_string());
                println!(
                    "\n> {}@{} {} {}",
                    pkg_name,
                    manifest.version.as_deref().unwrap_or("0.0.0"),
                    ws_opts.script,
                    current_dir.display()
                );
                println!("> {full_cmd}\n");

                let mut ctx = LifecycleContext::new(
                    &current_dir,
                    &current_dir,
                    &pkg_name,
                    &ws_opts.script,
                    &full_cmd,
                );
                ctx.package_version = manifest.version.clone();

                if !ignore_scripts {
                    let status = execute_lifecycle_script(&ctx)?;
                    if !status.success() {
                        let code = rnpm_lifecycle::extract_exit_status_code(&status);
                        return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                            exit_code: code,
                            message: format!(
                                "Workspace root script '{}' failed with exit code: {}",
                                ws_opts.script, code
                            ),
                        }));
                    }
                }
            } else if !if_present && !has_filter {
                return Err(anyhow::anyhow!("missing script: {}", ws_opts.script));
            }
        }
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
            let formatted_args: Vec<String> = args
                .iter()
                .map(|a| {
                    if a.contains(' ') || a.contains('\t') || a.contains('"') {
                        format!("\"{}\"", a.replace('"', "\\\""))
                    } else {
                        a.clone()
                    }
                })
                .collect();
            format!("{script_cmd} {}", formatted_args.join(" "))
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
        Commands::Install {
            packages,
            registry,
            cache,
            offline,
            ignore_scripts,
            save_dev,
            save_exact,
            save_prod,
            save_optional,
            save_peer,
            no_save,
            package_lock_only,
            omit,
            include,
            no_package_lock,
            package_lock,
            dry_run,
            os,
            cpu,
            libc,
            no_audit,
            audit,
            no_fund,
            fund,
            workspace_root,
            workspace,
            workspaces,
            legacy_peer_deps: _,
            strict_peer_deps: _,
        } => {
            let (omit_dev, omit_optional, omit_peer) = parse_omit_and_include_options(&omit, &include);
            let package_lock_val = if no_package_lock || package_lock == Some(false) {
                false
            } else {
                package_lock.unwrap_or(true)
            };
            let audit_val = if no_audit || audit == Some(false) {
                false
            } else {
                audit.unwrap_or(true)
            };
            let fund_val = if no_fund || fund == Some(false) {
                false
            } else {
                fund.unwrap_or(true)
            };

            let options = InstallOptions {
                project_dir: current_dir.clone(),
                registry_url: registry.clone(),
                cache_dir: cache,
                offline,
                ignore_scripts,
                omit_dev,
                omit_optional,
                omit_peer,
                save_dev,
                save_exact,
                save_prod,
                save_optional,
                save_peer,
                no_save,
                package_lock_only,
                packages,
                include,
                package_lock: package_lock_val,
                no_package_lock,
                dry_run,
                os,
                cpu,
                libc,
                audit: audit_val,
                fund: fund_val,
                workspace_root,
                workspace,
                workspaces,
            };

            let mut installer = Installer::new(options)?;
            let summary = installer.run().await?;

            if dry_run {
                println!(
                    "rnpm: dry-run: would install {} package(s)",
                    summary.packages_installed
                );
            } else {
                println!(
                    "rnpm: successfully installed {} package(s) (cache hits: {}, misses: {})",
                    summary.packages_installed, summary.cache_hits, summary.cache_misses
                );

                if fund_val {
                    let count = audit::count_funding_packages(&current_dir);
                    if count > 0 {
                        println!(
                            "\n{} packages are looking for funding\n  run `rnpm fund`",
                            count
                        );
                    }
                }

                if audit_val {
                    let _ = audit::run_post_install_audit(&current_dir, registry).await;
                }
            }
        }
        Commands::Ci {
            registry,
            cache,
            offline,
            ignore_scripts,
            omit,
            include,
            no_package_lock,
            package_lock,
            dry_run,
            os,
            cpu,
            libc,
            no_audit,
            audit,
            no_fund,
            fund,
            workspace_root,
            workspace,
            workspaces,
            legacy_peer_deps: _,
            strict_peer_deps: _,
            package_lock_only,
        } => {
            let (omit_dev, omit_optional, omit_peer) = parse_omit_and_include_options(&omit, &include);
            let package_lock_val = if no_package_lock || package_lock == Some(false) {
                false
            } else {
                package_lock.unwrap_or(true)
            };
            let audit_val = if no_audit || audit == Some(false) {
                false
            } else {
                audit.unwrap_or(true)
            };
            let fund_val = if no_fund || fund == Some(false) {
                false
            } else {
                fund.unwrap_or(true)
            };

            let options = InstallOptions {
                project_dir: current_dir.clone(),
                registry_url: registry.clone(),
                cache_dir: cache,
                offline,
                ignore_scripts,
                omit_dev,
                omit_optional,
                omit_peer,
                package_lock_only,
                include,
                package_lock: package_lock_val,
                no_package_lock,
                dry_run,
                os,
                cpu,
                libc,
                audit: audit_val,
                fund: fund_val,
                workspace_root,
                workspace,
                workspaces,
                ..Default::default()
            };

            let mut installer = Installer::new(options)?;
            let summary = installer.run_ci().await?;

            if dry_run {
                println!(
                    "rnpm: dry-run: would install {} package(s)",
                    summary.packages_installed
                );
            } else {
                println!(
                    "rnpm: successfully verified and installed {} package(s) from lockfile",
                    summary.packages_installed
                );

                if fund_val {
                    let count = audit::count_funding_packages(&current_dir);
                    if count > 0 {
                        println!(
                            "\n{} packages are looking for funding\n  run `rnpm fund`",
                            count
                        );
                    }
                }

                if audit_val {
                    let _ = audit::run_post_install_audit(&current_dir, registry).await;
                }
            }
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
            workspace_root,
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
                workspace_root,
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
                        ..Default::default()
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
            legacy_peer_deps: _,
        } => {
            let options = InstallOptions {
                project_dir: current_dir,
                registry_url: registry,
                cache_dir: cache,
                offline,
                ignore_scripts,
                ..Default::default()
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
        Commands::Prune {
            omit,
            include,
            production,
            dry_run,
            json,
        } => {
            let (mut omit_dev, omit_optional, omit_peer) = parse_omit_and_include_options(&omit, &include);
            if production {
                let has_dev_included = include.iter().any(|val| {
                    val.split(',').any(|part| {
                        let t = part.trim().to_ascii_lowercase();
                        t == "dev" || t == "development"
                    })
                });
                if !has_dev_included {
                    omit_dev = true;
                }
            }
            let prune_options = rnpm_install::prune::PruneOptions {
                project_dir: current_dir.clone(),
                omit_dev,
                omit_optional,
                omit_peer,
            };

            let installer = Installer::new(InstallOptions {
                project_dir: current_dir,
                ..Default::default()
            })?;

            if dry_run {
                let analysis = installer.analyze_prune(&prune_options)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&analysis)?);
                } else if analysis.extraneous_packages.is_empty() {
                    println!("rnpm: dry-run: no packages would be pruned");
                } else {
                    for pkg in &analysis.extraneous_packages {
                        println!("rnpm: would remove {}", pkg.path);
                    }
                    println!(
                        "rnpm: dry-run: {} package(s) would be removed",
                        analysis.extraneous_packages.len()
                    );
                }
            } else {
                let summary = installer.prune(&prune_options)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                } else if summary.removed_packages.is_empty() {
                    println!("rnpm: no extraneous packages pruned");
                } else {
                    for pkg in &summary.removed_packages {
                        println!("rnpm: removed {pkg}");
                    }
                    println!(
                        "rnpm: successfully pruned {} package(s)",
                        summary.removed_packages.len()
                    );
                }
            }
        }
        Commands::Pkg {
            action,
            prefix,
            json,
        } => {
            let base_path = if prefix.is_absolute() {
                prefix
            } else {
                current_dir.join(&prefix)
            };
            let manifest_path = if base_path.file_name().map_or(false, |f| f == "package.json") {
                base_path
            } else {
                base_path.join("package.json")
            };

            if !manifest_path.exists() {
                return Err(anyhow::anyhow!(
                    "code ENOENT: package.json not found in {}",
                    manifest_path.parent().unwrap_or(&manifest_path).display()
                ));
            };

            match action {
                PkgAction::Get { fields } => {
                    let output = rnpm_core::pkg::pkg_get(&manifest_path, &fields, json)?;
                    println!("{output}");
                }
                PkgAction::Set { assignments } => {
                    rnpm_core::pkg::pkg_set(&manifest_path, &assignments)?;
                }
                PkgAction::Delete { fields } => {
                    rnpm_core::pkg::pkg_delete(&manifest_path, &fields)?;
                }
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

    let (filtered_args, _scoped_registries) = extract_scoped_registries(std::env::args_os());

    if let Some((_, msg)) = check_unsupported_cli_invocation(&filtered_args) {
        eprintln!("{msg}");
        std::process::exit(1);
    }

    let cli = match Cli::try_parse_from(&filtered_args) {
        Ok(c) => c,
        Err(e) => {
            if !e.use_stderr() {
                print!("{e}");
                std::process::exit(0);
            }
            let rendered = e.render().to_string();
            if rendered.contains("unrecognized subcommand") {
                let first_arg = filtered_args.get(1).cloned().unwrap_or_default();
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
