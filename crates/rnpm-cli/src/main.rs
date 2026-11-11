#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::too_many_arguments)]

mod audit;
mod explain;
pub mod commands;
pub mod diagnostics;
pub mod diff;
pub mod doctor;
pub mod init;
pub mod inspect_tree;
pub mod list;
pub mod outdated;
pub mod query;
pub mod sbom;
pub mod version;
pub mod view;

use clap::{CommandFactory, Parser, Subcommand};
use reqwest::Url;
use rnpm_core::manifest::Manifest;
use rnpm_install::{InstallOptions, Installer, UninstallOptions};
use rnpm_lifecycle::{execute_lifecycle_script, LifecycleContext};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser, Debug)]
#[command(
    name = "rnpm",
    version,
    about = "High performance Rust implementation of npm workflows",
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Install project dependencies or packages
    #[command(
        alias = "i",
        alias = "add",
        alias = "isntall",
        alias = "in",
        alias = "ins",
        alias = "inst",
        alias = "insta",
        alias = "instal",
        alias = "isnt",
        alias = "isnta",
        alias = "isntal"
    )]
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

        /// Force installation even if dependencies appear up to date
        #[arg(short = 'f', long = "force")]
        force: bool,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,

        /// Run scripts with direct stdio inheritance
        #[arg(long = "foreground-scripts")]
        foreground_scripts: bool,

        /// Enforce strict sandbox policy
        #[arg(long = "strict-sandbox")]
        strict_sandbox: bool,

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

        /// Write package-lock.json using npm's legacy format (1, 2, or 3)
        #[arg(long = "lockfile-version", value_parser = clap::value_parser!(u32).range(1..=3))]
        lockfile_version: Option<u32>,

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

        /// Prefix to use before version in package.json (e.g. '^', '~', or '')
        #[arg(long = "save-prefix")]
        save_prefix: Option<String>,

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

        /// Install into global prefix
        #[arg(short = 'g', long = "global")]
        global: bool,

        /// Custom installation prefix directory
        #[arg(long = "prefix")]
        prefix: Option<PathBuf>,

        /// Print high-resolution per-phase timing table and metrics
        #[arg(long = "timing")]
        timing: bool,

        /// Installation layout strategy: hoisted (default npm layout), linked (NTFS junctions to global store), nested, or shallow
        #[arg(long = "install-strategy", value_parser = ["hoisted", "linked", "nested", "shallow"])]
        install_strategy: Option<String>,

        /// Wait for background trash deletions to finish before exiting (default: false)
        #[arg(long = "wait-for-trash", alias = "wait-trash")]
        wait_for_trash: bool,

        /// Detached background trash deletion without blocking exit (default: true)
        #[arg(long = "detached-trash", default_value = "true", action = clap::ArgAction::Set)]
        detached_trash: bool,

        /// Output JSON summary instead of text
        #[arg(long)]
        json: bool,
    },

    /// Install dependencies directly from package-lock.json (clean slate)
    #[command(
        alias = "clean-install",
        alias = "ic",
        alias = "install-clean",
        alias = "isntall-clean"
    )]
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

        /// Force installation
        #[arg(short = 'f', long = "force")]
        force: bool,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,

        /// Run scripts with direct stdio inheritance
        #[arg(long = "foreground-scripts")]
        foreground_scripts: bool,

        /// Enforce strict sandbox policy
        #[arg(long = "strict-sandbox")]
        strict_sandbox: bool,

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

        /// Select package-lock.json serialization format (1, 2, or 3)
        #[arg(long = "lockfile-version", value_parser = clap::value_parser!(u32).range(1..=3))]
        lockfile_version: Option<u32>,

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

        /// Print high-resolution per-phase timing table and metrics
        #[arg(long = "timing")]
        timing: bool,

        /// Installation layout strategy: hoisted (default npm layout), linked (NTFS junctions to global store), nested, or shallow
        #[arg(long = "install-strategy", value_parser = ["hoisted", "linked", "nested", "shallow"])]
        install_strategy: Option<String>,

        /// Wait for background trash deletions to finish before exiting (default: false)
        #[arg(long = "wait-for-trash", alias = "wait-trash")]
        wait_for_trash: bool,

        /// Detached background trash deletion without blocking exit (default: true)
        #[arg(long = "detached-trash", default_value = "true", action = clap::ArgAction::Set)]
        detached_trash: bool,

        /// Output JSON summary instead of text
        #[arg(long)]
        json: bool,
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
    #[command(alias = "run-script", alias = "rum", alias = "urn")]
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

        /// Run scripts with direct stdio inheritance
        #[arg(long = "foreground-scripts")]
        foreground_scripts: bool,

        /// Enforce strict sandbox policy
        #[arg(long = "strict-sandbox")]
        strict_sandbox: bool,

        /// Include workspace root when workspaces are enabled
        #[arg(long = "workspace-root", alias = "include-workspace-root")]
        workspace_root: bool,
    },

    /// Run arbitrary package binaries dynamically (npx equivalent)
    #[command(alias = "npx", alias = "x")]
    Exec {
        /// Run string inside shell
        #[arg(short = 'c', long = "call")]
        call: Option<String>,

        /// Package name or binary to execute
        #[arg(default_value = "")]
        package: String,

        /// Additional arguments passed to the binary
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Automatically say yes to installation prompts
        #[arg(short = 'y', long = "yes")]
        yes: bool,

        /// Package to install for the command
        #[arg(short = 'p', long = "package")]
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

        /// Target specific workspace package(s)
        #[arg(short = 'w', long = "workspace")]
        workspace: Vec<String>,

        /// Target all workspace packages
        #[arg(long = "workspaces", alias = "ws")]
        workspaces: bool,

        /// Include workspace root when workspaces are enabled
        #[arg(long = "workspace-root", alias = "include-workspace-root")]
        workspace_root: bool,
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

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,

        /// Run scripts with direct stdio inheritance
        #[arg(long = "foreground-scripts")]
        foreground_scripts: bool,
    },

    /// Remove a package from project dependencies
    #[command(alias = "remove", alias = "rm", alias = "r", alias = "un")]
    Uninstall {
        /// Package names to uninstall
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

        /// Specific workspace(s) to target
        #[arg(long = "workspace", short = 'w')]
        workspace: Vec<String>,

        /// Run across all workspaces
        #[arg(long = "workspaces")]
        workspaces: bool,

        /// Include workspace root
        #[arg(long = "include-workspace-root")]
        workspace_root: bool,

        /// Remove from global prefix
        #[arg(short = 'g', long = "global")]
        global: bool,

        /// Custom installation prefix directory
        #[arg(long = "prefix")]
        prefix: Option<PathBuf>,

        /// Output JSON summary instead of text
        #[arg(long)]
        json: bool,

        /// Disable audit check
        #[arg(long = "no-audit")]
        no_audit: bool,

        /// Disable funding messages
        #[arg(long = "no-fund")]
        no_fund: bool,
    },

    /// Update packages
    #[command(alias = "up", alias = "u", alias = "upgrade", alias = "udpate")]
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

        /// Run scripts with direct stdio inheritance
        #[arg(long = "foreground-scripts")]
        foreground_scripts: bool,

        /// Enforce strict sandbox policy
        #[arg(long = "strict-sandbox")]
        strict_sandbox: bool,

        /// Bypass peer dependency installation conflicts
        #[arg(long = "legacy-peer-deps")]
        legacy_peer_deps: bool,

        /// Fail installation if any peer dependencies are missing or invalid
        #[arg(long = "strict-peer-deps")]
        strict_peer_deps: bool,

        /// Output JSON summary instead of text
        #[arg(long)]
        json: bool,

        /// Disable audit check
        #[arg(long = "no-audit")]
        no_audit: bool,

        /// Disable funding messages
        #[arg(long = "no-fund")]
        no_fund: bool,
    },

    /// Perform a security audit of dependency vulnerabilities
    Audit {
        /// Subcommand or action, e.g. "fix"
        #[arg(value_name = "ACTION")]
        action: Option<String>,

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

        /// Force audit fix with potential breaking changes
        #[arg(long)]
        force: bool,
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

    /// Reduce duplication in node_modules and package-lock.json
    #[command(alias = "deduplicate", alias = "ddp")]
    Dedupe {
        /// Specific package names to deduplicate
        packages: Vec<String>,

        /// Report deduplication actions without modifying files or lockfile
        #[arg(long)]
        dry_run: bool,

        /// Disable audit check
        #[arg(long = "no-audit")]
        no_audit: bool,

        /// Disable funding messages
        #[arg(long = "no-fund")]
        no_fund: bool,
    },

    /// Find duplicate packages across nesting levels (equivalent to dedupe --dry-run)
    FindDupes {
        /// Specific package names to inspect
        packages: Vec<String>,
    },

    /// Re-run compilation and lifecycle build scripts for installed packages
    #[command(alias = "rb")]
    Rebuild {
        /// Specific packages to rebuild
        packages: Vec<String>,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,

        /// Run scripts with direct stdio inheritance
        #[arg(long = "foreground-scripts")]
        foreground_scripts: bool,

        /// Enforce strict sandbox policy
        #[arg(long = "strict-sandbox")]
        strict_sandbox: bool,
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
        /// Target specific workspace package(s)
        #[arg(short = 'w', long = "workspace", global = true)]
        workspace: Vec<String>,
        /// Target all workspace packages
        #[arg(long = "workspaces", alias = "ws", global = true)]
        workspaces: bool,
    },

    /// Create a package.json file or run an initializer
    #[command(alias = "create", alias = "innit")]
    Init {
        /// Initializer package or template (e.g. react-app, @scope/pkg, vite)
        initializer: Option<String>,

        /// Arguments forwarded to initializer binary
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Generate package.json with defaults without prompting
        #[arg(short = 'y', long = "yes", short_alias = 'f', alias = "force")]
        yes: bool,

        /// Scope to prefix package name with (e.g. @myorg or myorg)
        #[arg(long)]
        scope: Option<String>,

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

    /// Manage the package cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,

        /// Custom cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,
    },

    /// Compare package versions, tarballs, or directories
    Diff {
        /// Specs to compare (positional arguments, 0 to 2)
        specs: Vec<String>,

        /// Arguments passed via --diff=<spec>
        #[arg(long = "diff", action = clap::ArgAction::Append)]
        diff_specs: Vec<String>,

        /// Output list of changed file names only
        #[arg(long = "diff-name-only")]
        diff_name_only: bool,

        /// Context lines in unified diff (default 3)
        #[arg(long = "diff-unified", default_value = "3")]
        diff_unified: usize,

        /// Ignore whitespace
        #[arg(long = "diff-ignore-all-space")]
        diff_ignore_all_space: bool,

        /// Don't include a/ and b/ prefixes
        #[arg(long = "diff-no-prefix")]
        diff_no_prefix: bool,

        /// Custom source prefix (default a/)
        #[arg(long = "diff-src-prefix")]
        diff_src_prefix: Option<String>,

        /// Custom destination prefix (default b/)
        #[arg(long = "diff-dst-prefix")]
        diff_dst_prefix: Option<String>,

        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,
    },

    /// Generate Software Bill of Materials (SBOM)
    Sbom {
        /// SBOM specification format (spdx, cyclonedx)
        #[arg(long = "sbom-format", default_value = "spdx")]
        sbom_format: String,

        /// CycloneDX component type (library, application, framework)
        #[arg(long = "sbom-type", default_value = "application")]
        sbom_type: String,

        /// Inspect only package-lock.json without requiring node_modules
        #[arg(long = "package-lock-only")]
        package_lock_only: bool,

        /// Dependency types to omit (dev, optional, peer)
        #[arg(long, value_delimiter = ',')]
        omit: Vec<String>,
    },

    /// Bump a package version or view version details
    #[command(alias = "verison")]
    Version {
        newversion: Option<String>,

        #[arg(long)]
        preid: Option<String>,

        #[arg(short = 'm', long = "message")]
        message: Option<String>,

        #[arg(long = "allow-same-version")]
        allow_same_version: bool,

        #[arg(long = "no-git-tag-version")]
        no_git_tag_version: bool,

        #[arg(long = "no-commit-hooks")]
        no_commit_hooks: bool,

        #[arg(short = 's', long = "sign-git-tag")]
        sign_git_tag: bool,

        #[arg(short = 'f', long = "force")]
        force: bool,

        #[arg(long = "ignore-scripts")]
        ignore_scripts: bool,

        #[arg(long = "json")]
        json: bool,

        /// Target specific workspace package(s)
        #[arg(short = 'w', long = "workspace")]
        workspace: Vec<String>,

        /// Target all workspace packages
        #[arg(long = "workspaces", alias = "ws")]
        workspaces: bool,

        /// Include workspace root when workspaces are enabled
        #[arg(long = "workspace-root", alias = "include-workspace-root")]
        include_workspace_root: bool,
    },

    /// List installed packages
    #[command(alias = "ls", alias = "la", alias = "ll")]
    List {
        /// Specific package name(s) or specs to filter the tree
        packages: Vec<String>,

        /// Maximum depth to recurse (default 0 for direct dependencies)
        #[arg(long)]
        depth: Option<usize>,

        /// Show all dependencies regardless of depth
        #[arg(short = 'a', long = "all")]
        all: bool,

        /// Output tree as structured JSON
        #[arg(long)]
        json: bool,

        /// Show extended information (description, license, path)
        #[arg(short = 'l', long = "long")]
        long: bool,

        /// Output parseable list of paths
        #[arg(short = 'p', long = "parseable")]
        parseable: bool,

        /// Inspect only package-lock.json without node_modules
        #[arg(long = "package-lock-only")]
        package_lock_only: bool,

        /// Dependency types to omit (dev, optional, peer)
        #[arg(long, value_delimiter = ',')]
        omit: Vec<String>,

        /// List packages in the global install prefix
        #[arg(short = 'g', long = "global")]
        global: bool,

        /// Custom prefix directory
        #[arg(long = "prefix")]
        prefix: Option<PathBuf>,

        /// Target specific workspace package(s)
        #[arg(short = 'w', long = "workspace")]
        workspace: Vec<String>,

        /// Target all workspace packages
        #[arg(long = "workspaces", alias = "ws")]
        workspaces: bool,

        /// Include workspace root when workspaces are enabled
        #[arg(long = "workspace-root", alias = "include-workspace-root")]
        workspace_root: bool,
    },

    /// Check for outdated packages
    Outdated {
        /// Specific package name(s) to check
        packages: Vec<String>,

        /// Show all dependencies
        #[arg(short = 'a', long = "all")]
        all: bool,

        /// Output outdated report as structured JSON
        #[arg(long)]
        json: bool,

        /// Show extended information (package type, homepage)
        #[arg(short = 'l', long = "long")]
        long: bool,

        /// Output parseable list of outdated specs
        #[arg(short = 'p', long = "parseable")]
        parseable: bool,

        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,
    },

    /// View package information from registry
    #[command(alias = "info", alias = "v", alias = "show")]
    View {
        /// Package spec and optional field paths
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Output as structured JSON
        #[arg(long)]
        json: bool,

        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,
    },

    /// Execute CSS-like selector queries on the dependency tree
    Query {
        /// CSS-like selector query string (e.g. :root, [name=react], :outdated)
        selector: Option<String>,

        /// Query only package-lock.json without inspecting node_modules
        #[arg(long = "package-lock-only")]
        package_lock_only: bool,

        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,
    },

    /// Publish a package to the registry
    Publish {
        /// Target package directory or spec (defaults to current directory)
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Tag to publish to (defaults to 'latest')
        #[arg(long, default_value = "latest")]
        tag: String,

        /// Package access: public or restricted
        #[arg(long)]
        access: Option<String>,

        /// Perform all pack and verification steps without uploading to registry
        #[arg(long)]
        dry_run: bool,

        /// One-time password for two-factor authentication
        #[arg(long)]
        otp: Option<String>,

        /// Generate and include provenance attestations
        #[arg(long)]
        provenance: bool,

        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,

        /// Output JSON summary
        #[arg(long)]
        json: bool,
    },

    /// Display npm username for the active registry
    Whoami {
        /// Custom registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Ping the registry and report response time
    Ping {
        /// Custom registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Log in to a registry
    #[command(alias = "adduser", alias = "add-user")]
    Login {
        /// Custom registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Auth type
        #[arg(long)]
        auth_type: Option<String>,

        /// Scope whose registry should receive the credentials
        #[arg(long)]
        scope: Option<String>,

        /// One-time password for legacy/basic authentication
        #[arg(long)]
        otp: Option<String>,
    },

    /// Log out of a registry
    Logout {
        /// Custom registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Scope to log out from
        #[arg(long)]
        scope: Option<String>,
    },

    /// Manage registry authentication tokens
    Token {
        #[command(subcommand)]
        action: Option<TokenAction>,

        /// Custom registry URL
        #[arg(long, global = true)]
        registry: Option<String>,

        /// Output in JSON format
        #[arg(long, global = true)]
        json: bool,
    },

    /// Manage lifecycle script approval policy.
    ApproveScripts {
        packages: Vec<String>,
        #[arg(short = 'a', long)]
        all: bool,
        #[arg(long = "allow-scripts-pending")]
        allow_scripts_pending: bool,
        #[arg(long)]
        json: bool,
    },
    /// Remove lifecycle script approval entries.
    DenyScripts {
        packages: Vec<String>,
        #[arg(short = 'a', long)]
        all: bool,
        #[arg(long = "allow-scripts-pending")]
        allow_scripts_pending: bool,
        #[arg(long)]
        json: bool,
    },
    /// Generate shell completion scripts.
    Completion { shell: Option<String> },
    /// Manage package distribution tags.
    #[command(alias = "dist-tags")]
    DistTag {
        #[command(subcommand)]
        action: DistTagAction,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        otp: Option<String>,
    },
    /// Manage package owners/collaborators.
    #[command(alias = "author")]
    Owner {
        #[command(subcommand)]
        action: OwnerAction,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        otp: Option<String>,
    },
    /// Remove a package or package version from a registry.
    Unpublish {
        package: Option<String>,
        version: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        otp: Option<String>,
    },
    /// Mark package versions as deprecated.
    Deprecate {
        package: String,
        message: String,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove a package deprecation notice.
    Undeprecate {
        package: String,
        version: Option<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Manage package access control.
    Access {
        args: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        otp: Option<String>,
    },
    /// Manage npm profile information.
    Profile {
        action: Option<String>,
        args: Vec<String>,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(short = 'p', long)]
        parseable: bool,
    },
    /// Manage npm organizations.
    #[command(alias = "ogr")]
    Org {
        action: Option<String>,
        args: Vec<String>,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(short = 'p', long)]
        parseable: bool,
    },
    /// Manage npm teams.
    Team {
        action: Option<String>,
        args: Vec<String>,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(short = 'p', long)]
        parseable: bool,
    },
    /// Check the local npm/rnpm installation and machine performance diagnostics.
    Doctor {
        /// Optional diagnostic category (e.g. "perf" for performance diagnostics)
        action: Option<String>,
        /// Additional arguments
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show packages seeking funding.
    Fund {
        package: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Explain why a package is installed.
    #[command(alias = "why")]
    Explain {
        package: String,
        #[arg(long)]
        json: bool,
    },
    /// Search the registry.
    #[command(alias = "find", alias = "s", alias = "se")]
    Search {
        terms: Vec<String>,
        #[arg(long = "searchlimit", alias = "search-limit", default_value_t = 20)]
        search_limit: usize,
        #[arg(long)]
        json: bool,
        #[arg(short = 'p', long)]
        parseable: bool,
        #[arg(long = "no-description")]
        no_description: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show packages starred by the current user.
    Stars {
        user: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Star a package.
    Star {
        packages: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long = "no-unicode")]
        no_unicode: bool,
    },
    /// Unstar a package.
    Unstar {
        packages: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long = "no-unicode")]
        no_unicode: bool,
    },
    /// Repair installed dependencies.
    Fix {
        #[arg(long)]
        force: bool,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Show package bug tracker URL.
    #[command(alias = "issues")]
    Bugs {
        packages: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Open or print package documentation URL.
    #[command(alias = "home")]
    Docs {
        packages: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show the source repository URL for a package.
    Repo {
        packages: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Edit a package in the configured editor.
    Edit {
        package: Option<String>,
        #[arg(long)]
        editor: Option<String>,
    },
    /// Explore a package in a shell.
    Explore {
        package: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
        #[arg(long)]
        shell: Option<String>,
    },
    /// Search npm help topics.
    HelpSearch {
        terms: Vec<String>,
        #[arg(short = 'l', long)]
        long: bool,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Manage staged package versions.
    Stage {
        action: Option<String>,
        args: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Install dependencies and run the CI test script.
    #[command(alias = "cit", alias = "clean-install-test", alias = "sit")]
    InstallCiTest {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Install dependencies and run install scripts.
    InstallScripts {
        action: Option<String>,
        packages: Vec<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Install dependencies and run the test script.
    #[command(alias = "it")]
    InstallTest {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Manage registry webhooks
    Hook {
        action: Option<String>,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        otp: Option<String>,
    },
    /// Create npm-shrinkwrap.json from package-lock.json.
    Shrinkwrap,
    /// Record package trust metadata.
    Trust {
        action: Option<String>,
        args: Vec<String>,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long = "file")]
        workflow_file: Option<String>,
        #[arg(long = "repo", alias = "repository")]
        repository: Option<String>,
        #[arg(long = "env", alias = "environment")]
        environment: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        org_id: Option<String>,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long)]
        pipeline_definition_id: Option<String>,
        #[arg(long)]
        vcs_origin: Option<String>,
        #[arg(long = "context-id")]
        context_id: Vec<String>,
        #[arg(long = "allow-publish")]
        allow_publish: bool,
        #[arg(long = "allow-stage-publish", alias = "allow-staged-publish")]
        allow_stage_publish: bool,
        #[arg(long)]
        json: bool,
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },

    /// Retrieve a configuration value (npm get alias)
    Get {
        /// Configuration key to retrieve
        key: Option<String>,
    },

    /// Set a configuration value (npm set alias)
    Set {
        /// Configuration key to set
        key: String,
        /// Value to assign
        value: String,
        /// Set in global configuration
        #[arg(short = 'g', long = "global")]
        global: bool,
        /// Configuration location (global, user, project)
        #[arg(long)]
        location: Option<String>,
    },

    /// Manage npm configuration
    #[command(alias = "c")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Link a package folder locally or globally
    #[command(alias = "ln")]
    Link {
        /// Package name to link from global prefix into local node_modules
        package: Option<String>,
    },

    /// Unlink a package locally or globally
    Unlink {
        /// Package name to unlink from local node_modules
        package: Option<String>,
    },

    /// Display npm prefix
    Prefix {
        /// Display global prefix
        #[arg(short = 'g', long = "global")]
        global: bool,
    },

    /// Display npm root (node_modules directory)
    Root {
        /// Display global node_modules
        #[arg(short = 'g', long = "global")]
        global: bool,
    },

    /// Display npm bin directory
    Bin {
        /// Display global bin directory
        #[arg(short = 'g', long = "global")]
        global: bool,
    },

    /// View help for npm/rnpm commands and concepts
    #[command(alias = "hlep")]
    Help {
        /// Help topic or command name (e.g. install-strategy)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        topic: Vec<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum TokenAction {
    /// List active authentication tokens
    List,
    /// Revoke an authentication token
    #[command(alias = "delete")]
    Revoke { token_id: String },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum DistTagAction {
    /// List tags for a package.
    Ls { package: Option<String> },
    /// Add or replace a tag.
    Add {
        package: String,
        tag: Option<String>,
    },
    /// Remove a tag.
    #[command(alias = "remove")]
    Rm { package: String, tag: String },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum OwnerAction {
    /// List package owners.
    Ls { package: String },
    /// Add an owner.
    Add { user: String, package: String },
    /// Remove an owner.
    #[command(alias = "remove")]
    Rm { user: String, package: String },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum ConfigAction {
    /// Set a configuration key to a value
    Set {
        /// Configuration key to set (or key=value)
        key: String,
        /// Value to assign
        value: Option<String>,
        /// Set in global configuration
        #[arg(short = 'g', long = "global")]
        global: bool,
        /// Configuration location (global, user, project)
        #[arg(long)]
        location: Option<String>,
    },
    /// Retrieve a configuration key value (or list all settings if no key is provided)
    Get {
        /// Configuration key to retrieve
        key: Option<String>,
    },
    /// Delete a configuration key
    #[command(alias = "rm", alias = "del")]
    Delete {
        /// Configuration key to delete
        key: String,
        /// Delete from global configuration
        #[arg(short = 'g', long = "global")]
        global: bool,
        /// Configuration location (global, user, project)
        #[arg(long)]
        location: Option<String>,
    },
    /// List configuration settings
    #[command(alias = "ls")]
    List {
        /// Output configuration in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Open the config file in an editor
    Edit,
    /// Repair or normalize configuration
    Fix,
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
    /// Normalize and fix package.json
    Fix,
}

#[derive(Subcommand, Debug)]
pub(crate) enum CacheAction {
    /// Add the specified package or tarball to the local cache
    Add {
        /// Package spec or tarball path to cache
        package: String,

        /// Custom cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,
    },

    /// List contents of the cache folder
    Ls {
        /// Subpath or key filter to list
        path: Option<String>,

        /// Custom cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,
    },

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

    let unsupported_commands: [&str; 1] = ["definitely-unknown-command"];

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
    } else if first == "test"
        || first == "t"
        || first == "tst"
        || first == "start"
        || first == "restart"
        || first == "stop"
        || first == "init"
        || first == "create"
        || first == "innit"
    {
        // Trailing arguments for script shortcuts and initializers are forwarded payloads to the script
    } else {
        args_to_scan.extend_from_slice(pre_dash_dash);
    }

    let unsupported_flags = [
        "--legacy-peer-deps",
        "--strict-peer-deps",
        "--save-bundle",
        "--production",
    ];

    let mut i = 0;
    while i < args_to_scan.len() {
        let arg = &args_to_scan[i];
        // For prune, --production, -p, --omit=..., and --include=... are supported options.
        if first == "prune"
            && (arg == "--production"
                || arg == "-p"
                || arg.starts_with("--omit")
                || arg.starts_with("--include"))
        {
            i += 1;
            continue;
        }
        if matches!(first.as_str(), "config" | "c") {
            if arg == "--workspaces"
                || arg == "--workspace"
                || arg == "--no-workspace"
                || arg.starts_with("--workspace=")
                || arg.starts_with("--no-workspace=")
            {
                return Some((
                    "ENOWORKSPACES".to_string(),
                    "npm error code ENOWORKSPACES\nnpm error This command does not support workspaces.".to_string(),
                ));
            }
            i += 1;
            continue;
        }

        if matches!(
            first.as_str(),
            "pkg" | "ls" | "list" | "la" | "ll"
        ) {
            i += 1;
            continue;
        }
        // --legacy-peer-deps and --strict-peer-deps are supported on install, ci, update (and their aliases)
        let is_global = args_to_scan.iter().any(|a| a == "-g" || a == "--global");
        if matches!(
            first.as_str(),
            "install" | "i" | "add" | "isntall"
        ) && !is_global && (arg == "--allow-scripts" || arg == "--no-allow-scripts") {
            return Some((
                "EALLOWSCRIPTS".to_string(),
                "npm error code EALLOWSCRIPTS\nnpm error --allow-scripts is not allowed in project-scoped installs. Add the entries to the \"allowScripts\" field in package.json, or to .npmrc, instead.".to_string(),
            ));
        }
        if matches!(
            first.as_str(),
            "install" | "i" | "add" | "isntall" | "ci" | "clean-install" | "ic" | "update" | "up"
        ) && (arg == "--legacy-peer-deps"
            || arg.starts_with("--legacy-peer-deps=")
            || arg == "--strict-peer-deps"
            || arg.starts_with("--strict-peer-deps="))
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

pub(crate) fn parse_omit_and_include_options(
    omit: &[String],
    include: &[String],
) -> (bool, bool, bool) {
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
        "test",
        "start",
        "restart",
        "stop",
        "prepare",
        "prepublishOnly",
        "prepack",
        "postpack",
        "dependencies",
        "preinstall",
        "install",
        "postinstall",
        "prepublish",
        "publish",
        "postpublish",
        "prerestart",
        "postrestart",
        "prestart",
        "poststart",
        "prestop",
        "poststop",
        "pretest",
        "posttest",
        "preuninstall",
        "uninstall",
        "postuninstall",
        "preversion",
        "version",
        "postversion",
    ];
    LIFECYCLE_NAMES.contains(&name)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_run(
    current_dir: PathBuf,
    script: Option<String>,
    args: Vec<String>,
    workspaces: bool,
    workspace: Vec<String>,
    filter: Vec<String>,
    scope: Vec<String>,
    if_present: bool,
    ignore_scripts: bool,
    foreground_scripts: bool,
    strict_sandbox: bool,
    workspace_root: bool,
) -> anyhow::Result<()> {
    let manifest_path = current_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow::anyhow!(
            "package.json not found in {}",
            current_dir.display()
        ));
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
                    println!("Scripts available in {pkg_id} via `npm run`:");
                } else {
                    println!("available via `npm run`:");
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
        let mut filters = workspace;
        filters.extend(filter);
        filters.extend(scope);
        let members = select_workspace_members(&current_dir, &filters, workspace_root)?;
        let mut failed = false;
        for member in members {
            let result = execute_run_sync(
                member.path.clone(), script.clone(), args.clone(), if_present,
                ignore_scripts, foreground_scripts, strict_sandbox,
            );
            if let Err(err) = result {
                if failed { eprintln!(); }
                failed = true;
                eprintln!("npm error Lifecycle script \x60{script}\x60 failed with error:");
                if let Some(exit) = err.downcast_ref::<rnpm_lifecycle::ScriptExitError>() {
                    eprintln!("npm error code {}", exit.exit_code);
                }
                let id = member.manifest.version.as_ref()
                    .map(|v| format!("{}@{v}", member.name)).unwrap_or_else(|| member.name.clone());
                eprintln!("npm error workspace {id}");
                eprintln!("npm error location {}", member.path.display());
                if !member.manifest.scripts.contains_key(&script) {
                    eprintln!("npm error Missing script: \"{script}\"\nnpm error\nnpm error To see a list of scripts, run:\nnpm error   npm run --workspace={id}");
                } else {
                    eprintln!("npm error command failed");
                    eprintln!("npm error command {}", member.manifest.scripts[&script]);
                }
            }
        }
        if failed {
            return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                exit_code: 1, message: format!("Workspace script '{script}' failed"),
            }));
        }
        Ok(())
    } else {
        execute_run_sync(current_dir, script, args, if_present, ignore_scripts,
            foreground_scripts, strict_sandbox)
    }
}

fn select_workspace_members(
    root: &Path,
    filters: &[String],
    include_root: bool,
) -> anyhow::Result<Vec<rnpm_core::workspace::WorkspaceMember>> {
    let mut members = rnpm_core::workspace::discover_workspaces(root)?;
    if members.is_empty() {
        anyhow::bail!("npm error code ENOWORKSPACES\nnpm error No workspaces found!");
    }
    for filter in filters {
        if !members.iter().any(|m| rnpm_lifecycle::matches_filter(filter, &m.name, &m.path, root)) {
            anyhow::bail!("npm error No workspaces found:\nnpm error   --workspace={filter}");
        }
    }
    // Preserve the existing topological extension for workspace: specs, which
    // npm does not accept. npm-compatible manifests use declaration order.
    let uses_workspace_protocol = members.iter().any(|m| m.manifest.dependencies.values()
        .chain(m.manifest.dev_dependencies.values()).any(|spec| spec.starts_with("workspace:")));
    if uses_workspace_protocol {
        if let Ok(graph) = rnpm_solver::WorkspaceDependencyGraph::construct(&members) {
        let order_map: std::collections::HashMap<&str, usize> = graph
            .topological_order
            .iter()
            .enumerate()
            .map(|(i, name)| (name.as_str(), i))
            .collect();
        members.sort_by_key(|m| order_map.get(m.name.as_str()).copied().unwrap_or(usize::MAX));
    }
    } else {
        let manifest = Manifest::from_file(root.join("package.json"))?;
        let mut ordered_paths = Vec::new();
        for pattern in manifest.workspace_patterns().iter().filter(|p| !p.starts_with('!')) {
            ordered_paths.extend(rnpm_core::workspace::match_glob_patterns(root, std::slice::from_ref(pattern))?);
        }
        members.sort_by_key(|m| ordered_paths.iter().position(|p| p == &m.path).unwrap_or(usize::MAX));
    }
    members.retain(|m| filters.is_empty() || filters.iter()
        .any(|f| rnpm_lifecycle::matches_filter(f, &m.name, &m.path, root)));
    if include_root {
        let manifest = Manifest::from_file(root.join("package.json"))?;
        members.insert(0, rnpm_core::workspace::WorkspaceMember {
            name: manifest.name.clone().unwrap_or_default(),
            version: manifest.version.clone(), path: root.to_path_buf(),
            relative_path: String::new(), manifest,
        });
    }
    Ok(members)
}

pub(crate) fn normalize_cli_args<I, T>(raw_args: I) -> Vec<String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString>,
{
    let args: Vec<String> = raw_args
        .into_iter()
        .map(|a| a.into().to_string_lossy().to_string())
        .collect();

    let mut result = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if i == 1 && arg == "-v" {
            // npm accepts the lowercase short form as an alias for --version.
            // clap's generated version flag is -V, so normalize it before parsing.
            result.push("--version".to_string());
        } else if arg == "--legacy-bundling" {
            result.push("--install-strategy=nested".to_string());
        } else if arg == "--global-style" {
            result.push("--install-strategy=shallow".to_string());
        } else if arg == "-ws" {
            result.push("--workspaces".to_string());
        } else if let Some(rest) = arg.strip_prefix("-ws=") {
            result.push(format!("--workspaces={rest}"));
        } else if arg == "--git-tag-version=false" || arg == "--git-tag-version=0" {
            result.push("--no-git-tag-version".to_string());
        } else if arg == "--git-tag-version"
            && i + 1 < args.len()
            && (args[i + 1] == "false" || args[i + 1] == "0")
        {
            result.push("--no-git-tag-version".to_string());
            i += 1;
        } else if arg == "--git-tag-version"
            || arg == "--git-tag-version=true"
            || arg == "--git-tag-version=1"
        {
            // default is true, ignore flag
        } else if arg == "--git-tag-version"
            && i + 1 < args.len()
            && (args[i + 1] == "true" || args[i + 1] == "1")
        {
            i += 1;
        } else if arg == "--commit-hooks=false" || arg == "--commit-hooks=0" {
            result.push("--no-commit-hooks".to_string());
        } else if arg == "--commit-hooks"
            && i + 1 < args.len()
            && (args[i + 1] == "false" || args[i + 1] == "0")
        {
            result.push("--no-commit-hooks".to_string());
            i += 1;
        } else if arg == "--commit-hooks"
            || arg == "--commit-hooks=true"
            || arg == "--commit-hooks=1"
        {
            // default is true, ignore flag
        } else if arg == "--commit-hooks"
            && i + 1 < args.len()
            && (args[i + 1] == "true" || args[i + 1] == "1")
        {
            i += 1;
        } else {
            result.push(arg.clone());
        }
        i += 1;
    }
    result
}

fn is_clap_declared_arg(cmd: &clap::Command, token: &str) -> Option<bool> {
    if token == "--help" || token == "-h" {
        return Some(false);
    }
    let (name, is_long) = if let Some(stripped) = token.strip_prefix("--") {
        if let Some(eq) = stripped.find('=') {
            (&stripped[..eq], true)
        } else {
            (stripped, true)
        }
    } else {
        let stripped = token.strip_prefix('-')?;
        (stripped, false)
    };

    for arg in cmd.get_arguments() {
        if is_long {
            if let Some(long) = arg.get_long() {
                if long == name {
                    return Some(arg.get_action().takes_values());
                }
            }
            if let Some(aliases) = arg.get_all_aliases() {
                for alias in aliases {
                    if alias == name {
                        return Some(arg.get_action().takes_values());
                    }
                }
            }
        } else if name.len() == 1 {
            let ch = name.chars().next().unwrap();
            if let Some(short) = arg.get_short() {
                if short == ch {
                    return Some(arg.get_action().takes_values());
                }
            }
            if let Some(aliases) = arg.get_all_short_aliases() {
                for alias in aliases {
                    if alias == ch {
                        return Some(arg.get_action().takes_values());
                    }
                }
            }
        }
    }
    None
}

fn extract_config_flag(
    token: &str,
    next_token: Option<&str>,
    is_silent: bool,
    overrides: &mut BTreeMap<String, String>,
) -> Option<usize> {
    if token == "--" || token == "--help" || token == "-h" || token == "--version" || token == "-v" || token == "-V" {
        return None;
    }
    if token == "-s" || token == "--silent" {
        overrides.insert("loglevel".to_string(), "silent".to_string());
        return Some(1);
    }
    if let Some(path) = token.strip_prefix("--userconfig=") {
        rnpm_config::set_process_userconfig(PathBuf::from(path));
        return Some(1);
    }
    if token == "--userconfig" {
        if let Some(val) = next_token {
            rnpm_config::set_process_userconfig(PathBuf::from(val));
            return Some(2);
        } else {
            return Some(1);
        }
    }
    if let Some(path) = token.strip_prefix("--globalconfig=") {
        rnpm_config::set_process_globalconfig(PathBuf::from(path));
        return Some(1);
    }
    if token == "--globalconfig" {
        if let Some(val) = next_token {
            rnpm_config::set_process_globalconfig(PathBuf::from(val));
            return Some(2);
        } else {
            return Some(1);
        }
    }
    if let Some(raw_key) = token.strip_prefix("--no-") {
        let key = rnpm_config::normalize_config_key(raw_key);
        if !rnpm_config::is_known_npm_config_key(&key) && !is_silent {
            eprintln!(
                "npm warn Unknown cli config \"--{raw_key}\". This will stop working in the next major version of npm."
            );
        }
        if !(key == "ca" || key == "cafile") {
            overrides.insert(key, "false".to_string());
        }
        return Some(1);
    }
    if let Some(rest) = token.strip_prefix("--") {
        if let Some(eq) = rest.find('=') {
            let raw_key = &rest[..eq];
            let val = &rest[eq + 1..];
            let key = rnpm_config::normalize_config_key(raw_key);
            if !rnpm_config::is_known_npm_config_key(&key) && !is_silent {
                eprintln!(
                    "npm warn Unknown cli config \"--{raw_key}\". This will stop working in the next major version of npm."
                );
            }
            if !((key == "ca" || key == "cafile") && (val == "true" || val == "false")) {
                overrides.insert(key, val.to_string());
            }
            return Some(1);
        } else {
            let raw_key = rest;
            let key = rnpm_config::normalize_config_key(raw_key);
            let is_bool = rnpm_config::is_boolean_npm_config_key(&key);
            let is_known = rnpm_config::is_known_npm_config_key(&key);
            if !is_known && !is_silent {
                if let Some(next) = next_token {
                    if !next.starts_with('-') {
                        eprintln!(
                            "npm warn \"{next}\" is being parsed as a normal command line argument."
                        );
                    }
                }
                eprintln!(
                    "npm warn Unknown cli config \"--{raw_key}\". This will stop working in the next major version of npm."
                );
            }
            if is_known && !is_bool {
                if let Some(next) = next_token {
                    if !next.starts_with('-') {
                        if !((key == "ca" || key == "cafile") && (next == "true" || next == "false")) {
                            overrides.insert(key, next.to_string());
                        }
                        return Some(2);
                    }
                }
            }
            if !(key == "ca" || key == "cafile") {
                overrides.insert(key, "true".to_string());
            }
            return Some(1);
        }
    }
    None
}

fn preprocess_exec_args(
    program: &str,
    _subcmd: &str,
    tokens: &[String],
    is_silent: bool,
    overrides: &mut BTreeMap<String, String>,
) -> Vec<String> {
    let dashdash_pos = tokens.iter().position(|t| t == "--");
    let (before_dashdash, after_dashdash) = match dashdash_pos {
        Some(pos) => (&tokens[..pos], &tokens[pos + 1..]),
        None => (tokens, &[][..]),
    };

    if before_dashdash.iter().any(|t| t == "--help" || t == "-h") {
        return vec![program.to_string(), _subcmd.to_string(), "--help".to_string()];
    }

    let mut clap_flags = Vec::new();
    let mut command_name = None;
    let mut script_positional_args = Vec::new();
    let mut i = 0;

    while i < before_dashdash.len() {
        let token = &before_dashdash[i];
        let next_token = before_dashdash.get(i + 1).map(|s| s.as_str());

        if token == "-s" || token == "--silent" {
            overrides.insert("loglevel".to_string(), "silent".to_string());
            i += 1;
            continue;
        }

        if token == "-y" || token == "--yes" {
            clap_flags.push(token.clone());
            i += 1;
            continue;
        }
        if token == "-c" || token == "--call" {
            clap_flags.push(token.clone());
            if let Some(next) = next_token {
                clap_flags.push(next.to_string());
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if token.starts_with("--call=") || token.starts_with("-c=") {
            clap_flags.push(token.clone());
            i += 1;
            continue;
        }
        if token == "--offline" {
            clap_flags.push(token.clone());
            i += 1;
            continue;
        }
        if token == "-p" || token == "--package" {
            clap_flags.push(token.clone());
            if let Some(next) = next_token {
                if !next.starts_with('-') {
                    clap_flags.push(next.to_string());
                    i += 2;
                    continue;
                }
            }
            i += 1;
            continue;
        }
        if let Some(rest) = token.strip_prefix("--package=") {
            clap_flags.push(format!("--package={rest}"));
            i += 1;
            continue;
        }
        if token == "--registry" || token == "--cache" {
            clap_flags.push(token.clone());
            if let Some(next) = next_token {
                if !next.starts_with('-') {
                    clap_flags.push(next.to_string());
                    i += 2;
                    continue;
                }
            }
            i += 1;
            continue;
        }
        if token.starts_with("--registry=") || token.starts_with("--cache=") {
            clap_flags.push(token.clone());
            i += 1;
            continue;
        }
        if token == "-w" || token == "--workspace" {
            clap_flags.push(token.clone());
            if let Some(next) = next_token {
                if !next.starts_with('-') {
                    clap_flags.push(next.to_string());
                    i += 2;
                    continue;
                }
            }
            i += 1;
            continue;
        }
        if token.starts_with("--workspace=") {
            clap_flags.push(token.clone());
            i += 1;
            continue;
        }
        if token == "--workspaces" || token == "-ws" {
            clap_flags.push(token.clone());
            i += 1;
            continue;
        }
        if token == "--include-workspace-root" || token == "--workspace-root" {
            clap_flags.push(token.clone());
            i += 1;
            continue;
        }

        if token.starts_with('-') {
            if let Some(consumed) = extract_config_flag(token, next_token, is_silent, overrides) {
                i += consumed;
                continue;
            }
        }

        if command_name.is_none() {
            command_name = Some(token.clone());
        } else {
            script_positional_args.push(token.clone());
        }
        i += 1;
    }

    let mut final_args = script_positional_args;
    let mut final_cmd = command_name;
    let mut after_idx = 0;
    if final_cmd.is_none() && !after_dashdash.is_empty() {
        final_cmd = Some(after_dashdash[0].clone());
        after_idx = 1;
    }
    final_args.extend(after_dashdash[after_idx..].iter().cloned());

    let mut result = vec![program.to_string(), "exec".to_string()];
    result.extend(clap_flags);
    if let Some(cmd) = final_cmd {
        result.push(cmd);
    }
    if !final_args.is_empty() {
        result.push("--".to_string());
        result.extend(final_args);
    }
    result
}

fn preprocess_init_args(
    program: &str,
    _subcmd: &str,
    tokens: &[String],
    is_silent: bool,
    overrides: &mut BTreeMap<String, String>,
) -> Vec<String> {
    if tokens.iter().any(|t| t == "--help" || t == "-h") {
        return vec![program.to_string(), _subcmd.to_string(), "--help".to_string()];
    }

    let mut clap_flags = Vec::new();
    let mut initializer = None;
    let mut forwarded_args = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        let token = &tokens[i];
        let next_token = tokens.get(i + 1).map(|s| s.as_str());

        if initializer.is_some() {
            forwarded_args.push(token.clone());
            i += 1;
            continue;
        }

        if token == "-y" || token == "--yes" || token == "-f" || token == "--force" {
            clap_flags.push(token.clone());
            i += 1;
            continue;
        }
        if token == "--scope" || token == "--registry" || token == "--cache" {
            clap_flags.push(token.clone());
            if let Some(next) = next_token {
                if !next.starts_with('-') {
                    clap_flags.push(next.to_string());
                    i += 2;
                    continue;
                }
            }
            i += 1;
            continue;
        }
        if token.starts_with("--scope=") || token.starts_with("--registry=") || token.starts_with("--cache=") {
            clap_flags.push(token.clone());
            i += 1;
            continue;
        }

        if token.starts_with('-') {
            if let Some(consumed) = extract_config_flag(token, next_token, is_silent, overrides) {
                i += consumed;
                continue;
            }
        }

        initializer = Some(token.clone());
        i += 1;
    }

    let mut result = vec![program.to_string(), "init".to_string()];
    result.extend(clap_flags);
    if let Some(init) = initializer {
        result.push(init);
        if !forwarded_args.is_empty() {
            result.push("--".to_string());
            result.extend(forwarded_args);
        }
    }
    result
}

fn preprocess_run_args(
    program: &str,
    subcmd: &str,
    tokens: &[String],
    is_silent: bool,
    overrides: &mut BTreeMap<String, String>,
) -> Vec<String> {
    let dashdash_pos = tokens.iter().position(|t| t == "--");
    let (before_dashdash, after_dashdash) = match dashdash_pos {
        Some(pos) => (&tokens[..pos], &tokens[pos + 1..]),
        None => (tokens, &[][..]),
    };

    if before_dashdash.iter().any(|t| t == "--help" || t == "-h") {
        return vec![program.to_string(), subcmd.to_string(), "--help".to_string()];
    }

    let is_run = subcmd == "run" || subcmd == "run-script" || subcmd == "rum" || subcmd == "urn";

    let mut clap_flags = Vec::new();
    let mut script_name: Option<String> = if !is_run {
        Some(subcmd.to_string())
    } else {
        None
    };
    let mut script_positional_args = Vec::new();
    let mut i = 0;

    while i < before_dashdash.len() {
        let token = &before_dashdash[i];
        let next_token = before_dashdash.get(i + 1).map(|s| s.as_str());

        if token == "-s" || token == "--silent" {
            overrides.insert("loglevel".to_string(), "silent".to_string());
            i += 1;
            continue;
        }

        if is_run {
            if token == "--if-present" {
                clap_flags.push("--if-present".to_string());
                i += 1;
                continue;
            }
            if token == "--ignore-scripts" {
                clap_flags.push("--ignore-scripts".to_string());
                i += 1;
                continue;
            }
            if token == "--foreground-scripts" {
                clap_flags.push("--foreground-scripts".to_string());
                i += 1;
                continue;
            }
            if token == "--strict-sandbox" {
                clap_flags.push("--strict-sandbox".to_string());
                i += 1;
                continue;
            }
            if token == "--workspaces" || token == "-ws" {
                clap_flags.push("--workspaces".to_string());
                i += 1;
                continue;
            }
            if token == "--no-workspaces" {
                overrides.insert("workspaces".to_string(), "false".to_string());
                i += 1;
                continue;
            }
            if token == "--workspace-root" || token == "--include-workspace-root" {
                clap_flags.push("--workspace-root".to_string());
                i += 1;
                continue;
            }
            if token == "--no-workspace" {
                clap_flags.push("--workspace".to_string());
                clap_flags.push("false".to_string());
                i += 1;
                continue;
            }
            if token == "-w" || token == "--workspace" {
                clap_flags.push("--workspace".to_string());
                if let Some(next) = next_token {
                    if !next.starts_with('-') {
                        clap_flags.push(next.to_string());
                        i += 2;
                        continue;
                    }
                }
                clap_flags.push("true".to_string());
                i += 1;
                continue;
            }
            if let Some(rest) = token.strip_prefix("--workspace=") {
                clap_flags.push(format!("--workspace={rest}"));
                i += 1;
                continue;
            }
            if token == "--filter" || token == "--scope" {
                clap_flags.push(token.clone());
                if let Some(next) = next_token {
                    if !next.starts_with('-') {
                        clap_flags.push(next.to_string());
                        i += 2;
                        continue;
                    }
                }
                i += 1;
                continue;
            }
            if token.starts_with("--filter=") || token.starts_with("--scope=") {
                clap_flags.push(token.clone());
                i += 1;
                continue;
            }
        }

        if token.starts_with('-') {
            if let Some(consumed) = extract_config_flag(token, next_token, is_silent, overrides) {
                i += consumed;
                continue;
            }
        }

        if is_run && script_name.is_none() {
            script_name = Some(token.clone());
        } else {
            script_positional_args.push(token.clone());
        }
        i += 1;
    }

    let mut result = vec![program.to_string(), subcmd.to_string()];
    result.extend(clap_flags);
    if is_run {
        if let Some(s) = script_name {
            result.push(s);
        }
    }
    let mut final_script_args = script_positional_args;
    final_script_args.extend(after_dashdash.iter().cloned());
    if !final_script_args.is_empty() {
        result.push("--".to_string());
        result.extend(final_script_args);
    }
    result
}

pub(crate) fn preprocess_cli_args<I, T>(raw_args: I) -> Vec<String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString>,
{
    let args: Vec<String> = raw_args
        .into_iter()
        .map(|a| a.into().to_string_lossy().to_string())
        .collect();

    if args.is_empty() {
        return args;
    }

    let program = args[0].clone();
    let rest = &args[1..];

    // Detect if --silent / -s / --loglevel silent is anywhere
    let mut is_silent = false;
    for (idx, arg) in rest.iter().enumerate() {
        if arg == "-s" || arg == "--silent" || arg == "--loglevel=silent" {
            is_silent = true;
            break;
        }
        if (arg == "--loglevel" || arg == "-loglevel") && rest.get(idx + 1).map(|s| s.as_str()) == Some("silent") {
            is_silent = true;
            break;
        }
    }

    // Find subcommand index
    let mut subcmd_idx = None;
    if !rest.is_empty() && !rest[0].starts_with('-') {
        subcmd_idx = Some(0);
    } else {
        let root_cmd = Cli::command();
        let mut i = 0;
        while i < rest.len() {
            let token = &rest[i];
            let next_token = rest.get(i + 1).map(|s| s.as_str());

            if !token.starts_with('-') {
                if root_cmd.find_subcommand(token).is_some() {
                    subcmd_idx = Some(i);
                    break;
                }
            } else {
                if token == "--userconfig" || token == "--globalconfig" || token == "--prefix" {
                    if let Some(next) = next_token {
                        if !next.starts_with('-') {
                            i += 1;
                        }
                    }
                } else if let Some(takes_val) = is_clap_declared_arg(&root_cmd, token) {
                    if takes_val && !token.contains('=') {
                        if let Some(next) = next_token {
                            if !next.starts_with('-') {
                                i += 1;
                            }
                        }
                    }
                }
            }
            i += 1;
        }
    }

    let has_version_flag = rest
        .iter()
        .take_while(|t| *t != "--")
        .any(|t| t == "--version" || t == "-V" || t == "-v");
    if has_version_flag {
        let is_forwarded = if let Some(idx) = subcmd_idx {
            let sub = &rest[idx];
            if matches!(
                sub.as_str(),
                "run" | "run-script" | "rum" | "urn" | "exec" | "x" | "npx" | "test" | "t" | "tst" | "start" | "restart" | "stop" | "init" | "create"
            ) {
                let pos_after = rest[idx + 1..]
                    .iter()
                    .position(|t| t == "--version" || t == "-V" || t == "-v");
                let script_pos = rest[idx + 1..].iter().position(|t| !t.starts_with('-'));
                match (pos_after, script_pos) {
                    (Some(vp), Some(sp)) => vp > sp,
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        };

        if !is_forwarded {
            println!("rnpm {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
    }

    let mut overrides = BTreeMap::new();

    // Process any flags that appear BEFORE the subcommand
    let actual_subcmd_idx = subcmd_idx.unwrap_or(rest.len());
    let mut pre_flags_idx = 0;
    while pre_flags_idx < actual_subcmd_idx {
        let token = &rest[pre_flags_idx];
        let next_token = rest.get(pre_flags_idx + 1).map(|s| s.as_str());
        if let Some(consumed) = extract_config_flag(token, next_token, is_silent, &mut overrides) {
            pre_flags_idx += consumed;
        } else {
            pre_flags_idx += 1;
        }
    }

    let result = if let Some(idx) = subcmd_idx {
        let subcmd = &rest[idx];
        if subcmd == "run"
            || subcmd == "run-script"
            || subcmd == "rum"
            || subcmd == "urn"
            || subcmd == "test"
            || subcmd == "t"
            || subcmd == "tst"
            || subcmd == "start"
            || subcmd == "restart"
            || subcmd == "stop"
        {
            preprocess_run_args(&program, subcmd, &rest[idx + 1..], is_silent, &mut overrides)
        } else if subcmd == "exec" || subcmd == "x" || subcmd == "npx" {
            preprocess_exec_args(&program, subcmd, &rest[idx + 1..], is_silent, &mut overrides)
        } else if subcmd == "init" || subcmd == "create" {
            preprocess_init_args(&program, subcmd, &rest[idx + 1..], is_silent, &mut overrides)
        } else {
            // General subcommand
            let root_cmd = Cli::command();
            let mut cmd_stack = vec![root_cmd.clone()];
            if let Some(sub) = root_cmd.find_subcommand(subcmd) {
                cmd_stack.push(sub.clone());
            }
            let mut new_tokens = vec![program.clone(), subcmd.clone()];
            let mut j = idx + 1;
            while j < rest.len() {
                let token = &rest[j];
                let next_token = rest.get(j + 1).map(|s| s.as_str());

                if token == "--" {
                    new_tokens.push(token.clone());
                    new_tokens.extend(rest[j + 1..].iter().cloned());
                    break;
                }

                if !token.starts_with('-') {
                    if let Some(last_cmd) = cmd_stack.last() {
                        if let Some(sub) = last_cmd.find_subcommand(token) {
                            cmd_stack.push(sub.clone());
                        }
                    }
                    new_tokens.push(token.clone());
                    j += 1;
                    continue;
                }

                let declared_takes_val = cmd_stack
                    .iter()
                    .rev()
                    .find_map(|cmd| is_clap_declared_arg(cmd, token));

                if let Some(takes_val) = declared_takes_val {
                    if takes_val && !token.contains('=') {
                        if let Some(next) = next_token {
                            if !next.starts_with('-') {
                                new_tokens.push(token.clone());
                                new_tokens.push(next.to_string());
                                j += 2;
                                continue;
                            }
                        }
                        if let Some(consumed) = extract_config_flag(token, next_token, is_silent, &mut overrides) {
                            j += consumed;
                            continue;
                        }
                    } else {
                        if !takes_val && new_tokens.iter().any(|t| t == token) {
                            j += 1;
                            continue;
                        }
                        new_tokens.push(token.clone());
                        j += 1;
                        continue;
                    }
                }

                if let Some(consumed) = extract_config_flag(token, next_token, is_silent, &mut overrides) {
                    j += consumed;
                    continue;
                }

                new_tokens.push(token.clone());
                j += 1;
            }
            new_tokens
        }
    } else {
        // No subcommand (e.g. `rnpm --version`, `rnpm --help`, or `rnpm`)
        let root_cmd = Cli::command();
        let mut new_tokens = vec![program.clone()];
        let mut j = 0;
        while j < rest.len() {
            let token = &rest[j];
            let next_token = rest.get(j + 1).map(|s| s.as_str());

            if token == "--" {
                new_tokens.push(token.clone());
                new_tokens.extend(rest[j + 1..].iter().cloned());
                break;
            }

            if let Some(takes_val) = is_clap_declared_arg(&root_cmd, token) {
                if takes_val && !token.contains('=') {
                    if let Some(next) = next_token {
                        if !next.starts_with('-') {
                            new_tokens.push(token.clone());
                            new_tokens.push(next.to_string());
                            j += 2;
                            continue;
                        }
                    }
                    if let Some(consumed) = extract_config_flag(token, next_token, is_silent, &mut overrides) {
                        j += consumed;
                        continue;
                    }
                } else {
                    new_tokens.push(token.clone());
                    j += 1;
                    continue;
                }
            }

            if let Some(consumed) = extract_config_flag(token, next_token, is_silent, &mut overrides) {
                j += consumed;
                continue;
            }

            new_tokens.push(token.clone());
            j += 1;
        }
        new_tokens
    };

    if !overrides.is_empty() {
        rnpm_config::set_process_cli_overrides(overrides);
    }

    result
}

fn parse_package_spec(spec: &str) -> (String, String) {
    if let Some(stripped) = spec.strip_prefix('@') {
        if let Some(idx) = stripped.find('@') {
            (
                format!("@{}", &stripped[..idx]),
                stripped[idx + 1..].to_string(),
            )
        } else {
            (spec.to_string(), "*".to_string())
        }
    } else if let Some(idx) = spec.find('@') {
        (spec[..idx].to_string(), spec[idx + 1..].to_string())
    } else {
        (spec.to_string(), "*".to_string())
    }
}

pub(crate) async fn execute_exec(
    current_dir: &std::path::Path,
    command: &str,
    package_specs: &[String],
    args: &[String],
    registry: Option<String>,
    cache: Option<PathBuf>,
    offline: bool,
) -> anyhow::Result<()> {
    if command.is_empty() && package_specs.is_empty() {
        return Ok(());
    }
    let (cmd_pkg_name, _) = parse_package_spec(command);
    let cmd_bin_name = if let Some(slash) = cmd_pkg_name.find('/') {
        &cmd_pkg_name[slash + 1..]
    } else {
        &cmd_pkg_name
    };

    let cache_path = cache.clone().unwrap_or_else(|| {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            PathBuf::from(appdata).join("rnpm").join("cache")
        } else {
            std::env::temp_dir().join(".rnpm-cache")
        }
    });

fn find_system_binary(command: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for p in std::env::split_paths(&path_var) {
        let direct = p.join(command);
        if direct.is_file() {
            return Some(direct);
        }
        #[cfg(windows)]
        {
            for ext in &[".cmd", ".exe", ".bat", ".ps1"] {
                let with_ext = p.join(format!("{command}{ext}"));
                if with_ext.is_file() {
                    return Some(with_ext);
                }
            }
        }
    }
    None
}

    let binary_to_run = if package_specs.is_empty() {
        // When -p is NOT provided:
        // 1. Check local node_modules/.bin first, or system PATH
        let local_bin = rnpm_lifecycle::find_local_binary(current_dir, &cmd_pkg_name)
            .or_else(|| rnpm_lifecycle::find_local_binary(current_dir, cmd_bin_name))
            .or_else(|| rnpm_lifecycle::find_local_binary(current_dir, command))
            .or_else(|| find_system_binary(command));

        if let Some(bin_path) = local_bin {
            bin_path
        } else {
            // Not found locally: derive package and version from command, and install into ephemeral _npx cache
            let (pkg_name, version_req) = parse_package_spec(command);
            let safe_spec: String = command
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();

            let npx_env_dir = cache_path.join("_npx").join(&safe_spec);
            let bin_target = rnpm_lifecycle::find_local_binary(&npx_env_dir, &cmd_pkg_name)
                .or_else(|| rnpm_lifecycle::find_local_binary(&npx_env_dir, cmd_bin_name))
                .or_else(|| rnpm_lifecycle::find_local_binary(&npx_env_dir, command));

            if let Some(target) = bin_target {
                target
            } else {
                if offline {
                    return Err(anyhow::anyhow!(
                        "Package '{}' is not installed locally and offline mode prevents dynamic fetching",
                        command
                    ));
                }

                std::fs::create_dir_all(&npx_env_dir)?;

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
                if let Some(target) = rnpm_lifecycle::find_local_binary(&npx_env_dir, &cmd_pkg_name)
                {
                    target
                } else if let Some(target) =
                    rnpm_lifecycle::find_local_binary(&npx_env_dir, cmd_bin_name)
                {
                    target
                } else if let Some(target) =
                    rnpm_lifecycle::find_local_binary(&npx_env_dir, command)
                {
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
                    found.ok_or_else(|| {
                        anyhow::anyhow!(
                            "Could not determine binary to run for package '{}'",
                            command
                        )
                    })?
                }
            }
        }
    } else {
        // When -p is provided:
        // Strictly install packages provided via -p into ephemeral _npx cache,
        // and execute command from the resulting node_modules/.bin
        let mut sorted_specs = package_specs.to_vec();
        sorted_specs.sort();
        let raw_spec = sorted_specs.join("_");
        let safe_spec: String = raw_spec
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let npx_env_dir = cache_path.join("_npx").join(&safe_spec);
        let bin_target = rnpm_lifecycle::find_local_binary(&npx_env_dir, command)
            .or_else(|| rnpm_lifecycle::find_local_binary(&npx_env_dir, cmd_bin_name))
            .or_else(|| rnpm_lifecycle::find_local_binary(&npx_env_dir, &cmd_pkg_name));

        if let Some(target) = bin_target {
            target
        } else {
            if offline {
                return Err(anyhow::anyhow!(
                    "Package(s) '{}' not installed locally and offline mode prevents dynamic fetching",
                    package_specs.join(", ")
                ));
            }

            std::fs::create_dir_all(&npx_env_dir)?;

            let mut deps = serde_json::Map::new();
            for spec in package_specs {
                let (pkg_name, version_req) = parse_package_spec(spec);
                deps.insert(pkg_name, serde_json::Value::String(version_req));
            }

            let minimal_manifest = serde_json::json!({
                "name": "rnpm-exec-env",
                "version": "1.0.0",
                "dependencies": deps
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

            if let Some(target) = rnpm_lifecycle::find_local_binary(&npx_env_dir, command) {
                target
            } else if let Some(target) =
                rnpm_lifecycle::find_local_binary(&npx_env_dir, cmd_bin_name)
            {
                target
            } else if let Some(target) =
                rnpm_lifecycle::find_local_binary(&npx_env_dir, &cmd_pkg_name)
            {
                target
            } else {
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
                found.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Could not determine binary to run for command '{}'",
                        command
                    )
                })?
            }
        }
    };

    // Execute the resolved binary with ancestor bin directories prepended to PATH
    let mut path_entries = rnpm_lifecycle::collect_ancestor_bin_dirs(current_dir);
    if let Some(parent_bin) = binary_to_run.parent() {
        if !path_entries.contains(&parent_bin.to_path_buf()) {
            path_entries.insert(0, parent_bin.to_path_buf());
        }
    }

    let mut env = lifecycle_config_env(current_dir);
    env.insert("npm_lifecycle_event".into(), "npx".into());
    env.insert("npm_command".into(), "exec".into());
    let status = rnpm_lifecycle::execute_binary_async(
        &binary_to_run,
        args,
        current_dir,
        &path_entries,
        &env,
    )
    .await?;

    if !status.success() {
        let code = rnpm_lifecycle::extract_exit_status_code(&status);
        return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
            exit_code: code,
            message: format!("Process exited with status code: {}", code),
        }));
    }

    Ok(())
}

/// Rewrites a relative local package spec (`./x`, `../x.tgz`, `file:x`, or an
/// existing relative path) to an absolute path anchored at `base`. Registry,
/// git, URL, and absolute specs are returned unchanged.
fn rebase_local_spec(spec: &str, base: &std::path::Path) -> String {
    let (prefix, path_part) = match spec.strip_prefix("file:") {
        Some(rest) => ("file:", rest),
        None => ("", spec),
    };
    let looks_relative = path_part.starts_with("./")
        || path_part.starts_with("../")
        || path_part.starts_with(".\\")
        || path_part.starts_with("..\\")
        || path_part == "."
        || path_part == "..";
    let is_local = !prefix.is_empty() || looks_relative || {
        let lower = path_part.to_ascii_lowercase();
        (lower.ends_with(".tgz") || lower.ends_with(".tar.gz") || lower.ends_with(".tar"))
            && !path_part.contains("://")
    } || (!path_part.contains(':')
        && !path_part.starts_with('@')
        && base.join(path_part).is_dir()
        && (path_part.contains('/') || path_part.contains('\\')));
    let path = std::path::Path::new(path_part);
    if !is_local || path_part.is_empty() || path.is_absolute() || path_part.starts_with("//") {
        return spec.to_string();
    }
    format!("{prefix}{}", base.join(path).display())
}

/// Records `--json` in the process-wide CLI overrides so lifecycle output
/// emitted outside this crate can route banners to stderr, as npm does.
fn mark_json_mode() {
    let mut overrides = rnpm_config::get_process_cli_overrides().unwrap_or_default();
    overrides.insert("json".to_string(), "true".to_string());
    rnpm_config::set_process_cli_overrides(overrides);
}

pub(crate) fn run_lifecycle_hook(
    package_dir: &std::path::Path,
    manifest: &Manifest,
    hook_name: &str,
    ignore_scripts: bool,
    foreground_scripts: bool,
    is_silent: bool,
    json: bool,
) -> anyhow::Result<()> {
    if ignore_scripts {
        return Ok(());
    }

    if let Some(script_cmd) = manifest.scripts.get(hook_name) {
        if !is_silent && foreground_scripts {
            let id = match (&manifest.name, &manifest.version) {
                (Some(name), Some(version)) => format!("{name}@{version}"),
                (Some(name), None) => name.clone(),
                _ => String::new(),
            };
            let banner = format!("\n> {}{hook_name}\n> {script_cmd}\n", if id.is_empty() { id } else { format!("{id} ") });
            if json { eprintln!("{banner}"); } else { println!("{banner}"); }
        }
        let mut ctx =
            LifecycleContext::new(package_dir, package_dir, manifest.name.as_deref().unwrap_or(""), hook_name, script_cmd);
        ctx.package_version = manifest.version.clone();
        ctx.foreground_scripts = foreground_scripts;
        ctx.capture_output = !foreground_scripts;
        ctx.extra_env = lifecycle_config_env(package_dir);
        let status = execute_lifecycle_script(&ctx)?;
        if !status.success() {
            return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError::lifecycle_failure(&ctx, &status)));
        }
    }

    Ok(())
}

pub(crate) async fn execute_publish(
    current_dir: PathBuf,
    target: PathBuf,
    tag: String,
    access: Option<String>,
    dry_run: bool,
    otp: Option<String>,
    provenance: bool,
    registry: Option<String>,
    ignore_scripts: bool,
    json: bool,
) -> anyhow::Result<()> {
    let package_dir = if target.is_absolute() {
        target
    } else {
        current_dir.join(target)
    };

    let manifest_path = package_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow::anyhow!(
            "npm error code ENOENT\nnpm error package.json not found in {}",
            package_dir.display()
        ));
    }

    let manifest_content = std::fs::read_to_string(&manifest_path)?;
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest_content).map_err(|e| {
            anyhow::anyhow!(
                "npm error code EJSONPARSE\nnpm error Failed to parse package.json: {e}"
            )
        })?;

    if manifest_json
        .get("private")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(anyhow::anyhow!(
            "npm error code EPRIVATE\nnpm error This package has been marked as private\nnpm error Remove the 'private' field from package.json to publish it."
        ));
    }

    let manifest = Manifest::from_file(&manifest_path)?;
    let pkg_name = manifest.name.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "npm error code ENEEDPACKAGE\nnpm error package.json must contain a \"name\" field"
        )
    })?;
    let pkg_version = manifest.version.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "npm error code ENEEDPACKAGE\nnpm error package.json must contain a \"version\" field"
        )
    })?;

    if let Some(ref acc) = access {
        if acc != "public" && acc != "restricted" {
            return Err(anyhow::anyhow!(
                "npm error code EUSAGE\nnpm error Invalid access type: '{}'. Valid options are 'public' or 'restricted'.",
                acc
            ));
        }
    }

    if provenance {
        let is_ci = std::env::var("CI").is_ok()
            || std::env::var("GITHUB_ACTIONS").is_ok()
            || std::env::var("GITLAB_CI").is_ok()
            || std::env::var("CIRCLECI").is_ok()
            || std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").is_ok();
        if !is_ci && !dry_run {
            return Err(anyhow::anyhow!(
                "npm error code EUSAGE\nnpm error --provenance can only be used from a supported CI/CD environment (such as GitHub Actions or GitLab CI)"
            ));
        }
    }

    let script_config = rnpm_config::Config::load(Some(&package_dir))?;
    let is_silent = script_config.get("loglevel") == Some("silent");
    let foreground = script_config.get_bool("foreground-scripts").unwrap_or(true);

    // 1. prepublishOnly
    run_lifecycle_hook(&package_dir, &manifest, "prepublishOnly", ignore_scripts, foreground, is_silent, json)?;

    // 2. prepack
    run_lifecycle_hook(&package_dir, &manifest, "prepack", ignore_scripts, foreground, is_silent, json)?;

    run_lifecycle_hook(&package_dir, &manifest, "prepare", ignore_scripts, foreground, is_silent, json)?;

    let updated_manifest = Manifest::from_file(&manifest_path).unwrap_or_else(|_| manifest.clone());
    let updated_manifest_content =
        std::fs::read_to_string(&manifest_path).unwrap_or_else(|_| manifest_content.clone());
    let updated_manifest_json: serde_json::Value =
        serde_json::from_str(&updated_manifest_content).unwrap_or_else(|_| manifest_json.clone());

    // 3. Packaging into memory using canonical rnpm-fs tarball pack logic
    let (summary, tarball_bytes) = match rnpm_fs::pack_directory(&package_dir, None) {
        Ok(res) => res,
        Err(e) => {
            return Err(anyhow::anyhow!("npm error pack failed: {e}"));
        }
    };

    // 4. postpack
    run_lifecycle_hook(&package_dir, &updated_manifest, "postpack", ignore_scripts, foreground, is_silent, json)?;

    if dry_run {
        if json {
            let id = format!("{}@{}", summary.name, summary.version);
            let files_json = summary.files.iter().map(|f| serde_json::json!({
                "path": f.path,
                "size": f.size,
                "mode": f.mode,
            })).collect::<Vec<_>>();
            let pkg_details = serde_json::json!({
                "id": id,
                "name": summary.name,
                "version": summary.version,
                "size": summary.package_size,
                "unpackedSize": summary.unpacked_size,
                "shasum": summary.shasum,
                "integrity": summary.integrity,
                "filename": summary.filename,
                "files": files_json,
                "entryCount": summary.entry_count,
                "bundled": summary.bundled,
            });
            let json_output = serde_json::json!({ summary.name.clone(): pkg_details });
            println!("{}", serde_json::to_string_pretty(&json_output)?);
        } else {
            if !is_silent {
                print_pack_notices(&summary);
            }
            if provenance {
                eprintln!(
                    "npm notice provenance would be generated and verified in CI environment"
                );
            }
            if !is_silent { println!("+ {}@{}", summary.name, summary.version); }
        }
        let config = rnpm_config::Config::load(Some(&package_dir))?;
        if config.get("loglevel") != Some("silent") {
            let registry = registry.as_deref().or_else(|| updated_manifest_json.get("publishConfig")
                .and_then(|c| c.get("registry")).and_then(|v| v.as_str()))
                .unwrap_or(config.npmrc.registry.as_str());
            let registry_url = Url::parse(registry)?;
            if config.npmrc.get_auth_token(&registry_url).is_none() {
                eprintln!("npm warn publish This command requires you to be logged in to {registry_url} (dry-run)");
            }
            eprintln!("npm notice Publishing to {registry_url} with tag {tag} and {} access (dry-run)",
                access.as_deref().or_else(|| updated_manifest_json.get("publishConfig")
                    .and_then(|c| c.get("access")).and_then(|v| v.as_str())).unwrap_or("default"));
        }
        return Ok(());
    }

    // 5. publish
    run_lifecycle_hook(&package_dir, &updated_manifest, "publish", ignore_scripts, foreground, is_silent, json)?;

    let config = rnpm_config::Config::load(Some(&package_dir)).unwrap_or_default();
    let registry_url = if let Some(ref reg_str) = registry {
        Url::parse(reg_str).map_err(|e| {
            anyhow::anyhow!(
                "npm error code EINVALIDURL\nnpm error Invalid registry URL '{reg_str}': {e}"
            )
        })?
    } else if let Some(pub_reg) = updated_manifest_json
        .get("publishConfig")
        .and_then(|c| c.get("registry"))
        .and_then(|r| r.as_str())
    {
        Url::parse(pub_reg).map_err(|e| anyhow::anyhow!("npm error code EINVALIDURL\nnpm error Invalid publishConfig registry URL '{pub_reg}': {e}"))?
    } else {
        config.npmrc.registry_for_package(&pkg_name).clone()
    };

    let effective_access = access.as_deref().or_else(|| {
        updated_manifest_json
            .get("publishConfig")
            .and_then(|c| c.get("access"))
            .and_then(|a| a.as_str())
    });

    let mut client_config = rnpm_registry::RegistryClientConfig {
        default_registry: registry_url.clone(),
        scoped_registries: config.npmrc.scoped_registries.clone(),
        auth_tokens: config.npmrc.auth_tokens.clone(),
        ..Default::default()
    };
    let token = config.npmrc.get_auth_token(&registry_url);
    if token.is_none() {
        return Err(anyhow::anyhow!(
            "npm error code ENEEDAUTH\nnpm error This command requires you to be logged in to <{registry_url}>\nnpm error You need a valid auth token to publish."
        ));
    }
    if let Some(token) = token {
        client_config.auth_token = Some(token.to_string());
    }

    let client = rnpm_registry::RegistryClient::with_config(client_config)?;

    let tarball_data = rnpm_registry::PublishTarballData {
        filename: &summary.filename,
        bytes: &tarball_bytes,
        shasum: &summary.shasum,
        integrity: &summary.integrity,
    };

    let desc = updated_manifest_json
        .get("description")
        .and_then(|d| d.as_str());

    let payload_opts = rnpm_registry::PublishPayloadOptions {
        name: &pkg_name,
        version: &pkg_version,
        description: desc,
        tag: &tag,
        access: effective_access,
        manifest: &updated_manifest_json,
        tarball: tarball_data,
        registry_url: &registry_url,
        provenance_attestation: None,
    };

    let payload = rnpm_registry::create_publish_payload(&payload_opts);

    // Send HTTP PUT request to registry
    client
        .publish_to(&registry_url, &pkg_name, &payload, otp.as_deref())
        .await?;

    if json {
        let json_output = serde_json::json!({
            summary.name.clone(): {
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
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        if !is_silent {
            print_pack_notices(&summary);
        }
        if provenance {
            eprintln!("npm notice published with provenance attestations");
        }
        println!("+ {}@{}", summary.name, summary.version);
    }

    // 6. postpublish
    run_lifecycle_hook(
        &package_dir,
        &updated_manifest,
        "postpublish",
        ignore_scripts,
        foreground,
        is_silent,
        json,
    )?;

    Ok(())
}



async fn execute_login(
    current_dir: &std::path::Path,
    registry: Option<String>,
    auth_type: Option<String>,
    scope: Option<String>,
    otp: Option<String>,
) -> anyhow::Result<()> {
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    let registry_url = if let Some(ref reg_str) = registry {
        Url::parse(reg_str).map_err(|e| {
            anyhow::anyhow!(
                "npm error code EINVALIDURL\nnpm error Invalid registry URL '{reg_str}': {e}"
            )
        })?
    } else {
        config.npmrc.registry.clone()
    };

    let auth_str = auth_type.unwrap_or_else(|| "web".to_string());
    let token = std::env::var("NPM_TOKEN")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let token = if let Some(token) = token {
        token
    } else if auth_str == "legacy" || auth_str == "basic" {
        let username = std::env::var("NPM_USERNAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "npm error code ENEEDAUTH\nnpm error set NPM_USERNAME for legacy login"
                )
            })?;
        let password = std::env::var("NPM_PASSWORD")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "npm error code ENEEDAUTH\nnpm error set NPM_PASSWORD for legacy login"
                )
            })?;
        let mut client_config = rnpm_registry::RegistryClientConfig {
            default_registry: registry_url.clone(),
            ..Default::default()
        };
        client_config.scoped_registries = config.npmrc.scoped_registries.clone();
        let client = rnpm_registry::RegistryClient::with_config(client_config)?;
        let otp = otp.or_else(|| std::env::var("NPM_OTP").ok());
        let response = client
            .login_legacy(Some(&registry_url), &username, &password, otp.as_deref())
            .await?;
        response.get("token").and_then(|v| v.as_str()).map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("npm error code EAUTHUNKNOWN\nnpm error registry login response did not contain a token"))?
    } else {
        return Err(anyhow::anyhow!(
            "npm error code ENEEDAUTH\nnpm error Set NPM_TOKEN to a registry token before running rnpm login"
        ));
    };

    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map_err(|_| {
            anyhow::anyhow!(
                "npm error code ENOENT\nnpm error Cannot determine the user home directory"
            )
        })?;
    let user_npmrc = PathBuf::from(home).join(".npmrc");
    let key = auth_key_for_registry(&registry_url);
    rnpm_config::set_config_value_in_file(&user_npmrc, &key, &token)?;
    if let Some(scope) = scope {
        let scope = if scope.starts_with('@') {
            scope
        } else {
            format!("@{scope}")
        };
        rnpm_config::set_config_value_in_file(
            &user_npmrc,
            &format!("{scope}:registry"),
            registry_url.as_str(),
        )?;
    }
    let _ = current_dir;
    println!(
        "Logged in to {} using {} authentication",
        registry_url, auth_str
    );

    Ok(())
}

fn auth_key_for_registry(registry: &Url) -> String {
    let host = registry.host_str().unwrap_or_default();
    let port = registry.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = if registry.path().is_empty() {
        "/".to_string()
    } else {
        format!("{}/", registry.path().trim_end_matches('/'))
    };
    format!("//{host}{port}{path}:_authToken")
}




pub(crate) fn make_registry_client(
    current_dir: &Path,
    registry: Option<String>,
) -> anyhow::Result<(Url, rnpm_registry::RegistryClient)> {
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    let registry_url = match registry {
        Some(value) => Url::parse(&value).map_err(|e| {
            anyhow::anyhow!(
                "npm error code EINVALIDURL\nnpm error Invalid registry URL '{value}': {e}"
            )
        })?,
        None => config.npmrc.registry.clone(),
    };
    let mut client_config = rnpm_registry::RegistryClientConfig {
        default_registry: registry_url.clone(),
        scoped_registries: config.npmrc.scoped_registries.clone(),
        auth_tokens: config.npmrc.auth_tokens.clone(),
        ..Default::default()
    };
    if let Some(token) = config.npmrc.get_auth_token(&registry_url) {
        client_config.auth_token = Some(token.to_string());
    }
    Ok((
        registry_url,
        rnpm_registry::RegistryClient::with_config(client_config)?,
    ))
}





pub(crate) fn split_package_version(spec: &str) -> anyhow::Result<(&str, &str)> {
    let at = if let Some(stripped) = spec.strip_prefix('@') {
        stripped.rfind('@').map(|i| i + 1)
    } else {
        spec.rfind('@')
    };
    let at = at.ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error package must include a version (for example pkg@1.2.3)"))?;
    let (name, version) = spec.split_at(at);
    let version = version.strip_prefix('@').unwrap_or(version);
    if name.is_empty() || version.is_empty() {
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\nnpm error invalid package version specifier"
        ));
    }
    Ok((name, version))
}

pub(crate) fn package_name_from_spec(spec: &str) -> &str {
    if let Some(stripped) = spec.strip_prefix('@') {
        stripped
            .rfind('@')
            .map(|idx| &spec[..idx + 1])
            .unwrap_or(spec)
    } else {
        spec.split_once('@').map(|(name, _)| name).unwrap_or(spec)
    }
}

pub(crate) fn package_name_from_manifest(current_dir: &Path) -> anyhow::Result<String> {
    let path = current_dir.join("package.json");
    let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    value
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "npm error code ENEEDPACKAGE\nnpm error package.json must contain a name"
            )
        })
}

fn resolve_local_package_dir(current_dir: &Path, package: &str) -> anyhow::Result<PathBuf> {
    let path = if package == "." || package.is_empty() {
        current_dir.to_path_buf()
    } else {
        current_dir.join("node_modules").join(package)
    };
    if path.join("package.json").is_file() {
        Ok(path)
    } else {
        Err(anyhow::anyhow!(
            "npm error code ENOENT\nnpm error package '{}' is not installed",
            package
        ))
    }
}

fn package_manifest_value(path: &Path) -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(
        path.join("package.json"),
    )?)?)
}


fn print_fixed_summary(
    fixed_vulns: usize,
    fixed_counts: &audit::VulnerabilitiesCount,
    pkg_count: usize,
) {
    let mut parts = Vec::new();
    if fixed_counts.critical > 0 {
        parts.push(format!("{} critical", fixed_counts.critical));
    }
    if fixed_counts.high > 0 {
        parts.push(format!("{} high", fixed_counts.high));
    }
    if fixed_counts.moderate > 0 {
        parts.push(format!("{} moderate", fixed_counts.moderate));
    }
    if fixed_counts.low > 0 {
        parts.push(format!("{} low", fixed_counts.low));
    }
    if fixed_counts.info > 0 {
        parts.push(format!("{} info", fixed_counts.info));
    }
    let details = if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    };
    let vuln_word = if fixed_vulns == 1 {
        "vulnerability"
    } else {
        "vulnerabilities"
    };
    let pkg_word = if pkg_count == 1 {
        "package"
    } else {
        "packages"
    };
    println!("fixed {fixed_vulns} {vuln_word}{details} in {pkg_count} {pkg_word}");
}

async fn run_audit_fix(
    project_dir: &Path,
    registry: Option<String>,
    dry_run: bool,
    force: bool,
) -> anyhow::Result<()> {
    let manifest_path = project_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow::anyhow!(
            "npm error code ENOENT\nnpm error package.json not found"
        ));
    }
    let lock_path = project_dir.join("package-lock.json");
    if !lock_path.exists() {
        return Err(anyhow::anyhow!(
            "npm error code ENOLOCK\n\
             npm error This command requires an existing lockfile.\n\
             npm error Try creating one with `rnpm install`."
        ));
    }

    if force {
        eprintln!("npm warn audit --force installing breaking changes if necessary");
    }

    // Run initial audit scan to retrieve list of vulnerability advisories
    let (initial_report, _, advisories) =
        audit::build_audit_report_with_advisories(project_dir, registry.clone()).await?;
    let initial_vulns = initial_report.metadata.vulnerabilities.total;

    if initial_vulns == 0 {
        println!("found 0 vulnerabilities");
        println!("fixed 0 packages");
        return Ok(());
    }

    // Parse package.json to identify declared dependency ranges
    let manifest_content = std::fs::read_to_string(&manifest_path)?;
    let manifest_val: serde_json::Value = serde_json::from_str(&manifest_content)?;

    let mut declared_direct: BTreeMap<String, String> = BTreeMap::new();
    for sec_name in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(sec) = manifest_val.get(sec_name).and_then(|s| s.as_object()) {
            for (k, v) in sec {
                if let Some(s) = v.as_str() {
                    declared_direct.insert(k.clone(), s.to_string());
                }
            }
        }
    }

    // Group advisories by package name
    let mut advs_by_pkg: BTreeMap<String, Vec<&audit::AuditAdvisory>> = BTreeMap::new();
    for adv in &advisories {
        advs_by_pkg.entry(adv.name.clone()).or_default().push(adv);
    }

    let lockfile_raw = std::fs::read_to_string(&lock_path)?;
    let existing_lockfile = rnpm_lockfile::parse_and_migrate(&lockfile_raw)?;

    let mut targets_to_update: Vec<String> = Vec::new();
    let mut packages_to_upgrade: BTreeMap<String, (rnpm_core::semver::Version, String)> =
        BTreeMap::new();
    let mut packages_needing_force = 0usize;
    let mut manifest_updates: Vec<(String, String)> = Vec::new();

    for (pkg_name, pkg_advs) in &advs_by_pkg {
        let mut old_ver_str = String::new();
        for adv in pkg_advs {
            if old_ver_str.is_empty() {
                old_ver_str = adv.installed_version.clone();
            }
        }
        let _installed_ver = rnpm_core::semver::Version::parse(&old_ver_str)
            .unwrap_or_else(|_| rnpm_core::semver::Version::new(0, 0, 0));

        let mut in_range_candidates: Vec<rnpm_core::semver::Version> = Vec::new();
        let mut out_of_range_candidates: Vec<rnpm_core::semver::Version> = Vec::new();

        // 1. Direct dependency in package.json
        if let Some(declared_range_str) = declared_direct.get(pkg_name) {
            let declared_range_opt = rnpm_core::semver::Range::parse(declared_range_str).ok();
            for adv in pkg_advs {
                if let Some(target) = audit::resolve_target_patched_version(
                    adv.patched_versions.as_deref(),
                    &adv.vulnerable_versions,
                ) {
                    if let Some(ref r) = declared_range_opt {
                        if r.satisfies(&target) {
                            in_range_candidates.push(target);
                        } else {
                            out_of_range_candidates.push(target);
                        }
                    } else {
                        out_of_range_candidates.push(target);
                    }
                }
            }

            if let Some(best_in_range) = in_range_candidates.into_iter().max() {
                packages_to_upgrade.insert(pkg_name.clone(), (best_in_range, old_ver_str.clone()));
                targets_to_update.push(pkg_name.clone());
            } else if force {
                if let Some(best_out_of_range) = out_of_range_candidates.into_iter().max() {
                    let target_ver = best_out_of_range;
                    packages_to_upgrade
                        .insert(pkg_name.clone(), (target_ver.clone(), old_ver_str.clone()));
                    let new_range = format!("^{target_ver}");
                    manifest_updates.push((pkg_name.clone(), new_range));
                    targets_to_update.push(format!("{pkg_name}@^{target_ver}"));
                } else {
                    packages_needing_force += 1;
                }
            } else {
                packages_needing_force += 1;
            }
        } else {
            // 2. Transitive dependency: evaluate each vulnerable node_path against its enclosing parent package
            let mut any_fixed = false;
            for adv in pkg_advs {
                let parent_loc = if let Some(idx) = adv.node_path.rfind("/node_modules/") {
                    &adv.node_path[..idx]
                } else {
                    ""
                };

                let parent_range_opt = if parent_loc.is_empty() {
                    declared_direct
                        .get(pkg_name)
                        .and_then(|r| rnpm_core::semver::Range::parse(r).ok())
                } else {
                    existing_lockfile.packages.get(parent_loc).and_then(|p| {
                        let empty = BTreeMap::new();
                        let deps = p.dependencies.as_ref().unwrap_or(&empty);
                        deps.get(pkg_name)
                            .or_else(|| {
                                p.optional_dependencies
                                    .as_ref()
                                    .unwrap_or(&empty)
                                    .get(pkg_name)
                            })
                            .and_then(|r| rnpm_core::semver::Range::parse(r).ok())
                    })
                };

                let cur_ver = rnpm_core::semver::Version::parse(&adv.installed_version)
                    .unwrap_or_else(|_| rnpm_core::semver::Version::new(0, 0, 0));

                if let Some(target) = audit::resolve_target_patched_version(
                    adv.patched_versions.as_deref(),
                    &adv.vulnerable_versions,
                ) {
                    let parent_allows = parent_range_opt
                        .as_ref()
                        .map(|r| r.satisfies(&target))
                        .unwrap_or(false);

                    if parent_allows && target > cur_ver {
                        packages_to_upgrade.insert(
                            pkg_name.clone(),
                            (target.clone(), adv.installed_version.clone()),
                        );
                        targets_to_update.push(format!("{}@{}", adv.node_path, target));
                        any_fixed = true;
                    }
                }
            }

            if !any_fixed {
                packages_needing_force += 1;
            }
        }
    }

    let mut fixed_counts = audit::VulnerabilitiesCount::default();
    for (pkg_name, (target_ver, _old_ver)) in &packages_to_upgrade {
        let mut highest_sev: Option<audit::Severity> = None;
        if let Some(advs) = advs_by_pkg.get(pkg_name) {
            for adv in advs {
                let is_still_vuln = match rnpm_core::semver::Range::parse(&adv.vulnerable_versions)
                {
                    Ok(r) => r.satisfies(target_ver),
                    Err(_) => false,
                };
                if !is_still_vuln {
                    highest_sev = match highest_sev {
                        Some(cur) => Some(cur.max(adv.severity)),
                        None => Some(adv.severity),
                    };
                }
            }
        }
        if let Some(sev) = highest_sev {
            match sev {
                audit::Severity::Info => fixed_counts.info += 1,
                audit::Severity::Low => fixed_counts.low += 1,
                audit::Severity::Moderate => fixed_counts.moderate += 1,
                audit::Severity::High => fixed_counts.high += 1,
                audit::Severity::Critical => fixed_counts.critical += 1,
            }
            fixed_counts.total += 1;
        }
    }

    if targets_to_update.is_empty() {
        println!("found 0 vulnerabilities to fix");
        audit::print_concise_audit_summary(&initial_report);
        if packages_needing_force > 0 {
            eprintln!("npm warn audit Semver-major updates or breaking changes require `rnpm audit fix --force`");
        }
        return Ok(());
    }

    if dry_run {
        for (pkg_name, (target_ver, old_ver)) in &packages_to_upgrade {
            println!("would update {pkg_name} from {old_ver} to {target_ver}");
        }
        print_fixed_summary(fixed_counts.total, &fixed_counts, packages_to_upgrade.len());
        return Ok(());
    }

    // 1. If --force updated declared ranges, update package.json PRESERVING key order and formatting!
    if !manifest_updates.is_empty() {
        let content = std::fs::read_to_string(&manifest_path)?;
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        for (pkg_name, new_range) in &manifest_updates {
            let key_str = format!("\"{pkg_name}\"");
            for line in lines.iter_mut() {
                if let Some(pos) = line.find(&key_str) {
                    if let Some(colon_pos) = line[pos..].find(':') {
                        let actual_colon = pos + colon_pos;
                        if let Some(first_quote) = line[actual_colon..].find('"') {
                            let val_start = actual_colon + first_quote + 1;
                            if let Some(second_quote) = line[val_start..].find('"') {
                                let val_end = val_start + second_quote;
                                let mut new_line = line[..val_start].to_string();
                                new_line.push_str(new_range);
                                new_line.push_str(&line[val_end..]);
                                *line = new_line;
                                break;
                            }
                        }
                    }
                }
            }
        }
        let mut new_content = lines.join("\n");
        if content.ends_with('\n') {
            new_content.push('\n');
        }
        std::fs::write(&manifest_path, new_content)?;
    }

    // 2. Perform real package resolution, tarball extraction, and lockfile updates via Installer!
    let config = rnpm_config::Config::load(Some(project_dir)).unwrap_or_default();
    let options = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        registry_url: registry.clone(),
        ignore_scripts: config.get_bool("ignore-scripts").unwrap_or(false),
        foreground_scripts: config.get_bool("foreground-scripts").unwrap_or(false),
        strict_sandbox: config.get_bool("strict-sandbox").unwrap_or(false),
        ..Default::default()
    };

    let mut vulnerability_constraints: std::collections::HashMap<
        String,
        Vec<rnpm_core::semver::Range>,
    > = std::collections::HashMap::new();
    for (pkg_name, pkg_advs) in &advs_by_pkg {
        for adv in pkg_advs {
            if let Ok(r) = rnpm_core::semver::Range::parse(&adv.vulnerable_versions) {
                vulnerability_constraints
                    .entry(pkg_name.clone())
                    .or_default()
                    .push(r);
            }
        }
    }

    let mut installer = Installer::new(options)?;
    let _update_summary = installer
        .update_with_constraints(&targets_to_update, &vulnerability_constraints)
        .await?;

    // 3. Re-run audit to count actual remaining vs fixed vulnerabilities
    let (post_report, _, _) = audit::build_audit_report_with_advisories(project_dir, registry)
        .await
        .unwrap_or((initial_report.clone(), None, Vec::new()));
    let remaining_vulns = post_report.metadata.vulnerabilities.total;
    let actual_fixed = initial_vulns.saturating_sub(remaining_vulns);

    if actual_fixed > 0 {
        print_fixed_summary(actual_fixed, &fixed_counts, packages_to_upgrade.len());
    }

    if remaining_vulns > 0 {
        audit::print_concise_audit_summary(&post_report);
        if !force && packages_needing_force > 0 {
            eprintln!("npm warn audit Semver-major updates or breaking changes require `rnpm audit fix --force`");
        }
    } else {
        println!("found 0 vulnerabilities");
    }

    Ok(())
}

fn should_cleanup_trash(cmd: &Commands) -> bool {
    match cmd {
        Commands::Install { dry_run, .. } if *dry_run => false,
        Commands::Ci { dry_run, .. } if *dry_run => false,
        Commands::Prune { dry_run, .. } if *dry_run => false,
        Commands::Dedupe { dry_run, .. } if *dry_run => false,
        Commands::Fix { dry_run, .. } if *dry_run => false,
        Commands::Install { .. }
        | Commands::Ci { .. }
        | Commands::Update { .. }
        | Commands::Uninstall { .. }
        | Commands::Prune { .. }
        | Commands::Dedupe { .. }
        | Commands::InstallCiTest { .. }
        | Commands::InstallTest { .. }
        | Commands::InstallScripts { .. }
        | Commands::Fix { .. } => true,
        Commands::Cache {
            action: CacheAction::Clean { .. },
            ..
        } => true,
        _ => false,
    }
}

pub(crate) fn format_duration(d: std::time::Duration) -> String {
    let millis = d.as_millis();
    if millis < 1000 {
        format!("{millis}ms")
    } else {
        let secs = d.as_secs_f64();
        if (secs * 10.0).round() % 10.0 == 0.0 {
            format!("{:.0}s", secs)
        } else {
            format!("{:.1}s", secs)
        }
    }
}

pub(crate) async fn run_cli(cli: Cli, dir: Option<PathBuf>) -> anyhow::Result<()> {
    let current_dir = match dir {
        Some(d) => d,
        None => std::env::current_dir()?,
    };

    let silent =
        rnpm_config::Config::load(Some(&current_dir))?.get("loglevel") == Some("silent");

    // Clean up any leftover .rnpm-trash-* directories only for commands that mutate node_modules or clean cache
    if should_cleanup_trash(&cli.command) {
        rnpm_install::trash::cleanup_leftover_trash(&current_dir);
    }

    match cli.command {
        Commands::Install {
            packages,
            registry,
            cache,
            offline,
            force,
            ignore_scripts,
            foreground_scripts,
            strict_sandbox,
            save_dev,
            save_exact,
            save_prefix,
            save_prod,
            save_optional,
            save_peer,
            no_save,
            package_lock_only,
            omit,
            legacy_peer_deps,
            strict_peer_deps,
            global,
            prefix,
            include,
            no_package_lock,
            package_lock,
            lockfile_version,
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
            timing,
            install_strategy,
            wait_for_trash,
            detached_trash,
            json,
        } => {
            if json {
                mark_json_mode();
            }
            let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
            let timing_val = timing
                || config.get_bool("timing").unwrap_or(false)
                || std::env::var("RNPM_TIMING")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            let effective_ignore =
                ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false);
            let effective_foreground =
                foreground_scripts || config.get_bool("foreground-scripts").unwrap_or(false);
            let effective_strict =
                strict_sandbox || config.get_bool("strict-sandbox").unwrap_or(false);

            let strategy_str = install_strategy
                .as_deref()
                .or_else(|| config.get("install-strategy"))
                .or_else(|| config.get("install_strategy"))
                .unwrap_or("hoisted");
            let effective_strategy = strategy_str
                .parse::<rnpm_install::InstallStrategy>()
                .unwrap_or_else(|_| {
                    eprintln!("npm warn invalid config install-strategy={} set in command line options", strategy_str);
                    eprintln!("npm warn invalid config Must be one of: hoisted, nested, shallow, linked");
                    rnpm_install::InstallStrategy::Hoisted
                });

            let (omit_dev, omit_optional, omit_peer) =
                parse_omit_and_include_options(&omit, &include);
            let package_lock_val = if no_package_lock || package_lock == Some(false) {
                false
            } else {
                package_lock.unwrap_or(true)
            };
            let audit_val = if no_audit || audit == Some(false) {
                false
            } else {
                audit.unwrap_or_else(|| config.get_bool("audit").unwrap_or(true))
            };
            let fund_val = if no_fund || fund == Some(false) {
                false
            } else {
                fund.unwrap_or_else(|| config.get_bool("fund").unwrap_or(true))
            };
            let mut workspace = workspace;
            let target_dir = if let Some(p) = prefix {
                if p.is_absolute() {
                    p
                } else {
                    current_dir.join(p)
                }
            } else if global {
                rnpm_config::find_global_prefix()
            } else {
                if let Some(root) = rnpm_config::find_workspace_root(&current_dir) {
                    if workspace.is_empty() && !workspaces {
                        if let Some(member) = rnpm_core::workspace::discover_workspaces(&root)?
                            .into_iter().find(|m| m.path == current_dir) {
                            workspace.push(member.name);
                        }
                    }
                    root
                } else {
                    current_dir.clone()
                }
            };
            // Relative local specs were typed relative to the invocation directory;
            // keep them pointing there after switching to the workspace root.
            let packages: Vec<String> = if target_dir != current_dir {
                packages
                    .into_iter()
                    .map(|spec| rebase_local_spec(&spec, &current_dir))
                    .collect()
            } else {
                packages
            };

            let effective_save_prefix = save_prefix
                .or_else(|| config.get("save-prefix").map(ToString::to_string))
                .or_else(|| config.get("save_prefix").map(ToString::to_string));

            let cli_overrides = rnpm_config::get_process_cli_overrides();
            let ws_in_overrides = cli_overrides.as_ref().map(|o| {
                o.get("workspaces").map(|v| v != "false" && v != "0").unwrap_or(false)
                    || o.contains_key("workspace")
            }).unwrap_or(false);
            if workspaces || !workspace.is_empty() || ws_in_overrides {
                let has_ws = if let Ok(content) = std::fs::read_to_string(target_dir.join("package.json")) {
                    content.contains("\"workspaces\"")
                } else {
                    false
                };
                if !has_ws {
                    eprintln!("npm error code ENOWORKSPACES\nnpm error No workspaces found in {}", target_dir.display());
                    std::process::exit(1);
                }
            }

            let options = InstallOptions {
                project_dir: target_dir,
                is_global: global,
                registry_url: registry.clone(),
                cache_dir: cache,
                offline,
                force,
                ignore_scripts: effective_ignore,
                foreground_scripts: effective_foreground,
                strict_sandbox: effective_strict,
                omit_dev,
                omit_optional,
                omit_peer,
                legacy_peer_deps,
                strict_peer_deps,
                save_dev,
                save_exact,
                save_prefix: effective_save_prefix,
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
                lockfile_version: lockfile_version.unwrap_or_else(|| {
                    config
                        .get("lockfile-version")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(3)
                }),
                timing: timing_val,
                install_strategy: effective_strategy,
                wait_for_trash,
                detached_trash,
                silent,
                ..Default::default()
            };

            let start_time = std::time::Instant::now();
            let mut installer = Installer::new(options)?;
            let summary = installer.run().await?;
            let elapsed_str = format_duration(start_time.elapsed());

            if json {
                let json_output = serde_json::json!({
                    "add": [],
                    "added": summary.packages_installed,
                    "audited": 0,
                    "change": [],
                    "changed": 0,
                    "funding": 0,
                    "remove": [],
                    "removed": 0
                });
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            } else if !silent && dry_run {
                println!(
                    "rnpm: dry-run: would install {} package(s)",
                    summary.packages_installed
                );
            } else if !dry_run {
                if !silent {
                    if summary.packages_installed > 0 {
                        let pkg_str = if summary.packages_installed == 1 { "package" } else { "packages" };
                        println!("\nadded {} {} in {}", summary.packages_installed, pkg_str, elapsed_str);
                    } else {
                        println!("\nup to date in {}", elapsed_str);
                    }

                    if fund_val {
                        let count = audit::count_funding_packages(&current_dir);
                        if count > 0 {
                            println!(
                                "\n{} packages are looking for funding\n  run `rnpm fund`",
                                count
                            );
                        }
                    }
                }

                if audit_val {
                    let _ = audit::run_post_install_audit(&current_dir, registry).await;
                }
            }

            if let Some(ref timing_metrics) = summary.timing {
                if timing_val {
                    print!("{}", timing_metrics.format_table());
                    print!("{}", timing_metrics.format_counters());
                }
            }
        }
        Commands::Ci {
            registry,
            cache,
            offline,
            force,
            ignore_scripts,
            foreground_scripts,
            strict_sandbox,
            omit,
            legacy_peer_deps,
            strict_peer_deps,
            package_lock_only,
            include,
            no_package_lock,
            package_lock,
            lockfile_version,
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
            timing,
            install_strategy,
            wait_for_trash,
            detached_trash,
            json,
        } => {
            if json {
                mark_json_mode();
            }
            let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
            let timing_val = timing
                || config.get_bool("timing").unwrap_or(false)
                || std::env::var("RNPM_TIMING")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            let effective_ignore =
                ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false);
            let effective_foreground =
                foreground_scripts || config.get_bool("foreground-scripts").unwrap_or(false);
            let effective_strict =
                strict_sandbox || config.get_bool("strict-sandbox").unwrap_or(false);

            let strategy_str = install_strategy
                .as_deref()
                .or_else(|| config.get("install-strategy"))
                .or_else(|| config.get("install_strategy"))
                .unwrap_or("hoisted");
            let effective_strategy = strategy_str
                .parse::<rnpm_install::InstallStrategy>()
                .unwrap_or_else(|_| {
                    eprintln!("npm warn invalid config install-strategy={} set in command line options", strategy_str);
                    eprintln!("npm warn invalid config Must be one of: hoisted, nested, shallow, linked");
                    rnpm_install::InstallStrategy::Hoisted
                });

            let (omit_dev, omit_optional, omit_peer) =
                parse_omit_and_include_options(&omit, &include);
            let package_lock_val = if no_package_lock || package_lock == Some(false) {
                false
            } else {
                package_lock.unwrap_or(true)
            };
            let audit_val = if no_audit || audit == Some(false) {
                false
            } else {
                audit.unwrap_or_else(|| config.get_bool("audit").unwrap_or(true))
            };
            let fund_val = if no_fund || fund == Some(false) {
                false
            } else {
                fund.unwrap_or_else(|| config.get_bool("fund").unwrap_or(true))
            };
            let options = InstallOptions {
                project_dir: current_dir.clone(),
                registry_url: registry.clone(),
                cache_dir: cache,
                offline,
                force,
                ignore_scripts: effective_ignore,
                foreground_scripts: effective_foreground,
                strict_sandbox: effective_strict,
                omit_dev,
                omit_optional,
                omit_peer,
                legacy_peer_deps,
                strict_peer_deps,
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
                lockfile_version: lockfile_version.unwrap_or_else(|| {
                    config
                        .get("lockfile-version")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(3)
                }),
                timing: timing_val,
                install_strategy: effective_strategy,
                wait_for_trash,
                detached_trash,
                ..Default::default()
            };

            let start_time = std::time::Instant::now();
            let mut installer = Installer::new(options)?;
            let summary = installer.run_ci().await?;
            let elapsed_str = format_duration(start_time.elapsed());

            if json {
                let json_output = serde_json::json!({
                    "add": [],
                    "added": summary.packages_installed,
                    "audited": 0,
                    "change": [],
                    "changed": 0,
                    "funding": 0,
                    "remove": [],
                    "removed": 0
                });
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            } else if !silent && dry_run {
                println!(
                    "rnpm: dry-run: would install {} package(s)",
                    summary.packages_installed
                );
            } else if !dry_run {
                if !silent {
                    if summary.packages_installed > 0 {
                        let pkg_str = if summary.packages_installed == 1 { "package" } else { "packages" };
                        println!("\nadded {} {} in {}", summary.packages_installed, pkg_str, elapsed_str);
                    } else {
                        println!("\nup to date in {}", elapsed_str);
                    }

                    if fund_val {
                        let count = audit::count_funding_packages(&current_dir);
                        if count > 0 {
                            println!(
                                "\n{} packages are looking for funding\n  run `rnpm fund`",
                                count
                            );
                        }
                    }
                }

                if audit_val {
                    let _ = audit::run_post_install_audit(&current_dir, registry).await;
                }
            }

            if let Some(ref timing_metrics) = summary.timing {
                if timing_val {
                    print!("{}", timing_metrics.format_table());
                    print!("{}", timing_metrics.format_counters());
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
                false,
                false,
            )
            .await?;
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
                false,
                false,
            )
            .await?;
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
                false,
                false,
            )
            .await?;
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
                false,
                false,
            )
            .await?;
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
            foreground_scripts,
            strict_sandbox,
            workspace_root,
        } => {
            let cli_overrides = rnpm_config::get_process_cli_overrides();
            let has_script_overrides = cli_overrides.as_ref().map(|o| {
                o.contains_key("ignore-scripts")
                    || o.contains_key("foreground-scripts")
                    || o.contains_key("strict-sandbox")
            }).unwrap_or(false);

            let (effective_ignore, effective_foreground, effective_strict) = if has_script_overrides {
                let overrides = cli_overrides.as_ref().unwrap();
                let ig = ignore_scripts || overrides.get("ignore-scripts").map(|v| v == "true" || v == "1").unwrap_or(false);
                let fg = foreground_scripts || overrides.get("foreground-scripts").map(|v| v == "true" || v == "1").unwrap_or(false);
                let ss = strict_sandbox || overrides.get("strict-sandbox").map(|v| v == "true" || v == "1").unwrap_or(false);
                (ig, fg, ss)
            } else if current_dir.join(".npmrc").is_file() {
                let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
                let ig = ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false);
                let fg = foreground_scripts || config.get_bool("foreground-scripts").unwrap_or(false);
                let ss = strict_sandbox || config.get_bool("strict-sandbox").unwrap_or(false);
                (ig, fg, ss)
            } else {
                (ignore_scripts, foreground_scripts, strict_sandbox)
            };

            execute_run(
                current_dir,
                script,
                args,
                workspaces,
                workspace,
                filter,
                scope,
                if_present,
                effective_ignore,
                effective_foreground,
                effective_strict,
                workspace_root,
            )
            .await?;
        }
        Commands::Exec {
            call,
            package,
            args,
            yes: _,
            packages,
            registry,
            cache,
            offline,
            workspace,
            workspaces,
            workspace_root,
        } => {
            let has_ws = workspaces || !workspace.is_empty();
            let targets: Vec<PathBuf> = if has_ws {
                let members = select_workspace_members(&current_dir, &workspace, workspace_root)?;
                members.into_iter().map(|m| m.path).collect()
            } else {
                vec![current_dir.clone()]
            };

            for target_dir in targets {
                if let Some(cmd_str) = &call {
                    let full_cmd = if args.is_empty() {
                        cmd_str.clone()
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
                        format!("{cmd_str} {}", formatted_args.join(" "))
                    };
                    let manifest = Manifest::from_file(target_dir.join("package.json")).unwrap_or_default();
                    let mut ctx = LifecycleContext::new(
                        &target_dir,
                        &target_dir,
                        manifest.name.as_deref().unwrap_or(""),
                        "npx",
                        &full_cmd,
                    );
                    ctx.package_version = manifest.version;
                    ctx.extra_env = lifecycle_config_env(&target_dir);
                    let status = execute_lifecycle_script(&ctx)?;
                    if !status.success() {
                        let code = rnpm_lifecycle::extract_exit_status_code(&status);
                        return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                            exit_code: code,
                            message: format!("Process exited with status code: {}", code),
                        }));
                    }
                } else {
                    let (target_command, target_args) = if package.is_empty() {
                        if !args.is_empty() {
                            (args[0].clone(), args[1..].to_vec())
                        } else if packages.len() == 1 {
                            (packages[0].clone(), vec![])
                        } else {
                            (String::new(), vec![])
                        }
                    } else {
                        (package.clone(), args.clone())
                    };
                    execute_exec(
                        &target_dir,
                        &target_command,
                        &packages,
                        &target_args,
                        registry.clone(),
                        cache.clone(),
                        offline,
                    )
                    .await?;
                }
            }
        }
        Commands::Init {
            initializer,
            args,
            yes,
            scope,
            registry,
            cache,
            offline,
        } => {
            let init_args = commands::init::InitCommandArgs {
                initializer,
                args,
                yes,
                scope,
                registry,
                cache,
                offline,
            };
            commands::init::run(init_args, current_dir).await?;
        }
        Commands::Pack {
            target,
            dry_run,
            json,
            pack_destination,
            ignore_scripts,
            foreground_scripts,
        } => {
            let args = commands::pack::PackCommandArgs {
                target,
                dry_run,
                json,
                pack_destination,
                ignore_scripts,
                foreground_scripts,
            };
            commands::pack::run(args, current_dir).await?;
        }
        Commands::Uninstall {
            packages,
            save_dev,
            save_optional,
            save_prod,
            global,
            prefix,
            workspace,
            workspaces,
            workspace_root,
            json,
            ..
        } => {
            if packages.is_empty() {
                return Err(anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error Must provide a package name to remove"
                ));
            }
            let is_global = global || prefix.is_some();
            let target_dir = if let Some(p) = prefix {
                if p.is_absolute() {
                    p
                } else {
                    current_dir.join(p)
                }
            } else if global {
                rnpm_config::find_global_prefix()
            } else {
                current_dir
            };
            let options = InstallOptions {
                project_dir: target_dir,
                is_global,
                ..Default::default()
            };
            let start_time = std::time::Instant::now();
            let installer = Installer::new(options)?;
            let uninstall_options = UninstallOptions {
                packages,
                save_dev,
                save_optional,
                save_prod,
                is_global,
                workspace,
                workspaces,
                workspace_root,
            };
            let summary = installer.uninstall(&uninstall_options)?;
            let mut all_removed = std::collections::HashSet::new();
            for pkg in &summary.removed_packages {
                all_removed.insert(pkg.clone());
            }
            for pruned in &summary.pruned_dependencies {
                let name = pruned.rsplit("node_modules/").next().unwrap_or(pruned);
                all_removed.insert(name.to_string());
            }
            let total_removed = all_removed.len();
            let elapsed_str = format_duration(start_time.elapsed());

            if json {
                let json_output = serde_json::json!({
                    "add": [],
                    "added": 0,
                    "audited": 0,
                    "change": [],
                    "changed": 0,
                    "funding": 0,
                    "remove": [],
                    "removed": total_removed
                });
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            } else if !silent {
                if total_removed > 0 {
                    let pkg_str = if total_removed == 1 { "package" } else { "packages" };
                    println!("\nremoved {} {} in {}", total_removed, pkg_str, elapsed_str);
                } else {
                    println!("\nup to date in {}", elapsed_str);
                }
            }
        }
        Commands::Update {
            packages,
            registry,
            cache,
            offline,
            ignore_scripts,
            foreground_scripts,
            strict_sandbox,
            legacy_peer_deps,
            strict_peer_deps,
            json,
            ..
        } => {
            let opts = commands::update::UpdateOptions {
                packages,
                registry,
                cache,
                offline,
                ignore_scripts,
                foreground_scripts,
                strict_sandbox,
                legacy_peer_deps,
                strict_peer_deps,
                silent,
                json,
            };
            commands::update::run(opts, current_dir).await?;
        }
        Commands::Prune {
            omit,
            include,
            production,
            dry_run,
            json,
        } => {
            let args = commands::prune::PruneCommandArgs {
                omit,
                include,
                production,
                dry_run,
                json,
                silent,
            };
            commands::prune::run(args, current_dir).await?;
        }
        Commands::Dedupe {
            packages,
            dry_run,
            ..
        } => {
            commands::dedupe::run_dedupe(packages, dry_run, current_dir).await?;
        }
        Commands::FindDupes { packages } => {
            commands::dedupe::run_find_dupes(packages, current_dir).await?;
        }
        Commands::Rebuild {
            packages,
            ignore_scripts,
            foreground_scripts,
            strict_sandbox,
        } => {
            let opts = commands::rebuild::RebuildOptions {
                packages,
                ignore_scripts,
                foreground_scripts,
                strict_sandbox,
            };
            commands::rebuild::run(opts, current_dir).await?;
        }
        Commands::Pkg {
            action,
            prefix,
            json,
            workspace,
            workspaces,
        } => {
            commands::pkg::run(action, prefix, json, workspace, workspaces, current_dir)?;
        }
        Commands::Audit {
            action,
            registry,
            json,
            audit_level,
            dry_run,
            force,
            ..
        } => {
            if action.as_deref() == Some("fix") {
                run_audit_fix(&current_dir, registry, dry_run, force).await?;
            } else {
                audit::run_audit(&current_dir, registry, json, &audit_level).await?;
            }
        }
        Commands::Cache { action, cache } => {
            commands::cache::run(action, cache, current_dir)?;
        }
        Commands::Diff {
            specs,
            diff_specs,
            diff_name_only,
            diff_unified,
            diff_ignore_all_space,
            diff_no_prefix,
            diff_src_prefix,
            diff_dst_prefix,
            registry,
            cache: _,
        } => {
            let options = diff::DiffOptions {
                name_only: diff_name_only,
                unified: diff_unified,
                ignore_all_space: diff_ignore_all_space,
                no_prefix: diff_no_prefix,
                src_prefix: diff_src_prefix,
                dst_prefix: diff_dst_prefix,
            };
            diff::run_diff(&current_dir, specs, diff_specs, options, registry).await?;
        }
        Commands::Sbom {
            sbom_format,
            sbom_type,
            package_lock_only,
            omit,
        } => {
            commands::sbom::run(
                commands::sbom::SbomCommandArgs {
                    sbom_format,
                    sbom_type,
                    package_lock_only,
                    omit,
                },
                current_dir,
            )
            .await?;
        }
        Commands::Version {
            newversion,
            preid,
            message,
            allow_same_version,
            no_git_tag_version,
            no_commit_hooks,
            sign_git_tag,
            force,
            ignore_scripts,
            json,
            workspace,
            workspaces,
            include_workspace_root,
        } => {
            let args = commands::version::VersionCommandArgs {
                newversion,
                preid,
                message,
                allow_same_version,
                no_git_tag_version,
                no_commit_hooks,
                sign_git_tag,
                force,
                ignore_scripts,
                json,
                workspace,
                workspaces,
                include_workspace_root,
            };
            commands::version::run(args, current_dir).await?;
        }
        Commands::List {
            mut packages,
            depth,
            all,
            json,
            long,
            parseable,
            package_lock_only,
            omit,
            global,
            prefix,
            workspace,
            workspaces,
            workspace_root,
        } => {
            let is_global = global || prefix.is_some();
            let target_dir = if let Some(p) = prefix {
                if p.is_absolute() {
                    p
                } else {
                    current_dir.join(p)
                }
            } else if global {
                rnpm_config::find_global_prefix()
            } else {
                current_dir
            };

            if package_lock_only && !target_dir.join("package-lock.json").is_file() {
                eprintln!("npm error code ENOLOCK\nnpm error ls This command requires an existing lockfile.\nnpm error ls Try creating one first with: npm i --package-lock-only");
                std::process::exit(1);
            }

            let cli_overrides = rnpm_config::get_process_cli_overrides();
            let ws_in_overrides = workspaces || !workspace.is_empty() || cli_overrides.as_ref().map(|o| {
                o.get("workspaces").map(|v| v != "false" && v != "0").unwrap_or(false)
                    || o.contains_key("workspace")
            }).unwrap_or(false);
            if ws_in_overrides {
                let ws_filters = if !workspace.is_empty() {
                    workspace.clone()
                } else if let Some(ref o) = cli_overrides {
                    o.get("workspace").map(|w| vec![w.clone()]).unwrap_or_default()
                } else {
                    Vec::new()
                };
                select_workspace_members(&target_dir, &ws_filters, workspace_root)?;
                if packages.is_empty() && !ws_filters.is_empty() {
                    packages.extend(ws_filters);
                }
            }

            let opts = list::ListOptions {
                packages,
                depth,
                all,
                json,
                long,
                parseable,
                package_lock_only,
                omit,
                is_global,
            };
            let code = list::run_list(&target_dir, &opts)?;
            if code != 0 {
                return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                    exit_code: code,
                    message: "list finished with problems".to_string(),
                }));
            }
        }
        Commands::Outdated {
            packages,
            all,
            json,
            long,
            parseable,
            registry,
        } => {
            commands::outdated::run(packages, all, json, long, parseable, registry, current_dir).await?;
        }
        Commands::View {
            args,
            json,
            registry,
        } => {
            commands::view::run(args, json, registry, current_dir).await?;
        }
        Commands::Query {
            selector,
            package_lock_only,
            registry,
        } => {
            commands::query::run(selector, package_lock_only, registry, current_dir).await?;
        }
        Commands::Publish {
            target,
            tag,
            access,
            dry_run,
            otp,
            provenance,
            registry,
            ignore_scripts,
            json,
        } => {
            commands::publish::run(
                commands::publish::PublishArgs {
                    target,
                    tag,
                    access,
                    dry_run,
                    otp,
                    provenance,
                    registry,
                    ignore_scripts,
                    json,
                },
                current_dir,
            )
            .await?;
        }
        Commands::Whoami { registry, json } => {
            commands::whoami::run(registry, json, current_dir).await?;
        }
        Commands::Ping { registry, json } => {
            commands::ping::run(registry, json, current_dir).await?;
        }
        Commands::Login {
            registry,
            auth_type,
            scope,
            otp,
        } => {
            execute_login(&current_dir, registry, auth_type, scope, otp).await?;
        }
        Commands::Logout { registry, scope } => {
            commands::logout::run(&current_dir, registry, scope).await?;
        }
        Commands::Token {
            action,
            registry,
            json,
        } => {
            commands::token::run(action, registry, json, current_dir).await?;
        }
        Commands::ApproveScripts {
            packages,
            all,
            allow_scripts_pending,
            json,
        } => {
            commands::allow_scripts::run_approve(&current_dir, &packages, all, allow_scripts_pending, json)?;
        }
        Commands::DenyScripts {
            packages,
            all,
            allow_scripts_pending,
            json,
        } => {
            commands::allow_scripts::run_deny(&current_dir, &packages, all, allow_scripts_pending, json)?;
        }
        Commands::Completion { shell } => {
            if shell.is_none() {
                #[cfg(windows)]
                return Err(anyhow::anyhow!(
                    "npm error code ENOTSUP\nnpm error npm completion supported only in MINGW / Git bash on Windows"
                ));
            }
            const COMMANDS: &str = "install ci test start restart stop run exec pack uninstall update audit prune dedupe find-dupes rebuild pkg init create cache diff sbom version list outdated view query publish whoami ping login logout token approve-scripts deny-scripts completion dist-tag owner unpublish deprecate undeprecate access profile org team doctor fund explain search stars star unstar fix bugs docs edit explore help-search install-ci-test install-scripts install-test shrinkwrap trust config link unlink prefix root bin";
            match shell.as_deref().unwrap_or("bash") {
                "bash" => println!("complete -W '{COMMANDS}' rnpm"),
                "zsh" => println!("#compdef rnpm\n_arguments '1:command:({COMMANDS})'"),
                "fish" => println!("complete -c rnpm -f -a '{COMMANDS}'"),
                "powershell" => {
                    let quoted = COMMANDS
                        .split_whitespace()
                        .map(|command| format!("'{command}'"))
                        .collect::<Vec<_>>()
                        .join(",");
                    println!("Register-ArgumentCompleter -Native -CommandName rnpm -ScriptBlock {{ param($wordToComplete) {quoted} | Where-Object {{ $_ -like \"$wordToComplete*\" }} }}");
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "npm error code EUSAGE\nnpm error unsupported shell '{other}'"
                    ))
                }
            }
        }
        Commands::DistTag {
            action,
            registry,
            json,
            otp,
        } => commands::dist_tag::run(current_dir, action, registry, json, otp).await?,
        Commands::Owner {
            action,
            registry,
            json,
            otp,
        } => commands::owner::run(current_dir, action, registry, json, otp).await?,
        Commands::Unpublish {
            package,
            version,
            force,
            dry_run,
            registry,
            otp,
        } => {
            commands::unpublish::run(
                commands::unpublish::UnpublishArgs {
                    package,
                    version,
                    force,
                    dry_run,
                    registry,
                    otp,
                },
                current_dir,
            )
            .await?;
        }
        Commands::Deprecate {
            package,
            message,
            otp,
            registry,
        } => {
            commands::deprecate::run(
                commands::deprecate::DeprecateArgs {
                    package,
                    message,
                    otp,
                    registry,
                },
                current_dir,
            )
            .await?;
        }
        Commands::Undeprecate {
            package,
            version,
            registry,
        } => {
            commands::undeprecate::run(
                commands::undeprecate::UndeprecateArgs {
                    package,
                    version,
                    registry,
                },
                current_dir,
            )
            .await?;
        }
        Commands::Access {
            args,
            registry,
            json,
            otp,
        } => {
            commands::access::run(
                commands::access::AccessArgs {
                    args,
                    registry,
                    json,
                    otp,
                },
                current_dir,
            )
            .await?;
        }
        Commands::Search {
            terms,
            search_limit,
            json,
            parseable,
            no_description,
            registry,
        } => {
            commands::search::run(
                commands::search::SearchArgs {
                    terms,
                    search_limit,
                    json,
                    parseable,
                    no_description,
                    registry,
                },
                current_dir,
            )
            .await?;
        }
        Commands::Stars {
            user,
            json,
            registry,
        } => {
            commands::star::run_stars(user, json, registry, current_dir).await?;
        }
        Commands::Star {
            packages,
            registry,
            otp,
            no_unicode: _,
        } => {
            commands::star::run_star(packages, registry, otp, current_dir).await?;
        }
        Commands::Unstar {
            packages,
            registry,
            otp,
            no_unicode: _,
        } => {
            commands::star::run_unstar(packages, registry, otp, current_dir).await?;
        }
        Commands::Profile {
            action,
            args,
            otp,
            registry,
            json,
            parseable,
        } => {
            commands::profile::run(
                commands::profile::ProfileArgs {
                    action,
                    args,
                    otp,
                    registry,
                    json,
                    parseable,
                },
                &current_dir,
            )
            .await?;
        }
        Commands::Org {
            action,
            args,
            otp,
            registry,
            json,
            parseable,
        } => {
            commands::org::run(
                commands::org::OrgArgs {
                    action,
                    args,
                    otp,
                    registry,
                    json,
                    parseable,
                },
                &current_dir,
            )
            .await?;
        }
        Commands::Team {
            action,
            args,
            otp,
            description,
            registry,
            json,
            parseable,
        } => {
            commands::team::run(
                commands::team::TeamArgs {
                    action,
                    args,
                    otp,
                    description,
                    registry,
                    json,
                    parseable,
                },
                &current_dir,
            )
            .await?;
        }
        Commands::Doctor { action, args, json } => {
            let is_perf = action.as_deref() == Some("perf") || args.iter().any(|a| a == "perf");
            if is_perf {
                doctor::run_doctor_perf(&current_dir, json).await?;
            } else {
                doctor::run_doctor_standard(&current_dir, json).await?;
            }
        }
        Commands::Fund { package, json } => {
            let count = audit::count_funding_packages(&current_dir);
            let manifest_path = current_dir.join("package.json");
            let (pkg_name, pkg_version) = if manifest_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        let n = val.get("name").and_then(|v| v.as_str()).unwrap_or("project").to_string();
                        let v = val.get("version").and_then(|v| v.as_str()).unwrap_or("1.0.0").to_string();
                        (n, v)
                    } else {
                        ("project".to_string(), "1.0.0".to_string())
                    }
                } else {
                    ("project".to_string(), "1.0.0".to_string())
                }
            } else {
                ("project".to_string(), "1.0.0".to_string())
            };

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "length": count,
                        "name": pkg_name,
                        "version": pkg_version,
                        "dependencies": {}
                    }))?
                );
            } else if let Some(package) = package {
                println!("{package}: funding metadata is available in package.json");
            } else {
                println!("{pkg_name}@{pkg_version}");
            }
        }
        Commands::Explain { package, json } => {
            explain::run_explain(&current_dir, &package, json)?;
        }
        Commands::Bugs { packages, .. } => {
            for package in packages {
                let dir = resolve_local_package_dir(&current_dir, &package)?;
                let value = package_manifest_value(&dir)?;
                let url = value
                    .get("bugs")
                    .and_then(|v| v.get("url"))
                    .and_then(|v| v.as_str())
                    .or_else(|| value.get("bugs").and_then(|v| v.as_str()))
                    .unwrap_or("");
                if url.is_empty() {
                    println!("https://www.npmjs.com/package/{package}?activeTab=issues");
                } else {
                    println!("{url}");
                }
            }
        }
        Commands::Docs { packages, .. } => {
            for package in packages {
                let dir = resolve_local_package_dir(&current_dir, &package)?;
                let value = package_manifest_value(&dir)?;
                let url = value.get("homepage").and_then(|v| v.as_str()).unwrap_or("");
                if url.is_empty() {
                    println!("https://www.npmjs.com/package/{package}?activeTab=readme");
                } else {
                    println!("{url}");
                }
            }
        }
        Commands::Repo { packages, registry } => {
            if packages.is_empty() {
                let pkg_json = current_dir.join("package.json");
                let value = std::fs::read_to_string(&pkg_json)
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
                let repo = value
                    .as_ref()
                    .and_then(|v| v.get("repository"))
                    .and_then(|v| v.get("url").or(Some(v)))
                    .and_then(|v| v.as_str());
                if let Some(r) = repo {
                    println!("{r}");
                    return Ok(());
                } else {
                    return Err(anyhow::anyhow!("npm error no repository"));
                }
            }
            let (registry_url, client) = make_registry_client(&current_dir, registry)?;
            for package in packages {
                let local = current_dir
                    .join("node_modules")
                    .join(&package)
                    .join("package.json");
                if let Ok(value) = std::fs::read_to_string(&local)
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .ok_or(())
                {
                    if let Some(repo) = value
                        .get("repository")
                        .and_then(|v| v.get("url"))
                        .and_then(|v| v.as_str())
                        .or_else(|| value.get("repository").and_then(|v| v.as_str()))
                    {
                        println!("{repo}");
                        continue;
                    }
                }
                let metadata = client.get_package_metadata_full(&package).await?;
                let latest = metadata
                    .dist_tags
                    .get("latest")
                    .and_then(|v| metadata.versions.get(v));
                let repo = latest
                    .and_then(|v| v.extra.get("repository"))
                    .and_then(|v| v.get("url"))
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        latest
                            .and_then(|v| v.extra.get("repository"))
                            .and_then(|v| v.as_str())
                    });
                println!("{}", repo.unwrap_or("https://www.npmjs.com/package/"));
                let _ = registry_url;
            }
        }
        Commands::Edit { package, editor } => {
            commands::edit::run(package, editor, current_dir).await?;
        }
        Commands::Explore {
            package,
            args,
            shell,
        } => {
            commands::explore::run(package, args, shell, current_dir).await?;
        }
        Commands::HelpSearch {
            terms,
            long,
            registry: _,
            json: _,
        } => {
            commands::help_search::run(terms, long, None).await?;
        }
        Commands::Stage {
            action,
            args,
            registry,
            otp,
            json: _,
        } => {
            let (registry_url, client) = make_registry_client(&current_dir, registry)?;
            let value = match action.as_deref().unwrap_or("list") {
                "list" | "ls" => client.stage_list(Some(&registry_url)).await?,
                "view" | "show" => {
                    client
                        .stage_view(
                            Some(&registry_url),
                            args.first().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "npm error code EUSAGE\nnpm error stage view <stage-id>"
                                )
                            })?,
                        )
                        .await?
                }
                "approve" => {
                    client
                        .stage_approve(
                            Some(&registry_url),
                            args.first().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "npm error code EUSAGE\nnpm error stage approve <stage-id>"
                                )
                            })?,
                            otp.as_deref(),
                        )
                        .await?
                }
                "reject" | "delete" => {
                    client
                        .stage_reject(
                            Some(&registry_url),
                            args.first().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "npm error code EUSAGE\nnpm error stage reject <stage-id>"
                                )
                            })?,
                            otp.as_deref(),
                        )
                        .await?;
                    serde_json::Value::Null
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "npm error code EUSAGE\nnpm error unknown stage command: {other}"
                    ))
                }
            };
            if !value.is_null() {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
        }
        Commands::InstallCiTest { args } => {
            commands::install_test::run_install_ci_test(args, current_dir).await?;
        }
        Commands::InstallScripts {
            action,
            packages,
            all,
            json,
            dry_run,
        } => {
            commands::allow_scripts::run_install_scripts(
                &current_dir,
                action.as_deref(),
                &packages,
                all,
                json,
                dry_run,
            )?;
        }
        Commands::InstallTest { args } => {
            commands::install_test::run_install_test(args, current_dir).await?;
        }
        Commands::Shrinkwrap => {
            commands::shrinkwrap::run(current_dir)?;
        }
        Commands::Fix {
            force,
            registry,
            dry_run,
        } => {
            run_audit_fix(&current_dir, registry, dry_run, force).await?;
        }
        Commands::Trust {
            action,
            args,
            yes: _,
            registry,
            id,
            otp,
            workflow_file,
            repository,
            environment,
            project,
            org_id,
            project_id,
            pipeline_definition_id,
            vcs_origin,
            context_id,
            allow_publish,
            allow_stage_publish,
            json,
        } => {
            let action = action.unwrap_or_else(|| "list".into());
            let package = args
                .first()
                .cloned()
                .or_else(|| package_name_from_manifest(&current_dir).ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "npm error code ENEEDPACKAGE\nnpm error package name must be specified"
                    )
                })?;
            let (registry_url, client) = make_registry_client(&current_dir, registry)?;
            match action.as_str() {
                "list" => {
                    let value = client.trust_list(Some(&registry_url), &package).await?;
                    println!("{}", serde_json::to_string_pretty(&value)?);
                }
                "revoke" => {
                    let id = id.or_else(|| args.get(1).cloned()).ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error trust revoke requires --id=<trust-id>"))?;
                    client
                        .trust_revoke(Some(&registry_url), &package, &id, otp.as_deref())
                        .await?;
                    println!("revoked trusted configuration {id} for {package}");
                }
                "github" | "gitlab" | "circleci" => {
                    if !allow_publish && !allow_stage_publish {
                        return Err(anyhow::anyhow!("npm error code EUSAGE\nnpm error trust {action} requires --allow-publish or --allow-stage-publish"));
                    }
                    let claims = match action.as_str() {
                        "github" => {
                            let file = workflow_file.ok_or_else(|| {
                                anyhow::anyhow!(
                                    "npm error code EUSAGE\nnpm error trust github requires --file"
                                )
                            })?;
                            if !file.ends_with(".yml") && !file.ends_with(".yaml") {
                                return Err(anyhow::anyhow!("npm error code EUSAGE\nnpm error workflow file must end in .yml or .yaml"));
                            }
                            let mut claims = serde_json::Map::new();
                            if let Some(repo) = repository {
                                claims.insert("repository".into(), serde_json::Value::String(repo));
                            }
                            let mut workflow = serde_json::Map::new();
                            workflow.insert("file".into(), serde_json::Value::String(file));
                            claims
                                .insert("workflow_ref".into(), serde_json::Value::Object(workflow));
                            if let Some(env) = environment {
                                claims.insert("environment".into(), serde_json::Value::String(env));
                            }
                            serde_json::Value::Object(claims)
                        }
                        "gitlab" => {
                            let file = workflow_file.ok_or_else(|| {
                                anyhow::anyhow!(
                                    "npm error code EUSAGE\nnpm error trust gitlab requires --file"
                                )
                            })?;
                            let mut claims = serde_json::Map::new();
                            if let Some(project) = project.or(repository) {
                                claims.insert(
                                    "project_path".into(),
                                    serde_json::Value::String(project),
                                );
                            }
                            claims.insert("ref_path".into(), serde_json::Value::String(file));
                            if let Some(env) = environment {
                                claims.insert("environment".into(), serde_json::Value::String(env));
                            }
                            serde_json::Value::Object(claims)
                        }
                        _ => {
                            let org = org_id.ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error trust circleci requires --org-id"))?;
                            let project_id = project_id.ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error trust circleci requires --project-id"))?;
                            let pipeline = pipeline_definition_id.ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error trust circleci requires --pipeline-definition-id"))?;
                            let origin = vcs_origin.ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error trust circleci requires --vcs-origin"))?;
                            let mut claims = serde_json::Map::new();
                            for (key, value) in [
                                ("organization_id", org),
                                ("project_id", project_id),
                                ("pipeline_definition_id", pipeline),
                                ("vcs_origin", origin),
                            ] {
                                claims.insert(key.into(), serde_json::Value::String(value));
                            }
                            if !context_id.is_empty() {
                                claims.insert(
                                    "context_id".into(),
                                    serde_json::Value::Array(
                                        context_id
                                            .into_iter()
                                            .map(serde_json::Value::String)
                                            .collect(),
                                    ),
                                );
                            }
                            serde_json::Value::Object(claims)
                        }
                    };
                    let mut permissions = Vec::new();
                    if allow_publish {
                        permissions.push(serde_json::Value::String("createPackage".into()));
                    }
                    if allow_stage_publish {
                        permissions.push(serde_json::Value::String("createStagedPackage".into()));
                    }
                    let config = serde_json::json!([{"type": action, "claims": claims, "permissions": permissions}]);
                    let value = client
                        .trust_create(Some(&registry_url), &package, config, otp.as_deref())
                        .await?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&value)?);
                    } else {
                        println!("trusted {package} with {action}");
                    }
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "npm error code EUSAGE\nnpm error Unknown trust command: {other}"
                    ))
                }
            }
        }
        Commands::Hook { registry, .. } => {
            let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
            let registry_url = if let Some(ref reg_str) = registry {
                Url::parse(reg_str).map_err(|e| {
                    anyhow::anyhow!(
                        "npm error code EINVALIDURL\nnpm error Invalid registry URL '{reg_str}': {e}"
                    )
                })?
            } else {
                config.npmrc.registry.clone()
            };
            let token = config.npmrc.get_auth_token(&registry_url);
            if token.is_none() {
                return Err(anyhow::anyhow!(
                    "npm error code ENEEDAUTH\nnpm error This command requires you to be logged in to {registry_url}\nnpm error You need to authorize this machine using `npm adduser` or `npm login`"
                ));
            }
            return Err(anyhow::anyhow!(
                "npm error code ENOTSUP\nnpm error hook is not supported by the active registry"
            ));
        }
        Commands::Get { key } => {
            commands::config::run_get(key.as_deref(), &current_dir)?;
        }
        Commands::Set {
            key,
            value,
            global,
            location,
        } => {
            commands::config::run_set(&key, Some(&value), global, location.as_deref(), &current_dir)?;
        }
        Commands::Config { action } => {
            commands::config::run(action, current_dir)?;
        }
        Commands::Link { package } => {
            commands::link::run_link(package, current_dir)?;
        }
        Commands::Unlink { package } => {
            commands::link::run_unlink(package, current_dir)?;
        }
        Commands::Prefix { global } => {
            if global {
                let p = rnpm_config::find_global_prefix();
                println!("{}", p.display());
            } else {
                let p = rnpm_config::find_local_prefix(&current_dir);
                println!("{}", p.display());
            }
        }
        Commands::Root { global } => {
            if global {
                let p = rnpm_config::find_global_node_modules(&rnpm_config::find_global_prefix());
                println!("{}", p.display());
            } else {
                let p = rnpm_config::find_local_node_modules(&current_dir);
                println!("{}", p.display());
            }
        }
        Commands::Bin { global } => {
            if global {
                let p = rnpm_config::find_global_bin_dir(&rnpm_config::find_global_prefix());
                println!("{}", p.display());
            } else {
                let p = rnpm_config::find_local_bin_dir(&current_dir);
                println!("{}", p.display());
            }
        }
        Commands::Help { topic } => {
            let topic_str = topic.join("-").to_ascii_lowercase();
            if topic_str == "install-strategy" || topic_str == "install_strategy" {
                print_help_install_strategy();
            } else if topic.is_empty() {
                println!(
r#"npm <command>

Usage:

npm install        install all the dependencies in your project
npm install <foo>  add the <foo> dependency to your project
npm test           run this project's tests
npm run <foo>      run the script named <foo>
npm <command> -h   quick help on <command>
npm -l             display usage info for all commands
npm help <term>    search for help on <term> (in a browser)
npm help npm       more involved overview (in a browser)

All commands:

    access, adduser, audit, bugs, cache, ci, completion,
    config, dedupe, deprecate, diff, dist-tag, docs, doctor,
    edit, exec, explain, explore, find-dupes, fund, get, help,
    help-search, hook, init, install, install-ci-test,
    install-test, link, ll, login, logout, ls, org, outdated,
    owner, pack, ping, pkg, prefix, profile, prune, publish,
    query, rebuild, repo, restart, root, run-script, sbom,
    search, set, shrinkwrap, star, stars, start, stop, team,
    test, token, uninstall, unpublish, unstar, update, version,
    view, whoami"#
                );
            } else {
                let cmd = Cli::command();
                if let Some(sub) = cmd.find_subcommand(&topic[0]) {
                    let mut sub = sub.clone();
                    sub.print_help()?;
                    println!();
                } else {
                    let mut cmd = cmd;
                    cmd.print_help()?;
                    println!();
                }
            }
        }
    }

    Ok(())
}

fn print_help_install_strategy() {
    println!(
        r#"NAME
    install-strategy - Installation strategy for node_modules layout

SYNOPSIS
    rnpm install --install-strategy=<hoisted|linked|nested>
    rnpm ci --install-strategy=<hoisted|linked|nested>

DESCRIPTION
    Controls the layout strategy used when materializing dependencies in node_modules:

    hoisted (default)
        Standard npm layout where dependencies are hoisted toward the project root
        node_modules directory to deduplicate packages across the dependency tree.

    linked
        High-performance isolated layout utilizing NTFS junctions pointing into a
        global content store (%LOCALAPPDATA%\rnpm\store-v1\linked).

        Each package and dependency set exists once globally:
          %LOCALAPPDATA%\rnpm\store-v1\linked\<name>@<version>-<deps-hash>\node_modules\<name>
        with its own dependencies wired as NTFS directory junctions inside its store entry.

        Project node_modules entries are NTFS junctions (FSCTL_SET_REPARSE_POINT)
        pointing directly into the global store:
          - Zero file writes for linked packages (metadata-only operations)
          - Eliminates Windows Defender scanning overhead on the critical path
          - Seamlessly works cross-volume (e.g., project on D: HDD, store on C: NVMe)
          - Requires no Administrator privileges and no Windows Developer Mode

    nested
        Nested layout where each package places its dependencies directly in its
        own node_modules without hoisting.

TRADE-OFFS (linked strategy)
    Per fifty-mark.md Section 4.6:
    1. Phantom dependencies:
       Packages that rely on undeclared dependencies will fail to resolve. Because
       each package only has access to dependencies explicitly declared in its
       package.json, undeclared transitive dependencies are not visible.
    2. Shared global store mutations:
       Editing files inside node_modules directly will modify the global store copy.
       Workflows that require local code mutations (e.g. patching) should copy
       the package into the project first.
    3. Lifecycle and native addons:
       Native addons (e.g. packages with binding.gyp or install/postinstall scripts
       that compile or mutate the package directory) automatically fall back to
       a per-project copy to prevent modifying the global store.

CONFIGURATION
    Set in .npmrc or project configuration:
        install-strategy=linked"#
    );
}

pub(crate) fn use_unicode(dir: &Path) -> bool {
    rnpm_config::Config::load(Some(dir)).ok().and_then(|config| config.get_bool("unicode"))
        .unwrap_or_else(|| {
            let locale = ["LC_ALL", "LC_CTYPE", "LANG"].iter()
                .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
                .unwrap_or_default().to_ascii_uppercase();
            locale.ends_with("UTF8") || locale.ends_with("UTF-8")
        })
}

pub(crate) fn print_pack_notices(summary: &rnpm_fs::PackSummary) {
    eprintln!("npm notice");
    let unicode = use_unicode(&std::env::current_dir().unwrap_or_default());
    eprintln!("npm notice {} {}@{}", if unicode { "\u{1f4e6} " } else { "package:" }, summary.name, summary.version);
    eprintln!("npm notice Tarball Contents");
    for file in &summary.files {
        if file.path.starts_with("node_modules/") { continue; }
        eprintln!(
            "npm notice {} {}",
            format_bytes(file.size, false),
            file.path
        );
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
    eprintln!(
        "npm notice package size: {}",
        format_bytes(summary.package_size, true)
    );
    eprintln!(
        "npm notice unpacked size: {}",
        format_bytes(summary.unpacked_size, true)
    );
    eprintln!("npm notice shasum: {}", summary.shasum);
    let integrity_short = if summary.integrity.len() >= 80 {
        format!(
            "{}[...]{}",
            &summary.integrity[..20],
            &summary.integrity[80..]
        )
    } else {
        summary.integrity.clone()
    };
    eprintln!("npm notice integrity: {}", integrity_short);
    if !summary.bundled.is_empty() {
        eprintln!("npm notice bundled deps: {}", summary.bundled.len());
        eprintln!(
            "npm notice bundled files: {}",
            summary.entry_count.saturating_sub(summary.files.len())
        );
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

fn execute_run_sync(
    current_dir: PathBuf,
    script: String,
    args: Vec<String>,
    if_present: bool,
    ignore_scripts: bool,
    foreground_scripts: bool,
    strict_sandbox: bool,
) -> anyhow::Result<()> {
    let manifest_path = current_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(anyhow::anyhow!("package.json not found in {}", current_dir.display()));
    }
    let mut manifest = Manifest::from_file(&manifest_path)?;
    if !manifest.scripts.contains_key(&script) {
        if script == "start" && current_dir.join("server.js").exists() {
            manifest.scripts.insert("start".to_string(), "node server.js".to_string());
        } else {
            if if_present { return Ok(()); }
            anyhow::bail!("npm error Missing script: \"{script}\"\nnpm error\nnpm error To see a list of scripts, run:\nnpm error   npm run");
        }
    }
    let config = rnpm_config::Config::load(Some(&current_dir))?;
    let ignore_scripts = ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false);
    let foreground_scripts = foreground_scripts || config.get_bool("foreground-scripts").unwrap_or(false);
    let is_silent = config.get("loglevel") == Some("silent");
    let pre = format!("pre{script}");
    let post = format!("post{script}");
    for hook in [&pre, &script, &post] {
        if ignore_scripts && hook != &script { continue; }
        let Some(cmd) = manifest.scripts.get(hook) else { continue; };
        let full_cmd = if hook == &script && !args.is_empty() {
            let formatted: Vec<String> = args.iter().map(|arg| {
                if arg.contains([' ', '\t', '"']) {
                    format!("\"{}\"", arg.replace('"', "\\\""))
                } else { arg.clone() }
            }).collect();
            format!("{cmd} {}", formatted.join(" "))
        } else { cmd.clone() };
        if !is_silent {
            let id = match (&manifest.name, &manifest.version) {
                (Some(name), Some(version)) => format!("{name}@{version}"),
                (Some(name), None) => name.clone(),
                _ => String::new(),
            };
            println!("\n> {}{hook}\n> {full_cmd}\n", if id.is_empty() { id } else { format!("{id} ") });
        }
        let mut ctx = LifecycleContext::new(
            &current_dir, &current_dir, manifest.name.as_deref().unwrap_or(""), hook, &full_cmd,
        );
        ctx.package_version = manifest.version.clone();
        ctx.foreground_scripts = foreground_scripts;
        ctx.extra_env = lifecycle_config_env(&current_dir);
        ctx.extra_env.insert("npm_lifecycle_script".into(), cmd.clone());
        if ignore_scripts { ctx.extra_env.insert("npm_config_ignore_scripts".into(), "true".into()); }
        if foreground_scripts { ctx.extra_env.insert("npm_config_foreground_scripts".into(), "true".into()); }
        if strict_sandbox { ctx.sandbox_policy = rnpm_lifecycle::ScriptSandboxPolicy::restricted(); }
        let status = execute_lifecycle_script(&ctx)?;
        if !status.success() {
            let code = rnpm_lifecycle::extract_exit_status_code(&status);
            return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                exit_code: code, message: format!("Lifecycle script '{hook}' failed with exit code: {code}"),
            }));
        }
    }
    Ok(())
}

fn lifecycle_config_env(dir: &Path) -> std::collections::HashMap<String, String> {
    let mut env = std::collections::HashMap::new();
    if let Ok(cwd) = std::env::current_dir() {
        env.insert("INIT_CWD".into(), cwd.to_string_lossy().into_owned());
    }
    if let Ok(config) = rnpm_config::Config::load(Some(dir)) {
        for (key, value) in config.npmrc.settings {
            env.insert(format!("npm_config_{}", key.replace('-', "_")), value);
        }
    }
    env
}

fn finish_cli_error(err: &anyhow::Error) -> ! {
    if let Some(exit) = err.downcast_ref::<rnpm_lifecycle::ScriptExitError>() {
        if exit.message.starts_with("npm error ") { eprintln!("{}", exit.message); }
        std::process::exit(exit.exit_code);
    }
    let diagnostic = diagnostics::classify_error(err);
    if diagnostic.message.starts_with("npm error ") { eprintln!("{}", diagnostic.message); }
    else { print_structured_error(err); }
    let missing_manifest = format!("{err:#}").contains("package.json not found");
    std::process::exit(if missing_manifest { if cfg!(windows) { -4058 } else { -2 } } else { 1 });
}

fn main() {
    // Suppress mimalloc warning output on stderr under high memory pressure
    if std::env::var("MIMALLOC_SHOW_ERRORS").is_err() {
        std::env::set_var("MIMALLOC_SHOW_ERRORS", "0");
    }
    if std::env::var("MIMALLOC_VERBOSE").is_err() {
        std::env::set_var("MIMALLOC_VERBOSE", "0");
    }

    // Fast path: internal detached trash worker process
    let mut raw_args = std::env::args_os();
    let _bin = raw_args.next();
    if let Some(first) = raw_args.next() {
        if first == "__internal_clean_trash" {
            for path_arg in raw_args {
                let p = PathBuf::from(path_arg);
                let _ = rnpm_fs::remove_dir_all_safe(&p);
            }
            std::process::exit(0);
        }
    }

    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
    }

    let (filtered_args, _scoped_registries) = extract_scoped_registries(std::env::args_os());
    let warn_workspaces = filtered_args.iter().take_while(|a| a.as_str() != "--")
        .any(|a| a == "-ws");
    let filtered_args = normalize_cli_args(filtered_args);

    if let Some((_, msg)) = check_unsupported_cli_invocation(&filtered_args) {
        eprintln!("{msg}");
        std::process::exit(1);
    }

    let filtered_args = preprocess_cli_args(filtered_args);
    if warn_workspaces {
        let config = rnpm_config::Config::load(std::env::current_dir().ok().as_deref()).unwrap_or_default();
        if !matches!(config.get("loglevel"), Some("silent" | "error")) {
            eprintln!("npm warn -ws is not a valid single-hyphen cli flag and will be removed in the future");
        }
    }

    // Ultra-fast path for standard `rnpm run <script>` without clap AST building
    if filtered_args.get(1).map(|s| s.as_str()) == Some("run")
        && !filtered_args.iter().any(|a| a == "--help" || a == "-h" || a == "--workspaces" || a == "-ws" || a == "-w" || a == "--workspace" || a.starts_with("--workspace="))
    {
        let mut script_name = None;
        let mut script_args = Vec::new();
        let mut if_present = false;
        let mut ignore_scripts = false;
        let mut foreground_scripts = false;
        let mut strict_sandbox = false;

        let mut in_dashdash = false;
        for arg in &filtered_args[2..] {
            if in_dashdash {
                script_args.push(arg.clone());
            } else if arg == "--" {
                in_dashdash = true;
            } else if arg == "--if-present" {
                if_present = true;
            } else if arg == "--ignore-scripts" {
                ignore_scripts = true;
            } else if arg == "--foreground-scripts" {
                foreground_scripts = true;
            } else if arg == "--strict-sandbox" {
                strict_sandbox = true;
            } else if arg == "--workspace-root"
                || arg == "--include-workspace-root"
                || arg == "--scope"
                || arg == "--filter"
                || arg.starts_with("--scope=")
                || arg.starts_with("--filter=")
            {
                // npm run CLI flags, not forwarded script arguments
            } else if !arg.starts_with('-') && script_name.is_none() {
                script_name = Some(arg.clone());
            } else {
                script_args.push(arg.clone());
            }
        }

        if let Some(script) = script_name {
            let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let cli_overrides = rnpm_config::get_process_cli_overrides();
            if let Some(ref o) = cli_overrides {
                if let Some(shell) = o.get("script-shell") {
                    if shell == "true" {
                        eprintln!("npm error code ENOENT\nnpm error syscall spawn true");
                        std::process::exit(1);
                    }
                }
            }
            let has_script_overrides = cli_overrides.as_ref().map(|o| {
                o.contains_key("ignore-scripts")
                    || o.contains_key("foreground-scripts")
                    || o.contains_key("strict-sandbox")
            }).unwrap_or(false);

            let (effective_ignore, effective_foreground, effective_strict) = if has_script_overrides {
                let overrides = cli_overrides.as_ref().unwrap();
                let ig = ignore_scripts || overrides.get("ignore-scripts").map(|v| v == "true" || v == "1").unwrap_or(false);
                let fg = foreground_scripts || overrides.get("foreground-scripts").map(|v| v == "true" || v == "1").unwrap_or(false);
                let ss = strict_sandbox || overrides.get("strict-sandbox").map(|v| v == "true" || v == "1").unwrap_or(false);
                (ig, fg, ss)
            } else if let Ok(npmrc_text) = std::fs::read_to_string(current_dir.join(".npmrc")) {
                let ig = ignore_scripts || npmrc_text.lines().any(|l| l.trim().starts_with("ignore-scripts=true"));
                let fg = foreground_scripts || npmrc_text.lines().any(|l| l.trim().starts_with("foreground-scripts=true"));
                let ss = strict_sandbox || npmrc_text.lines().any(|l| l.trim().starts_with("strict-sandbox=true"));
                (ig, fg, ss)
            } else {
                (ignore_scripts, foreground_scripts, strict_sandbox)
            };

            if let Err(err) = execute_run_sync(
                current_dir,
                script,
                script_args,
                if_present,
                effective_ignore,
                effective_foreground,
                effective_strict,
            ) {
                finish_cli_error(&err);
            }
            std::process::exit(0);
        }
    }

    let mut cli = match Cli::try_parse_from(&filtered_args) {
        Ok(c) => c,
        Err(e) => {
            if !e.use_stderr() {
                print!("{e}");
                std::process::exit(0);
            }
            let rendered = e.render().to_string();
            if rendered.contains("unrecognized subcommand") {
                let first_arg = filtered_args.get(1).cloned().unwrap_or_default();
                println!("Unknown command: \"{first_arg}\"\n\nTo see a list of supported npm commands, run:\n  npm help");
            } else {
                eprintln!("{rendered}");
            }
            std::process::exit(1);
        }
    };

    if filtered_args.get(1).is_some_and(|s| s == "la" || s == "ll") {
        if let Commands::List { ref mut long, .. } = cli.command {
            *long = true;
        }
    }

    // Fast synchronous path for standard `rnpm run <script>` without tokio runtime overhead
    if let Commands::Run {
        ref script,
        ref args,
        workspaces,
        ref workspace,
        ref filter,
        ref scope,
        if_present,
        ignore_scripts,
        foreground_scripts,
        strict_sandbox,
        workspace_root: _,
    } = cli.command {
        let has_filter = !workspace.is_empty() || !filter.is_empty() || !scope.is_empty();
        if !workspaces && !has_filter && script.is_some() {
            let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let cli_overrides = rnpm_config::get_process_cli_overrides();
            if let Some(ref o) = cli_overrides {
                if let Some(shell) = o.get("script-shell") {
                    if shell == "true" {
                        eprintln!("npm error code ENOENT\nnpm error syscall spawn true");
                        std::process::exit(1);
                    }
                }
            }
            let has_script_overrides = cli_overrides.as_ref().map(|o| {
                o.contains_key("ignore-scripts")
                    || o.contains_key("foreground-scripts")
                    || o.contains_key("strict-sandbox")
            }).unwrap_or(false);

            let (effective_ignore, effective_foreground, effective_strict) = if has_script_overrides {
                let overrides = cli_overrides.as_ref().unwrap();
                let ig = ignore_scripts || overrides.get("ignore-scripts").map(|v| v == "true" || v == "1").unwrap_or(false);
                let fg = foreground_scripts || overrides.get("foreground-scripts").map(|v| v == "true" || v == "1").unwrap_or(false);
                let ss = strict_sandbox || overrides.get("strict-sandbox").map(|v| v == "true" || v == "1").unwrap_or(false);
                (ig, fg, ss)
            } else if let Ok(npmrc_text) = std::fs::read_to_string(current_dir.join(".npmrc")) {
                let ig = ignore_scripts || npmrc_text.lines().any(|l| l.trim().starts_with("ignore-scripts=true"));
                let fg = foreground_scripts || npmrc_text.lines().any(|l| l.trim().starts_with("foreground-scripts=true"));
                let ss = strict_sandbox || npmrc_text.lines().any(|l| l.trim().starts_with("strict-sandbox=true"));
                (ig, fg, ss)
            } else {
                (ignore_scripts, foreground_scripts, strict_sandbox)
            };

            if let Err(err) = execute_run_sync(
                current_dir,
                script.as_ref().unwrap().clone(),
                args.clone(),
                if_present,
                effective_ignore,
                effective_foreground,
                effective_strict,
            ) {
                finish_cli_error(&err);
            }
            std::process::exit(0);
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to initialize async runtime");

    if let Err(err) = rt.block_on(run_cli(cli, None)) {
        if err.is::<audit::AuditThresholdError>() {
            std::process::exit(1);
        }
        finish_cli_error(&err);
    }
}

#[cfg(test)]
mod tests;
