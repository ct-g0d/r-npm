#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::too_many_arguments)]

mod audit;
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

        /// Print high-resolution per-phase timing table and metrics
        #[arg(long = "timing")]
        timing: bool,

        /// Installation layout strategy: hoisted (default npm layout), linked (NTFS junctions to global store), or nested
        #[arg(long = "install-strategy", value_parser = ["hoisted", "linked", "nested"])]
        install_strategy: Option<String>,

        /// Wait for background trash deletions to finish before exiting (default: false)
        #[arg(long = "wait-for-trash", alias = "wait-trash")]
        wait_for_trash: bool,

        /// Detached background trash deletion without blocking exit (default: true)
        #[arg(long = "detached-trash", default_value = "true", action = clap::ArgAction::Set)]
        detached_trash: bool,
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

        /// Installation layout strategy: hoisted (default npm layout), linked (NTFS junctions to global store), or nested
        #[arg(long = "install-strategy", value_parser = ["hoisted", "linked", "nested"])]
        install_strategy: Option<String>,

        /// Wait for background trash deletions to finish before exiting (default: false)
        #[arg(long = "wait-for-trash", alias = "wait-trash")]
        wait_for_trash: bool,

        /// Detached background trash deletion without blocking exit (default: true)
        #[arg(long = "detached-trash", default_value = "true", action = clap::ArgAction::Set)]
        detached_trash: bool,
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

        /// Remove from global prefix
        #[arg(short = 'g', long = "global")]
        global: bool,
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
    #[command(alias = "deduplicate")]
    Dedupe {
        /// Specific package names to deduplicate
        packages: Vec<String>,

        /// Report deduplication actions without modifying files or lockfile
        #[arg(long)]
        dry_run: bool,
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
    #[command(alias = "adduser")]
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
        #[arg(long)]
        registry: Option<String>,

        /// Output in JSON format
        #[arg(long)]
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
        package: String,
        #[arg(long)]
        editor: Option<String>,
    },
    /// Explore a package in a shell.
    Explore {
        package: String,
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
    InstallTest {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
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
        key: String,
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
    /// Retrieve a configuration key value
    Get {
        /// Configuration key to retrieve
        key: String,
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

    let unsupported_commands: [&str; 0] = [];

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
        if first == "pkg" {
            i += 1;
            continue;
        }
        // --legacy-peer-deps and --strict-peer-deps are supported on install, ci, update (and their aliases)
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
        let discovered =
            rnpm_core::workspace::discover_workspaces_from_manifest(&current_dir, &manifest)
                .map_err(|e| anyhow::anyhow!("Failed to discover workspaces: {e}"))?;

        if discovered.is_empty() {
            return Err(anyhow::anyhow!(
                "npm error code ENOWORKSPACES\nnpm error No workspaces found in {}",
                current_dir.display()
            ));
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
            foreground_scripts,
            strict_sandbox,
            if_present,
            filter_members: filter_opt,
        };

        let summary = rnpm_lifecycle::execute_workspace_scripts_topological(
            &current_dir,
            &members,
            &graph.topological_order,
            &ws_opts,
        )
        .await?;

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

                let pkg_name = manifest
                    .name
                    .clone()
                    .unwrap_or_else(|| "project".to_string());
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

        let pkg_name = manifest
            .name
            .clone()
            .unwrap_or_else(|| "project".to_string());
        let mut ctx =
            LifecycleContext::new(&current_dir, &current_dir, &pkg_name, &script, &full_cmd);
        ctx.package_version = manifest.version.clone();
        ctx.foreground_scripts = foreground_scripts;
        if foreground_scripts {
            ctx.capture_output = false;
        }
        if strict_sandbox {
            ctx.sandbox_policy = rnpm_lifecycle::ScriptSandboxPolicy::restricted();
        }

        if !ignore_scripts {
            let status = execute_lifecycle_script(&ctx)?;
            if !status.success() {
                let code = rnpm_lifecycle::extract_exit_status_code(&status);
                return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                    exit_code: code,
                    message: format!(
                        "Lifecycle script '{}' failed with exit code: {}",
                        script, code
                    ),
                }));
            }
        }
    }

    Ok(())
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

pub(crate) async fn execute_exec(
    current_dir: &std::path::Path,
    package: &str,
    args: &[String],
    registry: Option<String>,
    cache: Option<PathBuf>,
    offline: bool,
) -> anyhow::Result<()> {
    // Parse package and version/range
    let (pkg_name, version_req) = if let Some(stripped) = package.strip_prefix('@') {
        if let Some(idx) = stripped.find('@') {
            (
                format!("@{}", &stripped[..idx]),
                stripped[idx + 1..].to_string(),
            )
        } else {
            (package.to_string(), "*".to_string())
        }
    } else if let Some(idx) = package.find('@') {
        (package[..idx].to_string(), package[idx + 1..].to_string())
    } else {
        (package.to_string(), "*".to_string())
    };

    let bin_name = if let Some(slash) = pkg_name.find('/') {
        &pkg_name[slash + 1..]
    } else {
        &pkg_name
    };

    // 1. Check local node_modules/.bin first
    let local_bin = rnpm_lifecycle::find_local_binary(current_dir, &pkg_name)
        .or_else(|| rnpm_lifecycle::find_local_binary(current_dir, bin_name))
        .or_else(|| rnpm_lifecycle::find_local_binary(current_dir, package));

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
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let npx_env_dir = cache_path.join("_npx").join(&safe_spec);
        let bin_target = rnpm_lifecycle::find_local_binary(&npx_env_dir, &pkg_name)
            .or_else(|| rnpm_lifecycle::find_local_binary(&npx_env_dir, bin_name))
            .or_else(|| rnpm_lifecycle::find_local_binary(&npx_env_dir, package));

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
            if let Some(target) = rnpm_lifecycle::find_local_binary(&npx_env_dir, &pkg_name) {
                target
            } else if let Some(target) = rnpm_lifecycle::find_local_binary(&npx_env_dir, bin_name) {
                target
            } else if let Some(target) = rnpm_lifecycle::find_local_binary(&npx_env_dir, package) {
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
                        package
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

    let status = rnpm_lifecycle::execute_binary_async(
        &binary_to_run,
        args,
        current_dir,
        &path_entries,
        &std::collections::HashMap::new(),
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

async fn run_publish_lifecycle_hook(
    package_dir: &std::path::Path,
    manifest: &Manifest,
    hook_name: &str,
    ignore_scripts: bool,
) -> anyhow::Result<()> {
    if ignore_scripts {
        return Ok(());
    }

    if let Some(script_cmd) = manifest.scripts.get(hook_name) {
        let pkg_name = manifest
            .name
            .clone()
            .unwrap_or_else(|| "package".to_string());
        let mut ctx =
            LifecycleContext::new(package_dir, package_dir, &pkg_name, hook_name, script_cmd);
        ctx.package_version = manifest.version.clone();
        let status = execute_lifecycle_script(&ctx)?;
        if !status.success() {
            let code = rnpm_lifecycle::extract_exit_status_code(&status);
            return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                exit_code: code,
                message: format!(
                    "Lifecycle script '{}' failed with exit code: {}",
                    hook_name, code
                ),
            }));
        }
    }

    Ok(())
}

async fn execute_publish(
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

    // 1. prepublishOnly
    run_publish_lifecycle_hook(&package_dir, &manifest, "prepublishOnly", ignore_scripts).await?;

    // 2. prepack
    run_publish_lifecycle_hook(&package_dir, &manifest, "prepack", ignore_scripts).await?;

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
    run_publish_lifecycle_hook(&package_dir, &updated_manifest, "postpack", ignore_scripts).await?;

    if dry_run {
        if json {
            let json_output = serde_json::json!({
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
                "tag": tag,
                "access": access.as_deref().or_else(|| {
                    updated_manifest_json.get("publishConfig")
                        .and_then(|c| c.get("access"))
                        .and_then(|a| a.as_str())
                }),
                "dryRun": true,
            });
            println!("{}", serde_json::to_string_pretty(&json_output)?);
        } else {
            print_pack_notices(&summary);
            if provenance {
                eprintln!(
                    "npm notice provenance would be generated and verified in CI environment"
                );
            }
            println!("+ {}@{}", summary.name, summary.version);
        }
        return Ok(());
    }

    // 5. publish
    run_publish_lifecycle_hook(&package_dir, &updated_manifest, "publish", ignore_scripts).await?;

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
    if let Some(token) = config.npmrc.get_auth_token(&registry_url) {
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
            "tag": tag,
            "access": effective_access,
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        print_pack_notices(&summary);
        if provenance {
            eprintln!("npm notice published with provenance attestations");
        }
        println!("+ {}@{}", summary.name, summary.version);
    }

    // 6. postpublish
    run_publish_lifecycle_hook(
        &package_dir,
        &updated_manifest,
        "postpublish",
        ignore_scripts,
    )
    .await?;

    Ok(())
}

async fn execute_whoami(
    current_dir: &std::path::Path,
    registry: Option<String>,
    json: bool,
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

    let token = config.npmrc.get_auth_token(&registry_url);
    if token.is_none() {
        return Err(anyhow::anyhow!(
            "npm error code ENEEDAUTH\nnpm error This command requires you to be logged in to {registry_url}\nnpm error You need to authorize this machine using `npm adduser` or `npm login`"
        ));
    }

    let mut client_config = rnpm_registry::RegistryClientConfig {
        default_registry: registry_url.clone(),
        scoped_registries: config.npmrc.scoped_registries.clone(),
        auth_tokens: config.npmrc.auth_tokens.clone(),
        ..Default::default()
    };
    if let Some(tok) = token {
        client_config.auth_token = Some(tok.to_string());
    }

    let client = rnpm_registry::RegistryClient::with_config(client_config)?;
    let username = client.whoami(Some(&registry_url)).await?;

    if json {
        println!("{}", serde_json::to_string(&username)?);
    } else {
        println!("{username}");
    }

    Ok(())
}

async fn execute_ping(
    current_dir: &std::path::Path,
    registry: Option<String>,
    json: bool,
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

    let mut client_config = rnpm_registry::RegistryClientConfig {
        default_registry: registry_url.clone(),
        scoped_registries: config.npmrc.scoped_registries.clone(),
        auth_tokens: config.npmrc.auth_tokens.clone(),
        ..Default::default()
    };
    if let Some(tok) = config.npmrc.get_auth_token(&registry_url) {
        client_config.auth_token = Some(tok.to_string());
    }

    let client = rnpm_registry::RegistryClient::with_config(client_config)?;
    let duration = client.ping(Some(&registry_url)).await?;

    if json {
        let json_out = serde_json::json!({
            "registry": registry_url.to_string(),
            "time": duration.as_millis(),
            "details": {}
        });
        println!("{}", serde_json::to_string_pretty(&json_out)?);
    } else {
        eprintln!("npm notice PING {registry_url}");
        eprintln!("npm notice PONG {}ms", duration.as_millis());
    }

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

async fn execute_logout(
    current_dir: &std::path::Path,
    registry: Option<String>,
    scope: Option<String>,
) -> anyhow::Result<()> {
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    let registry_url = if let Some(ref reg_str) = registry {
        Url::parse(reg_str).map_err(|e| {
            anyhow::anyhow!(
                "npm error code EINVALIDURL\nnpm error Invalid registry URL '{reg_str}': {e}"
            )
        })?
    } else if let Some(ref sc) = scope {
        let sc_norm = if sc.starts_with('@') {
            sc.clone()
        } else {
            format!("@{sc}")
        };
        config
            .npmrc
            .scoped_registries
            .get(&sc_norm.to_ascii_lowercase())
            .cloned()
            .unwrap_or_else(|| config.npmrc.registry.clone())
    } else {
        config.npmrc.registry.clone()
    };

    let user_home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok();
    let mut modified = false;

    let auth_key = auth_key_for_registry(&registry_url);
    if let Some(home) = user_home {
        let user_npmrc = PathBuf::from(home).join(".npmrc");
        if user_npmrc.is_file() {
            modified |=
                rnpm_config::delete_config_value_from_file(&user_npmrc, &auth_key).unwrap_or(false);
        }
    }

    let local_npmrc = current_dir.join(".npmrc");
    if local_npmrc.is_file() {
        modified |=
            rnpm_config::delete_config_value_from_file(&local_npmrc, &auth_key).unwrap_or(false);
    }

    if modified {
        println!("rnpm: successfully logged out of {registry_url}");
    } else {
        println!("rnpm: logged out of {registry_url} (no active session token found)");
    }

    Ok(())
}

async fn execute_token(
    current_dir: &std::path::Path,
    action: Option<TokenAction>,
    registry: Option<String>,
    json: bool,
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

    let token = config.npmrc.get_auth_token(&registry_url);
    if token.is_none() {
        return Err(anyhow::anyhow!(
            "npm error code ENEEDAUTH\nnpm error This command requires you to be logged in to {registry_url}\nnpm error You need to authorize this machine using `npm adduser` or `npm login`"
        ));
    }

    let mut client_config = rnpm_registry::RegistryClientConfig {
        default_registry: registry_url.clone(),
        scoped_registries: config.npmrc.scoped_registries.clone(),
        auth_tokens: config.npmrc.auth_tokens.clone(),
        ..Default::default()
    };
    if let Some(tok) = token {
        client_config.auth_token = Some(tok.to_string());
    }

    let client = rnpm_registry::RegistryClient::with_config(client_config)?;

    match action.unwrap_or(TokenAction::List) {
        TokenAction::List => match client.token_list(Some(&registry_url)).await {
            Ok(val) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else if let Some(tokens) = val.get("objects").and_then(|o| o.as_array()) {
                    println!("id\ttoken\tcreated\tread-only\tCIDR whitelist");
                    for t in tokens {
                        let id = t.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let tok = t.get("token").and_then(|v| v.as_str()).unwrap_or("");
                        let created = t.get("created").and_then(|v| v.as_str()).unwrap_or("");
                        let ro = t.get("readonly").and_then(|v| v.as_bool()).unwrap_or(false);
                        println!("{id}\t{tok}…\t{created}\t{ro}");
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                }
            }
            Err(e) => {
                if json {
                    println!("{}", serde_json::json!({ "error": e.to_string() }));
                } else {
                    eprintln!("npm notice Token management API not available or returned: {e}");
                    eprintln!("npm notice Please manage security tokens via the web dashboard at {registry_url}");
                }
            }
        },
        TokenAction::Revoke { token_id } => {
            client.token_revoke(Some(&registry_url), &token_id).await?;
            println!("rnpm: successfully revoked token {token_id}");
        }
    }

    Ok(())
}

fn make_registry_client(
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

async fn execute_dist_tag(
    current_dir: &Path,
    action: DistTagAction,
    registry: Option<String>,
    json: bool,
    otp: Option<String>,
) -> anyhow::Result<()> {
    let (registry_url, client) = make_registry_client(current_dir, registry)?;
    match action {
        DistTagAction::Ls { package } => {
            let package = package.unwrap_or(package_name_from_manifest(current_dir)?);
            let value = client.dist_tags(Some(&registry_url), &package).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(tags) = value.as_object() {
                for (tag, version) in tags {
                    println!("{tag}: {version}");
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
        }
        DistTagAction::Add { package, tag } => {
            let (name, version) = split_package_version(&package)?;
            let tag = tag.unwrap_or_else(|| "latest".to_string());
            client
                .dist_tag_add(Some(&registry_url), name, &tag, version, otp.as_deref())
                .await?;
            println!("+ {name}@{version} ({tag})");
        }
        DistTagAction::Rm { package, tag } => {
            let name = package_name_from_spec(&package);
            client
                .dist_tag_remove(Some(&registry_url), name, &tag, otp.as_deref())
                .await?;
            println!("- {name} {tag}");
        }
    }
    Ok(())
}

async fn execute_owner(
    current_dir: &Path,
    action: OwnerAction,
    registry: Option<String>,
    json: bool,
    otp: Option<String>,
) -> anyhow::Result<()> {
    let (registry_url, client) = make_registry_client(current_dir, registry)?;
    match action {
        OwnerAction::Ls { package } => {
            let value = client.package_owners(Some(&registry_url), &package).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(map) = value.as_object() {
                for (name, role) in map {
                    println!("{name}\t{}", role.as_str().unwrap_or("owner"));
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
        }
        OwnerAction::Add { user, package } => {
            client
                .package_owner_add(Some(&registry_url), &package, &user, otp.as_deref())
                .await?;
            println!("added {user} to {package}");
        }
        OwnerAction::Rm { user, package } => {
            client
                .package_owner_remove(Some(&registry_url), &package, &user, otp.as_deref())
                .await?;
            println!("removed {user} from {package}");
        }
    }
    Ok(())
}

async fn execute_package_admin(current_dir: &Path, command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Unpublish {
            package,
            version,
            force,
            dry_run,
            registry,
            otp,
        } => {
            let package = package.unwrap_or(package_name_from_manifest(current_dir)?);
            if version.is_none() && !force {
                return Err(anyhow::anyhow!("npm error code EUSAGE\nnpm error Refusing to unpublish an entire package without --force"));
            }
            if dry_run {
                println!(
                    "would remove {}{}",
                    package,
                    version
                        .as_deref()
                        .map(|v| format!("@{v}"))
                        .unwrap_or_default()
                );
                return Ok(());
            }
            let (registry_url, client) = make_registry_client(current_dir, registry)?;
            client
                .unpublish(
                    Some(&registry_url),
                    &package,
                    version.as_deref(),
                    otp.as_deref(),
                )
                .await?;
            println!(
                "- {}{}",
                package,
                version
                    .as_deref()
                    .map(|v| format!("@{v}"))
                    .unwrap_or_default()
            );
        }
        Commands::Deprecate {
            package,
            message,
            otp,
            registry,
        } => {
            let (name, version) = split_package_version(&package)?;
            let (registry_url, client) = make_registry_client(current_dir, registry)?;
            client
                .deprecate(Some(&registry_url), name, version, &message, otp.as_deref())
                .await?;
            println!("deprecated {name}@{version}");
        }
        Commands::Undeprecate {
            package,
            version,
            registry,
        } => {
            let (name, parsed_version): (&str, String) = if let Some(version) = version {
                (package.as_str(), version)
            } else {
                let (name, version) = split_package_version(&package)?;
                (name, version.to_string())
            };
            let (registry_url, client) = make_registry_client(current_dir, registry)?;
            client
                .deprecate(Some(&registry_url), name, &parsed_version, "", None)
                .await?;
            println!("undeprecated {name}@{parsed_version}");
        }
        Commands::Access {
            args,
            registry,
            json,
            otp,
        } => {
            let action = args.first().map(String::as_str).unwrap_or("get");
            let package = args
                .last()
                .filter(|value| !value.contains('='))
                .cloned()
                .or_else(|| package_name_from_manifest(current_dir).ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "npm error code EUSAGE\nnpm error access requires a package name"
                    )
                })?;
            let level = args
                .iter()
                .find_map(|value| value.strip_prefix("status="))
                .or_else(|| {
                    args.get(1)
                        .map(String::as_str)
                        .filter(|value| *value == "public" || *value == "restricted")
                })
                .or(match action {
                    "public" | "restricted" => Some(action),
                    _ => None,
                });
            let (registry_url, client) = make_registry_client(current_dir, registry)?;
            let value = match action {
                "public" | "restricted" => client.package_access(Some(&registry_url), &package, Some(action), otp.as_deref()).await?,
                "get" | "set" if args.get(1).is_some_and(|value| value == "status" || value.starts_with("status=") || value == "public" || value == "restricted") => client.package_access(Some(&registry_url), &package, level, otp.as_deref()).await?,
                "list" if args.get(1).is_some_and(|value| value == "collaborators") => client.package_owners(Some(&registry_url), &package).await?,
                _ => return Err(anyhow::anyhow!("npm error code ENOTSUP\nnpm error this access operation is not supported by the configured registry")),
            };
            if json || level.is_none() {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(level) = level {
                println!("{level}");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn split_package_version(spec: &str) -> anyhow::Result<(&str, &str)> {
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

fn package_name_from_spec(spec: &str) -> &str {
    if let Some(stripped) = spec.strip_prefix('@') {
        stripped
            .rfind('@')
            .map(|idx| &spec[..idx + 1])
            .unwrap_or(spec)
    } else {
        spec.split_once('@').map(|(name, _)| name).unwrap_or(spec)
    }
}

fn package_name_from_manifest(current_dir: &Path) -> anyhow::Result<String> {
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

/// Return installed dependency identities that can execute install-time code.
/// The walk follows the actual node_modules tree, so nested and multi-version
/// dependencies are classified independently just like Arborist's actual tree.
fn installed_install_script_packages(
    current_dir: &Path,
) -> anyhow::Result<BTreeMap<String, PathBuf>> {
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
    ) -> anyhow::Result<()> {
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
                // Scoped package directories and node_modules containers.
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

fn list_pending_install_scripts(current_dir: &Path, json: bool) -> anyhow::Result<()> {
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
        println!("{}", serde_json::json!({"pending": pending}));
    } else {
        for item in pending {
            println!("{item}");
        }
    }
    Ok(())
}

fn prune_install_scripts_policy(
    current_dir: &Path,
    json: bool,
    dry_run: bool,
) -> anyhow::Result<()> {
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
        // Preserve malformed / compound selectors exactly as npm does.
        if key.is_empty() || key.contains("||") || key.contains(' ') {
            continue;
        }
        let keep = if key == "*" {
            !installed.is_empty()
        } else if key.contains('@') && !key.starts_with('@') {
            installed.contains_key(&key)
        } else if key.starts_with('@') {
            // Scoped names have a second '@' only when pinned; otherwise match by name.
            installed
                .keys()
                .any(|identity| identity.starts_with(&format!("{key}@")))
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
            serde_json::json!({"removed": removed, "dryRun": dry_run})
        );
    } else {
        for item in removed {
            println!("removed {item}");
        }
    }
    Ok(())
}

fn update_allow_scripts_policy(
    current_dir: &Path,
    packages: &[String],
    approved: bool,
    all: bool,
    json: bool,
) -> anyhow::Result<()> {
    let path = current_dir.join("package.json");
    let mut document: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let installed = installed_install_script_packages(current_dir)?;
    let mut names: Vec<String> = if all {
        installed.keys().cloned().collect()
    } else {
        packages
            .iter()
            .flat_map(|requested| {
                let matched: Vec<String> = installed
                    .keys()
                    .filter(|identity| {
                        *identity == requested
                            || identity
                                .rsplit_once('@')
                                .map(|(name, _)| name == requested)
                                .unwrap_or(false)
                    })
                    .cloned()
                    .collect();
                if matched.is_empty() {
                    vec![requested.clone()]
                } else {
                    matched
                }
            })
            .collect()
    };
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\nnpm error specify at least one package or --all"
        ));
    }
    let policy = {
        let map = document.as_object_mut().ok_or_else(|| {
            anyhow::anyhow!(
                "npm error code EJSONPARSE\nnpm error package.json must contain an object"
            )
        })?;
        let allow = map
            .entry("allowScripts")
            .or_insert_with(|| serde_json::json!({}));
        let allow = allow.as_object_mut().ok_or_else(|| {
            anyhow::anyhow!(
                "npm error code EJSONPARSE\nnpm error package.json allowScripts must be an object"
            )
        })?;
        for name in &names {
            if approved {
                // An explicit denial always wins over blanket approval.
                let package_name = name.rsplit_once('@').map(|(n, _)| n).unwrap_or(name);
                if allow.get(package_name).and_then(|v| v.as_bool()) == Some(false)
                    || allow.get(name).and_then(|v| v.as_bool()) == Some(false)
                {
                    continue;
                }
                allow.insert(name.clone(), serde_json::Value::Bool(true));
            } else {
                let package_name = name.rsplit_once('@').map(|(n, _)| n).unwrap_or(name);
                allow.insert(package_name.to_string(), serde_json::Value::Bool(false));
            }
        }
        serde_json::Value::Object(allow.clone())
    };
    std::fs::write(&path, serde_json::to_string_pretty(&document)? + "\n")?;
    if json {
        println!("{}", serde_json::json!({"allowScripts": policy}));
    } else {
        println!(
            "{} {} lifecycle scripts",
            if approved { "approved" } else { "denied" },
            names.join(",")
        );
    }
    Ok(())
}

fn split_team_entity(entity: &str) -> anyhow::Result<(&str, &str)> {
    let entity = entity.trim_start_matches('@');
    entity.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("npm error code EUSAGE\nnpm error team entity must use <scope:team> format")
    })
}

async fn execute_profile(
    current_dir: &Path,
    action: Option<String>,
    args: Vec<String>,
    registry: Option<String>,
    json: bool,
    otp: Option<String>,
    _parseable: bool,
) -> anyhow::Result<()> {
    let (registry_url, client) = make_registry_client(current_dir, registry)?;
    match action.as_deref().unwrap_or("get") {
        "get" => {
            let value = client.profile_get(Some(&registry_url)).await?;
            if let Some(key) = args.first() {
                let selected = value.get(key).cloned().unwrap_or(serde_json::Value::Null);
                if json {
                    println!("{}", serde_json::to_string_pretty(&selected)?);
                } else {
                    println!(
                        "{}",
                        selected
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| selected.to_string())
                    );
                }
                return Ok(());
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(object) = value.as_object() {
                for (key, value) in object {
                    let rendered = value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string());
                    println!("{key}: {rendered}");
                }
            } else {
                println!("{}", value);
            }
        }
        "set" => {
            if args.len() < 2 {
                return Err(anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error profile set <property> <value>"
                ));
            }
            let value = client
                .profile_set(
                    Some(&registry_url),
                    serde_json::json!({args[0].clone(): args[1..].join(" ")}),
                    otp.as_deref(),
                )
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                println!("profile updated");
            }
        }
        "enable-2fa" | "disable-2fa" => {
            return Err(anyhow::anyhow!(
            "npm error code ENOTSUP\nnpm error profile action is not supported by this registry"
        ))
        }
        other => {
            return Err(anyhow::anyhow!(
                "npm error code EUSAGE\nnpm error Unknown profile command: {other}"
            ))
        }
    }
    Ok(())
}

async fn execute_org(
    current_dir: &Path,
    action: Option<String>,
    args: Vec<String>,
    registry: Option<String>,
    json: bool,
    _parseable: bool,
) -> anyhow::Result<()> {
    let (registry_url, client) = make_registry_client(current_dir, registry)?;
    let action = action.as_deref().unwrap_or("ls");
    let value = match action {
        "ls" => {
            let org = args
                .first()
                .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error org ls <org>"))?;
            client.org_members(Some(&registry_url), org).await?
        }
        "add" | "set" => {
            let org = args.first().ok_or_else(|| {
                anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error org add <org> <user> [developer|admin]"
                )
            })?;
            let user = args.get(1).ok_or_else(|| {
                anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error org add <org> <user> [developer|admin]"
                )
            })?;
            client
                .org_member_set(
                    Some(&registry_url),
                    org,
                    user,
                    args.get(2).map(String::as_str),
                )
                .await?
        }
        "rm" | "remove" => {
            let org = args.first().ok_or_else(|| {
                anyhow::anyhow!("npm error code EUSAGE\nnpm error org rm <org> <user>")
            })?;
            let user = args.get(1).ok_or_else(|| {
                anyhow::anyhow!("npm error code EUSAGE\nnpm error org rm <org> <user>")
            })?;
            client
                .org_member_remove(Some(&registry_url), org, user)
                .await?;
            serde_json::Value::Null
        }
        other => {
            return Err(anyhow::anyhow!(
                "npm error code EUSAGE\nnpm error Unknown org command: {other}"
            ))
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if let Some(object) = value.as_object() {
        for (user, role) in object {
            println!("{user}\t{}", role.as_str().unwrap_or("member"));
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}

async fn execute_team(
    current_dir: &Path,
    action: Option<String>,
    args: Vec<String>,
    registry: Option<String>,
    json: bool,
    description: Option<String>,
    _parseable: bool,
) -> anyhow::Result<()> {
    let (registry_url, client) = make_registry_client(current_dir, registry)?;
    let action = action.as_deref().unwrap_or("ls");
    let value = match action {
        "create" => {
            let entity = args.first().ok_or_else(|| {
                anyhow::anyhow!("npm error code EUSAGE\nnpm error team create <scope:team>")
            })?;
            let (scope, team) = split_team_entity(entity)?;
            client
                .team_create(Some(&registry_url), scope, team, description.as_deref())
                .await?
        }
        "destroy" => {
            let entity = args.first().ok_or_else(|| {
                anyhow::anyhow!("npm error code EUSAGE\nnpm error team destroy <scope:team>")
            })?;
            let (scope, team) = split_team_entity(entity)?;
            client
                .team_destroy(Some(&registry_url), scope, team)
                .await?;
            serde_json::Value::Null
        }
        "add" | "rm" => {
            let entity = args.first().ok_or_else(|| {
                anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error team {action} <scope:team> <user>"
                )
            })?;
            let user = args.get(1).ok_or_else(|| {
                anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error team {action} <scope:team> <user>"
                )
            })?;
            let (scope, team) = split_team_entity(entity)?;
            if action == "add" {
                client
                    .team_add_user(Some(&registry_url), scope, team, user)
                    .await?
            } else {
                client
                    .team_remove_user(Some(&registry_url), scope, team, user)
                    .await?;
                serde_json::Value::Null
            }
        }
        "ls" => {
            let entity = args.first().ok_or_else(|| {
                anyhow::anyhow!("npm error code EUSAGE\nnpm error team ls <scope>|<scope:team>")
            })?;
            if entity.contains(':') {
                let (scope, team) = split_team_entity(entity)?;
                client.team_users(Some(&registry_url), scope, team).await?
            } else {
                client.teams(Some(&registry_url), entity).await?
            }
        }
        other => {
            return Err(anyhow::anyhow!(
                "npm error code EUSAGE\nnpm error Unknown team command: {other}"
            ))
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if let Some(array) = value.as_array() {
        for item in array {
            let rendered = item
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| item.to_string());
            println!("{rendered}");
        }
    } else if !value.is_null() {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}

fn replace_version_in_url(url: &str, pkg_name: &str, new_ver: &str) -> String {
    let simple_name = pkg_name.split('/').next_back().unwrap_or(pkg_name);
    let pattern = format!("{simple_name}-");
    if let Some(pos) = url.rfind(&pattern) {
        let prefix = &url[..pos + pattern.len()];
        let after_pattern = &url[pos + pattern.len()..];
        if let Some(end) = after_pattern.find(".tgz") {
            let remainder = &after_pattern[end..];
            return format!("{prefix}{new_ver}{remainder}");
        }
    }
    url.to_string()
}

fn print_fixed_summary(
    fixed_vulns: usize,
    fixed_counts: &audit::VulnerabilitiesCount,
    pkg_count: usize,
) {
    let mut parts = Vec::new();
    if fixed_counts.low > 0 {
        parts.push(format!("{} low", fixed_counts.low));
    }
    if fixed_counts.moderate > 0 {
        parts.push(format!("{} moderate", fixed_counts.moderate));
    }
    if fixed_counts.high > 0 {
        parts.push(format!("{} high", fixed_counts.high));
    }
    if fixed_counts.critical > 0 {
        parts.push(format!("{} critical", fixed_counts.critical));
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
    let mut manifest_val: serde_json::Value = serde_json::from_str(&manifest_content)?;

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

    let mut packages_to_upgrade: BTreeMap<String, (rnpm_core::semver::Version, String)> =
        BTreeMap::new();
    let mut fixed_advisory_ids: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut fixed_counts = audit::VulnerabilitiesCount::default();

    for (pkg_name, pkg_advs) in &advs_by_pkg {
        let mut highest_target_ver: Option<rnpm_core::semver::Version> = None;
        let mut old_ver_str = String::new();

        for adv in pkg_advs {
            if old_ver_str.is_empty() {
                old_ver_str = adv.installed_version.clone();
            }

            if let Some(target) = audit::resolve_target_patched_version(
                adv.patched_versions.as_deref(),
                &adv.vulnerable_versions,
            ) {
                highest_target_ver = match highest_target_ver {
                    Some(cur) => Some(cur.max(target)),
                    None => Some(target),
                };
            }
        }

        let target_ver = match highest_target_ver {
            Some(v) => v,
            None => continue,
        };

        let installed_ver = rnpm_core::semver::Version::parse(&old_ver_str)
            .unwrap_or_else(|_| rnpm_core::semver::Version::new(0, 0, 0));

        // Semver compatibility check
        let is_compatible = if let Some(declared_range_str) = declared_direct.get(pkg_name) {
            if let Ok(declared_range) = rnpm_core::semver::Range::parse(declared_range_str) {
                declared_range.satisfies(&target_ver)
            } else {
                false
            }
        } else if installed_ver.major == 0 {
            target_ver.major == 0 && target_ver.minor == installed_ver.minor
        } else {
            target_ver.major == installed_ver.major
        };

        if is_compatible || force {
            packages_to_upgrade.insert(pkg_name.clone(), (target_ver.clone(), old_ver_str.clone()));
            for adv in pkg_advs {
                let is_still_vuln = match rnpm_core::semver::Range::parse(&adv.vulnerable_versions)
                {
                    Ok(r) => r.satisfies(&target_ver),
                    Err(_) => false,
                };
                if !is_still_vuln {
                    let adv_key = format!("{}:{:?}", adv.name, adv.id);
                    if fixed_advisory_ids.insert(adv_key) {
                        match adv.severity {
                            audit::Severity::Info => fixed_counts.info += 1,
                            audit::Severity::Low => fixed_counts.low += 1,
                            audit::Severity::Moderate => fixed_counts.moderate += 1,
                            audit::Severity::High => fixed_counts.high += 1,
                            audit::Severity::Critical => fixed_counts.critical += 1,
                        }
                        fixed_counts.total += 1;
                    }
                }
            }
        }
    }

    let fixed_vulns = fixed_counts.total;

    if packages_to_upgrade.is_empty() || fixed_vulns == 0 {
        println!("found 0 vulnerabilities to fix");
        audit::print_concise_audit_summary(&initial_report);
        if !force {
            eprintln!("npm warn audit Semver-major updates or transitive dependencies may require `rnpm audit fix --force`");
        }
        return Ok(());
    }

    if dry_run {
        for (pkg_name, (target_ver, old_ver)) in &packages_to_upgrade {
            println!("would update {pkg_name} from {old_ver} to {target_ver}");
        }
        print_fixed_summary(fixed_vulns, &fixed_counts, packages_to_upgrade.len());
        return Ok(());
    }

    // 1. Rewrite package.json
    let mut modified_manifest = false;
    for (pkg_name, (target_ver, _)) in &packages_to_upgrade {
        let new_range = format!("^{target_ver}");
        for section in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(sec) = manifest_val
                .get_mut(section)
                .and_then(|s| s.as_object_mut())
            {
                if sec.contains_key(pkg_name) {
                    sec.insert(
                        pkg_name.clone(),
                        serde_json::Value::String(new_range.clone()),
                    );
                    modified_manifest = true;
                }
            }
        }
    }
    if modified_manifest {
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest_val)? + "\n",
        )?;
    }

    // 2. Rewrite package-lock.json
    let lock_content = std::fs::read_to_string(&lock_path)?;
    let mut lock_val: serde_json::Value = serde_json::from_str(&lock_content)?;

    if let Some(packages) = lock_val.get_mut("packages").and_then(|p| p.as_object_mut()) {
        for (pkg_name, (target_ver, _)) in &packages_to_upgrade {
            let target_str = target_ver.to_string();
            if let Some(root_pkg) = packages.get_mut("").and_then(|r| r.as_object_mut()) {
                let new_range = format!("^{target_str}");
                for sec_name in ["dependencies", "devDependencies", "optionalDependencies"] {
                    if let Some(sec) = root_pkg.get_mut(sec_name).and_then(|s| s.as_object_mut()) {
                        if sec.contains_key(pkg_name) {
                            sec.insert(
                                pkg_name.clone(),
                                serde_json::Value::String(new_range.clone()),
                            );
                        }
                    }
                }
            }

            for (key, node_val) in packages.iter_mut() {
                if key.is_empty() {
                    continue;
                }
                let is_match = key == &format!("node_modules/{pkg_name}")
                    || key.ends_with(&format!("/node_modules/{pkg_name}"))
                    || node_val.get("name").and_then(|n| n.as_str()) == Some(pkg_name.as_str());
                if is_match {
                    if let Some(obj) = node_val.as_object_mut() {
                        obj.insert(
                            "version".to_string(),
                            serde_json::Value::String(target_str.clone()),
                        );
                        if let Some(resolved) = obj.get("resolved").and_then(|r| r.as_str()) {
                            let updated_url =
                                replace_version_in_url(resolved, pkg_name, &target_str);
                            obj.insert(
                                "resolved".to_string(),
                                serde_json::Value::String(updated_url),
                            );
                        }
                    }
                }
            }
        }
    }

    if let Some(v1_deps) = lock_val
        .get_mut("dependencies")
        .and_then(|d| d.as_object_mut())
    {
        for (pkg_name, (target_ver, _)) in &packages_to_upgrade {
            let target_str = target_ver.to_string();
            if let Some(pkg_obj) = v1_deps.get_mut(pkg_name).and_then(|p| p.as_object_mut()) {
                pkg_obj.insert("version".to_string(), serde_json::Value::String(target_str));
            }
        }
    }

    std::fs::write(&lock_path, serde_json::to_string_pretty(&lock_val)? + "\n")?;

    // 3. Update node_modules package.json if present
    let nm_dir = project_dir.join("node_modules");
    if nm_dir.exists() {
        for (pkg_name, (target_ver, _)) in &packages_to_upgrade {
            let pkg_nm = nm_dir.join(pkg_name).join("package.json");
            if pkg_nm.exists() {
                if let Ok(content) = std::fs::read_to_string(&pkg_nm) {
                    if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(obj) = val.as_object_mut() {
                            obj.insert(
                                "version".to_string(),
                                serde_json::Value::String(target_ver.to_string()),
                            );
                            let _ = std::fs::write(
                                &pkg_nm,
                                serde_json::to_string_pretty(&val).unwrap_or_default() + "\n",
                            );
                        }
                    }
                }
            }
        }
    }

    print_fixed_summary(fixed_vulns, &fixed_counts, packages_to_upgrade.len());

    let (post_report, _) = audit::build_audit_report(project_dir, registry)
        .await
        .unwrap_or((initial_report.clone(), None));
    let remaining_vulns = post_report.metadata.vulnerabilities.total;

    if remaining_vulns > 0 {
        audit::print_concise_audit_summary(&post_report);
        if !force {
            eprintln!("npm warn audit Semver-major updates or transitive dependencies may require `rnpm audit fix --force`");
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

pub(crate) async fn run_cli(cli: Cli, dir: Option<PathBuf>) -> anyhow::Result<()> {
    let current_dir = match dir {
        Some(d) => d,
        None => std::env::current_dir()?,
    };

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
            save_prod,
            save_optional,
            save_peer,
            no_save,
            package_lock_only,
            omit,
            legacy_peer_deps,
            strict_peer_deps,
            global,
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
        } => {
            let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
            let timing_val = timing || config.get_bool("timing").unwrap_or(false);
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
            let effective_strategy = strategy_str.parse::<rnpm_install::InstallStrategy>()?;

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
                audit.unwrap_or(true)
            };
            let fund_val = if no_fund || fund == Some(false) {
                false
            } else {
                fund.unwrap_or(true)
            };
            let target_dir = if global {
                rnpm_config::find_global_prefix()
            } else {
                current_dir.clone()
            };

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
                ..Default::default()
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
        } => {
            let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
            let timing_val = timing || config.get_bool("timing").unwrap_or(false);
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
            let effective_strategy = strategy_str.parse::<rnpm_install::InstallStrategy>()?;

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
            let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
            let effective_ignore =
                ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false);
            let effective_foreground =
                foreground_scripts || config.get_bool("foreground-scripts").unwrap_or(false);
            let effective_strict =
                strict_sandbox || config.get_bool("strict-sandbox").unwrap_or(false);

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
            package,
            args,
            registry,
            cache,
            offline,
        } => {
            execute_exec(&current_dir, &package, &args, registry, cache, offline).await?;
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
            if let Some(init_pkg) = initializer {
                let transformed = init::transform_initializer(&init_pkg);
                execute_exec(&current_dir, &transformed, &args, registry, cache, offline).await?;
            } else {
                let init_opts = init::InitOptions {
                    yes,
                    scope,
                    directory: current_dir,
                };
                let stdin = std::io::stdin();
                let mut stdin_lock = stdin.lock();
                let stdout = std::io::stdout();
                let mut stdout_lock = stdout.lock();
                init::run_init(&init_opts, &mut stdin_lock, &mut stdout_lock)?;
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

            let (summary, tarball_bytes) = match rnpm_fs::pack_directory(&package_dir, None) {
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
            global,
        } => {
            let target_dir = if global {
                rnpm_config::find_global_prefix()
            } else {
                current_dir
            };
            let options = InstallOptions {
                project_dir: target_dir,
                is_global: global,
                ..Default::default()
            };
            let installer = Installer::new(options)?;
            let uninstall_options = UninstallOptions {
                packages,
                save_dev,
                save_optional,
                save_prod,
                is_global: global,
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
            foreground_scripts,
            strict_sandbox,
            legacy_peer_deps,
            strict_peer_deps,
        } => {
            let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
            let effective_ignore =
                ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false);
            let effective_foreground =
                foreground_scripts || config.get_bool("foreground-scripts").unwrap_or(false);
            let effective_strict =
                strict_sandbox || config.get_bool("strict-sandbox").unwrap_or(false);

            let options = InstallOptions {
                project_dir: current_dir,
                registry_url: registry,
                cache_dir: cache,
                offline,
                ignore_scripts: effective_ignore,
                foreground_scripts: effective_foreground,
                strict_sandbox: effective_strict,
                legacy_peer_deps,
                strict_peer_deps,
                ..Default::default()
            };

            let mut installer = Installer::new(options)?;
            let summary = installer.update(&packages).await?;

            if summary.packages_updated == 0 {
                println!("rnpm: up to date");
            } else {
                for pkg in &summary.updated_packages {
                    let old_v = summary
                        .old_versions
                        .get(pkg)
                        .map(|s| s.as_str())
                        .unwrap_or("none");
                    let new_v = summary
                        .new_versions
                        .get(pkg)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
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
            let (mut omit_dev, omit_optional, omit_peer) =
                parse_omit_and_include_options(&omit, &include);
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
        Commands::Dedupe { packages, dry_run } => {
            let dedupe_options = rnpm_install::DedupeOptions {
                project_dir: current_dir.clone(),
                dry_run,
                packages,
            };
            let installer = Installer::new(InstallOptions {
                project_dir: current_dir,
                ..Default::default()
            })?;
            let summary = installer.dedupe(&dedupe_options)?;

            if dry_run {
                if summary.actions.is_empty() {
                    println!(
                        "rnpm: dedupe dry-run: tree is already deduplicated, no duplicates found"
                    );
                } else {
                    for action in &summary.actions {
                        match action.action_type {
                            rnpm_install::DedupeActionType::DeleteDuplicate => {
                                println!(
                                    "rnpm: dedupe: would remove {} ({})",
                                    action.original_path, action.reason
                                );
                            }
                            rnpm_install::DedupeActionType::HoistAndDedupe => {
                                println!(
                                    "rnpm: dedupe: would hoist {} -> {} ({})",
                                    action.original_path, action.target_path, action.reason
                                );
                            }
                        }
                    }
                    println!(
                        "rnpm: dedupe dry-run: {} action(s) would be performed",
                        summary.actions.len()
                    );
                }
            } else if summary.actions.is_empty() {
                println!("rnpm: tree is already deduplicated");
            } else {
                for action in &summary.actions {
                    match action.action_type {
                        rnpm_install::DedupeActionType::DeleteDuplicate => {
                            println!("rnpm: dedupe: removed {}", action.original_path);
                        }
                        rnpm_install::DedupeActionType::HoistAndDedupe => {
                            println!(
                                "rnpm: dedupe: hoisted {} -> {}",
                                action.original_path, action.target_path
                            );
                        }
                    }
                }
                println!(
                    "rnpm: successfully deduplicated {} package(s)",
                    summary.actions.len()
                );
            }
        }
        Commands::FindDupes { packages } => {
            let dedupe_options = rnpm_install::DedupeOptions {
                project_dir: current_dir.clone(),
                dry_run: true,
                packages,
            };
            let installer = Installer::new(InstallOptions {
                project_dir: current_dir,
                ..Default::default()
            })?;
            let summary = installer.find_dupes(&dedupe_options)?;

            if summary.actions.is_empty() {
                println!("rnpm: find-dupes: no duplicate packages found");
            } else {
                for action in &summary.actions {
                    println!(
                        "rnpm: find-dupes: duplicate found: {} ({})",
                        action.original_path, action.reason
                    );
                }
                println!(
                    "rnpm: find-dupes: {} duplicate package(s) detected",
                    summary.actions.len()
                );
            }
        }
        Commands::Rebuild {
            packages,
            ignore_scripts,
            foreground_scripts,
            strict_sandbox,
        } => {
            let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
            let effective_ignore =
                ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false);
            let effective_foreground =
                foreground_scripts || config.get_bool("foreground-scripts").unwrap_or(false);
            let effective_strict =
                strict_sandbox || config.get_bool("strict-sandbox").unwrap_or(false);

            let rebuild_options = rnpm_install::RebuildOptions {
                project_dir: current_dir.clone(),
                packages,
                ignore_scripts: effective_ignore,
                foreground_scripts: effective_foreground,
                strict_sandbox: effective_strict,
            };

            let installer = Installer::new(InstallOptions {
                project_dir: current_dir,
                ignore_scripts: effective_ignore,
                foreground_scripts: effective_foreground,
                strict_sandbox: effective_strict,
                ..Default::default()
            })?;

            let summary = installer.rebuild(&rebuild_options).await?;
            if summary.rebuilt_packages.is_empty() {
                println!("rnpm: rebuild: no packages required rebuilding");
            } else {
                for pkg in &summary.rebuilt_packages {
                    println!("rnpm: rebuilt {pkg}");
                }
                println!(
                    "rnpm: successfully rebuilt {} package(s)",
                    summary.rebuilt_packages.len()
                );
            }
        }
        Commands::Pkg {
            action,
            prefix,
            json,
            workspace,
            workspaces,
        } => {
            let base_path = if prefix.is_absolute() {
                prefix
            } else {
                current_dir.join(&prefix)
            };
            let root_manifest_path = if base_path.file_name().is_some_and(|f| f == "package.json") {
                base_path.clone()
            } else {
                base_path.join("package.json")
            };
            let project_root = if base_path.file_name().is_some_and(|f| f == "package.json") {
                base_path.parent().unwrap_or(&base_path).to_path_buf()
            } else {
                base_path.clone()
            };

            if !root_manifest_path.exists() {
                return Err(anyhow::anyhow!(
                    "code ENOENT: package.json not found in {}",
                    project_root.display()
                ));
            }

            let is_workspace_mode = workspaces || !workspace.is_empty();
            if is_workspace_mode {
                let discovered = rnpm_core::workspace::discover_workspaces(&project_root)
                    .map_err(|e| anyhow::anyhow!("Failed to discover workspaces: {e}"))?;

                if discovered.is_empty() {
                    return Err(anyhow::anyhow!(
                        "npm error code ENOWORKSPACES\nnpm error No workspaces found in {}",
                        project_root.display()
                    ));
                }

                let matched_members: Vec<rnpm_core::workspace::WorkspaceMember> = if workspaces
                    && workspace.is_empty()
                {
                    discovered
                } else {
                    let mut matched = Vec::new();
                    for ws_filter in &workspace {
                        let matches: Vec<_> = discovered
                            .iter()
                            .filter(|m| {
                                rnpm_lifecycle::matches_filter(
                                    ws_filter,
                                    &m.name,
                                    &m.path,
                                    &project_root,
                                )
                            })
                            .cloned()
                            .collect();
                        if matches.is_empty() {
                            return Err(anyhow::anyhow!(
                                "npm error code ENOWORKSPACE\nnpm error No workspaces found for: {ws_filter}"
                            ));
                        }
                        for m in matches {
                            if !matched.iter().any(
                                |existing: &rnpm_core::workspace::WorkspaceMember| {
                                    existing.name == m.name
                                },
                            ) {
                                matched.push(m);
                            }
                        }
                    }
                    matched
                };

                match action {
                    PkgAction::Get { fields } => {
                        let member_refs: Vec<(&str, &Path)> = matched_members
                            .iter()
                            .map(|m| (m.name.as_str(), m.path.as_path()))
                            .collect();
                        let output = rnpm_core::pkg::pkg_get_workspaces(&member_refs, &fields)?;
                        println!("{output}");
                    }
                    PkgAction::Set { assignments } => {
                        for m in &matched_members {
                            rnpm_core::pkg::pkg_set(&m.manifest_path(), &assignments)?;
                        }
                    }
                    PkgAction::Delete { fields } => {
                        for m in &matched_members {
                            rnpm_core::pkg::pkg_delete(&m.manifest_path(), &fields)?;
                        }
                    }
                }
            } else {
                match action {
                    PkgAction::Get { fields } => {
                        let output = rnpm_core::pkg::pkg_get(&root_manifest_path, &fields, json)?;
                        println!("{output}");
                    }
                    PkgAction::Set { assignments } => {
                        rnpm_core::pkg::pkg_set(&root_manifest_path, &assignments)?;
                    }
                    PkgAction::Delete { fields } => {
                        rnpm_core::pkg::pkg_delete(&root_manifest_path, &fields)?;
                    }
                }
            }
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
                        eprintln!(
                            "npm error If you are sure you want to delete the entire cache, run:"
                        );
                        eprintln!("npm error   rnpm cache clean --force");
                        std::process::exit(1);
                    }
                    cache.clean()?;
                    println!(
                        "rnpm: cache cleared successfully ({})",
                        cache_path.display()
                    );
                }
                CacheAction::Verify { .. } => {
                    let start = std::time::Instant::now();
                    let report = cache.verify()?;
                    let elapsed = start.elapsed().as_secs_f64();
                    println!("Cache verified and compacted ({})", cache_path.display());
                    println!(
                        "Content verified: {} ({} bytes)",
                        report.verified_blobs, report.total_blob_bytes
                    );
                    println!("Index entries: {}", report.verified_indices);
                    if report.corrupted_blobs > 0
                        || report.corrupted_indices > 0
                        || report.orphaned_indices > 0
                        || report.stale_temp_files_cleaned > 0
                    {
                        println!(
                            "Cleaned: {} corrupt blob(s), {} corrupt index file(s), {} orphaned index pointer(s), {} stale temp file(s)",
                            report.corrupted_blobs, report.corrupted_indices, report.orphaned_indices, report.stale_temp_files_cleaned
                        );
                    }
                    println!("Finished in {:.3}s", elapsed);
                }
            }
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
            package_lock_only: _,
            omit,
        } => {
            let options = sbom::SbomOptions {
                format: sbom_format,
                sbom_type,
                package_lock_only: false,
                omit,
            };
            sbom::run_sbom(&current_dir, options).await?;
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
        } => {
            let options = version::VersionOptions {
                newversion,
                preid,
                message,
                allow_same_version,
                git_tag_version: !no_git_tag_version,
                commit_hooks: !no_commit_hooks,
                sign_git_tag,
                force,
                ignore_scripts,
                json,
            };

            version::execute_version(&current_dir, options).await?;
        }
        Commands::List {
            packages,
            depth,
            all,
            json,
            long,
            parseable,
            package_lock_only,
            omit,
        } => {
            let opts = list::ListOptions {
                packages,
                depth,
                all,
                json,
                long,
                parseable,
                package_lock_only,
                omit,
            };
            let code = list::run_list(&current_dir, &opts)?;
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
            let opts = outdated::OutdatedOptions {
                packages,
                all,
                json,
                long,
                parseable,
                registry,
            };
            let code = outdated::run_outdated(&current_dir, &opts).await?;
            if code != 0 {
                return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                    exit_code: code,
                    message: "outdated dependencies found".to_string(),
                }));
            }
        }
        Commands::View {
            args,
            json,
            registry,
        } => {
            let opts = view::ViewOptions {
                args,
                json,
                registry,
            };
            let code = view::run_view(&current_dir, &opts).await?;
            if code != 0 {
                return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                    exit_code: code,
                    message: "view finished with non-zero exit code".to_string(),
                }));
            }
        }
        Commands::Query {
            selector,
            package_lock_only,
            registry,
        } => {
            let opts = query::QueryOptions {
                selector,
                package_lock_only,
                registry,
            };
            let code = query::run_query(&current_dir, &opts).await?;
            if code != 0 {
                return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
                    exit_code: code,
                    message: "query finished with non-zero exit code".to_string(),
                }));
            }
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
            execute_publish(
                current_dir,
                target,
                tag,
                access,
                dry_run,
                otp,
                provenance,
                registry,
                ignore_scripts,
                json,
            )
            .await?;
        }
        Commands::Whoami { registry, json } => {
            execute_whoami(&current_dir, registry, json).await?;
        }
        Commands::Ping { registry, json } => {
            execute_ping(&current_dir, registry, json).await?;
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
            execute_logout(&current_dir, registry, scope).await?;
        }
        Commands::Token {
            action,
            registry,
            json,
        } => {
            execute_token(&current_dir, action, registry, json).await?;
        }
        Commands::ApproveScripts {
            packages,
            all,
            allow_scripts_pending: _,
            json,
        } => {
            update_allow_scripts_policy(&current_dir, &packages, true, all, json)?;
        }
        Commands::DenyScripts {
            packages,
            all,
            allow_scripts_pending: _,
            json,
        } => {
            update_allow_scripts_policy(&current_dir, &packages, false, all, json)?;
        }
        Commands::Completion { shell } => {
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
        } => execute_dist_tag(&current_dir, action, registry, json, otp).await?,
        Commands::Owner {
            action,
            registry,
            json,
            otp,
        } => execute_owner(&current_dir, action, registry, json, otp).await?,
        Commands::Unpublish {
            package,
            version,
            force,
            dry_run,
            registry,
            otp,
        } => {
            execute_package_admin(
                &current_dir,
                Commands::Unpublish {
                    package,
                    version,
                    force,
                    dry_run,
                    registry,
                    otp,
                },
            )
            .await?;
        }
        Commands::Deprecate {
            package,
            message,
            otp,
            registry,
        } => {
            execute_package_admin(
                &current_dir,
                Commands::Deprecate {
                    package,
                    message,
                    otp,
                    registry,
                },
            )
            .await?;
        }
        Commands::Undeprecate {
            package,
            version,
            registry,
        } => {
            execute_package_admin(
                &current_dir,
                Commands::Undeprecate {
                    package,
                    version,
                    registry,
                },
            )
            .await?;
        }
        Commands::Access {
            args,
            registry,
            json,
            otp,
        } => {
            execute_package_admin(
                &current_dir,
                Commands::Access {
                    args,
                    registry,
                    json,
                    otp,
                },
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
            let (registry_url, client) = make_registry_client(&current_dir, registry)?;
            let text = terms.join(" ");
            let value = client
                .search(Some(&registry_url), &text, search_limit, 0)
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(objects) = value.get("objects").and_then(|v| v.as_array()) {
                for item in objects {
                    let p = item.get("package").unwrap_or(item);
                    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
                    let description = p.get("description").and_then(|v| v.as_str()).unwrap_or("");
                    if parseable {
                        println!("{name}\t{version}\t{description}");
                    } else if no_description {
                        println!("{name}@{version}");
                    } else {
                        println!("{name}@{version}\t{description}");
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
        }
        Commands::Stars {
            user,
            json,
            registry,
        } => {
            let (registry_url, client) = make_registry_client(&current_dir, registry)?;
            let value = client
                .starred_packages(Some(&registry_url), user.as_deref())
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(packages) = value.as_array() {
                for package in packages {
                    if let Some(name) = package.as_str() {
                        println!("{name}");
                    } else if let Some(name) = package.get("name").and_then(|v| v.as_str()) {
                        println!("{name}");
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
        }
        Commands::Star {
            packages,
            registry,
            otp,
            no_unicode: _,
        } => {
            let (registry_url, client) = make_registry_client(&current_dir, registry)?;
            if packages.is_empty() {
                return Err(anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error star requires at least one package"
                ));
            }
            for package in packages {
                client
                    .star_package(Some(&registry_url), &package, otp.as_deref())
                    .await?;
                println!("starred {package}");
            }
        }
        Commands::Unstar {
            packages,
            registry,
            otp,
            no_unicode: _,
        } => {
            let (registry_url, client) = make_registry_client(&current_dir, registry)?;
            if packages.is_empty() {
                return Err(anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error unstar requires at least one package"
                ));
            }
            for package in packages {
                client
                    .unstar_package(Some(&registry_url), &package, otp.as_deref())
                    .await?;
                println!("unstarred {package}");
            }
        }
        Commands::Profile {
            action,
            args,
            otp,
            registry,
            json,
            parseable,
        } => execute_profile(&current_dir, action, args, registry, json, otp, parseable).await?,
        Commands::Org {
            action,
            args,
            otp: _,
            registry,
            json,
            parseable,
        } => execute_org(&current_dir, action, args, registry, json, parseable).await?,
        Commands::Team {
            action,
            args,
            otp: _,
            description,
            registry,
            json,
            parseable,
        } => {
            execute_team(
                &current_dir,
                action,
                args,
                registry,
                json,
                description,
                parseable,
            )
            .await?
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
            if json {
                println!(
                    "{}",
                    serde_json::json!({"package": package, "packages": count})
                );
            } else if let Some(package) = package {
                println!("{package}: funding metadata is available in package.json");
            } else {
                println!("{} packages are looking for funding", count);
            }
        }
        Commands::Explain { package, json } => {
            let lock = current_dir.join("package-lock.json");
            let value = std::fs::read_to_string(lock)
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
            let result = value
                .as_ref()
                .and_then(|v| v.get("packages"))
                .and_then(|p| p.get(format!("node_modules/{package}")))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.is_null() {
                return Err(anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error No dependencies found matching {package}"
                ));
            } else {
                let version = result
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let location = format!("node_modules/{package}");
                println!("{package}@{version}");
                println!("{location}");
                let root_spec = value
                    .as_ref()
                    .and_then(|v| v.get("packages"))
                    .and_then(|p| p.get(""))
                    .and_then(|root| {
                        [
                            "dependencies",
                            "optionalDependencies",
                            "devDependencies",
                            "peerDependencies",
                        ]
                        .iter()
                        .find_map(|field| {
                            root.get(*field)
                                .and_then(|deps| deps.get(&package))
                                .and_then(|spec| spec.as_str())
                        })
                    });
                if let Some(spec) = root_spec {
                    println!("  {package}@\"{spec}\" from the root project");
                }
            }
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
            let dir = resolve_local_package_dir(&current_dir, &package)?;
            let editor = editor
                .or_else(|| std::env::var("npm_config_editor").ok())
                .or_else(|| std::env::var("VISUAL").ok())
                .or_else(|| std::env::var("EDITOR").ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("npm error code ENOENT\nnpm error no editor configured")
                })?;
            let status = std::process::Command::new(&editor)
                .current_dir(dir)
                .status()?;
            if !status.success() {
                return Err(anyhow::anyhow!(
                    "npm error code ELIFECYCLE\nnpm error editor exited with {status}"
                ));
            }
        }
        Commands::Explore { package, shell } => {
            let dir = resolve_local_package_dir(&current_dir, &package)?;
            #[cfg(windows)]
            let (program, args): (String, Vec<String>) = (
                shell
                    .or_else(|| std::env::var("ComSpec").ok())
                    .unwrap_or_else(|| "cmd.exe".into()),
                vec!["/K".into()],
            );
            #[cfg(not(windows))]
            let (program, args): (String, Vec<String>) = (
                shell
                    .or_else(|| std::env::var("SHELL").ok())
                    .unwrap_or_else(|| "/bin/sh".into()),
                Vec::new(),
            );
            let status = std::process::Command::new(program)
                .args(args)
                .current_dir(dir)
                .status()?;
            if !status.success() {
                return Err(anyhow::anyhow!(
                    "npm error code ELIFECYCLE\nnpm error explore shell exited with {status}"
                ));
            }
        }
        Commands::HelpSearch {
            terms,
            long,
            registry,
            json,
        } => {
            let (registry_url, client) = make_registry_client(&current_dir, registry)?;
            let value = client
                .search(
                    Some(&registry_url),
                    &terms.join(" "),
                    if long { 50 } else { 20 },
                    0,
                )
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if let Some(objects) = value.get("objects").and_then(|v| v.as_array()) {
                for object in objects {
                    let package = object.get("package").unwrap_or(object);
                    let name = package.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let description = package
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    println!("{name}\t{description}");
                }
            }
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
            let mut installer = Installer::new(InstallOptions {
                project_dir: current_dir.clone(),
                ..Default::default()
            })?;
            installer.run_ci().await?;
            execute_run(
                current_dir,
                Some("test".into()),
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
        Commands::InstallScripts {
            action,
            packages,
            all,
            json,
            dry_run,
        } => match action.as_deref().unwrap_or("") {
            "approve" => update_allow_scripts_policy(&current_dir, &packages, true, all, json)?,
            "deny" => update_allow_scripts_policy(&current_dir, &packages, false, all, json)?,
            "ls" | "list" => list_pending_install_scripts(&current_dir, json)?,
            "prune" => prune_install_scripts_policy(&current_dir, json, dry_run)?,
            _ => {
                return Err(anyhow::anyhow!(
                    "npm error code EUSAGE\nnpm error install-scripts approve|deny|ls|prune"
                ))
            }
        },
        Commands::InstallTest { args } => {
            let mut installer = Installer::new(InstallOptions {
                project_dir: current_dir.clone(),
                ..Default::default()
            })?;
            installer.run().await?;
            execute_run(
                current_dir,
                Some("test".into()),
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
        Commands::Shrinkwrap => {
            let src = current_dir.join("package-lock.json");
            let dst = current_dir.join("npm-shrinkwrap.json");
            if dst.exists() {
                println!("npm-shrinkwrap.json up to date");
            } else if src.exists() {
                if std::fs::rename(&src, &dst).is_err() {
                    std::fs::copy(&src, &dst)?;
                    std::fs::remove_file(&src)?;
                }
                println!("package-lock.json has been renamed to npm-shrinkwrap.json");
            } else {
                return Err(anyhow::anyhow!(
                    "npm error code ENOENT\nnpm error package-lock.json not found"
                ));
            }
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
        Commands::Get { key } => {
            let config = rnpm_config::Config::load(Some(&current_dir))?;
            if let Some(val) = config.get(&key) {
                println!("{val}");
            } else {
                println!("undefined");
            }
        }
        Commands::Set {
            key,
            value,
            global,
            location,
        } => {
            let target_path = if global || location.as_deref() == Some("global") {
                rnpm_config::find_global_npmrc().unwrap_or_else(|| {
                    rnpm_config::get_default_global_npmrc(&rnpm_config::find_global_prefix())
                })
            } else if location.as_deref() == Some("project") {
                current_dir.join(".npmrc")
            } else if location.as_deref() == Some("user") {
                rnpm_config::get_default_user_npmrc()
            } else if current_dir.join(".npmrc").exists() {
                current_dir.join(".npmrc")
            } else {
                rnpm_config::get_default_user_npmrc()
            };

            rnpm_config::set_config_value_in_file(&target_path, &key, &value)?;
        }
        Commands::Config { action } => match action {
            ConfigAction::Set {
                key,
                value,
                global,
                location,
            } => {
                let target_path = if global || location.as_deref() == Some("global") {
                    rnpm_config::find_global_npmrc().unwrap_or_else(|| {
                        rnpm_config::get_default_global_npmrc(&rnpm_config::find_global_prefix())
                    })
                } else if location.as_deref() == Some("project") {
                    current_dir.join(".npmrc")
                } else if location.as_deref() == Some("user") {
                    rnpm_config::get_default_user_npmrc()
                } else if current_dir.join(".npmrc").exists() {
                    current_dir.join(".npmrc")
                } else {
                    rnpm_config::get_default_user_npmrc()
                };

                rnpm_config::set_config_value_in_file(&target_path, &key, &value)?;
            }
            ConfigAction::Get { key } => {
                let config = rnpm_config::Config::load(Some(&current_dir))?;
                if let Some(val) = config.get(&key) {
                    println!("{val}");
                } else {
                    println!("undefined");
                }
            }
            ConfigAction::Delete {
                key,
                global,
                location,
            } => {
                let target_path = if global || location.as_deref() == Some("global") {
                    rnpm_config::find_global_npmrc().unwrap_or_else(|| {
                        rnpm_config::get_default_global_npmrc(&rnpm_config::find_global_prefix())
                    })
                } else if location.as_deref() == Some("project") {
                    current_dir.join(".npmrc")
                } else if location.as_deref() == Some("user") {
                    rnpm_config::get_default_user_npmrc()
                } else if current_dir.join(".npmrc").exists() {
                    current_dir.join(".npmrc")
                } else {
                    rnpm_config::get_default_user_npmrc()
                };

                let _ = rnpm_config::delete_config_value_from_file(&target_path, &key)?;
            }
            ConfigAction::List { json } => {
                let opts = rnpm_config::ConfigOptions::new().project_dir(&current_dir);
                let detailed = rnpm_config::Config::load_detailed(opts)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&detailed.effective)?);
                } else {
                    print!("{}", detailed.format_text());
                }
            }
        },
        Commands::Link { package } => {
            let global_prefix = rnpm_config::find_global_prefix();
            match package {
                None => {
                    let target_link = rnpm_install::link_package(&current_dir, &global_prefix)?;
                    println!("{} -> {}", target_link.display(), current_dir.display());
                }
                Some(pkg) => {
                    let target_link =
                        rnpm_install::link_package_from_global(&current_dir, &pkg, &global_prefix)?;
                    let global_nm = rnpm_config::find_global_node_modules(&global_prefix);
                    println!(
                        "{} -> {}",
                        target_link.display(),
                        global_nm.join(&pkg).display()
                    );
                }
            }
        }
        Commands::Unlink { package } => {
            let global_prefix = rnpm_config::find_global_prefix();
            match package {
                None => {
                    if let Some(target) =
                        rnpm_install::unlink_package(&current_dir, &global_prefix)?
                    {
                        println!("unlinked {}", target.display());
                    }
                }
                Some(pkg) => {
                    if let Some(target) =
                        rnpm_install::unlink_package_from_consumer(&current_dir, &pkg)?
                    {
                        println!("unlinked {}", target.display());
                    }
                }
            }
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
                let mut cmd = Cli::command();
                cmd.print_help()?;
                println!();
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

fn print_pack_notices(summary: &rnpm_fs::PackSummary) {
    eprintln!("npm notice");
    eprintln!("npm notice package: {}@{}", summary.name, summary.version);
    eprintln!("npm notice Tarball Contents");
    for file in &summary.files {
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
            &summary.integrity[summary.integrity.len().saturating_sub(14)..]
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

#[tokio::main]
async fn main() {
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

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let (filtered_args, _scoped_registries) = extract_scoped_registries(std::env::args_os());
    let filtered_args = normalize_cli_args(filtered_args);

    if let Some((_, msg)) = check_unsupported_cli_invocation(&filtered_args) {
        eprintln!("{msg}");
        std::process::exit(1);
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
                eprintln!("npm error code ERR_UNSUPPORTED_COMMAND");
                eprintln!(
                    "npm error The command '{first_arg}' is not currently implemented in rnpm."
                );
                eprintln!("npm error See docs/compatibility-contract.md for the active compatibility surface.");
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

    if let Err(err) = Box::pin(run_cli(cli, None)).await {
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
