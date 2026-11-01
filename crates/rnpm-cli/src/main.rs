use std::path::PathBuf;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use rnpm_core::manifest::Manifest;
use rnpm_install::{InstallOptions, Installer};
use rnpm_lifecycle::{execute_lifecycle_script, LifecycleContext};

#[derive(Parser, Debug)]
#[command(name = "rnpm", version, about = "High performance Rust implementation of npm workflows")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Install project dependencies or packages
    #[command(alias = "i")]
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
    Ci {
        /// Custom npm registry URL
        #[arg(long)]
        registry: Option<String>,

        /// Cache directory path
        #[arg(long)]
        cache: Option<PathBuf>,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,
    },

    /// Run arbitrary package scripts
    Run {
        /// Script name declared in package.json
        script: String,

        /// Additional arguments passed to the script
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Skip lifecycle scripts
        #[arg(long)]
        ignore_scripts: bool,
    },

    /// Pack project into a tarball archive
    Pack,

    /// Remove a package from project dependencies
    Uninstall {
        package: String,
    },

    /// Update packages
    Update {
        package: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let current_dir = std::env::current_dir()?;

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
        Commands::Ci { registry, cache, ignore_scripts } => {
            let options = InstallOptions {
                project_dir: current_dir,
                registry_url: registry,
                cache_dir: cache,
                offline: false,
                ignore_scripts,
            };

            let mut installer = Installer::new(options)?;
            let summary = installer.run_ci().await?;

            println!(
                "rnpm: successfully verified and installed {} package(s) from lockfile",
                summary.packages_installed
            );
        }
        Commands::Run { script, args, ignore_scripts } => {
            let manifest_path = current_dir.join("package.json");
            if !manifest_path.exists() {
                eprintln!("rnpm ERR! code ENOENT: package.json not found in {}", current_dir.display());
                std::process::exit(1);
            }

            let manifest = Manifest::from_file(&manifest_path)?;
            let script_cmd = match manifest.scripts.get(&script) {
                Some(cmd) => cmd,
                None => {
                    eprintln!("rnpm ERR! missing script: {script}");
                    std::process::exit(1);
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
                match execute_lifecycle_script(&ctx) {
                    Ok(status) => {
                        if let Some(code) = status.code() {
                            if code != 0 {
                                std::process::exit(code);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("rnpm ERR! lifecycle script failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Pack => {
            eprintln!("rnpm ERR! code ERR_UNSUPPORTED_COMMAND: 'pack' command workflow is scheduled for Phase 5.");
            std::process::exit(1);
        }
        Commands::Uninstall { .. } | Commands::Update { .. } => {
            eprintln!("rnpm ERR! code ERR_UNSUPPORTED_COMMAND: mutation workflow is scheduled for Phase 5.");
            std::process::exit(1);
        }
    }

    Ok(())
}
