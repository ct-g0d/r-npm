use std::path::PathBuf;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use rnpm_install::{InstallOptions, Installer};

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
    },

    /// Install dependencies directly from package-lock.json
    Ci {
        #[arg(long)]
        registry: Option<String>,

        #[arg(long)]
        cache: Option<PathBuf>,
    },

    /// Run arbitrary package scripts
    Run {
        script: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
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

    match cli.command {
        Commands::Install { registry, cache, offline, .. } => {
            let options = InstallOptions {
                project_dir: std::env::current_dir()?,
                registry_url: registry,
                cache_dir: cache,
                offline,
            };

            let mut installer = Installer::new(options)?;
            let summary = installer.run().await?;

            println!(
                "rnpm: successfully installed {} package(s) (cache hits: {}, misses: {})",
                summary.packages_installed, summary.cache_hits, summary.cache_misses
            );
        }
        Commands::Ci { registry, cache } => {
            let options = InstallOptions {
                project_dir: std::env::current_dir()?,
                registry_url: registry,
                cache_dir: cache,
                offline: false,
            };

            let mut installer = Installer::new(options)?;
            let summary = installer.run().await?;

            println!(
                "rnpm: successfully verified and installed {} package(s)",
                summary.packages_installed
            );
        }
        Commands::Run { script, .. } => {
            eprintln!("rnpm ERR! code ERR_NOT_IMPLEMENTED_YET");
            eprintln!("rnpm ERR! 'run' lifecycle execution is scheduled for Phase 4.");
            std::process::exit(1);
        }
        Commands::Pack => {
            eprintln!("rnpm ERR! code ERR_NOT_IMPLEMENTED_YET");
            eprintln!("rnpm ERR! 'pack' workflow is scheduled for Phase 4.");
            std::process::exit(1);
        }
        Commands::Uninstall { .. } | Commands::Update { .. } => {
            eprintln!("rnpm ERR! code ERR_NOT_IMPLEMENTED_YET");
            eprintln!("rnpm ERR! Mutation workflows are scheduled for Phase 4.");
            std::process::exit(1);
        }
    }

    Ok(())
}
