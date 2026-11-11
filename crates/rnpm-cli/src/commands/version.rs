use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct VersionCommandArgs {
    pub newversion: Option<String>,
    pub preid: Option<String>,
    pub message: Option<String>,
    pub allow_same_version: bool,
    pub no_git_tag_version: bool,
    pub no_commit_hooks: bool,
    pub sign_git_tag: bool,
    pub force: bool,
    pub ignore_scripts: bool,
    pub json: bool,
    pub workspace: Vec<String>,
    pub workspaces: bool,
    pub include_workspace_root: bool,
}

pub(crate) async fn run(args: VersionCommandArgs, current_dir: PathBuf) -> Result<()> {
    let config = rnpm_config::Config::load(Some(&current_dir))?;
    let options = crate::version::VersionOptions {
        newversion: args.newversion,
        preid: args.preid,
        message: args.message,
        allow_same_version: args.allow_same_version,
        git_tag_version: !args.no_git_tag_version,
        commit_hooks: !args.no_commit_hooks,
        sign_git_tag: args.sign_git_tag,
        force: args.force,
        ignore_scripts: args.ignore_scripts || config.get_bool("ignore-scripts").unwrap_or(false),
        json: args.json,
    };

    let has_ws = args.workspaces || !args.workspace.is_empty();
    if has_ws {
        let members = crate::select_workspace_members(&current_dir, &args.workspace, args.include_workspace_root)?;
        let names: Vec<String> = members.iter().map(|m| m.name.clone()).collect();
        for member in members {
            println!("{}", member.name);
            let mut member_options = options.clone();
            member_options.git_tag_version = false;
            crate::version::execute_version(&member.path, member_options).await?;
        }
        if options.newversion.is_some() && config.get_bool("workspaces-update") != Some(false) {
            let silent = config.get("loglevel") == Some("silent");
            let start = std::time::Instant::now();
            let mut installer = rnpm_install::Installer::new(rnpm_install::InstallOptions {
                project_dir: current_dir.clone(), workspace: names.clone(),
                unlocked_packages: names.into_iter().collect(),
                // Reification after a version bump must not repeat root install hooks.
                ignore_scripts: true, audit: false, fund: false, silent,
                ..Default::default()
            })?;
            let summary = installer.run().await?;
            if !silent {
                if summary.packages_installed == 0 {
                    println!("\nup to date in {}", crate::format_duration(start.elapsed()));
                } else {
                    println!("\nadded {} package{} in {}", summary.packages_installed,
                        if summary.packages_installed == 1 { "" } else { "s" }, crate::format_duration(start.elapsed()));
                }
            }
        }
    } else {
        crate::version::execute_version(&current_dir, options).await?;
    }

    Ok(())
}
