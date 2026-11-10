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
    let options = crate::version::VersionOptions {
        newversion: args.newversion,
        preid: args.preid,
        message: args.message,
        allow_same_version: args.allow_same_version,
        git_tag_version: !args.no_git_tag_version,
        commit_hooks: !args.no_commit_hooks,
        sign_git_tag: args.sign_git_tag,
        force: args.force,
        ignore_scripts: args.ignore_scripts,
        json: args.json,
    };

    let has_ws = args.workspaces || !args.workspace.is_empty();
    if has_ws {
        let members = crate::select_workspace_members(&current_dir, &args.workspace, args.include_workspace_root)?;
        for member in members {
            println!("{}", member.name);
            crate::version::execute_version(&member.path, options.clone()).await?;
        }
    } else {
        crate::version::execute_version(&current_dir, options).await?;
    }

    Ok(())
}
