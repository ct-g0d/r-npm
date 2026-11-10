use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct PublishArgs {
    pub target: PathBuf,
    pub tag: String,
    pub access: Option<String>,
    pub dry_run: bool,
    pub otp: Option<String>,
    pub provenance: bool,
    pub registry: Option<String>,
    pub ignore_scripts: bool,
    pub json: bool,
}

pub(crate) async fn run(args: PublishArgs, current_dir: PathBuf) -> Result<()> {
    crate::execute_publish(
        current_dir,
        args.target,
        args.tag,
        args.access,
        args.dry_run,
        args.otp,
        args.provenance,
        args.registry,
        args.ignore_scripts,
        args.json,
    )
    .await
}
