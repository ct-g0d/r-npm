use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct SbomCommandArgs {
    pub sbom_format: String,
    pub sbom_type: String,
    pub package_lock_only: bool,
    pub omit: Vec<String>,
}

pub(crate) async fn run(args: SbomCommandArgs, current_dir: PathBuf) -> Result<()> {
    let options = crate::sbom::SbomOptions {
        format: args.sbom_format,
        sbom_type: args.sbom_type,
        package_lock_only: args.package_lock_only,
        omit: args.omit,
    };
    crate::sbom::run_sbom(&current_dir, options).await?;
    Ok(())
}
