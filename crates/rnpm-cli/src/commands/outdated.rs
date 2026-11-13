use anyhow::Result;
use std::path::PathBuf;

pub(crate) async fn run(
    opts: crate::outdated::OutdatedOptions,
    current_dir: PathBuf,
) -> Result<()> {
    let code = crate::outdated::run_outdated(&current_dir, &opts).await?;
    if code != 0 {
        return Err(crate::outdated::OutdatedStatus.into());
    }
    Ok(())
}
