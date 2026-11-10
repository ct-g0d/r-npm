use anyhow::Result;
use std::path::PathBuf;

pub(crate) async fn run(
    packages: Vec<String>,
    all: bool,
    json: bool,
    long: bool,
    parseable: bool,
    registry: Option<String>,
    current_dir: PathBuf,
) -> Result<()> {
    let opts = crate::outdated::OutdatedOptions {
        packages,
        all,
        json,
        long,
        parseable,
        registry,
    };
    let code = crate::outdated::run_outdated(&current_dir, &opts).await?;
    if code != 0 {
        return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
            exit_code: code,
            message: "outdated dependencies found".to_string(),
        }));
    }
    Ok(())
}
