use anyhow::{Error, Result};
use std::path::PathBuf;

pub(crate) async fn run(
    args: Vec<String>,
    json: bool,
    registry: Option<String>,
    current_dir: PathBuf,
) -> Result<()> {
    let opts = crate::view::ViewOptions {
        args,
        json,
        registry,
    };
    let code = crate::view::run_view(&current_dir, &opts).await?;
    if code != 0 {
        return Err(Error::from(rnpm_lifecycle::ScriptExitError {
            exit_code: code,
            message: "view finished with non-zero exit code".to_string(),
        }));
    }
    Ok(())
}
