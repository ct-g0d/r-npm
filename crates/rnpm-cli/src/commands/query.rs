use anyhow::Result;
use std::path::PathBuf;

pub(crate) async fn run(
    selector: Option<String>,
    package_lock_only: bool,
    registry: Option<String>,
    current_dir: PathBuf,
) -> Result<()> {
    let opts = crate::query::QueryOptions {
        selector,
        package_lock_only,
        registry,
    };
    let code = crate::query::run_query(&current_dir, &opts).await?;
    if code != 0 {
        return Err(anyhow::Error::from(rnpm_lifecycle::ScriptExitError {
            exit_code: code,
            message: "query finished with non-zero exit code".to_string(),
        }));
    }
    Ok(())
}
