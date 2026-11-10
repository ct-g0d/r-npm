use anyhow::{anyhow, Result};
use std::path::PathBuf;

pub(crate) fn run(current_dir: PathBuf) -> Result<()> {
    let src = current_dir.join("package-lock.json");
    let dst = current_dir.join("npm-shrinkwrap.json");
    if dst.exists() {
        eprintln!("npm notice npm-shrinkwrap.json up to date");
    } else if src.exists() {
        if std::fs::rename(&src, &dst).is_err() {
            std::fs::copy(&src, &dst)?;
            std::fs::remove_file(&src)?;
        }
        eprintln!("npm notice package-lock.json has been renamed to npm-shrinkwrap.json");
    } else if current_dir.join("package.json").exists() {
        let lock = rnpm_lockfile::LockfileV3::new("project", Some("1.0.0".to_string()));
        let json = serde_json::to_string_pretty(&lock)?;
        std::fs::write(&dst, json)?;
        eprintln!("npm notice created a lockfile as npm-shrinkwrap.json with version 3");
    } else {
        return Err(anyhow!(
            "npm error code ENOENT\nnpm error package.json not found"
        ));
    }
    Ok(())
}
