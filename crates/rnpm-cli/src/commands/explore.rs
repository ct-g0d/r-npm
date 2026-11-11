use anyhow::Result;
use rnpm_lifecycle::ScriptExitError;
use std::path::{Path, PathBuf};

/// Build the PATH environment variable with node_modules/.bin directories prepended.
pub fn build_explore_path(pkg_dir: &Path, current_dir: &Path) -> String {
    let mut bin_dirs = Vec::new();

    // 1. Package's own nested node_modules/.bin
    let pkg_bin = pkg_dir.join("node_modules").join(".bin");
    if pkg_bin.is_dir() {
        bin_dirs.push(pkg_bin);
    }

    // 2. Ancestor node_modules/.bin up to current_dir
    let mut cur = pkg_dir.parent();
    while let Some(parent) = cur {
        let parent_bin = parent.join(".bin");
        if parent_bin.is_dir() && !bin_dirs.contains(&parent_bin) {
            bin_dirs.push(parent_bin);
        }
        let nm_bin = parent.join("node_modules").join(".bin");
        if nm_bin.is_dir() && !bin_dirs.contains(&nm_bin) {
            bin_dirs.push(nm_bin);
        }
        if parent == current_dir {
            break;
        }
        cur = parent.parent();
    }

    let root_bin = current_dir.join("node_modules").join(".bin");
    if root_bin.is_dir() && !bin_dirs.contains(&root_bin) {
        bin_dirs.push(root_bin);
    }

    let bin_strs: Vec<String> = bin_dirs
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let path_sep = if cfg!(windows) { ";" } else { ":" };
    let existing_path = std::env::var("PATH").unwrap_or_default();

    if bin_strs.is_empty() {
        existing_path
    } else if existing_path.is_empty() {
        bin_strs.join(path_sep)
    } else {
        format!("{}{path_sep}{existing_path}", bin_strs.join(path_sep))
    }
}

/// Execute `npm explore <pkg> [ -- <command>]`.
pub async fn run(
    package: Option<String>,
    args: Vec<String>,
    shell_opt: Option<String>,
    current_dir: PathBuf,
) -> Result<()> {
    let pkgname = package.ok_or_else(|| {
        anyhow::anyhow!(
            "npm error code EUSAGE\n\
             npm error\n\
             npm error Browse an installed package\n\
             npm error\n\
             npm error Usage:\n\
             npm error npm explore <pkg> [ -- <command>]\n\
             npm error\n\
             npm error Options:\n\
             npm error [--shell <shell>]\n\
             npm error\n\
             npm error   --shell\n\
             npm error     The shell to run for the `npm explore` command.\n\
             npm error\n\
             npm error\n\
             npm error Run \"npm help explore\" for more info"
        )
    })?;

    if pkgname == "." || pkgname.is_empty() {
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\n\
             npm error\n\
             npm error Browse an installed package\n\
             npm error\n\
             npm error Usage:\n\
             npm error npm explore <pkg> [ -- <command>]"
        ));
    }

    let pkg_dir = current_dir.join("node_modules").join(&pkgname);
    let manifest_path = pkg_dir.join("package.json");

    if !manifest_path.is_file() {
        let errno_str = if cfg!(windows) { "errno -4058\n" } else { "errno -2\n" };
        return Err(anyhow::anyhow!(
            "npm error explore It doesn't look like {pkgname} is installed.\n\
             npm error code ENOENT\n\
             npm error syscall open\n\
             npm error path {}\n\
             npm error {}\
             npm error enoent Could not read package.json: Error: ENOENT: no such file or directory, open '{}'\n\
             npm error enoent This is related to npm not being able to find a file.",
            manifest_path.display(),
            errno_str.trim_end(),
            manifest_path.display(),
        ));
    }

    let manifest_content = std::fs::read_to_string(&manifest_path).unwrap_or_default();
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest_content).unwrap_or(serde_json::Value::Null);

    let pkg_real_name = manifest_json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(&pkgname)
        .to_string();
    let pkg_version = manifest_json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let new_path = build_explore_path(&pkg_dir, &current_dir);

    // Determine command to run
    let is_interactive = args.is_empty();
    let (program, cmd_args, script_str, full_cmd_display) = if is_interactive {
        println!("\nExploring {}\nType 'exit' or ^D when finished\n", pkg_dir.display());

        #[cfg(windows)]
        {
            let sh = shell_opt
                .or_else(|| std::env::var("ComSpec").ok())
                .unwrap_or_else(|| "cmd.exe".into());
            let display = format!("{sh} /K");
            (sh, vec!["/K".to_string()], String::new(), display)
        }

        #[cfg(not(windows))]
        {
            let sh = shell_opt
                .or_else(|| std::env::var("SHELL").ok())
                .unwrap_or_else(|| "/bin/sh".into());
            let display = sh.clone();
            (sh, Vec::new(), String::new(), display)
        }
    } else {
        let script = args.join(" ").trim().to_string();

        #[cfg(windows)]
        {
            let sh = std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into());
            let display = format!("{sh} /d /s /c {script}");
            (sh, vec!["/d".into(), "/s".into(), "/c".into(), script.clone()], script, display)
        }

        #[cfg(not(windows))]
        {
            let sh = "/bin/sh".to_string();
            let display = format!("{sh} -c {script}");
            (sh, vec!["-c".into(), script.clone()], script, display)
        }
    };

    let status = std::process::Command::new(&program)
        .args(&cmd_args)
        .current_dir(&pkg_dir)
        .env("PATH", &new_path)
        .env("npm_lifecycle_event", "_explore")
        .env("npm_lifecycle_script", &script_str)
        .env("npm_package_name", &pkg_real_name)
        .env("npm_package_version", &pkg_version)
        .env("npm_package_json", manifest_path.to_string_lossy().to_string())
        .env("npm_command", "explore")
        .status()
        .map_err(|e| anyhow::anyhow!("npm error failed to run explore command: {e}"))?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        let msg = format!(
            "npm error code {code}\n\
             npm error path {}\n\
             npm error command failed\n\
             npm error command {full_cmd_display}",
            pkg_dir.display(),
        );
        return Err(anyhow::Error::from(ScriptExitError {
            exit_code: code,
            message: msg,
        }));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_explore_path() {
        let tmp = tempfile::tempdir().unwrap();
        let current_dir = tmp.path().to_path_buf();
        let pkg_dir = current_dir.join("node_modules").join("test-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let path = build_explore_path(&pkg_dir, &current_dir);
        assert!(!path.is_empty());
    }
}
