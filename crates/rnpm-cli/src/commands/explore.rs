use anyhow::Result;
use rnpm_lifecycle::ScriptExitError;
use std::path::{Path, PathBuf};

/// Normalize package target string to emulate npm's `join(this.npm.dir, join('/', pkgname))`
/// and reject escaping or matching the node_modules root itself.
pub fn normalize_explore_target(node_modules_dir: &Path, pkgname: &str) -> Option<PathBuf> {
    let trimmed = pkgname.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Split components by both '/' and '\' to match path.join('/', pkgname) semantics
    let mut stack: Vec<&str> = Vec::new();
    for part in trimmed.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            stack.pop();
        } else {
            stack.push(part);
        }
    }

    // If stack is empty, target resolved to the node_modules root itself (e.g. "..", ".", "/")
    if stack.is_empty() {
        return None;
    }

    let mut target = node_modules_dir.to_path_buf();
    for part in stack {
        target.push(part);
    }
    Some(target)
}

/// Build PATH matching `@npmcli/run-script/lib/set-path.js` and `rnpm-lifecycle`:
/// Unconditionally walk up all directory ancestors from `pkg_dir` to root,
/// prepending each ancestor's `node_modules/.bin` directory.
pub fn build_explore_path(pkg_dir: &Path) -> String {
    let mut bins: Vec<PathBuf> = pkg_dir
        .ancestors()
        .map(|dir| dir.join("node_modules").join(".bin"))
        .collect();

    let inherited = std::env::var_os("PATH")
        .or_else(|| std::env::var_os("Path"))
        .unwrap_or_default();
    bins.extend(std::env::split_paths(&inherited));

    std::env::join_paths(bins)
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn usage_error() -> anyhow::Error {
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
}

/// Execute `npm explore <pkg> [ -- <command>]`.
pub async fn run(
    package: Option<String>,
    args: Vec<String>,
    shell_opt: Option<String>,
    current_dir: PathBuf,
) -> Result<()> {
    let pkgname = package.ok_or_else(usage_error)?;

    let node_modules_dir = current_dir.join("node_modules");
    let pkg_dir = match normalize_explore_target(&node_modules_dir, &pkgname) {
        Some(dir) => dir,
        None => return Err(usage_error()),
    };

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

    let new_path = build_explore_path(&pkg_dir);

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
        .env("Path", &new_path)
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
    fn test_normalize_explore_target_rejections() {
        let nm = PathBuf::from("C:/test/project/node_modules");
        assert_eq!(normalize_explore_target(&nm, ""), None);
        assert_eq!(normalize_explore_target(&nm, "."), None);
        assert_eq!(normalize_explore_target(&nm, ".."), None);
        assert_eq!(normalize_explore_target(&nm, "../.."), None);
        assert_eq!(normalize_explore_target(&nm, "/"), None);
    }

    #[test]
    fn test_normalize_explore_target_valid() {
        let nm = PathBuf::from("C:/test/project/node_modules");
        assert_eq!(
            normalize_explore_target(&nm, "foo"),
            Some(nm.join("foo"))
        );
        assert_eq!(
            normalize_explore_target(&nm, "@scope/pkg"),
            Some(nm.join("@scope").join("pkg"))
        );
        assert_eq!(
            normalize_explore_target(&nm, "../foo"),
            Some(nm.join("foo"))
        );
        assert_eq!(
            normalize_explore_target(&nm, "foo/../bar"),
            Some(nm.join("bar"))
        );
    }

    #[test]
    fn test_build_explore_path_ancestors() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("node_modules").join("a").join("node_modules").join("b");
        let path = build_explore_path(&pkg_dir);
        assert!(!path.is_empty());
        // Verify both package's node_modules/.bin and ancestor node_modules/.bin are present
        let sep = if cfg!(windows) { ';' } else { ':' };
        let entries: Vec<&str> = path.split(sep).collect();
        assert!(entries.iter().any(|e| e.contains("b") && e.contains(".bin")));
        assert!(entries.iter().any(|e| e.contains("a") && e.contains(".bin")));
    }
}
