use anyhow::Result;
use std::path::{Path, PathBuf};

/// Normalize package specification with optional subpackages according to npm's `splitPackageNames`.
pub fn split_package_names(pkg: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for part in pkg.split('/') {
        if part.is_empty() {
            continue;
        }
        if let Some(last) = parts.last_mut() {
            if last.starts_with('@') && !last.contains('/') {
                last.push('/');
                last.push_str(part);
                continue;
            }
        }
        parts.push(part.to_string());
    }
    let mut joined = parts.join("/node_modules/");
    while joined.contains("/node_modules/node_modules") {
        joined = joined.replace("/node_modules/node_modules", "/node_modules");
    }
    joined
}

/// Tokenize an editor command string into binary and arguments, handling single and double quotes.
pub fn parse_editor_command(editor_cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = editor_cmd.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            ' ' | '\t' if !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(cur);
                    cur = String::new();
                }
            }
            _ => {
                cur.push(c);
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Determine configured editor by precedence:
/// 1. CLI flag `--editor`
/// 2. `npm_config_editor` env var
/// 3. `.npmrc` / rnpm config `editor`
/// 4. `VISUAL` env var
/// 5. `EDITOR` env var
/// 6. Default (%SYSTEMROOT%\notepad.exe or vi)
pub fn resolve_editor_command(cli_editor: Option<String>, current_dir: &Path) -> Result<String> {
    if let Some(ed) = cli_editor {
        if !ed.trim().is_empty() {
            return Ok(ed);
        }
    }
    if let Ok(ed) = std::env::var("npm_config_editor") {
        if !ed.trim().is_empty() {
            return Ok(ed);
        }
    }
    if let Ok(config) = rnpm_config::Config::load(Some(current_dir)) {
        if let Some(ed) = config.get("editor") {
            if !ed.trim().is_empty() {
                return Ok(ed.to_string());
            }
        }
    }
    if let Ok(ed) = std::env::var("VISUAL") {
        if !ed.trim().is_empty() {
            return Ok(ed);
        }
    }
    if let Ok(ed) = std::env::var("EDITOR") {
        if !ed.trim().is_empty() {
            return Ok(ed);
        }
    }

    #[cfg(windows)]
    {
        if let Ok(sysroot) = std::env::var("SYSTEMROOT") {
            let notepad = format!("{sysroot}\\notepad.exe");
            if Path::new(&notepad).exists() {
                return Ok(notepad);
            }
        }
        Ok("notepad.exe".to_string())
    }

    #[cfg(not(windows))]
    {
        Ok("vi".to_string())
    }
}

/// Execute `npm edit <pkg>[/<subpkg>...]`.
pub async fn run(
    package: Option<String>,
    editor_opt: Option<String>,
    current_dir: PathBuf,
) -> Result<()> {
    let package = package.ok_or_else(|| {
        anyhow::anyhow!(
            "npm error code EUSAGE\n\
             npm error\n\
             npm error Edit an installed package\n\
             npm error\n\
             npm error Usage:\n\
             npm error npm edit <pkg>[/<subpkg>...]\n\
             npm error\n\
             npm error Options:\n\
             npm error [--editor <editor>]\n\
             npm error\n\
             npm error   --editor\n\
             npm error     The command to run for `npm edit` and `npm config edit`.\n\
             npm error\n\
             npm error\n\
             npm error Run \"npm help edit\" for more info"
        )
    })?;

    let subpath = split_package_names(&package);
    let dir = current_dir.join("node_modules").join(&subpath);

    // Verify package directory exists (equivalent to npm's `await lstat(dir)`)
    if std::fs::symlink_metadata(&dir).is_err() {
        let errno_str = if cfg!(windows) { "errno -4058\n" } else { "errno -2\n" };
        return Err(anyhow::anyhow!(
            "npm error code ENOENT\n\
             npm error syscall lstat\n\
             npm error path {}\n\
             npm error {}\
             npm error enoent ENOENT: no such file or directory, lstat '{}'\n\
             npm error enoent This is related to npm not being able to find a file.",
            dir.display(),
            errno_str.trim_end(),
            dir.display(),
        ));
    }

    let editor_str = resolve_editor_command(editor_opt, &current_dir)?;
    let mut tokens = parse_editor_command(&editor_str);
    if tokens.is_empty() {
        return Err(anyhow::anyhow!(
            "npm error code ENOENT\nnpm error no editor configured"
        ));
    }

    let bin = tokens.remove(0);
    let mut spawn_args = tokens;
    // Target directory is appended as the final argument
    spawn_args.push(dir.to_string_lossy().to_string());

    // Spawn editor in current_dir (matching npm's process cwd)
    let status = std::process::Command::new(&bin)
        .args(&spawn_args)
        .current_dir(&current_dir)
        .status()
        .map_err(|e| {
            anyhow::anyhow!("npm error failed to spawn editor '{}': {e}", bin)
        })?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        return Err(anyhow::anyhow!(
            "npm error editor process exited with code: {code}"
        ));
    }

    // Post-editor behavior: run rebuild on the edited package directory
    let rebuild_opts = super::rebuild::RebuildOptions {
        packages: vec![dir.to_string_lossy().to_string()],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
    };
    super::rebuild::run(rebuild_opts, current_dir).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_package_names() {
        assert_eq!(split_package_names("pkg"), "pkg");
        assert_eq!(split_package_names("@scope/pkg"), "@scope/pkg");
        assert_eq!(split_package_names("pkg/sub"), "pkg/node_modules/sub");
        assert_eq!(split_package_names("@scope/pkg/sub"), "@scope/pkg/node_modules/sub");
        assert_eq!(
            split_package_names("@s1/p1/@s2/p2"),
            "@s1/p1/node_modules/@s2/p2"
        );
        assert_eq!(
            split_package_names("pkg/node_modules/sub"),
            "pkg/node_modules/sub"
        );
    }

    #[test]
    fn test_parse_editor_command_quoting() {
        let cmd = r#"node "C:\My Path\script.js" --arg 'foo bar'"#;
        let tokens = parse_editor_command(cmd);
        assert_eq!(tokens, vec![
            "node".to_string(),
            r#"C:\My Path\script.js"#.to_string(),
            "--arg".to_string(),
            "foo bar".to_string()
        ]);
    }
}
