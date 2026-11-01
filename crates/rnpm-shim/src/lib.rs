use std::fs;
use std::path::Path;
use anyhow::{Context, Result};
use rnpm_core::manifest::Manifest;

#[cfg(test)]
mod tests;

/// Generates POSIX shell script shim matching docs/platform-fs-contract.md.
pub fn generate_posix_shim(target_rel_from_node_modules: &str) -> String {
    let target = target_rel_from_node_modules.replace('\\', "/");
    format!(
        "#!/bin/sh\n\
        basedir=$(dirname \"$(echo \"$0\" | sed -e 's,\\\\,/,g')\")\n\n\
        case `uname` in\n    \
            *CYGWIN*|*MINGW*|*MSYS*)\n        \
                if command -v cygpath > /dev/null 2>&1; then\n            \
                    basedir=`cygpath -w \"$basedir\"`\n        \
                fi\n    \
            ;;\n\
        esac\n\n\
        if [ -x \"$basedir/node\" ]; then\n  \
          exec \"$basedir/node\" \"$basedir/../{target}\" \"$@\"\n\
        else\n  \
          exec node \"$basedir/../{target}\" \"$@\"\n\
        fi\n"
    )
}

/// Generates Windows Batch (.cmd) wrapper matching docs/platform-fs-contract.md.
pub fn generate_cmd_shim(target_rel_from_node_modules: &str) -> String {
    let target_win = target_rel_from_node_modules.replace('/', "\\");
    format!(
        "@ECHO off\r\n\
        GOTO start\r\n\
        :find_dp0\r\n\
        SET dp0=%~dp0\r\n\
        EXIT /b\r\n\
        :start\r\n\
        SETLOCAL\r\n\
        CALL :find_dp0\r\n\r\n\
        IF EXIST \"%dp0%\\node.exe\" (\r\n  \
          SET \"_prog=%dp0%\\node.exe\"\r\n\
        ) ELSE (\r\n  \
          SET \"_prog=node\"\r\n  \
          SET PATHEXT=%PATHEXT:;.JS;=;%\r\n\
        )\r\n\r\n\
        endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" \"%dp0%\\..\\{target_win}\" %*\r\n"
    )
}

/// Generates PowerShell (.ps1) wrapper matching docs/platform-fs-contract.md.
pub fn generate_ps1_shim(target_rel_from_node_modules: &str) -> String {
    let target = target_rel_from_node_modules.replace('\\', "/");
    format!(
        "#!/usr/bin/env pwsh\r\n\
        $basedir = Split-Path $MyInvocation.MyCommand.Definition -Parent\r\n\r\n\
        $exe = \"\"\r\n\
        if ($PSVersionTable.PSVersion -lt \"6.0\" -or $IsWindows) {{\r\n  \
          # Windows\r\n  \
          if (Test-Path \"$basedir/node.exe\") {{\r\n    \
            $exe = \"$basedir/node.exe\"\r\n  \
          }} else {{\r\n    \
            $exe = \"node\"\r\n  \
          }}\r\n\
        }} else {{\r\n  \
          # Linux/macOS\r\n  \
          if (Test-Path \"$basedir/node\") {{\r\n    \
            $exe = \"$basedir/node\"\r\n  \
          }} else {{\r\n    \
            $exe = \"node\"\r\n  \
          }}\r\n\
        }}\r\n\r\n\
        $ret = 0\r\n\
        if (Test-Path \"$basedir/../{target}\") {{\r\n  \
          & \"$exe\" \"$basedir/../{target}\" $args\r\n  \
          $ret = $LASTEXITCODE\r\n\
        }} else {{\r\n  \
          & \"$exe\" \"$basedir/../{target}\" $args\r\n  \
          $ret = $LASTEXITCODE\r\n\
        }}\r\n\
        exit $ret\r\n"
    )
}

/// Rewrites CRLF shebang to LF to prevent `/usr/bin/env: 'node\r': No such file or directory` on Unix.
pub fn normalize_shebang(file_path: &Path) -> std::io::Result<()> {
    if !file_path.exists() {
        return Ok(());
    }
    let content = fs::read(file_path)?;
    if content.starts_with(b"#!") {
        if let Some(pos) = content.iter().position(|&b| b == b'\n') {
            if pos > 0 && content[pos - 1] == b'\r' {
                let mut new_content = Vec::with_capacity(content.len());
                new_content.extend_from_slice(&content[..pos - 1]);
                new_content.push(b'\n');
                new_content.extend_from_slice(&content[pos + 1..]);
                fs::write(file_path, new_content)?;
            }
        }
    }
    Ok(())
}

/// Creates all three companion shims in `bin_dir`:
/// - `<bin_name>` (POSIX shell script)
/// - `<bin_name>.cmd` (Windows batch)
/// - `<bin_name>.ps1` (PowerShell)
pub fn create_shims(
    bin_dir: &Path,
    bin_name: &str,
    target_rel_from_node_modules: &str,
) -> Result<()> {
    fs::create_dir_all(bin_dir)
        .with_context(|| format!("Failed to create bin dir {}", bin_dir.display()))?;

    // 1. POSIX shell script
    let posix_path = bin_dir.join(bin_name);
    let posix_content = generate_posix_shim(target_rel_from_node_modules);
    fs::write(&posix_path, posix_content)
        .with_context(|| format!("Failed to write POSIX shim {}", posix_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&posix_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&posix_path, perms)?;
    }

    // 2. Windows cmd wrapper
    let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));
    let cmd_content = generate_cmd_shim(target_rel_from_node_modules);
    fs::write(&cmd_path, cmd_content)
        .with_context(|| format!("Failed to write CMD shim {}", cmd_path.display()))?;

    // 3. PowerShell wrapper
    let ps1_path = bin_dir.join(format!("{bin_name}.ps1"));
    let ps1_content = generate_ps1_shim(target_rel_from_node_modules);
    fs::write(&ps1_path, ps1_content)
        .with_context(|| format!("Failed to write PS1 shim {}", ps1_path.display()))?;

    Ok(())
}

/// Creates shims for all binary targets declared in a package's manifest.
pub fn create_package_shims(
    pkg_dir: &Path,
    bin_dir: &Path,
    manifest: &Manifest,
) -> Result<()> {
    for (bin_name, rel_script) in manifest.bin_entries() {
        let script_full_path = pkg_dir.join(&rel_script);
        let _ = normalize_shebang(&script_full_path);

        let node_modules_dir = bin_dir.parent().unwrap_or(bin_dir);
        let target_rel = match script_full_path.strip_prefix(node_modules_dir) {
            Ok(rel) => rel.to_string_lossy().to_string(),
            Err(_) => {
                let pkg_name = manifest.name.as_deref().unwrap_or("unknown");
                format!("{pkg_name}/{rel_script}")
            }
        };

        create_shims(bin_dir, &bin_name, &target_rel)?;
    }
    Ok(())
}
