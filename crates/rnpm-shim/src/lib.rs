#![allow(clippy::permissions_set_readonly_false)]

use anyhow::{Context, Result};
use rnpm_core::manifest::Manifest;
use std::fs;
use std::path::Path;

pub mod error;
pub mod generator;
pub mod path;
pub mod shebang;

#[cfg(test)]
mod tests;

/// Escapes a relative path string for use inside double quotes in POSIX shell script.
pub fn escape_posix_path(path: &str) -> String {
    let forward = path.replace('\\', "/");
    let sanitized = forward.replace(['\0', '\r', '\n'], "");
    sanitized
        .replace('\\', "\\\\")
        .replace('\"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

/// Escapes a command-line argument for POSIX shell.
pub fn escape_posix_arg(arg: &str) -> String {
    let sanitized = arg.replace('\0', "");
    if sanitized.is_empty() {
        return "''".to_string();
    }
    if sanitized.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/' || c == ':'
    }) {
        sanitized
    } else {
        format!("'{}'", sanitized.replace('\'', r"'\''"))
    }
}

/// Escapes a relative path string for use inside double quotes in Windows Command Prompt (.cmd).
/// Metacharacters such as % are escaped to %% to prevent unintended batch variable expansion,
/// and quotes/newlines/null bytes are stripped.
pub fn escape_cmd_path(path: &str) -> String {
    let win = path.replace('/', "\\");
    let sanitized = win.replace(['\0', '\r', '\n', '\"'], "");
    sanitized.replace('%', "%%")
}

/// Escapes an argument for Windows command line according to Win32 CommandLineToArgvW rules
/// and protects against cmd shell metacharacters and injection vectors.
pub fn escape_cmd_arg(arg: &str) -> String {
    let sanitized = arg.replace(['\0', '\r', '\n'], "");
    if sanitized.is_empty() {
        return "\"\"".to_string();
    }

    let needs_quotes = sanitized.chars().any(|c| {
        c == ' '
            || c == '\t'
            || c == '\n'
            || c == '\r'
            || c == '\x0B'
            || c == '\"'
            || c == '&'
            || c == '|'
            || c == '<'
            || c == '>'
            || c == '^'
            || c == '('
            || c == ')'
            || c == '%'
            || c == '!'
            || c == ','
            || c == ';'
            || c == '='
    });
    if !needs_quotes {
        return sanitized;
    }

    let mut result = String::with_capacity(sanitized.len() + 2);
    result.push('\"');

    let mut backslashes = 0;
    for c in sanitized.chars() {
        if c == '\\' {
            backslashes += 1;
        } else if c == '\"' {
            for _ in 0..backslashes * 2 {
                result.push('\\');
            }
            result.push('\\');
            result.push('\"');
            backslashes = 0;
        } else if c == '%' {
            for _ in 0..backslashes {
                result.push('\\');
            }
            backslashes = 0;
            result.push('%');
            result.push('%');
        } else {
            for _ in 0..backslashes {
                result.push('\\');
            }
            backslashes = 0;
            result.push(c);
        }
    }
    for _ in 0..backslashes * 2 {
        result.push('\\');
    }
    result.push('\"');
    result
}

/// Escapes a path for PowerShell double quotes.
/// Strips null bytes and escapes backticks, double quotes, dollar signs, and newlines.
pub fn escape_ps1_path(path: &str) -> String {
    let forward = path.replace('\\', "/");
    let sanitized = forward.replace('\0', "");
    sanitized
        .replace('`', "``")
        .replace('\"', "`\"")
        .replace('$', "`$")
        .replace('\r', "`r")
        .replace('\n', "`n")
}

/// Escapes an argument for PowerShell.
/// Wraps non-trivial arguments in single quotes with escaped internal single quotes.
pub fn escape_ps1_arg(arg: &str) -> String {
    let sanitized = arg.replace('\0', "");
    if sanitized.is_empty() {
        return "''".to_string();
    }
    if sanitized.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/' || c == ':'
    }) {
        sanitized
    } else {
        format!("'{}'", sanitized.replace('\'', "''"))
    }
}

/// Generates POSIX shell script shim matching docs/platform-fs-contract.md.
pub fn generate_posix_shim(target_rel_from_node_modules: &str) -> String {
    let target = escape_posix_path(target_rel_from_node_modules);
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
          exec \"$basedir/node\"  \"$basedir/../{target}\" \"$@\"\n\
        else \n  \
          exec node  \"$basedir/../{target}\" \"$@\"\n\
        fi\n"
    )
}

/// Generates Windows Batch (.cmd) wrapper matching docs/platform-fs-contract.md.
pub fn generate_cmd_shim(target_rel_from_node_modules: &str) -> String {
    let target_win = escape_cmd_path(target_rel_from_node_modules);
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
        endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\"  \"%dp0%\\..\\{target_win}\" %*\r\n"
    )
}

/// Generates PowerShell (.ps1) wrapper matching docs/platform-fs-contract.md.
pub fn generate_ps1_shim(target_rel_from_node_modules: &str) -> String {
    let rel = format!("../{target_rel_from_node_modules}");
    generator::generate_shim_content(&rel, None)
        .ps1
        .replace("\r\n", "\n")
}
/// Rewrites CRLF shebang to LF to prevent `/usr/bin/env: 'node\r': No such file or directory` on Unix and Git Bash.
/// Also supports files with UTF-8 BOM and clears Windows read-only flags if necessary.
pub fn normalize_shebang(file_path: &Path) -> std::io::Result<()> {
    if !file_path.exists() {
        return Ok(());
    }
    let content = fs::read(file_path)?;
    let (offset, is_shebang) = if content.starts_with(b"\xEF\xBB\xBF#!") {
        (3, true)
    } else if content.starts_with(b"#!") {
        (0, true)
    } else {
        (0, false)
    };

    if !is_shebang {
        return Ok(());
    }

    if let Some(newline_pos) = content[offset..].iter().position(|&b| b == b'\n') {
        let abs_pos = offset + newline_pos;
        if abs_pos > offset && content[abs_pos - 1] == b'\r' {
            let mut new_content = Vec::with_capacity(content.len());
            new_content.extend_from_slice(&content[..abs_pos - 1]);
            new_content.push(b'\n');
            new_content.extend_from_slice(&content[abs_pos + 1..]);

            // Clear read-only attribute if set (common on Windows)
            if let Ok(metadata) = fs::metadata(file_path) {
                let mut perms = metadata.permissions();
                if perms.readonly() {
                    perms.set_readonly(false);
                    let _ = fs::set_permissions(file_path, perms);
                }
            }

            fs::write(file_path, new_content)?;
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

    let is_dot_bin = bin_dir.file_name().is_some_and(|f| f == ".bin");
    if is_dot_bin {
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
    } else {
        // Global bin directory (Windows: %APPDATA%/npm, Unix: /usr/local/bin)
        let rel_path = if cfg!(windows) {
            format!("node_modules/{target_rel_from_node_modules}")
        } else {
            format!("../lib/node_modules/{target_rel_from_node_modules}")
        };
        let content = generator::generate_shim_content(&rel_path, None);

        let posix_path = bin_dir.join(bin_name);
        fs::write(&posix_path, content.sh)
            .with_context(|| format!("Failed to write POSIX shim {}", posix_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&posix_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&posix_path, perms)?;
        }

        let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));
        fs::write(&cmd_path, content.cmd)
            .with_context(|| format!("Failed to write CMD shim {}", cmd_path.display()))?;

        let ps1_path = bin_dir.join(format!("{bin_name}.ps1"));
        fs::write(&ps1_path, content.ps1)
            .with_context(|| format!("Failed to write PS1 shim {}", ps1_path.display()))?;
    }

    Ok(())
}

/// Creates shims for all binary targets declared in a package's manifest.
pub fn create_package_shims(pkg_dir: &Path, bin_dir: &Path, manifest: &Manifest) -> Result<()> {
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
