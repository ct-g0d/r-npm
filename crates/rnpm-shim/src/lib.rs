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

/// The shebang of `target` as cmd-shim parses it: `None` when the file has
/// no `#!` line (run directly), else `(env vars, program, trimmed args)`.
#[cfg(any(not(unix), test))]
#[allow(dead_code)]
fn cmd_shim_shebang(target: &Path) -> Option<(String, String, String)> {
    let data = fs::read(target).ok()?;
    let text = String::from_utf8_lossy(&data);
    let line = text
        .trim()
        .split('\n')
        .next()
        .unwrap_or("")
        .trim_end_matches('\r');
    let mut rest = line.strip_prefix("#!")?.trim_start();
    let mut vars = String::new();
    // /^#!\s*(?:\/usr\/bin\/env\s+(?:-S\s+)?((?:[^ \t=]+=[^ \t=]+\s+)*))?([^ \t]+)(.*)$/
    if let Some(after) = rest.strip_prefix("/usr/bin/env") {
        if after.starts_with(char::is_whitespace) {
            let mut after = after.trim_start();
            if let Some(s) = after.strip_prefix("-S") {
                if s.starts_with(char::is_whitespace) {
                    after = s.trim_start();
                }
            }
            loop {
                let end = after.find(char::is_whitespace).unwrap_or(after.len());
                let token = &after[..end];
                let is_var = token
                    .split_once('=')
                    .is_some_and(|(k, v)| !k.is_empty() && !v.is_empty() && !v.contains('='));
                if !is_var || end == after.len() {
                    break;
                }
                let next = after[end..].trim_start();
                vars.push_str(&after[..after.len() - next.len()]);
                after = next;
            }
            rest = after;
        }
    }
    let end = rest.find([' ', '\t']).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some((
        vars,
        rest[..end].to_string(),
        rest[end..].trim().to_string(),
    ))
}

const SH_HEAD: &str = concat!(
    "#!/bin/sh\n",
    r#"basedir=$(dirname "$(echo "$0" | sed -e 's,\\,/,g')")"#,
    "\n\ncase `uname` in\n",
    "    *CYGWIN*|*MINGW*|*MSYS*)\n",
    "        if command -v cygpath > /dev/null 2>&1; then\n",
    "            basedir=`cygpath -w \"$basedir\"`\n",
    "        fi\n",
    "    ;;\n",
    "esac\n\n",
);

const CMD_HEAD: &str =
    "@ECHO off\r\nGOTO start\r\n:find_dp0\r\nSET dp0=%~dp0\r\nEXIT /b\r\n:start\r\nSETLOCAL\r\nCALL :find_dp0\r\n";

const PS1_HEAD: &str = concat!(
    "#!/usr/bin/env pwsh\n",
    "$basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent\n\n",
    "$exe=\"\"\n",
    "if ($PSVersionTable.PSVersion -lt \"6.0\" -or $IsWindows) {\n",
    "  # Fix case when both the Windows and Linux builds of Node\n",
    "  # are installed in the same directory\n",
    "  $exe=\".exe\"\n",
    "}\n",
);

/// Shim trio for a target whose shebang names `prog` (other than plain node),
/// as cmd-shim writes it: the program and its args are copied verbatim.
pub fn generate_program_shims(
    target_rel_from_node_modules: &str,
    prog: &str,
    args: &str,
) -> (String, String, String) {
    let sh_target = format!(
        "\"$basedir/../{}\"",
        escape_posix_path(target_rel_from_node_modules)
    );
    let ps1_target = format!(
        "\"$basedir/../{}\"",
        escape_ps1_path(target_rel_from_node_modules)
    );
    let win_target = escape_cmd_path(&target_rel_from_node_modules.replace('/', "\\"));
    let sh_prog = prog.replace('\\', "/");
    let sh = format!(
        "{SH_HEAD}if [ -x \"$basedir/{prog}\" ]; then\n  exec \"$basedir/{prog}\" {args} {sh_target} \"$@\"\nelse \n  exec {sh_prog} {args} {sh_target} \"$@\"\nfi\n"
    );
    let cmd = format!(
        "{CMD_HEAD}\r\nIF EXIST \"%dp0%\\{prog}.exe\" (\r\n  SET \"_prog=%dp0%\\{prog}.exe\"\r\n) ELSE (\r\n  SET \"_prog={prog}\"\r\n  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n)\r\n\r\nendLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" {args} \"%dp0%\\..\\{win_target}\" %*\r\n"
    );
    let long = format!("\"$basedir/{prog}$exe\"");
    let short = format!("\"{sh_prog}$exe\"");
    let ps1 = format!(
        "{PS1_HEAD}$ret=0\nif (Test-Path {long}) {{\n  # Support pipeline input\n  if ($MyInvocation.ExpectingInput) {{\n    $input | & {long} {args} {ps1_target} $args\n  }} else {{\n    & {long} {args} {ps1_target} $args\n  }}\n  $ret=$LASTEXITCODE\n}} else {{\n  # Support pipeline input\n  if ($MyInvocation.ExpectingInput) {{\n    $input | & {short} {args} {ps1_target} $args\n  }} else {{\n    & {short} {args} {ps1_target} $args\n  }}\n  $ret=$LASTEXITCODE\n}}\nexit $ret\n"
    );
    (sh, cmd, ps1)
}

/// Shim trio (sh, cmd, ps1) for a target without a shebang, as cmd-shim writes it.
pub fn generate_direct_shims(target_rel_from_node_modules: &str) -> (String, String, String) {
    let sh_target = format!(
        "\"$basedir/../{}\"",
        escape_posix_path(target_rel_from_node_modules)
    );
    let ps1_target = format!(
        "\"$basedir/../{}\"",
        escape_ps1_path(target_rel_from_node_modules)
    );
    let win_target = escape_cmd_path(&target_rel_from_node_modules.replace('/', "\\"));
    let sh = format!("{SH_HEAD}exec {sh_target}   \"$@\"\n");
    let cmd = format!("{CMD_HEAD}\"%dp0%\\..\\{win_target}\"   %*\r\n");
    let ps1 = [
        PS1_HEAD,
        "# Support pipeline input\n",
        "if ($MyInvocation.ExpectingInput) {\n",
        &format!("  $input | & {ps1_target}   $args\n"),
        "} else {\n",
        &format!("  & {ps1_target}   $args\n"),
        "}\n",
        "exit $LASTEXITCODE\n",
    ]
    .concat();
    (sh, cmd, ps1)
}

/// Computes the relative POSIX symlink target from a bin directory to the target script.
/// For a local `.bin` directory, the target is `../<target_rel_from_node_modules>`.
/// For a global bin directory, the target is `../lib/node_modules/<target_rel_from_node_modules>`.
pub fn compute_symlink_target(bin_dir: &Path, target_rel_from_node_modules: &str) -> String {
    let is_dot_bin = bin_dir.file_name().is_some_and(|f| f == ".bin");
    let normalized = target_rel_from_node_modules.replace('\\', "/");
    let clean = normalized.strip_prefix("./").unwrap_or(&normalized);
    if is_dot_bin {
        format!("../{clean}")
    } else {
        format!("../lib/node_modules/{clean}")
    }
}

/// Extracts the npm package name or scoped package name from a relative or absolute target path.
/// Examples:
/// - `../lib/node_modules/typescript/bin/tsc.js` -> `Some("typescript")`
/// - `../lib/node_modules/@scope/pkg/bin/tool.js` -> `Some("@scope/pkg")`
/// - `typescript/bin/tsc.js` -> `Some("typescript")`
/// - `@scope/pkg/bin/tool.js` -> `Some("@scope/pkg")`
/// - `../typescript/bin/tsc.js` -> `Some("typescript")`
/// - `/usr/bin/bash` -> `None`
pub fn extract_package_name(path_str: &str) -> Option<String> {
    let normalized = path_str.replace('\\', "/");
    let trimmed = normalized.trim();

    if let Some(idx) = trimmed.find("node_modules/") {
        let remainder = &trimmed[idx + "node_modules/".len()..];
        let parts: Vec<&str> = remainder.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return None;
        }
        if parts[0].starts_with('@') {
            if parts.len() >= 2 {
                return Some(format!("{}/{}", parts[0], parts[1]));
            }
            return None;
        }
        return Some(parts[0].to_string());
    }

    // Absolute path without node_modules/ is not an npm package path
    if trimmed.starts_with('/') || (trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':') {
        return None;
    }

    // Strip relative prefixes
    let mut s = trimmed;
    while let Some(rest) = s.strip_prefix("../") {
        s = rest;
    }
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }

    let parts: Vec<&str> = s.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    if parts[0].starts_with('@') {
        if parts.len() >= 2 {
            Some(format!("{}/{}", parts[0], parts[1]))
        } else {
            None
        }
    } else {
        Some(parts[0].to_string())
    }
}

/// Extracts the target path and package name from an existing rnpm or npm (cmd-shim) generated shim file.
/// Returns `None` if the file does not appear to be an rnpm/npm generated shim.
pub fn parse_shim_target_and_pkg(content: &str) -> Option<(String, Option<String>)> {
    let is_shim = content.contains("%dp0%")
        || content.contains("%~dp0")
        || content.contains(":find_dp0")
        || content.contains("$basedir")
        || content.contains("basedir=")
        || content.contains("$PSScriptRoot")
        || content.contains("Created by npm")
        || content.contains("cmd-shim")
        || content.contains("rnpm");
    if !is_shim {
        return None;
    }

    let normalized = content.replace('\\', "/");
    // 1. Look for node_modules/...
    if let Some(idx) = normalized.find("node_modules/") {
        let remainder = &normalized[idx..];
        let end = remainder
            .find(|c: char| {
                c == '"'
                    || c == '\''
                    || c == ' '
                    || c == '\r'
                    || c == '\n'
                    || c == '$'
                    || c == '%'
                    || c == '`'
            })
            .unwrap_or(remainder.len());
        let target_path = remainder[..end].to_string();
        let pkg = extract_package_name(&target_path);
        return Some((target_path, pkg));
    }

    // 2. Fallback: look for relative target like "$basedir/../" or "%dp0%/../"
    for marker in &["$basedir/../", "%dp0%/../", "%dp0%/.."] {
        if let Some(idx) = normalized.find(marker) {
            let remainder = &normalized[idx + marker.len()..];
            let end = remainder
                .find(|c: char| {
                    c == '"'
                        || c == '\''
                        || c == ' '
                        || c == '\r'
                        || c == '\n'
                        || c == '$'
                        || c == '%'
                        || c == '`'
                })
                .unwrap_or(remainder.len());
            let target_path = format!("../{}", &remainder[..end]);
            let pkg = extract_package_name(&target_path);
            return Some((target_path, pkg));
        }
    }

    None
}

/// Checks for collisions with an existing file, directory, or symlink at `link_path`
/// according to npm's `bin-links` rules:
/// - If `link_path` does not exist: returns `Ok(())`.
/// - If `link_path` is a directory: ALWAYS refuses with `EEXIST` (even if `force` is true).
/// - If `force` is true: returns `Ok(())`.
/// - If `bin_dir` is a local `.bin` directory: returns `Ok(())` (local `.bin` allows clobbering across dependencies).
/// - In a global bin directory (not `.bin` and `force == false`):
///   - If `link_path` is a symlink:
///     - If the symlink points to the same target or to the same package, returns `Ok(())`.
///     - If the symlink points to a foreign package or unrelated target, refuses with `EEXIST`.
///   - If `link_path` is a regular file:
///     - If the file is an existing rnpm/npm-generated shim pointing to the same package, returns `Ok(())`.
///     - If the file is an existing rnpm/npm-generated shim pointing to a foreign package, refuses with `EEXIST`.
///     - If the file is an unrelated regular file, refuses with `EEXIST` (cannot overwrite without force).
pub fn check_existing_bin_collision(
    bin_dir: &Path,
    link_path: &Path,
    rel_target: &str,
    force: bool,
) -> Result<()> {
    let meta = match fs::symlink_metadata(link_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "Failed to check symlink metadata for {}",
                    link_path.display()
                )
            })
        }
    };

    // 1. Directory collision: ALWAYS refuse, even with force
    if meta.is_dir() {
        anyhow::bail!(
            "EEXIST: refusing to overwrite existing directory {} with bin link",
            link_path.display()
        );
    }

    // 2. Force allows overwriting files and symlinks
    if force {
        return Ok(());
    }

    // 3. Local .bin allows overwriting stale files/symlinks
    let is_dot_bin = bin_dir.file_name().is_some_and(|f| f == ".bin");
    if is_dot_bin {
        return Ok(());
    }

    // 4. Global bin directory collision checks (force == false)
    if meta.file_type().is_symlink() {
        let existing_dest = match fs::read_link(link_path) {
            Ok(dest) => dest,
            Err(_) => {
                anyhow::bail!(
                    "EEXIST: file already exists: refusing to overwrite existing symlink at {}",
                    link_path.display()
                );
            }
        };

        if existing_dest == Path::new(rel_target) {
            return Ok(());
        }

        let target_pkg = extract_package_name(rel_target);
        let existing_pkg = extract_package_name(&existing_dest.to_string_lossy());
        if target_pkg.is_some() && target_pkg == existing_pkg {
            return Ok(());
        }

        anyhow::bail!(
            "EEXIST: file already exists: refusing to overwrite foreign bin link at {} pointing to {}",
            link_path.display(),
            existing_dest.display()
        );
    }

    if meta.is_file() {
        if let Ok(content) = fs::read_to_string(link_path) {
            if let Some((existing_target, existing_pkg)) = parse_shim_target_and_pkg(&content) {
                let target_pkg = extract_package_name(rel_target);
                let norm_rel_target = rel_target.replace('\\', "/");
                let clean_rel_target = norm_rel_target
                    .strip_prefix("../lib/")
                    .unwrap_or(&norm_rel_target);

                if existing_target == rel_target || existing_target == clean_rel_target {
                    return Ok(());
                }

                if target_pkg.is_some() && target_pkg == existing_pkg {
                    return Ok(());
                }

                if let Some(ref foreign_pkg) = existing_pkg {
                    anyhow::bail!(
                        "EEXIST: file already exists: refusing to overwrite foreign bin link at {} pointing to {} (package {})",
                        link_path.display(),
                        existing_target,
                        foreign_pkg
                    );
                } else {
                    anyhow::bail!(
                        "EEXIST: file already exists: refusing to overwrite foreign bin link at {} pointing to {}",
                        link_path.display(),
                        existing_target
                    );
                }
            }
        }

        anyhow::bail!(
            "EEXIST: file already exists: refusing to overwrite existing file at {}",
            link_path.display()
        );
    }

    anyhow::bail!(
        "EEXIST: file already exists at {}",
        link_path.display()
    );
}

/// Creates bin links/shims in `bin_dir`.
///
/// On Unix (`#[cfg(unix)]`): creates a relative POSIX symlink matching npm's `bin-links`:
/// - `<bin_name>` -> pointing to `../<target_rel_from_node_modules>` (or global target)
/// removes any stale existing file/symlink first, and sets executable permissions (0755)
/// on the target script (if it exists). Does NOT write `.cmd` or `.ps1` files on Unix.
#[cfg(unix)]
pub fn create_shims(
    bin_dir: &Path,
    bin_name: &str,
    target_rel_from_node_modules: &str,
) -> Result<()> {
    create_shims_with_force(bin_dir, bin_name, target_rel_from_node_modules, false)
}

/// Creates bin links/shims in `bin_dir`, with optional `force` override.
#[cfg(unix)]
pub fn create_shims_with_force(
    bin_dir: &Path,
    bin_name: &str,
    target_rel_from_node_modules: &str,
    force: bool,
) -> Result<()> {
    fs::create_dir_all(bin_dir)
        .with_context(|| format!("Failed to create bin dir {}", bin_dir.display()))?;

    let rel_target = compute_symlink_target(bin_dir, target_rel_from_node_modules);
    let target_script = bin_dir.join(&rel_target);

    // Skip missing bin script targets gracefully (matching npm bin-links)
    if !target_script.exists() {
        return Ok(());
    }

    // Normalize CRLF in shebang lines and ensure executable mode 0o755 before linking
    let _ = normalize_shebang(&target_script);
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(&target_script) {
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        let _ = fs::set_permissions(&target_script, perms);
    }

    let link_path = bin_dir.join(bin_name);

    // Follow npm's bin-links collision & force rules
    check_existing_bin_collision(bin_dir, &link_path, &rel_target, force)?;

    // If check passed and file/symlink exists, remove it before linking
    if let Ok(meta) = fs::symlink_metadata(&link_path) {
        if meta.is_dir() {
            anyhow::bail!(
                "EEXIST: refusing to overwrite existing directory {} with bin link {}",
                link_path.display(),
                bin_name
            );
        } else {
            let res = fs::remove_file(&link_path);
            if let Err(e) = res {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e).with_context(|| {
                        format!("Failed to remove stale bin link at {}", link_path.display())
                    });
                }
            }
        }
    }

    // Clean up any stale .cmd or .ps1 shims if present
    let _ = fs::remove_file(bin_dir.join(format!("{bin_name}.cmd")));
    let _ = fs::remove_file(bin_dir.join(format!("{bin_name}.ps1")));

    std::os::unix::fs::symlink(Path::new(&rel_target), &link_path).with_context(|| {
        format!(
            "Failed to create symlink at {} -> {}",
            link_path.display(),
            rel_target
        )
    })?;

    Ok(())
}

/// Creates all three companion shims in `bin_dir`:
/// - `<bin_name>` (POSIX shell script)
/// - `<bin_name>.cmd` (Windows batch)
/// - `<bin_name>.ps1` (PowerShell)
#[cfg(not(unix))]
pub fn create_shims(
    bin_dir: &Path,
    bin_name: &str,
    target_rel_from_node_modules: &str,
) -> Result<()> {
    create_shims_with_force(bin_dir, bin_name, target_rel_from_node_modules, false)
}

/// Creates all three companion shims in `bin_dir`, with optional `force` override.
#[cfg(not(unix))]
pub fn create_shims_with_force(
    bin_dir: &Path,
    bin_name: &str,
    target_rel_from_node_modules: &str,
    force: bool,
) -> Result<()> {
    fs::create_dir_all(bin_dir)
        .with_context(|| format!("Failed to create bin dir {}", bin_dir.display()))?;

    let is_dot_bin = bin_dir.file_name().is_some_and(|f| f == ".bin");
    let posix_path = bin_dir.join(bin_name);
    let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));
    let ps1_path = bin_dir.join(format!("{bin_name}.ps1"));
    let rel_target = compute_symlink_target(bin_dir, target_rel_from_node_modules);

    // Follow npm's bin-links collision & force rules for ALL THREE companion shims on Windows
    check_existing_bin_collision(bin_dir, &posix_path, &rel_target, force)?;
    check_existing_bin_collision(bin_dir, &cmd_path, &rel_target, force)?;
    check_existing_bin_collision(bin_dir, &ps1_path, &rel_target, force)?;

    let write_shim_file = |path: &Path, data: &[u8]| -> Result<()> {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                fs::remove_file(path)
                    .with_context(|| format!("Failed to remove existing symlink {}", path.display()))?;
            } else if meta.permissions().readonly() {
                let mut perms = meta.permissions();
                perms.set_readonly(false);
                let _ = fs::set_permissions(path, perms);
            }
        }
        fs::write(path, data)
            .with_context(|| format!("Failed to write shim {}", path.display()))
    };

    let target = bin_dir
        .parent()
        .map(|nm| nm.join(target_rel_from_node_modules))
        .filter(|t| is_dot_bin && t.is_file());
    // Plain `node` (and env-var shebangs, not modelled here) keep the node shim.
    let custom = target
        .map(|t| cmd_shim_shebang(&t))
        .and_then(|shebang| match shebang {
            None => Some(generate_direct_shims(target_rel_from_node_modules)),
            Some((vars, prog, args)) if vars.is_empty() && (prog != "node" || !args.is_empty()) => {
                Some(generate_program_shims(
                    target_rel_from_node_modules,
                    &prog,
                    &args,
                ))
            }
            Some(_) => None,
        });
    if let Some((sh, cmd, ps1)) = custom {
        write_shim_file(&posix_path, sh.as_bytes())?;
        write_shim_file(&cmd_path, cmd.as_bytes())?;
        write_shim_file(&ps1_path, ps1.as_bytes())?;
    } else if is_dot_bin {
        // 1. POSIX shell script
        let posix_content = generate_posix_shim(target_rel_from_node_modules);
        write_shim_file(&posix_path, posix_content.as_bytes())?;

        // 2. Windows cmd wrapper
        let cmd_content = generate_cmd_shim(target_rel_from_node_modules);
        write_shim_file(&cmd_path, cmd_content.as_bytes())?;

        // 3. PowerShell wrapper
        let ps1_content = generate_ps1_shim(target_rel_from_node_modules);
        write_shim_file(&ps1_path, ps1_content.as_bytes())?;
    } else {
        // Global bin directory (Windows: %APPDATA%/npm, Unix: /usr/local/bin)
        let rel_path = if cfg!(windows) {
            format!("node_modules/{target_rel_from_node_modules}")
        } else {
            format!("../lib/node_modules/{target_rel_from_node_modules}")
        };
        let content = generator::generate_shim_content(&rel_path, None);

        write_shim_file(&posix_path, content.sh.as_bytes())?;
        write_shim_file(&cmd_path, content.cmd.as_bytes())?;
        write_shim_file(&ps1_path, content.ps1.as_bytes())?;
    }

    Ok(())
}

/// Creates shims for all binary targets declared in a package's manifest.
pub fn create_package_shims(pkg_dir: &Path, bin_dir: &Path, manifest: &Manifest) -> Result<()> {
    create_package_shims_with_force(pkg_dir, bin_dir, manifest, false)
}

/// Creates shims for all binary targets declared in a package's manifest with optional force override.
pub fn create_package_shims_with_force(
    pkg_dir: &Path,
    bin_dir: &Path,
    manifest: &Manifest,
    force: bool,
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

        create_shims_with_force(bin_dir, &bin_name, &target_rel, force)?;
    }
    Ok(())
}
