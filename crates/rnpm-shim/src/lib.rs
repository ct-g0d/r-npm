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

#[inline]
pub(crate) fn push_escaped_posix_path(out: &mut String, path: &str) {
    out.reserve(path.len());
    for c in path.chars() {
        match c {
            '\\' => out.push('/'),
            '\0' | '\r' | '\n' => {}
            '\"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            _ => out.push(c),
        }
    }
}

/// Escapes a relative path string for use inside double quotes in POSIX shell script.
pub fn escape_posix_path(path: &str) -> String {
    if !path
        .bytes()
        .any(|b| matches!(b, b'\\' | b'\0' | b'\r' | b'\n' | b'\"' | b'$' | b'`'))
    {
        return path.to_string();
    }
    let mut out = String::with_capacity(path.len() + 8);
    push_escaped_posix_path(&mut out, path);
    out
}

#[inline]
pub(crate) fn push_escaped_posix_arg(out: &mut String, arg: &str) {
    let mut all_safe = true;
    let mut non_empty = false;
    for b in arg.bytes() {
        if b == 0 {
            continue;
        }
        non_empty = true;
        if !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':')) {
            all_safe = false;
        }
    }
    if !non_empty {
        out.push_str("''");
        return;
    }
    if all_safe {
        out.reserve(arg.len());
        for b in arg.bytes() {
            if b != 0 {
                out.push(b as char);
            }
        }
    } else {
        out.reserve(arg.len() + 4);
        out.push('\'');
        for c in arg.chars() {
            match c {
                '\0' => {}
                '\'' => out.push_str(r"'\''"),
                _ => out.push(c),
            }
        }
        out.push('\'');
    }
}

/// Escapes a command-line argument for POSIX shell.
pub fn escape_posix_arg(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 4);
    push_escaped_posix_arg(&mut out, arg);
    out
}

#[inline]
pub(crate) fn push_escaped_cmd_path(out: &mut String, path: &str) {
    out.reserve(path.len());
    for c in path.chars() {
        match c {
            '/' => out.push('\\'),
            '\0' | '\r' | '\n' | '\"' => {}
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
}

/// Escapes a relative path string for use inside double quotes in Windows Command Prompt (.cmd).
/// Metacharacters such as % are escaped to %% to prevent unintended batch variable expansion,
/// and quotes/newlines/null bytes are stripped.
pub fn escape_cmd_path(path: &str) -> String {
    if !path
        .bytes()
        .any(|b| matches!(b, b'/' | b'\0' | b'\r' | b'\n' | b'\"' | b'%'))
    {
        return path.to_string();
    }
    let mut out = String::with_capacity(path.len() + 8);
    push_escaped_cmd_path(&mut out, path);
    out
}

#[inline]
pub(crate) fn push_escaped_cmd_arg(out: &mut String, arg: &str) {
    let mut non_empty = false;
    let mut needs_quotes = false;
    for b in arg.bytes() {
        if matches!(b, 0 | b'\r' | b'\n') {
            continue;
        }
        non_empty = true;
        if matches!(
            b,
            b' ' | b'\t'
                | b'\x0B'
                | b'\"'
                | b'&'
                | b'|'
                | b'<'
                | b'>'
                | b'^'
                | b'('
                | b')'
                | b'%'
                | b'!'
                | b','
                | b';'
                | b'='
        ) {
            needs_quotes = true;
        }
    }
    if !non_empty {
        out.push_str("\"\"");
        return;
    }
    if !needs_quotes {
        out.reserve(arg.len());
        for c in arg.chars() {
            if !matches!(c, '\0' | '\r' | '\n') {
                out.push(c);
            }
        }
        return;
    }

    out.reserve(arg.len() + 4);
    out.push('\"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\0' | '\r' | '\n' => {}
            '\\' => backslashes += 1,
            '\"' => {
                for _ in 0..backslashes * 2 {
                    out.push('\\');
                }
                out.push_str("\\\"");
                backslashes = 0;
            }
            '%' => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push_str("%%");
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..backslashes * 2 {
        out.push('\\');
    }
    out.push('\"');
}

/// Escapes an argument for Windows command line according to Win32 CommandLineToArgvW rules
/// and protects against cmd shell metacharacters and injection vectors.
pub fn escape_cmd_arg(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 4);
    push_escaped_cmd_arg(&mut out, arg);
    out
}

#[inline]
pub(crate) fn push_escaped_ps1_path(out: &mut String, path: &str) {
    if !path
        .bytes()
        .any(|b| matches!(b, b'\\' | b'\0' | b'`' | b'\"' | b'$' | b'\r' | b'\n'))
    {
        out.push_str(path);
        return;
    }
    out.reserve(path.len() + 4);
    for c in path.chars() {
        match c {
            '\\' => out.push('/'),
            '\0' => {}
            '`' => out.push_str("``"),
            '\"' => out.push_str("`\""),
            '$' => out.push_str("`$"),
            '\r' => out.push_str("`r"),
            '\n' => out.push_str("`n"),
            _ => out.push(c),
        }
    }
}

/// Escapes a path for PowerShell double quotes.
/// Strips null bytes and escapes backticks, double quotes, dollar signs, and newlines.
pub fn escape_ps1_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 4);
    push_escaped_ps1_path(&mut out, path);
    out
}

#[inline]
pub(crate) fn push_escaped_ps1_arg(out: &mut String, arg: &str) {
    let mut non_empty = false;
    let mut all_safe = true;
    for b in arg.bytes() {
        if b == 0 {
            continue;
        }
        non_empty = true;
        if !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':')) {
            all_safe = false;
        }
    }
    if !non_empty {
        out.push_str("''");
        return;
    }
    if all_safe {
        out.reserve(arg.len());
        for b in arg.bytes() {
            if b != 0 {
                out.push(b as char);
            }
        }
    } else {
        out.reserve(arg.len() + 4);
        out.push('\'');
        for c in arg.chars() {
            match c {
                '\0' => {}
                '\'' => out.push_str("''"),
                _ => out.push(c),
            }
        }
        out.push('\'');
    }
}

/// Escapes an argument for PowerShell.
/// Wraps non-trivial arguments in single quotes with escaped internal single quotes.
pub fn escape_ps1_arg(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 4);
    push_escaped_ps1_arg(&mut out, arg);
    out
}

/// Generates POSIX shell script shim matching docs/platform-fs-contract.md.
pub fn generate_posix_shim(target_rel_from_node_modules: &str) -> String {
    let mut out = String::with_capacity(320 + target_rel_from_node_modules.len());
    out.push_str(
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
           exec \"$basedir/node\"  \"$basedir/../",
    );
    push_escaped_posix_path(&mut out, target_rel_from_node_modules);
    out.push_str(
        "\" \"$@\"\n\
         else \n  \
           exec node  \"$basedir/../",
    );
    push_escaped_posix_path(&mut out, target_rel_from_node_modules);
    out.push_str("\" \"$@\"\nfi\n");
    out
}

/// Generates Windows Batch (.cmd) wrapper matching docs/platform-fs-contract.md.
pub fn generate_cmd_shim(target_rel_from_node_modules: &str) -> String {
    let mut out = String::with_capacity(320 + target_rel_from_node_modules.len());
    out.push_str(
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
         endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\"  \"%dp0%\\..\\",
    );
    push_escaped_cmd_path(&mut out, target_rel_from_node_modules);
    out.push_str("\" %*\r\n");
    out
}

#[inline]
pub(crate) fn escape_ps1_path_cow(path: &str) -> std::borrow::Cow<'_, str> {
    if !path
        .bytes()
        .any(|b| matches!(b, b'\\' | b'\0' | b'`' | b'\"' | b'$' | b'\r' | b'\n'))
    {
        std::borrow::Cow::Borrowed(path)
    } else {
        let mut out = String::with_capacity(path.len() + 4);
        push_escaped_ps1_path(&mut out, path);
        std::borrow::Cow::Owned(out)
    }
}

#[inline]
pub(crate) fn escape_posix_path_cow(path: &str) -> std::borrow::Cow<'_, str> {
    if !path
        .bytes()
        .any(|b| matches!(b, b'\\' | b'\0' | b'\r' | b'\n' | b'\"' | b'$' | b'`'))
    {
        std::borrow::Cow::Borrowed(path)
    } else {
        let mut out = String::with_capacity(path.len() + 8);
        push_escaped_posix_path(&mut out, path);
        std::borrow::Cow::Owned(out)
    }
}

#[inline]
pub(crate) fn escape_cmd_path_cow(path: &str) -> std::borrow::Cow<'_, str> {
    if !path
        .bytes()
        .any(|b| matches!(b, b'/' | b'\0' | b'\r' | b'\n' | b'\"' | b'%'))
    {
        std::borrow::Cow::Borrowed(path)
    } else {
        let mut out = String::with_capacity(path.len() + 8);
        push_escaped_cmd_path(&mut out, path);
        std::borrow::Cow::Owned(out)
    }
}

/// Generates PowerShell (.ps1) wrapper matching docs/platform-fs-contract.md.
pub fn generate_ps1_shim(target_rel_from_node_modules: &str) -> String {
    let ps1_target = escape_ps1_path_cow(target_rel_from_node_modules);
    let mut out = String::with_capacity(560 + ps1_target.len() * 4);
    out.push_str(PS1_HEAD);
    out.push_str(
        "$ret=0\n\
         if (Test-Path \"$basedir/node$exe\") {\n  \
           # Support pipeline input\n  \
           if ($MyInvocation.ExpectingInput) {\n    \
             $input | & \"$basedir/node$exe\"  \"$basedir/../",
    );
    out.push_str(&ps1_target);
    out.push_str("\" $args\n  } else {\n    & \"$basedir/node$exe\"  \"$basedir/../");
    out.push_str(&ps1_target);
    out.push_str(
        "\" $args\n  }\n  \
         $ret=$LASTEXITCODE\n\
         } else {\n  \
           # Support pipeline input\n  \
           if ($MyInvocation.ExpectingInput) {\n    \
             $input | & \"node$exe\"  \"$basedir/../",
    );
    out.push_str(&ps1_target);
    out.push_str("\" $args\n  } else {\n    & \"node$exe\"  \"$basedir/../");
    out.push_str(&ps1_target);
    out.push_str("\" $args\n  }\n  $ret=$LASTEXITCODE\n}\nexit $ret\n");
    out
}
/// Rewrites CRLF shebang to LF to prevent `/usr/bin/env: 'node\r': No such file or directory` on Unix and Git Bash.
/// Also supports files with UTF-8 BOM and clears Windows read-only flags if necessary.
pub fn normalize_shebang(file_path: &Path) -> std::io::Result<()> {
    let _ = shebang::normalize_shebang_file(file_path)
        .map_err(|e| match e {
            crate::error::ShimError::Io { source, .. } => source,
            other => std::io::Error::other(other.to_string()),
        })?;
    Ok(())
}

/// The shebang of `target` as cmd-shim parses it: `None` when the file has
/// no `#!` line (run directly), else `(env vars, program, trimmed args)`.
#[cfg(any(not(unix), test))]
#[allow(dead_code)]
fn cmd_shim_shebang(target: &Path) -> Option<(String, String, String)> {
    use std::io::Read;
    let mut file = fs::File::open(target).ok()?;
    let mut buf = [0u8; 512];
    let n = file.read(&mut buf).ok()?;
    let header = &buf[..n];
    if !header.starts_with(b"#!") && !header.starts_with(b"\xEF\xBB\xBF#!") {
        return None;
    }
    let clean_bytes = if header.starts_with(b"\xEF\xBB\xBF#!") {
        &header[3..]
    } else {
        header
    };
    let line_bytes = if let Some(pos) = clean_bytes.iter().position(|&b| b == b'\n') {
        &clean_bytes[..pos]
    } else if n < 512 {
        clean_bytes
    } else {
        let mut line_vec = clean_bytes.to_vec();
        let mut byte = [0u8; 1];
        while let Ok(1) = file.read(&mut byte) {
            if byte[0] == b'\n' {
                break;
            }
            line_vec.push(byte[0]);
        }
        return parse_cmd_shim_shebang_line(&String::from_utf8_lossy(&line_vec));
    };
    let text = String::from_utf8_lossy(line_bytes);
    parse_cmd_shim_shebang_line(&text)
}

#[cfg(any(not(unix), test))]
fn parse_cmd_shim_shebang_line(text: &str) -> Option<(String, String, String)> {
    let clean_text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let line = clean_text
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
    let sh_target = escape_posix_path_cow(target_rel_from_node_modules);
    let ps1_target = escape_ps1_path_cow(target_rel_from_node_modules);
    let win_target = escape_cmd_path_cow(target_rel_from_node_modules);
    let sh_prog: std::borrow::Cow<'_, str> = if prog.contains('\\') {
        std::borrow::Cow::Owned(prog.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(prog)
    };

    let mut sh = String::with_capacity(
        SH_HEAD.len() + 64 + prog.len() + sh_prog.len() + args.len() * 2 + sh_target.len() * 2,
    );
    sh.push_str(SH_HEAD);
    sh.push_str("if [ -x \"$basedir/");
    sh.push_str(prog);
    sh.push_str("\" ]; then\n  exec \"$basedir/");
    sh.push_str(prog);
    sh.push_str("\" ");
    sh.push_str(args);
    sh.push_str(" \"$basedir/../");
    sh.push_str(&sh_target);
    sh.push_str("\" \"$@\"\nelse \n  exec ");
    sh.push_str(&sh_prog);
    sh.push(' ');
    sh.push_str(args);
    sh.push_str(" \"$basedir/../");
    sh.push_str(&sh_target);
    sh.push_str("\" \"$@\"\nfi\n");

    let mut cmd = String::with_capacity(
        CMD_HEAD.len() + 140 + prog.len() * 3 + args.len() + win_target.len(),
    );
    cmd.push_str(CMD_HEAD);
    cmd.push_str("\r\nIF EXIST \"%dp0%\\");
    cmd.push_str(prog);
    cmd.push_str(".exe\" (\r\n  SET \"_prog=%dp0%\\");
    cmd.push_str(prog);
    cmd.push_str(".exe\"\r\n) ELSE (\r\n  SET \"_prog=");
    cmd.push_str(prog);
    cmd.push_str(
        "\"\r\n  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n)\r\n\r\n\
         endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" ",
    );
    cmd.push_str(args);
    cmd.push_str(" \"%dp0%\\..\\");
    cmd.push_str(&win_target);
    cmd.push_str("\" %*\r\n");

    let mut ps1 = String::with_capacity(
        PS1_HEAD.len() + 340 + prog.len() * 3 + sh_prog.len() * 2 + args.len() * 4 + ps1_target.len() * 4,
    );
    ps1.push_str(PS1_HEAD);
    ps1.push_str("$ret=0\nif (Test-Path \"$basedir/");
    ps1.push_str(prog);
    ps1.push_str(
        "$exe\") {\n  # Support pipeline input\n  if ($MyInvocation.ExpectingInput) {\n    $input | & \"$basedir/",
    );
    ps1.push_str(prog);
    ps1.push_str("$exe\" ");
    ps1.push_str(args);
    ps1.push_str(" \"$basedir/../");
    ps1.push_str(&ps1_target);
    ps1.push_str("\" $args\n  } else {\n    & \"$basedir/");
    ps1.push_str(prog);
    ps1.push_str("$exe\" ");
    ps1.push_str(args);
    ps1.push_str(" \"$basedir/../");
    ps1.push_str(&ps1_target);
    ps1.push_str(
        "\" $args\n  }\n  $ret=$LASTEXITCODE\n} else {\n  # Support pipeline input\n  if ($MyInvocation.ExpectingInput) {\n    $input | & \"",
    );
    ps1.push_str(&sh_prog);
    ps1.push_str("$exe\" ");
    ps1.push_str(args);
    ps1.push_str(" \"$basedir/../");
    ps1.push_str(&ps1_target);
    ps1.push_str("\" $args\n  } else {\n    & \"");
    ps1.push_str(&sh_prog);
    ps1.push_str("$exe\" ");
    ps1.push_str(args);
    ps1.push_str(" \"$basedir/../");
    ps1.push_str(&ps1_target);
    ps1.push_str("\" $args\n  }\n  $ret=$LASTEXITCODE\n}\nexit $ret\n");
    (sh, cmd, ps1)
}

/// Shim trio (sh, cmd, ps1) for a target without a shebang, as cmd-shim writes it.
pub fn generate_direct_shims(target_rel_from_node_modules: &str) -> (String, String, String) {
    let sh_target = escape_posix_path_cow(target_rel_from_node_modules);
    let ps1_target = escape_ps1_path_cow(target_rel_from_node_modules);
    let win_target = escape_cmd_path_cow(target_rel_from_node_modules);

    let mut sh = String::with_capacity(SH_HEAD.len() + 32 + sh_target.len());
    sh.push_str(SH_HEAD);
    sh.push_str("exec \"$basedir/../");
    sh.push_str(&sh_target);
    sh.push_str("\"   \"$@\"\n");

    let mut cmd = String::with_capacity(CMD_HEAD.len() + 24 + win_target.len());
    cmd.push_str(CMD_HEAD);
    cmd.push_str("\"%dp0%\\..\\");
    cmd.push_str(&win_target);
    cmd.push_str("\"   %*\r\n");

    let mut ps1 = String::with_capacity(PS1_HEAD.len() + 140 + ps1_target.len() * 2);
    ps1.push_str(PS1_HEAD);
    ps1.push_str(
        "# Support pipeline input\n\
         if ($MyInvocation.ExpectingInput) {\n  \
           $input | & \"$basedir/../",
    );
    ps1.push_str(&ps1_target);
    ps1.push_str("\"   $args\n} else {\n  & \"$basedir/../");
    ps1.push_str(&ps1_target);
    ps1.push_str("\"   $args\n}\nexit $LASTEXITCODE\n");

    (sh, cmd, ps1)
}

/// Computes the relative POSIX symlink target from a bin directory to the target script.
/// For a local `.bin` directory, the target is `../<target_rel_from_node_modules>`.
/// For a global bin directory, the target is `../lib/node_modules/<target_rel_from_node_modules>`.
pub fn compute_symlink_target(bin_dir: &Path, target_rel_from_node_modules: &str) -> String {
    let is_dot_bin = bin_dir.file_name().is_some_and(|f| f == ".bin");
    let normalized: std::borrow::Cow<'_, str> = if target_rel_from_node_modules.contains('\\') {
        std::borrow::Cow::Owned(target_rel_from_node_modules.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(target_rel_from_node_modules)
    };
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

    let extract_boundary = |remainder: &str| -> usize {
        if let Some(q_idx) = remainder.find('"') {
            let nl_idx = remainder.find(['\r', '\n']).unwrap_or(remainder.len());
            if q_idx < nl_idx {
                return q_idx;
            }
        }
        let nl_idx = remainder.find(['\r', '\n']).unwrap_or(remainder.len());
        let line = &remainder[..nl_idx];
        if let Some(arg_idx) = line.find(" %*").or_else(|| line.find(" \"$@\"")) {
            return arg_idx;
        }
        nl_idx
    };

    let clean_escapes = |s: &str| -> String {
        s.replace("%%", "%")
            .replace("`$", "$")
            .replace("`\"", "\"")
            .replace("``", "`")
    };

    // For POSIX shims, unescape shell escapes (\$, \", \`, \\) before normalizing path separators
    let unescaped_content = if content.contains("#!/bin/sh") || (content.contains("basedir") && !content.contains("$basedir=")) {
        content
            .replace("\\$", "$")
            .replace("\\\"", "\"")
            .replace("\\`", "`")
            .replace("\\\\", "\\")
    } else {
        content.to_string()
    };

    let normalized = unescaped_content.replace('\\', "/");
    // 1. Look for node_modules/...
    if let Some(idx) = normalized.find("node_modules/") {
        let remainder = &normalized[idx..];
        let end = extract_boundary(remainder);
        let target_path = clean_escapes(&remainder[..end]);
        let pkg = extract_package_name(&target_path);
        return Some((target_path, pkg));
    }

    // 2. Fallback: look for relative target like "$basedir/../" or "%dp0%/../"
    for marker in &["$basedir/../", "%dp0%/../", "%dp0%/.."] {
        if let Some(idx) = normalized.find(marker) {
            let remainder = &normalized[idx + marker.len()..];
            let end = extract_boundary(remainder);
            let target_path = format!("../{}", clean_escapes(&remainder[..end]));
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
    check_existing_bin_collision_meta(bin_dir, link_path, rel_target, force).map(|_| ())
}

fn check_existing_bin_collision_meta(
    bin_dir: &Path,
    link_path: &Path,
    rel_target: &str,
    force: bool,
) -> Result<Option<fs::Metadata>> {
    // Fast path: local .bin directory allows clobbering across dependencies without checking metadata.
    // Hoisting this to the very top skips 3 redundant symlink_metadata syscalls per binary!
    if bin_dir.file_name().is_some_and(|f| f == ".bin") {
        return Ok(None);
    }

    let meta = match fs::symlink_metadata(link_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "Failed to check symlink metadata for {}",
                    link_path.display()
                )
            })
        }
    };

    // 1. Directory collision: ALWAYS refuse, even with force (unless it is a reparse point/junction on Windows)
    if meta.is_dir() {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 == 0 {
                anyhow::bail!(
                    "EEXIST: refusing to overwrite existing directory {} with bin link",
                    link_path.display()
                );
            }
        }
        #[cfg(not(windows))]
        anyhow::bail!(
            "EEXIST: refusing to overwrite existing directory {} with bin link",
            link_path.display()
        );
    }

    // 2. Force allows overwriting files and symlinks
    if force {
        return Ok(Some(meta));
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
            return Ok(Some(meta));
        }

        let target_pkg = extract_package_name(rel_target);
        let existing_pkg = extract_package_name(&existing_dest.to_string_lossy());
        if target_pkg.is_some() && target_pkg == existing_pkg {
            return Ok(Some(meta));
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
                    return Ok(Some(meta));
                }

                if target_pkg.is_some() && target_pkg == existing_pkg {
                    return Ok(Some(meta));
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
/// - `<bin_name>` -> pointing to `../<target_rel_from_node_modules>` (or global target),
///   removes any stale existing file/symlink first, and sets executable permissions (0755)
///   on the target script (if it exists). Does NOT write `.cmd` or `.ps1` files on Unix.
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
    create_shims_with_options(
        bin_dir,
        bin_name,
        target_rel_from_node_modules,
        force,
        None,
        false,
    )
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
    create_shims_with_options(
        bin_dir,
        bin_name,
        target_rel_from_node_modules,
        force,
        None,
        false,
    )
}

/// Fast-path shim creator that optionally reuses an already-known script path
/// (merging CRLF shebang normalization + header parsing into one `File::open`)
/// and skips `create_dir_all` when the caller has already created `bin_dir`.
#[cfg(unix)]
pub fn create_shims_with_options(
    bin_dir: &Path,
    bin_name: &str,
    target_rel_from_node_modules: &str,
    force: bool,
    source_target: Option<&Path>,
    bin_dir_precreated: bool,
) -> Result<()> {
    if !bin_dir_precreated {
        fs::create_dir_all(bin_dir)
            .with_context(|| format!("Failed to create bin dir {}", bin_dir.display()))?;
    }

    let rel_target = compute_symlink_target(bin_dir, target_rel_from_node_modules);
    let target_script = source_target
        .map(Path::to_path_buf)
        .unwrap_or_else(|| bin_dir.join(&rel_target));

    if !target_script.exists() {
        return Ok(());
    }

    let _ = normalize_shebang(&target_script);
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(&target_script) {
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        let _ = fs::set_permissions(&target_script, perms);
    }

    let link_path = bin_dir.join(bin_name);
    let existing_meta = check_existing_bin_collision_meta(bin_dir, &link_path, &rel_target, force)?;
    if let Some(meta) = existing_meta.or_else(|| fs::symlink_metadata(&link_path).ok()) {
        if meta.is_dir() {
            anyhow::bail!(
                "EEXIST: refusing to overwrite existing directory {} with bin link {}",
                link_path.display(),
                bin_name
            );
        } else if let Err(e) = fs::remove_file(&link_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e).with_context(|| {
                    format!("Failed to remove stale bin link at {}", link_path.display())
                });
            }
        }
    }

    for stale_ext in [".cmd", ".ps1"] {
        let stale_path = bin_dir.join(format!("{bin_name}{stale_ext}"));
        if let Ok(meta) = fs::symlink_metadata(&stale_path) {
            if meta.permissions().readonly() {
                let mut perms = meta.permissions();
                perms.set_readonly(false);
                let _ = fs::set_permissions(&stale_path, perms);
            }
            let _ = fs::remove_file(&stale_path);
        }
    }

    std::os::unix::fs::symlink(Path::new(&rel_target), &link_path).with_context(|| {
        format!(
            "Failed to create symlink at {} -> {}",
            link_path.display(),
            rel_target
        )
    })?;

    Ok(())
}

/// Fast-path shim creator that optionally normalizes & inspects `source_target`
/// in a single file open, and skips `create_dir_all` / redundant `symlink_metadata` stats.
#[cfg(not(unix))]
pub fn create_shims_with_options(
    bin_dir: &Path,
    bin_name: &str,
    target_rel_from_node_modules: &str,
    force: bool,
    source_target: Option<&Path>,
    bin_dir_precreated: bool,
) -> Result<()> {
    use std::io::{Read, Write};

    let is_dot_bin = bin_dir.file_name().is_some_and(|f| f == ".bin");
    let posix_path = bin_dir.join(bin_name);
    let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));
    let ps1_path = bin_dir.join(format!("{bin_name}.ps1"));

    let (existing_posix_meta, existing_cmd_meta, existing_ps1_meta) = if is_dot_bin {
        (None, None, None)
    } else {
        if !bin_dir_precreated {
            fs::create_dir_all(bin_dir)
                .with_context(|| format!("Failed to create bin dir {}", bin_dir.display()))?;
        }
        let rel_target = compute_symlink_target(bin_dir, target_rel_from_node_modules);
        (
            check_existing_bin_collision_meta(bin_dir, &posix_path, &rel_target, force)?,
            check_existing_bin_collision_meta(bin_dir, &cmd_path, &rel_target, force)?,
            check_existing_bin_collision_meta(bin_dir, &ps1_path, &rel_target, force)?,
        )
    };

    let remove_reparse_or_prepare = |path: &Path, meta: &fs::Metadata| -> Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            let attrs = meta.file_attributes();
            if attrs & 0x400 != 0 {
                if attrs & 0x10 != 0 {
                    fs::remove_dir(path).with_context(|| {
                        format!(
                            "Failed to remove existing directory reparse point {}",
                            path.display()
                        )
                    })?;
                } else {
                    fs::remove_file(path).with_context(|| {
                        format!(
                            "Failed to remove existing file reparse point {}",
                            path.display()
                        )
                    })?;
                }
            } else if meta.is_dir() {
                anyhow::bail!(
                    "EEXIST: refusing to overwrite existing directory {} with bin link",
                    path.display()
                );
            } else if meta.permissions().readonly() {
                let mut perms = meta.permissions();
                perms.set_readonly(false);
                let _ = fs::set_permissions(path, perms);
            }
        }
        #[cfg(not(windows))]
        {
            if meta.file_type().is_symlink() {
                fs::remove_file(path).with_context(|| {
                    format!("Failed to remove existing symlink {}", path.display())
                })?;
            } else if meta.permissions().readonly() {
                let mut perms = meta.permissions();
                perms.set_readonly(false);
                let _ = fs::set_permissions(path, perms);
            }
        }
        Ok(())
    };

    let write_shim_file_dot_bin = |path: &Path, data: &[u8]| -> Result<()> {
        if !force {
            // Optimistic CREATE_NEW: 0 symlink_metadata syscalls on fresh installs.
            match fs::OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut f) => {
                    return f
                        .write_all(data)
                        .with_context(|| format!("Failed to write shim {}", path.display()));
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::AlreadyExists
                        || e.kind() == std::io::ErrorKind::PermissionDenied => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir_all(bin_dir).with_context(|| {
                        format!("Failed to create bin dir {}", bin_dir.display())
                    })?;
                    match fs::OpenOptions::new().write(true).create_new(true).open(path) {
                        Ok(mut f) => {
                            return f.write_all(data).with_context(|| {
                                format!("Failed to write shim {}", path.display())
                            });
                        }
                        Err(e2) if e2.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e2) => {
                            return Err(e2).with_context(|| {
                                format!("Failed to write shim {}", path.display())
                            });
                        }
                    }
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Failed to write shim {}", path.display()));
                }
            }
        }

        match fs::symlink_metadata(path) {
            Ok(meta) => {
                remove_reparse_or_prepare(path, &meta)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !bin_dir_precreated => {
                fs::create_dir_all(bin_dir)
                    .with_context(|| format!("Failed to create bin dir {}", bin_dir.display()))?;
            }
            Err(_) => {}
        }
        fs::write(path, data).with_context(|| format!("Failed to write shim {}", path.display()))
    };

    let write_shim_file_global =
        |path: &Path, known_meta: Option<fs::Metadata>, data: &[u8]| -> Result<()> {
            if let Some(ref meta) = known_meta {
                remove_reparse_or_prepare(path, meta)?;
            }
            fs::write(path, data)
                .with_context(|| format!("Failed to write shim {}", path.display()))
        };

    // Single-open target shebang read (+ optional CRLF normalization).
    let custom = if is_dot_bin {
        let script_path = match source_target {
            Some(p) => Some(p.to_path_buf()),
            None => bin_dir
                .parent()
                .map(|nm| nm.join(target_rel_from_node_modules)),
        };
        if let Some(target_path) = script_path {
            let inspect = if source_target.is_some() {
                shebang::normalize_and_read_shebang_line(&target_path)
                    .unwrap_or(shebang::ShebangRead::NotFile)
            } else {
                // Preserve existing contract: read shebang once without mutating target.
                match fs::File::open(&target_path) {
                    #[cfg(windows)]
                    Ok(mut file) => {
                        let mut buf = [0u8; 512];
                        let n = file.read(&mut buf).unwrap_or(0);
                        let header = &buf[..n];
                        if !header.starts_with(b"#!") && !header.starts_with(b"\xEF\xBB\xBF#!") {
                            shebang::ShebangRead::NoShebang
                        } else {
                            let clean_bytes = if header.starts_with(b"\xEF\xBB\xBF#!") {
                                &header[3..]
                            } else {
                                header
                            };
                            if let Some(pos) = clean_bytes.iter().position(|&b| b == b'\n') {
                                shebang::ShebangRead::Line(
                                    String::from_utf8_lossy(&clean_bytes[..pos]).into_owned(),
                                )
                            } else if n < 512 {
                                shebang::ShebangRead::Line(
                                    String::from_utf8_lossy(clean_bytes).into_owned(),
                                )
                            } else {
                                let mut line_vec = clean_bytes.to_vec();
                                let mut byte = [0u8; 1];
                                while let Ok(1) = file.read(&mut byte) {
                                    if byte[0] == b'\n' {
                                        break;
                                    }
                                    line_vec.push(byte[0]);
                                }
                                shebang::ShebangRead::Line(
                                    String::from_utf8_lossy(&line_vec).into_owned(),
                                )
                            }
                        }
                    }
                    #[cfg(not(windows))]
                    Ok(mut file) if file.metadata().map(|m| m.is_file()).unwrap_or(false) => {
                        let mut buf = [0u8; 512];
                        let n = file.read(&mut buf).unwrap_or(0);
                        let header = &buf[..n];
                        if !header.starts_with(b"#!") && !header.starts_with(b"\xEF\xBB\xBF#!") {
                            shebang::ShebangRead::NoShebang
                        } else {
                            let clean_bytes = if header.starts_with(b"\xEF\xBB\xBF#!") {
                                &header[3..]
                            } else {
                                header
                            };
                            if let Some(pos) = clean_bytes.iter().position(|&b| b == b'\n') {
                                shebang::ShebangRead::Line(
                                    String::from_utf8_lossy(&clean_bytes[..pos]).into_owned(),
                                )
                            } else if n < 512 {
                                shebang::ShebangRead::Line(
                                    String::from_utf8_lossy(clean_bytes).into_owned(),
                                )
                            } else {
                                let mut line_vec = clean_bytes.to_vec();
                                let mut byte = [0u8; 1];
                                while let Ok(1) = file.read(&mut byte) {
                                    if byte[0] == b'\n' {
                                        break;
                                    }
                                    line_vec.push(byte[0]);
                                }
                                shebang::ShebangRead::Line(
                                    String::from_utf8_lossy(&line_vec).into_owned(),
                                )
                            }
                        }
                    }
                    _ => shebang::ShebangRead::NotFile,
                }
            };

            match inspect {
                shebang::ShebangRead::NotFile => None,
                shebang::ShebangRead::NoShebang => {
                    Some(generate_direct_shims(target_rel_from_node_modules))
                }
                shebang::ShebangRead::Line(line) => {
                    match parse_cmd_shim_shebang_line(&line) {
                        None => Some(generate_direct_shims(target_rel_from_node_modules)),
                        Some((vars, prog, args))
                            if vars.is_empty() && (prog != "node" || !args.is_empty()) =>
                        {
                            Some(generate_program_shims(
                                target_rel_from_node_modules,
                                &prog,
                                &args,
                            ))
                        }
                        Some(_) => None,
                    }
                }
            }
        } else {
            None
        }
    } else {
        if let Some(src) = source_target {
            let _ = normalize_shebang(src);
        }
        None
    };

    if is_dot_bin {
        if let Some((sh, cmd, ps1)) = custom {
            write_shim_file_dot_bin(&posix_path, sh.as_bytes())?;
            write_shim_file_dot_bin(&cmd_path, cmd.as_bytes())?;
            write_shim_file_dot_bin(&ps1_path, ps1.as_bytes())?;
        } else {
            let posix_content = generate_posix_shim(target_rel_from_node_modules);
            write_shim_file_dot_bin(&posix_path, posix_content.as_bytes())?;
            let cmd_content = generate_cmd_shim(target_rel_from_node_modules);
            write_shim_file_dot_bin(&cmd_path, cmd_content.as_bytes())?;
            let ps1_content = generate_ps1_shim(target_rel_from_node_modules);
            write_shim_file_dot_bin(&ps1_path, ps1_content.as_bytes())?;
        }
    } else {
        let rel_path = if cfg!(windows) {
            format!("node_modules/{target_rel_from_node_modules}")
        } else {
            format!("../lib/node_modules/{target_rel_from_node_modules}")
        };
        let content = generator::generate_shim_content(&rel_path, None);
        write_shim_file_global(&posix_path, existing_posix_meta, content.sh.as_bytes())?;
        write_shim_file_global(&cmd_path, existing_cmd_meta, content.cmd.as_bytes())?;
        write_shim_file_global(&ps1_path, existing_ps1_meta, content.ps1.as_bytes())?;
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
    let entries = manifest.bin_entries();
    if entries.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(bin_dir)
        .with_context(|| format!("Failed to create bin dir {}", bin_dir.display()))?;
    let node_modules_dir = bin_dir.parent().unwrap_or(bin_dir);
    for (bin_name, rel_script) in entries {
        let script_full_path = pkg_dir.join(&rel_script);
        let target_rel = match script_full_path.strip_prefix(node_modules_dir) {
            Ok(rel) => rel.to_string_lossy().to_string(),
            Err(_) => {
                let pkg_name = manifest.name.as_deref().unwrap_or("unknown");
                format!("{pkg_name}/{rel_script}")
            }
        };

        create_shims_with_options(
            bin_dir,
            &bin_name,
            &target_rel,
            force,
            Some(&script_full_path),
            true,
        )?;
    }
    Ok(())
}
