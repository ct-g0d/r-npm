use crate::error::ShimError;
use crate::path::compute_relative_path;
use crate::shebang::{normalize_and_read_shebang_info, ShebangInfo};
use crate::{
    escape_cmd_path_cow, escape_posix_path_cow, escape_ps1_path_cow, push_escaped_cmd_arg,
    push_escaped_posix_arg, push_escaped_ps1_arg,
};
use rnpm_core::manifest::{Manifest, PackageBin};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The string contents of the executable shim trio (sh, cmd, ps1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimContent {
    pub sh: String,
    pub cmd: String,
    pub ps1: String,
}

/// Information about a generated executable shim trio on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimTrio {
    pub name: String,
    pub sh_path: PathBuf,
    pub cmd_path: PathBuf,
    pub ps1_path: PathBuf,
    pub target_rel_path: String,
    pub content: ShimContent,
}

#[cfg(unix)]
fn set_executable_mode(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable_mode(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

fn prepare_shim_destination(path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            let attrs = meta.file_attributes();
            if attrs & 0x400 != 0 {
                if attrs & 0x10 != 0 {
                    let _ = std::fs::remove_dir(path);
                } else {
                    let _ = std::fs::remove_file(path);
                }
                return;
            }
        }
        #[cfg(not(windows))]
        {
            if meta.file_type().is_symlink() {
                let _ = std::fs::remove_file(path);
                return;
            }
        }
        #[cfg(windows)]
        if meta.permissions().readonly() {
            let mut perms = meta.permissions();
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
        #[cfg(unix)]
        if meta.permissions().readonly() {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() | 0o200);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
}

/// Generates the content of the executable shim trio for a target script.
///
/// - `rel_path`: Relative path from `node_modules/.bin/` to the target script with forward slashes (e.g. `../my-pkg/bin/cli.js`).
/// - `shebang`: Optional parsed shebang information. Defaults to `node` if `None`.
pub fn generate_shim_content(rel_path: &str, shebang: Option<&ShebangInfo>) -> ShimContent {
    let default_shebang = ShebangInfo::default();
    let info = shebang.unwrap_or(&default_shebang);
    let prog = &info.program;

    // 1. Unix POSIX Shell Script (<name>)
    // Match npm's cmd-shim output exactly, including blank lines, indentation,
    // and the double-space argument separator when no shebang args exist.
    let sh_rel_path = escape_posix_path_cow(rel_path);
    let mut sh = String::with_capacity(
        310 + prog.len() * 2 + sh_rel_path.len() * 2 + info.args.len() * 8,
    );
    sh.push_str(
        "#!/bin/sh\n\
basedir=$(dirname \"$(echo \"$0\" | sed -e 's,\\,/,g')\")\n\
\n\
case `uname` in\n\
    *CYGWIN*|*MINGW*|*MSYS*)\n\
        if command -v cygpath > /dev/null 2>&1; then\n\
            basedir=`cygpath -w \"$basedir\"`\n\
        fi\n\
    ;;\n\
esac\n\
\n\
if [ -x \"$basedir/",
    );
    sh.push_str(prog);
    sh.push_str("\" ]; then\n  exec \"$basedir/");
    sh.push_str(prog);
    sh.push_str("\" ");
    if info.args.is_empty() {
        sh.push_str("  ");
    } else {
        for arg in &info.args {
            push_escaped_posix_arg(&mut sh, arg);
            sh.push(' ');
        }
    }
    sh.push_str("\"$basedir/");
    sh.push_str(&sh_rel_path);
    sh.push_str("\" \"$@\"\nelse \n  exec ");
    sh.push_str(prog);
    sh.push(' ');
    if info.args.is_empty() {
        sh.push_str("  ");
    } else {
        for arg in &info.args {
            push_escaped_posix_arg(&mut sh, arg);
            sh.push(' ');
        }
    }
    sh.push_str("\"$basedir/");
    sh.push_str(&sh_rel_path);
    sh.push_str("\" \"$@\"\nfi\n");

    // 2. Windows Batch Wrapper (<name>.cmd)
    let win_rel_path = escape_cmd_path_cow(rel_path);
    let mut cmd = String::with_capacity(
        320 + prog.len() * 3 + win_rel_path.len() + info.args.len() * 8,
    );
    cmd.push_str(
        "@ECHO off\r\n\
GOTO start\r\n\
:find_dp0\r\n\
SET dp0=%~dp0\r\n\
EXIT /b\r\n\
:start\r\n\
SETLOCAL\r\n\
CALL :find_dp0\r\n\
\r\n\
IF EXIST \"%dp0%\\",
    );
    cmd.push_str(prog);
    cmd.push_str(".exe\" (\r\n  SET \"_prog=%dp0%\\");
    cmd.push_str(prog);
    cmd.push_str(".exe\"\r\n) ELSE (\r\n  SET \"_prog=");
    cmd.push_str(prog);
    cmd.push_str(
        "\"\r\n  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n)\r\n\r\nendLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" ",
    );
    if info.args.is_empty() {
        cmd.push(' ');
    } else {
        for arg in &info.args {
            push_escaped_cmd_arg(&mut cmd, arg);
            cmd.push(' ');
        }
    }
    cmd.push_str("\"%dp0%\\");
    cmd.push_str(&win_rel_path);
    cmd.push_str("\" %*\r\n");

    // 3. Windows PowerShell Wrapper (<name>.ps1)
    let ps1_rel_path = escape_ps1_path_cow(rel_path);
    let mut ps1 = String::with_capacity(
        620 + prog.len() * 3 + ps1_rel_path.len() * 4 + info.args.len() * 16,
    );
    ps1.push_str(
        "#!/usr/bin/env pwsh\r\n\
$basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent\r\n\
\r\n\
$exe=\"\"\r\n\
if ($PSVersionTable.PSVersion -lt \"6.0\" -or $IsWindows) {\r\n\
# Fix case when both the Windows and Linux builds of Node\r\n\
# are installed in the same directory\r\n\
  $exe=\".exe\"\r\n\
}\r\n\
$ret=0\r\n\
if (Test-Path \"$basedir/",
    );
    ps1.push_str(prog);
    ps1.push_str(
        "$exe\") {\r\n\
  # Support pipeline input\r\n\
  if ($MyInvocation.ExpectingInput) {\r\n\
    $input | & \"$basedir/",
    );
    ps1.push_str(prog);
    ps1.push_str("$exe\" ");
    let mut ps1_args_buf = String::new();
    if info.args.is_empty() {
        ps1_args_buf.push_str("  ");
    } else {
        for arg in &info.args {
            push_escaped_ps1_arg(&mut ps1_args_buf, arg);
            ps1_args_buf.push(' ');
        }
    }
    ps1.push_str(&ps1_args_buf);
    ps1.push_str("\"$basedir/");
    ps1.push_str(&ps1_rel_path);
    ps1.push_str("\" $args\r\n  } else {\r\n    & \"$basedir/");
    ps1.push_str(prog);
    ps1.push_str("$exe\" ");
    ps1.push_str(&ps1_args_buf);
    ps1.push_str("\"$basedir/");
    ps1.push_str(&ps1_rel_path);
    ps1.push_str(
        "\" $args\r\n  }\r\n\
  $ret=$LASTEXITCODE\r\n\
} else {\r\n\
  # Support pipeline input\r\n\
  if ($MyInvocation.ExpectingInput) {\r\n\
    $input | & \"",
    );
    ps1.push_str(prog);
    ps1.push_str("$exe\" ");
    ps1.push_str(&ps1_args_buf);
    ps1.push_str("\"$basedir/");
    ps1.push_str(&ps1_rel_path);
    ps1.push_str("\" $args\r\n  } else {\r\n    & \"");
    ps1.push_str(prog);
    ps1.push_str("$exe\" ");
    ps1.push_str(&ps1_args_buf);
    ps1.push_str("\"$basedir/");
    ps1.push_str(&ps1_rel_path);
    ps1.push_str(
        "\" $args\r\n  }\r\n\
  $ret=$LASTEXITCODE\r\n\
}\r\n\
exit $ret\r\n",
    );

    ShimContent { sh, cmd, ps1 }
}

fn write_trio_shim_file(path: &Path, data: &[u8]) -> Result<(), ShimError> {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        f.write_all(data).map_err(|e| ShimError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        return Ok(());
    }
    prepare_shim_destination(path);
    std::fs::write(path, data).map_err(|e| ShimError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Generates the standard executable shim trio into `bin_dir` for a target script file.
pub fn create_shim_trio(
    target_script: &Path,
    bin_dir: &Path,
    bin_name: &str,
) -> Result<ShimTrio, ShimError> {
    // 1. Compute relative path with forward slashes (e.g. "../my-pkg/bin/cli.js")
    let target_rel_path = compute_relative_path(bin_dir, target_script)?;

    // 2. Single-open normalize CRLF shebang + read shebang info
    let (is_file, shebang) = normalize_and_read_shebang_info(target_script)?;
    if is_file {
        let _ = set_executable_mode(target_script);
    }

    // 3. Generate content
    let content = generate_shim_content(&target_rel_path, shebang.as_ref());

    // 4. Ensure bin_dir exists
    std::fs::create_dir_all(bin_dir).map_err(|e| ShimError::Io {
        path: bin_dir.to_path_buf(),
        source: e,
    })?;

    // 5. Write shims to disk
    let sh_path = bin_dir.join(bin_name);
    let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));
    let ps1_path = bin_dir.join(format!("{bin_name}.ps1"));

    write_trio_shim_file(&sh_path, content.sh.as_bytes())?;
    let _ = set_executable_mode(&sh_path);

    write_trio_shim_file(&cmd_path, content.cmd.as_bytes())?;
    let _ = set_executable_mode(&cmd_path);

    write_trio_shim_file(&ps1_path, content.ps1.as_bytes())?;
    let _ = set_executable_mode(&ps1_path);

    Ok(ShimTrio {
        name: bin_name.to_string(),
        sh_path,
        cmd_path,
        ps1_path,
        target_rel_path,
        content,
    })
}

/// Generates executable shims for all binaries declared in a package `Manifest`.
/// Handles both single bin string (`"bin": "./cli.js"`) and map (`"bin": { "tool": "./tool.js" }`).
pub fn create_package_shims(
    pkg_dir: &Path,
    bin_dir: &Path,
    manifest: &Manifest,
) -> Result<Vec<ShimTrio>, ShimError> {
    let mut shims = Vec::new();
    let entries = manifest.bin_entries();

    for (bin_name, script_rel) in entries {
        let target_script = pkg_dir.join(&script_rel);
        let trio = create_shim_trio(&target_script, bin_dir, &bin_name)?;
        shims.push(trio);
    }

    Ok(shims)
}

/// Generates executable shims from a `PackageBin` enum directly.
pub fn create_shims_from_bin(
    pkg_dir: &Path,
    bin_dir: &Path,
    pkg_name: Option<&str>,
    bin: &PackageBin,
) -> Result<Vec<ShimTrio>, ShimError> {
    let mut entries = Vec::new();
    match bin {
        PackageBin::Single(script_path) => {
            let bin_name = pkg_name
                .map(|n| {
                    if let Some(slash_idx) = n.find('/') {
                        &n[slash_idx + 1..]
                    } else {
                        n
                    }
                })
                .unwrap_or("app")
                .to_string();
            entries.push((bin_name, script_path.clone()));
        }
        PackageBin::Map(map) => {
            for (k, v) in map {
                entries.push((k.clone(), v.clone()));
            }
        }
    }

    let mut shims = Vec::new();
    for (bin_name, script_rel) in entries {
        let target_script = pkg_dir.join(&script_rel);
        let trio = create_shim_trio(&target_script, bin_dir, &bin_name)?;
        shims.push(trio);
    }

    Ok(shims)
}
