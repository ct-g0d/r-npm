use std::path::{Path, PathBuf};
use rnpm_core::manifest::{Manifest, PackageBin};
use crate::error::ShimError;
use crate::path::compute_relative_path;
use crate::shebang::{normalize_shebang_file, read_shebang_from_file, ShebangInfo};

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

/// Generates the content of the executable shim trio for a target script.
///
/// - `rel_path`: Relative path from `node_modules/.bin/` to the target script with forward slashes (e.g. `../my-pkg/bin/cli.js`).
/// - `shebang`: Optional parsed shebang information. Defaults to `node` if `None`.
pub fn generate_shim_content(rel_path: &str, shebang: Option<&ShebangInfo>) -> ShimContent {
    let default_shebang = ShebangInfo::default();
    let info = shebang.unwrap_or(&default_shebang);
    let prog = &info.program;

    // 1. Unix POSIX Shell Script (<name>)
    let sh_args_str = if info.args.is_empty() {
        "  ".to_string()
    } else {
        let escaped: Vec<String> = info.args.iter().map(|arg| crate::escape_posix_arg(arg)).collect();
        format!("{} ", escaped.join(" "))
    };
    let sh_rel_path = crate::escape_posix_path(rel_path);
    let mut sh = format!(
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
         if [ -x \"$basedir/{prog}\" ]; then\n\
           exec \"$basedir/{prog}\" {sh_args_str}\"$basedir/{sh_rel_path}\" \"$@\"\n\
         else \n\
           exec {prog} {sh_args_str}\"$basedir/{sh_rel_path}\" \"$@\"\n\
         fi\n"
    );
    // Match npm's cmd-shim output exactly: its sed expression contains two
    // literal backslashes in the generated script, and its node invocation
    // keeps the double-space argument separator.
    sh = sh.replace("s,\\\\\\\\,/,g", "s,\\\\,/,g");

    // 2. Windows Batch Wrapper (<name>.cmd)
    let cmd_args_str = if info.args.is_empty() {
        " ".to_string()
    } else {
        let escaped: Vec<String> = info.args.iter().map(|arg| crate::escape_cmd_arg(arg)).collect();
        format!("{} ", escaped.join(" "))
    };
    let win_rel_path = crate::escape_cmd_path(&rel_path.replace('/', "\\"));
    let cmd = format!(
        "@ECHO off\r\n\
         GOTO start\r\n\
         :find_dp0\r\n\
         SET dp0=%~dp0\r\n\
         EXIT /b\r\n\
         :start\r\n\
         SETLOCAL\r\n\
         CALL :find_dp0\r\n\
         \r\n\
         IF EXIST \"%dp0%\\{prog}.exe\" (\r\n\
           SET \"_prog=%dp0%\\{prog}.exe\"\r\n\
         ) ELSE (\r\n\
           SET \"_prog={prog}\"\r\n\
           SET PATHEXT=%PATHEXT:;.JS;=;%\r\n\
         )\r\n\
         \r\n\
         endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" {cmd_args_str}\"%dp0%\\{win_rel_path}\" %*\r\n"
    );

    // 3. Windows PowerShell Wrapper (<name>.ps1)
    let ps1_args_str = if info.args.is_empty() {
        "  ".to_string()
    } else {
        let escaped: Vec<String> = info.args.iter().map(|arg| crate::escape_ps1_arg(arg)).collect();
        format!("{} ", escaped.join(" "))
    };
    let ps1_rel_path = crate::escape_ps1_path(rel_path);
    let ps1 = format!(
        "#!/usr/bin/env pwsh\r\n\
         $basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent\r\n\
         \r\n\
         $exe=\"\"\r\n\
         if ($PSVersionTable.PSVersion -lt \"6.0\" -or $IsWindows) {{\r\n\
           # Fix case when both the Windows and Linux builds of Node are installed in the same directory\r\n\
           $exe=\".exe\"\r\n\
         }}\r\n\
         $ret=0\r\n\
         if (Test-Path \"$basedir/{prog}$exe\") {{\r\n\
           # Support pipeline input\r\n\
           if ($MyInvocation.ExpectingInput) {{\r\n\
             $input | & \"$basedir/{prog}$exe\" {ps1_args_str}\"$basedir/{ps1_rel_path}\" $args\r\n\
           }} else {{\r\n\
             & \"$basedir/{prog}$exe\" {ps1_args_str}\"$basedir/{ps1_rel_path}\" $args\r\n\
           }}\r\n\
           $ret=$LASTEXITCODE\r\n\
         }} else {{\r\n\
           # Support pipeline input\r\n\
           if ($MyInvocation.ExpectingInput) {{\r\n\
             $input | & \"{prog}$exe\" {ps1_args_str}\"$basedir/{ps1_rel_path}\" $args\r\n\
           }} else {{\r\n\
             & \"{prog}$exe\" {ps1_args_str}\"$basedir/{ps1_rel_path}\" $args\r\n\
           }}\r\n\
           $ret=$LASTEXITCODE\r\n\
         }}\r\n\
         exit $ret\r\n"
    )
    .replace("\r\n# Fix", "\r\n  # Fix")
    .replace("\r\n$exe=\".exe\"", "\r\n  $exe=\".exe\"")
    .replace("\r\n# Support", "\r\n  # Support")
    .replace("\r\nif ($MyInvocation", "\r\n  if ($MyInvocation")
    .replace("\r\n$input |", "\r\n    $input |")
    .replace("\r\n& \"", "\r\n    & \"")
    .replace("\r\n}\r\n$ret=$LASTEXITCODE", "\r\n  }\r\n  $ret=$LASTEXITCODE")
    .replace("\r\n} else {\r\n  # Support", "\r\n  } else {\r\n  # Support")
    .replace("\"   \"$basedir", "\"  \"$basedir")
    .replace("\"   \"$basedir", "\"  \"$basedir")
    .replace("$basedir =", "$basedir=")
    .replace("$exe =", "$exe=")
    .replace("$ret =", "$ret=");

    ShimContent { sh, cmd, ps1 }
}

/// Generates the standard executable shim trio into `bin_dir` for a target script file.
///
/// 1. Computes the relative path from `bin_dir` to `target_script` (with forward slashes).
/// 2. Normalizes any CRLF shebang in `target_script` if it exists on disk.
/// 3. Reads any shebang options.
/// 4. Generates `<bin_name>`, `<bin_name>.cmd`, and `<bin_name>.ps1` in `bin_dir`.
/// 5. Sets file mode `0755` on Unix.
pub fn create_shim_trio(
    target_script: &Path,
    bin_dir: &Path,
    bin_name: &str,
) -> Result<ShimTrio, ShimError> {
    // 1. Compute relative path with forward slashes (e.g. "../my-pkg/bin/cli.js")
    let target_rel_path = compute_relative_path(bin_dir, target_script)?;

    // 2. Normalize CRLF shebang in the target script if it exists
    if target_script.exists() {
        let _ = normalize_shebang_file(target_script)?;
        let _ = set_executable_mode(target_script);
    }

    // 3. Read shebang info if present
    let shebang = read_shebang_from_file(target_script).ok().flatten();

    // 4. Generate content
    let content = generate_shim_content(&target_rel_path, shebang.as_ref());

    // 5. Ensure bin_dir exists
    std::fs::create_dir_all(bin_dir).map_err(|e| ShimError::Io {
        path: bin_dir.to_path_buf(),
        source: e,
    })?;

    // 6. Write shims to disk
    let sh_path = bin_dir.join(bin_name);
    let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));
    let ps1_path = bin_dir.join(format!("{bin_name}.ps1"));

    std::fs::write(&sh_path, content.sh.as_bytes()).map_err(|e| ShimError::Io {
        path: sh_path.clone(),
        source: e,
    })?;
    let _ = set_executable_mode(&sh_path);

    std::fs::write(&cmd_path, content.cmd.as_bytes()).map_err(|e| ShimError::Io {
        path: cmd_path.clone(),
        source: e,
    })?;
    let _ = set_executable_mode(&cmd_path);

    std::fs::write(&ps1_path, content.ps1.as_bytes()).map_err(|e| ShimError::Io {
        path: ps1_path.clone(),
        source: e,
    })?;
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
