# Platform Filesystem & Windows Resilience Contract

## 1. Overview & Platform Architecture

Node.js packages operate across heterogeneous operating systems: Windows (NTFS / ReFS), Linux (ext4, xfs, btrfs), and macOS (APFS). Differences in symbolic links, path length limits, process locks, and file permissions create critical divergence points.

This contract specifies `rnpm`'s platform-level filesystem abstractions, with particular emphasis on **Windows resilience**.

---

## 2. Windows Directory Junctions vs Symbolic Links

### 2.1. Privilege Boundaries & The Non-Admin Contract
- On Windows, creating a standard symbolic link (`CreateSymbolicLinkW`) requires either:
  1. Elevated Administrator privileges (`SeCreateSymbolicLinkPrivilege`), or
  2. Windows Developer Mode enabled in system settings.
- In enterprise environments and CI runners, neither condition can be assumed.
- **Contract:** For local directory links (workspaces, `file:` directories), `rnpm` creates **NTFS Directory Junctions** (`IO_REPARSE_TAG_MOUNT_POINT`).
- **Junction Guarantees:**
  - Can be created by any unprivileged user without Developer Mode.
  - Resolved natively by the Windows NT kernel and Win32 subsystem.
  - Transparently traversed by Node.js runtime `fs` operations.

### 2.2. Critical Safety Rule: Safe Junction Pruning
Junctions contain a reparse point buffer directing file operations to a target directory.
> [!CAUTION]
> If a recursive directory deletion function traverses into a junction reparse point, it will recursively delete the contents of the linked target directory (e.g. the entire workspace source package)!

**The Pruning Contract:**
1. Before deleting any directory entry, query its filesystem metadata (`GetFileAttributesW` / `fs::symlink_metadata`).
2. If the entry possesses the attribute `FILE_ATTRIBUTE_REPARSE_POINT`:
   - It is a junction or symlink.
   - Call `RemoveDirectoryW` on the junction entry directly.
   - **DO NOT** recurse into its child entries.
3. This unlinks the reparse point while leaving the linked target directory and its contents completely untouched.

---

## 3. Path Length & Extended Paths (`MAX_PATH`)

### 3.1. The 260-Character `MAX_PATH` Limitation
The legacy Windows Win32 API imposes a 260-character path limit (`MAX_PATH = 260`). In deeply nested `node_modules` hierarchies (e.g. `node_modules/a/node_modules/b/...`), absolute paths frequently exceed 300+ characters.

### 3.2. Extended-Length Path Prefix (`\\?\`)
- **Contract:** All filesystem operations on Windows must canonicalize absolute paths and prepend the Win32 extended-length path prefix:
  `\\?\D:\npm-rust\node_modules\...`
- Extended paths allow path lengths up to **32,767 characters**.
- For UNC network paths, the prefix is `\\?\UNC\server\share\...`.
- When passing paths to user-facing output or child processes, strip the `\\?\` prefix if the path length is within standard limits to maintain output readability.

---

## 4. Executable Command Shims (`node_modules/.bin`)

Packages expose CLI binaries via the `"bin"` field in `package.json`. `rnpm` creates executable launchers in `node_modules/.bin/`.

### 4.1. Unix Platforms (Linux & macOS)
- Create a relative symbolic link pointing to the target binary file:
  `node_modules/.bin/<name>` -> `../<pkg>/<binPath>`
- Set file permissions to `0755` (`rwxr-xr-x`).
- **CRLF Shebang Normalization:** If the target script has a shebang (`#!/usr/bin/env node`) containing Windows CRLF (`\r\n`) line endings, rewrite the shebang line to LF (`\n`) during extraction. (CRLF shebangs fail on Linux with `/usr/bin/env: 'node\r': No such file or directory`).

### 4.2. Windows Platforms (cmd, PowerShell, Git Bash)
Windows does not execute shebangs directly from the command line. `rnpm` generates **three companion files** for each binary entry:

#### 1. POSIX Shell Script (`node_modules/.bin/<name>`)
For Git Bash, MSYS2, Cygwin, and WSL:
```sh
#!/bin/sh
basedir=$(dirname "$(echo "$0" | sed -e 's,\\,/,g')")

case `uname` in
    *CYGWIN*|*MINGW*|*MSYS*)
        if command -v cygpath > /dev/null 2>&1; then
            basedir=`cygpath -w "$basedir"`
        fi
    ;;
esac

if [ -x "$basedir/node" ]; then
  exec "$basedir/node" "$basedir/../<pkg>/<binPath>" "$@"
else
  exec node "$basedir/../<pkg>/<binPath>" "$@"
fi
```

#### 2. Windows Batch Wrapper (`node_modules/.bin/<name>.cmd`)
For standard Command Prompt (`cmd.exe`):
```cmd
@ECHO off
GOTO start
:find_dp0
SET dp0=%~dp0
EXIT /b
:start
SETLOCAL
CALL :find_dp0

IF EXIST "%dp0%\node.exe" (
  SET "_prog=%dp0%\node.exe"
) ELSE (
  SET "_prog=node"
  SET PATHEXT=%PATHEXT:;.JS;=;%
)

endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%" "%dp0%\..\<pkg>\<binPath>" %*
```
- Safely handles argument passing `%*` with quotes.
- Cleans up trailing backslashes using `:find_dp0`.

#### 3. Windows PowerShell Wrapper (`node_modules/.bin/<name>.ps1`)
For PowerShell sessions:
```powershell
#!/usr/bin/env pwsh
$basedir = Split-Path $MyInvocation.MyCommand.Definition -Parent

$exe = ""
if ($PSVersionTable.PSVersion -lt "6.0" -or $IsWindows) {
  # Windows
  if (Test-Path "$basedir/node.exe") {
    $exe = "$basedir/node.exe"
  } else {
    $exe = "node"
  }
} else {
  # Linux/macOS
  if (Test-Path "$basedir/node") {
    $exe = "$basedir/node"
  } else {
    $exe = "node"
  }
}

$ret = 0
if (Test-Path "$basedir/../<pkg>/<binPath>") {
  & "$exe" "$basedir/../<pkg>/<binPath>" $args
  $ret = $LASTEXITCODE
} else {
  & "$exe" "$basedir/../<pkg>/<binPath>" $args
  $ret = $LASTEXITCODE
}
exit $ret
```

---

## 5. File Permissions & Mode Sanitization

### 5.1. Unix Permissions
- Regular extracted files: `0644` (`rw-r--r--`).
- Binaries and directories: `0755` (`rwxr-xr-x`).
- **Security Sanitization:** Strip SUID (`04000`) and SGID (`02000`) bits from all tarball entries upon extraction.

### 5.2. Windows Attributes
- Windows does not maintain POSIX permissions.
- If a file has the `FILE_ATTRIBUTE_READONLY` flag set, file deletion or overwrite fails with `ERROR_ACCESS_DENIED`.
- Before removing files on Windows, clear the read-only attribute:
  `SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL)`.

---

## 6. Transient File Locking & `EBUSY` / `EPERM` Retry Loop

### 6.1. Root Cause
On Windows, filesystem operations are subject to opportunistic and mandatory file locks:
1. Windows Defender (`MsMpEng.exe`) opens newly created files to scan for malware.
2. Windows Search Indexer (`SearchIndexer.exe`) opens files to index text content.
3. Background Node processes or developer editors (VS Code) hold temporary open handles.

When `rnpm` attempts to delete or atomically rename a directory while an external process holds a handle, the OS returns:
- `ERROR_SHARING_VIOLATION` (Win32 32) -> maps to `EBUSY`
- `ERROR_ACCESS_DENIED` (Win32 5) -> maps to `EPERM`

### 6.2. The Retry Algorithm
All file deletions (`rm`), directory removals (`rmdir`), and atomic file renames (`rename`) on Windows must use an exponential backoff retry loop with randomized jitter:

```rust
// Contract pseudo-code
const MAX_ATTEMPTS: u32 = 10;
const INITIAL_DELAY_MS: u64 = 50;
const MAX_DELAY_MS: u64 = 1000;

for attempt in 1..=MAX_ATTEMPTS {
    match operation() {
        Ok(result) => return Ok(result),
        Err(err) if is_transient_lock_error(&err) && attempt < MAX_ATTEMPTS => {
            // Exponential backoff with jitter
            let backoff = (INITIAL_DELAY_MS * 2u64.pow(attempt - 1)).min(MAX_DELAY_MS);
            let jitter = rand::random::<u64>() % 25;
            std::thread::sleep(std::time::Duration::from_millis(backoff + jitter));
        }
        Err(err) => return Err(err),
    }
}
```

### 6.3. Transient Error Codes Handled
- `ERROR_SHARING_VIOLATION` (32)
- `ERROR_LOCK_VIOLATION` (33)
- `ERROR_ACCESS_DENIED` (5)
- `ERROR_DIR_NOT_EMPTY` (145) / `ENOTEMPTY` (transiently raised while files are pending deletion)
