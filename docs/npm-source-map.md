# npm Observable Subsystems Source Map

## Overview

This document provides a comprehensive mapping of the internal and observable subsystems of `npm` (specifically `npm v11.x` as bundled with `Node.js v24.x`). For each subsystem, this document defines:
- **Purpose and Architectural Boundary**
- **Inputs and Outputs**
- **Important Data Structures & Models**
- **Error Names and Exit Codes**
- **Filesystem Effects**
- **Network Effects**
- **Platform-Specific Behavior (Windows vs Unix)**
- **Relevant npm Tests & Upstream Fixtures**

---

## 1. CLI Dispatch & Command Architecture

### Purpose
The entry point of npm (`bin/npm-cli.js`, `lib/npm.js`, `lib/cli/entry.js`). Manages process initialization, signals, logging, execution time profiling, exit code normalization, and command dispatch (`install`, `ci`, `run`, `uninstall`, `update`, `pack`, etc.).

### Inputs & Outputs
- **Inputs:** `process.argv`, `process.env`, standard input stream (stdin).
- **Outputs:** Process exit codes (`0` on success, non-zero on failure), JSON or human-readable stdout, stderr log messages.

### Important Data Structures
- `Npm`: Singleton application context object exposing `.config`, `.output()`, `.time()`, and `.registry`.
- `CommandDefinition`: Base class defining `.exec(args)`, `.usage`, and command completion hooks.

### Error Names & Exit Codes
- `0`: Successful completion.
- `1`: Generic operational failure or unhandled exception.
- `EUSAGE`: Invalid arguments or unrecognized command flag (exit code `1`).
- `ERR_SOCKET_TIMEOUT` / `ECONNREFUSED`: Network connectivity failure (exit code `1`).
- `SIGINT` / `SIGTERM`: Process interruption (exit code `130` or `143`).

### Filesystem Effects
- Writes crash reports to `_logs/<timestamp>-debug-0.log` inside the cache directory on uncaught errors.
- Respects `--timing` flag by dumping `timing.json` to the current working directory.

### Network Effects
None directly; coordinates downstream clients.

### Platform-Specific Behavior
- Windows: Console title updates via `title` command sequence; handles `SIGINT` via Windows Console Control Handler (`CTRL_C_EVENT`).
- Windows executable wrapper is invoked via `npm.cmd` or PowerShell `npm.ps1`.

### Relevant Upstream Tests & Fixtures
- `test/lib/cli/entry.js`
- `test/lib/npm.js`
- `test/lib/commands/*.js`

---

## 2. Configuration System (`@npmcli/config`)

### Purpose
Parses, merges, and validates configuration definitions from 6 cascading tiers:
1. Command-line flags (`--registry=...`, `--save-dev`)
2. Environment variables (`npm_config_*`)
3. Project `.npmrc` (discovered by walking upwards from cwd to workspace root)
4. User `.npmrc` (`~/.npmrc` or `%USERPROFILE%\.npmrc`)
5. Global `.npmrc` (`$PREFIX/etc/npmrc` or `%APPDATA%\npm\etc\npmrc`)
6. Builtin `.npmrc` (bundled with npm)

### Inputs & Outputs
- **Inputs:** CLI argv strings, `process.env`, `.npmrc` INI files.
- **Outputs:** Validated configuration map with type-coerced values (Boolean, String, Number, Path, Array).

### Important Data Structures
- `Config`: Root configuration object.
- `definitions`: Formal schema declarations for all ~250 npm options (type, default, description).
- `scopedRegistry`: Map from scope prefix (e.g. `@mycorp`) to registry URI.
- `nerfDart`: URL transform normalizing `https://registry.npmjs.org/` into `//registry.npmjs.org/:_authToken`.

### Error Names & Exit Codes
- `ERR_INVALID_CONFIG`: Malformed config value (e.g. invalid URL, unknown type).

### Filesystem Effects
- Read-only queries of `.npmrc` files in cwd, ancestor directories, and home directory.

### Network Effects
None directly; resolves registry URIs and auth tokens for network clients.

### Platform-Specific Behavior
- Windows parses `%USERPROFILE%\.npmrc` and `%APPDATA%\npm\etc\npmrc`.
- Environment variable names are case-insensitive on Windows, but normalized to lowercase `npm_config_*`.

### Relevant Upstream Tests & Fixtures
- `@npmcli/config/test/basic.js`
- `@npmcli/config/test/env.js`
- `@npmcli/config/test/nerf-dart.js`

---

## 3. Package Specifier Grammar (`npm-package-arg`)

### Purpose
Parses and normalizes package dependency specifiers into structured descriptors, distinguishing registry versions, semver ranges, dist-tags, git repositories, remote tarballs, local directories/files, and npm aliases.

### Inputs & Outputs
- **Inputs:** Raw specifier string (e.g. `react@^18.2.0`, `foo@npm:bar@~1.0.0`, `file:../local-pkg`).
- **Outputs:** `Result` object defining `name`, `type`, `raw`, `rawSpec`, `fetchSpec`, `subSpec`.

### Important Data Structures
- `Result`:
  - `type`: Enum: `tag`, `version`, `range`, `alias`, `file`, `directory`, `remote`, `git`.
  - `name`: Package name or alias identifier.
  - `rawSpec`: Target version/range/URL portion.
  - `subSpec`: Nested `Result` when `type === 'alias'`.

### Error Names & Exit Codes
- `EUNSUPPORTEDPROTOCOL`: Unsupported URL scheme.
- `EINVALIDTAGNAME`: Dist-tag containing invalid characters (e.g. spaces, uppercase).
- `EINVALIDPACKAGENAME`: Package name violating npm naming rules (uppercase, leading `.` or `_`, URL-unsafe chars).

### Filesystem Effects
- Resolves relative paths for `file:` and `directory:` against cwd.

### Network Effects
None.

### Platform-Specific Behavior
- On Windows, handles drive letters in paths (e.g. `file:C:/path/to/pkg`) without misclassifying `C:` as a URL protocol.
- Converts Windows `\` to `/` in specifier representation.

### Relevant Upstream Tests & Fixtures
- `npm-package-arg/test/basic.js`
- `npm-package-arg/test/aliases.js`

---

## 4. Dependency Graph Engine (`@npmcli/arborist`)

### Purpose
The core tree calculation and reification engine in npm. Builds and mutates three tree representations:
1. `ActualTree`: Physical package layout scanned from disk (`node_modules`).
2. `VirtualTree`: Dependency graph reconstructed from `package-lock.json`.
3. `IdealTree`: Target graph computed from manifests, ranges, overrides, and peer dependencies.
Performs reification: calculates tree diff, downloads missing packages, unlinks pruned packages, extracts tarballs, and writes the lockfile.

### Inputs & Outputs
- **Inputs:** Root `package.json`, `package-lock.json`, disk `node_modules`, registry packuments.
- **Outputs:** Mutated `node_modules` directory, updated `package-lock.json`, `node_modules/.package-lock.json`.

### Important Data Structures
- `Node`: Represents an installed or planned package (has `name`, `version`, `path`, `edgesIn`, `edgesOut`, `location`).
- `Link`: Special `Node` representing a symlink / junction (workspaces, `file:` directories).
- `Edge`: Directed dependency edge between nodes (types: `prod`, `dev`, `peer`, `optional`, `workspace`).
- `Diff`: Graph diff representing `added`, `removed`, and `updated` nodes for reification.

### Error Names & Exit Codes
- `ERESOLVE`: Unresolvable peer dependency conflict.
- `ETARGET`: No matching version found in registry for specifier.
- `EEXIST`: File conflict during reification.

### Filesystem Effects
- Walks directory trees in `node_modules`.
- Writes, extracts, and deletes folders in `node_modules`.
- Generates `node_modules/.package-lock.json` (hidden lockfile).

### Network Effects
- Dispatches metadata queries (packuments) via `pacote` to resolve dependencies.

### Platform-Specific Behavior
- On Windows, uses NTFS junctions for directory links instead of symlinks.
- Normalizes path separators to POSIX `/` in all lockfile and tree location strings.

### Relevant Upstream Tests & Fixtures
- `@npmcli/arborist/test/ideal-tree.js`
- `@npmcli/arborist/test/actual-tree.js`
- `@npmcli/arborist/test/reify.js`
- `@npmcli/arborist/test/peer-deps.js`

---

## 5. Package Extraction & Manifest Fetching (`pacote`)

### Purpose
Fetches package manifests, packuments, and tarballs from diverse sources (npm registry, git, local file, directory). Extracts tarball archives into destination directories with integrity verification.

### Inputs & Outputs
- **Inputs:** Package specifier, destination path, cache options, registry auth.
- **Outputs:** Manifest JSON object, extracted directory on disk, or raw tarball stream.

### Important Data Structures
- `Manifest`: In-memory `package.json` representation with normalized `_id`, `_integrity`, `_resolved`.
- `Packument`: Full registry document containing `versions` map and `dist-tags`.

### Error Names & Exit Codes
- `ETARGET`: Target version does not exist.
- `ENOENT`: Local tarball or directory not found.
- `EINTEGRITY`: Tarball integrity hash mismatch.

### Filesystem Effects
- Extracts tarballs into `node_modules/<pkg>`. Strips the standard `package/` top-level directory prefix.
- Writes downloaded blobs to `cacache`.

### Network Effects
- Fetches tarballs via HTTP GET; respects `pacote` cache policies (`prefer-online`, `prefer-offline`).

### Platform-Specific Behavior
- Normalizes file permissions on Windows (read-only attribute handling).
- Preserves executable permissions (`0755`) when extracting on Unix.

### Relevant Upstream Tests & Fixtures
- `pacote/test/manifest.js`
- `pacote/test/tarball.js`
- `pacote/test/extract.js`

---

## 6. Registry HTTP Client (`npm-registry-fetch`)

### Purpose
HTTP client specialized for the npm registry protocol. Built on `make-fetch-happen`. Handles authentication (`Bearer`, Basic), request retries (exponential backoff on 408, 429, 5xx), user-agent header generation, proxy handling, and URI-scoped token matching.

### Inputs & Outputs
- **Inputs:** URI path, HTTP method, request headers, body stream.
- **Outputs:** HTTP response stream, parsed JSON object.

### Important Data Structures
- `FetchOptions`: Combines timeout, retry settings, proxy, TLS certs, and auth mappings.

### Error Names & Exit Codes
- `E401` / `E403`: Authentication / authorization failure.
- `E404`: Package or version not found.
- `E429`: Rate limit exceeded.

### Filesystem Effects
None directly.

### Network Effects
- Executes HTTP/1.1 and HTTP/2 GET, PUT, POST requests against registry endpoints.
- Sends header `Accept: application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8` to request compact abbreviated metadata.

### Platform-Specific Behavior
- Respects system proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`).

### Relevant Upstream Tests & Fixtures
- `npm-registry-fetch/test/index.js`
- `npm-registry-fetch/test/auth.js`
- `npm-registry-fetch/test/errors.js`

---

## 7. Content-Addressable Cache (`cacache`)

### Purpose
High-concurrency content-addressable storage engine. Stores arbitrary data blobs indexed by cryptographic hash, along with a metadata index mapping arbitrary string keys to content hashes.

### Inputs & Outputs
- **Inputs:** Key string, content byte buffer/stream, SRI integrity string.
- **Outputs:** Stored blob path, verified content stream, entry metadata.

### Important Data Structures
- `IndexEntry`: JSON line stored in `index-v5/` bucket: `{ key, integrity, time, size, metadata }`.
- `content-v2/`: Two-level sharded directory structure storing raw blobs: `<algo>/<h0>/<h1>/<hash>`.

### Error Names & Exit Codes
- `EINTEGRITY`: Hash mismatch between index entry and stored blob.
- `ENOENT`: Cache key not found.

### Filesystem Effects
- Manages files under `~/.npm/_cacache/` (or `%LocalAppData%\npm-cache\_cacache`).
- Atomic writes: writes to `_cacache/tmp/` first, verifies hash, then renames to `content-v2/...`.
- Multi-process locking via `.lock` files.

### Network Effects
None.

### Platform-Specific Behavior
- Windows requires explicit file lock release before rename or deletion (`MoveFileExW`).
- Handles file locking retries when antivirus holds temporary handles.

### Relevant Upstream Tests & Fixtures
- `cacache/test/get.js`
- `cacache/test/put.js`
- `cacache/test/verify.js`

---

## 8. Subresource Integrity (`ssri`)

### Purpose
Standard Subresource Integrity parsing, string generation, multi-hash verification, and comparison library. Supports SHA-512, SHA-384, SHA-256, and legacy SHA-1.

### Inputs & Outputs
- **Inputs:** SRI string (e.g. `sha512-abc... sha256-xyz...`), byte stream.
- **Outputs:** `Integrity` object, verification boolean.

### Important Data Structures
- `Hash`: Individual hash tuple (`algorithm`, `digest`, `options`).
- `Integrity`: Set of `Hash` objects grouped by algorithm.

### Error Names & Exit Codes
- `EINTEGRITY`: Thrown when stream digest does not match expected integrity.

### Filesystem & Network Effects
None.

### Verification Precedence
When multiple algorithms are present in an SRI string:
- Prioritizes the strongest algorithm: `sha512` > `sha384` > `sha256` > `sha1`.
- If the strongest algorithm fails, verification FAILS immediately, even if a weaker algorithm (such as `sha1`) matches.

### Relevant Upstream Tests & Fixtures
- `ssri/test/parse.js`
- `ssri/test/stringify.js`
- `ssri/test/check.js`

---

## 9. Semantic Versioning Engine (`node-semver`)

### Purpose
The reference implementation of the Semantic Version 2.0.0 specification with Node.js extensions. Implements version parsing, comparator logic, range satisfiability, loose mode parsing, and prerelease sorting.

### Inputs & Outputs
- **Inputs:** Version string, range string, options (`loose`, `includePrerelease`).
- **Outputs:** `SemVer` instance, `Range` instance, comparison integer (`-1, 0, 1`), boolean match.

### Important Data Structures
- `SemVer`: `{ major, minor, patch, prerelease, build, raw }`.
- `Comparator`: Single operator and version (e.g. `>=1.2.3`).
- `Range`: 2D array representing Disjunctive Normal Form (set of comparator conjunctions).

### Key Grammar Rules
- Caret (`^`):
  - `^1.2.3` -> `>=1.2.3 <2.0.0`
  - `^0.2.3` -> `>=0.2.3 <0.3.0` (zero minor freezes minor)
  - `^0.0.3` -> `=0.0.3` (zero patch freezes patch)
- Tilde (`~`):
  - `~1.2.3` -> `>=1.2.3 <1.3.0`
  - `~1.2` -> `>=1.2.0 <1.3.0`
  - `~1` -> `>=1.0.0 <2.0.0`
- Hyphen ranges: `1.2.3 - 2.3.4` -> `>=1.2.3 <=2.3.4`.
- Prerelease rule: Prerelease versions (e.g. `1.2.3-alpha.1`) match a range ONLY if the range tuple has an identical major.minor.patch with a prerelease comparator.

### Relevant Upstream Tests & Fixtures
- `semver/test/ranges.js`
- `semver/test/satisfies.js`
- `semver/test/sort.js`

---

## 10. Lifecycle Scripts Execution (`@npmcli/run-script` & `promise-spawn`)

### Purpose
Executes package lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`, `test`, `start`, custom scripts) defined in `package.json`. Sets up the execution environment, PATH, and cleans up child process trees on exit.

### Inputs & Outputs
- **Inputs:** Script name, package manifest, package directory path, environment overrides.
- **Outputs:** Child process exit code, streaming stdout and stderr.

### Important Data Structures
- `RunScriptOptions`: `{ event, path, env, stdio, banner }`.

### Environment Construction
- Prepends `node_modules/.bin` and ancestor `node_modules/.bin` to `PATH`.
- Exposes `npm_lifecycle_event`, `npm_lifecycle_script`, `npm_package_name`, `npm_package_version`.
- Exposes `INIT_CWD` (invocation directory).
- **Security requirement:** Scrubs all auth tokens (`_authToken`, password fields) from `npm_config_*` before execution.

### Platform-Specific Behavior
- Windows: Spawns through `cmd.exe /d /s /c "<script>"`.
- Unix: Spawns through `/bin/sh -c "<script>"`.
- Process tree termination: Windows uses Job Objects; Unix uses process groups (`kill(-pgid)`).

### Relevant Upstream Tests & Fixtures
- `@npmcli/run-script/test/index.js`
- `promise-spawn/test/index.js`

---

## 11. Command Shims & Executable Links (`cmd-shim` & `bin-links`)

### Purpose
Creates cross-platform executable launchers in `node_modules/.bin/` for binaries exposed in package manifests (`"bin": { "my-cli": "./bin/cli.js" }`).

### Inputs & Outputs
- **Inputs:** Source binary path, destination path in `node_modules/.bin/`.
- **Outputs:** Executable files/symlinks on disk.

### Platform-Specific Behavior
- **Unix:**
  - Creates relative symbolic link `node_modules/.bin/<name>` -> `../<pkg>/<binPath>`.
  - Sets executable mode bits `chmod 0755`.
  - Normalizes CRLF line endings in shebang (`#!/usr/bin/env node`) to prevent Linux `/bin/sh^M: bad interpreter` failure.
- **Windows:**
  - Creates three companion files for every binary:
    1. `<name>`: POSIX shell script (for Git Bash / WSL).
    2. `<name>.cmd`: Batch file for `cmd.exe`. Safely forwards arguments `%*` and escapes special metacharacters.
    3. `<name>.ps1`: PowerShell script for PowerShell sessions.

### Relevant Upstream Tests & Fixtures
- `cmd-shim/test/index.js`
- `bin-links/test/index.js`

---

## 12. Safe Filesystem Operations (`@npmcli/fs`)

### Purpose
Hardened filesystem operations designed to tolerate concurrent multi-process access, platform edge cases, symlink traversal attacks, and Windows file-locking quirks.

### Features & Contracts
- `writeFile`: Writes to unique temporary file alongside target, flushes to disk (`fsync`), and atomically renames.
- `rm`: Recursive directory removal with exponential backoff retry loop on Windows `EBUSY` / `EPERM` / `ENOTEMPTY`.
- `mkdir`: Recursive directory creation with mode bit preservation.
- `copyFile`: Preserves timestamps and mode bits.

### Platform-Specific Behavior
- Windows retry parameters: 10 attempts, 50ms initial delay, exponential backoff with jitter up to 1000ms.

### Relevant Upstream Tests & Fixtures
- `@npmcli/fs/test/rm.js`
- `@npmcli/fs/test/write-file.js`

---

## 13. Workspaces Management

### Purpose
Manages monorepos containing multiple interdependent local packages. Handles workspace discovery, dependency resolution using the `workspace:` protocol, hoisting to the root `node_modules`, symlinking workspace directories, and topological execution of lifecycle scripts.

### Inputs & Outputs
- **Inputs:** Root `package.json` `"workspaces"` field (array of glob patterns).
- **Outputs:** Discovered workspace packages list, topological build order, root links.

### Important Data Structures
- `Workspace`: `{ name, path, manifest }`.
- `WorkspaceGraph`: Directed Acyclic Graph (DAG) of inter-workspace dependencies.

### Protocols
- `workspace:*`: Matches exact version of local workspace.
- `workspace:^`: Matches semver compatible version.
- `workspace:~`: Matches patch-compatible version.

### Platform-Specific Behavior
- On Windows, links workspace packages into `node_modules` using NTFS Directory Junctions.
- Cycle detection: Monorepos with circular dependencies between workspaces must be detected and scheduled without infinite loops.

### Relevant Upstream Tests & Fixtures
- `@npmcli/arborist/test/workspaces.js`
- `test/lib/commands/workspaces.js`
