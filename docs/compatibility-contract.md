# Compatibility Contract & Architecture Decisions

## 1. Guiding Rules & Compatibility Philosophy

1. **Behavioral Oracle:** `npm` (specifically `npm v11.x` running on Node.js `v24.x` / `v26.x`) is the definitive behavioral ground truth for this project.
2. **Normalized Parity:** The project is successful when it produces an installed `node_modules` dependency tree and `package-lock.json` file whose normalized digests match npm with **zero diff**.
3. **Correctness Before Speed:** Never trade correctness or compatibility for performance. A faster installer that computes a divergent dependency tree is a failed installer.
4. **Isolated Contracts:** Each subsystem operates under an explicit frozen contract. Cross-subsystem interactions must adhere to documented boundaries.
5. **Deterministic Diagnostics:** Failures must report structured, informative error codes matching npm error names (`ERESOLVE`, `ETARGET`, `EINTEGRITY`, `ELOCKFILE_DRIFT`, `E404`, etc.).

---

## 2. Command Surface & Scope Boundaries

### Active Command Matrix & Aliases
- `install` (aliases: `i`, `add`, `isntall`): Resolve, fetch, verify, unpack, link, run lifecycle scripts, and write lockfile v3.
  - Flags: `--save-dev` (`-D`), `--save-exact` (`-E`), `--save-prod` (`-P`, `-S`, `--save`), `--save-optional` (`-O`), `--save-peer`, `--no-save`, `--package-lock-only`, `--omit` (`dev`, `optional`, `peer`), `--offline`, `--ignore-scripts`, `--legacy-peer-deps`, `--strict-peer-deps`, `--registry`, `--cache`, scoped registries (`--@scope:registry=...`, `@scope:registry=...`).
- `ci` / `clean-install` (aliases: `clean-install`, `ic`): Clean install strictly from lockfile v3 (or v1/v2 migrated in memory). Rejects manifest/lockfile drift with immediate termination (`ELOCKFILE_DRIFT`) and zero network/filesystem side effects.
  - Flags: `--omit` (`dev`, `optional`, `peer`), `--offline`, `--ignore-scripts`, `--legacy-peer-deps`, `--strict-peer-deps`, `--package-lock-only`, `--registry`, `--cache`.
- `test` (aliases: `t`, `tst`): Dedicated shortcut to execute package `test` script defined in `package.json`, passing arbitrary trailing arguments through to the underlying runner.
- `start`: Dedicated shortcut to execute package `start` script, forwarding arbitrary trailing arguments.
- `restart`: Dedicated shortcut to execute package `restart` script, forwarding arbitrary trailing arguments.
- `stop`: Dedicated shortcut to execute package `stop` script, forwarding arbitrary trailing arguments.
- `run` (alias: `run-script`): Execute scripts defined in `package.json` with appropriate `PATH`, environment variables, credential scrubbing, and process tree lifecycle controls.
  - When invoked without arguments (`rnpm run`), lists all available lifecycle scripts and custom user scripts alongside package ID.
  - Flags: `--workspaces` (`-w`, `ws`), `--workspace`, `--filter`, `--scope`, `--if-present`, `--ignore-scripts`.
- `exec` / `npx` (alias: `x`): Dynamic ephemeral package downloads and binary execution with isolated temporary workspaces and ancestor binary PATH inheritance.
  - Flags: `--registry`, `--cache`, `--offline`.
- `pack`: Package project files into a canonical npm-compatible `.tgz` archive with npm ignore/files filtering.
  - Flags: `--dry-run`, `--json`, `--pack-destination`.
- `uninstall` (aliases: `remove`, `rm`, `r`, `un`): Remove dependencies from `package.json`, mutate tree, re-hoist if necessary, update lockfile, and clean empty scope directories.
  - Flags: `--save-dev` (`-D`), `--save-optional` (`-O`), `--save-prod` (`-P`, `--save`).
- `update` (alias: `up`): Fetch latest versions matching declared semver ranges for registry dependencies, clean superseded packages, and update package.json/lockfile.
  - Flags: `--registry`, `--cache`, `--offline`, `--ignore-scripts`, `--legacy-peer-deps`.
- `prune`: Remove extraneous packages from `node_modules` not reachable from `package.json` manifest declarations or pruned by omit flags.
  - Flags: `--omit` (`dev`, `optional`, `peer`), `--production` (`-p`), `--dry-run`, `--json`.
- `pkg`: Programmatically inspect, mutate, or delete properties in `package.json` with dot-notated field path expressions.
  - Subcommands: `get <field...>`, `set <key>=<val...>`, `delete <field...>`.
  - Flags: `--prefix`, `--json`.
- `audit`: Security vulnerability auditing parsing lockfile trees, querying bulk advisory endpoints using shared `rnpm-config` and `rnpm-registry` stacks, generating structured JSON / human-readable reports, classifying dependencies (`prod`, `dev`, `optional`, `peer`, `peerOptional`), and enforcing `--audit-level` exit thresholds (`info`, `low`, `moderate`, `high`, `critical`, `none`).
  - Flags: `--registry`, `--json`, `--audit-level`, `--dry-run`.
- `cache`: Content-addressable cache management (`clean [--force]` and `verify`).
  - Flags: `--cache`.
- `list` / `ls` (aliases: `la`, `ll`): Inspect installed `node_modules` dependency tree (or lockfile with `--package-lock-only`). Formats hierarchical tree matching npm (`+-- `, `` `-- ``, `|   `) with markers (`extraneous`, `invalid`, `UNMET DEPENDENCY`, `deduped`). Supports `--depth=<n>`, `--all` (`-a`), `--json`, `--long` (`-l`, and aliases `la`/`ll`), `--parseable` (`-p`), `--package-lock-only`, `--omit`, and package name filters. Exits with code `1` and `ELSPROBLEMS` diagnostic if problems exist.
- `view` / `info` (aliases: `v`, `show`): Query package metadata from the npm registry for `<pkg>[@<version_or_tag>] [<field>[.<subfield>]...]`. Resolves dist-tags, exact versions, and semver ranges. Supports nested dot notation field extraction, multi-field output, full manifest display, and `--json`.
- `outdated`: Inspect declared vs installed dependency versions and query registry packuments to determine `wanted` (max satisfying version) and `latest` (`dist-tags.latest`). Tabular output with columns `Package`, `Current`, `Wanted`, `Latest`, `Location`, `Depended by`. Supports `--long` (`-l`), `--json`, `--parseable` (`-p`), and package filters. Exits with code `1` if any outdated packages are found, `0` if up to date.
- `query`: Execute CSS-like selector queries on the dependency tree (`:root`, `[name=<pkg>]`, `[version^=<v>]`, `:outdated`, `:extraneous`, `:missing`, `:invalid`, `:dev`, `:prod`, `:optional`, `:peer`, child `>`, descendant space, union `,`). Emits matching package nodes as structured JSON array matching npm query schema.

### Supported Protocol Surface
- **Registry Packages:** Ordinary registry dependencies, dist-tags, semver ranges, and scoped packages (`@scope/pkg`).
- **Local Directories (`file:../dir`):** Linked via unprivileged directory junctions (Windows) or symlinks (Unix).
- **Local Archives (`file:./pkg.tgz`):** In-memory manifest extraction, streaming unpacking, and SSRI sha512 integrity generation.
- **Workspaces (`workspace:*`, `workspace:^`, `workspace:~`):** Multi-tier workspace DAGs, cross-package linking, and topological script execution.
- **Git Dependencies (`github:user/repo`, `gitlab:`, `bitbucket:`, `git+https://`, `git+ssh://`, `git://`, `git+file://`):** Remote repositories with optional commit-ish / tag specs.
- **Direct HTTP/HTTPS Tarball URLs (`https://.../pkg-1.0.0.tgz`):** Direct remote tarball archives with cross-origin credential protection.

### Unsupported Protocols (Gate E)
Protocols outside the supported surface (e.g., `ftp://`, `svn://`, `sftp://`, `hg+https://`, `cvs://`, `telnet://`) are strictly rejected with exit code `1` and structured npm-compatible diagnostic:
```text
npm error code EUNSUPPORTEDPROTOCOL
npm error Unsupported URL Type "<protocol>": <spec>
```
Regression fixture: `benchmarks/fixtures/gate-e-unsupported-protocol/`.

### Unsupported Flags Handling (Gate E)
Flags not supported or outside the active scope of `rnpm` (e.g., `--global`, `-g`, `--save-bundle`, `--production` on install) terminate immediately with exit code `1` and a structured diagnostic:
```text
npm error code ERR_UNSUPPORTED_FLAG
npm error The flag '<flag>' is not supported by rnpm.
npm error See docs/compatibility-contract.md for supported options.
```
*(Note: `--legacy-peer-deps` is fully supported on `install`, `ci`, and `update` commands).*

### Unsupported & Deferred Commands
- `publish`: Package publishing (deferred).
- `login`, `adduser`, `logout`, `token`, `team`: Account management and auth tokens.
- `fix`: Vulnerability automated remediation.
- `deprecate`, `access`, `profile`, `org`, `doctor`, `fund`, `explain`, `search`, `stars`, `star`, `unstar`, `ping`, `whoami`, `version`, `init`, `create`.
- Writing legacy lockfile formats (v1 or v2).

### Drop-in Compatibility Target & Unsupported Command Handling (DEC-004)
DEC-004 formalizes the complete drop-in target for `npm 11.x`: all standard package management, inspection, publishing, lifecycle, linking, and query workflows are supported with drop-in compatibility.
When a user invokes an unsupported or deferred command during the transition, `rnpm` terminates immediately with exit code `1` and a structured diagnostic:
```text
npm error code ERR_UNSUPPORTED_COMMAND
npm error The command '<command>' is not currently implemented in rnpm.
npm error See docs/compatibility-contract.md for the active compatibility surface.
```

---

## 3. Architecture-Blocking Decisions

| ID | Title | Status | Contract & Implementation Decision |
|---|---|---|---|
| **DEC-001** | Semver Implementation | Accepted | Custom `node-semver`-compatible parser. The standard Rust `semver` crate grammar is incompatible with npm (diverges on loose versions, `x` ranges, hyphen ranges, prerelease precedence, and `0.x` caret rules). |
| **DEC-002** | Performance Registry | Accepted | Performance checkpoints (Gates A, D, F) exclusively use a pinned loopback registry (`http://127.0.0.1:4873/`). Public upstream (`npmjs.org`) is reserved for smoke tests and functional fixtures. |
| **DEC-003** | Windows Process Accounting | Accepted | Benchmark instrumentation uses Windows Job Objects (`QueryInformationJobObject`) to aggregate CPU time, peak working set, commit charge, and I/O across the entire process tree. |
| **DEC-004** | Full npm 11.x Drop-in Target | Accepted | Define exact npm 11.x drop-in target: all standard package management, inspection, publishing, lifecycle, linking, and query workflows are supported with drop-in compatibility. Active command matrix and flag surface expanded. Deferred commands terminate with structured `ERR_UNSUPPORTED_COMMAND` error and non-zero exit code during parallel transition. |
| **DEC-005** | Core code isolation & Worktrees | Accepted | Mandatory rule: Any modifications to core crates (`crates/rnpm-*`) must be performed within dedicated git worktrees. This directive applies to all successor threads in the lineage. |

---

## 4. Frozen Compatibility Specifications

### 4.1. Package Identity, Aliases & Overrides
- **Package Identity vs Alias:** In-memory models must separate `spec_name` (the alias key in `dependencies`) from `target_package` (the real package to download).
- **Aliases Syntax:** Support `npm:<real-name>@<version-spec>` (e.g. `"my-react": "npm:react@^18.2.0"`). Reification must install `react` files into directory `node_modules/my-react`.
- **Overrides Engine (npm RFC 36):**
  - Support root overrides: `"overrides": { "foo": "1.2.3" }`.
  - Support nested overrides: `"overrides": { "bar": { "foo": "1.2.3" } }`.
  - Support spec-targeted overrides: `"overrides": { "foo@^1.0.0": "1.2.3" }`.
  - Support package reference aliases: `"overrides": { "foo": "$bar" }`.
  - Overrides mutate the dependency resolution graph before tree calculation.

### 4.2. Local Dependencies: `file:` Protocol
- **Distinguish Directories vs Tarballs:**
  - `file:../local-dir`: Directory reference. Must be linked via platform directory link (NTFS Junction on Windows, symlink on Unix). Never copy or re-pack.
  - `file:../local-pkg.tgz`: Tarball archive. Must be unpacked, verified, and installed like a registry package.

### 4.3. Optional Dependencies Multi-Stage Failure Isolation
An optional dependency failure must NEVER fail the parent installation. Failure isolation applies at four distinct stages:
1. **Metadata Resolution:** If an optional dependency fails to resolve (e.g. 404 from registry), omit node from graph and log warning.
2. **Tarball Download & Integrity:** If tarball download fails (network drop) or integrity check fails, omit node and proceed.
3. **Platform Filtering:** Evaluate package `os`, `cpu`, and `libc` manifest fields against host environment. If incompatible, skip installation.
4. **Lifecycle Build Scripts:** If an optional dependency has a native build script (`binding.gyp` / `install`) that exits with a non-zero exit code, catch error, log warning, remove optional package from `node_modules`, and complete parent install with exit code `0`.

### 4.4. Registry HTTP & Authentication Security
- **Abbreviated Metadata:** Prefer `Accept: application/vnd.npm.install-v1+json` to reduce network payload by up to 90%.
- **Scoped Package URL Encoding:** Encode scoped packages in registry paths (e.g. `@mycorp/foo` -> `/@mycorp%2ffoo`).
- **HTTP Error Diagnostics:** Translate HTTP status codes to npm-compatible error codes:
  - `401 Unauthorized` -> `E401`
  - `403 Forbidden` -> `E403`
  - `404 Not Found` -> `E404`
  - `429 Too Many Requests` -> `E429`
- **Credential Containment & Redirect Security (Security Boundary):**
  - **Redirect Auth Stripping:** If an HTTP redirect points to a different host (e.g. CDN storage bucket on S3/Cloudflare), `Authorization` headers must be stripped immediately.
  - **Redirect Cycle Detection:** Maintain a set of visited URLs (`seen_redirect_urls`); abort immediately with `RegistryError::SecurityViolation` upon detecting a redirect loop.
  - **Redirect Scheme Restriction:** Strictly reject redirects to non-HTTP(S) schemes (e.g. `file:`, `data:`, `javascript:`, `ftp:`) with `RegistryError::SecurityViolation`.
  - **CRLF Header Defense:** Validate `Location` header against CR/LF characters (`\r`, `\n`) to prevent HTTP response splitting.
  - **Process Environment:** Auth tokens (`_authToken`) and passwords must NEVER be passed into environment variables (`process.env`) of child lifecycle scripts.

### 4.5. Lockfile v3 Serialization & Migration
- **Lockfile Format:** Generate and read `lockfileVersion: 3`.
- **Root Package:** Lockfile must contain entry `packages[""]` representing root package manifest and dependencies.
- **POSIX Path Keys:** All package keys in `packages` must use POSIX forward slashes (`/`), even on Windows (e.g. `node_modules/@scope/pkg`).
- **Preserved Descriptors:** Lockfile entries must preserve: `version`, `resolved`, `integrity`, `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `bin`, `license`, `engines`, `cpu`, `os`, `libc`, `inBundle`, `hasInstallScript`.
- **v1 / v2 Migration:** Read-only automatic migration. Lockfile v1 (nested `dependencies` tree) and v2 (hybrid) must be parsed into the unified in-memory graph and serialized as v3.
- **Hidden Lockfile:** Maintain `node_modules/.package-lock.json` to record actual disk state.
- **`npm ci` Drift Detection:** If `package.json` dependencies diverge from `package-lock.json`, `ci` must exit with `ELOCKFILE_DRIFT` with zero disk mutation and zero network requests.

### 4.6. Cache Architecture & Atomic Operations
- **Content-Addressable Storage:** Mirror `cacache` directory layout (`content-v2` and `index-v5`).
- **Atomic Staging:**
  - Write files to `<cache-dir>/_cacache/tmp/` first.
  - Temporary files and final cache destination must reside on the same filesystem/drive to ensure atomic rename (`MoveFileExW` / `rename`).
  - Calculate SSRI integrity streamingly during write.
  - Verify hash before renaming into `content-v2/<algo>/<h0>/<h1>/<hash>`.
- **Cross-Process Locking:** Use OS file locks (`LockFileEx` / `flock`).
- **Stale Lock Recovery:** Detect dead process IDs (PIDs) or expired timestamps (> 60s) and reclaim locks.
- **Self-Healing:** If a cached tarball fails decompression or integrity verification, unlink corrupted blob and index entry, fetch fresh copy from registry, and update cache.

### 4.7. Tar Extraction Security Boundary & Tar Bomb Defenses
- **Path Traversal Defense:** Reject tar entries containing `..`, absolute paths (leading `/` or `C:\`), or drive letters.
- **Symlink & Hardlink Escape:** Symlinks and hardlinks pointing outside the target package root directory are strictly rejected.
- **Windows Forbidden Device Names:** Reject entries matching `CON`, `PRN`, `AUX`, `NUL`, `COM1`鈥揱COM9`, `LPT1`鈥揱LPT9` (including extensions like `NUL.txt`).
- **Trailing Characters:** Strip or reject trailing dots (`.`) and spaces in filenames on Windows.
- **Mode Bit Sanitization:** Strip SUID (04000) and SGID (02000) bits. Normalize file permissions to `0644` (regular file) or `0755` (executable / binary).
- **Directory Prefix Stripping:** Strip exactly the standard top-level `package/` prefix from tar archives.
- **Tar Bomb Resource Limits:**
  - Max entry count: 50,000 files per package.
  - Max uncompressed size: 512 MB per package (configurable).
  - Max compression ratio: 100:1.
  - If any limit is exceeded, abort extraction immediately, purge staged files, and exit with `ETARBOMB`.

### 4.8. Multi-Hash Integrity Verification
- **SSRI Parsing:** Parse `sha512-...`, `sha384-...`, `sha256-...`, `sha1-...`.
- **Strongest Hash Rule:** Group hashes by algorithm. Evaluate in order: `sha512` > `sha384` > `sha256` > `sha1`.
- If the strongest declared hash fails, verification **FAILS immediately with `EINTEGRITY`**, even if a weaker hash matches.

### 4.9. Platform Filesystem & Windows Resilience
- **Unprivileged Windows Directory Links:** Use NTFS Junctions (`IO_REPARSE_TAG_MOUNT_POINT`) for directory links (workspaces, `file:` packages). Junctions require no Administrator rights and work with Developer Mode disabled.
- **Safe Junction Pruning:** When removing or cleaning a junction, use `RemoveDirectoryW` (unlinking the reparse point). **NEVER recursively delete inside a junction target!**
- **Long Path Support:** All Windows filesystem operations must prepend `\\?\` to absolute paths to support paths exceeding 260 characters (`MAX_PATH`).
- **Transient Lock Retries (`EBUSY` / `EPERM`):** Implement exponential backoff retry loop (10 attempts, 50ms initial delay up to 1000ms with jitter) when file deletion, directory removal, or renaming fails due to Windows antivirus or search indexer file locks.
- **Executable Shims:** For binaries declared in `bin`:
  - Unix: Symlink + `chmod 0755`. Normalize shebang CRLF to LF.
  - Windows: Generate trio `<name>`, `<name>.cmd`, `<name>.ps1`. Safely escape shell metacharacters in batch arguments.

### 4.10. Lifecycle Scripts & Process Management
- **Hierarchical PATH:** Prepend current and ancestor `node_modules/.bin` and the active Node.js binary directory to `PATH`.
- **Environment Variables:** Set `INIT_CWD`, `npm_lifecycle_event`, `npm_lifecycle_script`, `npm_package_name`, `npm_package_version`, `npm_package_json`, `npm_config_*`.
- **Credential Scrubbing:** Filter out all authentication tokens and sensitive credentials from environment variables before spawning scripts.
- **Execution Order:** Bottom-up topological execution: dependency lifecycle scripts run before parent packages.
- **Prepare Rules:**
  - Root package executes `prepare` on `install`.
  - Registry dependencies **NEVER** run `prepare`.
  - Local `file:` dependencies run `prepare`.
- **Shell Runner:** Windows uses `cmd.exe /d /s /c`; Unix uses `/bin/sh -c`.
- **Script Skipping:** Support `--ignore-scripts`.
- **Process Tree Cleanup:** On abort / interrupt, kill the complete child process tree using Windows Job Objects or Unix process groups.

### 4.11. Manifest Parsing Resilience
- **UTF-8 BOM:** Strip UTF-8 Byte Order Mark (`0xEF, 0xBB, 0xBF`) if present.
- **Malformed JSON:** Emit structured `EJSONPARSE` error with line and column numbers.
- **Missing Fields:** Default missing `dependencies`, `devDependencies`, `peerDependencies`, `scripts` to empty objects.

### 4.12. Workspaces Contract
- **Discovery:** Expand `workspaces` globs (e.g. `packages/*`, `apps/**`) using POSIX-style globbing.
- **Workspace Protocols:** Resolve `workspace:*`, `workspace:^`, `workspace:~` to local sibling packages.
- **Topological Sorting:** Compute dependency DAG of workspace packages; execute lifecycle scripts in topological order.
- **Cycle Handling:** Cyclic dependencies between local workspaces must be permitted without deadlocks or infinite loops.

---

## 5. Comprehensive Error Code Matrix

| Error Code | Exit Code | Trigger Condition |
|---|---|---|
| `ERESOLVE` | 1 | Conflicting peer dependencies that cannot be resolved |
| `ETARGET` | 1 | Package version or tag not found in registry |
| `E404` | 1 | Package not found in registry |
| `E401` | 1 | Authentication credentials missing or invalid |
| `E403` | 1 | Permission denied for registry resource |
| `E429` | 1 | Registry rate limit exceeded |
| `EINTEGRITY` | 1 | Tarball checksum does not match manifest/lockfile SSRI |
| `ELOCKFILE_DRIFT` | 1 | `npm ci` detected divergence between `package.json` and `package-lock.json` |
| `EUNSUPPORTEDPROTOCOL` | 1 | Unsupported protocol in package specifier |
| `ETARBOMB` | 1 | Tarball exceeded safe entry count, size, or compression ratio limits |
| `ESECURITY` | 1 | Tarball contained traversal (`..`), absolute paths, or escaping symlinks |
| `EJSONPARSE` | 1 | Malformed `package.json` or `package-lock.json` |
| `ERR_UNSUPPORTED_COMMAND` | 1 | Attempted invocation of an out-of-scope or deferred npm command |
| `ERR_UNSUPPORTED_FLAG` | 1 | Attempted invocation of an unsupported flag |
| `ENOLOCK` | 1 | Command requires an existing package-lock.json |
| `ENOENT` | 1 | File or package.json not found |
| `ENOWORKSPACES` | 1 | No workspace packages discovered |
| `EUNKNOWN` | 1 | Unclassified runtime error |
| `SIGINT` | 130 | Process terminated via Ctrl+C / interrupt signal |
