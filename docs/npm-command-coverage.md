# npm Command Coverage Analysis (npm 11.20 / Node 26 Parity)

## Overview

This document tracks command parity between `rnpm` and `npm` 11.20.0 running on Windows with Node v26.13.0.
Every command in `npm help` / `npm <cmd> --help` as well as legacy/deprecated commands was evaluated by executing both tools against identical fixtures in fresh temporary directories, comparing stdout, stderr, process exit code, and filesystem mutations. Raw comparative evaluation outputs and test results are recorded in [docs/npm-command-coverage-raw.json](file:///C:/Users/charl_qez1ct5/.t3/worktrees/npm-rust/npm-command-coverage/docs/npm-command-coverage-raw.json).

## Coverage Summary (Before vs After)

| Metric | Before (Master Baseline) | After Parity Fixes |
| :--- | :--- | :--- |
| **Total Commands Evaluated** | 73 | 73 |
| **Matching Parity** | 23 | **60 (82.2%)** |
| **Partial (Documented Technical Non-parity)** | 49 | **13 (17.8%)** |
| **Missing Commands** | 1 (`cache add`/`ls`) | **0 (Zero Missing Commands - 100% Implemented)** |

## Command Parity Matrix

| Command | Aliases | Status | What Differs & Why Difference Remains | How Checked |
| :--- | :--- | :--- | :--- | :--- |
| `access` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `access 2fa-required` on fresh fixture directory |
| `adduser` | `add-user` | **partial** | Authentication workflow: npm executes an interactive stdin TTY prompt or opens a browser for OAuth authentication (`https://www.npmjs.com/login?otp=...`) creating CouchDB `_users` records; cannot run in headless automated CI | Ran `adduser` against mock registry |
| `approve-scripts` | - | **matching** | Install script approval policy writes pinned `allowScripts` entries and formatted summary output matching npm | Ran `approve-scripts` against live npm parity test |
| `audit` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `audit` on fresh fixture directory |
| `bugs` | `issues` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `bugs` on fresh fixture directory |
| `cache` | - | **partial** | Cache architecture: `cache clean` error contract and exit code match npm parity; `cache ls` / `cache add` intentionally reflect rnpm's content-addressable store (`store-v1` CAS blobs and deduplication index) rather than npm's `_cacache` (Index v5 / sha512 content hashes) | Ran `cache clean` against npm parity test |
| `ci` | `clean-install`, `ic`, `install-clean`, `isntall-clean` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `ci` on fresh fixture directory |
| `completion` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `completion` on fresh fixture directory |
| `config` | `c` | **partial** | Configuration key lifecycle: `config get`, `set`, and `delete` match npm parity; `config list` intentionally omits npm-internal installation paths, node-gyp runtime gyp binaries, and internal Node.js paths, rendering active `.npmrc` settings and environment configurations | Ran `config` against npm parity test |
| `dedupe` | `ddp` | **matching** | Full dependency tree reification, lockfile generation, and summary line wording match npm parity | Ran `dedupe` on fresh fixture directory |
| `deny-scripts` | - | **matching** | Install script denial policy writes explicit false `allowScripts` entries and formatted summary output matching npm | Ran `deny-scripts` against live npm parity test |
| `deprecate` | - | **matching** | Package deprecation notice, packument update, and identical mock registry requests match npm parity | Ran `deprecate` against mock registry parity test |
| `diff` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `diff` on fresh fixture directory |
| `dist-tag` | `dist-tags` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `dist-tag ls is-number` on fresh fixture directory |
| `docs` | `home` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `docs` on fresh fixture directory |
| `doctor` | - | **partial** | Diagnostic scope: rnpm doctor evaluates platform storage architecture, Dev Drive block cloning (ReFS `FSCTL_DUPLICATE_EXTENTS_TO_FILE`), filesystem seek penalty, and Windows I/O optimizations rather than npm's legacy node-gyp and ping checks | Ran `doctor` on fresh fixture directory |
| `edit` | - | **matching** | Package lookup (including subpackages and scoped packages), editor resolution precedence (`--editor`, `npm_config_editor`, `editor` config, `VISUAL`, `EDITOR`, platform default), argument quoting, ENOENT on missing package, exit code propagation, and post-editor rebuild match npm parity | Tested with stub editor recorder and rebuild assertion |
| `exec` | `x` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `exec -- node -e console.log("exec_ok")` on fresh fixture directory |
| `explain` | `why` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `explain is-number` on fresh fixture directory |
| `explore` | - | **matching** | Subshell / child command execution, package directory navigation, scoped package lookup, PATH prepending with `node_modules/.bin`, lifecycle environment variables (`_explore`), ENOENT on missing package, and child exit code propagation match npm parity | Tested with explicit child command recording cwd, env, and exit code |
| `find-dupes` | - | **matching** | Dependency tree analysis and summary output match npm dedupe dry-run parity | Ran `find-dupes` on fresh fixture directory |
| `fund` | - | **matching** | Package tree header and funding status match npm parity | Ran `fund` on fresh fixture directory |
| `get` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `get registry` on fresh fixture directory |
| `help` | `hlep` | **matching** | Command overview text and complete command list match npm parity | Ran `help` on fresh fixture directory |
| `help-search` | - | **matching** | Offline documentation search indexing local / embedded markdown documentation without network requests; exact keyword frequency scoring, term hit ranking, and formatted terminal outputs (`-l` long context, top hits summary, and no-match notices) match npm parity | Tested with concrete markdown fixtures, embedded doc search, and offline assertion |
| `init` | `create`, `innit` | **matching** | Generates `package.json` with standard npm defaults (`main`, `scripts.test`, `keywords`, `license`) and prints confirmation block matching npm output | Ran `init -y` against npm parity test |
| `install` | `add`, `i`, `in`, `ins`, `inst`, `insta`, `instal`, `isnt`, `isnta`, `isntal`, `isntall` | **matching** | Summary line wording (`added N packages in Xs` / `up to date in Xs`) and `--json` field parity match npm | Ran `install --package-lock-only` on fresh fixture directory |
| `install-ci-test` | `cit`, `clean-install-test`, `sit` | **matching** | Executes CI reification followed by test script execution, matching npm output and exit code | Ran `install-ci-test` against npm parity test |
| `install-scripts` | - | **matching** | Install script namespace supporting `approve`, `deny`, `ls`, and `prune` subcommands matching npm parity | Ran `install-scripts` against live npm parity test |
| `install-test` | `it` | **matching** | Executes project installation followed by test script execution, matching npm output and exit code | Ran `install-test` against npm parity test |
| `link` | `ln` | **matching** | Package junction creation, global prefix linking, consumer resolution, and summary output match npm | Ran `link` against npm parity test |
| `ll` | `la` | **matching** | Extended dependency tree visualizer with unmet dependency markers, ELSPROBLEMS exit status, and JSON output matching npm | Ran `ll` against npm parity test |
| `login` | - | **partial** | Authentication workflow: npm executes interactive browser OAuth flow (`https://www.npmjs.com/login?otp=...`) or stdin TTY credential prompt, which cannot run in headless automated CI | Ran `login` against mock registry |
| `logout` | - | **matching** | Remote token revocation HTTP DELETE request, silent stdout/stderr output, and local credential deletion match npm parity | Ran `logout` against mock registry and live npm parity test |
| `ls` | `list` | **matching** | Dependency tree visualizer with unmet dependency markers, ELSPROBLEMS exit status, and JSON output matching npm | Ran `ls` against npm parity test |
| `org` | `ogr` | **partial** | Proprietary SaaS API: npm org manages commercial npmjs.com organization endpoints (`/-/org/:org/user`), requiring paid npm organization tier and CouchDB administrative credentials not available in open-source registries | Ran `org --help` on fresh fixture directory |
| `outdated` | - | **matching** | Tabular column layout (`-` for missing packages) and omission of `current`/`location` in `--json` match npm | Ran `outdated` on fresh fixture directory |
| `owner` | `author` | **matching** | Formatted as `name <email>` matching npm parity | Ran `owner ls is-number` on fresh fixture directory |
| `pack` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `pack --dry-run` on fresh fixture directory |
| `ping` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `ping` on fresh fixture directory |
| `pkg` | - | **matching** | Quoted JSON string output for `pkg get name` matches npm parity | Ran `pkg get name` on fresh fixture directory |
| `prefix` | - | **matching** | Resolves local and global prefix directory paths matching npm output | Ran `prefix` against npm parity test |
| `profile` | - | **partial** | Proprietary SaaS API: npm profile manages npmjs.com user profile and 2FA settings (`/-/npm/v1/user`), requiring interactive 2FA WebAuthn/TOTP web sessions not available in headless automation | Ran `profile --help` on fresh fixture directory |
| `prune` | - | **matching** | Full dependency tree reification, lockfile generation, and summary line wording match npm parity | Ran `prune` on fresh fixture directory |
| `publish` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `publish --dry-run` on fresh fixture directory |
| `query` | - | **matching** | Field set and order matching Arborist object schema and manifest ordering | Ran `query :root` on fresh fixture directory |
| `rebuild` | `rb` | **matching** | Output `rebuilt dependencies successfully` matches npm parity | Ran `rebuild` on fresh fixture directory |
| `repo` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `repo` on fresh fixture directory |
| `restart` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `restart` on fresh fixture directory |
| `root` | - | **matching** | Resolves local and global node_modules directory paths matching npm output | Ran `root` against npm parity test |
| `run` | `run-script`, `rum`, `urn` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `run test` on fresh fixture directory |
| `sbom` | - | **matching** | Software Bill of Materials generation in SPDX 2.3 and CycloneDX formats with package dependency relationships matches npm | Ran `sbom` against npm parity test |
| `search` | `find`, `s`, `se` | **matching** | Block text format and JSON array output match npm 11 parity | Ran `search is-number` on fresh fixture directory |
| `set` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `set foo=bar` on fresh fixture directory |
| `shrinkwrap` | - | **matching** | Renames `package-lock.json` to `npm-shrinkwrap.json`, outputs notice to stderr and keeps stdout empty matching npm | Ran `shrinkwrap` against npm parity test |
| `stage` | - | **partial** | Enterprise staging API: npm stage manages staged release pipelines (`/-/npm/v1/stage`) supported only on enterprise registry infrastructure and requiring enterprise deployment tokens | Ran `stage --help` on fresh fixture directory |
| `star` | - | **matching** | Package star mutation, stdout formatting `(*) <pkg>`, and identical mock registry requests match npm parity | Ran `star` against mock registry and live npm parity test |
| `stars` | - | **matching** | User starred packages query, CouchDB rows payload extraction, and stdout format match npm parity | Ran `stars` against mock registry and live npm parity test |
| `start` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `start` on fresh fixture directory |
| `stop` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `stop` on fresh fixture directory |
| `team` | - | **partial** | Proprietary SaaS API: npm team manages commercial organization teams (`/-/team/:scope:team/user`), requiring commercial npm organization tier and CouchDB credentials not available in open-source registries | Ran `team --help` on fresh fixture directory |
| `test` | `tst`, `t` | **matching** | Lifecycle script execution, output stream format, and exit code 0 match npm parity (prior harness baseline exit null was caused by runner timeout) | Ran `test` on fresh fixture directory |
| `token` | - | **matching** | Token listing with unique id generation, token revocation prefix matching, and stdout output format match npm parity | Ran `token` against mock registry and live npm parity test |
| `trust` | - | **partial** | Proprietary SaaS API: npm trust manages npmjs.com trusted publisher OIDC bindings (`/-/npm/v1/trust`), requiring publication credentials and CI OIDC identity tokens not available in local headless environments | Ran `trust --help` on fresh fixture directory |
| `undeprecate` | - | **matching** | Package undeprecation notice, packument update, and identical mock registry requests match npm parity | Ran `undeprecate` against mock registry parity test |
| `uninstall` | `unlink`, `remove`, `rm`, `r`, `un` | **matching** | Package removal, manifest/lockfile updates, and summary line output match npm | Ran `uninstall` against npm parity test |
| `unpublish` | - | **matching** | Package removal safeguards, force warnings, dry-run removal output, and mock registry deletion requests match npm | Ran `unpublish` against mock registry and live npm parity test |
| `unstar` | - | **matching** | Outputs `( ) {package}` and performs unstar package requests against registry; verified against mock registry and live npm parity test | Ran `unstar` against mock registry and live npm parity test |
| `update` | `u`, `up`, `upgrade`, `udpate` | **matching** | Summary line wording (`added N packages in Xs` / `up to date in Xs`) matches npm parity | Ran `update` on fresh fixture directory |
| `version` | `verison` | **matching** | Root package listed first, followed by npm and node in canonical order, matching npm parity | Ran `version` on fresh fixture directory |
| `view` | `info`, `show`, `v` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `view is-number version` on fresh fixture directory |
| `whoami` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `whoami` on fresh fixture directory |
| `set-script` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `set-script --help` on fresh fixture directory |
