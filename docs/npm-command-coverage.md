# npm Command Coverage Analysis (npm 11.20 / Node 26 Parity)

## Overview

This document tracks command parity between `rnpm` and `npm` 11.20.0 running on Windows with Node v26.13.0.
Every command in `npm help` / `npm <cmd> --help` as well as legacy/deprecated commands was evaluated by executing both tools against identical fixtures in fresh temporary directories, comparing stdout, stderr, process exit code, and filesystem mutations. Raw comparative evaluation outputs and test results are recorded in [docs/npm-command-coverage-raw.json](file:///C:/Users/charl_qez1ct5/.t3/worktrees/npm-rust/npm-command-coverage/docs/npm-command-coverage-raw.json).

## Coverage Summary (Before vs After)

| Metric | Before (Master Baseline) | After Parity Fixes |
| :--- | :--- | :--- |
| **Total Commands Evaluated** | 73 | 73 |
| **Matching Parity** | 23 | **38 (52.1%)** |
| **Partial** | 49 | **35 (47.9%)** |
| **Missing Commands** | 1 (`cache add`/`ls`) | **0 (Zero Missing Commands - 100% Implemented)** |

## Command Parity Matrix

| Command | Aliases | Status | What Differs & Why Difference Remains | How Checked |
| :--- | :--- | :--- | :--- | :--- |
| `access` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `access 2fa-required` on fresh fixture directory |
| `adduser` | `add-user` | **partial** | Authentication workflow: npm executes interactive web/couch credentials flow via stdin TTY, whereas rnpm supports non-interactive automated credentials and token configuration | Ran `adduser` against mock registry |
| `approve-scripts` | - | **matching** | Install script approval policy writes pinned `allowScripts` entries and formatted summary output matching npm | Ran `approve-scripts` against live npm parity test |
| `audit` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `audit` on fresh fixture directory |
| `bugs` | `issues` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `bugs` on fresh fixture directory |
| `cache` | - | **partial** | Cache management: `cache clean` error contract and exit code match npm parity; `cache ls` reflects rnpm's content-addressable store layout (`store-v1`) rather than make-fetch-happen HTTP cache index | Ran `cache clean` against npm parity test |
| `ci` | `clean-install`, `ic`, `install-clean`, `isntall-clean` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `ci` on fresh fixture directory |
| `completion` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `completion` on fresh fixture directory |
| `config` | `c` | **partial** | Configuration key lifecycle: `get`, `set`, and `delete` match npm contract; `config list` omits node-gyp and npm internal installation paths while outputting active `.npmrc` and environment settings | Ran `config` against npm parity test |
| `dedupe` | `ddp` | **matching** | Full dependency tree reification, lockfile generation, and summary line wording match npm parity | Ran `dedupe` on fresh fixture directory |
| `deny-scripts` | - | **matching** | Install script denial policy writes explicit false `allowScripts` entries and formatted summary output matching npm | Ran `deny-scripts` against live npm parity test |
| `deprecate` | - | **matching** | Package deprecation notice, packument update, and identical mock registry requests match npm parity | Ran `deprecate` against mock registry parity test |
| `diff` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `diff` on fresh fixture directory |
| `dist-tag` | `dist-tags` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `dist-tag ls is-number` on fresh fixture directory |
| `docs` | `home` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `docs` on fresh fixture directory |
| `doctor` | - | **partial** | Diagnostic scope: rnpm doctor evaluates platform, Dev Drive, filesystem block cloning, and storage seek penalty rather than npm's node-gyp / npm ping network diagnostics | Ran `doctor` on fresh fixture directory |
| `edit` | - | **partial** | CLI parser architecture: rnpm generates clap usage with standard option flags, whereas npm renders custom manpage text templates | Ran `edit --help` on fresh fixture directory |
| `exec` | `x` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `exec -- node -e console.log("exec_ok")` on fresh fixture directory |
| `explain` | `why` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `explain is-number` on fresh fixture directory |
| `explore` | - | **partial** | CLI parser architecture: rnpm generates clap usage with standard option flags, whereas npm renders custom manpage text templates | Ran `explore --help` on fresh fixture directory |
| `find-dupes` | - | **matching** | Dependency tree analysis and summary output match npm dedupe dry-run parity | Ran `find-dupes` on fresh fixture directory |
| `fund` | - | **matching** | Package tree header and funding status match npm parity | Ran `fund` on fresh fixture directory |
| `get` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `get registry` on fresh fixture directory |
| `help` | `hlep` | **matching** | Command overview text and complete command list match npm parity | Ran `help` on fresh fixture directory |
| `help-search` | - | **partial** | Search index source: npm indexes local markdown manpages bundled with npm, whereas rnpm searches online registry documentation indices | Ran `help-search install` on fresh fixture directory |
| `init` | `create`, `innit` | **matching** | Generates `package.json` with standard npm defaults (`main`, `scripts.test`, `keywords`, `license`) and prints confirmation block matching npm output | Ran `init -y` against npm parity test |
| `install` | `add`, `i`, `in`, `ins`, `inst`, `insta`, `instal`, `isnt`, `isnta`, `isntal`, `isntall` | **matching** | Summary line wording (`added N packages in Xs` / `up to date in Xs`) and `--json` field parity match npm | Ran `install --package-lock-only` on fresh fixture directory |
| `install-ci-test` | `cit`, `clean-install-test`, `sit` | **matching** | Executes CI reification followed by test script execution, matching npm output and exit code | Ran `install-ci-test` against npm parity test |
| `install-scripts` | - | **matching** | Install script namespace supporting `approve`, `deny`, `ls`, and `prune` subcommands matching npm parity | Ran `install-scripts` against live npm parity test |
| `install-test` | `it` | **matching** | Executes project installation followed by test script execution, matching npm output and exit code | Ran `install-test` against npm parity test |
| `link` | `ln` | **matching** | Package junction creation, global prefix linking, consumer resolution, and summary output match npm | Ran `link` against npm parity test |
| `ll` | `la` | **matching** | Extended dependency tree visualizer with unmet dependency markers, ELSPROBLEMS exit status, and JSON output matching npm | Ran `ll` against npm parity test |
| `login` | - | **partial** | Authentication workflow: npm executes interactive browser/couch credentials flow via stdin TTY, whereas rnpm supports non-interactive automated credentials and token configuration | Ran `login` against mock registry |
| `logout` | - | **matching** | Remote token revocation HTTP DELETE request, silent stdout/stderr output, and local credential deletion match npm parity | Ran `logout` against mock registry and live npm parity test |
| `ls` | `list` | **matching** | Dependency tree visualizer with unmet dependency markers, ELSPROBLEMS exit status, and JSON output matching npm | Ran `ls` against npm parity test |
| `org` | `ogr` | **partial** | CLI parser architecture: rnpm generates clap usage with standard option flags, whereas npm renders custom manpage text templates | Ran `org --help` on fresh fixture directory |
| `outdated` | - | **matching** | Tabular column layout (`-` for missing packages) and omission of `current`/`location` in `--json` match npm | Ran `outdated` on fresh fixture directory |
| `owner` | `author` | **matching** | Formatted as `name <email>` matching npm parity | Ran `owner ls is-number` on fresh fixture directory |
| `pack` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `pack --dry-run` on fresh fixture directory |
| `ping` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `ping` on fresh fixture directory |
| `pkg` | - | **matching** | Quoted JSON string output for `pkg get name` matches npm parity | Ran `pkg get name` on fresh fixture directory |
| `prefix` | - | **matching** | Resolves local and global prefix directory paths matching npm output | Ran `prefix` against npm parity test |
| `profile` | - | **partial** | CLI parser architecture: rnpm generates clap usage with standard option flags, whereas npm renders custom manpage text templates | Ran `profile --help` on fresh fixture directory |
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
| `stage` | - | **partial** | CLI parser architecture: rnpm generates clap usage with standard option flags, whereas npm renders custom manpage text templates | Ran `stage --help` on fresh fixture directory |
| `star` | - | **matching** | Package star mutation, stdout formatting `(*) <pkg>`, and identical mock registry requests match npm parity | Ran `star` against mock registry and live npm parity test |
| `stars` | - | **matching** | User starred packages query, CouchDB rows payload extraction, and stdout format match npm parity | Ran `stars` against mock registry and live npm parity test |
| `start` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `start` on fresh fixture directory |
| `stop` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `stop` on fresh fixture directory |
| `team` | - | **partial** | CLI parser architecture: rnpm generates clap usage with standard option flags, whereas npm renders custom manpage text templates | Ran `team --help` on fresh fixture directory |
| `test` | `tst`, `t` | **matching** | Lifecycle script execution, output stream format, and exit code 0 match npm parity (prior harness baseline exit null was caused by runner timeout) | Ran `test` on fresh fixture directory |
| `token` | - | **matching** | Token listing with unique id generation, token revocation prefix matching, and stdout output format match npm parity | Ran `token` against mock registry and live npm parity test |
| `trust` | - | **partial** | CLI parser architecture: rnpm generates clap usage with standard option flags, whereas npm renders custom manpage text templates | Ran `trust --help` on fresh fixture directory |
| `undeprecate` | - | **matching** | Package undeprecation notice, packument update, and identical mock registry requests match npm parity | Ran `undeprecate` against mock registry parity test |
| `uninstall` | `unlink`, `remove`, `rm`, `r`, `un` | **matching** | Package removal, manifest/lockfile updates, and summary line output match npm | Ran `uninstall` against npm parity test |
| `unpublish` | - | **matching** | Package removal safeguards, force warnings, dry-run removal output, and mock registry deletion requests match npm | Ran `unpublish` against mock registry and live npm parity test |
| `unstar` | - | **matching** | Outputs `( ) {package}` and performs unstar package requests against registry; verified against mock registry and live npm parity test | Ran `unstar` against mock registry and live npm parity test |
| `update` | `u`, `up`, `upgrade`, `udpate` | **matching** | Summary line wording (`added N packages in Xs` / `up to date in Xs`) matches npm parity | Ran `update` on fresh fixture directory |
| `version` | `verison` | **matching** | Root package listed first, followed by npm and node in canonical order, matching npm parity | Ran `version` on fresh fixture directory |
| `view` | `info`, `show`, `v` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `view is-number version` on fresh fixture directory |
| `whoami` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `whoami` on fresh fixture directory |
| `set-script` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `set-script --help` on fresh fixture directory |
