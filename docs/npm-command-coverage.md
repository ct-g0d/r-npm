# npm Command Coverage Analysis (npm 11.20 / Node 26 Parity)

## Overview

This document tracks command parity between `rnpm` (master baseline) and `npm` 11.20.0 running on Windows with Node v26.13.0.
Every command in `npm help` / `npm <cmd> --help` as well as deprecated/legacy commands (e.g. `set-script`, `bin`) was evaluated by executing both tools against identical fixtures in fresh temporary directories, comparing stdout, stderr, process exit code, and filesystem mutations.

## Command Parity Matrix (Master Baseline)

| Command | Aliases | Status | What Differs | How Checked |
| :--- | :--- | :--- | :--- | :--- |
| `access` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `access 2fa-required` on fresh fixture directory |
| `adduser` | `add-user` | **partial** | stdout format differs: npm="Add a registry user account  Usage: npm adduser  Options: [--registry <registry>..." vs rnpm="Log in to a registry  Usage: rnpm.exe login [OPTIONS]  Options:       --registry..." | Ran `adduser --help` on fresh fixture directory |
| `approve-scripts` | - | **partial** | stdout format differs: npm="Approve install scripts for specific dependencies  Usage: npm approve-scripts <p..." vs rnpm="Manage lifecycle script approval policy  Usage: rnpm.exe approve-scripts [OPTION..." | Ran `approve-scripts --help` on fresh fixture directory |
| `audit` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `audit` on fresh fixture directory |
| `bugs` | `issues` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `bugs` on fresh fixture directory |
| `cache` | - | **missing** | Command not implemented in rnpm (reports unknown command); stdout format differs: npm="make-fetch-happen:request-cache:http://127.0.0.1:19876/custom.tgz make-fetch-hap..." vs rnpm="Unknown command: "cache"  To see a list of supported npm commands, run:   npm he..." | Ran `cache ls` on fresh fixture directory |
| `ci` | `clean-install, ic, install-clean, isntall-clean` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `ci` on fresh fixture directory |
| `completion` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `completion` on fresh fixture directory |
| `config` | `c` | **partial** | stdout format differs: npm="; "builtin" config from C:\Program Files\nodejs\node_modules\npm\npmrc  prefix =..." vs rnpm="; environment-related config audit = "false" fund = "false" update-notifier = "f..." | Ran `config list` on fresh fixture directory |
| `dedupe` | `ddp` | **partial** | File system changes differ: npm wrote [node_modules/, node_modules\.package-lock.json, node_modules\is-number/, node_modules\is-number\LICENSE, node_modules\is-number\README.md, node_modules\is-number\index.js, node_modules\is-number\package.json], rnpm wrote []; stdout format differs: npm="added 1 package in 2s..." vs rnpm="rnpm: tree is already deduplicated..." | Ran `dedupe` on fresh fixture directory |
| `deny-scripts` | - | **partial** | stdout format differs: npm="Deny install scripts for specific dependencies  Usage: npm deny-scripts <pkg> [<..." vs rnpm="Remove lifecycle script approval entries  Usage: rnpm.exe deny-scripts [OPTIONS]..." | Ran `deny-scripts --help` on fresh fixture directory |
| `deprecate` | - | **partial** | stdout format differs: npm="Deprecate a version of a package  Usage: npm deprecate <package-spec> <message> ..." vs rnpm="Mark package versions as deprecated  Usage: rnpm.exe deprecate [OPTIONS] <PACKAG..." | Ran `deprecate --help` on fresh fixture directory |
| `diff` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `diff` on fresh fixture directory |
| `dist-tag` | `dist-tags` | **partial** | stdout format differs: npm="latest: 7.0.0..." vs rnpm="latest: "7.0.0"..." | Ran `dist-tag ls is-number` on fresh fixture directory |
| `docs` | `home` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `docs` on fresh fixture directory |
| `doctor` | - | **partial** | stdout format differs: npm="Check the health of your npm environment  Usage: npm doctor [connection] [regist..." vs rnpm="Check the local npm/rnpm installation and machine performance diagnostics  Usage..." | Ran `doctor --help` on fresh fixture directory |
| `edit` | - | **partial** | stdout format differs: npm="Edit an installed package  Usage: npm edit <pkg>[/<subpkg>...]  Options: [--edit..." vs rnpm="Edit a package in the configured editor  Usage: rnpm.exe edit [OPTIONS] <PACKAGE..." | Ran `edit --help` on fresh fixture directory |
| `exec` | `x` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `exec -- node -e console.log("exec_ok")` on fresh fixture directory |
| `explain` | `why` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `explain is-number` on fresh fixture directory |
| `explore` | - | **partial** | stdout format differs: npm="Browse an installed package  Usage: npm explore <pkg> [ -- <command>]  Options: ..." vs rnpm="Explore a package in a shell  Usage: rnpm.exe explore [OPTIONS] <PACKAGE>  Argum..." | Ran `explore --help` on fresh fixture directory |
| `find-dupes` | - | **partial** | stdout format differs: npm="add is-number 7.0.0  added 1 package in 717ms..." vs rnpm="rnpm: find-dupes: no duplicate packages found..." | Ran `find-dupes` on fresh fixture directory |
| `fund` | - | **partial** | stdout format differs: npm="test-pkg@1.0.0..." vs rnpm="0 packages are looking for funding..." | Ran `fund` on fresh fixture directory |
| `get` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `get registry` on fresh fixture directory |
| `help` | `hlep` | **partial** | stdout format differs: npm="npm <command>  Usage:  npm install        install all the dependencies in your p..." vs rnpm="High performance Rust implementation of npm workflows  Usage: rnpm <COMMAND>  Co..." | Ran `help` on fresh fixture directory |
| `help-search` | - | **partial** | stdout format differs: npm="Top hits for "install" —————————————————————————————————————————————————————————..." vs rnpm="install	Minimal JavaScript module loader @antfu/install-pkg	Install package prog..." | Ran `help-search install` on fresh fixture directory |
| `init` | `create, innit` | **partial** | stdout format differs: npm="Wrote to C:\Users\charl_qez1ct5\.t3\userdata\antigravity-tmp\1160a0fb1bcd\run-UE..." vs rnpm="Wrote to C:\Users\charl_qez1ct5\.t3\userdata\antigravity-tmp\1160a0fb1bcd\run-UE..." | Ran `init -y` on fresh fixture directory |
| `install` | `add, i, in, ins, inst, insta, instal, isnt, isnta, isntal, isntall` | **partial** | stdout format differs: npm="up to date in 1s..." vs rnpm="rnpm: successfully installed 0 package(s) (cache hits: 0, misses: 0)..." | Ran `install --package-lock-only` on fresh fixture directory |
| `install-ci-test` | `cit, clean-install-test, sit` | **partial** | stdout format differs: npm="Install a project with a clean slate and run tests  Usage: npm install-ci-test  ..." vs rnpm="Install dependencies and run the CI test script  Usage: rnpm.exe install-ci-test..." | Ran `install-ci-test --help` on fresh fixture directory |
| `install-scripts` | - | **partial** | stdout format differs: npm="Manage install-script approvals for dependencies  Usage: npm install-scripts app..." vs rnpm="Install dependencies and run install scripts  Usage: rnpm.exe install-scripts [O..." | Ran `install-scripts --help` on fresh fixture directory |
| `install-test` | `it` | **partial** | stdout format differs: npm="Install package(s) and run tests  Usage: npm install-test [<package-spec> ...]  ..." vs rnpm="Install dependencies and run the test script  Usage: rnpm.exe install-test [ARGS..." | Ran `install-test --help` on fresh fixture directory |
| `link` | `ln` | **partial** | stdout format differs: npm="Symlink a package folder  Usage: npm link [<package-spec>]  Options: [-S\|--save\|..." vs rnpm="Link a package folder locally or globally  Usage: rnpm.exe link [PACKAGE]  Argum..." | Ran `link --help` on fresh fixture directory |
| `ll` | `la` | **partial** | stdout format differs: npm="..." vs rnpm="test-pkg@1.0.0 \| C:\Users\charl_qez1ct5\.t3\userdata\antigravity-tmp\1160a0fb1bc..." | Ran `ll` on fresh fixture directory |
| `login` | - | **partial** | stdout format differs: npm="Login to a registry user account  Usage: npm login  Options: [--registry <regist..." vs rnpm="Log in to a registry  Usage: rnpm.exe login [OPTIONS]  Options:       --registry..." | Ran `login --help` on fresh fixture directory |
| `logout` | - | **partial** | stdout format differs: npm="Log out of the registry  Usage: npm logout  Options: [--registry <registry>] [--..." vs rnpm="Log out of a registry  Usage: rnpm.exe logout [OPTIONS]  Options:       --regist..." | Ran `logout --help` on fresh fixture directory |
| `ls` | `list` | **partial** | stdout format differs: npm="test-pkg@1.0.0 C:\Users\charl_qez1ct5\.t3\userdata\antigravity-tmp\1160a0fb1bcd\..." vs rnpm="test-pkg@1.0.0 C:\Users\charl_qez1ct5\.t3\userdata\antigravity-tmp\1160a0fb1bcd\..." | Ran `ls` on fresh fixture directory |
| `org` | `ogr` | **partial** | stdout format differs: npm="Manage orgs  Usage: npm org set orgname username [developer \| admin \| owner] npm..." vs rnpm="Manage npm organizations  Usage: rnpm.exe org [OPTIONS] [ACTION] [ARGS]...  Argu..." | Ran `org --help` on fresh fixture directory |
| `outdated` | - | **partial** | stdout format differs: npm="Package    Current  Wanted  Latest  Location  Depended by is-number  MISSING   7..." vs rnpm="Package    Current  Wanted  Latest  Location                Depended by is-numbe..." | Ran `outdated` on fresh fixture directory |
| `owner` | `author` | **partial** | stdout format differs: npm="doowb <brian.woodward@gmail.com> jonschlinkert <github@sellside.com> realityking..." vs rnpm="doowb	write jonschlinkert	write realityking	write..." | Ran `owner ls is-number` on fresh fixture directory |
| `pack` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `pack --dry-run` on fresh fixture directory |
| `ping` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `ping` on fresh fixture directory |
| `pkg` | - | **partial** | stdout format differs: npm=""test-pkg"..." vs rnpm="test-pkg..." | Ran `pkg get name` on fresh fixture directory |
| `prefix` | - | **partial** | stdout format differs: npm="C:\Users\charl_qez1ct5\.t3\userdata\antigravity-tmp\1160a0fb1bcd\run-UEkG3I\npm-..." vs rnpm="C:\Users\charl_qez1ct5\.t3\userdata\antigravity-tmp\1160a0fb1bcd\run-UEkG3I\npm-..." | Ran `prefix` on fresh fixture directory |
| `profile` | - | **partial** | stdout format differs: npm="Change settings on your registry profile  Usage: npm profile enable-2fa [auth-on..." vs rnpm="Manage npm profile information  Usage: rnpm.exe profile [OPTIONS] [ACTION] [ARGS..." | Ran `profile --help` on fresh fixture directory |
| `prune` | - | **partial** | File system changes differ: npm wrote [node_modules/, node_modules\.package-lock.json, node_modules\is-number/, node_modules\is-number\LICENSE, node_modules\is-number\README.md, node_modules\is-number\index.js, node_modules\is-number\package.json, package-lock.json], rnpm wrote []; stdout format differs: npm="added 1 package in 832ms..." vs rnpm="rnpm: no extraneous packages pruned..." | Ran `prune` on fresh fixture directory |
| `publish` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `publish --dry-run` on fresh fixture directory |
| `query` | - | **partial** | stdout format differs: npm="[   {     "name": "test-pkg",     "version": "1.0.0",     "description": "test f..." vs rnpm="[   {     "_id": "test-pkg@1.0.0",     "deduped": false,     "description": "tes..." | Ran `query :root` on fresh fixture directory |
| `rebuild` | `rb` | **partial** | stdout format differs: npm="rebuilt dependencies successfully..." vs rnpm="rnpm: rebuild: no packages required rebuilding..." | Ran `rebuild` on fresh fixture directory |
| `repo` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `repo` on fresh fixture directory |
| `restart` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `restart` on fresh fixture directory |
| `root` | - | **partial** | stdout format differs: npm="C:\Users\charl_qez1ct5\.t3\userdata\antigravity-tmp\1160a0fb1bcd\run-UEkG3I\npm-..." vs rnpm="C:\Users\charl_qez1ct5\.t3\userdata\antigravity-tmp\1160a0fb1bcd\run-UEkG3I\npm-..." | Ran `root` on fresh fixture directory |
| `run` | `run-script, rum, urn` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `run test` on fresh fixture directory |
| `sbom` | - | **partial** | stdout format differs: npm="Generate a Software Bill of Materials (SBOM)  Usage: npm sbom  Options: [--omit ..." vs rnpm="Generate Software Bill of Materials (SBOM)  Usage: rnpm.exe sbom [OPTIONS]  Opti..." | Ran `sbom --help` on fresh fixture directory |
| `search` | `find, s, se` | **partial** | stdout format differs: npm="is-number Returns true if a number or string value is a finite number. Useful fo..." vs rnpm="is-number@7.0.0	Returns true if a number or string value is a finite number. Use..." | Ran `search is-number` on fresh fixture directory |
| `set` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `set foo=bar` on fresh fixture directory |
| `shrinkwrap` | - | **partial** | stdout format differs: npm="..." vs rnpm="npm-shrinkwrap.json up to date..." | Ran `shrinkwrap` on fresh fixture directory |
| `stage` | - | **partial** | stdout format differs: npm="Stage packages for publishing, deferring proof-of-presence (2FA) to a later poin..." vs rnpm="Manage staged package versions  Usage: rnpm.exe stage [OPTIONS] [ACTION] [ARGS]...." | Ran `stage --help` on fresh fixture directory |
| `star` | - | **partial** | stdout format differs: npm="Mark your favorite packages  Usage: npm star [<package-spec>...]  Options: [--re..." vs rnpm="Star a package  Usage: rnpm.exe star [OPTIONS] [PACKAGES]...  Arguments:   [PACK..." | Ran `star --help` on fresh fixture directory |
| `stars` | - | **partial** | stdout format differs: npm="View packages marked as favorites  Usage: npm stars [<user>]  Options: [--regist..." vs rnpm="Show packages starred by the current user  Usage: rnpm.exe stars [OPTIONS] [USER..." | Ran `stars --help` on fresh fixture directory |
| `start` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `start` on fresh fixture directory |
| `stop` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `stop` on fresh fixture directory |
| `team` | - | **partial** | stdout format differs: npm="Manage organization teams and team memberships  Usage: npm team create <scope:te..." vs rnpm="Manage npm teams  Usage: rnpm.exe team [OPTIONS] [ACTION] [ARGS]...  Arguments: ..." | Ran `team --help` on fresh fixture directory |
| `test` | `tst, t` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `test` on fresh fixture directory |
| `token` | - | **partial** | stdout format differs: npm="Manage your authentication tokens  Usage: npm token list npm token revoke <id\|to..." vs rnpm="Manage registry authentication tokens  Usage: rnpm.exe token [OPTIONS] [COMMAND]..." | Ran `token --help` on fresh fixture directory |
| `trust` | - | **partial** | stdout format differs: npm="Create a trusted relationship between a package and a OIDC provider  Usage: npm ..." vs rnpm="Record package trust metadata  Usage: rnpm.exe trust [OPTIONS] [ACTION] [ARGS]....." | Ran `trust --help` on fresh fixture directory |
| `undeprecate` | - | **partial** | stdout format differs: npm="Undeprecate a version of a package  Usage: npm undeprecate <package-spec>  Optio..." vs rnpm="Remove a package deprecation notice  Usage: rnpm.exe undeprecate [OPTIONS] <PACK..." | Ran `undeprecate --help` on fresh fixture directory |
| `uninstall` | `unlink, remove, rm, r, un` | **partial** | stdout format differs: npm="Remove a package  Usage: npm uninstall [<@scope>/]<pkg>...  Options: [-S\|--save\|..." vs rnpm="Remove a package from project dependencies  Usage: rnpm.exe uninstall [OPTIONS] ..." | Ran `uninstall --help` on fresh fixture directory |
| `unpublish` | - | **partial** | stdout format differs: npm="Remove a package from the registry  Usage: npm unpublish [<package-spec>]  Optio..." vs rnpm="Remove a package or package version from a registry  Usage: rnpm.exe unpublish [..." | Ran `unpublish --help` on fresh fixture directory |
| `unstar` | - | **partial** | stdout format differs: npm="Remove an item from your favorite packages  Usage: npm unstar [<package-spec>......" vs rnpm="Unstar a package  Usage: rnpm.exe unstar [OPTIONS] [PACKAGES]...  Arguments:   [..." | Ran `unstar --help` on fresh fixture directory |
| `update` | `u, up, upgrade, udpate` | **partial** | stdout format differs: npm="added 1 package in 760ms..." vs rnpm="rnpm: updated is-number none -> 7.0.0 rnpm: successfully updated 1 package(s) (c..." | Ran `update` on fresh fixture directory |
| `version` | `verison` | **partial** | stdout format differs: npm="{   'test-pkg': '1.0.0',   npm: '11.20.0',   node: '26.13.0',   acorn: '8.19.0',..." vs rnpm="{   acorn: '8.19.0',   ada: '4.0.0',   amaro: '1.1.11',   ares: '1.34.9',   brot..." | Ran `version` on fresh fixture directory |
| `view` | `info, show, v` | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `view is-number version` on fresh fixture directory |
| `whoami` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `whoami` on fresh fixture directory |
| `set-script` | - | **matching** | Stdout, stderr, exit code and file changes match expected parity | Ran `set-script --help` on fresh fixture directory |

## Summary Statistics (Master Baseline)

- **Total Commands Evaluated**: 73
- **Matching**: 23
- **Partial**: 49
- **Missing**: 1

## Next Steps

1. Implement missing commands and subcommands:
   - `cache` (`add`, `ls`)
   - Re-architect commands into isolated modules under `crates/rnpm-cli/src/commands/<name>.rs` with one-line dispatch entries in `main.rs`.
2. Align priority local dev and CI workflows (`cache`, `config`, `pkg`, `outdated`, `update`, `version`, `pack`, `prune`, `dedupe`, `rebuild`, `link`, `init -y`, `query`, `install-test`, `shrinkwrap`, `sbom`).
3. Align registry-read commands (`view`, `search`, `dist-tag`, `owner`, `ping`, `whoami`).
4. Align registry-write commands with safety guards (`publish`, `deprecate`, `access`, `token`, `star`).
