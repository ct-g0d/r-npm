# npm parity audit, 2026-11-10

Baseline: `7214999` (`origin/master`). Oracle: the installed Windows `npm.cmd`
11.20.0 and Node v26.13.0. Scenarios ran sequentially in sibling `npm` and `rnpm`
directories under `%TEMP%`, outside the repository. Builds used `-j 4`.

For each scenario the audit captured exit code, stdout, stderr, and SHA-256 of
every file in package.json, package-lock.json, node_modules, and workspace
manifests. No JSON normalization was applied to file comparisons. Junction
targets and absolute paths in stdout were compared relative to each fixture's
directory. Initial runs used npm.cmd's underlying npm-cli.js; the verification
pass invoked npm.cmd itself. Audit and funding were disabled through environment
configuration to keep registry advisories out of command output.

The first, invalid tarball fixture was discarded: its binary data had accidentally
been encoded as text, and both tools rejected it. The valid tarball scenario used
the same npm-packed bytes in both directories.

| Audited item | Status | Evidence after changes | Commit |
| --- | --- | --- | --- |
| 1. Local tarball manifest name | FIXED-by-you | Both already used `actual-package-name`, despite filename `realname-1.0.0.tgz`. Fixed remaining `file:./` vs `file:` save-spec difference; all compared files now match. The resolver also accepts existing noncanonical metadata. | `17316b1`, `c7ae72a` |
| 2. Root URL and transitive registry range | already-OK | Root is-number URL resolves 7.0.0, is-odd gets nested is-number 6.0.0; exits 0 and all files match. | baseline |
| 3. Install into workspace a | already-OK | `install is-number@7 -w a` leaves root dependencies unchanged and saves `^7.0.0` to a; all files match. | baseline |
| 4. CRLF, tabs, BOM, key order | FIXED-by-you | package.json was already exact. Fixed hidden lockfile using spaces instead of tabs. Manifest, public lockfile, hidden lockfile, and package files now match. | `686af48` |
| 5. ci exact manifest vs caret lock spec | already-OK | Manifest 7.0.0 with lock root ^7.0.0: exits 0; all files match. | baseline |
| 6. Config flags before and after command | FIXED-by-you | --loglevel, --no-bin-links, --install-links, --userconfig already parse in both positions. Silent install now emits no summary, matching npm. Empty hidden-lock creation remains separately blocked below. | `c6d9e7b` |
| 7. run x --silent | already-OK | Both execute script with `[]` arguments, identical stdout and exit 0. | baseline |
| 8. install is-number@7 save spec | already-OK | Both save `^7.0.0`; exits 0 and all files match. | baseline |
| 9. ls --all, optional missing peer | FIXED-by-you | Exit 0 already correct. Fixed JSON to render optional missing peer as `{}` and use npm field order; stdout now matches exactly. | `b657d8f` |
| 10. outdated --json, current empty project | already-OK | Both stdout `{}` and exit 0; no file changes. | baseline |
| 11. view is-number@7.0.0 version --json | already-OK | Identical stdout `"7.0.0"`, exit 0; no file changes. | baseline |
| 12. pack --dry-run | already-OK | Identical tarball filename on stdout, exit 0; no archive or project mutations. | baseline |
| 13. explain is-number --json | FIXED-by-you | npm returned an array with dependents; rnpm returned a raw lock entry. Now matching JSON after substituting the sibling fixture path. Also works without a lockfile, fails for missing matches, and preserves each parent's declared range for shared dependencies. | `b657d8f`, `c1f4850` |
| 14. config get registry | FIXED-by-you | Previously `undefined`; now npm's default registry URL, preserving explicit project override. Stdout matches. | `72f8e94` |
| 15. uninstall is-number --silent | FIXED-by-you | Removed extra rnpm summary; exits, stdout, manifests, lockfiles, and resulting node_modules match. | `c6d9e7b` |
| 16. update --dry-run --silent, empty project | FIXED-by-you | Previously wrote lockfiles/node_modules and printed a summary. Now exit 0, empty stdout, no file changes, matching npm. | `c6d9e7b` |
| 17. prune --silent, dependency-free project | FIXED-by-you | Previously omitted npm's root lockfile and printed a summary. Now writes the matching root lockfile and stays silent. | `c6d9e7b` |
| 18. version patch --no-git-tag-version | already-OK | Both stdout `v1.0.1`, exit 0, byte-identical package.json. | baseline |
| 19. init -y --silent, existing manifest | FIXED-by-you | Previously sorted keys and omitted `type`. Now keeps insertion order, defaults to commonjs, and matches file bytes and stdout after fixture-path substitution. | `1d1a605` |
| 20. exec -- node -e console.log(123) | already-OK | Both stdout `123`, exit 0, no file changes. | baseline |
| Empty install hidden lockfile | OPEN-blocked-by-constraint | npm writes the public lockfile but does not create node_modules. rnpm also creates node_modules/.package-lock.json. | protected function below |
| Populated update --dry-run --silent | OPEN-blocked-by-constraint | Both exit 0 and leave all project files unchanged. npm stdout is empty; rnpm prints one simulation line for is-number from protected install code. | protected function below |
| Existing manifest with file:./ archive dependency | OPEN-blocked-by-constraint | Both install successfully and preserve package.json. npm canonicalizes the installed package's lockfile resolved field to file:realname-1.0.0.tgz; rnpm retains file:./realname-1.0.0.tgz in both lockfiles. | protected function below |

## Regressions and validation

Each new regression was observed failing before its fix. Tests cover normalized
file targets, hidden-lock indentation and newline precedence, config defaults
and overrides, init file/output bytes, optional-peer JSON, explain without a
lockfile and missing matches, silent mutation summaries, update dry-run file
preservation, and dependency-free prune lock contents. Existing tests were kept.

Focused regressions passed. `cargo test --workspace -j 4 -- --test-threads=1`
passed all 885 tests. `cargo clippy --workspace -j 4 --all-targets -- -D warnings`
passed with zero warnings.

No protected install-speed, filesystem-writer, tarball, or cache source files were
edited. No speed/parity gates or timing loops were run.

## Protected-file follow-up

`crates/rnpm-install/src/lib.rs`, `Installer::install_internal`: the reification
path creates node_modules and its bin directory even when there are no packages,
then saves a hidden lockfile. After saving the public lockfile, skip creation of a
new node_modules tree and hidden lockfile when the graph contains only the root
and no installed tree existed. Preserve handling of an already-existing tree.

The dry-run simulation in `Installer::install_internal` also prints one line per
package directly. Its logging should respect loglevel silent. The CLI fix routes
update dry-runs through this existing simulation rather than through update's
summary code, which requires a newly written lockfile. Nonempty dry-run output
therefore still needs this protected-function follow-up.

`crates/rnpm-install/src/lib.rs`, `Installer::populate_custom_target_metadata`,
File archive branch: `resolved_url` uses `file_spec_clean`, the original manifest
text. Build the resolved file URL from the normalized parsed file target instead,
relative to the project for absolute paths, while keeping the user's dependency
spec unchanged in package.json and the root lockfile entry.

The audit verifies the listed fixtures, not complete npm compatibility. In
particular, flag acceptance is not proof of complete flag semantics, and empty
outdated/update/prune checks do not establish all populated-project behaviors.

## Wave 2

Resumed 2026-11-11 against npm.cmd 11.20.0 and Node v26.13.0. The original
requested base was 31c7f48. During the pause, master incorporated a4ff8c1 and
subsequent changes; this follow-up uses b942b95 as its baseline and preserves the
paused WIP on backup/npm-parity-wave2-wip-1fe1191. Already-correct behavior below
means correct at this resumed baseline, not a new fix in this PR.

Run `node scripts/audit-wave2.cjs <label>` after `cargo build --release -j 4`.
The runner creates sibling npm/rnpm fixtures under the Windows temp directory,
invokes npm.cmd itself, and runs each scenario sequentially. Configuration and
caches are isolated outside each package. It captures exits, both streams, file
hashes, and literal Buffer.equals comparisons of every resulting regular file;
junction targets are compared after substituting fixture paths. Only temp paths
and command durations are normalized. Registry failures also compare the first
error line, as requested. npm's additional debug-log footer is retained in the
captured output rather than removed to make stderr appear equal.

`exec -ws` uses `--call="node probe.cjs"` so it exercises workspace dispatch
without npm installing a separate registry-distributed Node binary. The initial
attempt with `exec -- node` exposed npm's registry lookup and is not treated as
the final controlled exec fixture.

The table distinguishes a fixed command behavior from a remaining protected
archive or lockfile mismatch. The raw comparison matrix remains authoritative
about complete stream/file equality; an archive-dependent case is not claimed
byte-identical merely because its file list matches.

| Case | Status | Evidence | Commit |
| --- | --- | --- | --- |
| run pre/main/post hooks | already-OK | Exit 0; stdout, stderr, event file, and manifest match. | b942b95 |
| run --ignore-scripts | already-OK | Explicit x runs; prex/postx do not. All compared bytes match. | b942b95 |
| run --foreground-scripts | already-OK | prex, x, postx order and both streams match. | b942b95 |
| failing run script | already-OK | Exit 7, pre-hook runs, post-hook is skipped; both streams/files match. | b942b95 |
| lifecycle environment and PATH | FIXED | Stops exporting description/scripts; config false becomes an empty string. All ancestor .bin paths are present, including absent directories. Selected npm_package_*, npm_config_*, lifecycle fields and INIT_CWD match. | ec26035 |
| install root lifecycle | FIXED | Complete hook order was already correct. Adds npm's hook banners; both streams and resulting files now match. | ec26035 |
| install --ignore-scripts | already-OK | No event file; exit, streams and files match. | b942b95 |
| install --foreground-scripts | FIXED | Hook banners and child output now match npm. | ec26035 |
| ci root lifecycle | FIXED | Adds matching hook banners; all seven hooks, streams and files match. | ec26035 |
| failing install | OPEN-blocked-by-constraint | Exit 7 and first error line now match; rnpm still omits the public lockfile that npm writes before the failing hook. | ec26035 |
| pack prepack/prepare/postpack | OPEN-blocked-by-constraint | Hook order/stdout and event file match; archive-dependent notices remain separately blocked. | ec26035 |
| pack --ignore-scripts | OPEN-blocked-by-constraint | Hooks are skipped and no dry-run archive is written. | b942b95 |
| pack --silent | FIXED | Preserves child output and filename while suppressing banners/notices. Both streams and files match. | ec26035 |
| pack --json with hooks | OPEN-blocked-by-constraint | Preserves child stdout and sends hook banners to stderr. Archive size/digests remain separately blocked. | ec26035 |
| failing pack hook | FIXED | Exit 7 and npm error code/path/command block; no archive or later hooks. npm retains an extra debug-log footer. | ec26035 |
| version hooks | FIXED | preversion/version/postversion headers, stdout and resulting manifest match. | ec26035 |
| run x -ws | FIXED | Uses manifest order for npm-compatible manifests; preserves the separate workspace: protocol extension. Dependent a runs before b, matching npm. | ec26035 |
| run x -w a | already-OK | Only a runs; exit, streams and files match. | b942b95 |
| run x -ws --include-workspace-root | FIXED | Root runs first, followed by a and b; output and files match. | ec26035 |
| run x -ws --ignore-scripts | FIXED | Explicit scripts still run, in npm order; output and files match. | ec26035 |
| workspace missing script | FIXED | Existing missing-script failure was correct; now includes npm's -ws warning. Exit 1 and both streams match. | ec26035 |
| workspace --if-present | FIXED | Existing skip behavior retained; -ws warning now matches. Exit 0 and no package mutations. | ec26035 |
| workspace orphan pre/post hooks | FIXED | Existing main-script presence check retained; matching warning and output, no orphan execution. | ec26035 |
| exec -ws | FIXED | Runs in a then b, with npm_lifecycle_event=npx and the original INIT_CWD. Streams/event files match. | ec26035 |
| version patch -ws | OPEN-blocked-by-constraint | Correct order, headers, versions, stdout, root preservation and reified tree. Workspace lifecycle events and lockfile metadata still differ in protected install code. | ec26035 |
| ls -ws, uninstalled workspace | FIXED | Matching empty-tree marker, warning, exit 0 and no mutations. | ec26035 |
| install from workspace subdirectory | OPEN-blocked-by-constraint | Fixed routing to root, workspace links and summary; remaining public/hidden lock metadata mismatch is protected. | ec26035 |
| pack files whitelist and required files | OPEN-blocked-by-constraint | Basic file list, sizes/modes, README, LICENSE and package.json match. Archive bytes/digests differ. | ec26035 |
| pack .npmignore and required files | OPEN-blocked-by-constraint | Basic exclusions and required file list match; archive bytes/digests differ. | ec26035 |
| pack .gitignore fallback | OPEN-blocked-by-constraint | Added matching fallback warning. Basic file list matches; archive bytes/digests differ. | ec26035 |
| files whitelist vs root .npmignore | OPEN-blocked-by-constraint | npm includes explicitly listed keep.js; rnpm wrongly excludes it. | ec26035 |
| nested .npmignore under files directory | OPEN-blocked-by-constraint | npm excludes lib/omit.js; rnpm includes it. | ec26035 |
| bundleDependencies and pack --json | OPEN-blocked-by-constraint | Bundled file list/contents, modes and entry count match. Actual tgz bytes, compressed size and digests differ. | ec26035 |
| publish --dry-run --json | OPEN-blocked-by-constraint | Fixed package-keyed JSON without duplicated top-level fields; notices and file list match. Compressed size/digests remain protected. | ec26035 |
| publish --dry-run --silent hooks | FIXED | prepare now runs between prepack/postpack. Child output is preserved, package summary suppressed; streams and event file match. | ec26035 |
| missing script error | already-OK | Exit 1 and first error line match; npm also emits its debug-log footer. | b942b95 |
| missing package.json error | already-OK | Windows exit -4058 and first line npm error code ENOENT match. | b942b95 |
| invalid package.json error | already-OK | Exit 1 and first line npm error code EJSONPARSE match. | b942b95 |
| unknown command | already-OK | Exit 1, stdout wording and empty stderr match. | b942b95 |
| ETARGET | FIXED | Solver's missing-version error previously became EUNKNOWN. Now exit 1 and npm error code ETARGET, with npm's notarget message. | 7ab5097 |
| E404 package | FIXED | Solver's missing-metadata error previously became EUNKNOWN. Now exit 1 and npm error code E404. | 7ab5097 |

The -ws deprecation warning itself is covered by a new exact-output regression.
The full workspace run additionally exposed star/unstar's unconditional ASCII
markers. Those now honor explicit unicode configuration and npm's UTF-8 locale
default; the existing live mock-registry parity test is preserved and passes.

### Protected follow-up identified in Wave 2

- `crates/rnpm-fs/src/tarball.rs`, `should_include_file`: root ignore rules must
  not discard an explicit files whitelist entry. Keep npm's always-included and
  always-excluded rules separate from that precedence decision.
- The same file, `collect_pack_files` and `walk_dir_collect`: load and apply
  directory-local .npmignore/.gitignore rules with the correct relative scope.
  The current recursion reuses only the root ignore pattern list.
- The same file, `pack_directory`: separate archive entry order from the sorted
  human/JSON file list, and reproduce npm's portable USTAR header encoding and
  explicit regular-file type. The audit's gzip headers and numeric mtimes already
  agree; raw tar headers, archive order and compressed bytes do not. Validate the
  resulting tar stream and compressor output against npm before claiming matching
  shasum/integrity/compressed size.
- `crates/rnpm-install/src/lib.rs`, `Installer::install_internal`: save the public
  lockfile before executing root hooks, as npm does, so a failing hook does not
  incorrectly remove the resolved lockfile result.
- The same function's workspace target lock entries explicitly set name to the
  workspace's canonical name. Omit redundant names when npm omits them, while
  preserving genuinely noncanonical names. This affects public and hidden locks.
- `Installer::enrich_lockfile_from_registry`: do not enrich a workspace target
  with metadata for an unrelated registry package sharing its name/version. The
  workspace-subdirectory fixture currently gives local b the registry b package's
  node engine constraint.
- `Installer::install_internal` and its lifecycle invocation need a workspace
  reification mode for version: run workspace/dependency hooks without repeating
  root install hooks. npm's observed workspace order after version is preinstall,
  prepare, install, postinstall. The current public installer API only supplies a
  single ignore_scripts switch; the CLI follow-up refreshes the tree without
  inventing an alternate install pipeline or changing protected files.

No protected source file, cache source, speed/parity gate, or timing loop was
edited or run. Builds use -j 4 and fixtures run sequentially. Existing tests are
preserved; two stale pack/publish snapshots now assert npm's observed output, and
the workspace-version scope test explicitly uses --silent while retaining its
exact output and manifest assertions.

### Wave 2 validation and evidence

Implementation commits: `ec260350ab3a310730f05749a05fc0a656fe7a72` and
`7ab5097646791a2ed525811b7a4de035b1948f64`. The
committed `docs/npm-parity-wave2-results.json` records before/after exit codes,
first error lines, normalized stream hashes, pack payloads and differing file
hashes for all 42 scenarios. All exit codes and all requested first error
lines match. Complete stream/file equality holds for 23 scenarios; the matrix
retains the other mismatches instead of applying extra normalization.

`cargo test --workspace -j 4 -- --test-threads=1` passed 971 tests (0 ignored).
`cargo clippy --workspace -j 4 --all-targets -- -D warnings` passed with no
warnings. `cargo build --release -j 4` passed. Eleven new integration tests and
two diagnostic regressions were observed failing before the relevant fixes. The
existing install-library lifecycle regression and star mock-registry parity test
also pass unchanged. No protected source files appear in the implementation diff.
