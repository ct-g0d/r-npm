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
| 1. Local tarball manifest name | FIXED-by-you | Both already used `actual-package-name`, despite filename `realname-1.0.0.tgz`. Fixed remaining `file:./` vs `file:` save-spec difference; all compared files now match. | `17316b1` |
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
| 13. explain is-number --json | FIXED-by-you | npm returned an array with dependents; rnpm returned a raw lock entry. Now matching JSON after substituting the sibling fixture path. Also works without a lockfile and fails for missing matches. | `b657d8f` |
| 14. config get registry | FIXED-by-you | Previously `undefined`; now npm's default registry URL, preserving explicit project override. Stdout matches. | `72f8e94` |
| 15. uninstall is-number --silent | FIXED-by-you | Removed extra rnpm summary; exits, stdout, manifests, lockfiles, and resulting node_modules match. | `c6d9e7b` |
| 16. update --dry-run --silent, empty project | FIXED-by-you | Previously wrote lockfiles/node_modules and printed a summary. Now exit 0, empty stdout, no file changes, matching npm. | `c6d9e7b` |
| 17. prune --silent, dependency-free project | FIXED-by-you | Previously omitted npm's root lockfile and printed a summary. Now writes the matching root lockfile and stays silent. | `c6d9e7b` |
| 18. version patch --no-git-tag-version | already-OK | Both stdout `v1.0.1`, exit 0, byte-identical package.json. | baseline |
| 19. init -y --silent, existing manifest | FIXED-by-you | Previously sorted keys and omitted `type`. Now keeps insertion order, defaults to commonjs, and matches file bytes and stdout after fixture-path substitution. | `1d1a605` |
| 20. exec -- node -e console.log(123) | already-OK | Both stdout `123`, exit 0, no file changes. | baseline |
| Empty install hidden lockfile | OPEN-blocked-by-constraint | npm writes the public lockfile but does not create node_modules. rnpm also creates node_modules/.package-lock.json. | protected function below |

## Regressions and validation

Each new regression was observed failing before its fix. Tests cover normalized
file targets, hidden-lock indentation and newline precedence, config defaults
and overrides, init file/output bytes, optional-peer JSON, explain without a
lockfile and missing matches, silent mutation summaries, update dry-run file
preservation, and dependency-free prune lock contents. Existing tests were kept.

Focused core, lockfile, init, and CLI regression tests passed. Full workspace test
and Clippy results are recorded in the PR description after execution.

No protected install-speed, filesystem-writer, tarball, or cache source files were
edited. No speed/parity gates or timing loops were run.

## Protected-file follow-up

`crates/rnpm-install/src/lib.rs`, `Installer::install_internal`: the reification
path creates node_modules and its bin directory even when there are no packages,
then saves a hidden lockfile. After saving the public lockfile, skip creation of a
new node_modules tree and hidden lockfile when the graph contains only the root
and no installed tree existed. Preserve handling of an already-existing tree.

The dry-run simulation in the same protected function also prints one line per
package directly. Its logging should respect loglevel silent. The CLI fix routes
update dry-runs through this existing simulation rather than through update's
summary code, which requires a newly written lockfile. Nonempty dry-run output
therefore still needs this protected-function follow-up.

The audit verifies the listed fixtures, not complete npm compatibility. In
particular, flag acceptance is not proof of complete flag semantics, and empty
outdated/update/prune checks do not establish all populated-project behaviors.
