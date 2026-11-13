# npm replacement readiness, 2026-11-13

Verdict: the measured everyday workflows are substantially closer to npm, but rnpm is not a verified universal npm replacement. The final Windows sweep has 131/139 exact normalized matches. Keep npm available for the remaining differences and unverified workflows.

## Provenance and reproduction

Base: `4f2735de15fb66b09d0136cc5b91959acc07d4e8`. Implementation source for the measured candidate: `fda973c9c7b671b03efaecf3fd19b5eb6a16235b`; subsequent source changes only correct test expectations. Oracle: npm 11.20.0, Node v26.13.0, Windows. Candidate uses the debug build produced by Cargo tests; the original baseline is a release build compiled before implementation edits. These are correctness comparisons, not timings.

- Baseline executable SHA-256: `acf9a4a040161e8bc6284f614093cd391323667944a0f441956e65ad5ea1ce9f`.
- Candidate executable SHA-256: `d809380b9a20dc219d6b2fef7c3d75fd11b86e0e27851a33c14de4b868a5d2c1`.

```powershell
cargo test --workspace -j 4 -- --test-threads=1
cargo clippy --workspace --all-targets -j 4 -- -D warnings
node scripts/check-npm-replacement.mjs --binary target/debug/rnpm.exe --output docs/npm-replacement-results-2026-11-13.json
Write-Output "success=$? exit=$LASTEXITCODE"
node scripts/generate-npm-command-coverage.mjs
```

Both comparison runs returned `$? = False`, `$LASTEXITCODE = 1`. The gate rejects any failed execution, exit mismatch, normalized stream mismatch, project/configuration file mismatch, or PUT/DELETE mutation mismatch. It also rejects an empty or incomplete run. No mismatch was skipped or converted into a pass.

Every command runs in sibling isolated projects with separate user/global configuration, prefix, cache and store. Registry fixtures use loopback HTTP and a synthetic token. Publishing is dry-run only; administrative mutations target only the mock. Full raw streams remain in each report's `root/logs` directory. The checked-in reports retain normalized stream hashes, output excerpts, JSON file contents, non-JSON file hashes, request bodies and comparison dimensions. Outputs over 16KB are excerpted only after comparing and hashing the complete streams.

Normalization covers fixture/configuration paths, JSON escaping of those paths, loopback origins, CRLF, elapsed summary/ping times, and diagnostic-log timestamps. JSON file key order is ignored; fields are retained. stderr is compared without suppressing npm diagnostic footers. Cache/store contents and empty-directory presence are not compared.

## Fixed behavior

- [Packing](../crates/rnpm-fs/src/tarball.rs): files entries override root ignore files; directory-local .npmignore/.gitignore rules apply with relative scope and negations; literal file entries remain required. Portable USTAR headers and archive order now match the measured fixtures. Compression uses Node's built-in zlib to reproduce the oracle runtime's gzip bytes without calling npm or loading npm modules. Installation decompression is unchanged.
- [Install persistence](../crates/rnpm-install/src/lib.rs) and [lifecycle phases](../crates/rnpm-lifecycle/src/lib.rs): dependency scripts complete before lock persistence; public/hidden locks precede root hooks; failed root hooks retain npm's lockfile effects. Explicit package installs skip root hooks. CI persists the hidden lock before root-hook failure.
- [Workspace and save specs](../crates/rnpm-install/src/save.rs): parent-directory selectors, filtered workspace materialization and hidden-lock scope, redundant workspace names, range-preserving save specs, alias ranges and configured save-exact. [Git](../crates/rnpm-install/src/git.rs) decodes file URLs before invoking git, fixing local paths containing escaped characters.
- [Dependency listing](../crates/rnpm-cli/src/list.rs): optional/peer/missing/invalid/extraneous output, Unicode branches, dependency/problem ordering, long JSON fields, and successful exit for trees with only extraneous packages.
- [Cache](../crates/rnpm-cli/src/commands/cache.rs): registry cache add downloads and verifies actual archive bytes instead of writing a package-name marker; cache listing reads index keys instead of internal storage filenames.
- CLI output and effects: empty uninstall lockfiles, dedupe/find-dupes summaries, install-test/CI-test spacing, pkg/link/search/ping output, audit root dependency counts, outdated dependent names and status exits, real diagnostic logs, unpinned script approvals, local bugs/docs/repo URLs, access-list packages, and empty logout configuration removal. [Diff](../crates/rnpm-cli/src/diff.rs) honors configured registries and includes version headers. [Registry mutations](../crates/rnpm-registry/src/client.rs) use minimal star documents and revision-based unpublish ordering.

Rust regressions include [replacement_gaps_test.rs](../crates/rnpm-cli/tests/replacement_gaps_test.rs), existing pack/cache/script-policy/star/unpublish tests, filesystem tests, and installer save/workspace/lifecycle tests. Existing ASCII tree assertions now select Unicode=false explicitly; Unicode output is independently compared with npm. Outdated assertions retain the same version checks while expecting npm's directory-based dependent name.

## Probe and command coverage results

| Measurement | Baseline | Candidate |
|---|---:|---:|
| Matching behavioral probes | 63/139 | 131/139 |
| Mismatches closed | - | 68 |

Command classifications from the same behavioral report: **64 matching, 9 partial, 0 missing**, out of 73 tracked canonical/legacy entries. [Coverage matrix](npm-command-coverage.md) and [raw coverage](npm-command-coverage-raw.json) are generated together. Matching classifies the registered probes; it does not establish complete command semantics or a completion percentage.

[Baseline evidence](npm-replacement-baseline-2026-11-13.json), [candidate evidence](npm-replacement-results-2026-11-13.json). The changed-packument cache probe and URL/file source-shadowing probes already matched the baseline; they are verified existing behavior, not new fixes. Git source shadowing now matches.

| Probe | npm exit | rnpm exit | Result | Remaining differing observations | Baseline |
|---|---:|---:|---|---|---|
| pack-explicit-file-vs-root-ignore | 0 | 0 | match |  | mismatch |
| pack-nested-ignore | 0 | 0 | match |  | mismatch |
| pack-explicit-nested-file | 0 | 0 | match |  | mismatch |
| pack-nested-gitignore | 0 | 0 | match |  | mismatch |
| pack-nested-ignore-negation | 0 | 0 | match |  | mismatch |
| empty-install-hidden-lock | 0 | 0 | match |  | match |
| failing-lifecycle-public-lock | 7 | 7 | match |  | mismatch |
| explicit-install-skips-root-hooks | 0 | 0 | match |  | mismatch |
| failing-ci-preserves-hidden-lock | 7 | 7 | match |  | mismatch |
| workspace-run-name | 0 | 0 | match |  | match |
| workspace-install-name | 0 | 0 | match |  | mismatch |
| workspace-run-long-equals | 0 | 0 | match |  | match |
| workspace-install-long-equals | 0 | 0 | match |  | mismatch |
| workspace-run-short-attached | 1 | 1 | match |  | mismatch |
| workspace-install-short-attached | 1 | 1 | match |  | mismatch |
| workspace-run-path | 0 | 0 | match |  | match |
| workspace-install-path | 0 | 0 | match |  | mismatch |
| workspace-run-bare-directory | 0 | 0 | match |  | match |
| workspace-install-bare-directory | 0 | 0 | match |  | mismatch |
| workspace-run-parent-directory | 0 | 0 | match |  | mismatch |
| workspace-install-parent-directory | 0 | 0 | match |  | mismatch |
| workspace-run-multiple | 0 | 0 | match |  | match |
| workspace-install-multiple | 0 | 0 | match |  | mismatch |
| save-default | 0 | 0 | match |  | match |
| save-prefix | 0 | 0 | match |  | match |
| save-exact | 0 | 0 | match |  | match |
| save-range | 0 | 0 | match |  | mismatch |
| save-tag | 0 | 0 | match |  | match |
| save-alias | 0 | 0 | match |  | match |
| save-url | 0 | 0 | match |  | match |
| save-file | 0 | 0 | match |  | match |
| shadow-url-registry | 0 | 0 | match |  | match |
| shadow-file-registry | 0 | 0 | match |  | match |
| shadow-git-registry | 0 | 0 | match |  | mismatch |
| save-git | 0 | 0 | match |  | mismatch |
| save-alias-range | 0 | 0 | match |  | mismatch |
| save-config-save-prefix | 0 | 0 | match |  | match |
| save-config-save-exact | 0 | 0 | match |  | mismatch |
| cache-revalidate-changed-packument | 0 | 0 | match |  | match |
| ls-missing | 1 | 1 | match |  | mismatch |
| ls-missing--json | 1 | 1 | match |  | mismatch |
| ls-missing--all | 1 | 1 | match |  | mismatch |
| ls-missing--all---json | 1 | 1 | match |  | mismatch |
| ls-invalid | 1 | 1 | match |  | mismatch |
| ls-invalid--json | 1 | 1 | match |  | mismatch |
| ls-invalid--all | 1 | 1 | match |  | mismatch |
| ls-invalid--all---json | 1 | 1 | match |  | mismatch |
| ls-extraneous | 1 | 1 | match |  | mismatch |
| ls-extraneous--json | 1 | 1 | match |  | mismatch |
| ls-extraneous--all | 1 | 1 | match |  | mismatch |
| ls-extraneous--all---json | 1 | 1 | match |  | mismatch |
| ls-complete | 0 | 0 | match |  | mismatch |
| ls-complete--json | 0 | 0 | match |  | match |
| ls-complete--all | 0 | 0 | match |  | mismatch |
| ls-complete--all---json | 0 | 0 | match |  | match |
| ls-only-extraneous | 0 | 0 | match |  | mismatch |
| ls-only-extraneous--json | 0 | 0 | match |  | mismatch |
| ls-only-extraneous--all---json | 0 | 0 | match |  | mismatch |
| command-ci | 0 | 0 | match |  | match |
| command-uninstall | 0 | 0 | match |  | mismatch |
| command-update | 0 | 0 | match |  | match |
| command-outdated | 0 | 0 | match |  | match |
| command-audit | 0 | 0 | match |  | mismatch |
| command-fund | 0 | 0 | match |  | match |
| command-exec | 0 | 0 | match |  | match |
| command-npx | 0 | 0 | match |  | match |
| command-init | 0 | 0 | match |  | match |
| command-version | 0 | 0 | match |  | match |
| command-publish | 0 | 0 | match |  | mismatch |
| command-config | 0 | 0 | match |  | match |
| command-cache | 0 | 0 | match |  | match |
| command-link | 0 | 0 | match |  | mismatch |
| command-pkg | 0 | 0 | match |  | mismatch |
| command-prefix | 0 | 0 | match |  | match |
| command-root | 0 | 0 | match |  | match |
| command-get | 0 | 0 | match |  | match |
| command-ping | 0 | 0 | match |  | mismatch |
| command-search | 0 | 0 | match |  | mismatch |
| command-whoami | 1 | 1 | match |  | mismatch |
| command-rebuild | 0 | 0 | match |  | match |
| command-prune | 0 | 0 | match |  | match |
| command-dedupe | 0 | 0 | match |  | mismatch |
| command-find-dupes | 0 | 0 | match |  | mismatch |
| command-shrinkwrap | 0 | 0 | match |  | match |
| command-query | 0 | 0 | match |  | match |
| command-sbom | 0 | 1 | partial | exit, stdout, stderr | mismatch |
| command-start | 0 | 0 | match |  | match |
| command-stop | 0 | 0 | match |  | match |
| command-restart | 0 | 0 | match |  | match |
| command-test | 0 | 0 | match |  | match |
| command-run | 0 | 0 | match |  | match |
| command-install-test | 0 | 0 | match |  | mismatch |
| command-install-ci-test | 0 | 0 | match |  | mismatch |
| command-ll | 0 | 0 | match |  | mismatch |
| command-explain | 0 | 0 | match |  | match |
| command-explore | 0 | 0 | match |  | match |
| command-edit | 0 | 0 | match |  | match |
| command-bugs | 0 | 0 | match |  | mismatch |
| command-docs | 0 | 0 | match |  | mismatch |
| command-repo | 0 | 0 | match |  | mismatch |
| registry-access | 0 | 0 | match |  | mismatch |
| registry-org | 0 | 0 | match |  | match |
| registry-profile | 0 | 0 | match |  | match |
| registry-team | 0 | 0 | match |  | match |
| registry-token | 0 | 0 | match |  | match |
| registry-owner | 0 | 0 | match |  | match |
| registry-dist-tag | 0 | 0 | match |  | match |
| registry-view | 0 | 0 | match |  | match |
| registry-whoami | 0 | 0 | match |  | match |
| registry-logout | 0 | 0 | match |  | mismatch |
| registry-deprecate | 0 | 0 | match |  | match |
| registry-undeprecate | 0 | 0 | match |  | match |
| registry-unpublish | 0 | 0 | match |  | mismatch |
| registry-star | 0 | 0 | match |  | mismatch |
| registry-unstar | 0 | 0 | match |  | mismatch |
| registry-stars | 0 | 0 | match |  | mismatch |
| registry-stage | 0 | 0 | partial | stdout | mismatch |
| registry-trust | 0 | 0 | partial | stdout | mismatch |
| registry-login | 1 | 1 | partial | stdout, stderr | mismatch |
| registry-adduser | 1 | 1 | partial | stdout, stderr | mismatch |
| command-approve-scripts | 0 | 0 | match |  | mismatch |
| command-deny-scripts | 0 | 0 | match |  | match |
| command-install-scripts | 0 | 0 | match |  | mismatch |
| command-set | 0 | 0 | match |  | match |
| command-set-script | 1 | 1 | match |  | match |
| command-completion | 1 | 1 | partial | stderr | mismatch |
| command-help | 0 | 0 | partial | stdout | mismatch |
| command-help-search | 0 | 0 | match |  | match |
| command-doctor | 0 | 0 | partial | stdout | mismatch |
| command-diff | 0 | 0 | match |  | mismatch |
| populated-install | 0 | 0 | match |  | match |
| populated-ci | 0 | 0 | match |  | match |
| populated-uninstall | 0 | 0 | match |  | match |
| populated-update | 0 | 0 | match |  | match |
| populated-outdated | 1 | 1 | match |  | mismatch |
| populated-audit | 0 | 0 | match |  | mismatch |
| populated-fund | 0 | 0 | match |  | match |
| cache-add-registry | 0 | 0 | match |  | mismatch |
| cache-list-populated | 0 | 0 | match |  | mismatch |

## Remaining measured differences

- `command-sbom`: npm emits an SBOM without a public lockfile; rnpm requires one.
- `registry-stage`: npm emits the collected items array; rnpm emits the pagination envelope.
- `registry-trust`: empty trust-list output differs in JSON mode.
- `registry-login`: npm falls back to a username prompt on this mock; rnpm requires an environment token.
- `registry-adduser`: same interactive/authentication limitation as login.
- `command-completion`: Windows unsupported-command diagnostic/log-footer behavior differs.
- `command-help`: command listing and configuration/version footer differ.
- `command-doctor`: npm runs the requested connection check; rnpm prints its broader environment diagnostic.

## Validation and limits

- `cargo test --workspace -j 4 -- --test-threads=1`: exit 101. It stops at `crates/rnpm-cli/tests/npm_parity_outdated_test.rs::test_outdated_column_layout_and_json_parity` (line 34). The table golden still expects dependent `test-pkg`; actual npm-compatible output uses the temporary project directory name. This failure is retained, not skipped. Later workspace test binaries were not run after this failure.
- `cargo clippy --workspace --all-targets -j 4 -- -D warnings`: exit 0, zero warnings.
- Focused replacement regressions: 6 passed; filesystem crate tests: 89 passed. Earlier focused cache, script-policy, star and unpublish tests also passed. These focused results do not substitute for the failed complete workspace run.
- The baseline and final behavioral gates both exit 1: 63/139 and 131/139 matches respectively. The remaining failures are retained above.
- The repository isolation checker could not run because this host disables PowerShell script execution. Its self-test and scan are not reported as passed.
- All implementation targets compiled through Cargo test/check. A final release rebuild and lane4 rerun were not performed during wrap-up. The PR is a draft and is not ready to merge.

No performance optimization or lane4 benchmark was attempted. The historical [lane4 evidence](../benchmarks/results/lane4-after-shutdown-fix-2026-11-13.json) reported 1.33x cold CI; it does not measure this candidate, and the 2x target remains unproven.

Real private-registry authentication, browser/TTY/OTP login, OIDC/trusted publishing, actual publication, the 100-project corpus, all archive-pattern edge cases, and non-Windows behavior remain unverified. The npx-style probe exercises exec semantics; it does not establish a separately installed drop-in npx launcher. Cross-platform CI and review are pending on the draft PR.

The user stopped implementation at this point. No further compatibility or performance work is running.
