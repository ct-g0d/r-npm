# npm replacement readiness, 2026-11-13

Verdict: the final Windows release gate has **194/194 exact normalized matches**. This establishes parity for the registered probes; rnpm is not a verified universal npm replacement. Keep npm available for the incomplete and unverified workflows listed below.

## Provenance and reproduction

Implementation head: `cdbf51a626389ab62f9af780c64a4049e66eaa01`. The final report was generated after a successful `cargo build --release`, from a clean tracked source tree (report source_dirty: false). Documentation and generated evidence are committed afterward. Oracle: npm 11.20.0, Node v26.13.0, Windows. These are correctness comparisons, not performance measurements.

- Release executable SHA-256: `eef18313458ca09aced0749e48871250840123021923d733fc2c02596ba1531d`.
- Raw fixture and log root: `C:\Users\CHARL_~1\AppData\Local\Temp\rnpm-replacement-xfbEJn` (local temporary evidence).
- [Final behavioral evidence](npm-replacement-results-2026-11-13.json).
- [Historical baseline](npm-replacement-baseline-2026-11-13.json): 63/139; the final suite adds 55 probes and is larger than that baseline.

```powershell
cargo build --release
node scripts/check-npm-replacement.mjs --output docs/npm-replacement-results-2026-11-13.json
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
node scripts/generate-npm-command-coverage.mjs
```

The final gate exits 0. It rejects execution failures, exit mismatches, any normalized stdout/stderr mismatch, project/userconfig file mismatches, and POST/PUT/DELETE request-body differences. It also rejects an empty or incomplete run. No case is skipped or converted into a pass.

Each command runs in sibling isolated projects with separate user/global configuration, prefix, cache and store. Registry probes use loopback HTTP with synthetic credentials. Stage upload and trusted-publisher creation mutate only the mock. The gate retains normalized streams, hashes, file snapshots, registry requests and comparisons; raw streams remain under the printed temporary root. Long streams are excerpted only after comparing and hashing the complete output.

Normalization covers fixture/configuration paths and JSON escaping, loopback origins, CRLF, elapsed summary/ping times, generated diagnostic-log timestamps, generated UUIDs and millisecond UTC timestamps, and the npm installation root. Couch authentication request dates are normalized after checking the ISO timestamp shape. JSON file key order is ignored; fields remain present. stderr is compared without suppressing diagnostic footers. Cache/store contents and empty-directory presence are not compared.

## Fixed behavior

- [Packing](../crates/rnpm-fs/src/tarball.rs): files entries override root ignore files; directory-local .npmignore/.gitignore rules apply with relative scope and negations; literal file entries remain required. Portable USTAR headers and archive order now match the measured fixtures. Compression uses Node's built-in zlib to reproduce the oracle runtime's gzip bytes without calling npm or loading npm modules. Installation decompression is unchanged.
- [Install persistence](../crates/rnpm-install/src/lib.rs) and [lifecycle phases](../crates/rnpm-lifecycle/src/lib.rs): dependency scripts complete before lock persistence; public/hidden locks precede root hooks; failed root hooks retain npm's lockfile effects. Explicit package installs skip root hooks. CI persists the hidden lock before root-hook failure.
- [Workspace and save specs](../crates/rnpm-install/src/save.rs): parent-directory selectors, filtered workspace materialization and hidden-lock scope, redundant workspace names, range-preserving save specs, alias ranges and configured save-exact. [Git](../crates/rnpm-install/src/git.rs) decodes file URLs before invoking git, fixing local paths containing escaped characters.
- [Dependency listing](../crates/rnpm-cli/src/list.rs): optional/peer/missing/invalid/extraneous output, Unicode branches, dependency/problem ordering, long JSON fields, and successful exit for trees with only extraneous packages.
- [Cache](../crates/rnpm-cli/src/commands/cache.rs): registry cache add downloads and verifies actual archive bytes instead of writing a package-name marker; cache listing reads index keys instead of internal storage filenames.
- CLI output and effects: empty uninstall lockfiles, dedupe/find-dupes summaries, install-test/CI-test spacing, pkg/link/search/ping output, audit root dependency counts, outdated dependent names and status exits, real diagnostic logs, unpinned script approvals, local bugs/docs/repo URLs, access-list packages, and empty logout configuration removal. [Diff](../crates/rnpm-cli/src/diff.rs) honors configured registries and includes version headers. [Registry mutations](../crates/rnpm-registry/src/client.rs) use minimal star documents and revision-based unpublish ordering.

Rust regressions include [replacement_gaps_test.rs](../crates/rnpm-cli/tests/replacement_gaps_test.rs), existing pack/cache/script-policy/star/unpublish tests, filesystem tests, and installer save/workspace/lifecycle tests. Existing ASCII tree assertions now select Unicode=false explicitly; Unicode output is independently compared with npm. Outdated assertions retain the same version checks while expecting npm's directory-based dependent name.


Additional completed work in this continuation:

- [Doctor](../crates/rnpm-cli/src/doctor.rs): verified the WIP release build, retained doctor perf, removed the dead custom standard report, and compared connection, registry, environment and unknown groups with npm.
- [Authentication](../crates/rnpm-cli/src/commands/login.rs), [dispatch](../crates/rnpm-cli/src/main.rs): distinct login/adduser web payloads, login URL output, pending doneUrl polling, canonical npmjs done-host rebasing, HTTP 4xx/500 legacy fallback, stdin username/password/email prompts, couch conflict retry, token cleanup and configured userconfig persistence. Eight login/adduser probes changed from DIFF to MATCH. No real credentials were used.
- [Trust creation](../crates/rnpm-cli/src/commands/trust.rs): GitHub/GitLab/CircleCI claim bodies, permission selection, text/JSON output, dry-run, repository inference and confirmation. Nine create/JSON/dry-run probes changed from DIFF to MATCH.
- [Stage](../crates/rnpm-cli/src/commands/stage.rs): download summaries and archive bytes, missing/invalid IDs, directory stage publish uploads, JSON stage IDs and dry-run output. Eight probes changed from DIFF to MATCH.
- [Registry cache](../crates/rnpm-install/src/lib.rs): removed the invented 300-second freshness assumption when HTTP freshness headers have not been stored. Unlocked packuments revalidate by ETag unless offline/prefer-offline is requested. This can increase metadata requests; performance was not remeasured.
- [Audit](../crates/rnpm-cli/src/audit.rs): empty inventories make no advisory POST, matching npm. POST comparison exposed this difference.
- [List](../crates/rnpm-cli/src/list.rs): retain required on the first missing dependency, matching npm's breadth-first seenNodes behavior. The new single-missing probe failed before the fix; all 20 listing probes now match.
- [Tests](../crates/rnpm-cli/tests): outdated uses loopback metadata and compares npm's actual dependent name. Doctor/auth/script-log expectations follow npm. SBOM tests require explicit formats and lock-only mode for lockfile fixtures, compare complete oracle documents, and retain actual-tree missing-dependency errors. Only generated document UUIDs/timestamps and diagnostic-log filenames vary.

## Probe and command coverage results

| Measurement | Historical baseline | Final release |
|---|---:|---:|
| Matching behavioral probes | 63/139 | 194/194 |
| Remaining DIFFs | 76 | 0 |

Generated command classifications: **71 matching, 2 partial, 0 missing**, out of 73 tracked canonical/legacy entries. [Coverage matrix](npm-command-coverage.md) and [raw coverage](npm-command-coverage-raw.json) use this final report. Matching is a probe classification, not a completion percentage; negative-only commands remain partial even when their observed errors match.

| Probe | npm exit | rnpm exit | Result | Differing observations | Historical baseline |
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
| ls-single-missing-json | 1 | 1 | match |  | not probed |
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
| command-sbom | 0 | 0 | match |  | mismatch |
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
| registry-stage | 0 | 0 | match |  | mismatch |
| registry-trust | 0 | 0 | match |  | mismatch |
| registry-login | 1 | 1 | match |  | mismatch |
| registry-adduser | 1 | 1 | match |  | mismatch |
| registry-login-web-success | 0 | 0 | match |  | not probed |
| registry-login-legacy-couch-success | 0 | 0 | match |  | not probed |
| registry-login-web-couch-success | 0 | 0 | match |  | not probed |
| registry-adduser-web-success | 0 | 0 | match |  | not probed |
| registry-adduser-legacy-couch-success | 0 | 0 | match |  | not probed |
| registry-adduser-web-couch-success | 0 | 0 | match |  | not probed |
| command-approve-scripts | 0 | 0 | match |  | mismatch |
| command-deny-scripts | 0 | 0 | match |  | match |
| command-install-scripts | 0 | 0 | match |  | mismatch |
| command-set | 0 | 0 | match |  | match |
| command-set-script | 1 | 1 | match |  | match |
| command-completion | 1 | 1 | match |  | mismatch |
| command-help | 0 | 0 | match |  | mismatch |
| command-help-search | 0 | 0 | match |  | match |
| command-doctor | 0 | 0 | match |  | mismatch |
| doctor-registry | 1 | 1 | match |  | not probed |
| doctor-environment | 1 | 1 | match |  | not probed |
| doctor-unknown | 0 | 0 | match |  | not probed |
| sbom-populated-spdx | 0 | 0 | match |  | not probed |
| sbom-populated-cyclonedx | 0 | 0 | match |  | not probed |
| sbom-populated-cyclonedx-application | 0 | 0 | match |  | not probed |
| sbom-populated-omit-dev | 0 | 0 | match |  | not probed |
| sbom-populated-lock-only | 0 | 0 | match |  | not probed |
| sbom-missing-format | 1 | 1 | match |  | not probed |
| sbom-lock-only-without-lock | 1 | 1 | match |  | not probed |
| sbom-missing-dependency | 1 | 1 | match |  | not probed |
| stage-list | 0 | 0 | match |  | not probed |
| stage-list-json | 0 | 0 | match |  | not probed |
| stage-list-filter-empty | 0 | 0 | match |  | not probed |
| stage-list-version-spec | 1 | 1 | match |  | not probed |
| stage-bare | 1 | 1 | match |  | not probed |
| stage-view | 0 | 0 | match |  | not probed |
| stage-view-json | 0 | 0 | match |  | not probed |
| stage-view-missing-id | 1 | 1 | match |  | not probed |
| stage-view-invalid-id | 1 | 1 | match |  | not probed |
| stage-approve | 0 | 0 | match |  | not probed |
| stage-reject | 0 | 0 | match |  | not probed |
| stage-approve-missing-id | 1 | 1 | match |  | not probed |
| trust-list | 0 | 0 | match |  | not probed |
| trust-list-json | 0 | 0 | match |  | not probed |
| trust-list-empty | 0 | 0 | match |  | not probed |
| trust-list-from-manifest | 0 | 0 | match |  | not probed |
| trust-revoke | 0 | 0 | match |  | not probed |
| trust-revoke-dry-run | 0 | 0 | match |  | not probed |
| trust-revoke-missing-id | 1 | 1 | match |  | not probed |
| trust-bare | 1 | 1 | match |  | not probed |
| command-diff | 0 | 0 | match |  | mismatch |
| trust-create-github-create | 0 | 0 | match |  | not probed |
| trust-create-github-create-json | 0 | 0 | match |  | not probed |
| trust-create-github-dry-run | 0 | 0 | match |  | not probed |
| trust-create-gitlab-create | 0 | 0 | match |  | not probed |
| trust-create-gitlab-create-json | 0 | 0 | match |  | not probed |
| trust-create-gitlab-dry-run | 0 | 0 | match |  | not probed |
| trust-create-circleci-create | 0 | 0 | match |  | not probed |
| trust-create-circleci-create-json | 0 | 0 | match |  | not probed |
| trust-create-circleci-dry-run | 0 | 0 | match |  | not probed |
| stage-download | 0 | 0 | match |  | not probed |
| stage-download-json | 0 | 0 | match |  | not probed |
| stage-download-missing | 1 | 1 | match |  | not probed |
| stage-download-invalid | 1 | 1 | match |  | not probed |
| stage-publish | 0 | 0 | match |  | not probed |
| stage-publish-json | 0 | 0 | match |  | not probed |
| stage-publish-dry-run | 0 | 0 | match |  | not probed |
| stage-publish-dry-run-json | 0 | 0 | match |  | not probed |
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

None in the final 194-probe Windows suite.

The first full release sweep in this continuation was 174/176 (exit 1): stale changing-packument metadata and an unnecessary empty-audit POST. Both causes were fixed, then verified in focused probes and the final expanded suite.

## Validation and unfinished work

- `cargo build --release`: exit 0; final gate uses that executable.
- `cargo test --workspace`: exit 0; **1,037 passed, 0 failed, 1 existing ignored benchmark** (`bench_fetch_matrix`). All workspace test binaries and doc-tests completed. Earlier failures were investigated and fixed, not skipped; the final invocation has no filters.
- `cargo clippy --workspace --all-targets -- -D warnings`: exit 0, zero warnings.
- Final differential gate: **194/194**, exit 0.
- Interactive terminal/browser launching and OTP exchanges are not fully ported or verified. Reusing saved username/password prompt defaults is incomplete. Web and legacy non-TTY exchanges are verified only against the mock.
- Stage publish coverage is directory-based. Remote package/tarball specs, provenance and complete publish-time validation still need work; these probes do not establish full npm publish semantics.
- Doctor version checks and POSIX permissions/cache verification need broader coverage; this host verifies the requested Windows groups only.
- Real private registries, real trusted-publisher/OIDC exchanges, real publication and cross-platform behavior remain unverified. The draft PR has no approving review; GitHub checks were pending at wrap-up.
- The 100-project replacement corpus and performance gates were not run. The historical lane4 1.33x cold result is not a measurement of this candidate; the 2x target remains unproven.

Implementation stopped at the user's time limit. No additional compatibility work was started during wrap-up.
