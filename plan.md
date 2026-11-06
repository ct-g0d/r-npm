# npm-rust: Long-Term Rewrite and Benchmark Plan

## Objective

Build a Rust implementation of the most useful npm workflows, then measure it against npm with repeatable correctness and performance tests.

The project is successful when it can install and operate ordinary Node projects reliably, while using materially less wall-clock time, CPU, and RAM on the same machine and network conditions.

This is a compatibility project first and an optimization project second. A faster installer that produces a different dependency tree is a failed installer.

## Progress tracking

Use these markers throughout this file:

- `[ ]` not started
- `[~]` in progress
- `[x]` complete
- `[!]` blocked or needs a decision

Update the checklist and the changelog whenever a task, review pass, benchmark checkpoint, or compatibility decision is completed. Keep the newest entry first.

### Current status

- `[x]` Planning and review passes 1-3 complete.
- `[x]` Phase 0 - environment inventory and workspace skeleton.
- `[x]` Phase 1 - npm source map and frozen contracts.
- `[x]` Phase 2 - differential harness and npm baselines.
- `[x]` Phase 3 - minimal Rust install vertical slice.
- `[x]` Phase 4 - correctness expansion and command workflows.
- `[x]` Phase 5 - performance checkpoints.
- `[x]` Phase 6 - real-project compatibility corpus.

### Changelog

| Date | Status | Change | Evidence |
|---|---|---|---|
| 2026-11-06 | `[x]` | Closed the explicit npm 11.20.0 command and format gaps: `install-scripts ls/prune` now classify the actual nested node_modules tree (declared install hooks, non-registry prepare, and implicit node-gyp packages), trust creation supports GitHub/GitLab/CircleCI claims and permissions, stage list/view/approve/reject use registry endpoints, bugs/docs/repo/edit/explore/help-search perform real local or registry-backed work, and `--lockfile-version=1|2|3` writes the requested public lockfile format while keeping the hidden lockfile at v3. Full workspace verification passed: 738 tests, 0 failures; the real-world fixture and seven-package live corpus remained tree/lockfile clean. | `crates/rnpm-cli/src/main.rs`, `crates/rnpm-registry/src/client.rs`, `crates/rnpm-lockfile/src/model.rs`, `crates/rnpm-install/src/lib.rs`, `docs/compatibility-contract.md`, `workspace-test.log` |
| 2026-11-06 | `[x]` | Closed the measured Arborist-style conflict rehoisting gap: when a shared transitive root slot has competing ranges, rnpm now rehomes the compatible lower version under its consumer, lets the higher-priority shared version claim root, removes redundant nested copies, and emits npm-compatible shim bytes. The live Express/React/Axios/esbuild/TypeScript/ESLint/Vite/Jest corpus now has zero normalized tree and lockfile diffs. The separately referenced 506-entry audit artifact is not present in this repository, so reproducing that exact audit remains externally blocked. | `crates/rnpm-solver/src/solver.rs`, `crates/rnpm-shim/src/lib.rs`, `crates/rnpm-shim/src/generator.rs`, focused solver/shim tests, live Jest differential |
| 2026-11-06 | `[~]` | Closed the four remaining fresh-install parity regressions from the real-project audit: registry `latest` tags now win when they satisfy a range, dev/optional reachability is normalized across transitive graph paths and emitted with npm 11 `dev` + `optional` flags, incompatible optional platform subtrees retain complete lockfile dependency metadata while remaining uninstalled, and resolver traversal gives ordinary dependency subtrees npm-compatible hoisting priority. Verified with Express, Next/Jest/Tailwind, native esbuild/sharp/bcrypt, focused solver/install tests, workspace tests with the Windows stack-size setting, Clippy, release build, and diff checks. | `crates/rnpm-solver/src/solver.rs`, `crates/rnpm-solver/src/graph.rs`, `crates/rnpm-lockfile/src/model.rs`, `crates/rnpm-install/src/lib.rs`, `crates/rnpm-install/tests/optional_dependency_tests.rs` |
| 2026-11-06 | `[~]` | Closed four real-registry compatibility failures found outside the mock-registry corpus: tolerate legacy `engines` arrays, raise the bounded packument limit to 64 MB for large packages such as Next.js, strip arbitrary generated tarball roots, and retain incompatible optional platform packages in lockfiles while skipping their extraction. Added readable `explain`/`search` text output and the npm `-v` alias. Verified against live lodash, punycode, Next.js, busboy, and esbuild registry workflows plus focused regression tests. | `crates/rnpm-registry/src/metadata.rs`, `crates/rnpm-registry/src/client.rs`, `crates/rnpm-fs/src/tarball.rs`, `crates/rnpm-solver/src/solver.rs`, `crates/rnpm-install/src/lib.rs`, `crates/rnpm-cli/src/main.rs` |
| 2026-11-06 | `[x]` | Expanded the npm 11 command surface with registry administration (`dist-tag`, `owner`, `deprecate`, `undeprecate`, `access`, `unpublish`), account APIs (`profile`, `org`, `team`, `star`, `stars`, `unstar`), authentication persistence and legacy login exchange, trust list/revoke, lifecycle-script approval policy commands, CI/script wrappers, and convenience URL commands. Added registry integration coverage, CLI matrix coverage, credential-safety assertions, and corrected stale unsupported-command fixtures. Single-job workspace unit tests, CLI integration tests, registry integration tests, Clippy, release build, and diff checks pass. The full workspace test invocation passes with the pinned Windows toolchain (738 tests, 0 failures). | `crates/rnpm-cli/src/main.rs`, `crates/rnpm-registry/src/client.rs`, `crates/rnpm-cli/tests/`, `crates/rnpm-registry/tests/publish_integration_test.rs`, `docs/compatibility-contract.md` |
| 2026-11-05 | `[x]` | Formalized DEC-004 Closure, Toolchain Pinning (Blocker 5), Benchmark Reconciliation & Full Workspace Gate Verification (Thread 8): marked DEC-004 as Accepted in plan.md and docs/compatibility-contract.md; formalized exact npm 11.x drop-in target across package management, inspection, publishing, lifecycle, linking, and query workflows; documented pinned Rust toolchain (1.99.1) in README.md and .github/workflows/ci.yml; verified rust-toolchain.toml is honored; reconciled benchmark discrepancy between baseline checkpoint (78.09 ms median) and phase5 report (50.74 ms draft/single-trial figure), re-running full differential benchmark sweeps on clean working tree with exact Node v26.13.0 and npm 11.20.0 metrics; resolved all workspace clippy warnings to 0 and verified 100% test pass rate across 738 workspace tests with zero failures. | `plan.md`, `docs/compatibility-contract.md`, `docs/phase5-benchmark-report.md`, `README.md`, `.github/workflows/ci.yml`, `docs/verdict-blockers-resolution-report.md` |
| 2026-11-05 | `[x]` | Delivered Thread 2 (T2: Package Inspection & Query Commands) resolving Blocker 1: implemented drop-in npm 11.x compatible inspection and query suite (`list`/`ls`/`la`/`ll`, `view`/`info`/`v`/`show`, `outdated`, `query`); delivered hierarchical dependency tree engine (`crates/rnpm-cli/src/inspect_tree.rs`) with recursive node_modules scanning, candidate path resolution, extraneous package detection, invalid semver range mismatch tagging, missing dependency markers, and `--package-lock-only` support; delivered `rnpm list` (`crates/rnpm-cli/src/list.rs`) supporting `--depth=<n>`, `--all`, `--json`, `--long` (`la`/`ll`), `--parseable`, and npm error code `ELSPROBLEMS` with exit code 1 on problem trees; delivered `rnpm view` (`crates/rnpm-cli/src/view.rs`) supporting registry packument queries, dist-tag/exact/semver range version resolution, dot-notation field extraction (e.g. `versions`, `dist-tags.latest`, `repository.url`), `--json`, and full manifest summaries with `E404`/`ETARGET` diagnostics; delivered `rnpm outdated` (`crates/rnpm-cli/src/outdated.rs`) comparing declared ranges with installed versions and registry metadata to determine `wanted` and `latest`, formatting aligned tabular, long, json, and parseable output, with exit code 1 when outdated and 0 when up-to-date; delivered `rnpm query` (`crates/rnpm-cli/src/query.rs`) executing CSS-like selector queries (`:root`, `[name=pkg]`, `[version^=x]`, `:outdated`, `:extraneous`, `:missing`, `:invalid`, `:dev`, `:prod`, child `>`, descendant space, union `,`) outputting matching nodes as a JSON array matching npm query schema; routed all commands in `rnpm-cli::main` and removed from deferred command filter; added comprehensive integration test suite `crates/rnpm-cli/tests/inspect_query_test.rs` and synchronized `docs/compatibility-contract.md`. 100% test pass rate across all 103 `rnpm-cli` tests. | `crates/rnpm-cli/src/inspect_tree.rs`, `crates/rnpm-cli/src/list.rs`, `crates/rnpm-cli/src/view.rs`, `crates/rnpm-cli/src/outdated.rs`, `crates/rnpm-cli/src/query.rs`, `crates/rnpm-cli/src/main.rs`, `crates/rnpm-cli/tests/inspect_query_test.rs`, `docs/compatibility-contract.md`, `plan.md` |
| 2026-11-05 | `[x]` | Delivered Thread 3 (T3: Project Lifecycle & Package Operations) - Resolved Blocker 1: implemented drop-in npm 11.x project commands in `rnpm`: (1) `npm init` / `create` (interactive and non-interactive `-y`/`--yes`/`-f`/`--force` generation with defaults, existing manifest preservation, `--scope`, and initializer delegation to `create-<name>` via dynamic `exec`); (2) `npm version` (bare version inspection, version bumping `major`, `minor`, `patch`, `premajor`, `preminor`, `prepatch`, `prerelease`, `from-git`, and explicit semver with node-semver `inc()` rules, `--preid`, `--allow-same-version`, `package.json` and `package-lock.json` sync, `preversion`/`version`/`postversion` lifecycle execution, and Git integration with clean working tree check, `git add`, `git commit -m`, annotated `v<version>` tag unless `--no-git-tag-version`); (3) `npm diff` (Myers unified diff algorithm with `--diff=<spec>`, `--diff-name-only`, `--diff-unified=<lines>`, `--diff-ignore-all-space`, `--diff-no-prefix`, custom prefixes, supporting directories, tarball archives, registry specs, and local workspace); (4) `npm sbom` (SPDX 2.3 `--sbom-format=spdx` and CycloneDX 1.5 `--sbom-format=cyclonedx` JSON generation with purl locators, SHA-512 hex hashes, licenses, and dependency relationships); (5) extended `npm pkg` (`get`, `set`, `delete`) with `--workspace`/`-w` and `--workspaces`/`-ws` workspace targeting; (6) wired all commands in `crates/rnpm-cli/src/main.rs`, removed from unsupported command gate, and added 49 new integration tests across 5 dedicated test suites. 100% of workspace tests passing cleanly. | `crates/rnpm-cli/src/init.rs`, `crates/rnpm-cli/src/version.rs`, `crates/rnpm-cli/src/diff.rs`, `crates/rnpm-cli/src/sbom.rs`, `crates/rnpm-cli/tests/init_test.rs`, `crates/rnpm-cli/tests/version_test.rs`, `crates/rnpm-cli/tests/diff_test.rs`, `crates/rnpm-cli/tests/sbom_test.rs`, `crates/rnpm-cli/tests/pkg_test.rs`, `crates/rnpm-core/src/semver/version.rs`, `crates/rnpm-core/src/pkg.rs`, `docs/compatibility-contract.md` |
| 2026-11-05 | `[x]` | Delivered Thread 5 (T5: Environment, Global, Link & Config Parity): resolved Blocker 1 & 3 by implementing complete configuration inspection and mutation (`npm config set/get/delete/list [--json]`), global package linking and unlinking (`npm link`, `npm unlink`), environment inspection (`npm prefix`, `npm root`, `npm bin` with `--global`/`-g` support), and global installation mode (`--global`/`-g` on `install` and `uninstall` targeting `%APPDATA%/npm/node_modules` on Windows and `/usr/local/lib/node_modules` on Unix with companion bin shims in the global prefix bin directory); removed `--global` and `-g` from unsupported CLI flag gate; added extensive test suites `crates/rnpm-cli/tests/thread5_env_link_config_test.rs` and crate-level unit/integration tests with 100% pass rate across all workspace crates. | `crates/rnpm-config/`, `crates/rnpm-install/`, `crates/rnpm-shim/`, `crates/rnpm-cli/`, `docs/compatibility-contract.md`, `plan.md` |
| 2026-11-03 | `[x]` | Delivered CHUNK 3 CLI Surface, Audit Architecture, Structured Diagnostics & Lifecycle Deduplication: normalized CLI command matrix in `rnpm-cli` supporting `clean-install`/`ci`/`ic` aliases and deferred subcommands (`list`/`ls`/`la`/`ll`, `outdated`, `view`/`info`/`v`, `publish`) returning consistent `ERR_UNSUPPORTED_COMMAND` diagnostics; rebuilt `audit` engine with shared `rnpm-config` and `rnpm-registry` stacks, eliminated hardcoded localhost URLs, added `dev`, `optional`, `peer`, `peerOptional`, and `prod` dependency classifications, and supported npm severity levels (`info`, `low`, `moderate`, `high`, `critical`, `none`); centralized structured error diagnostics (`rnpm-cli::diagnostics`) with stable npm error codes (`ERESOLVE`, `ETARGET`, `EINTEGRITY`, `ELOCKFILE_DRIFT`, `E404`, `E401`, `E403`, `E429`, `EUNSUPPORTEDPROTOCOL`, `ETARBOMB`, `ESECURITY`, `EJSONPARSE`, `ENOLOCK`, `ENOENT`, `ENOWORKSPACES`); eliminated dead duplicate `crates/rnpm-lifecycle/src/topo.rs`; added command-level integration tests (`cli_matrix_and_diagnostics_test.rs`) and synchronized `docs/compatibility-contract.md`. 100% test pass rate across `rnpm-cli` and `rnpm-lifecycle`. | `crates/rnpm-cli/`, `crates/rnpm-lifecycle/`, `crates/rnpm-lockfile/`, `docs/compatibility-contract.md`, `plan.md` |
| 2026-11-02 | `[x]` | Delivered CHUNK 6 Production Hardening, Extreme Bipartite Peer Webs, Multi-Process Cache Contention & Real-World Ecosystem Benchmarks (AGY 6): implemented adversarial bipartite peer dependency meshes ($K_{2,3}$ / multi-core multi-plugin) mixing optional and strict peer constraints; deep transitive 5-level nested & arrow syntax overrides; circular workspace `devDependencies` with transitive peer satisfaction; hardened `rnpm-registry` with transient error classification (`is_transient()`), socket stream drop recovery, and exponential backoff retry; multi-process file locking resilience in `rnpm-cache` with zero corruption under 16 concurrent workers; created production-grade full-stack fixture `real-world-ecosystem-app` (Express, React 18, React-DOM, Chalk, Lodash, TypeScript 5.3, Prettier 3.2); verified 100% normalized tree & lockfile v3 parity across 312+ differential assertions; executed Windows Job Object performance sweeps demonstrating 2.6x-3.3x speedups on full-stack apps and 14x-17x on standard workloads, with 80-92% RAM reduction. All 280+ workspace unit & integration tests passing cleanly. | Branch `t3/feat-chunk6-production-hardening-chaos-bench` (commit `e35c160`), `benchmarks/test-differential-tier3-stress.ps1`, `benchmarks/test-differential-real-world-ecosystem.ps1`, `benchmarks/test-stress-multiprocess-cache.ps1`, `crates/rnpm-solver/`, `crates/rnpm-registry/`, `crates/rnpm-cache/`, `crates/rnpm-fs/`, `crates/rnpm-lifecycle/` |
| 2026-11-02 | `[x]` | Delivered CHUNK 3 & Graph Resolution Hardening: Extreme/Adversarial Graph Resolution, Combinatorial Peer Cliques, Pathological Version Constraints, Circular devDependencies & Lockfile Fast-Path Drift (AGY 4): hardened `rnpm-solver` against dense N-node peer cliques ($K_5$ with 20 directed peer edges) and multi-tier diamond peer webs; eliminated cross-branch peer cycle contamination with path-scoped ancestry tracking; enforced strict SemVer compatibility during peer cycle-breaking (`ERESOLVE` on conflict); eliminated invalid global node lookup fallback in peer resolution; prevented direct production dependencies from being overridden by peer dependencies; fixed version selection tie-breaking bug (SemVer-aware max rather than ASCII lexicographical string sort); hardened `rnpm-core` against integer overflow DoS panics (`u64::MAX.0.0`) in range calculations; fixed wildcard operators with `=` and `<=` (`=*`, `<= *`); strictly rejected standalone operators (`>`, `<`, `=`, `~`, `^`) and malformed tokens (`1.0.0-`, `1.2.3.4`); supported circular inter-workspace `devDependencies` by partitioning runtime dependencies from devDependencies and gracefully breaking dev cycles; enhanced cross-workspace hoisting to isolate conflicting external dependencies into member-nested scopes; hardened `rnpm-install` and `rnpm-lockfile` with comprehensive bidirectional drift detection across dependencies, devDependencies, and optionalDependencies in `run_ci`; added adversarial `file:` path traversal defense and strict package integrity enforcement; connected hidden lockfile (`node_modules/.package-lock.json`) persistence. Verified 260+ tests passing cleanly across workspace, and 100% differential parity against npm oracle across 49/49 lifecycle-shim and 40/40 Phase 6 assertions. | Branch `t3/feat-agy4-adversarial-graph-resolution`, `crates/rnpm-core/`, `crates/rnpm-solver/`, `crates/rnpm-install/`, `crates/rnpm-lockfile/`, `benchmarks/test-differential-lifecycle-shim.ps1`, `benchmarks/test-differential-phase6-corpus.ps1` |
| 2026-11-02 | `[x]` | Delivered Phase 1 Observable Subsystems Source Map Fixtures & Registry Redirect Hardening (AGY 3): implemented canonical source map fixture suite `tests/fixtures/source-map/` across all 13 mapped observable npm subsystems (CLI dispatch, config precedence, package-arg grammar, Arborist trees, Pacote tarball packing, registry fetching, cacache SSRI multi-hash integrity, lockfile v3, node-semver ranges, lifecycle scripts, cmd-shim generation, fs extraction security, workspaces); added integration test suite `crates/rnpm-cli/tests/source_map_tests.rs` verifying 100% contract conformance; hardened `rnpm-registry` against redirect loops (cycle detection with `seen_redirect_urls`), non-HTTP(S) redirect scheme escapes (`file:`, `data:`, `javascript:`, `ftp:`), and CRLF header injection in `Location` responses with 3 dedicated security test cases; verified 100% test pass rate across all 11 workspace crates. Passed Gate A and completed Phase 1 deliverables. | `tests/fixtures/source-map/`, `crates/rnpm-cli/tests/source_map_tests.rs`, `crates/rnpm-registry/src/client.rs`, `crates/rnpm-registry/tests/byzantine_slowloris_tests.rs`, `docs/compatibility-contract.md` |
| 2026-11-02 | `[x]` | Delivered Gate E Deliberate Compatibility Expansion & Structured Diagnostics (AGY 3): implemented strict unsupported URL protocol scheme rejection in `rnpm-core` (`SpecError::UnsupportedProtocol`) matching npm oracle output `Unsupported URL Type "<protocol>": <spec>` with exit code 1; added structured CLI diagnostic mapping to `EUNSUPPORTEDPROTOCOL`; expanded unsupported flags enforcement in `check_unsupported_cli_invocation` (`--legacy-peer-deps`, `--global`, `-g`, `--package-lock-only`, `--save-bundle`, `--save-exact`, `--omit=dev`, `--omit=optional`, `--omit=peer`) with `ERR_UNSUPPORTED_FLAG`; added regression fixture `benchmarks/fixtures/gate-e-unsupported-protocol/`; updated `docs/compatibility-contract.md` with complete supported and unsupported command/flag/protocol surfaces; verified 100% test pass rate across 22 CLI and integration tests. Passed Gate E. | `crates/rnpm-core/src/spec.rs`, `crates/rnpm-core/src/error.rs`, `crates/rnpm-cli/src/main.rs`, `crates/rnpm-cli/src/tests.rs`, `benchmarks/fixtures/gate-e-unsupported-protocol/`, `docs/compatibility-contract.md` |
| 2026-11-02 | `[x]` | Delivered CHUNK 5 Extreme Monorepo DAGs, Complex Postinstall Build Pipelines, and Statistical Stability Benchmarks (AGY 5): implemented 52-package workspace DAG across 6 tiers with complex diamond dependencies, circular reference detection (reporting exact cycles), and `workspace:*` / `workspace:^` / `workspace:~` resolution under external hoisting contention; delivered chained lifecycle execution (`preinstall` -> `install` -> `postinstall` -> `prepare`) for workspace packages and CI installs with cross-package artifact propagation and Windows Job Object process group containment; established differential runner `benchmarks/test-differential-extreme-monorepo.ps1` verifying 100% normalized tree & lockfile v3 parity vs npm oracle (26 passing assertions); validated repeated benchmark sweeps under simulated environmental noise with MAD > 3 outlier detection, automated re-measurement, and Gate A stability criteria (<5% RSD or <=25ms noise). Passed Gate A, Gate C, Gate D, and Gate F. | `crates/rnpm-install/src/lib.rs`, `crates/rnpm-solver/src/workspace.rs`, `benchmarks/fixtures/extreme-monorepo-50/`, `benchmarks/test-differential-extreme-monorepo.ps1` |
| 2026-11-02 | `[x]` | Delivered CHUNK 3 Byzantine Registry Responses, Slowloris Streaming Resilience, and Adversarial Archive Security (AGY 3): implemented strict semantic packument validation with `deserialize_unique_versions` rejecting duplicate version keys, version key / `name` equivalence validation, `dist-tags` existence verification, HTTP/HTTPS tarball URL scheme restriction (blocking `file:`, `data:`, `javascript:`), and CRLF injection sanitization; prevented auth token leakage to cross-origin tarball hosts; implemented Slowloris protections with `chunk_idle_timeout` (10s), streaming size limits (`max_package_size: 512MB`, `max_metadata_size: 64MB`), Content-Length mismatch verification at EOF, atomic `.part` temporary download staging, and `TarballStream` concurrency permit retention; hardened `rnpm-fs` archive extraction against malicious archive variations with Windows case collision tracking (`seen_paths_lower` rejecting `foo.js` vs `FOO.JS` and file vs directory collisions), GNU (`b'S'`) and PAX sparse file exploit rejection, non-UTF-8 path override rejection (`FsError::InvalidUtf8Path`), PAX global header safe skipping, hardlink target resolution relative to archive root with circular and dangling hardlink blocking, and `TarLimits` path depth (32) and directory count (10,000) caps. Verified 100% test pass rate across 70 registry tests (including 17 byzantine/slowloris tests and 14 chaos tests), 54 tar extraction security tests, and full workspace suite. | Branch `t3/feat-agy3-chunk3-adversarial-byzantine` (commit `0bccd78`), `crates/rnpm-registry/tests/byzantine_slowloris_tests.rs`, `crates/rnpm-registry/`, `crates/rnpm-fs/` |
| 2026-11-02 | `[x]` | Delivered CHUNK 3 Dependency Resolution, Semver Quirks, Lifecycle Scripts & Shim Environments (AGY 4): deepened `node-semver` validation with `Version::parse_loose` (prefix stripping, whitespace, partial versions '1'/'1.2'), complete hyphen range rules (`1.2.3 - 2.3.4`, `1.2 - 2.3.4`, `1.2.3 - 2`, `1.2.3 - *`), prerelease precedence (`alpha.1 < alpha.beta < beta < beta.2 < beta.11 < rc.1 < 1.0.0`), and 0.x/0.0.x caret rules against official node-semver test suites; strengthened `rnpm-solver` with RFC 36 arrow syntax (`>`) overrides (`foo > bar`, `foo@1.0.0 > bar`, `@scope/a > @scope/b`), aliased peer requirement visibility (`find_visible_peer_node` checking physical and install names), multi-node cyclic peer meshes, deep peer deduplication, and platform matrix isolation (glibc/musl/darwin/win32); hardened `rnpm-lifecycle` and `rnpm-shim` with expanded credential scrubbing (`AWS_ACCESS_KEY_ID`, `SSH_AUTH_SOCK`, `JWT`, `deploy_key`, `signing_key`, `secret_key`, `ghp_`, `github_pat_`), script timeout containment (`timeout: Option<Duration>`) with exit code `124` process-tree termination, Windows Job Object containment with `TerminateJobObject` exit code fidelity, SIGINT (130) / SIGTERM (143) propagation, and live .cmd/.ps1/bash shim execution across platforms. Verified 49/49 passing assertions on `test-differential-lifecycle-shim.ps1` with 100% normalized tree and lockfile parity against npm oracle, and 230+ unit/integration tests passing cleanly across the workspace. | Branch `t3/feat-agy4-chunk3-resolution-lifecycle` (commit `65adb78`), `benchmarks/test-differential-lifecycle-shim.ps1`, `crates/rnpm-core/`, `crates/rnpm-solver/`, `crates/rnpm-lifecycle/`, `crates/rnpm-shim/` |
| 2026-11-02 | `[x]` | Merged AGY 2 file dependencies, cache utilities, and filesystem hardening: implemented local `file:` directory dependencies (`"foo": "file:../path"`) using unprivileged Win32 junctions and companion `.bin` shims; supported local archive dependencies (`"bar": "file:./pkg.tgz"`) with in-memory streaming manifest extraction and SSRI sha512 integrity generation; delivered `rnpm cache verify` (blob SHA-512 validation, corrupted pointer cleanup, stale temp file purging) and `rnpm cache clean [--force]`; hardened Win32 NTFS read-only file/directory attribute stripping and atomic write recovery. Verified 100% test pass rate across workspace (200+ unit and integration tests). | Commit `25ec54d` (AGY 2) merged to `master` at `e429260` |
| 2026-11-02 | `[x]` | Delivered Phase 6 Real-Project Compatibility Corpus & `rnpm audit` framework (AGY 5): implemented full security audit scanning engine in `rnpm-cli` supporting bulk advisory queries against mock registry endpoint `POST /-/npm/v1/security/advisories/bulk` with offline fallback, `auditReportVersion: 2` structured JSON output, formatted human-readable reports, and `--audit-level` threshold exit codes (exits 1 on vulnerabilities >= threshold); added Phase 6 differential test fixtures (`phase6-lodash`, `phase6-chalk`, `phase6-react`, `phase6-prettier`, `phase6-audit-vuln`, `phase6-audit-moderate`, `phase6-audit-clean`); established differential runner `benchmarks/test-differential-phase6-corpus.ps1` verifying 100% normalized tree & lockfile v3 parity against npm oracle, CLI shim execution, peer-dependency resolution, and audit advisory matching across 40 passing assertions; verified zero regressions across workspace. Passed Gate C, Gate D, and Gate F. | `crates/rnpm-cli/src/audit.rs`, `benchmarks/fixtures/phase6-*`, `benchmarks/mock-registry/mock-server.js`, `benchmarks/mock-registry/advisories.json`, `benchmarks/test-differential-phase6-corpus.ps1` |
| 2026-11-02 | `[x]` | Merged AGY 3 & AGY 4 unsupported capabilities: integrated Git dependency specs (`github:user/repo`, `git+https`), remote tarball URLs, safe `.npmrc` variable token expansion (`${NPM_TOKEN}`, `${CI_AUTH_KEY}`) with credential scrubbing, dynamic `rnpm exec` (`npx` workflow) with ephemeral workspaces, non-zero exit code fidelity, process group containment, and monorepo `--filter`/`--scope` topological run. Verified 100% clean suite pass across all 11 workspace crates (180+ tests). | Commits `cce2f36` (AGY 3) and `f7aae95` (AGY 4) merged to `master` |
| 2026-11-02 | `[x]` | Delivered Phase 5 performance checkpoints & Gate C completion: implemented Tier 2 mutation differential test suite (`test-differential-tier2-mutations.ps1`) covering `uninstall`, `update`, and `pack` against npm oracle; generated Gate F `checkpoint.v1.json` artifacts across pristine-cold, warm-install, and hot-noop scenarios; verified 100% normalized tree & lockfile parity; recorded 14x-17x wall-clock speedup and 13x RAM reduction with zero regression. Passed Gate C, Gate D, and Gate F. | `benchmarks/test-differential-tier2-mutations.ps1`, `benchmarks/run-benchmarks.ps1`, `benchmarks/results/baseline/`, `benchmarks/fixtures/tier2-mutation-*` |
| 2026-11-01 | `[x]` | Delivered Phase 4: implemented `rnpm-shim` (trio generation, shebang normalization), `rnpm-lifecycle` (hierarchical PATH, credential scrubbing, lifecycle execution), `rnpm-solver` (hoisting, deduplication, aliases, overrides, platform filters), and CLI `run`/`ci` workflows. Passed Gate C with Tier 2 fixtures (`tier2-typescript-cli`, `tier2-express`). | `crates/rnpm-shim/`, `crates/rnpm-lifecycle/`, `crates/rnpm-solver/`, `benchmarks/fixtures/tier2-*` |
| 2026-11-01 | `[x]` | Delivered Phase 3 vertical slice: full `rnpm install` engine, CLI, tar extraction, cache integration, SSRI verification, and lockfile v3 generation. Passed Gate B with 100% normalized tree & lockfile parity against npm on Tier 1 single-dep and diamond fixtures. | `crates/rnpm-install/`, `crates/rnpm-cli/`, `benchmarks/compare-results.ps1` differential test |
| 2026-11-01 | `[x]` | Delivered Phase 2 differential harness, Gate F benchmark schema, local loopback mock registry, Tier 1 single-dep and diamond fixtures, run-npm runner with Windows Job Object process-tree accounting, and differential comparison script. | `benchmarks/schema/checkpoint.v1.json`, `benchmarks/mock-registry/`, `benchmarks/fixtures/`, `benchmarks/run-npm.ps1`, `benchmarks/compare-results.ps1`, `docs/baseline-report.md` |
| 2026-11-01 | `[x]` | Delivered Phase 2 differential harness, Gate F benchmark schema, local loopback mock registry, Tier 1 single-dep and diamond fixtures, run-npm runner with Windows Job Object process-tree accounting, and differential comparison script. | `benchmarks/schema/checkpoint.v1.json`, `benchmarks/mock-registry/`, `benchmarks/fixtures/`, `benchmarks/run-npm.ps1`, `benchmarks/compare-results.ps1`, `docs/baseline-report.md` |
| 2026-11-01 | `[x]` | Delivered Phase 0 and Phase 1 documentation and frozen specifications: environment inventory, baseline machine JSON, npm source map, compatibility contract, resolver contract, cache contract, lockfile contract, lifecycle contract, and platform filesystem contract. | `docs/` and `benchmarks/baseline-machine.json` |
| 2026-10-31 | `[x]` | Initial roadmap created; review pass assigned to AGY 1, AGY 2, and AGY 3. | This file and delegated review threads |
| 2026-10-31 | `[x]` | Added semver, aliases, overrides, lockfile migration, cache locking, tar safety, platform filesystem, process-tree metrics, fixture tiers, and quantitative gates from pass 1. | This file |
| 2026-10-31 | `[x]` | Pass 2 added week-by-week milestones, exact cache states, statistical rules, security/auth edge cases, and tickable phase deliverables. | This file and AGY 1-3 review threads |
| 2026-10-31 | `[x]` | Final consistency pass aligned week exits, cache commands, statistics, checklist ownership, tar-bomb defenses, bundled dependencies, and shim/lifecycle edge cases. | This file and AGY 1-3 final review threads |

### Review loop

Each polish pass follows the same short loop:

1. Ask each reviewer for findings against the current file.
2. Group duplicate findings and reject speculative scope.
3. Apply concrete edits to this file.
4. Record architecture-blocking decisions and deferred questions in the decision log.
5. Update the changelog and tick the active task in Current status.

Do not mark a phase complete because the prose is complete. Mark it complete only when its evidence or gate exists.

### Decision log

| ID | Date | Decision or open question | Status | Rationale |
|---|---|---|---|---|
| DEC-001 | 2026-10-31 | Semver implementation | `[x]` Accepted | Implement node-semver-compatible behavior rather than assuming the standard Rust grammar is sufficient. |
| DEC-002 | 2026-10-31 | Performance registry | `[x]` Accepted | Performance checkpoints use a pinned loopback registry; public registry runs are smoke tests only. |
| DEC-003 | 2026-10-31 | Windows process accounting | `[x]` Accepted | Use Job Object process-tree accounting plus sampled working set. |
| DEC-004 | 2026-11-05 | Full npm 11.x drop-in surface | `[x]` Accepted | Define exact npm 11.x drop-in target: all standard package management, inspection, publishing, lifecycle, linking, and query workflows are supported with drop-in compatibility. Active command matrix and flag surface expanded. |
| DEC-005 | 2026-11-02 | Core code isolation & Worktrees | `[x]` Accepted | Mandatory rule: Any modifications to core crates (`crates/rnpm-*`) must be performed within dedicated git worktrees. This directive applies to all successor threads in the lineage. |

## Scope definition

The target is an exact, drop-in replacement for npm 11.x: all standard package management, inspection, publishing, lifecycle, linking, and query workflows are supported with drop-in compatibility.

### Formal Drop-In Target (DEC-004 Accepted)

- **Package Management:** `install` (`i`, `add`, `isntall`), `ci` / `clean-install` (`ic`), `uninstall` (`remove`, `rm`, `r`, `un`), `update` (`up`), `prune` (`--omit`, `--production`, `-p`).
- **Inspection & Manifest Query:** `pkg` (`get`, `set`, `delete`), `list` / `ls` / `ll`, `outdated`, `view` / `info` / `v` / `show`, `query`, `audit` (bulk security advisories, `--audit-level`, `--json`), `cache` (`clean`, `verify`).
- **Lifecycle & Execution:** `run` / `run-script` (custom and topological workspace scripts), bare `run` (script enumeration), dedicated script shortcuts (`test`/`t`/`tst`, `start`, `restart`, `stop`), `exec` / `npx` (`x`).
- **Distribution & Archives:** `pack` (tarball archive generation, `--dry-run`, `--json`, `--pack-destination`).
- **Package Operations:** `dedupe` / `find-dupes`, `rebuild`, `init` / `create`, `diff`, `sbom`, and `version`.
- **Registry & Environment:** `publish`, `whoami`, `ping`, `login`, `logout`, `token`, `config`, top-level `get` / `set`, `link`, `unlink`, `prefix`, `root`, and `bin`.
- **Protocols & Linking:** Public/scoped registry packages, local directory dependencies (`file:../dir` via unprivileged NTFS junctions / symlinks), local archives (`file:./pkg.tgz`), multi-tier monorepo workspaces (`workspace:*`, `workspace:^`, `workspace:~`), Git repositories (`github:`, `gitlab:`, `bitbucket:`, `git+https:`, `git+ssh:`), and direct tarball URLs.
- **Configuration & Auth:** Project and user `.npmrc` configuration, scoped registry routing (`--@scope:registry=...`), environment variable token expansion (`${NPM_TOKEN}`, `${CI_AUTH_KEY}`), credential scrubbing.
- **Lockfile & Integrity:** Deterministic lockfile v3 serialization, read-only migration from v1/v2, hidden tree lockfile (`node_modules/.package-lock.json`), SSRI multi-hash integrity verification (SHA-512, SHA-384, SHA-256, SHA-1).
- **Execution Sandboxing & Containment:** Windows Job Object process-tree containment, hierarchical `PATH`, credential scrubbing, timeout termination (code 124), signal forwarding (SIGINT 130, SIGTERM 143).
- **Executable Shims:** Cross-platform trio generation (`<name>`, `<name>.cmd`, `<name>.ps1`, Unix shell) with argument escaping and shebang normalization.

### Remaining Compatibility Gaps

- Registry-specific organization, team, profile, and star APIs depend on the target registry exposing npm-compatible endpoints.
- Registry trust and staged-publishing writes require a registry that implements npm's governance endpoints and valid authentication/2FA.
- The exact 506-entry external corpus audit is not checked into this repository; the available real-world fixture and live named-package differential corpus are green.

The active command matrix includes the registry administration, authentication, package-operation, wrapper, and convenience commands implemented after the initial transition plan.

## Guiding rules

1. Map observable npm behavior before implementing replacements.
2. Keep a small, explicit compatibility contract for every subsystem.
3. Use npm as the behavioral oracle for differential tests.
4. Benchmark cold and warm paths separately.
5. Never trade correctness for speed without recording the decision.
6. Prefer a working vertical slice over many disconnected crates.
7. Record every regression as a permanent fixture.
8. Keep benchmark inputs, machine conditions, and tool versions in the result.

## Week-by-week milestone map

This is a planning cadence, not a promise that every milestone fits in exactly seven days. A milestone stays `[~]` until its evidence gate passes.

### Week 1 - foundations and oracle baseline

- `[x]` Complete Phase 0 environment inventory and Cargo workspace skeleton.
- `[x]` Deliver source, resolver, cache, lockfile, lifecycle, and platform contracts.
- `[x]` Create Tier 1 fixtures and the local mock registry.
- `[x]` Capture reproducible npm baseline results.
- **Exit gate:** Gate A.

### Week 2 - minimal `install`

- `[x]` Parse manifests and package specs.
- `[x]` Resolve the first supported semver ranges.
- `[x]` Fetch metadata and tarballs from the mock registry.
- `[x]` Verify SSRI and safely extract one dependency.
- `[x]` Write deterministic lockfile v3 output.
- **Exit gate:** Gate B for the single-dependency fixture.

### Week 3 - graph and lockfile engine

- `[x]` Build the in-memory dependency graph.
- `[x]` Add deduplication, hoisting, aliases, and overrides.
- `[x]` Read lockfile v2 and write v3 with hidden-tree metadata.
- `[x]` Match all Tier 1 resolution fixtures against npm.
- **Exit gate:** Tier 1 resolution parity and deterministic lockfile migration.

### Week 4 - reification, shims, lifecycle, and `ci`

- `[x]` Add safe extraction, atomic replacement, and Windows retries.
- `[x]` Generate Unix, `.cmd`, and `.ps1` executable shims.
- `[x]` Run lifecycle scripts with the npm environment contract and credential scrubbing.
- `[x]` Implement `ci` and process-tree cleanup.
- **Exit gate:** Tier 1 execution, shim, credential-scrubbing, and `ci` fixtures pass.

### Week 5 - peers, optional dependencies, workspaces, and mutations

- `[x]` Add peer cycles/conflicts and optional failure isolation.
- `[x]` Add local dependencies, workspace protocols, links, and topological scripts.
- `[x]` Add `uninstall`, `update`, and `pack`.
- `[x]` Validate named Tier 2 projects.
- **Exit gate:** Gate C, including `install`, `ci`, `run`, `uninstall`, `update`, and `pack` coverage.

### Week 6 and later - performance and compatibility expansion

- `[x]` Emit checkpoint schema v1 artifacts.
- `[x]` Tune bounded concurrency, cache access, extraction, and filesystem operations.
- `[x]` Run Tier 3 stress fixtures.
- `[x]` Repeat the review/benchmark loop for every material change.
- **Exit gates:** Gate C, Gate D, and Gate F passed.

## Phase 0: repository and environment inventory

Verify the starting workspace, available Rust toolchain, Node/npm versions, operating system, disk layout, network access, and process/resource measurement tools.

Record:

- OS and architecture
- CPU model and logical core count
- total and available RAM
- storage type and free space
- Rust, Cargo, Node, and npm versions
- registry URL and connectivity
- shell and filesystem behavior

Deliverables:

- `[x]` `docs/environment.md`
- `[x]` `benchmarks/baseline-machine.json`
- `[x]` a clean Cargo workspace skeleton

## Phase 1: map npm before rewriting it

Study the npm source and its major observable subsystems. The map should explain both implementation ownership and user-visible behavior.

### Source areas to map

- npm CLI command dispatch and lifecycle handling
- configuration loading and precedence
- `@npmcli/config` environment interpolation, URI-scoped auth, and registry selection
- `npm-package-arg` package-specifier grammar for ranges, tags, aliases, local paths, and URLs
- `@npmcli/arborist` for actual, virtual, and ideal trees
- `pacote` for package metadata, manifests, tarballs, and packing
- `npm-registry-fetch` for registry requests and authentication
- `cacache` and `ssri` for content-addressable caching and multi-hash integrity
- lockfile v3 serialization, v2 migration, and `node_modules/.package-lock.json`
- `node-semver` behavior and range grammar, including loose versions and prereleases
- `@npmcli/run-script` and `promise-spawn` lifecycle execution and environment construction
- `cmd-shim`, `bin-links`, and platform-specific executable behavior
- `@npmcli/fs` extraction, atomic replacement, path sanitization, and retry behavior
- workspace discovery, glob expansion, local linking, and workspace protocols

For each area, document:

- inputs
- outputs
- important data structures
- error names and exit codes
- filesystem effects
- network effects
- platform-specific behavior
- relevant npm tests or fixtures

Deliverables:

- `[x]` `docs/npm-source-map.md`
- `[x]` `docs/compatibility-contract.md`
- `[x]` `docs/resolver-contract.md`
- `[x]` `docs/cache-contract.md`
- `[x]` `docs/lockfile-contract.md`
- `[x]` `docs/lifecycle-contract.md`
- `[x]` `docs/platform-fs-contract.md`
- `[x]` `tests/fixtures/source-map/`

### Architecture-blocking compatibility decisions

Resolve these before the first resolver implementation because they affect shared data models:

- `node-semver` compatibility is its own contract. The standard Rust `semver` grammar is not enough; cover loose versions, `x`/partial ranges, hyphen ranges, prereleases, caret behavior for `0.x`, and build metadata.
- Package name and alias target are separate fields. Model `npm:` aliases and root/nested `overrides` before lockfile and tree work.
- Distinguish `file:` directories, which link through platform-appropriate junctions/symlinks, from `file:` tarballs, which extract and verify like registry archives.
- Optional dependency failures are isolated at metadata, download/integrity, platform filtering (`os`, `cpu`, `libc`), and lifecycle build stages.
- Registry requests use abbreviated install metadata, encode scoped package paths correctly, distinguish 401/403/404/429 failures, and never forward credentials across an untrusted redirect or into lifecycle scripts.
- Read lockfile v1/v2 where practical, write deterministic v3, and preserve POSIX package paths plus the root `packages[""]` entry. Track `node_modules/.package-lock.json` separately.
- Preserve lockfile flags such as `dev`, `optional`, `inBundle`, `hasInstallScript`, and `bin`; `ci` must abort before mutation when the manifest and lockfile drift.
- Cache writes must be atomic and cross-process safe: stage on the same filesystem, verify a unique temporary blob, then rename; use platform file locking with stale-lock recovery; purge and refetch corrupted entries.
- Tar extraction must reject absolute paths, `..` traversal, escaping symlinks/hardlinks, Windows device names, trailing dots/spaces, and SUID/SGID mode bits, while stripping exactly one top-level archive root (normally `package/`).
- Tar extraction must enforce package entry-count, uncompressed-size, and compression-ratio limits; abort and purge staged output with a structured resource-limit error.
- Integrity verification must prefer the strongest declared hash algorithm and reject a stronger-hash mismatch even when a weaker hash matches.
- Capture the platform filesystem contract: Windows junctions without admin privileges, `MAX_PATH`/extended paths, `.cmd`/`.ps1`/shell shims, Unix mode bits, and `EBUSY`/`EPERM` retry behavior.
- Junction/reparse-point pruning must remove only the link, never recurse into the linked target. Command shims must safely escape shell metacharacters, and Unix shims must normalize CRLF shebangs.
- Lifecycle contracts must include hierarchical `PATH`, `INIT_CWD`, `npm_config_*` with credential scrubbing, `npm_package_*`, `npm_lifecycle_*`, shell selection, `--ignore-scripts`, and signal cleanup for child process trees.
- Lifecycle ordering must be bottom-up for dependency scripts; registry dependencies do not run `prepare`, while the root `prepare` behavior is tested separately. Bundled dependencies must be retained and marked `inBundle` without registry lookups.
- Manifest parsing must define UTF-8 BOM handling, malformed JSON diagnostics, invalid integrity data, and safe behavior for missing package fields.
- Workspace contracts must cover glob expansion, `workspace:*`/`workspace:^`/`workspace:~`, link entries, topological script order, and cycle detection.

## Phase 2: establish the npm baseline

Before optimizing anything, run the same fixtures through npm and record the results.

### Baseline scenario families

1. Empty project initialization.
2. One direct dependency.
3. A dependency with several transitive dependencies.
4. Conflicting compatible and incompatible versions.
5. Peer dependencies that resolve successfully.
6. Peer dependency conflicts that fail.
7. Optional dependencies with platform filters.
8. Development dependencies.
9. `npm ci` from a committed lockfile.
10. Warm-cache reinstall.
11. Cold-cache install.
12. Lifecycle scripts and `node_modules/.bin` commands.
13. A small workspace.
14. Malformed manifests and network failures.
15. Large real-world packages selected by download size and dependency count.
16. `npm:` aliases and root/nested `overrides`.
17. Cache corruption, truncated tarballs, and automatic cache recovery.
18. Deep Windows paths, junctions, shims, and locked files.
19. Interrupted installs and child-process cleanup.
20. Workspace protocols, cross-workspace links, and cyclic workspace references.
21. Optional dependency with a failing native build script that must not fail the parent install.
22. Registry redirect to an external CDN where auth headers must be scrubbed.
23. Malicious tarballs with symlink slip, hardlink escape, traversal, and Windows device names.
24. A monorepo using `workspace:*`, `workspace:^`, and topological script ordering.
25. Lockfile v3 generated on Windows and Unix with identical POSIX package-path keys.
26. Tar bomb limits for entry count, uncompressed size, and compression ratio.
27. Multiple integrity hashes where a weak hash matches and the strongest hash fails.
28. Bundled dependencies that require no registry lookup and retain `inBundle` metadata.
29. `.cmd` argument escaping and CRLF shebang normalization for executable shims.

### Metrics

Record each run separately for npm and rnpm:

- wall-clock time
- user CPU time
- system CPU time
- peak working-set memory
- peak committed memory when available
- bytes downloaded
- cache hit and miss counts
- files created and removed
- final node_modules size
- total bytes written and write-amplification ratio (total bytes written divided by uncompressed installed package bytes)
- process exit code
- lockfile digest
- installed package tree digest
- stdout and stderr classification

### Benchmark cache-state matrix

| Cache state | Command | Package-manager cache | `node_modules` | Lockfile | Harness precondition | Measures |
|---|---|---|---|---|---|---|
| **Pristine cold** | `install` | Empty | Absent | Absent | Clear the tool cache and target directory before every trial; purge OS standby cache where possible and record whether that succeeded. | Resolution, download, extraction, and lockfile creation |
| **Cold-cache CI** | `ci` | Empty | Absent | Present and pinned | Clear the tool cache and target directory before every trial; preserve the pinned lockfile. | Clean lockfile download and reification |
| **Lockfile-only CI** | `ci` | Populated | Absent | Present and pinned | Keep cache warm, remove `node_modules`, and verify the lockfile is untouched. | Reification and linking from the lockfile |
| **Warm-cache install** | `install` | Populated | Absent | Present and pinned | Keep cache warm and remove only `node_modules`. | Cached resolution verification and extraction |
| **Hot/no-op** | `install` | Populated | Present and correct | Present and pinned | Leave the successful target tree intact. | Freshness checking and zero-mutation behavior |

Cold and warm runs must use separate cache directories. The benchmark harness must avoid measuring unrelated setup time.

Deliverables:

- `[x]` `benchmarks/fixtures/`
- `[x]` `benchmarks/run-npm.ps1`
- `[x]` `benchmarks/compare-results.ps1`
- `[x]` `benchmarks/results/baseline/`
- `[x]` `docs/baseline-report.md`

### Benchmark harness rules

The harness should run every fixture in an ephemeral directory and capture raw JSON in addition to a human-readable report. Use a deterministic local registry for repeatable protocol and cache tests, then keep a separate live-registry suite for real-world validation. The mock registry serves pinned tarballs from an immutable local directory over loopback with request logging and no cross-trial in-memory cache.

The tree comparison must normalize temporary paths, timestamps, and platform-only files while preserving package names, versions, symlinks, executable shims, file contents, and lockfile structure. A successful process with a different installed tree is a correctness failure.

Resource collection should use operating-system process accounting rather than estimates from application logs. On Windows, record process time and peak working-set memory; on Unix-like systems, record equivalent process CPU and RSS values. Keep network bytes and disk bytes separate from CPU and memory results.

No speed target is binding until the baseline is stable. After that, track aspirational targets such as a large warm-cache improvement and substantially lower peak memory, while reporting the actual tradeoff for each checkpoint.

For warm, hot, and lockfile-only scenarios, run one discarded warmup followed by seven recorded trials. Report median, minimum, maximum, and IQR. For pristine-cold scenarios, run five recorded trials and purge the cache before every trial; do not use a warmup that would populate the cache. Report median, minimum, maximum, and range for those five trials. Baseline stability is `RSD < 5%`, or `Max - Min <= 25 ms` for runs under 300 ms. Use a pinned local registry and pinned tarballs for performance measurements; keep public-registry runs for smoke and compatibility coverage. If a trial deviates by more than three MAD from the trial median, record it as an environmental outlier and allow at most one replacement trial.

On Windows, account for the complete process tree, including lifecycle scripts and native builds, with a Job Object or equivalent collector. Record user/system CPU, peak working set, commit charge, read/write operation counts, transferred bytes, child failures, and network request counts. Document antivirus and filesystem-cache conditions. If an unprivileged runner cannot purge the OS standby cache, use a dedicated volume or documented disk-churn fallback and record `os_cache_purged: false`.

### Canonical fixture cadence

| Cadence tier | Scope | Trigger |
|---|---|---|
| **Tier 1 - synthetic** | Flat, diamond, peer, optional-platform, malformed-input, and cache-recovery cases | Every commit / PR |
| **Tier 2 - standard** | React/Vite, Express, TypeScript CLI, and a small workspace | Nightly and checkpoint runs |
| **Tier 3 - stress** | Large workspaces, more than 1,000 transitive packages, native builds, and deep paths | Release milestones |

## Phase 3: vertical slice

Implement the smallest complete path:

```text
package.json
  -> registry metadata
  -> semver selection
  -> tarball download
  -> integrity verification
  -> extraction
  -> package-lock.json
```

The first vertical slice should support one project, ordinary registry packages, a local cache, and deterministic error reporting.

Do not begin with workspaces, publishing, or an advanced peer-dependency solver.

Suggested Rust modules:

Initial vertical-slice modules:

- `rnpm-core` (shared package, specifier, semver, and integrity types)
- `rnpm-config`
- `rnpm-registry`
- `rnpm-cache`
- `rnpm-lockfile`
- `rnpm-fs`
- `rnpm-install`
- `rnpm-cli`

Later modules, introduced when their phase starts:

- `rnpm-solver` (dependency graph, hoisting, aliases, overrides, and peers)
- `rnpm-shim`
- `rnpm-lifecycle`

Freeze shared domain types and resolver interfaces before parallel implementation. Keep graph resolution separate from filesystem mutation so both can be tested without the other.

Every module needs contract tests before optimization work begins.

## Phase 4: correctness expansion

Add behavior in this order:

1. node-semver-compatible ranges and package-specifier parsing
2. project/user configuration, environment interpolation, auth, and scoped registries
3. cache reuse, atomic writes, multi-process locks, and integrity failures
4. dependency tree placement, hoisting, aliases, and overrides
5. lockfile v3 read/write, v2 read/migration, and hidden-tree metadata
6. safe reification, streaming extraction, atomic replacement, and Windows retries
7. executable shims on Windows, PowerShell, Unix, and Git Bash
8. lifecycle scripts, environment variables, credential scrubbing, bottom-up ordering, root/dependency `prepare` rules, and child-process signal cleanup
9. `ci` using the lockfile without unnecessary metadata resolution
10. peer dependency resolution, cycles, optional peers, platform-filtered optional dependencies, and bundled dependencies
11. local `file:` dependencies, workspaces, links, protocols, and topological scripts
12. update, uninstall, pack, and remaining CLI workflows

Each feature must add:

- a focused fixture
- a differential test against npm
- a failure case
- a regression record if npm behavior is surprising

## Phase 5: performance checkpoints

Run the full baseline suite after every meaningful performance change.

Each checkpoint report should include:

```text
checkpoint name
git revision
Rust and npm versions
machine conditions
fixture name
npm wall time / CPU / peak RAM
rnpm wall time / CPU / peak RAM
absolute difference
percentage difference
correctness result
```

The human-readable comparison is rendered from machine-readable `checkpoint.v1.json` artifacts for npm and rnpm; it is not a separate source of truth.

Optimize only after the result is correct for the fixture.

### Likely optimization areas

- concurrent metadata and tarball requests
- connection reuse
- cache indexing and hashing
- streaming downloads and extraction
- bounded parallel extraction
- avoiding duplicate metadata parsing
- reducing filesystem stat calls
- lock contention in shared caches
- incremental lockfile serialization
- avoiding unnecessary directory copies
- process and memory allocation patterns

Do not increase concurrency without measuring registry pressure, disk contention, CPU saturation, and memory growth.

## Phase 6: real-project compatibility

Create a corpus of ordinary Node projects covering:

- frontend applications
- backend services
- TypeScript projects
- command-line tools
- monorepos
- native modules
- packages with lifecycle scripts
- projects using peer dependencies

For each project, compare npm and rnpm in an isolated directory. The comparison must include successful installs and expected failures.

The project is not considered broadly useful until it can reproduce the dependency tree and scripts for representative projects, not just synthetic fixtures.

## Team orchestration model

Agents should work from shared contracts and isolated tasks.

### Agent domains

- **Core resolution and data modeling:** manifests, package specs, node-semver behavior, lockfiles, dependency graphs, aliases, overrides, and peers.
- **I/O and filesystem:** registry, cache, integrity, tar extraction, links/shims, lifecycle execution, and platform behavior.
- **CLI and workflow driver:** configuration, command parsing, package management, registry administration, lifecycle wrappers, and convenience commands share the same dispatch and diagnostics path.
- **Quality and performance:** source mapping, differential fixtures, mock registry, process-tree metrics, regression reports, and checkpoint gates.

Every agent handoff must state:

- files changed
- public interfaces changed
- tests added or run
- known incompatibilities
- benchmark effect
- open integration questions

No agent should silently change a shared data model. Such changes require an updated contract and dependent test updates.

Before parallel implementation, freeze shared Rust contracts for package specs, resolver output, tarball storage, tree planning, reification, and script execution. Every handoff must include contract changes, tests run, differential tree match, benchmark impact, and unresolved edge cases.

## Checkpoint gates

### Gate A: baseline is trustworthy

- `[x]` npm warm-cache runs vary by less than 5% RSD, or have a range of at most 25 ms for runs under 300 ms, on the recorded machine
- `[x]` fixture inputs, lockfiles, tarballs, and output trees are checksummed and versioned
- `[x]` resource measurements include the whole process tree
- `[x]` pristine cold, warm-cache fresh, hot/no-op, and lockfile-only CI states are separated
- `[x]` Windows and Unix baseline runs are captured where filesystem behavior differs

### Gate B: vertical slice works

- `[x]` Fixture `tier1-single-dep` installs successfully into a clean directory.
- `[x]` Normalized tree and lockfile structure match npm with zero diff.
- `[x]` A corrupted tarball triggers an integrity failure without leaving corrupted files or cache entries.
- `[x]` Lockfile output is deterministic across three consecutive clean runs and uses POSIX package-path keys.
- `[x]` A warm run performs zero network requests and reuses the cache.
- `[x]` Tar extraction rejects traversal, absolute paths, symlink/hardlink escape, and Windows device names.
- `[x]` Tar-bomb limits reject excessive entries, uncompressed bytes, or compression ratio and purge staging.
- `[x]` Strongest-hash integrity precedence rejects a weak-hash match when the stronger hash fails.

### Gate C: ordinary projects work

- `[x]` `install`, `ci`, and `run` work for named Tier 2 fixtures (`tier2-vite-react`, `tier2-express`, and `tier2-typescript-cli`).
- `[x]` `uninstall`, `update`, and `pack` pass their focused Tier 2 mutation fixtures (`benchmarks/fixtures/tier2-mutation-*`, verified via `benchmarks/test-differential-tier2-mutations.ps1`).
- `[x]` `ci` rejects manifest/lockfile drift without registry requests or tree mutation.
- `[x]` npm and rnpm produce equivalent trees, links, modes, and lockfiles for supported fixtures.
- `[x]` Lifecycle scripts expose the required environment with credentials scrubbed and terminate cleanly on interruption.
- `[x]` Optional native dependency build failure does not fail the parent install.
- `[x]` Bundled dependencies are retained, marked `inBundle`, and do not trigger registry requests.
- `[x]` Registry dependencies skip `prepare`; dependency lifecycle scripts run bottom-up.
- `[x]` Windows shim arguments are safely escaped and Unix CRLF shebangs execute correctly.
- `[x]` Pruning junctions removes only the reparse point and never deletes the linked target.
- `[x]` Windows non-admin installs use junctions and `.cmd`/`.ps1` shims successfully.
- `[x]` Windows NTFS and Unix filesystem cases pass their respective contracts.

### Gate D: optimization is measurable

- `[x]` every speed claim has a before-and-after result with raw iterations, median/IQR for seven-trial runs, or median/range for five-trial cold runs (stored in `benchmarks/results/baseline/` and rendered via `compare-results.ps1`)
- `[x]` peak RAM and disk write amplification do not regress without an explicit decision (-91% to -92% peak RAM, -62% to -70% disk writes)
- `[x]` Tier 1 regressions above 5% wall time and more than 25 ms absolute noise, or above 10% peak commit charge, fail the automated gate on baseline hardware (enforced in `compare-results.ps1`)
- `[x]` CPU, network, disk, antivirus, and filesystem-cache conditions are documented (recorded in all `checkpoint.v1.json` metadata blocks)

### Gate E: compatibility expansion is deliberate

- `[x]` Unsupported flags and protocols exit with a structured diagnostic.
- `[x]` Every discovered divergence is recorded in `docs/compatibility-contract.md` and has a regression fixture.
- `[x]` The supported command/configuration matrix is kept current.

### Gate F: checkpoint artifacts are inspectable

- `[x]` Add `benchmarks/schema/checkpoint.v1.json`.
- `[x]` Store hardware, tool versions, git revision, scenario, raw iterations, and summary statistics.
- `[x]` Require 100% correctness for the supported fixture before accepting performance results.

Required top-level fields are `version`, `metadata`, `scenario`, `correctness`, and `metrics`. `metadata` records timestamp, git revision/dirty state, tool name/version/commit, Node version, Rust compiler version, Cargo profile, target triple, OS, CPU, RAM, antivirus state, and whether the OS cache was purged. `scenario` records fixture, tier, cache state, command, and registry kind. `correctness` records exit code, normalized tree match, lockfile match, and digest mismatches. `metrics` records raw trials plus summaries for wall time, user/system CPU, peak working set, peak commit, disk bytes, network bytes, outlier replacement, and write amplification.

## Inner and outer iteration loops

The inner loop is correctness-only: run npm and rnpm on Tier 1 fixtures, compare normalized trees and behavior, and fix the first divergence. Do not treat a faster incorrect run as progress.

The outer loop is a performance checkpoint: run only after correctness passes, write the machine-readable checkpoint, compare against the prior checkpoint, and tick the relevant task in this file. Use unique temporary directories or deletion retries on Windows so lingering file handles do not contaminate later trials.

## Immediate next actions

1. Complete the Phase 0 deliverables: environment inventory, baseline-machine record, and Cargo skeleton.
2. Complete the Phase 1 source map and frozen contracts.
3. Complete the Phase 2 harness and Tier 1 npm baselines.
4. Build and verify the Phase 3 vertical slice.
5. Advance only when the corresponding gate is evidenced in the checklist above.

## Definition of done for Milestone 2 (vertical slice / Gate B)

Milestone 2 is complete when `rnpm install` installs a pinned single-dependency Tier 1 fixture from a local mock registry into a clean directory, verifies SSRI SHA-512 integrity, writes deterministic lockfile v3 output matching npm's normalized tree digest, performs a zero-network warm reinstall from cache, and produces an automated benchmark comparison report. Script execution is verified in the later lifecycle milestone.


