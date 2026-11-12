# npm replacement readiness, 2026-11-13

rnpm is suitable for controlled trials on projects whose workflows have been compared with npm. It is not yet a verified universal npm replacement. Lane four's worker is settled; its correctness repairs and evidence are retained on PR #14. The 2x performance target remains unmet, so the PR must not be presented as a passed speed lane.

## Measured lane four result

Implementation: `61a631ae65d8788bdd0ca38140d6c7035a0c1431`. Release binary SHA-256: `1f6c0836de5dd5a47e04c6bcc11660d791ab761dbebc5dd3c65aee6230b02631`. Node v26.13.0, npm 11.20.0, Windows. Source was clean before measurement and the binary hash was unchanged afterwards.

Three fixed, unfiltered rounds alternate tool order. Every cold invocation has an empty tool cache and rnpm store; warm invocations use separately seeded tarball caches with an empty rnpm store. Process timing excludes setup, parity hashing and cleanup. Both tools use isolated configuration. npm is invoked through Node's npm-cli.js. This is application-cache cold, not an OS page-cache flush.

| Scenario | npm median | rnpm median | Speedup | rnpm spread | Target |
|---|---:|---:|---:|---:|---|
| Cold ci | 7.388s | 5.745s | 1.29x | 6.2% | FAIL, requires >=2x |
| Warm tarballs / empty store | 6.653s | 4.826s | 1.38x | 6.9% | FAIL, requires >=2x |

All four scenario spreads pass the <=25% limit. All twelve measured commands exit zero. Every measured rnpm tree matches npm across 10,298 files after excluding tool-internal metadata, and npm ls --all exits zero on every rnpm tree. Same-size CAS corruption is repaired and the complete installed tree is checked again. This is one larger project fixture; it is not evidence of complete compatibility across arbitrary projects.

Raw samples, exits, configuration, provenance and corruption results: [lane four evidence](../benchmarks/results/lane4-takeover-2026-11-13.json). Per-command stdout/stderr: [raw logs](../benchmarks/results/lane4-takeover-2026-11-13-logs/).

## Repairs completed in this takeover

- Bound the Node writer queue and concurrent persistence work; retain the default writer after a fixed comparison did not support lower concurrency. Legacy worker measurements are explicitly labelled as historical evidence with incomplete source provenance.
- Reap the Node child even after an input-pipe failure. Preserve all producer/persistence/writer joins and propagate failures. The regression now calls the production join helper instead of copying its implementation into a test.
- Use the shared validated tar decoder for the pipelined cache path. Preserve relative symlink metadata and hardlink payloads across cold and reopened-cache installs. Exclusive Node file creation safely replaces existing hardlinks instead of truncating their source. Required link failures now fail the install.
- Move the CLI persistence-failure regression into the CLI crate so Cargo supplies the actual binary. Add queue-drain, child-reaping, escaping-link, cached-link and persistence-panic coverage.
- Replace the PowerShell gate's nested-scope exit-code handling with a Node harness that records real subprocess exits, keeps every sample, uses unique temporary roots, retains raw logs, validates both installed scenarios and checks full-tree corruption recovery. A deliberately failing candidate is rejected with gate exit 1.

Workspace tests and strict workspace clippy pass locally. Isolation checker self-test and repository scan pass. Cross-platform GitHub checks are tracked separately on PR #14; local Windows success does not substitute for those checks.

## Reproduced remaining behavior gaps

The release binary above was compared with npm on these exact fixtures. [Raw smoke evidence](../benchmarks/results/npm-replacement-smoke-2026-11-13.json) includes commands, manifests and file contents. It is a targeted regression probe, not a representative percentage score.

| Case | npm | rnpm | Assessment |
|---|---|---|---|
| files whitelist vs root .npmignore | Explicitly listed keep.js is packed | keep.js is omitted | Package contents differ |
| Nested .npmignore inside whitelisted directory | lib/omit.js is excluded | lib/omit.js is packed | Publishing can include files npm would exclude |
| Failing postinstall, exit 7 | Writes public package-lock.json before failure | Public lockfile absent after failure | Failed-install filesystem behavior differs |
| Empty install | Public lockfile; no hidden lockfile | Same | This older reported gap is no longer reproduced |

Reproduce with `node scripts/check-npm-replacement.mjs`; exit 1 means a mismatch remains. The probe uses a separately installed npm CLI alongside Node on Windows; it performs no publishing or authenticated account mutation.

## Work before replacing npm globally

1. Correct the reproduced package-ignore and failed-lifecycle lockfile differences, and compare archive output and workspace mutation cases against npm again.
2. Integrate and verify the still-open [PR #20](https://github.com/ct-g0d/r-npm/pull/20) follow-ups for bare workspace directory arguments and lifecycle JSON output. They are absent from current master and lane four.
3. Regenerate a current, reproducible compatibility matrix across actual project workflows, lockfile variants, native dependencies, workspaces and all supported operating systems. The stored coverage summary claims 62 matching commands, while its older raw JSON records 26 matching, 46 partial and 1 missing; many probes are --help-only. Neither is a defensible completion percentage.
4. Validate real private-registry authentication, interactive login/2FA, publishing and trusted-publisher/OIDC workflows with explicitly authorized test accounts. Mock-registry tests cover useful contracts but do not demonstrate those end-to-end service flows.
5. Finish the measured cold/write-path performance work without removing validation or required cache writes. Passing the 2x goal alone would not resolve the compatibility gaps above.

Keep npm available as the reference and fallback while using rnpm only for workflows that have passed project-specific comparisons. There is no supported universal replacement date or percentage from the present evidence.
