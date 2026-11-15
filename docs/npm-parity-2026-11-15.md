# npm parity progress, 2026-11-15

Oracle: npm 11.20.0, Node 26.13.0, Windows x64. Starting revision:
`b50d85cd9eb728ea4c739165e56a14b59fab651a` (PR #35 merge).

## Changes

- Drain root dependency resolution before enqueueing workspace targets.
  Arborist's `build-ideal-tree.js` drains `depsQueue` and then visits link
  targets through `resolveLinks`. Workspace targets have depth zero, but
  their initial discovery happens after the root's transitive dependencies.
- Use each workspace manifest's optional version in its public lock entry.
  The solver's internal fallback must not become a synthetic lockfile version.
- Preserve dependency-owned `workspaces` metadata when converting the graph
  into a lockfile. The metadata differential fixture now exercises this field.
- Remove a graph-wide consumer scan used only by an always-disabled branch.
- Account for detached and reinserted packages when reporting reify order.
  Audit updates also visit old dependents whose outgoing edges need repair;
  those visits can precede expansion of newly placed parents.
- Allow repeated `--case` filters in the comparison runner so related cases
  can be verified together without running unrelated commands.

## Real-project checks

The Lerna fixture was copied from the corpus twice and both tools ran
`install --package-lock-only --ignore-scripts --no-audit --no-fund`.
The optimized rnpm probe has the workspace traversal/version changes; it
predates the audit-reporting and final metadata changes.

Top-level `semver` matches npm at 7.8.6 and `got` matches at 15.1.0.
There are still 130 differing package entries. In particular, npm selects
top-level lru-cache 11.5.3 and react 19.3.0, while rnpm selects 5.1.1 and
19.3.1. This is a partial workspace fix, not an exact Lerna lockfile match.
Timings from this diagnostic run are not a controlled performance benchmark.

`npm-check-updates` was run through all three corpus phases. Fresh install
still differs (including an extra cosmiconfig subtree). `ci` and
`ci --omit=dev` both produce zero differences from npm's lockfile.

## Remaining work

- Remaining Lerna placement, peer flags, and the other workspace fixtures.
- Preserve scalar/array platform metadata forms, including libc.
- Fresh npm-check-updates resolution and the remaining native/script cases.
- Complete ERESOLVE text and package-lock-only audit counts.
- Real-registry publish, 2FA, and web login using a supplied test account.
- Controlled performance measurements after correctness work.

Passing comparison probes do not establish universal npm replacement parity.
