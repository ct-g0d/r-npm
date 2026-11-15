# npm parity progress, 2026-11-15

Oracle: npm 11.20.0, Node 26.13.0, Windows x64. Starting revision:
`b50d85cd9eb728ea4c739165e56a14b59fab651a` (PR #35 merge).

## Changes

- Defer workspace targets to Arborist's `resolveLinks` pass, unless a
  newly placed provider invalidates a workspace's dependency edge. That
  invalidation queues the workspace immediately at depth zero, before the
  remaining root children. An instrumented npm 11.20.0 run confirms that
  placing semver from @nx/devkit activates packages/lerna through the
  `buildDepStep` invalid-edge branch, before its normal link traversal.
- Use each workspace manifest's optional version in its public lock entry.
  The solver's internal fallback must not become a synthetic lockfile version.
- Preserve dependency-owned `workspaces` metadata when converting the graph
  into a lockfile. The metadata differential fixture now exercises this field.
- Remove a graph-wide consumer scan used only by an always-disabled branch.
- Keep the original virtual parent when resolving a peer of a peer, so a
  workspace's direct version constraint also guides that peer candidate.
- Check override-adjusted peer ranges in the candidate's virtual context.
  Reference overrides can use the virtual parent's or callee's dependency
  fields before attachment. Reuse an identical attached package before
  considering the incoming candidate's virtual peer context.
- Account for detached and reinserted packages when reporting reify order.
  Audit updates also visit old dependents whose outgoing edges need repair;
  those visits can precede expansion of newly placed parents.
- Allow repeated `--case` filters in the comparison runner so related cases
  can be verified together without running unrelated commands.
- Compare complete names before applying case tiebreaks when sorting JSON
  keys. English collation places JSONStream before jsonwebtoken; applying
  case ranks at each character produced an unnecessary byte difference.

## Real-project checks

The Lerna fixture was copied from the corpus twice and both tools ran
`install --package-lock-only --ignore-scripts --no-audit --no-fund`.
After the workspace activation and peer-context corrections, the complete
Lerna lockfile matches npm with zero parsed-JSON differences. This includes
top-level semver 7.8.6, got 15.1.0, lru-cache 11.5.3, and react 19.3.0,
without extra nested @nx/vitest or React entries. This checks the fresh
lockfile-only reproduction; it does not substitute for the full install/ci
corpus phases on this workspace or the other workspace projects.

The final diagnostic binary uses release optimization with LTO disabled
and 16 codegen units. CI also builds the repository's default release profile.
Timings from this diagnostic run are not a controlled performance benchmark.
Re-serializing the resolved tree with the collation correction produces a
byte-identical copy of npm's reference lockfile.

An intermediate `npm-check-updates` corpus run matched `ci` and
`ci --omit=dev`; fresh install still differed in ESLint peer placement.
After correcting conflicted virtual peer handling, its fresh lockfile-only
resolution has zero parsed-JSON differences from npm. The full corpus
phases remain part of the final validation.

The cosmiconfig placement was reduced to lockfile-lint plus TypeScript and
the root `$typescript` override. npm's virtual candidate evaluates that
optional peer against cosmiconfig's own development range; its attached
edge later uses the real project-root override. This affects placement
without adding another installed TypeScript. A separate direct-dependency
probe verifies that an already attached identical candidate is reused.
The remaining ESLint placement was reduced separately: npm marks a virtual
peer edge conflicted when a non-project parent's provider wins. Those
conflicted virtual edges do not block hoisting. The matching mock probe and
the real two-dependency ESLint reproduction both verify this behavior.

## Remaining work

- Full install/ci corpus phases for Lerna and the other workspace fixtures.
- Preserve scalar/array platform metadata forms, including libc.
- Final full npm-check-updates corpus rerun and the remaining native/script cases.
- Audit dry-run report node identities and isDirect fields (add order matches).
- Complete ERESOLVE text and package-lock-only audit counts.
- Real-registry publish, 2FA, and web login using a supplied test account.
- Controlled performance measurements after correctness work.

Passing comparison probes do not establish universal npm replacement parity.
