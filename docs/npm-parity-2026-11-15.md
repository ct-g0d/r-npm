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
After the workspace activation, peer-context, and collation corrections,
the complete Lerna lockfile is byte-identical to npm's lockfile. This includes
top-level semver 7.8.6, got 15.1.0, lru-cache 11.5.3, and react 19.3.0,
without extra nested @nx/vitest or React entries. Full install/ci corpus
phases remain for this workspace and the other workspace projects.

The final diagnostic binary uses release optimization with LTO disabled
and 16 codegen units. CI also builds the repository's default release profile.
Timings from this diagnostic run are not a controlled performance benchmark.
The pinned `28def49` reproduction is retained in
`target/lock-pr36-lerna-fresh/workspace-lerna-lerna`; both lockfiles have SHA-256
`115fd2c0fcd017daf3276185229324c0a9757075c93357f823ef6a68fd5bd8d5`.

After correcting conflicted virtual peer handling, `npm-check-updates`
matches the full corpus checks for fresh install, `ci`, and `ci --omit=dev`.
The evidence is retained in `target/corpus-ncu-pr36`.

The complete comparison run on the pinned `28def49` binary matches 489/491
cases (`target/npm-parity-pr36.json`). Only the two audit dry-run report-node
and isDirect differences remain. PR #36 merged as `ae409e2` after all eight
CI checks passed.

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

## Platform metadata

Preserve string versus array forms for `os`, `cpu`, and `libc` through
manifest parsing, registry metadata caching, solver nodes, and lockfile
serialization. The shared `PlatformList` exposes the constraint values for
matching and retains the original form for serialization. Full-packument
enrichment also keeps a scalar libc value scalar. Registry parsing retains
its existing tolerance for published arrays containing null entries.

Differential fixtures cover scalar and array constraints in install,
lockfile-only install, and ci, including a scalar libc value omitted from
the abbreviated packument. Unit checks also exercise the metadata cache
roundtrip and lockfile serialization.

Validation: all 1,099 workspace tests, strict all-target workspace clippy,
and the all-target compile check pass. The five focused comparison cases
match (`target/npm-parity-platform-optional.json`). The fresh Vite
lockfile-only reproduction is byte-identical: both files are 181,164 bytes
(`target/lock-platform-final/vite`). The fixtures use optional native
dependencies so unsupported libc packages remain locked on Windows while
supported hosts also check their installed contents.

The initial required-dependency fixtures also exposed a separate force
gap: npm accepts incompatible platform packages under `--force`, while
rnpm still rejects them in the solver. The failed reproduction is retained
in `target/npm-parity-platform-final.json` for the next fix.

## Optional dependency and peer overlap

Resolve a package's own production and optional dependencies before its
peer declarations for the same name. Exclude the shadowed peer during
placement, child-edge creation, late optional-peer linking, and fast-path
validation. Keep the original peer metadata in the public lockfile.

All 129 solver tests and strict solver clippy pass. Four differential
cases match npm, including direct and transitive overlap, an unavailable
optional version, and the existing nested optional-peer conflict case
(`target/npm-parity-optional-peer-final.json`). A fresh two-project corpus
rerun is retained in `target/corpus-optional-peer-final`; scripts-sqlite3
now matches install, ci, and ci-omit-dev, clearing the prior 524 fresh-install
differences. The completed corpus rerun matches both projects exactly,
including sqlite3's script-enabled install and smoke test. PR #38 merged
as `d093186` after all eight CI checks passed. The complete pinned
comparison run matches 495/497 cases, with only the two audit dry-run
report differences remaining (`target/npm-parity-optional-peer-full.json`).

## Late optional-peer providers

A two-package mock reproduces the shared pacote/cacache resolution gap:
an optional peer is initially absent, then becomes invalid when another
dependency places an incompatible provider. npm revisits the owner, moves
the transitive provider beneath its consumer, and retains the peer's
provider at the top level, marked extraneous. Defer missing peer tasks by
name and wake them when a visible provider arrives. Preserve queued child
locations when their package moves. Plain `install --no-save` does not
perform this repair; explicit package requests and updates still do.

All 130 solver tests, strict workspace clippy on all targets, and the
all-target compile check pass. Seven focused differential cases match,
including provider children and --no-save (`target/npm-late-peer-final.json`).
The fresh real-project results are retained in `target/corpus-late-peer`.
Both pacote and cacache lockfiles now match npm exactly. Their remaining
36 and 154 fresh-install differences concern the installed tree, including
a TypeScript native package and nested command shims. Both projects match
ci and ci-omit-dev. The complete pre-review binary matched 498/500 cases,
with only the two audit dry-run differences (`target/npm-late-peer-full.json`).

Review also identified a required-peer constraint: a provider cannot be
moved beneath its peer consumer. Preserve compatible incoming peer edges
and return a peer conflict when the project cannot place both providers.
The regression covers the error exit and absence of installation mutations.
It also exposed unconditional fatal-error output under --silent; suppress
the terminal diagnostic and log-path notice while retaining the debug log.

## Installed tree materialization

Include bundled package bins from the inflated lockfile when fresh install
links commands. These children are discovered after solving and are absent
from the original solver graph. Cached ci now finishes files and symlinks
before linking commands so interpreter detection reads complete scripts.

Track a package's own platform skip condition separately from inherited
skip state. A shared optional native package can remain installable through
one parent even when another parent is unsupported. A focused regression
first failed with the native package incorrectly skipped, then passed with
the separate intrinsic flag.

The combined branch passes 132 solver tests, 103 installer tests, strict
all-target workspace clippy, and 13 focused differential cases covering
bundled commands, ci shims, shared native packages, and peer constraints.
Evidence: `target/npm-materialization-combined.json`. A fresh pacote/cacache
rerun is retained in `target/corpus-materialization-final`.

## Native-project baseline

The PR #36 binary fails fresh better-sqlite3 installation because sqlite3
declares node-gyp in both `optionalDependencies` and optional
`peerDependencies`. The solver's child dependency pass currently replaces
the optional dependency with a peer edge. npm's `Node._loadDeps` loads peers
first, then production and optional edges, so the optional dependency wins.
npm keeps root node-gyp 13.1.0 and installs 8.4.1 beneath sqlite3. The ci and
omit-dev phases already match when starting with npm's lockfile.

The fresh five-case native/script rerun uses the frozen PR #36 binary and
retains evidence in `target/corpus-native-pr36`. It includes better-sqlite3,
pacote, cacache, scripts-sqlite3, and scripts-sharp.
The completed fresh-install phases for pacote and cacache report 76 and 79
differences respectively. Their first lockfile difference is the same:
npm retains conventional-commits-filter 3.0.0 under conventional-changelog-writer,
while rnpm has no entry at that nested location. Their full per-case reports
and stderr logs are retained in the same evidence directory.
Both projects match ci and ci-omit-dev. Scripts-sqlite3 reports 524
differences in fresh install and scripts, with both ci phases matching.
Scripts-sharp matches fresh install, both ci phases, scripts, and lockfile
v2/v3 upgrades; its v1 upgrade reports 356 differences, including extra
license and dependency metadata in rnpm's lockfile.

## Audit dry-run diagnosis

The remaining two comparison failures concern node identities and
isDirect, rather than add order. npm's audit report initially tracks the
old lockfile nodes. Replacing them detaches those objects, leaving empty
locations in the report. `Vuln.isVulnerable` adds replacement objects only
when the ideal-tree walk examines them. In the chain reproduction, leaf
and branch have detached old nodes plus visible replacements; middle and
top retain only detached old nodes, and top becomes non-direct. rnpm
currently retains the old visible locations and direct flag.

The existing reify-order simulation in `reify_report.rs` may supply the
walk events needed to retain and replay these identities. Avoid deriving
the report solely from the final resolved graph. The local instrumented
npm source and `target/trace-audit-nodes.cjs` provide the reproduction.

## Remaining work

- Full install/ci corpus phases for Lerna and the other workspace fixtures.
- Remaining native/script cases, including better-sqlite3, pacote, cacache,
  scripts-sqlite3, and scripts-sharp.
- Audit dry-run report node identities and isDirect fields (add order matches).
- Complete ERESOLVE text and package-lock-only audit counts.
- Match --force behavior for required packages with platform constraints.
- Real-registry publish, 2FA, and web login using a supplied test account.
- Controlled performance measurements after correctness work.
