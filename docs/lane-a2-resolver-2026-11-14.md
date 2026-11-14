# Lane A2 resolver verification

Base: `30a0808`. Branch: `lane-a2-resolver`.
Reference: npm 11.20.0, Node v26.13.0, Windows x64.

## Changes

The two resolver changes in `origin/lane-a-wip` (`b94ae8b`) were reviewed
against the installed npm source and retained as focused commits, without
importing that branch's older test expectations or other ancestors.

- `resolver-nesting-preserves-pending-descendant-edges`: inspect manifest
  edges before their dependency queue turn. Like
  `can-place-dep.js:checkCanPlaceNoCurrent`, an empty intermediate slot must
  not intercept a valid descendant dependency that resolves above it.
  The baseline installed ten packages where npm installed nine.
- `resolver-peer-set-prefers-parent-dependency`: constrain a broad peer range
  with the dependency of its source package, following
  `build-ideal-tree.js:loadPeerSet/nodeFromEdge`. The baseline selected
  shared 2.0.0 at the root and duplicated 1.0.0; npm selected only 1.0.0.
- `resolver-nested-optional-peer-conflict`: when an incompatible optional
  provider is visible, resolve the provider alongside the nested plugin if
  its sibling slot is free. Missing optional peers still do not trigger
  installation. Match `calc-dep-flags.js` by keeping nodes reached only
  through optional peer edges extraneous, and match
  `shrinkwrap.js:metaFromNode` by suppressing their dependency-class flags.
  This reduces the real CRA/postcss-load-config/YAML mismatch to four
  packages. The baseline installed three and omitted the nested provider.

Every new probe failed before its fix and passed afterward. The ten resolver
probes compare stdout, stderr, exit status, complete installed files, parsed
lockfiles, and registry mutations without changing the differential gate's
normalization.

## Real-registry method

`scripts/check-lane-a2-real-registry.mjs` prepares separate projects, configs,
caches, and stores for npm and rnpm. It records downloaded source manifests,
process logs, and recursive lockfile JSON differences. Object key order is
irrelevant; no fields or values are ignored. Full installs use
`install --ignore-scripts`, with audit and fund disabled, so native build
scripts do not affect this resolver comparison. Initial lockfile-only runs
are retained separately from the final materialized installs.

The requested six manifests are Express 5.1.0 plus latest TypeScript and
@types/node, Express 5.1.0 alone, Next 15 plus dev Sharp 0.33, latest bcrypt
and esbuild, Vite's React template, and CRA's own package.json (including
its dev dependencies). A seventh generated CRA app covers the alternate
interpretation of the CRA request: react-scripts 5.0.1, React/React DOM 19,
and the official cra-template dependencies.

Baseline lockfile-only measurements:

| Project | npm packages | rnpm packages | JSON differences |
| --- | ---: | ---: | ---: |
| Express + TypeScript + @types/node | 91 | 91 | 0 |
| Express | 68 | 68 | 0 |
| Next + dev Sharp | 80 | 80 | 0 |
| bcrypt + esbuild | 30 | 30 | 0 |
| Vite React template | 74 | 74 | 0 |
| create-react-app package.json | 371 | 371 | 0 |
| Generated CRA app | 1307 | 1309 | 12 |

The first two fixes remove eleven of the generated CRA differences. The
remaining entry is the nested optional YAML provider handled by the third
fix. Complete baseline differences are in `target/lane-a2-real/identity-rnpm.json`.

Final full installs match npm's parsed lockfile JSON exactly for all seven
projects. npm's full-install oracle is itself exactly equal to its earlier
lockfile-only oracle for every project, so the before/after oracle is stable.

| Project | Differences before | Differences after | Final packages (each tool) |
| --- | ---: | ---: | ---: |
| Express + TypeScript + @types/node | 0 | 0 | 91 |
| Express | 0 | 0 | 68 |
| Next + dev Sharp | 0 | 0 | 80 |
| bcrypt + esbuild | 0 | 0 | 30 |
| Vite React template | 0 | 0 | 74 |
| create-react-app package.json | 0 | 0 | 371 |
| Generated CRA app | 12 | 0 | 1307 |

Final raw process logs and lockfiles are under `target/lane-a2-full-real`;
the complete comparisons are in `identity-rnpm.json`. The committed JSON
summary records the manifests, every baseline difference, final counts,
binary hash, and tested revision.

## Final validation and timings

- Release build: passed. No performance changes were made.
- Resolver differential probes: 10/10 match, including all three new probes.
- Solver tests: 108 passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- Full gate: stopped at the coordinator's wrap-up request after 184 matching
  comparisons and zero DIFFs. This is a partial run, not a passing full gate.
- `cargo test --workspace`: not green. Three attempts under load stopped on
  lifecycle grandchild startup/output-drain time limits or the existing
  install-ci-test normalizer, which accepts milliseconds/seconds but leaves
  npm's elapsed `2m` untouched. Both lifecycle tests passed in isolated
  retries. These unrelated test files and lifecycle code were not modified.

The requested three-run warm no-lockfile and cold `ci` medians were not run
before the coordinator requested handoff. The benchmark implementation is
ready in `scripts/check-lane-a2-real-registry.mjs --benchmark`; use a fresh
`--root` and copy the recorded manifests there to preserve the inputs.

The following are single fresh full-install wall times from lockfile
verification, in seconds. They ran under heavy, changing host load and are
not controlled speed comparisons or the requested warm/`ci` benchmarks.
Both tools used `--ignore-scripts`, with audit and fund disabled.

| Project | npm seconds | rnpm seconds |
| --- | ---: | ---: |
| Express + TypeScript + @types/node | 14.083 | 25.460 |
| Express | 7.504 | 7.133 |
| Next + dev Sharp | 449.987 | 204.395 |
| bcrypt + esbuild | 11.427 | 29.581 |
| Vite React template | 16.902 | 62.516 |
| create-react-app package.json | 134.776 | 141.240 |
| Generated CRA app | 437.388 | 500.505 |

Remaining work: complete an uninterrupted full gate, obtain a green full
workspace test run under lower load, and collect the requested two-project
three-run warm-install/cold-ci medians. All implementation changes and
real-project lockfile comparisons are complete. Raw verification evidence
remains under this worktree's `target/lane-a2-*` paths; the latest incomplete
gate log is `target/lane-a2-full-gate-final.log`.
