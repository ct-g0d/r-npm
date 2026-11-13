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

Final results are recorded after the release build and measurements finish.
