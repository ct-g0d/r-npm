# Phase 1: npm Observable Subsystems Source Map Fixtures

This directory contains canonical fixtures mapping the 13 major observable subsystems of npm (npm v11.x on Node.js v24.x) as defined in `docs/npm-source-map.md`.

## Fixture Index

1. **`01-cli-dispatch`**: Command execution, flags, exit codes (0 for success, 1 for failure, 130 for SIGINT, 124 for timeout), and diagnostic formatting.
2. **`02-config-precedence`**: 6-tier configuration cascade, `.npmrc` parsing, nerf-dart auth tokens, and scoped registries.
3. **`03-spec-grammar`**: `npm-package-arg` grammar rules (registry, ranges, tags, npm aliases, git protocols, file/directory paths, remote tarball URLs).
4. **`04-arborist-tree`**: Arborist actual, ideal, and virtual trees; dependency hoisting, deduplication, and hidden lockfile invariants.
5. **`05-pacote-tarball`**: Archive packing and unpacking contracts, deterministic timestamps (epoch 499162500), and manifest extraction.
6. **`06-registry-fetch`**: `application/vnd.npm.install-v1+json` abbreviated metadata, scoped package percent-encoding, and auth containment across cross-origin redirects.
7. **`07-cacache-ssri`**: Content-addressable cache layout (`content-v2`, `index-v5`), SSRI multi-hash integrity parsing, and strongest-hash priority.
8. **`08-lockfile-v3`**: `lockfileVersion: 3` schema, root `packages[""]` entry, POSIX package path keys, and v1/v2 migration invariants.
9. **`09-node-semver`**: Loose version parsing, hyphen ranges, prerelease precedence, and 0.x / 0.0.x caret boundaries.
10. **`10-lifecycle-scripts`**: Hierarchical `PATH`, `INIT_CWD`, `npm_lifecycle_*` variables, bottom-up execution ordering, and credential scrubbing.
11. **`11-cmd-shim`**: Executable shim generation (Windows trio: `<bin>`, `<bin>.cmd`, `<bin>.ps1`), argument escaping, and CRLF shebang normalization.
12. **`12-fs-extraction`**: Safe archive extraction, `package/` prefix stripping, path traversal rejection, Windows device name defense, and atomic directory replacement.
13. **`13-workspaces`**: Workspace glob expansion, `workspace:*`/`workspace:^`/`workspace:~` resolution, directory junctions, and topological execution.
