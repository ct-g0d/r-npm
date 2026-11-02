# Tier 3 Monorepo Fixture

Stress benchmark fixture evaluating:
- Multi-package monorepo workspaces (`packages/*`: core, utils, ui, api, cli, app).
- Inter-package workspace linking and directory junctions (`@tier3-mono/*`).
- Bin shim linking for workspace binaries (`mono-cli` -> `node_modules/.bin/mono-cli`).
- External shared dependency hoisting and deduplication across workspace members.
- Differential lockfile v3 and normalized tree parity against npm 10.x oracle.
