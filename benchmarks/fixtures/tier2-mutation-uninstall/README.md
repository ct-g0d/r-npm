# tier2-mutation-uninstall

Tier 2 focused mutation fixture for testing `rnpm uninstall` and `npm uninstall` differential parity:
- Direct dependency uninstallation (e.g., `cookie-parser`)
- DevDependency uninstallation and binary shim pruning (e.g., `typescript` and `node_modules/.bin/tsc*`)
- Transitive dependency pruning upon removing sole parent dependency (e.g., `express` pruning `depd`, `debug`)
