# tier2-mutation-update

Tier 2 focused mutation fixture for testing `rnpm update` and `npm update` differential parity:
- Targeted package update (e.g., updating only `cors` from `2.8.4` to `2.8.5` while leaving `commander` at `11.0.0`)
- Full package update (e.g., updating all packages within declared semver ranges `commander` -> `11.1.0`, `cors` -> `2.8.5`)
- Lockfile v3 and node_modules parity across updates
