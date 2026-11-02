# Tier 3 Deep Tree Fixture

Stress benchmark fixture evaluating:
- Deeply nested recursive dependency chains (25+ levels: `pkg-tier3-deep-00` -> `pkg-tier3-deep-25`).
- Cross-branch diamond joins (`pkg-tier3-deep-branch` joining at level 15).
- Hoisting depth and tree flattening parity between npm and rnpm.
