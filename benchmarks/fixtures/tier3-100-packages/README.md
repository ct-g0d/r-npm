# Tier 3 100+ Packages Fixture

Stress benchmark fixture evaluating:
- Large dependency graph with 110 distinct packages (`pkg-tier3-stress-001` through `pkg-tier3-stress-110`).
- Multi-tier dependency tree: 10 root packages -> 40 intermediate packages -> 60 leaf packages.
- Resolution, network parallel fetch, and disk write performance and correctness at scale.
