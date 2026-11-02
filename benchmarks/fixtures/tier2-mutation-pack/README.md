# tier2-mutation-pack

Tier 2 focused mutation fixture for testing `rnpm pack` and `npm pack` differential parity:
- Tarball naming convention (`tier2-mutation-pack-1.0.0.tgz`)
- Inclusion of `package.json`, `README.md`, `lib/`, and `bin/` files with normalized `package/` path prefix
- Exclusion of unlisted files (e.g. `temp.log`)
- Normalized execution mode (0o755 for bin, 0o644 for regular files)
- `--dry-run` and `--json` format parity
