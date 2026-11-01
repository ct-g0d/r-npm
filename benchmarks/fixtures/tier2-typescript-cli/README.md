# Tier 2: TypeScript CLI Fixture (`tier2-typescript-cli`)

Synthetic benchmark fixture representing a Node.js TypeScript command-line tool.

## Manifest Characteristics
- `bin`: Defines `./bin/ts-cli.js` launcher.
- `scripts`: Includes `preinstall`, `postinstall`, `build` (`tsc --version`), `start`, and `test`.
- `dependencies`:
  - `commander`: CLI argument parser.
  - `typescript`: Compiler providing `.bin/tsc` and `.bin/tsserver` executable shims.
  - `mock-cli-helper`: Executable helper with `postinstall` lifecycle hook and `.bin/cli-helper` shim.

## Purpose
Validates:
1. Generation and execution of Windows `.cmd`, `.ps1`, and Unix `.bin` executable wrappers.
2. Argument forwarding through shims (including quotes, flags, and special characters).
3. Dependency lifecycle execution in bottom-up order.
4. Credential scrubbing during lifecycle runs.
