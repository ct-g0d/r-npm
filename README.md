# npm-rust (`rnpm`)

High-performance, drop-in Rust implementation of npm 11.x workflows.

`rnpm` is designed to install and operate ordinary Node.js projects reliably, reproducing exact `node_modules` trees and `package-lock.json` v3 lockfiles with zero diff against npm 11.x, while using materially less wall-clock time, CPU, and RAM.

---

## Toolchain & Reproducibility (Blocker 5)

To guarantee deterministic, byte-for-byte reproducible compilation across developer workstations and CI runners, the Rust compiler and toolchain are strictly pinned.

### Pinned Rust Toolchain: `1.99.1`

The repository root includes a pinned [`rust-toolchain.toml`](rust-toolchain.toml):

```toml
[toolchain]
channel = "1.99.1"
components = ["rustfmt", "clippy"]
targets = ["x86_64-pc-windows-msvc"]
```

- **Rust Version:** `rustc 1.99.1 (58cf8f9c3 2026-10-13)`
- **Cargo Version:** `cargo 1.99.1 (5f94df478 2026-08-27)`
- **Clippy Version:** `clippy 0.1.99 (58cf8f9c35 2026-10-13)`
- **Cargo MSRV:** `rust-version = "1.99.1"` in `Cargo.toml`
- **Behavioral Oracle:** `npm v11.x` running on Node.js `v24.x` / `v26.x`

When rustup is used in this repository, `rust-toolchain.toml` automatically selects toolchain `1.99.1`:

```text
Default host: x86_64-pc-windows-msvc
installed toolchains:
  stable-x86_64-pc-windows-msvc (default)
  1.99.1-x86_64-pc-windows-msvc (active)

active toolchain:
  name: 1.99.1-x86_64-pc-windows-msvc
  active because: overridden by 'rust-toolchain.toml'
```

*Note on local workstation environment:* Cargo and Rust toolchain binaries are located in `D:\AppData\user2\.cargo\bin`. To ensure the pinned toolchain is in your active PowerShell path:
```powershell
$env:PATH = "D:\AppData\user2\.cargo\bin;" + $env:PATH
```

---

## Architecture Overview

`rnpm` is organized as a Cargo workspace of focused, modular crates:

| Crate | Responsibility |
|---|---|
| [`rnpm-core`](crates/rnpm-core) | Domain types, manifest parsing (`package.json`), node-semver versioning & ranges, package specifier grammar, SSRI multi-hash integrity descriptors. |
| [`rnpm-config`](crates/rnpm-config) | Configuration loading (`.npmrc`), environment variable interpolation (`${NPM_TOKEN}`), scoped registry routing, credential masking. |
| [`rnpm-registry`](crates/rnpm-registry) | HTTP registry client, abbreviated packument metadata, streaming tarball fetch, exponential backoff retry, Byzantine & Slowloris defenses, SLSA provenance verification. |
| [`rnpm-cache`](crates/rnpm-cache) | Content-addressable storage (`cacache`), cross-process file locking (`fs4`), atomic file staging, automatic corruption self-healing. |
| [`rnpm-lockfile`](crates/rnpm-lockfile) | Lockfile v3 parsing & deterministic serialization, read-only v1/v2 migration, hidden lockfile (`node_modules/.package-lock.json`), drift detection. |
| [`rnpm-fs`](crates/rnpm-fs) | Filesystem operations, atomic directory replacement, unprivileged NTFS directory junctions (Windows), path traversal security, tar-bomb limits. |
| [`rnpm-solver`](crates/rnpm-solver) | In-memory dependency graph, hoisting & deduplication, npm RFC 36 overrides, dense peer dependency resolution, multi-tier monorepo workspaces. |
| [`rnpm-shim`](crates/rnpm-shim) | Cross-platform executable shim generation (`<bin>`, `<bin>.cmd`, `<bin>.ps1`, Unix shell) with shell argument escaping and CRLF shebang normalization. |
| [`rnpm-lifecycle`](crates/rnpm-lifecycle) | Topological lifecycle script execution (`preinstall`, `install`, `postinstall`, `prepare`), credential scrubbing, Windows Job Object containment, process signal cleanup. |
| [`rnpm-install`](crates/rnpm-install) | Installation orchestrator (`install`, `ci`, `uninstall`, `update`, `prune`), offline caching, parallel tiered extraction. |
| [`rnpm-cli`](crates/rnpm-cli) | CLI entrypoint, argument parsing, script shortcuts (`test`, `start`, `restart`, `stop`, bare `run`), `pkg` manifest manipulation, `audit` scanning, structured diagnostics. |

---

## Active Command Matrix & Flags

`rnpm` provides drop-in compatibility for all standard npm 11.x package management, inspection, query, and lifecycle commands (DEC-004 Accepted):

- **`install`** (aliases: `i`, `add`, `isntall`): Full resolution, fetch, verify, unpack, link, lifecycle execution, lockfile v3 serialization.
  - Flags: `-D`/`--save-dev`, `-E`/`--save-exact`, `-P`/`-S`/`--save-prod`/`--save`, `-O`/`--save-optional`, `--save-peer`, `--no-save`, `--package-lock-only`, `--omit=<types>`, `--offline`, `--ignore-scripts`, `--legacy-peer-deps`, `--strict-peer-deps`, `--registry`, `--cache`.
- **`ci` / `clean-install`** (alias: `ic`): Clean installation strictly from `package-lock.json` with drift detection (`ELOCKFILE_DRIFT`).
  - Flags: `--omit=<types>`, `--offline`, `--ignore-scripts`, `--legacy-peer-deps`, `--strict-peer-deps`, `--package-lock-only`, `--registry`, `--cache`.
- **`test` / `start` / `restart` / `stop`** (aliases: `t`, `tst`): Dedicated script execution shortcuts forwarding trailing arguments.
- **`run` / `run-script`**: Run package scripts or enumerate available scripts when invoked with no arguments (`rnpm run`).
  - Flags: `-w`/`--workspaces`/`ws`, `--workspace`, `--filter`, `--scope`, `--if-present`, `--ignore-scripts`.
- **`exec` / `npx`** (alias: `x`): Dynamic ephemeral package execution.
- **`pack`**: Build canonical npm `.tgz` package archives with files/ignore filtering.
- **`uninstall`** (aliases: `remove`, `rm`, `r`, `un`): Remove packages, clean unused transitive dependencies, update lockfile.
- **`update`** (alias: `up`): Update registry dependencies within declared semver ranges.
- **`prune`**: Remove extraneous packages from `node_modules` (`--omit`, `-p`/`--production`, `--dry-run`, `--json`).
- **`pkg`**: Manifest inspection and manipulation (`get`, `set`, `delete`, `--prefix`, `--json`).
- **`audit`**: Security advisory audit queries against registry endpoint with threshold exit codes (`--audit-level`, `--json`, `--dry-run`).
- **`cache`**: Content-addressable cache verification and purge (`clean [--force]`, `verify`).

---

## Verification & Testing

### Building

```powershell
cargo build --release --bin rnpm
```

The resulting binary is located at `target/release/rnpm.exe`.

### Running Tests

Execute the full workspace test suite (441+ unit and integration tests):

```powershell
cargo test --workspace
```

### Static Analysis & Lints

Verify zero warnings across all workspace targets:

```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

### Benchmarks & Differential Parity

Differential correctness and performance sweeps against npm 11.x:

```powershell
powershell -ExecutionPolicy Bypass -File benchmarks\run-benchmarks.ps1
```

---

## License

MIT OR Apache-2.0
