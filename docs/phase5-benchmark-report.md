# Phase 5: Differential Benchmark Report & Performance Evaluation

## Executive Summary

This report documents the official **Gate D** and **Gate F** benchmark evaluations of `rnpm` (v0.1.0 release profile compiled with rustc 1.99.1) against `npm` (v11.20.0 running on Node.js v26.13.0) under standardized machine conditions on Windows 11.

All benchmark trials were captured with Windows Job Object process-tree accounting, measuring wall-clock time, user CPU, system CPU, peak working set RAM, peak commit charge, disk writes, and network transfers.

In addition, **Gate C** completion was verified through comprehensive Tier 2 mutation differential tests covering `uninstall`, `update`, and `pack` against npm as the behavioral oracle.

---

## Benchmark Reconciliation & Discrepancy Resolution

### 1. Root Cause Analysis of the Discrepancy (78.09 ms vs 50.74 ms)
- **Checkpoint Baseline Artifact:** In the previous baseline artifact `benchmarks/results/baseline/checkpoint-rnpm-tier1-single-dep-pristine-cold.json` (commit `cdd8584`), 5 pristine-cold trials were recorded:
  - Trial 0: 43.17 ms
  - Trial 1: 108.10 ms
  - Trial 2: 164.16 ms
  - Trial 3: 78.09 ms
  - Trial 4: 50.50 ms
  - **Formal 5-Trial Median:** `78.09 ms` (accurately reported in `report-tier1-single-dep-pristine-cold.md`).
- **Discrepant Report Figure:** The earlier version of `docs/phase5-benchmark-report.md` listed `50.74 ms` as the pristine-cold wall time for `rnpm`. This figure originated from an informal single-trial preliminary observation (similar to Trial 4's 50.50 ms) during draft writing, rather than using the formal 5-trial median required by `plan.md` statistical rules.
- **Environment Inconsistency:** The earlier report also cited obsolete runtime versions (Node `v24.21.0` and npm `v11.19.0`).

### 2. Reconciliation & Clean Re-run
Under clean working tree conditions and the pinned `rust-toolchain.toml` (1.99.1 release profile), the benchmark suite was re-executed against the host's actual Node.js `v26.13.0` and npm `11.20.0` environment.

The newly measured, reproducible 5-trial pristine-cold numbers are:
- **`npm` (Baseline):** 1,113.79 ms median (5 trials: 1167.1, 1113.8, 1094.1, 1060.3, 1120.6 ms)
- **`rnpm` (Target):** **74.27 ms** median (5 trials: 76.1, 81.4, 74.3, 59.4, 60.4 ms)
- **Performance Advantage:** **15.0x faster (-93.33% wall time)**, with **89.45% less RAM** (9.05 MB vs 85.79 MB) and **96.14% less peak commit** (3.61 MB vs 93.59 MB).
- **Correctness:** 100% normalized tree digest match and 100% deterministic lockfile v3 byte-for-byte digest match (`6c3be7219d0c368ff09117443dbdca0644310f8ce9bb2d8cf14b59cc8bedc50c`).

---

## Environment & Machine Conditions

| Attribute | Specification |
|---|---|
| **OS** | Microsoft Windows 11 Home (NT 10.0.26300.0) |
| **CPU** | Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz (6 physical cores, 12 logical threads) |
| **RAM** | 31.9 GB (34,202,836,992 bytes) |
| **Node.js / npm** | Node v26.13.0 / npm 11.20.0 |
| **Rust Toolchain** | rustc 1.99.1 (58cf8f9c3 2026-10-13), target `x86_64-pc-windows-msvc` |
| **Cargo Profile** | `release` (`opt-level = 3`) |
| **Antivirus State** | Windows Defender Real-time Protection Enabled |
| **OS Standby Purge** | `false` |
| **Registry** | Local Pinned Loopback Mock Registry (`http://127.0.0.1:4873`) |

---

## Comparative Benchmark Summary

Evaluated across standard cache states for `tier1-single-dep` using 5 cold trials and 7 warm/hot trials (with 3-MAD outlier replacement per `plan.md` statistical rules):

### 1. Pristine Cold (`install`)
- **Cache Precondition:** Empty cache, absent `node_modules`, absent lockfile. Measures full resolution, tarball download, integrity verification, extraction, and lockfile creation.
- **Correctness:** 100% Normalized tree digest & lockfile v3 match (`PASS`).

| Metric | Baseline (npm) | Target (rnpm) | Delta (Abs) | Delta (%) | Gate Threshold | Status |
|---|---|---|---|---|---|---|
| **Wall-clock Time** | 1,113.79 ms | 74.27 ms | -1039.52 ms | **-93.33%** | <= +5.0% and > 25 ms | **FASTER (15.0x)** |
| **User CPU Time** | 625.00 ms | 31.25 ms | -593.75 ms | **-95.00%** | Informational | **INFO (20.0x)** |
| **System CPU Time** | 312.50 ms | 31.25 ms | -281.25 ms | **-90.00%** | Informational | **INFO (10.0x)** |
| **Peak Working Set** | 85.79 MB | 9.05 MB | -76.73 MB | **-89.45%** | Informational | **INFO (9.5x less RAM)** |
| **Peak Commit Charge** | 93.59 MB | 3.61 MB | -89.97 MB | **-96.14%** | <= +10.0% | **FASTER (25.9x less)** |
| **Disk Write Bytes** | 3.04 KB | 2.05 KB | -0.99 KB | **-32.66%** | Informational | **INFO** |
| **Write Amplification**| 13.35x | 8.99x | -4.36x | **-32.66%** | Informational | **INFO** |

---

### 2. Warm Install (`install`)
- **Cache Precondition:** Populated cache, clean `node_modules`, pinned lockfile. Measures cached verification and extraction.
- **Correctness:** 100% Normalized tree digest & lockfile v3 match (`PASS`).

| Metric | Baseline (npm) | Target (rnpm) | Delta (Abs) | Delta (%) | Gate Threshold | Status |
|---|---|---|---|---|---|---|
| **Wall-clock Time** | 958.41 ms | 42.18 ms | -916.23 ms | **-95.60%** | <= +5.0% and > 25 ms | **FASTER (22.7x)** |
| **User CPU Time** | 484.38 ms | 15.62 ms | -468.76 ms | **-96.78%** | Informational | **INFO (31.0x)** |
| **System CPU Time** | 375.00 ms | 15.62 ms | -359.38 ms | **-95.83%** | Informational | **INFO (24.0x)** |
| **Peak Working Set** | 85.89 MB | 7.35 MB | -78.54 MB | **-91.44%** | Informational | **INFO (11.7x less RAM)** |
| **Peak Commit Charge** | 93.67 MB | 3.50 MB | -90.18 MB | **-96.27%** | <= +10.0% | **FASTER (26.8x less)** |
| **Disk Write Bytes** | 2.57 KB | 1.32 KB | -1.24 KB | **-48.40%** | Informational | **INFO** |
| **Write Amplification**| 11.28x | 5.82x | -5.46x | **-48.40%** | Informational | **INFO** |

---

### 3. Hot No-Op (`install`)
- **Cache Precondition:** Populated cache, present and correct `node_modules`, pinned lockfile. Measures freshness checking and zero-mutation validation.
- **Correctness:** 100% Normalized tree digest & lockfile v3 match (`PASS`).

| Metric | Baseline (npm) | Target (rnpm) | Delta (Abs) | Delta (%) | Gate Threshold | Status |
|---|---|---|---|---|---|---|
| **Wall-clock Time** | 1,010.05 ms | 40.34 ms | -969.71 ms | **-96.01%** | <= +5.0% and > 25 ms | **FASTER (25.0x)** |
| **User CPU Time** | 437.50 ms | 15.62 ms | -421.88 ms | **-96.43%** | Informational | **INFO (28.0x)** |
| **System CPU Time** | 296.88 ms | 15.62 ms | -281.26 ms | **-94.74%** | Informational | **INFO (19.0x)** |
| **Peak Working Set** | 85.75 MB | 7.82 MB | -77.93 MB | **-90.88%** | Informational | **INFO (11.0x less RAM)** |
| **Peak Commit Charge** | 93.54 MB | 3.46 MB | -90.08 MB | **-96.30%** | <= +10.0% | **FASTER (27.0x less)** |
| **Disk Write Bytes** | 2.19 KB | 1.32 KB | -0.87 KB | **-39.57%** | Informational | **INFO** |
| **Write Amplification**| 9.63x | 5.82x | -3.81x | **-39.57%** | Informational | **INFO** |

---

### 4. Diamond Dependency Graph (`tier1-diamond` Warm Install)
- **Structure:** 2 root dependencies sharing a common transitive dependency (`pkg-diamond-bottom`).
- **Correctness:** 100% Normalized tree digest & lockfile v3 match (`PASS`).
- **Wall-clock Time:** 1,001.53 ms (npm) vs 45.69 ms (rnpm) -> **-95.44% FASTER (21.9x)**
- **Peak Working Set:** 86.03 MB vs 7.02 MB -> **-91.84% (-79.01 MB, 12.3x less RAM)**
- **Peak Commit Charge:** 93.82 MB vs 4.36 MB -> **-95.35% (-89.46 MB, 21.5x less commit)**
- **Disk Write Bytes:** 4.88 KB vs 3.43 KB -> **-29.77% (-1.45 KB)**

---

## Gate Checklist Status

### Gate A: Baseline is Trustworthy (`PASS`)
- `[x]` npm warm-cache runs vary by less than 5% RSD (3.14% on warm-install, 4.14% on hot-noop, 2.10% on diamond).
- `[x]` rnpm warm-cache runs vary by less than 5% RSD or <= 25ms absolute noise (4.77% on warm-install, 1.19% on hot-noop, 2.11% on diamond).
- `[x]` Full process-tree metrics captured via Windows Job Objects.
- `[x]` Pristine cold, warm install, and hot no-op states cleanly separated.

### Gate B: Vertical Slice Works (`PASS`)
- `[x]` Single-dependency fixture installs successfully into a clean directory.
- `[x]` Normalized tree digest and lockfile v3 match npm with 100% parity.
- `[x]` Deterministic lockfile output verified.

### Gate C: Ordinary Projects Work (`PASS`)
- `[x]` `install`, `ci`, and `run` work for named Tier 2 fixtures (`tier2-vite-react`, `tier2-express`, and `tier2-typescript-cli`).
- `[x]` `uninstall`, `update`, and `pack` pass their focused Tier 2 mutation fixtures (`test-differential-tier2-mutations.ps1` - 60/60 tests passed).
- `[x]` `ci` rejects manifest/lockfile drift without registry requests or tree mutation.
- `[x]` npm and rnpm produce equivalent trees, links, modes, and lockfiles for supported fixtures.
- `[x]` Lifecycle scripts expose the required environment with credentials scrubbed and terminate cleanly on interruption.
- `[x]` Optional native dependency build failure does not fail the parent install.
- `[x]` Bundled dependencies are retained, marked `inBundle`, and do not trigger registry requests.
- `[x]` Registry dependencies skip `prepare`; dependency lifecycle scripts run bottom-up.
- `[x]` Windows shim arguments are safely escaped and Unix CRLF shebangs execute correctly.
- `[x]` Pruning junctions removes only the reparse point and never deletes the linked target.
- `[x]` Windows non-admin installs use junctions and `.cmd`/`.ps1` shims successfully.
- `[x]` Windows NTFS and Unix filesystem cases pass their respective contracts.

### Gate D: Optimization is Measurable (`PASS`)
- `[x]` Every speed claim has a before-and-after result with raw iterations, median/IQR for seven-trial runs, or median/range for five-trial cold runs.
- `[x]` Peak RAM and disk write amplification do not regress (-89% to -92% peak RAM, -30% to -48% disk writes).
- `[x]` Zero regressions exceeding 5% wall time or 10% peak commit charge.
- `[x]` CPU, network, disk, antivirus, and filesystem-cache conditions documented.

### Gate F: Checkpoint Artifacts are Inspectable (`PASS`)
- `[x]` Standard machine-readable `checkpoint.v1.json` artifacts generated for all runs in `benchmarks/results/baseline/`.
- `[x]` Complete environment metadata, hardware specs, OS, Node, Rust, and tool commits recorded.
- `[x]` 100% correctness verified before accepting benchmark results.
