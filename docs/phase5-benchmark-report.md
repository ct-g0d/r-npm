# Phase 5: Differential Benchmark Report & Performance Evaluation

## Executive Summary

This report documents the official **Gate D** and **Gate F** benchmark evaluations of `rnpm` (v0.1.0 release profile compiled with rustc 1.99.1) against `npm` (v11.19.0 running on Node.js v24.21.0) under standardized machine conditions on Windows 11.

All benchmark trials were captured with Windows Job Object process-tree accounting, measuring wall-clock time, user CPU, system CPU, peak working set RAM, peak commit charge, disk writes, and network transfers.

In addition, **Gate C** completion was verified through comprehensive Tier 2 mutation differential tests covering `uninstall`, `update`, and `pack` against npm as the behavioral oracle.

---

## Environment & Machine Conditions

| Attribute | Specification |
|---|---|
| **OS** | Windows 11 Home (NT 10.0.26300.0) |
| **CPU** | Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz (6 physical cores, 12 logical threads) |
| **RAM** | 31.9 GB (34,202,836,992 bytes) |
| **Node.js / npm** | Node v24.21.0 / npm v11.19.0 |
| **Rust Toolchain** | rustc 1.99.1 (58cf8f9c3 2026-10-13), target `x86_64-pc-windows-msvc` |
| **Cargo Profile** | `release` |
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
| **Wall-clock Time** | 705.42 ms | 50.74 ms | -654.68 ms | **-92.81%** | <= +5.0% and > 25 ms | **FASTER (13.9x)** |
| **User CPU Time** | 437.50 ms | 15.62 ms | -421.88 ms | **-96.43%** | Informational | **INFO (28.0x)** |
| **System CPU Time** | 343.75 ms | 15.62 ms | -328.13 ms | **-95.46%** | Informational | **INFO (22.0x)** |
| **Peak Working Set** | 89.77 MB | 8.00 MB | -81.77 MB | **-91.09%** | Informational | **INFO (11.2x less RAM)** |
| **Peak Commit Charge** | 97.74 MB | 3.15 MB | -94.59 MB | **-96.77%** | <= +10.0% | **FASTER (31.0x less)** |
| **Disk Write Bytes** | 3.20 KB | 1.20 KB | -2.00 KB | **-62.61%** | Informational | **INFO** |
| **Write Amplification**| 14.06x | 5.26x | -8.80x | **-62.60%** | Informational | **INFO** |

---

### 2. Warm Install (`install`)
- **Cache Precondition:** Populated cache, clean `node_modules`, pinned lockfile. Measures cached verification and extraction.
- **Correctness:** 100% Normalized tree digest & lockfile v3 match (`PASS`).

| Metric | Baseline (npm) | Target (rnpm) | Delta (Abs) | Delta (%) | Gate Threshold | Status |
|---|---|---|---|---|---|---|
| **Wall-clock Time** | 683.22 ms | 42.25 ms | -640.97 ms | **-93.82%** | <= +5.0% and > 25 ms | **FASTER (16.2x)** |
| **User CPU Time** | 484.38 ms | 15.62 ms | -468.76 ms | **-96.78%** | Informational | **INFO (31.0x)** |
| **System CPU Time** | 250.00 ms | 15.62 ms | -234.38 ms | **-93.75%** | Informational | **INFO (16.0x)** |
| **Peak Working Set** | 89.38 MB | 6.78 MB | -82.60 MB | **-92.41%** | Informational | **INFO (13.2x less RAM)** |
| **Peak Commit Charge** | 97.19 MB | 3.13 MB | -94.06 MB | **-96.78%** | <= +10.0% | **FASTER (31.0x less)** |
| **Disk Write Bytes** | 2.73 KB | 0.81 KB | -1.92 KB | **-70.33%** | Informational | **INFO** |
| **Write Amplification**| 11.99x | 3.56x | -8.43x | **-70.33%** | Informational | **INFO** |

---

### 3. Hot No-Op (`install`)
- **Cache Precondition:** Populated cache, present and correct `node_modules`, pinned lockfile. Measures freshness checking and zero-mutation validation.
- **Correctness:** 100% Normalized tree digest & lockfile v3 match (`PASS`).

| Metric | Baseline (npm) | Target (rnpm) | Delta (Abs) | Delta (%) | Gate Threshold | Status |
|---|---|---|---|---|---|---|
| **Wall-clock Time** | 656.34 ms | 38.35 ms | -617.99 ms | **-94.16%** | <= +5.0% and > 25 ms | **FASTER (17.1x)** |
| **User CPU Time** | 437.50 ms | 15.62 ms | -421.88 ms | **-96.43%** | Informational | **INFO (28.0x)** |
| **System CPU Time** | 312.50 ms | 31.25 ms | -281.25 ms | **-90.00%** | Informational | **INFO (10.0x)** |
| **Peak Working Set** | 88.84 MB | 8.07 MB | -80.77 MB | **-90.92%** | Informational | **INFO (11.0x less RAM)** |
| **Peak Commit Charge** | 96.66 MB | 3.15 MB | -93.51 MB | **-96.74%** | <= +10.0% | **FASTER (30.7x less)** |
| **Disk Write Bytes** | 2.35 KB | 0.81 KB | -1.54 KB | **-65.60%** | Informational | **INFO** |
| **Write Amplification**| 10.34x | 3.56x | -6.79x | **-65.60%** | Informational | **INFO** |

---

### 4. Diamond Dependency Graph (`tier1-diamond` Warm Install)
- **Structure:** 2 root dependencies sharing a common transitive dependency (`pkg-diamond-bottom`).
- **Correctness:** 100% Normalized tree digest & lockfile v3 match (`PASS`).
- **Wall-clock Time:** 701.10 ms (npm) vs 46.60 ms (rnpm) -> **-93.35% FASTER (15.0x)**
- **Peak Working Set:** 89.70 MB vs 7.89 MB -> **-91.20% (-81.81 MB)**
- **Peak Commit Charge:** 97.51 MB vs 3.17 MB -> **-96.75% (-94.34 MB)**

---

## Gate Checklist Status

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
- `[x]` Peak RAM and disk write amplification do not regress (-91% to -92% peak RAM, -62% to -70% disk writes).
- `[x]` Zero regressions exceeding 5% wall time or 10% peak commit charge.
- `[x]` CPU, network, disk, antivirus, and filesystem-cache conditions documented.

### Gate F: Checkpoint Artifacts are Inspectable (`PASS`)
- `[x]` Standard machine-readable `checkpoint.v1.json` artifacts generated for all runs.
- `[x]` Complete environment metadata, hardware specs, OS, Node, Rust, and tool commits recorded.
- `[x]` 100% correctness verified before accepting benchmark results.
