# Phase 2: npm Baseline Benchmark Report

## Overview

This report documents the baseline performance and correctness metrics of `npm` (v11.19.0 running on Node.js v24.21.0) on Windows 11 against the Tier 1 synthetic benchmark fixtures using the local loopback mock registry.

These measurements establish the ground truth for Gate A and Gate F evaluations before optimizing `rnpm`.

---

## Machine and Environment Baseline

| Attribute | Value |
|---|---|
| **OS** | Windows 11 Home (NT 10.0.26300.0) |
| **CPU** | Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz (6 cores, 12 logical threads) |
| **RAM** | 31.9 GB (34,202,836,992 bytes) |
| **Node.js** | v24.21.0 |
| **npm** | 11.19.0 |
| **Antivirus** | Windows Defender Real-time Protection Enabled |
| **OS Standby Cache Purged** | `false` |
| **Registry** | Local Loopback Mock Registry (`http://127.0.0.1:4873`) |

---

## Benchmark Results Summary

### Fixture: `tier1-single-dep`

- **Command:** `npm install`
- **Cache State:** `warm-install` (pre-populated cache, clean `node_modules`, pinned `package-lock.json`)
- **Trials:** 1 warmup + 3 recorded trials
- **Normalized Tree Digest:** `2701629d4190fd106f9dbf7b20cd4bcfc9340c24e56b7d30b20211dfc8fdf342`
- **Lockfile v3 Digest:** `2ea2bca4eb947d427968a162538822ab75d2342286ff038670018c4decc95870`

| Metric | Median | Min | Max | IQR | Notes |
|---|---|---|---|---|---|
| **Wall-clock Time** | 836.97 ms | 713.81 ms | 1,071.73 ms | 178.96 ms | Mean: 874.17 ms |
| **User CPU Time** | 609.38 ms | 515.62 ms | 843.75 ms | 164.07 ms | |
| **System CPU Time** | 250.00 ms | 218.75 ms | 265.62 ms | 23.44 ms | |
| **Peak Working Set** | 89.38 MB | 89.25 MB | 90.12 MB | 0.44 MB | 93,724,672 bytes |
| **Peak Commit Charge**| 97.46 MB | 97.32 MB | 98.19 MB | 0.43 MB | 102,191,104 bytes |
| **Disk Writes** | 2.70 KB | 2.70 KB | 2.70 KB | 0 KB | 31 write operations |
| **Write Amplification**| 11.85x | - | - | - | 2.70 KB writes / 233 B uncompressed |

---

### Fixture: `tier1-diamond`

- **Command:** `npm install`
- **Cache State:** `warm-install` (pre-populated cache, clean `node_modules`, pinned `package-lock.json`)
- **Trials:** 1 warmup + 7 recorded trials (with automatic 3-MAD outlier replacement)
- **Normalized Tree Digest:** `aa7ab69a54b7c14605a17f694a32b37d71f84427d084167c691cd9e7c1f31361`
- **Lockfile v3 Digest:** `58621805c4c8c4f412c6931cd4735ca0a3095110a839721661d0ed71af882780`

| Metric | Median | Min | Max | IQR | Notes |
|---|---|---|---|---|---|
| **Wall-clock Time** | 832.19 ms | 742.87 ms | 1,127.73 ms | 93.74 ms | Mean: 863.03 ms |
| **User CPU Time** | 593.75 ms | 515.62 ms | 796.88 ms | 148.44 ms | |
| **System CPU Time** | 312.50 ms | 234.38 ms | 421.88 ms | 93.75 ms | |
| **Peak Working Set** | 89.75 MB | 89.58 MB | 90.28 MB | 0.27 MB | 94,109,696 bytes |
| **Peak Commit Charge**| 97.82 MB | 97.66 MB | 98.34 MB | 0.28 MB | 102,572,032 bytes |
| **Disk Writes** | 5.01 KB | 5.01 KB | 5.01 KB | 0 KB | 50 write operations |
| **Write Amplification**| 5.89x | - | - | - | 5.01 KB writes / 871 B uncompressed |

---

## Key Observations and Optimization Baselines

1. **Working Set & Commit Ceiling:**
   npm on Node.js v24 allocates ~89-94 MB peak working set and ~97-102 MB peak commit charge even for a single-dependency installation. `rnpm` in Rust is expected to operate with less than 15-20 MB peak working set on the same fixture.

2. **Process Spawn Count:**
   A single `npm install` execution spawns 5 separate processes on Windows (`cmd.exe` -> `npm.cmd` -> `node.exe` worker / arborist child processes). In `rnpm`, single-binary direct execution will eliminate process spawning overhead.

3. **Disk Write Behavior:**
   For a warm installation where tarballs are cached, npm writes approximately 2.7 KB - 5.0 KB to disk across 30-50 write operations. Write amplification sits around 6x to 12x for small synthetic packages.

4. **Correctness Invariants:**
   All Tier 1 dependencies must produce identical normalized tree digests and lockfile v3 structures matching the digests recorded above.
