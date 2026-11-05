# Differential Comparison Report: npm vs rnpm

- **Date:** 2026-11-05 09:50:12 UTC
- **Fixture:** tier1-single-dep (tier1)
- **Cache State:** pristine-cold (install)
- **Machine:** Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz | RAM: 31.9 GB
- **OS:** Microsoft Windows NT 10.0.26300.0 (Microsoft Windows 11 瀹跺涵鐗?涓枃鐗?
- **Node:** v26.13.0 | **npm:** 11.20.0
- **rnpm Version:** 0.1.0 (Rust: rustc 1.99.1 (58cf8f9c3 2026-10-13))

## Correctness Evaluation (Gate B / Gate F)

| Check | Baseline (npm) | Target (rnpm) | Result |
|---|---|---|---|
| **Exit Code** | 0 | 0 | 鉁?PASS |
| **Tree Digest** | $npmTreeDigest | $rnpmTreeDigest | PASS |
| **Lockfile v3 Digest** | $npmLockDigest | $rnpmLockDigest | PASS |

## Performance Metrics (Gate D)

| Metric | npm (Baseline) | rnpm (Target) | Delta (Abs) | Delta (%) | Gate Threshold | Status |
|---|---|---|---|---|---|---|
| **Wall-clock Time (Median)** | 1113.79 ms | 74.27 ms | -1039.52 ms | -93.33% | <= +5% and > 25 ms | 鈿?FASTER |
| **User CPU Time** | 625 ms | 31.25 ms | -593.75 ms | -95.00% | Informational | 鈩癸笍 INFO |
| **System CPU Time** | 312.5 ms | 31.25 ms | -281.25 ms | -90.00% | Informational | 鈩癸笍 INFO |
| **Peak Working Set** | 85.79 MB | 9.05 MB | -76.73 MB | -89.45% | Informational | 鈩癸笍 INFO |
| **Peak Commit Charge** | 93.59 MB | 3.61 MB | -89.97 MB | -96.14% | <= +10% | 鈿?FASTER |
| **Disk Write Bytes** | 3.04 KB | 2.05 KB | -0.99 KB | -32.66% | Informational | 鈩癸笍 INFO |
| **Write Amplification** | 13.35 x | 8.99 x | -4.36 x | -32.66% | Informational | 鈩癸笍 INFO |

## Gate Decision

### **OVERALL RESULT: PASS 鉁?*
Normalized dependency tree and lockfile v3 match 100%. Performance regressions are within allowable thresholds.