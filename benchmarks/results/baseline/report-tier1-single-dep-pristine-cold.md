# Differential Comparison Report: npm vs rnpm

- **Date:** 2026-11-02 09:55:31 UTC
- **Fixture:** tier1-single-dep (tier1)
- **Cache State:** pristine-cold (install)
- **Machine:** Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz | RAM: 31.9 GB
- **OS:** Microsoft Windows NT 10.0.26300.0 (Microsoft Windows 11 瀹跺涵鐗?涓枃鐗?
- **Node:** v24.21.0 | **npm:** 11.19.0
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
| **Wall-clock Time (Median)** | 1194.87 ms | 78.09 ms | -1116.78 ms | -93.46% | <= +5% and > 25 ms | 鈿?FASTER |
| **User CPU Time** | 750 ms | 31.25 ms | -718.75 ms | -95.83% | Informational | 鈩癸笍 INFO |
| **System CPU Time** | 437.5 ms | 31.25 ms | -406.25 ms | -92.86% | Informational | 鈩癸笍 INFO |
| **Peak Working Set** | 89.73 MB | 8.46 MB | -81.27 MB | -90.57% | Informational | 鈩癸笍 INFO |
| **Peak Commit Charge** | 97.04 MB | 3.38 MB | -93.66 MB | -96.52% | <= +10% | 鈿?FASTER |
| **Disk Write Bytes** | 3.17 KB | 1.74 KB | -1.43 KB | -45.21% | Informational | 鈩癸笍 INFO |
| **Write Amplification** | 13.93 x | 7.63 x | -6.30 x | -45.21% | Informational | 鈩癸笍 INFO |

## Gate Decision

### **OVERALL RESULT: PASS 鉁?*
Normalized dependency tree and lockfile v3 match 100%. Performance regressions are within allowable thresholds.