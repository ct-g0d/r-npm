# Differential Comparison Report: npm vs rnpm

- **Date:** 2026-11-05 09:51:28 UTC
- **Fixture:** tier1-single-dep (tier1)
- **Cache State:** hot-noop (install)
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
| **Wall-clock Time (Median)** | 1010.05 ms | 40.34 ms | -969.71 ms | -96.01% | <= +5% and > 25 ms | 鈿?FASTER |
| **User CPU Time** | 437.5 ms | 15.62 ms | -421.88 ms | -96.43% | Informational | 鈩癸笍 INFO |
| **System CPU Time** | 296.88 ms | 15.62 ms | -281.26 ms | -94.74% | Informational | 鈩癸笍 INFO |
| **Peak Working Set** | 85.75 MB | 7.82 MB | -77.93 MB | -90.88% | Informational | 鈩癸笍 INFO |
| **Peak Commit Charge** | 93.54 MB | 3.46 MB | -90.08 MB | -96.30% | <= +10% | 鈿?FASTER |
| **Disk Write Bytes** | 2.19 KB | 1.32 KB | -0.87 KB | -39.57% | Informational | 鈩癸笍 INFO |
| **Write Amplification** | 9.63 x | 5.82 x | -3.81 x | -39.57% | Informational | 鈩癸笍 INFO |

## Gate Decision

### **OVERALL RESULT: PASS 鉁?*
Normalized dependency tree and lockfile v3 match 100%. Performance regressions are within allowable thresholds.