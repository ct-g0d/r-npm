# Differential Comparison Report: npm vs rnpm

- **Date:** 2026-11-05 09:50:53 UTC
- **Fixture:** tier1-single-dep (tier1)
- **Cache State:** warm-install (install)
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
| **Wall-clock Time (Median)** | 958.41 ms | 42.18 ms | -916.23 ms | -95.60% | <= +5% and > 25 ms | 鈿?FASTER |
| **User CPU Time** | 484.38 ms | 15.62 ms | -468.76 ms | -96.78% | Informational | 鈩癸笍 INFO |
| **System CPU Time** | 375 ms | 15.62 ms | -359.38 ms | -95.83% | Informational | 鈩癸笍 INFO |
| **Peak Working Set** | 85.89 MB | 7.35 MB | -78.54 MB | -91.44% | Informational | 鈩癸笍 INFO |
| **Peak Commit Charge** | 93.67 MB | 3.5 MB | -90.18 MB | -96.27% | <= +10% | 鈿?FASTER |
| **Disk Write Bytes** | 2.57 KB | 1.32 KB | -1.24 KB | -48.40% | Informational | 鈩癸笍 INFO |
| **Write Amplification** | 11.28 x | 5.82 x | -5.46 x | -48.40% | Informational | 鈩癸笍 INFO |

## Gate Decision

### **OVERALL RESULT: PASS 鉁?*
Normalized dependency tree and lockfile v3 match 100%. Performance regressions are within allowable thresholds.