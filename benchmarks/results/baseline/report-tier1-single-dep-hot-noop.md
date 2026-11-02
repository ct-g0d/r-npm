# Differential Comparison Report: npm vs rnpm

- **Date:** 2026-11-02 05:20:59 UTC
- **Fixture:** tier1-single-dep (tier1)
- **Cache State:** hot-noop (install)
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
| **Wall-clock Time (Median)** | 655.35 ms | 40.82 ms | -614.53 ms | -93.77% | <= +5% and > 25 ms | 鈿?FASTER |
| **User CPU Time** | 437.5 ms | 15.62 ms | -421.88 ms | -96.43% | Informational | 鈩癸笍 INFO |
| **System CPU Time** | 265.62 ms | 31.25 ms | -234.37 ms | -88.24% | Informational | 鈩癸笍 INFO |
| **Peak Working Set** | 89.19 MB | 7.61 MB | -81.57 MB | -91.46% | Informational | 鈩癸笍 INFO |
| **Peak Commit Charge** | 97 MB | 3.14 MB | -93.86 MB | -96.76% | <= +10% | 鈿?FASTER |
| **Disk Write Bytes** | 2.35 KB | 0.81 KB | -1.54 KB | -65.60% | Informational | 鈩癸笍 INFO |
| **Write Amplification** | 10.34 x | 3.56 x | -6.79 x | -65.60% | Informational | 鈩癸笍 INFO |

## Gate Decision

### **OVERALL RESULT: PASS 鉁?*
Normalized dependency tree and lockfile v3 match 100%. Performance regressions are within allowable thresholds.