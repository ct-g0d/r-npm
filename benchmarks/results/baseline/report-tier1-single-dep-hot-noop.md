# Differential Comparison Report: npm vs rnpm

- **Date:** 2026-11-02 09:56:15 UTC
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
| **Wall-clock Time (Median)** | 664.43 ms | 39.08 ms | -625.35 ms | -94.12% | <= +5% and > 25 ms | 鈿?FASTER |
| **User CPU Time** | 421.88 ms | 15.62 ms | -406.26 ms | -96.30% | Informational | 鈩癸笍 INFO |
| **System CPU Time** | 296.88 ms | 15.62 ms | -281.26 ms | -94.74% | Informational | 鈩癸笍 INFO |
| **Peak Working Set** | 88.89 MB | 6.35 MB | -82.54 MB | -92.85% | Informational | 鈩癸笍 INFO |
| **Peak Commit Charge** | 96.84 MB | 3.32 MB | -93.52 MB | -96.58% | <= +10% | 鈿?FASTER |
| **Disk Write Bytes** | 2.32 KB | 1.32 KB | -1.00 KB | -42.95% | Informational | 鈩癸笍 INFO |
| **Write Amplification** | 10.2 x | 5.82 x | -4.38 x | -42.95% | Informational | 鈩癸笍 INFO |

## Gate Decision

### **OVERALL RESULT: PASS 鉁?*
Normalized dependency tree and lockfile v3 match 100%. Performance regressions are within allowable thresholds.