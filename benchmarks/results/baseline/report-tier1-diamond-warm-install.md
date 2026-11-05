# Differential Comparison Report: npm vs rnpm

- **Date:** 2026-11-05 09:52:07 UTC
- **Fixture:** tier1-diamond (tier1)
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
| **Wall-clock Time (Median)** | 1001.53 ms | 45.69 ms | -955.84 ms | -95.44% | <= +5% and > 25 ms | 鈿?FASTER |
| **User CPU Time** | 484.38 ms | 15.62 ms | -468.76 ms | -96.78% | Informational | 鈩癸笍 INFO |
| **System CPU Time** | 359.38 ms | 31.25 ms | -328.13 ms | -91.30% | Informational | 鈩癸笍 INFO |
| **Peak Working Set** | 86.03 MB | 7.02 MB | -79.01 MB | -91.84% | Informational | 鈩癸笍 INFO |
| **Peak Commit Charge** | 93.82 MB | 4.36 MB | -89.46 MB | -95.35% | <= +10% | 鈿?FASTER |
| **Disk Write Bytes** | 4.88 KB | 3.43 KB | -1.45 KB | -29.77% | Informational | 鈩癸笍 INFO |
| **Write Amplification** | 5.74 x | 4.03 x | -1.71 x | -29.77% | Informational | 鈩癸笍 INFO |

## Gate Decision

### **OVERALL RESULT: PASS 鉁?*
Normalized dependency tree and lockfile v3 match 100%. Performance regressions are within allowable thresholds.