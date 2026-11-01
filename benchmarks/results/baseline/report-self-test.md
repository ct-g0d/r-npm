# Differential Comparison Report: npm vs rnpm

- **Date:** 2026-11-01 06:13:33 UTC
- **Fixture:** tier1-single-dep (tier1)
- **Cache State:** warm-install (install)
- **Machine:** Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz | RAM: 31.9 GB
- **OS:** Microsoft Windows NT 10.0.26300.0 (Microsoft Windows 11 瀹跺涵鐗?涓枃鐗?
- **Node:** v24.21.0 | **npm:** 11.19.0
- **rnpm Version:** 11.19.0 (Rust: )

## Correctness Evaluation (Gate B / Gate F)

| Check | Baseline (npm) | Target (rnpm) | Result |
|---|---|---|---|
| **Exit Code** | 0 | 0 | 鉁?PASS |
| **Tree Digest** | ${npmTreeDigest} | ${rnpmTreeDigest} | 鉁?MATCH |
| **Lockfile v3 Digest** | ${npmLockDigest} | ${rnpmLockDigest} | 鉁?MATCH |

## Performance Metrics (Gate D)

| Metric | npm (Baseline) | rnpm (Target) | Delta (Abs) | Delta (%) | Gate Threshold | Status |
|---|---|---|---|---|---|---|
| **Wall-clock Time (Median)** | 836.97 ms | 836.97 ms | 0.00 ms | 0.00% | <= +5% and > 25 ms | 鉁?PASS |
| **User CPU Time** | 609.38 ms | 609.38 ms | 0.00 ms | 0.00% | Informational | 鈩癸笍 INFO |
| **System CPU Time** | 250 ms | 250 ms | 0.00 ms | 0.00% | Informational | 鈩癸笍 INFO |
| **Peak Working Set** | 89.38 MB | 89.38 MB | 0.00 MB | 0.00% | Informational | 鈩癸笍 INFO |
| **Peak Commit Charge** | 97.46 MB | 97.46 MB | 0.00 MB | 0.00% | <= +10% | 鉁?PASS |
| **Disk Write Bytes** | 2.7 KB | 2.7 KB | 0.00 KB | 0.00% | Informational | 鈩癸笍 INFO |
| **Write Amplification** | 11.85 x | 11.85 x | 0.00 x | 0.00% | Informational | 鈩癸笍 INFO |

## Gate Decision

### **OVERALL RESULT: PASS 鉁?*
Normalized dependency tree and lockfile v3 match 100%. Performance regressions are within allowable thresholds.