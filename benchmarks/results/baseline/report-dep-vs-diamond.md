# Differential Comparison Report: npm vs rnpm

- **Date:** 2026-11-01 06:14:56 UTC
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
| **Tree Digest** | $npmTreeDigest | $rnpmTreeDigest | MISMATCH |
| **Lockfile v3 Digest** | $npmLockDigest | $rnpmLockDigest | MISMATCH |

### Correctness Issues
- 鉂?Normalized tree digest mismatch: npm (2701629d4190fd106f9dbf7b20cd4bcfc9340c24e56b7d30b20211dfc8fdf342) vs rnpm (aa7ab69a54b7c14605a17f694a32b37d71f84427d084167c691cd9e7c1f31361)
- 鉂?Lockfile v3 digest mismatch: npm (2ea2bca4eb947d427968a162538822ab75d2342286ff038670018c4decc95870) vs rnpm (58621805c4c8c4f412c6931cd4735ca0a3095110a839721661d0ed71af882780)

## Performance Metrics (Gate D)

| Metric | npm (Baseline) | rnpm (Target) | Delta (Abs) | Delta (%) | Gate Threshold | Status |
|---|---|---|---|---|---|---|
| **Wall-clock Time (Median)** | 836.97 ms | 832.19 ms | -4.78 ms | -0.57% | <= +5% and > 25 ms | 鈿?FASTER |
| **User CPU Time** | 609.38 ms | 593.75 ms | -15.63 ms | -2.56% | Informational | 鈩癸笍 INFO |
| **System CPU Time** | 250 ms | 312.5 ms | +62.50 ms | +25.00% | Informational | 鈩癸笍 INFO |
| **Peak Working Set** | 89.38 MB | 89.75 MB | +0.37 MB | +0.42% | Informational | 鈩癸笍 INFO |
| **Peak Commit Charge** | 97.46 MB | 97.82 MB | +0.37 MB | +0.38% | <= +10% | 鉁?PASS |
| **Disk Write Bytes** | 2.7 KB | 5.01 KB | +2.31 KB | +85.84% | Informational | 鈩癸笍 INFO |
| **Write Amplification** | 11.85 x | 5.89 x | -5.96 x | -50.29% | Informational | 鈩癸笍 INFO |

## Gate Decision

### **OVERALL RESULT: FAIL 鉂?*
One or more correctness checks or performance regression thresholds failed.