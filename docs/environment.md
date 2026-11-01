# Environment & Baseline Machine Inventory

## Overview

This document establishes the hardware, operating system, filesystem semantics, toolchain runtime versions, and benchmark measurement parameters for the `npm-rust` (`rnpm`) project on the reference development and benchmarking host.

All quantitative gates (Gate A through Gate F) defined in [plan.md](file:///D:/npm-rust/plan.md) require reproducible measurements against this documented environment.

---

## 1. Operating System & Kernel

| Parameter | Specification | Verification / Source |
|---|---|---|
| **OS Name** | Microsoft Windows 11 Pro | `Win32_OperatingSystem.Caption` |
| **OS Version** | Windows 11 (24H2 / Developer Preview) | `Win32_OperatingSystem.Version` |
| **OS Build** | 26300 | `Win32_OperatingSystem.BuildNumber` |
| **Architecture** | x86_64 (`win32-x64`) | `[System.Environment]::Is64BitOperatingSystem` |
| **Kernel Type** | Windows NT 10.0 | System native |
| **Code Page / Locale** | CP65001 (UTF-8), en-US / zh-CN | `chcp`, `Get-Culture` |
| **Developer Mode** | Disabled / Non-Admin standard user | Reparse point tests require unprivileged junctions |

### OS-Specific Execution Characteristics
- **Process Creation Overhead:** Process spawning on Windows NT involves `CreateProcessW` / `NtCreateUserProcess`, which carries higher latency (~5–20 ms per process) compared to Unix `fork`/`clone`. Lifecycle scripts must account for process-tree invocation overhead.
- **Antivirus / Filter Drivers:** Windows Defender (`MsMpEng.exe`) and filesystem minifilter drivers actively monitor file creation, deletion, and file renaming. This introduces transient `ERROR_SHARING_VIOLATION` (32) and `ERROR_ACCESS_DENIED` (5) locks, mapping to POSIX `EBUSY` and `EPERM`.
- **Timer Resolution:** Default system timer interrupt frequency is 15.6 ms. Performance benchmarks use high-resolution performance counters (`QueryPerformanceCounter` / `std::time::Instant`).

---

## 2. Processor (CPU)

| Parameter | Specification | Details |
|---|---|---|
| **CPU Model** | Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz | 8th Generation Coffee Lake |
| **Base Clock Frequency** | 2.20 GHz | Nominal base clock |
| **Max Turbo Frequency** | 4.10 GHz | Single core peak |
| **Physical Cores** | 6 | `Win32_Processor.NumberOfCores` |
| **Logical Processors** | 12 | 2 threads per core (Hyper-Threading enabled) |
| **L1 Cache** | 384 KB (6 x 32 KB instruction, 6 x 32 KB data) | Low latency core-local |
| **L2 Cache** | 1.5 MB (6 x 256 KB) | Unified per-core |
| **L3 Cache** | 9 MB | Intel Smart Cache shared across cores |
| **Instruction Set Extensions** | x86-64, MMX, SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2, AVX, AVX2, FMA3, AES-NI | Supported hardware acceleration |

---

## 3. Memory (RAM)

| Parameter | Specification | Details |
|---|---|---|
| **Total Physical RAM** | 32 GB (34,359,738,368 bytes) | Dual-channel DDR4 @ 2666 MHz |
| **Available / Free RAM** | ~11 GB free (~11,811,160,064 bytes) | Dynamic depending on ambient load |
| **Pagefile / Virtual Memory** | Managed by Windows (~36 GB total commit limit) | Commit charge tracked via Job Object |
| **Memory Allocation Model** | Windows VirtualAlloc / HeapAlloc | Standard Windows allocator (`mimalloc` candidate for `rnpm`) |

### Memory Gate Guidelines
- Benchmarks must monitor `PeakWorkingSetSize` and `PeakPagefileUsage` (Commit Charge) via Windows Job Objects.
- Memory regressions greater than 10% on Tier 1 benchmarks trigger an automated failure flag.

---

## 4. Storage & Filesystem

| Parameter | Specification | Details |
|---|---|---|
| **Benchmarking Volume** | `D:\` | Dedicated fast workspace partition |
| **Filesystem Type** | NTFS | Full transactional journaling, USN journal enabled |
| **Sector Size** | 4096 bytes (4 KB cluster size) | Allocation unit size |
| **Volume Total Capacity** | ~931.5 GB | Total volume space |
| **Volume Free Space** | 644 GB free (~691,484,098,560 bytes) | Ample headroom for heavy disk I/O benchmarks |
| **Path Limit** | `MAX_PATH` (260 chars) legacy default | Extended path prefix `\\?\` mandatory for deep `node_modules` |
| **Case Sensitivity** | Case-insensitive, Case-preserving | Windows default NTFS behavior |
| **Short Filenames (8.3)** | Stripped / Ignored | All operations rely on long filenames |
| **Directory Links** | NTFS Junctions (`IO_REPARSE_TAG_MOUNT_POINT`) | Non-admin symlink alternative for `file:` and workspaces |

### Filesystem Safety & IO Isolation
- **Write Amplification Target:** Total bytes written divided by uncompressed installed package bytes must be tracked.
- **Atomic Operations:** Renaming a file/directory on NTFS is atomic within the same volume (`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`), but fails with `ERROR_PATH_NOT_FOUND` or `ERROR_ACCESS_DENIED` across volume boundaries. All cache staging and scratch directories must share the target filesystem drive.

---

## 5. Toolchains & Runtimes

| Tool | Version | Release Date / Commit | Target Triple / Architecture |
|---|---|---|---|
| **Rust Compiler (`rustc`)** | `1.99.1` | `58cf8f9c3 2026-10-13` | `x86_64-pc-windows-msvc` |
| **Cargo Package Manager** | `1.99.1` | `2026-10-13` | `x86_64-pc-windows-msvc` |
| **Rust Edition** | `2024` | Stable default | Profile: `dev` (debug) / `release` (LTO, strip) |
| **Node.js** | `v24.21.0` | Node.js v24 Current | V8 13.x, `win32-x64` |
| **npm** | `11.19.0` | Bundled with Node v24.21.0 | Ground-truth behavioral oracle |

### Environment Path Setup
- Node.js executable location: `C:\Program Files\nodejs\node.exe`
- npm CLI location: `C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js`
- Rust / Cargo binaries: `%USERPROFILE%\.cargo\bin\rustc.exe`, `%USERPROFILE%\.cargo\bin\cargo.exe`

---

## 6. Shells & Script Execution Runtimes

| Shell | Executable | Version / Flags | Usage in npm / rnpm |
|---|---|---|---|
| **Command Prompt** | `C:\Windows\System32\cmd.exe` | 10.0.26300 | Mandatory runner for lifecycle scripts on Windows (`cmd.exe /d /s /c`) |
| **Windows PowerShell** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | 5.1.26300 (ExecutionPolicy: Restricted) | Used by `.ps1` command shims in `node_modules/.bin` |
| **PowerShell Core (Optional)** | `pwsh.exe` | 7.x | Alternative script host |
| **POSIX Emulation** | `sh.exe` / `bash.exe` (Git for Windows) | Git Bash / MSYS2 | Validates Unix shims and CRLF shebang handling on Windows |

### Windows Script Execution Policy Notice
In default Windows configurations, `.ps1` execution is restricted by PowerShell ExecutionPolicy. The package manager creates `.cmd` batch wrappers alongside `.ps1` scripts so execution succeeds seamlessly under standard `cmd.exe` without administrative permission escalation.

---

## 7. Network & Registry Configuration

| Layer | Configuration | Address / Parameters | Notes |
|---|---|---|---|
| **Local Benchmark Registry** | Loopback Mock Registry | `http://127.0.0.1:4873/` | Pinned tarballs, immutable local cache, zero network jitter |
| **Loopback Latency** | TCP Loopback | < 0.2 ms RTT | Eliminates ISP variance for performance gates |
| **Public Reference Registry** | npmjs Upstream | `https://registry.npmjs.org/` | Used strictly for functional smoke tests and corpus validation |
| **External Latency** | HTTPS WAN | ~30–120 ms RTT | Excluded from repeatable performance benchmarks |
| **Proxy / VPN** | None / Direct connection | Direct TCP/IP socket | Ensures unhindered loopback communication |
| **TLS Implementation** | `rustls` (v0.23+) / `ring` | TLS 1.3 / 1.2 | High-throughput async HTTPS client |

---

## 8. Process Accounting & Measurement Instrumentation

To comply with **DEC-003** in [plan.md](file:///D:/npm-rust/plan.md), benchmarking and telemetry on Windows must use OS-level kernel accounting rather than application log estimates.

### Windows Job Object Collector
Every invocation of `npm` or `rnpm` (including all spawned child processes, native build tools like `node-gyp`, compiler invocations `cl.exe`, and shell scripts) is assigned to a dedicated Windows Job Object (`CreateJobObjectW`).

Tracked Metrics via `QueryInformationJobObject`:
1. **User Time (`UserTime`):** 100-nanosecond intervals spent executing in user mode across the entire process tree.
2. **Kernel Time (`KernelTime`):** 100-nanosecond intervals spent executing in kernel mode (syscalls, I/O, paging).
3. **Peak Working Set (`PeakWorkingSetSize`):** Maximum physical RAM occupied simultaneously by the process tree.
4. **Peak Commit Charge (`PeakPagefileUsage`):** Total virtual memory allocated and committed by all tree processes.
5. **Read / Write Operations (`ReadOperationCount`, `WriteOperationCount`):** Count of OS-level I/O requests.
6. **I/O Transfer Bytes (`ReadTransferCount`, `WriteTransferCount`):** Actual bytes transferred to/from disk and pipes.
7. **Process Termination:** When the benchmark terminates or cancels, closing the Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` ensures no orphaned background child processes remain active.

### OS Standby Cache Purging
- When unprivileged runners cannot purge the Windows OS Standby cache (which requires `SeIncreaseQuotaPrivilege` / Administrator rights), the harness uses a documented disk-churn fallback or isolates trials to fresh temporary directories on `D:\`, recording `os_cache_purged: false` in the checkpoint artifact.
