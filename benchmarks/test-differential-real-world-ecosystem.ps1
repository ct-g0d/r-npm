#Requires -Version 5.1
<#
.SYNOPSIS
    Differential test suite and ecosystem benchmark runner for Real-World Ecosystem App.
.DESCRIPTION
    Validates Gate C, D, and F criteria on a production-grade full-stack fixture:
    1. Full differential install parity between npm 10.x oracle and rnpm:
       - Normalized tree match (files, hashes, structure across express, react, react-dom, chalk, lodash)
       - Lockfile v3 deterministic match (POSIX keys, integrity, version, resolved, peerDependencies)
       - Clean-slate CI install parity (npm ci vs rnpm ci)
    2. Executable .bin shims & script execution:
       - Verified .bin shims for typescript (tsc, tsserver), prettier, mock-cli-helper
       - Script execution parity: build, test, format
       - Lifecycle postinstall artifact generation
    3. Windows Job Object Benchmark Runner:
       - Process-tree instrumentation tracking:
         - Wall-clock time (ms)
         - CPU User & Kernel time (ms)
         - Peak Working Set (MB) & Commit Charge (MB)
         - Disk Read/Write Bytes & Disk Read/Write Ops (Write Amplification)
         - Total Processes spawned
       - Benchmarks pristine-cold, warm-install, and hot-noop states for both npm and rnpm
#>

[CmdletBinding()]
param(
    [string]$RegistryUrl = "http://127.0.0.1:4873",
    [string]$RnpmPath = "",
    [string]$NpmPath = "npm.cmd",
    [int]$BenchmarkTrials = 3,
    [switch]$SkipBenchmarks,
    [switch]$KeepTemp
)

$ErrorActionPreference = "Stop"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    if ($MyInvocation.MyCommand.Path) {
        $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        $ScriptDir = Join-Path (Get-Location) "benchmarks"
    }
}
$RepoRoot = Split-Path -Parent $ScriptDir
$StatsUtil = Join-Path $ScriptDir "harness-utils.js"
$FixturePath = Join-Path $ScriptDir "fixtures\real-world-ecosystem-app"

if (-not (Test-Path $FixturePath)) {
    throw "Fixture not found at '$FixturePath'."
}

if (-not $RnpmPath) {
    $relCandidate = Join-Path $RepoRoot "target\release\rnpm.exe"
    $debCandidate = Join-Path $RepoRoot "target\debug\rnpm.exe"
    if (Test-Path $relCandidate) {
        $RnpmPath = $relCandidate
    } elseif (Test-Path $debCandidate) {
        $RnpmPath = $debCandidate
    } else {
        throw "rnpm executable not found in target\release or target\debug. Run 'cargo build -p rnpm-cli' first."
    }
}

$RnpmPath = [System.IO.Path]::GetFullPath($RnpmPath)
if ($NpmPath -and (Test-Path $NpmPath)) {
    $NpmPath = [System.IO.Path]::GetFullPath($NpmPath)
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Real-World Ecosystem Differential & Benchmark Suite            " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "rnpm binary: $RnpmPath" -ForegroundColor DarkGray
Write-Host "npm binary:  $NpmPath" -ForegroundColor DarkGray
Write-Host "Registry:    $RegistryUrl" -ForegroundColor DarkGray
Write-Host "Fixture:     $FixturePath`n" -ForegroundColor DarkGray

# Ensure mock registry
$MockServerProcess = $null
function Ensure-MockRegistry {
    try {
        $health = Invoke-RestMethod -Uri "$RegistryUrl/api/health" -TimeoutSec 2 -ErrorAction Stop
        Write-Host "[mock-registry] Running (uptime: $($health.uptime)s)" -ForegroundColor Green
    } catch {
        Write-Host "[mock-registry] Starting mock server on $RegistryUrl..." -ForegroundColor Cyan
        $mockScript = Join-Path $ScriptDir "mock-registry\mock-server.js"
        $script:MockServerProcess = Start-Process node -ArgumentList "$mockScript --port 4873 --quiet" -PassThru
        Start-Sleep -Milliseconds 800
        $health = Invoke-RestMethod -Uri "$RegistryUrl/api/health" -TimeoutSec 5
        Write-Host "[mock-registry] Started successfully." -ForegroundColor Green
    }
}

Ensure-MockRegistry

# Compile Windows Job Object Tracker C# type if not already loaded
if (-not ([System.Management.Automation.PSTypeName]'EcosystemJobTracker').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class EcosystemJobTracker {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll")]
    static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll")]
    static extern bool QueryInformationJobObject(IntPtr hJob, int JobInformationClass, IntPtr lpJobInformation, uint cbJobInformationLength, out uint lpReturnLength);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
        public IO_COUNTERS BasicInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryLimit;
        public UIntPtr PeakJobMemoryLimit;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    public class BenchmarkResult {
        public int ExitCode;
        public double WallTimeMs;
        public double UserCpuMs;
        public double KernelCpuMs;
        public ulong PeakWorkingSetBytes;
        public ulong PeakCommitBytes;
        public ulong DiskReadBytes;
        public ulong DiskWriteBytes;
        public ulong DiskReadOps;
        public ulong DiskWriteOps;
        public uint TotalProcesses;
        public string StdOut;
        public string StdErr;
    }

    public static BenchmarkResult Execute(string fileName, string arguments, string workingDir) {
        IntPtr hJob = CreateJobObject(IntPtr.Zero, null);
        var result = new BenchmarkResult();
        var sw = Stopwatch.StartNew();

        var psi = new ProcessStartInfo {
            FileName = fileName,
            Arguments = arguments,
            WorkingDirectory = workingDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using (var proc = new Process { StartInfo = psi }) {
            proc.Start();
            if (hJob != IntPtr.Zero) {
                try {
                    AssignProcessToJobObject(hJob, proc.Handle);
                } catch { }
            }

            ulong peakWorkingSet = 0;
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            while (!proc.WaitForExit(15)) {
                try {
                    proc.Refresh();
                    if ((ulong)proc.WorkingSet64 > peakWorkingSet) {
                        peakWorkingSet = (ulong)proc.WorkingSet64;
                    }
                } catch { }
            }
            sw.Stop();

            result.ExitCode = proc.ExitCode;
            result.WallTimeMs = sw.Elapsed.TotalMilliseconds;
            result.StdOut = stdoutTask.Result;
            result.StdErr = stderrTask.Result;

            try {
                proc.Refresh();
                if ((ulong)proc.PeakWorkingSet64 > peakWorkingSet) {
                    peakWorkingSet = (ulong)proc.PeakWorkingSet64;
                }
            } catch { }
            result.PeakWorkingSetBytes = peakWorkingSet;
        }

        if (hJob != IntPtr.Zero) {
            int sizeExt = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr ptrExt = Marshal.AllocHGlobal(sizeExt);
            try {
                uint retLen;
                if (QueryInformationJobObject(hJob, 9, ptrExt, (uint)sizeExt, out retLen)) {
                    var ext = (JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(ptrExt, typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                    result.PeakCommitBytes = (ulong)ext.PeakJobMemoryLimit.ToUInt64();
                    if ((ulong)ext.PeakProcessMemoryLimit.ToUInt64() > result.PeakWorkingSetBytes) {
                        result.PeakWorkingSetBytes = (ulong)ext.PeakProcessMemoryLimit.ToUInt64();
                    }
                }
            } finally {
                Marshal.FreeHGlobal(ptrExt);
            }

            int sizeBasic = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION));
            IntPtr ptrBasic = Marshal.AllocHGlobal(sizeBasic);
            try {
                uint retLen;
                if (QueryInformationJobObject(hJob, 8, ptrBasic, (uint)sizeBasic, out retLen)) {
                    var basic = (JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(ptrBasic, typeof(JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION));
                    result.UserCpuMs = basic.TotalUserTime * 0.0001;
                    result.KernelCpuMs = basic.TotalKernelTime * 0.0001;
                    result.TotalProcesses = basic.TotalProcesses;
                    result.DiskReadBytes = basic.BasicInfo.ReadTransferCount;
                    result.DiskWriteBytes = basic.BasicInfo.WriteTransferCount;
                    result.DiskReadOps = basic.BasicInfo.ReadOperationCount;
                    result.DiskWriteOps = basic.BasicInfo.WriteOperationCount;
                }
            } finally {
                Marshal.FreeHGlobal(ptrBasic);
            }

            CloseHandle(hJob);
        }

        return result;
    }
}
"@
}

$TestsPassed = 0
$TestsFailed = 0

function Assert-Condition {
    param(
        [bool]$Condition,
        [string]$Message,
        [string]$Details = ""
    )

    if ($Condition) {
        Write-Host "  [PASS] $Message" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] $Message" -ForegroundColor Red
        if ($Details) {
            Write-Host "         Details: $Details" -ForegroundColor Yellow
        }
        $script:TestsFailed++
    }
}

$TempBase = Join-Path ([System.IO.Path]::GetTempPath()) ("npm-rust-ecosystem-diff-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $TempBase -Force | Out-Null
$GlobalCacheDir = Join-Path $TempBase "cache"
New-Item -ItemType Directory -Path $GlobalCacheDir -Force | Out-Null

try {
    # =========================================================================
    # Part 1: Clean-Slate Differential Parity (npm oracle vs rnpm)
    # =========================================================================
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "Part 1: Real-World Ecosystem Differential Parity (npm vs rnpm)" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow

    $npmDir = Join-Path $TempBase "npm-app"
    $rnpmDir = Join-Path $TempBase "rnpm-app"
    Copy-Item $FixturePath -Destination $npmDir -Recurse
    Copy-Item $FixturePath -Destination $rnpmDir -Recurse

    Write-Host "[1.1] Installing real-world-ecosystem-app with npm oracle..." -ForegroundColor Gray
    $npmOut = cmd.exe /c "cd /d `"$npmDir`" && $NpmPath install --registry $RegistryUrl --cache `"$GlobalCacheDir`" --no-audit --no-fund 2>&1"
    $npmCode = $LASTEXITCODE
    Assert-Condition ($npmCode -eq 0) "npm install exited with 0" "Output: $npmOut"

    Write-Host "[1.2] Installing real-world-ecosystem-app with rnpm..." -ForegroundColor Gray
    $rnpmOut = cmd.exe /c "cd /d `"$rnpmDir`" && `"$RnpmPath`" install --registry $RegistryUrl --cache `"$GlobalCacheDir`" 2>&1"
    $rnpmCode = $LASTEXITCODE
    Assert-Condition ($rnpmCode -eq 0) "rnpm install exited with 0" "Output: $rnpmOut"

    # Normalized tree comparison
    Write-Host "[1.3] Comparing normalized installed trees (npm vs rnpm)..." -ForegroundColor Gray
    $treeCmp = (node $StatsUtil compare-trees "$npmDir\node_modules" "$rnpmDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmp.match) "100% normalized tree match on real-world ecosystem app" ($treeCmp.mismatches -join "; ")

    # Lockfile v3 comparison
    Write-Host "[1.4] Comparing generated lockfile v3 deterministic match..." -ForegroundColor Gray
    $lockCmp = (node $StatsUtil compare-lockfiles "$npmDir\package-lock.json" "$rnpmDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmp.match) "100% deterministic lockfile v3 match on real-world ecosystem app" ($lockCmp.mismatches -join "; ")

    # =========================================================================
    # Part 2: Executable Bin Shims & Script Execution Parity
    # =========================================================================
    Write-Host "`n=================================================================" -ForegroundColor Yellow
    Write-Host "Part 2: Bin Shims & Script Execution Parity" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow

    # Verify .bin shims in rnpm
    $binDir = Join-Path $rnpmDir "node_modules\.bin"
    $expectedShims = @("tsc", "tsserver", "prettier", "cli-helper")
    foreach ($shim in $expectedShims) {
        $cmdPath = Join-Path $binDir "$shim.cmd"
        $ps1Path = Join-Path $binDir "$shim.ps1"
        $unixPath = Join-Path $binDir $shim
        $hasShim = (Test-Path $cmdPath) -and (Test-Path $ps1Path) -and (Test-Path $unixPath)
        Assert-Condition $hasShim "rnpm generated all shim formats (.cmd, .ps1, Unix) for '$shim'"
    }

    # Execute shims directly
    Write-Host "[2.1] Executing bin shims via cmd.exe..." -ForegroundColor Gray
    $tscOut = cmd.exe /c "`"$binDir\tsc.cmd`" --version 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0 -and $tscOut -match "Version 5\.3\.3") "tsc.cmd executed successfully ($tscOut)"

    $prettierOut = cmd.exe /c "`"$binDir\prettier.cmd`" --version 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0 -and $prettierOut -match "3\.2\.5") "prettier.cmd executed successfully ($prettierOut)"

    # Lifecycle postinstall verification
    Write-Host "[2.2] Verifying postinstall artifact generation..." -ForegroundColor Gray
    $postinstallTxt = Join-Path $rnpmDir "dist\postinstall-ok.txt"
    Assert-Condition (Test-Path $postinstallTxt) "postinstall hook created dist\postinstall-ok.txt"

    # Script execution: rnpm run build
    Write-Host "[2.3] Testing 'rnpm run build'..." -ForegroundColor Gray
    $buildOut = cmd.exe /c "cd /d `"$rnpmDir`" && `"$RnpmPath`" run build 2>&1"
    $buildCode = $LASTEXITCODE
    $manifestPath = Join-Path $rnpmDir "dist\build-manifest.json"
    Assert-Condition ($buildCode -eq 0 -and (Test-Path $manifestPath)) "'rnpm run build' succeeded and created dist\build-manifest.json"

    # Script execution: rnpm run test
    Write-Host "[2.4] Testing 'rnpm run test'..." -ForegroundColor Gray
    $testOut = cmd.exe /c "cd /d `"$rnpmDir`" && `"$RnpmPath`" run test 2>&1"
    $testCode = $LASTEXITCODE
    $testText = ($testOut -join "`n")
    Assert-Condition ($testCode -eq 0 -and $testText -match "All real-world ecosystem tests passed") "'rnpm run test' passed all package assertions" "ExitCode: $testCode, Output: $testText"

    # Script execution: rnpm run format
    Write-Host "[2.5] Testing 'rnpm run format'..." -ForegroundColor Gray
    $formatOut = cmd.exe /c "cd /d `"$rnpmDir`" && `"$RnpmPath`" run format 2>&1"
    $formatCode = $LASTEXITCODE
    $formatText = ($formatOut -join "`n")
    Assert-Condition ($formatCode -eq 0 -and $formatText -match "3\.2\.5") "'rnpm run format' invoked prettier shim from PATH" "ExitCode: $formatCode, Output: $formatText"

    # =========================================================================
    # Part 3: Clean-Slate CI Install Parity (npm ci vs rnpm ci)
    # =========================================================================
    Write-Host "`n=================================================================" -ForegroundColor Yellow
    Write-Host "Part 3: Clean-Slate CI Parity (npm ci vs rnpm ci)" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow

    Remove-Item (Join-Path $npmDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $rnpmDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "[3.1] Running npm ci..." -ForegroundColor Gray
    $npmCiOut = cmd.exe /c "cd /d `"$npmDir`" && $NpmPath ci --registry $RegistryUrl --cache `"$GlobalCacheDir`" --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm ci exited cleanly with 0"

    Write-Host "[3.2] Running rnpm ci..." -ForegroundColor Gray
    $rnpmCiOut = cmd.exe /c "cd /d `"$rnpmDir`" && `"$RnpmPath`" ci --registry $RegistryUrl --cache `"$GlobalCacheDir`" 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm ci exited cleanly with 0"

    $ciTreeCmp = (node $StatsUtil compare-trees "$npmDir\node_modules" "$rnpmDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($ciTreeCmp.match) "100% normalized tree match after clean-slate CI install" ($ciTreeCmp.mismatches -join "; ")

    # =========================================================================
    # Part 4: Windows Job Object Ecosystem Benchmark Runner
    # =========================================================================
    if (-not $SkipBenchmarks) {
        Write-Host "`n=================================================================" -ForegroundColor Yellow
        Write-Host "Part 4: Windows Job Object Benchmark Instrumentation" -ForegroundColor Yellow
        Write-Host "=================================================================" -ForegroundColor Yellow

        $scenarios = @("pristine-cold", "warm-install", "hot-noop")
        $benchmarkSummary = @()

        foreach ($scenario in $scenarios) {
            Write-Host "`n>>> Running Benchmark: $scenario ($BenchmarkTrials trials) <<<" -ForegroundColor Magenta

            # Target workspaces for benchmarking
            $benchNpmDir = Join-Path $TempBase "bench-npm-$scenario"
            $benchRnpmDir = Join-Path $TempBase "bench-rnpm-$scenario"
            Copy-Item $FixturePath -Destination $benchNpmDir -Recurse
            Copy-Item $FixturePath -Destination $benchRnpmDir -Recurse

            $npmCache = Join-Path $TempBase "cache-npm-$scenario"
            $rnpmCache = Join-Path $TempBase "cache-rnpm-$scenario"

            if ($scenario -eq "pristine-cold") {
                # Cold cache: start with fresh empty cache directory
                New-Item -ItemType Directory -Path $npmCache -Force | Out-Null
                New-Item -ItemType Directory -Path $rnpmCache -Force | Out-Null
            } else {
                # Warm states: pre-populate cache by running an initial install
                cmd.exe /c "cd /d `"$benchNpmDir`" && $NpmPath install --registry $RegistryUrl --cache `"$npmCache`" --no-audit --no-fund >nul 2>&1"
                cmd.exe /c "cd /d `"$benchRnpmDir`" && `"$RnpmPath`" install --registry $RegistryUrl --cache `"$rnpmCache`" >nul 2>&1"
            }

            $npmResults = @()
            $rnpmResults = @()

            for ($t = 1; $t -le $BenchmarkTrials; $t++) {
                if ($scenario -eq "pristine-cold" -or $scenario -eq "warm-install") {
                    # In cold & warm install, node_modules is deleted before each trial
                    Remove-Item (Join-Path $benchNpmDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item (Join-Path $benchRnpmDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue
                }

                # Benchmark npm
                $npmArgs = "/c cd /d `"$benchNpmDir`" && $NpmPath install --registry $RegistryUrl --cache `"$npmCache`" --no-audit --no-fund"
                $npmRes = [EcosystemJobTracker]::Execute("cmd.exe", $npmArgs, $benchNpmDir)
                if ($npmRes.ExitCode -eq 0) { $npmResults += $npmRes }

                # Benchmark rnpm
                $rnpmArgs = "install --registry $RegistryUrl --cache `"$rnpmCache`""
                $rnpmRes = [EcosystemJobTracker]::Execute($RnpmPath, $rnpmArgs, $benchRnpmDir)
                if ($rnpmRes.ExitCode -eq 0) { $rnpmResults += $rnpmRes }
            }

            if ($npmResults.Count -gt 0 -and $rnpmResults.Count -gt 0) {
                # Calculate medians
                $npmWallMedian = ($npmResults | Measure-Object -Property WallTimeMs -Average).Average
                $rnpmWallMedian = ($rnpmResults | Measure-Object -Property WallTimeMs -Average).Average
                $speedup = if ($rnpmWallMedian -gt 0) { [math]::Round($npmWallMedian / $rnpmWallMedian, 2) } else { 1.0 }

                $npmCpuMedian = (($npmResults | Measure-Object -Property UserCpuMs -Average).Average) + (($npmResults | Measure-Object -Property KernelCpuMs -Average).Average)
                $rnpmCpuMedian = (($rnpmResults | Measure-Object -Property UserCpuMs -Average).Average) + (($rnpmResults | Measure-Object -Property KernelCpuMs -Average).Average)

                $npmMemMedianMB = [math]::Round((($npmResults | Measure-Object -Property PeakWorkingSetBytes -Average).Average) / 1MB, 2)
                $rnpmMemMedianMB = [math]::Round((($rnpmResults | Measure-Object -Property PeakWorkingSetBytes -Average).Average) / 1MB, 2)

                $npmCommitMedianMB = [math]::Round((($npmResults | Measure-Object -Property PeakCommitBytes -Average).Average) / 1MB, 2)
                $rnpmCommitMedianMB = [math]::Round((($rnpmResults | Measure-Object -Property PeakCommitBytes -Average).Average) / 1MB, 2)

                $npmWriteMB = [math]::Round((($npmResults | Measure-Object -Property DiskWriteBytes -Average).Average) / 1MB, 2)
                $rnpmWriteMB = [math]::Round((($rnpmResults | Measure-Object -Property DiskWriteBytes -Average).Average) / 1MB, 2)

                $row = [PSCustomObject]@{
                    Scenario = $scenario
                    NpmWallMs = [math]::Round($npmWallMedian, 1)
                    RnpmWallMs = [math]::Round($rnpmWallMedian, 1)
                    Speedup = "${speedup}x"
                    NpmCpuMs = [math]::Round($npmCpuMedian, 1)
                    RnpmCpuMs = [math]::Round($rnpmCpuMedian, 1)
                    NpmPeakWorkingSetMB = $npmMemMedianMB
                    RnpmPeakWorkingSetMB = $rnpmMemMedianMB
                    NpmPeakCommitMB = $npmCommitMedianMB
                    RnpmPeakCommitMB = $rnpmCommitMedianMB
                    NpmDiskWriteMB = $npmWriteMB
                    RnpmDiskWriteMB = $rnpmWriteMB
                }
                $benchmarkSummary += $row

                Write-Host "  -> Result [$scenario]: rnpm was ${speedup}x faster (rnpm: $([math]::Round($rnpmWallMedian, 1))ms vs npm: $([math]::Round($npmWallMedian, 1))ms)" -ForegroundColor Green
                Write-Host "     Peak Working Set: rnpm ${rnpmMemMedianMB}MB vs npm ${npmMemMedianMB}MB" -ForegroundColor DarkGray
                Write-Host "     Disk Write:       rnpm ${rnpmWriteMB}MB vs npm ${npmWriteMB}MB" -ForegroundColor DarkGray
            }
        }

        # Print Structured Markdown Summary Table
        Write-Host "`n### Real-World Ecosystem Benchmark Results (Windows Job Object Instrumentation)" -ForegroundColor Cyan
        $benchmarkSummary | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White
        Assert-Condition ($benchmarkSummary.Count -eq 3) "Successfully measured all 3 cache states (pristine-cold, warm-install, hot-noop)"
    }

} finally {
    if ($MockServerProcess -and -not $MockServerProcess.HasExited) {
        try { $MockServerProcess.Kill() } catch { }
    }

    if (-not $KeepTemp -and (Test-Path $TempBase)) {
        try {
            Remove-Item -Path $TempBase -Recurse -Force -ErrorAction SilentlyContinue
        } catch { }
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Ecosystem Differential Suite Summary: $TestsPassed Passed, $TestsFailed Failed" -ForegroundColor $(if ($TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "=================================================================" -ForegroundColor Cyan

if ($TestsFailed -gt 0) {
    exit 1
}
exit 0
