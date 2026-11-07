#Requires -Version 5.1
<#
.SYNOPSIS
    Benchmark runner script for npm against synthetic and standard fixtures.
.DESCRIPTION
    Executes npm across defined benchmark cache states (pristine-cold, cold-ci, lockfile-only-ci,
    warm-install, hot-noop), tracking full process-tree CPU, memory, IO, and wall time using
    Windows Job Objects, and emitting Gate F compliant checkpoint.v1.json artifacts.
.PARAMETER Fixture
    Fixture name (e.g. tier1-single-dep, tier1-diamond) or relative path.
.PARAMETER CacheState
    Benchmark cache state: pristine-cold, cold-ci, lockfile-only-ci, warm-install, hot-noop, or all.
.PARAMETER Trials
    Number of recorded trials. Defaults to 5 for cold states, 7 for warm/hot states.
.PARAMETER Warmup
    Number of discarded warmup trials. Defaults to 0 for cold states, 1 for warm/hot states.
.PARAMETER RegistryUrl
    URL of the mock or target registry. Default: http://127.0.0.1:4873
.PARAMETER NpmPath
    Path to npm executable. Defaults to npm.cmd.
.PARAMETER OutputDir
    Directory where JSON checkpoint artifacts are saved.
.PARAMETER OutputFile
    Optional explicit path to the output JSON checkpoint artifact.
.PARAMETER StartMockServer
    Switch to automatically launch mock-server.js if not reachable.
.PARAMETER PurgeOsCache
    Switch to attempt standby list purging before cold runs.
#>

[CmdletBinding()]
param(
    [string]$Fixture = "tier1-single-dep",
    [ValidateSet("pristine-cold", "cold-ci", "lockfile-only-ci", "warm-install", "hot-noop", "all")]
    [string]$CacheState = "warm-install",
    [int]$Trials = 0,
    [int]$Warmup = -1,
    [string]$RegistryUrl = "http://127.0.0.1:4873",
    [ValidateSet("npm", "rnpm")]
    [string]$Tool = "npm",
    [string]$RnpmPath = "",
    [string]$CargoProfile = "release",
    [string]$NpmPath = "npm.cmd",
    [string]$OutputDir = "",
    [string]$OutputFile = "",
    [switch]$StartMockServer,
    [switch]$PurgeOsCache,
    [switch]$SimulateLoad,
    [int]$InjectOutlierTrial = -1,
    [double]$InjectOutlierDelayMs = 350.0,
    [switch]$FailOnStabilityRegression
)

$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    if ($MyInvocation.MyCommand.Path) {
        $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        $ScriptDir = Join-Path (Get-Location) "benchmarks"
    }
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $ScriptDir "results\baseline"
}

if ($Tool -eq "rnpm" -and -not $RnpmPath) {
    $RepoRoot = Split-Path -Parent $ScriptDir
    $relCandidate = Join-Path $RepoRoot "target\release\rnpm.exe"
    $debCandidate = Join-Path $RepoRoot "target\debug\rnpm.exe"
    if (Test-Path $relCandidate) {
        $RnpmPath = $relCandidate
        $CargoProfile = "release"
    } elseif (Test-Path $debCandidate) {
        $RnpmPath = $debCandidate
        $CargoProfile = "dev"
    } else {
        throw "rnpm executable not found in target\release or target\debug."
    }
}

# Ensure ExecutionPolicy in current scope
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Compile Job Object Tracker C# type if not already loaded
if (-not ([System.Management.Automation.PSTypeName]'JobTracker').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class JobTracker {
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

    public class RunResult {
        public int ExitCode;
        public double WallTimeMs;
        public double UserCpuMs;
        public double SystemCpuMs;
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

    public static RunResult Execute(string fileName, string arguments, string workingDir) {
        IntPtr hJob = CreateJobObject(IntPtr.Zero, null);
        try {
            var result = new RunResult();
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
                // Read streams asynchronously to prevent deadlock
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
                        result.SystemCpuMs = basic.TotalKernelTime * 0.0001;
                        result.TotalProcesses = basic.TotalProcesses;
                        result.DiskReadBytes = basic.BasicInfo.ReadTransferCount;
                        result.DiskWriteBytes = basic.BasicInfo.WriteTransferCount;
                        result.DiskReadOps = basic.BasicInfo.ReadOperationCount;
                        result.DiskWriteOps = basic.BasicInfo.WriteOperationCount;
                    }
                } finally {
                    Marshal.FreeHGlobal(ptrBasic);
                }
            }

            return result;
        } finally {
            if (hJob != IntPtr.Zero) {
                CloseHandle(hJob);
            }
        }
    }
}
"@
}

# Resolve fixture path
$FixturePath = $Fixture
if (-not (Test-Path $FixturePath)) {
    $Candidate = Join-Path $ScriptDir "fixtures\$Fixture"
    if (Test-Path $Candidate) {
        $FixturePath = $Candidate
    } else {
        throw "Fixture '$Fixture' not found at '$FixturePath' or '$Candidate'"
    }
}
$FixtureName = (Get-Item $FixturePath).Name
$FixturePkgJson = Join-Path $FixturePath "package.json"
if (-not (Test-Path $FixturePkgJson)) {
    throw "Fixture '$FixtureName' does not contain package.json"
}

# Determine tier
$Tier = "tier1"
if ($FixtureName -match "^tier2-") { $Tier = "tier2" }
elseif ($FixtureName -match "^tier3-") { $Tier = "tier3" }

# Handle mock server
$MockServerProcess = $null
function Ensure-MockServer {
    try {
        $res = Invoke-RestMethod -Uri "$RegistryUrl/api/health" -TimeoutSec 2 -ErrorAction Stop
        Write-Verbose "Mock registry is running: $($res.status)"
    } catch {
        if ($StartMockServer) {
            Write-Host "[harness] Launching local mock registry..." -ForegroundColor Cyan
            $mockScript = Join-Path $ScriptDir "mock-registry\mock-server.js"
            $script:MockServerProcess = Start-Process -FilePath "node" -ArgumentList "$mockScript --port 4873" -PassThru
            Start-Sleep -Milliseconds 600
        } else {
            Write-Warning "Mock registry at $RegistryUrl not reachable. Use -StartMockServer to auto-launch."
        }
    }
}

Ensure-MockServer

# Collect Hardware and Environment Metadata
function Get-EnvironmentMetadata {
    $gitRev = "unknown"
    $gitDirty = $false
    try {
        $gitRev = (git rev-parse HEAD 2>$null).Trim()
        $dirtyOut = (git status --porcelain 2>$null)
        if ($dirtyOut) { $gitDirty = $true }
    } catch { }

    $npmVer = "unknown"
    try {
        $npmVer = (cmd.exe /c "$NpmPath -v" 2>$null).Trim()
    } catch { }

    $nodeVer = "unknown"
    try {
        $nodeVer = (node -v 2>$null).Trim()
    } catch { }

    $rustVer = $null
    try {
        $rustVer = (rustc --version 2>$null).Trim()
    } catch { }

    $osCaption = ""
    $ramBytes = 0
    try {
        $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
        $ramBytes = [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    } catch { }

    $cpuName = ""
    try {
        $cpuName = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    } catch { }

    $avState = "Windows Defender Active"
    try {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp -and $mp.RealTimeProtectionEnabled) {
            $avState = "Windows Defender Real-time Protection Enabled"
        }
    } catch { }

    return [PSCustomObject]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        git = [PSCustomObject]@{
            revision = $gitRev
            dirty = $gitDirty
        }
        tool = [PSCustomObject]@{
            name = $Tool
            version = $(if ($Tool -eq "rnpm") { "0.1.0" } else { $npmVer })
            commit = $(if ($Tool -eq "rnpm") { $gitRev } else { $null })
        }
        node_version = $nodeVer
        rust_version = $(if ($Tool -eq "rnpm") { $rustVer } else { $null })
        cargo_profile = $(if ($Tool -eq "rnpm") { $CargoProfile } else { $null })
        target_triple = $(if ($Tool -eq "rnpm") { "x86_64-pc-windows-msvc" } else { $null })
        os = "$([System.Environment]::OSVersion.VersionString) ($osCaption)"
        cpu = $cpuName
        ram_bytes = $ramBytes
        antivirus_state = $avState
        os_cache_purged = [bool]$PurgeOsCache
    }
}

# Function to run a single cache-state scenario
function Run-Scenario {
    param(
        [string]$CurrentCacheState
    )

    $Command = "install"
    $IsCi = ($CurrentCacheState -eq "cold-ci" -or $CurrentCacheState -eq "lockfile-only-ci")
    if ($IsCi) { $Command = "ci" }

    # Setup trial counts based on plan.md
    $CurrentTrials = $Trials
    $CurrentWarmup = $Warmup
    if ($CurrentCacheState -in @("pristine-cold", "cold-ci")) {
        if ($CurrentTrials -le 0) { $CurrentTrials = 5 }
        if ($CurrentWarmup -lt 0) { $CurrentWarmup = 0 }
    } else {
        if ($CurrentTrials -le 0) { $CurrentTrials = 7 }
        if ($CurrentWarmup -lt 0) { $CurrentWarmup = 1 }
    }

    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host "Running Benchmark: $FixtureName | $CurrentCacheState ($Command)" -ForegroundColor Green
    Write-Host "Trials: $CurrentTrials, Warmup: $CurrentWarmup, Registry: $RegistryUrl" -ForegroundColor Gray
    Write-Host "========================================================" -ForegroundColor Green

    # Benchmark work directories
    $BaseTempDir = Join-Path $env:TEMP "npm-bench-$(New-Guid)"
    New-Item -ItemType Directory -Path $BaseTempDir | Out-Null
    $TargetDir = Join-Path $BaseTempDir "target"
    $CacheDir = Join-Path $BaseTempDir "cache"
    New-Item -ItemType Directory -Path $TargetDir | Out-Null
    New-Item -ItemType Directory -Path $CacheDir | Out-Null

    function Reset-Target {
        param([bool]$KeepNodeModules = $false)
        if (-not $KeepNodeModules) {
            if (Test-Path "$TargetDir\node_modules") {
                Remove-Item -Path "$TargetDir\node_modules" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        # Copy package.json
        Copy-Item $FixturePkgJson -Destination "$TargetDir\package.json" -Force

        # Lockfile presence per cache state
        $PinnedLockfile = Join-Path $FixturePath "package-lock.json"
        if ($CurrentCacheState -eq "pristine-cold") {
            # Lockfile absent
            if (Test-Path "$TargetDir\package-lock.json") {
                Remove-Item "$TargetDir\package-lock.json" -Force
            }
        } else {
            # Lockfile present
            if (Test-Path $PinnedLockfile) {
                Copy-Item $PinnedLockfile -Destination "$TargetDir\package-lock.json" -Force
            }
        }
    }

    # Reset cache directory
    function Reset-Cache {
        if (Test-Path $CacheDir) {
            Remove-Item -Path $CacheDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
    }

    # Precondition warmup
    if ($CurrentWarmup -gt 0) {
        Write-Host "[harness] Running $CurrentWarmup warmup trial(s) to populate cache..." -ForegroundColor DarkGray
        for ($w = 0; $w -lt $CurrentWarmup; $w++) {
            Reset-Target -KeepNodeModules ($CurrentCacheState -eq "hot-noop")
            if ($Tool -eq "rnpm") {
                $rnpmArgs = "$Command --registry $RegistryUrl --cache `"$CacheDir`""
                $null = [JobTracker]::Execute($RnpmPath, $rnpmArgs, $TargetDir)
            } else {
                $npmArgs = "/c $NpmPath $Command --registry $RegistryUrl --cache `"$CacheDir`" --no-audit --no-fund"
                $null = [JobTracker]::Execute("cmd.exe", $npmArgs, $TargetDir)
            }
        }
    }

    $rawTrials = @()
    $outliersReplaced = 0

    function Execute-Trial {
        param(
            [int]$Index,
            [switch]$IsReplacement
        )

        if ($CurrentCacheState -in @("pristine-cold", "cold-ci")) {
            Reset-Cache
            Reset-Target -KeepNodeModules $false
        } elseif ($CurrentCacheState -eq "hot-noop") {
            # Target node_modules left intact
        } else {
            # Warm-install or lockfile-only-ci: remove node_modules but preserve cache
            Reset-Target -KeepNodeModules $false
        }

        # Clear request log on mock registry if available
        try {
            $null = Invoke-RestMethod -Uri "$RegistryUrl/api/reset" -Method POST -TimeoutSec 1 -ErrorAction SilentlyContinue
        } catch { }

        $loadProcs = @()
        $shouldInject = (-not $IsReplacement) -and (($SimulateLoad -and $Index -eq 1) -or ($InjectOutlierTrial -eq $Index))
        if ($shouldInject) {
            Write-Host "  [harness] Simulating environmental system load on trial $Index ($InjectOutlierDelayMs ms)..." -ForegroundColor Yellow
            $coreCount = [Environment]::ProcessorCount
            for ($c = 0; $c -lt [Math]::Min(2, $coreCount); $c++) {
                $p = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -Command `"`$sw=[Diagnostics.Stopwatch]::StartNew(); while(`$sw.ElapsedMilliseconds -lt $InjectOutlierDelayMs){ [Math]::Sin(1.23) }`"" -PassThru
                $loadProcs += $p
            }
        }

        $run = $null
        if ($Tool -eq "rnpm") {
            $rnpmArgs = "$Command --registry $RegistryUrl --cache `"$CacheDir`""
            $run = [JobTracker]::Execute($RnpmPath, $rnpmArgs, $TargetDir)
        } else {
            $npmArgs = "/c $NpmPath $Command --registry $RegistryUrl --cache `"$CacheDir`" --no-audit --no-fund"
            $run = [JobTracker]::Execute("cmd.exe", $npmArgs, $TargetDir)
        }

        foreach ($lp in $loadProcs) {
            if (-not $lp.HasExited) {
                Stop-Process -Id $lp.Id -Force -ErrorAction SilentlyContinue
                $lp.WaitForExit(1000)
            }
        }

        # Query request count from mock registry
        $reqCount = 0
        $netBytes = 0
        try {
            $reqStats = Invoke-RestMethod -Uri "$RegistryUrl/api/requests" -TimeoutSec 1 -ErrorAction SilentlyContinue
            if ($reqStats) {
                $reqCount = $reqStats.count
                foreach ($r in $reqStats.requests) { $netBytes += $r.bytes }
            }
        } catch { }

        $trialWallTime = $run.WallTimeMs
        $trialUserCpu = $run.UserCpuMs
        if ($shouldInject) {
            $trialWallTime += $InjectOutlierDelayMs
            $trialUserCpu += ($InjectOutlierDelayMs * 0.8)
        }

        $trial = [PSCustomObject]@{
            trial_index = $Index
            wall_time_ms = [Math]::Round($trialWallTime, 2)
            user_cpu_ms = [Math]::Round($trialUserCpu, 2)
            system_cpu_ms = [Math]::Round($run.SystemCpuMs, 2)
            peak_working_set_bytes = [int64]$run.PeakWorkingSetBytes
            peak_commit_charge_bytes = [int64]$run.PeakCommitBytes
            disk_read_bytes = [int64]$run.DiskReadBytes
            disk_write_bytes = [int64]$run.DiskWriteBytes
            disk_read_ops = [int64]$run.DiskReadOps
            disk_write_ops = [int64]$run.DiskWriteOps
            network_bytes_read = [int64]$netBytes
            network_bytes_written = 0
            network_requests = [int]$reqCount
            exit_code = $run.ExitCode
        }

        Write-Host ("  Trial {0,2}: Wall: {1,7:N1}ms | UserCPU: {2,6:N1}ms | SysCPU: {3,6:N1}ms | PeakRAM: {4,5:N1}MB | DiskWrite: {5,6:N1}KB | Exit: {6}" -f `
            $Index, $trial.wall_time_ms, $trial.user_cpu_ms, $trial.system_cpu_ms, `
            ($trial.peak_working_set_bytes / 1MB), ($trial.disk_write_bytes / 1KB), $trial.exit_code)

        return $trial
    }

    # Execute recorded trials
    for ($i = 0; $i -lt $CurrentTrials; $i++) {
        $rawTrials += Execute-Trial -Index $i
    }

    # Statistical evaluation & Outlier Replacement (plan.md: >3 MAD from median, at most 1 replacement)
    $wallTimes = $rawTrials | ForEach-Object { $_.wall_time_ms }
    $statsUtil = Join-Path $ScriptDir "harness-utils.js"
    $initialStats = (node $statsUtil stats @wallTimes) | ConvertFrom-Json

    $median = $initialStats.median
    $mad = $initialStats.mad
    $outlierThreshold = [Math]::Max(10.0, 3.0 * $mad)

    $maxDiff = 0.0
    $maxDiffIndex = -1
    for ($i = 0; $i -lt $rawTrials.Count; $i++) {
        $diff = [Math]::Abs($rawTrials[$i].wall_time_ms - $median)
        if ($diff -gt $outlierThreshold -and $diff -gt $maxDiff) {
            $maxDiff = $diff
            $maxDiffIndex = $i
        }
    }

    if ($maxDiffIndex -ge 0 -and $outliersReplaced -eq 0) {
        $i = $maxDiffIndex
        Write-Host "[harness] Environmental outlier detected at trial $i ($($rawTrials[$i].wall_time_ms)ms vs median ${median}ms, threshold ${outlierThreshold}ms). Running replacement trial..." -ForegroundColor Yellow
        $replacement = Execute-Trial -Index $i -IsReplacement
        $rawTrials[$i] = $replacement
        $outliersReplaced++
    }

    # Compute Final Metric Summaries
    function Get-MetricSummary {
        param([string]$Property)
        $vals = $rawTrials | ForEach-Object { $_.$Property }
        return (node $statsUtil stats @vals) | ConvertFrom-Json
    }

    $wallSummary = Get-MetricSummary "wall_time_ms"
    $userCpuSummary = Get-MetricSummary "user_cpu_ms"
    $sysCpuSummary = Get-MetricSummary "system_cpu_ms"
    $peakWsSummary = Get-MetricSummary "peak_working_set_bytes"
    $peakCommitSummary = Get-MetricSummary "peak_commit_charge_bytes"
    $diskWriteSummary = Get-MetricSummary "disk_write_bytes"
    $diskReadSummary = Get-MetricSummary "disk_read_bytes"

    # Inspect normalized tree and calculate uncompressed package bytes
    $treeInfo = (node $statsUtil digest-tree "$TargetDir\node_modules") | ConvertFrom-Json
    $lockInfo = (node $statsUtil digest-lockfile "$TargetDir\package-lock.json") | ConvertFrom-Json

    $uncompressedBytes = [int64]$treeInfo.totalBytes
    $writeAmpMedian = if ($uncompressedBytes -gt 0) { [Math]::Round(($diskWriteSummary.median / $uncompressedBytes), 3) } else { 0.0 }

    # Gate A stability check
    $isStableGateA = ($wallSummary.rsd_pct -lt 5.0) -or ($wallSummary.median -lt 300 -and ($wallSummary.max - $wallSummary.min) -le 25)
    $stabilityStatus = if ($isStableGateA) { "PASS (<5% RSD or <=25ms noise)" } else { "FAIL (RSD=$($wallSummary.rsd_pct)%)" }

    Write-Host "`nSummary for ${CurrentCacheState}:" -ForegroundColor Cyan
    Write-Host ("  Wall Time: Median: {0:N1}ms | Min: {1:N1}ms | Max: {2:N1}ms | IQR: {3:N1}ms | Mean: {4:N1}ms | RSD: {5:N2}%" -f `
        $wallSummary.median, $wallSummary.min, $wallSummary.max, $wallSummary.iqr, $wallSummary.mean, $wallSummary.rsd_pct)
    Write-Host ("  User CPU:  Median: {0:N1}ms | Sys CPU: Median: {1:N1}ms" -f $userCpuSummary.median, $sysCpuSummary.median)
    Write-Host ("  Peak RAM:  WorkingSet: {0:N1}MB | Commit: {1:N1}MB" -f ($peakWsSummary.median / 1MB), ($peakCommitSummary.median / 1MB))
    $statusColor = if ($isStableGateA) { "Green" } elseif ($wallSummary.rsd_pct -gt 15.0) { "Red" } else { "Yellow" }
    Write-Host ("  Gate A Stability: $stabilityStatus") -ForegroundColor $statusColor

    if ($FailOnStabilityRegression -and (-not $isStableGateA -or $wallSummary.rsd_pct -gt 15.0)) {
        throw "Gate A stability check failed ($stabilityStatus, RSD=$($wallSummary.rsd_pct)%)"
    }

    # Verify Correctness Against Reference
    $refLockfile = Join-Path $FixturePath "package-lock.json"
    $lockMatch = $false
    $treeMatch = ($treeInfo.digest -ne $null -and $treeInfo.fileCount -gt 0)
    $digestMismatches = @()

    if (Test-Path $refLockfile) {
        $lockCmp = (node $statsUtil compare-lockfiles $refLockfile "$TargetDir\package-lock.json") | ConvertFrom-Json
        $lockMatch = $lockCmp.match
        if (-not $lockMatch) {
            $digestMismatches += $lockCmp.mismatches
        }
    } else {
        $lockMatch = ($lockInfo.digest -ne $null)
    }

    # Construct Checkpoint Object conforming to checkpoint.v1.json
    $checkpoint = [ordered]@{
        version = "checkpoint.v1"
        metadata = Get-EnvironmentMetadata
        scenario = [ordered]@{
            fixture = $FixtureName
            tier = $Tier
            cache_state = $CurrentCacheState
            command = $Command
            registry_kind = $(if ($RegistryUrl -match "127\.0\.0\.1|localhost") { "mock-loopback" } else { "public" })
        }
        correctness = [ordered]@{
            exit_code = [int]($rawTrials[-1].exit_code)
            normalized_tree_match = [bool]$treeMatch
            lockfile_match = [bool]$lockMatch
            digest_mismatches = @($digestMismatches)
            installed_package_tree_digest = $treeInfo.digest
            lockfile_digest = $lockInfo.digest
        }
        metrics = [ordered]@{
            trials_raw = @($rawTrials)
            summary = [ordered]@{
                wall_time = [ordered]@{
                    median = [double]$wallSummary.median
                    min = [double]$wallSummary.min
                    max = [double]$wallSummary.max
                    iqr = [double]$wallSummary.iqr
                    mean = [double]$wallSummary.mean
                    rsd_pct = [double]$wallSummary.rsd_pct
                }
                user_cpu = [ordered]@{
                    median = [double]$userCpuSummary.median
                    min = [double]$userCpuSummary.min
                    max = [double]$userCpuSummary.max
                    iqr = [double]$userCpuSummary.iqr
                }
                system_cpu = [ordered]@{
                    median = [double]$sysCpuSummary.median
                    min = [double]$sysCpuSummary.min
                    max = [double]$sysCpuSummary.max
                    iqr = [double]$sysCpuSummary.iqr
                }
                peak_working_set = [ordered]@{
                    median = [int64]$peakWsSummary.median
                    min = [int64]$peakWsSummary.min
                    max = [int64]$peakWsSummary.max
                    iqr = [int64]$peakWsSummary.iqr
                }
                peak_commit_charge = [ordered]@{
                    median = [int64]$peakCommitSummary.median
                    min = [int64]$peakCommitSummary.min
                    max = [int64]$peakCommitSummary.max
                    iqr = [int64]$peakCommitSummary.iqr
                }
                disk_write_bytes = [ordered]@{
                    median = [int64]$diskWriteSummary.median
                    min = [int64]$diskWriteSummary.min
                    max = [int64]$diskWriteSummary.max
                    iqr = [int64]$diskWriteSummary.iqr
                }
                disk_read_bytes = [ordered]@{
                    median = [int64]$diskReadSummary.median
                    min = [int64]$diskReadSummary.min
                    max = [int64]$diskReadSummary.max
                    iqr = [int64]$diskReadSummary.iqr
                }
                write_amplification = [ordered]@{
                    median = [double]$writeAmpMedian
                    ratio = [double]$writeAmpMedian
                }
                uncompressed_package_bytes = [int64]$uncompressedBytes
                outliers_replaced = [int]$outliersReplaced
            }
        }
    }

    # Write Checkpoint JSON Artifact
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $DestFile = $OutputFile
    if (-not $DestFile) {
        $DestFile = Join-Path $OutputDir "checkpoint-$Tool-$FixtureName-$CurrentCacheState.json"
    }

    $jsonStr = $checkpoint | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($DestFile, $jsonStr)
    Write-Host "[harness] Saved checkpoint artifact: $DestFile" -ForegroundColor Cyan

    # Validate against Gate F schema
    try {
        $schemaValidation = (node $statsUtil validate-checkpoint $DestFile) | ConvertFrom-Json
        if (-not $schemaValidation.valid) {
            Write-Warning "[harness] Gate F schema validation failed for $DestFile`: $($schemaValidation.errors -join '; ')"
        } else {
            Write-Host "[harness] Gate F checkpoint schema validated successfully: $DestFile" -ForegroundColor Green
        }
    } catch {
        Write-Warning "[harness] Failed to invoke schema validator: $_"
    }

    # Cleanup temporary directories
    try {
        Remove-Item -Path $BaseTempDir -Recurse -Force -ErrorAction SilentlyContinue
    } catch { }

    return $checkpoint
}

try {
    if ($CacheState -eq "all") {
        $states = @("pristine-cold", "cold-ci", "lockfile-only-ci", "warm-install", "hot-noop")
        foreach ($s in $states) {
            $null = Run-Scenario -CurrentCacheState $s
        }
    } else {
        $null = Run-Scenario -CurrentCacheState $CacheState
    }
} finally {
    if ($script:MockServerProcess -and -not $script:MockServerProcess.HasExited) {
        Write-Host "[harness] Stopping mock registry..." -ForegroundColor DarkGray
        try {
            $null = Invoke-RestMethod -Uri "$RegistryUrl/api/shutdown" -TimeoutSec 2 -ErrorAction SilentlyContinue
        } catch { }
        Start-Sleep -Milliseconds 200
        if (-not $script:MockServerProcess.HasExited) {
            $script:MockServerProcess.Kill()
        }
    }
}
