#Requires -Version 5.1
<#
.SYNOPSIS
    Multi-Process Cache Contention & Stress Test for rnpm.
.DESCRIPTION
    Concurrently launches 8-16 parallel rnpm operations against the same shared cache directory:
    - Parallel installs competing for identical tarballs and content-addressable blobs
    - Interleaved concurrent cache verify operations during active downloads and extraction
    - Validates ZERO corruption (verified via rnpm cache verify report)
    - Validates ZERO deadlocks (watchdog timer enforcement)
    - Validates cross-process file lock serialization (fs4 exclusive locks released cleanly)
#>

[CmdletBinding()]
param(
    [int]$Workers = 16,
    [string]$RegistryUrl = "http://127.0.0.1:4873",
    [string]$RnpmPath = "",
    [string]$CacheDir = "",
    [int]$TimeoutSeconds = 90,
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

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Multi-Process Cache Contention & Stress Suite ($Workers Workers) " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Binary:   $RnpmPath" -ForegroundColor DarkGray
Write-Host "Registry: $RegistryUrl" -ForegroundColor DarkGray

# Ensure Mock Registry
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

# Prepare isolated test scratchpad
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rnpm-stress-contention-$([System.Guid]::NewGuid().ToString('N').Substring(0, 8))"
if (-not $CacheDir) {
    $CacheDir = Join-Path $TempRoot "shared-cache"
}
New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null

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

try {
    Write-Host "`n[Step 1] Initializing $Workers isolated worker project workspaces..." -ForegroundColor Yellow

    # Predefined packages available in mock-registry for realistic contention
    $PackageProfiles = @(
        @("express"),
        @("react", "react-dom"),
        @("chalk", "supports-color"),
        @("lodash"),
        @("commander"),
        @("bytes", "raw-body"),
        @("marked"),
        @("express"),                       # Duplicate intentionally for maximum lock contention
        @("chalk", "ansi-styles"),          # Overlapping chalk suite
        @("react"),                         # Duplicate react
        @("cookie-parser", "cors"),
        @("typescript"),
        @("prettier"),
        @("express", "cors"),               # Duplicate express + cors
        @("lodash", "chalk"),               # Duplicate multi-dep
        @("body-parser", "bytes")           # Shared sub-deps
    )

    $WorkerProjects = @()
    for ($i = 0; $i -lt $Workers; $i++) {
        $workerDir = Join-Path $TempRoot "worker-$($i.ToString('00'))"
        New-Item -ItemType Directory -Path $workerDir -Force | Out-Null

        $deps = $PackageProfiles[$i % $PackageProfiles.Count]
        $depObj = @{}
        foreach ($d in $deps) {
            $depObj[$d] = "*"
        }

        $pkgJson = @{
            name = "stress-worker-$($i.ToString('00'))"
            version = "1.0.0"
            private = $true
            dependencies = $depObj
        } | ConvertTo-Json -Depth 5

        Set-Content -Path (Join-Path $workerDir "package.json") -Value $pkgJson -Encoding UTF8
        $WorkerProjects += [PSCustomObject]@{
            Id = $i
            Directory = $workerDir
            Dependencies = $deps
        }
    }

    Write-Host "[Step 2] Concurrently dispatching $Workers parallel operations against shared cache..." -ForegroundColor Yellow
    $startTime = [System.Diagnostics.Stopwatch]::StartNew()

    $ProcessList = @()
    for ($i = 0; $i -lt $Workers; $i++) {
        $wp = $WorkerProjects[$i]
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $RnpmPath
        $psi.WorkingDirectory = $wp.Directory
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        # Workers 0..13 run install; workers 14..15 run cache verify concurrently
        if ($i -ge 14) {
            $psi.Arguments = "cache verify --cache `"$CacheDir`""
        } else {
            $psi.Arguments = "install --cache `"$CacheDir`" --registry `"$RegistryUrl`" --ignore-scripts"
        }

        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        $null = $p.Start()

        $ProcessList += [PSCustomObject]@{
            Id = $i
            Process = $p
            WorkDir = $wp.Directory
            Type = $(if ($i -ge 14) { "verify" } else { "install" })
            ExpectedDeps = $wp.Dependencies
        }
    }

    Write-Host "[Step 3] Monitoring for deadlocks with ${TimeoutSeconds}s watchdog..." -ForegroundColor Yellow
    $watchdogStart = [System.DateTime]::UtcNow
    $deadlockDetected = $false

    while ($true) {
        $running = $ProcessList | Where-Object { -not $_.Process.HasExited }
        if (-not $running -or $running.Count -eq 0) {
            break
        }

        $elapsedSec = ([System.DateTime]::UtcNow - $watchdogStart).TotalSeconds
        if ($elapsedSec -gt $TimeoutSeconds) {
            $deadlockDetected = $true
            Write-Host "  [DEADLOCK DETECTED] $($running.Count) processes still hung after ${TimeoutSeconds}s!" -ForegroundColor Red
            foreach ($r in $running) {
                Write-Host "    Hanging worker $($r.Id) (PID $($r.Process.Id))" -ForegroundColor Yellow
                try { $r.Process.Kill() } catch { }
            }
            break
        }
        Start-Sleep -Milliseconds 250
    }

    $startTime.Stop()
    Write-Host "All processes completed in $([math]::Round($startTime.Elapsed.TotalMilliseconds, 1)) ms." -ForegroundColor DarkGray

    # Validate Deadlock Free
    Assert-Condition (-not $deadlockDetected) "Zero deadlocks observed under high concurrency"

    # Validate Exit Codes and capture output
    $failedExits = 0
    foreach ($entry in $ProcessList) {
        $proc = $entry.Process
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        
        if ($proc.ExitCode -ne 0) {
            $failedExits++
            Write-Host "  Worker $($entry.Id) ($($entry.Type)) failed with exit code $($proc.ExitCode)" -ForegroundColor Red
            if ($stderr) { Write-Host "    StdErr: $stderr" -ForegroundColor Yellow }
            if ($stdout) { Write-Host "    StdOut: $stdout" -ForegroundColor DarkGray }
        }
    }
    Assert-Condition ($failedExits -eq 0) "All $Workers parallel processes exited successfully (ExitCode 0)" "Failed worker count: $failedExits"

    Write-Host "`n[Step 4] Validating workspace node_modules integrity across all install workers..." -ForegroundColor Yellow
    $workspaceErrors = 0
    foreach ($entry in ($ProcessList | Where-Object { $_.Type -eq "install" })) {
        $nmDir = Join-Path $entry.WorkDir "node_modules"
        if (-not (Test-Path $nmDir)) {
            $workspaceErrors++
            Write-Host "  Worker $($entry.Id) missing node_modules!" -ForegroundColor Red
            continue
        }

        foreach ($dep in $entry.ExpectedDeps) {
            $depPath = Join-Path $nmDir $dep
            $depPkgJson = Join-Path $depPath "package.json"
            if (-not (Test-Path $depPkgJson)) {
                $workspaceErrors++
                Write-Host "  Worker $($entry.Id) missing expected package '$dep' at $depPath" -ForegroundColor Red
            }
        }
    }
    Assert-Condition ($workspaceErrors -eq 0) "All installed workspaces contain complete, intact dependency packages"

    Write-Host "`n[Step 5] Running strict cache verification to assert ZERO corruption..." -ForegroundColor Yellow
    $verifyPsi = New-Object System.Diagnostics.ProcessStartInfo
    $verifyPsi.FileName = $RnpmPath
    $verifyPsi.Arguments = "cache verify --cache `"$CacheDir`""
    $verifyPsi.UseShellExecute = $false
    $verifyPsi.RedirectStandardOutput = $true
    $verifyPsi.RedirectStandardError = $true
    $verifyPsi.CreateNoWindow = $true

    $verifyProc = [System.Diagnostics.Process]::Start($verifyPsi)
    $verifyProc.WaitForExit()
    $verifyOut = $verifyProc.StandardOutput.ReadToEnd()
    $verifyErr = $verifyProc.StandardError.ReadToEnd()

    Write-Host "Cache Verify Output: $verifyOut" -ForegroundColor DarkGray
    Assert-Condition ($verifyProc.ExitCode -eq 0) "rnpm cache verify exited cleanly (ExitCode 0)"
    Assert-Condition ($verifyOut -notmatch "corrupt blob" -and $verifyOut -notmatch "corrupt index" -and $verifyOut -notmatch "orphaned index") "Zero corruption: no corrupt blobs or indices detected"
    Assert-Condition ($verifyOut -match "Content verified: [1-9]") "Cache verified stored content blobs"
    Assert-Condition ($verifyOut -match "Index entries: [1-9]") "Cache verified stored index entries"

    Write-Host "`n[Step 6] Verifying cross-process file lock serialization and clean lock release..." -ForegroundColor Yellow
    $lockDir = Join-Path $CacheDir "locks"
    $unreleasedLocks = 0
    if (Test-Path $lockDir) {
        $lockFiles = Get-ChildItem -Path $lockDir -Filter "*.lock" -File
        Write-Host "Found $($lockFiles.Count) lock files generated during contention." -ForegroundColor DarkGray
        foreach ($lf in $lockFiles) {
            try {
                # Attempt to open file exclusively with write access: will fail if any process still holds lock
                $stream = [System.IO.File]::Open($lf.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                $stream.Close()
            } catch {
                $unreleasedLocks++
                Write-Host "  Lock file still held: $($lf.Name)" -ForegroundColor Red
            }
        }
    }
    Assert-Condition ($unreleasedLocks -eq 0) "All cross-process file locks released cleanly (zero lingering locks)"

} finally {
    if ($MockServerProcess -and -not $MockServerProcess.HasExited) {
        try { $MockServerProcess.Kill() } catch { }
    }

    if (-not $KeepTemp -and (Test-Path $TempRoot)) {
        try {
            Remove-Item -Path $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        } catch { }
    }
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host " Multi-Process Stress Test Summary: $TestsPassed Passed, $TestsFailed Failed" -ForegroundColor $(if ($TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "================================================================" -ForegroundColor Cyan

if ($TestsFailed -gt 0) {
    exit 1
}
exit 0
