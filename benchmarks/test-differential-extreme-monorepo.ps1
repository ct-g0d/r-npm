#Requires -Version 5.1
<#
.SYNOPSIS
    Differential test suite for Extreme 50+ Package Monorepo Workspace DAG and Statistical Stability.
.DESCRIPTION
    Validates Gate C / Phase 2 Expansion criteria:
    1. Extreme 50+ Package Monorepo Workspace DAG (52 packages: pkg-01 .. pkg-52):
       - Full install differential parity between npm 10.x oracle and rnpm
       - 100% normalized tree match (files, hashes, structure)
       - Lockfile v3 deterministic match (POSIX keys, integrity, version, resolved)
       - Clean-slate CI install parity (rnpm ci vs npm ci)
    2. Complex Postinstall Build Pipeline & Cross-Package Artifact Propagation:
       - Verifies dist/pkg-01-artifact.json, dist/pkg-15-artifact.json, and dist/pkg-49-artifact.json produced in topological sequence
       - Verifies process group containment (no orphaned processes remaining)
    3. Circular Workspace Reference Detection:
       - Runs rnpm install on benchmarks/fixtures/extreme-circular-monorepo
       - Asserts exit code is non-zero (fails)
       - Asserts error message contains cycle detection mentioning circ-a and circ-b
    4. Statistical Stability & Outlier Replacement under Environmental Noise:
       - Validates Median Absolute Deviation (>3 MAD) threshold detection
       - Runs repeated benchmark sweeps under simulated environmental noise (run-npm.ps1 -SimulateLoad -InjectOutlierDelayMs 400.0)
       - Confirms outlier trial is replaced with clean re-measured trial (outliers_replaced == 1)
       - Validates Gate A stability criteria (<5% RSD or <=25ms noise)
       - Validates Gate F checkpoint.v1 schema validation output
#>

[CmdletBinding()]
param(
    [string]$RegistryUrl = "http://127.0.0.1:4873",
    [string]$RnpmPath = "",
    [string]$NpmPath = "npm.cmd",
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

if (-not $RnpmPath) {
    $releaseCandidate = Join-Path $RepoRoot "target\release\rnpm.exe"
    $debugCandidate = Join-Path $RepoRoot "target\debug\rnpm.exe"
    if (Test-Path $releaseCandidate) {
        $RnpmPath = $releaseCandidate
    } elseif (Test-Path $debugCandidate) {
        $RnpmPath = $debugCandidate
    } else {
        throw "rnpm executable not found at '$releaseCandidate' or '$debugCandidate'. Run 'cargo build --release -p rnpm-cli' first."
    }
}

# Ensure mock registry is running
$MockServerProcess = $null
function Ensure-MockRegistry {
    try {
        $health = Invoke-RestMethod -Uri "$RegistryUrl/api/health" -TimeoutSec 2 -ErrorAction Stop
        Write-Host "[test] Local mock registry reachable (uptime: $($health.uptime)s)" -ForegroundColor Green
    } catch {
        Write-Host "[test] Starting local mock registry server on $RegistryUrl..." -ForegroundColor Cyan
        $mockScript = Join-Path $ScriptDir "mock-registry\mock-server.js"
        $script:MockServerProcess = Start-Process node -ArgumentList "$mockScript --port 4873 --quiet" -PassThru
        Start-Sleep -Milliseconds 800
        $health = Invoke-RestMethod -Uri "$RegistryUrl/api/health" -TimeoutSec 5
        Write-Host "[test] Local mock registry started successfully." -ForegroundColor Green
    }
}

Ensure-MockRegistry

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

$TempBase = Join-Path ([System.IO.Path]::GetTempPath()) ("npm-rust-extreme-mono-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $TempBase -Force | Out-Null
$TestCacheDir = Join-Path $TempBase "cache"
New-Item -ItemType Directory -Path $TestCacheDir -Force | Out-Null

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Extreme 50+ Monorepo DAG & Statistical Stability Suite (AGY 5)  " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Work directory: $TempBase" -ForegroundColor DarkGray
Write-Host "rnpm binary:    $RnpmPath" -ForegroundColor DarkGray
Write-Host "npm binary:     $NpmPath" -ForegroundColor DarkGray
Write-Host "Registry:       $RegistryUrl`n" -ForegroundColor DarkGray

try {
    # =========================================================================
    # Part 1: Extreme 50+ Package Monorepo Workspace DAG
    # =========================================================================
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "Part 1: Extreme 50+ Package Monorepo Workspace DAG (52 Packages)" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow

    $extremeFixture = Join-Path $ScriptDir "fixtures\extreme-monorepo-50"
    $npmMonoDir = Join-Path $TempBase "npm-extreme-mono"
    $rnpmMonoDir = Join-Path $TempBase "rnpm-extreme-mono"

    Copy-Item $extremeFixture -Destination $npmMonoDir -Recurse
    Copy-Item $extremeFixture -Destination $rnpmMonoDir -Recurse

    Write-Host "`n[1.1] Pristine Install of Extreme 50+ Package Monorepo..." -ForegroundColor Gray

    # Clean existing lockfile if present for pristine cold install comparison
    Remove-Item (Join-Path $npmMonoDir "package-lock.json") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $rnpmMonoDir "package-lock.json") -Force -ErrorAction SilentlyContinue

    $npmOut = cmd.exe /c "cd /d `"$npmMonoDir`" && $NpmPath install --registry $RegistryUrl --cache `"$TestCacheDir`" --no-audit --no-fund 2>&1"
    $npmExit = $LASTEXITCODE
    Assert-Condition ($npmExit -eq 0) "npm install extreme monorepo exited with 0" "Output: $npmOut"

    $rnpmOut = cmd.exe /c "cd /d `"$rnpmMonoDir`" && `"$RnpmPath`" install --registry $RegistryUrl --cache `"$TestCacheDir`" 2>&1"
    $rnpmExit = $LASTEXITCODE
    Assert-Condition ($rnpmExit -eq 0) "rnpm install extreme monorepo exited with 0" "Output: $rnpmOut"

    # Verify workspace junctions/symlinks in rnpm node_modules for all 52 packages
    $allPkgsLinked = $true
    for ($i = 1; $i -le 52; $i++) {
        $pName = "pkg-" + $i.ToString("D2")
        $linkPath = Join-Path $rnpmMonoDir "node_modules\$pName"
        if (-not (Test-Path $linkPath)) {
            $allPkgsLinked = $false
            Write-Host "         Missing workspace link: $pName" -ForegroundColor Red
        }
    }
    Assert-Condition $allPkgsLinked "All 52 workspace packages linked into node_modules/*"

    # Verify bin shims generated for application packages (e.g. pkg-49-cli)
    $hasCliShim = (Test-Path (Join-Path $rnpmMonoDir "node_modules\.bin\pkg-49-cli.cmd")) -or (Test-Path (Join-Path $rnpmMonoDir "node_modules\.bin\pkg-49-cli"))
    Assert-Condition $hasCliShim "Workspace bin shim 'pkg-49-cli' generated in node_modules/.bin"

    # Compare installed trees
    $treeCmp = (node $StatsUtil compare-trees "$npmMonoDir\node_modules" "$rnpmMonoDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmp.match) "100% normalized tree match on extreme 50+ monorepo" ($treeCmp.mismatches -join "; ")

    # Compare lockfiles
    $lockCmp = (node $StatsUtil compare-lockfiles "$npmMonoDir\package-lock.json" "$rnpmMonoDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmp.match) "100% deterministic lockfile v3 match on extreme monorepo" ($lockCmp.mismatches -join "; ")

    # [1.2] Clean slate CI install
    Write-Host "`n[1.2] Clean-slate CI Install of Extreme Monorepo..." -ForegroundColor Gray
    Remove-Item (Join-Path $npmMonoDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $rnpmMonoDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue

    $npmCiOut = cmd.exe /c "cd /d `"$npmMonoDir`" && $NpmPath ci --registry $RegistryUrl --cache `"$TestCacheDir`" --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm ci extreme monorepo exited with 0"
    $rnpmCiOut = cmd.exe /c "cd /d `"$rnpmMonoDir`" && `"$RnpmPath`" ci --registry $RegistryUrl --cache `"$TestCacheDir`" 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm ci extreme monorepo exited with 0"

    $ciTreeCmp = (node $StatsUtil compare-trees "$npmMonoDir\node_modules" "$rnpmMonoDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($ciTreeCmp.match) "100% normalized tree match after clean-slate CI on extreme monorepo" ($ciTreeCmp.mismatches -join "; ")

    # =========================================================================
    # Part 2: Complex Postinstall Build Pipeline & Cross-Package Artifact Propagation
    # =========================================================================
    Write-Host "`n=================================================================" -ForegroundColor Yellow
    Write-Host "Part 2: Complex Postinstall Build Pipeline & Artifact Propagation" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow

    # Verify cross-package artifacts produced in topological sequence
    $art01Candidates = @(
        (Join-Path $rnpmMonoDir "dist\pkg-01-artifact.json"),
        (Join-Path $rnpmMonoDir "packages\pkg-01\dist\pkg-01-artifact.json")
    )
    $art15Candidates = @(
        (Join-Path $rnpmMonoDir "dist\pkg-15-artifact.json"),
        (Join-Path $rnpmMonoDir "packages\pkg-15\dist\pkg-15-artifact.json")
    )
    $art49Candidates = @(
        (Join-Path $rnpmMonoDir "dist\pkg-49-artifact.json"),
        (Join-Path $rnpmMonoDir "packages\pkg-49\dist\pkg-49-artifact.json")
    )

    $art01Path = $art01Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    $art15Path = $art15Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    $art49Path = $art49Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    Assert-Condition ($art01Path -ne $null) "dist/pkg-01-artifact.json was produced by pkg-01 postinstall/prepare"
    Assert-Condition ($art15Path -ne $null) "dist/pkg-15-artifact.json was produced by pkg-15 postinstall"
    Assert-Condition ($art49Path -ne $null) "dist/pkg-49-artifact.json was produced by pkg-49 postinstall"

    if ($art01Path -and $art15Path -and $art49Path) {
        $data01 = Get-Content $art01Path -Raw | ConvertFrom-Json
        $data15 = Get-Content $art15Path -Raw | ConvertFrom-Json
        $data49 = Get-Content $art49Path -Raw | ConvertFrom-Json

        $isTopoSeq = ($data01.timestamp -le $data15.timestamp) -and ($data15.timestamp -le $data49.timestamp)
        Assert-Condition $isTopoSeq "Artifacts produced in topological timestamp sequence (pkg-01 <= pkg-15 <= pkg-49)" "ts01=$($data01.timestamp), ts15=$($data15.timestamp), ts49=$($data49.timestamp)"

        $hasVerified15 = ($data15.verifiedFrom -ne $null)
        Assert-Condition $hasVerified15 "Cross-package propagation: pkg-15 verified existence of pkg-01 artifact"

        $hasVerified49 = ($data49.verified01 -ne $null -and $data49.verified15 -ne $null)
        Assert-Condition $hasVerified49 "Cross-package propagation: pkg-49 verified existence of both pkg-01 and pkg-15 artifacts"
    }

    # Verify Process Group Containment (no orphaned background processes left running)
    Write-Host "`n[2.2] Verifying Process Group Containment..." -ForegroundColor Gray
    $tempPosix = $TempBase.Replace("\", "/")
    $orphanedProcesses = Get-CimInstance Win32_Process -Filter "Name = 'node.exe' or Name = 'cmd.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and ($_.CommandLine.Replace("\", "/").Contains($tempPosix)) }

    $orphanCount = if ($orphanedProcesses) { @($orphanedProcesses).Count } else { 0 }
    Assert-Condition ($orphanCount -eq 0) "Process group containment: no orphaned processes remaining ($orphanCount found)"

    # =========================================================================
    # Part 3: Circular Workspace Reference Detection
    # =========================================================================
    Write-Host "`n=================================================================" -ForegroundColor Yellow
    Write-Host "Part 3: Circular Workspace Reference Detection" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow

    $circFixture = Join-Path $ScriptDir "fixtures\extreme-circular-monorepo"
    $rnpmCircDir = Join-Path $TempBase "rnpm-circular"
    Copy-Item $circFixture -Destination $rnpmCircDir -Recurse

    Write-Host "[3.1] Running rnpm install on circular monorepo fixture..." -ForegroundColor Gray
    $circOut = cmd.exe /c "cd /d `"$rnpmCircDir`" && `"$RnpmPath`" install --offline 2>&1"
    $circExit = $LASTEXITCODE

    Assert-Condition ($circExit -ne 0) "rnpm install fails on circular monorepo with non-zero exit code (exit: $circExit)"
    $mentionsCircA = $circOut -match "circ-a"
    $mentionsCircB = $circOut -match "circ-b"
    $mentionsCycle = $circOut -match "(?i)(cycle|circular)"
    Assert-Condition ($mentionsCycle -and $mentionsCircA -and $mentionsCircB) "Cycle detection error mentions circ-a and circ-b" "Output: $circOut"

    # =========================================================================
    # Part 4: Statistical Stability & Noise Benchmarks
    # =========================================================================
    Write-Host "`n=================================================================" -ForegroundColor Yellow
    Write-Host "Part 4: Statistical Stability & Noise Benchmarks" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow

    Write-Host "`n[4.1] Unit testing statistical MAD outlier detection algorithm..." -ForegroundColor Gray
    # Clean distribution: [100, 102, 101, 103, 99, 101, 102]
    $cleanStats = (node $StatsUtil stats 100 102 101 103 99 101 102) | ConvertFrom-Json
    Assert-Condition ($cleanStats.median -eq 101) "Clean distribution median is 101"
    Assert-Condition ($cleanStats.rsd_pct -lt 2.0) "Clean distribution RSD is <2% ($($cleanStats.rsd_pct)%)\"

    # Outlier injected distribution: trial 2 has a 450ms environmental noise spike
    $noisyVals = @(100, 450, 102, 101, 103, 99, 101)
    $noisyStats = (node $StatsUtil stats @noisyVals) | ConvertFrom-Json
    $outlierThreshold = [Math]::Max(10.0, 3.0 * $noisyStats.mad)
    $outlierDiff = [Math]::Abs(450 - $noisyStats.median)
    Assert-Condition ($outlierDiff -gt $outlierThreshold) "MAD detects 450ms noise spike as outlier ($outlierDiff > $outlierThreshold)"

    Write-Host "`n[4.2] Running benchmark sweep under simulated environmental noise..." -ForegroundColor Gray
    $benchScript = Join-Path $ScriptDir "run-npm.ps1"
    $stabOutDir = Join-Path $TempBase "bench-stability"
    New-Item -ItemType Directory -Path $stabOutDir -Force | Out-Null
    $ckPath = Join-Path $stabOutDir "checkpoint-rnpm-tier1-single-dep-warm-install.json"

    # Run rnpm benchmark on tier1-single-dep with simulated load
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $benchScript `
        -Fixture "tier1-single-dep" `
        -CacheState "warm-install" `
        -Tool "rnpm" `
        -RnpmPath $RnpmPath `
        -RegistryUrl $RegistryUrl `
        -OutputDir $stabOutDir `
        -OutputFile $ckPath `
        -Trials 5 `
        -Warmup 1 `
        -SimulateLoad `
        -InjectOutlierDelayMs 400.0

    Assert-Condition (Test-Path $ckPath) "Benchmark runner generated checkpoint artifact under simulated load"

    if (Test-Path $ckPath) {
        $ckData = Get-Content $ckPath -Raw | ConvertFrom-Json
        $outliersReplaced = $ckData.metrics.summary.outliers_replaced
        Assert-Condition ($outliersReplaced -eq 1) "Outlier replacement caught noise spike and re-measured (outliers_replaced == 1)" "Actual: $outliersReplaced"

        # Validate Gate F checkpoint schema
        $valResult = (node $StatsUtil validate-checkpoint $ckPath) | ConvertFrom-Json
        Assert-Condition ($valResult.valid) "Gate F checkpoint schema validation succeeded on stabilized checkpoint" ($valResult.errors -join "; ")

        # Check Gate A stability criteria (<5% RSD or <=25ms noise)
        $rsd = $ckData.metrics.summary.wall_time.rsd_pct
        $noiseRange = $ckData.metrics.summary.wall_time.max - $ckData.metrics.summary.wall_time.min
        $isGateAStable = ($rsd -lt 5.0) -or ($noiseRange -le 25.0) -or ($ckData.metrics.summary.wall_time.mad -le 25.0)
        Assert-Condition $isGateAStable "Gate A stability criteria satisfied (<5% RSD or <=25ms noise): RSD=$rsd%, noiseRange=${noiseRange}ms"
        Assert-Condition ($ckData.correctness.normalized_tree_match) "Installed package tree matches reference under simulated load"
    }

} finally {
    if (-not $KeepTemp -and (Test-Path $TempBase)) {
        Remove-Item -Path $TempBase -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($script:MockServerProcess -and -not $script:MockServerProcess.HasExited) {
        Stop-Process -Id $script:MockServerProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "Extreme Monorepo & Stability Summary: $TestsPassed Passed, $TestsFailed Failed" -ForegroundColor $(if ($TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "=================================================================" -ForegroundColor Cyan

if ($TestsFailed -gt 0) {
    exit 1
}
exit 0
