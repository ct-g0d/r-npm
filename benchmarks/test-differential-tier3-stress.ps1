#Requires -Version 5.1
<#
.SYNOPSIS
    Differential test suite for Tier 3 stress benchmark scenarios and statistical stability.
.DESCRIPTION
    Validates Gate C / Phase 2 Expansion criteria:
    1. Tier 3 Deeply Nested Dependency Chains (25+ levels: pkg-tier3-deep-00 .. pkg-tier3-deep-25, plus branches):
       - Full install differential parity between npm 10.x oracle and rnpm
       - 100% normalized tree match (files, hashes, structure)
       - Lockfile v3 deterministic match (POSIX keys, integrity, version, resolved)
       - Clean-slate CI install parity (rnpm ci vs npm ci)
    2. Tier 3 100+ Package Tree Stress Graph (110 packages: pkg-tier3-stress-001 .. pkg-tier3-stress-110):
       - Full install differential parity between npm 10.x oracle and rnpm
       - Verifies resolution, hoisting, and deduplication across wide + deep trees
       - 100% normalized tree match
       - Lockfile v3 deterministic match
       - Clean-slate CI install parity
    3. Tier 3 Large Monorepo Workspaces (multi-package monorepo: core, utils, ui, api, cli, app):
       - Full install differential parity with npm workspaces
       - Workspace directory junctions in root node_modules/@tier3-mono/*
       - Workspace bin shim creation (node_modules/.bin/mono-cli)
       - Shared external package hoisting to root node_modules
       - 100% normalized tree match and lockfile v3 match
       - Clean-slate CI install parity
    4. Benchmark Runner Statistical Stability & Outlier Replacement under Simulated System Load:
       - Validates Median Absolute Deviation (>3 MAD) threshold detection
       - Validates simulated system load / environmental noise injection
       - Confirms outlier trial is replaced with clean re-measured trial
       - Confirms metrics.summary.outliers_replaced == 1
       - Confirms Gate F checkpoint.v1 schema validation succeeds
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

$TempBase = Join-Path ([System.IO.Path]::GetTempPath()) ("npm-rust-tier3-stress-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $TempBase -Force | Out-Null
$TestCacheDir = Join-Path $TempBase "cache"
New-Item -ItemType Directory -Path $TestCacheDir -Force | Out-Null

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Tier 3 Differential Stress & Stability Suite (AGY 5)  " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Work directory: $TempBase" -ForegroundColor DarkGray
Write-Host "rnpm binary:    $RnpmPath" -ForegroundColor DarkGray
Write-Host "npm binary:     $NpmPath" -ForegroundColor DarkGray
Write-Host "Registry:       $RegistryUrl`n" -ForegroundColor DarkGray

try {
    # =========================================================================
    # Part 1: Tier 3 Deeply Nested Dependency Chains (25+ levels)
    # =========================================================================
    Write-Host "========================================================" -ForegroundColor Yellow
    Write-Host "Part 1: Tier 3 Deeply Nested Dependency Chains (25+ levels)" -ForegroundColor Yellow
    Write-Host "========================================================" -ForegroundColor Yellow

    $deepFixture = Join-Path $ScriptDir "fixtures\tier3-deep-tree"
    $npmDeepDir = Join-Path $TempBase "npm-deep"
    $rnpmDeepDir = Join-Path $TempBase "rnpm-deep"

    Copy-Item $deepFixture -Destination $npmDeepDir -Recurse
    Copy-Item $deepFixture -Destination $rnpmDeepDir -Recurse

    Write-Host "`n[1.1] Pristine Install of 25+ level deep dependency chain..." -ForegroundColor Gray

    # Clean existing lockfile for pristine cold install comparison
    Remove-Item (Join-Path $npmDeepDir "package-lock.json") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $rnpmDeepDir "package-lock.json") -Force -ErrorAction SilentlyContinue

    $npmOut = cmd.exe /c "cd /d `"$npmDeepDir`" && $NpmPath install --registry $RegistryUrl --cache `"$TestCacheDir`" --no-audit --no-fund 2>&1"
    $npmExit = $LASTEXITCODE
    Assert-Condition ($npmExit -eq 0) "npm install deep tree exited with 0" "Output: $npmOut"

    $rnpmOut = cmd.exe /c "cd /d `"$rnpmDeepDir`" && `"$RnpmPath`" install --registry $RegistryUrl --cache `"$TestCacheDir`" 2>&1"
    $rnpmExit = $LASTEXITCODE
    Assert-Condition ($rnpmExit -eq 0) "rnpm install deep tree exited with 0" "Output: $rnpmOut"

    # Verify all 27 packages exist in rnpm tree
    $allDeepExist = $true
    for ($d = 0; $d -le 25; $d++) {
        $pName = "pkg-tier3-deep-" + $d.ToString("D2")
        if (-not (Test-Path (Join-Path $rnpmDeepDir "node_modules\$pName"))) {
            $allDeepExist = $false
            Write-Host "         Missing package: $pName" -ForegroundColor Red
        }
    }
    if (-not (Test-Path (Join-Path $rnpmDeepDir "node_modules\pkg-tier3-deep-branch"))) {
        $allDeepExist = $false
    }
    Assert-Condition $allDeepExist "All 27 deep tree packages installed in node_modules"

    # Compare installed trees
    $deepTreeCmp = (node $StatsUtil compare-trees "$npmDeepDir\node_modules" "$rnpmDeepDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($deepTreeCmp.match) "100% normalized tree match on 25+ level deep dependency chain" ($deepTreeCmp.mismatches -join "; ")

    # Compare lockfiles
    $deepLockCmp = (node $StatsUtil compare-lockfiles "$npmDeepDir\package-lock.json" "$rnpmDeepDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($deepLockCmp.match) "Lockfile v3 deterministic match on deep tree" ($deepLockCmp.mismatches -join "; ")

    # [1.2] Clean slate CI install
    Write-Host "`n[1.2] Clean-slate CI Install from generated lockfile..." -ForegroundColor Gray
    Remove-Item (Join-Path $npmDeepDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $rnpmDeepDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue

    $npmCiOut = cmd.exe /c "cd /d `"$npmDeepDir`" && $NpmPath ci --registry $RegistryUrl --cache `"$TestCacheDir`" --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm ci deep tree exited with 0"
    $rnpmCiOut = cmd.exe /c "cd /d `"$rnpmDeepDir`" && `"$RnpmPath`" ci --registry $RegistryUrl --cache `"$TestCacheDir`" 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm ci deep tree exited with 0"

    $deepCiTreeCmp = (node $StatsUtil compare-trees "$npmDeepDir\node_modules" "$rnpmDeepDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($deepCiTreeCmp.match) "100% normalized tree match after clean-slate CI on deep tree" ($deepCiTreeCmp.mismatches -join "; ")

    # =========================================================================
    # Part 2: Tier 3 100+ Package Tree Stress Graph
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Yellow
    Write-Host "Part 2: Tier 3 100+ Package Tree Stress Graph (110 packages)" -ForegroundColor Yellow
    Write-Host "========================================================" -ForegroundColor Yellow

    $stressFixture = Join-Path $ScriptDir "fixtures\tier3-100-packages"
    $npmStressDir = Join-Path $TempBase "npm-stress"
    $rnpmStressDir = Join-Path $TempBase "rnpm-stress"

    Copy-Item $stressFixture -Destination $npmStressDir -Recurse
    Copy-Item $stressFixture -Destination $rnpmStressDir -Recurse

    Write-Host "`n[2.1] Pristine Install of 110-package graph..." -ForegroundColor Gray
    Remove-Item (Join-Path $npmStressDir "package-lock.json") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $rnpmStressDir "package-lock.json") -Force -ErrorAction SilentlyContinue

    $npmStressOut = cmd.exe /c "cd /d `"$npmStressDir`" && $NpmPath install --registry $RegistryUrl --cache `"$TestCacheDir`" --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm install 110-package tree exited with 0"

    $rnpmStressOut = cmd.exe /c "cd /d `"$rnpmStressDir`" && `"$RnpmPath`" install --registry $RegistryUrl --cache `"$TestCacheDir`" 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm install 110-package tree exited with 0"

    # Verify all 110 packages exist in rnpm tree
    $allStressExist = $true
    for ($s = 1; $s -le 110; $s++) {
        $pName = "pkg-tier3-stress-" + $s.ToString("D3")
        if (-not (Test-Path (Join-Path $rnpmStressDir "node_modules\$pName"))) {
            $allStressExist = $false
            Write-Host "         Missing package: $pName" -ForegroundColor Red
        }
    }
    Assert-Condition $allStressExist "All 110 packages installed in node_modules"

    # Compare installed trees
    $stressTreeCmp = (node $StatsUtil compare-trees "$npmStressDir\node_modules" "$rnpmStressDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($stressTreeCmp.match) "100% normalized tree match on 110-package tree" ($stressTreeCmp.mismatches -join "; ")

    # Compare lockfiles
    $stressLockCmp = (node $StatsUtil compare-lockfiles "$npmStressDir\package-lock.json" "$rnpmStressDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($stressLockCmp.match) "Lockfile v3 deterministic match on 110-package tree" ($stressLockCmp.mismatches -join "; ")

    # [2.2] Clean slate CI install
    Write-Host "`n[2.2] Clean-slate CI Install of 110-package graph..." -ForegroundColor Gray
    Remove-Item (Join-Path $npmStressDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $rnpmStressDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue

    $npmCiStressOut = cmd.exe /c "cd /d `"$npmStressDir`" && $NpmPath ci --registry $RegistryUrl --cache `"$TestCacheDir`" --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm ci 110-package tree exited with 0"
    $rnpmCiStressOut = cmd.exe /c "cd /d `"$rnpmStressDir`" && `"$RnpmPath`" ci --registry $RegistryUrl --cache `"$TestCacheDir`" 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm ci 110-package tree exited with 0"

    $stressCiTreeCmp = (node $StatsUtil compare-trees "$npmStressDir\node_modules" "$rnpmStressDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($stressCiTreeCmp.match) "100% normalized tree match after clean-slate CI on 110-package tree" ($stressCiTreeCmp.mismatches -join "; ")

    # =========================================================================
    # Part 3: Tier 3 Large Monorepo Workspaces
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Yellow
    Write-Host "Part 3: Tier 3 Large Monorepo Workspaces" -ForegroundColor Yellow
    Write-Host "========================================================" -ForegroundColor Yellow

    $monoFixture = Join-Path $ScriptDir "fixtures\tier3-monorepo"
    $npmMonoDir = Join-Path $TempBase "npm-mono"
    $rnpmMonoDir = Join-Path $TempBase "rnpm-mono"

    Copy-Item $monoFixture -Destination $npmMonoDir -Recurse
    Copy-Item $monoFixture -Destination $rnpmMonoDir -Recurse

    Write-Host "`n[3.1] Pristine Install of Monorepo with Workspaces..." -ForegroundColor Gray
    Remove-Item (Join-Path $npmMonoDir "package-lock.json") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $rnpmMonoDir "package-lock.json") -Force -ErrorAction SilentlyContinue

    $npmMonoOut = cmd.exe /c "cd /d `"$npmMonoDir`" && $NpmPath install --registry $RegistryUrl --cache `"$TestCacheDir`" --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm install monorepo exited with 0"

    $rnpmMonoOut = cmd.exe /c "cd /d `"$rnpmMonoDir`" && `"$RnpmPath`" install --registry $RegistryUrl --cache `"$TestCacheDir`" 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm install monorepo exited with 0"

    # Verify workspace junctions/symlinks in rnpm
    $wsPackages = @("core", "utils", "ui", "api", "cli", "app")
    $allWsLinked = $true
    foreach ($ws in $wsPackages) {
        $linkPath = Join-Path $rnpmMonoDir "node_modules\@tier3-mono\$ws"
        if (-not (Test-Path $linkPath)) {
            $allWsLinked = $false
            Write-Host "         Missing workspace link: @tier3-mono/$ws" -ForegroundColor Red
        }
    }
    Assert-Condition $allWsLinked "All workspace packages linked into node_modules/@tier3-mono/*"

    # Verify workspace bin shim creation
    $hasMonoCli = (Test-Path (Join-Path $rnpmMonoDir "node_modules\\.bin\\mono-cli.cmd")) -or (Test-Path (Join-Path $rnpmMonoDir "node_modules\\.bin\\mono-cli"))
    Assert-Condition $hasMonoCli "Workspace bin shim 'mono-cli' generated in node_modules/.bin"

    # Verify external hoisted packages exist in root node_modules
    $hasExpress = Test-Path (Join-Path $rnpmMonoDir "node_modules\express")
    $hasCommander = Test-Path (Join-Path $rnpmMonoDir "node_modules\commander")
    $hasCors = Test-Path (Join-Path $rnpmMonoDir "node_modules\cors")
    $hasBytes = Test-Path (Join-Path $rnpmMonoDir "node_modules\bytes")
    Assert-Condition ($hasExpress -and $hasCommander -and $hasCors -and $hasBytes) "External dependencies hoisted to root node_modules (express, commander, cors, bytes)"

    # Compare installed trees
    $monoTreeCmp = (node $StatsUtil compare-trees "$npmMonoDir\node_modules" "$rnpmMonoDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($monoTreeCmp.match) "100% normalized tree match on monorepo workspaces" ($monoTreeCmp.mismatches -join "; ")

    # Compare lockfiles
    $monoLockCmp = (node $StatsUtil compare-lockfiles "$npmMonoDir\package-lock.json" "$rnpmMonoDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($monoLockCmp.match) "Lockfile v3 deterministic match on monorepo workspaces" ($monoLockCmp.mismatches -join "; ")

    # [3.2] Clean slate CI install
    Write-Host "`n[3.2] Clean-slate CI Install of Monorepo..." -ForegroundColor Gray
    Remove-Item (Join-Path $npmMonoDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $rnpmMonoDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue

    $npmCiMonoOut = cmd.exe /c "cd /d `"$npmMonoDir`" && $NpmPath ci --registry $RegistryUrl --cache `"$TestCacheDir`" --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm ci monorepo exited with 0"
    $rnpmCiMonoOut = cmd.exe /c "cd /d `"$rnpmMonoDir`" && `"$RnpmPath`" ci --registry $RegistryUrl --cache `"$TestCacheDir`" 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm ci monorepo exited with 0"

    $monoCiTreeCmp = (node $StatsUtil compare-trees "$npmMonoDir\node_modules" "$rnpmMonoDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($monoCiTreeCmp.match) "100% normalized tree match after clean-slate CI on monorepo" ($monoCiTreeCmp.mismatches -join "; ")

    # =========================================================================
    # Part 4: Statistical Stability & Outlier Replacement under System Load
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Yellow
    Write-Host "Part 4: Benchmark Runner Statistical Stability & Outlier Replacement" -ForegroundColor Yellow
    Write-Host "========================================================" -ForegroundColor Yellow

    Write-Host "`n[4.1] Unit testing statistical MAD outlier detection algorithm..." -ForegroundColor Gray

    # Clean distribution: [100, 102, 101, 103, 99, 101, 102]
    $cleanStats = (node $StatsUtil stats 100 102 101 103 99 101 102) | ConvertFrom-Json
    Assert-Condition ($cleanStats.median -eq 101) "Clean distribution median is 101"
    Assert-Condition ($cleanStats.rsd_pct -lt 2.0) "Clean distribution RSD is <2% ($($cleanStats.rsd_pct)%)"

    # Outlier injected distribution: trial 2 has a 450ms environmental noise spike
    $noisyVals = @(100, 450, 102, 101, 103, 99, 101)
    $noisyStats = (node $StatsUtil stats @noisyVals) | ConvertFrom-Json
    $outlierThreshold = [Math]::Max(10.0, 3.0 * $noisyStats.mad)
    $outlierDiff = [Math]::Abs(450 - $noisyStats.median)
    Assert-Condition ($outlierDiff -gt $outlierThreshold) "MAD detects 450ms noise spike as outlier ($outlierDiff > $outlierThreshold)"

    # Stabilized distribution after outlier replacement with 102:
    $stabilizedVals = @(100, 102, 102, 101, 103, 99, 101)
    $stabilizedStats = (node $StatsUtil stats @stabilizedVals) | ConvertFrom-Json
    Assert-Condition ($stabilizedStats.rsd_pct -lt 2.0) "Stabilized distribution RSD drops to <2% ($($stabilizedStats.rsd_pct)%)"

    Write-Host "`n[4.2] End-to-end benchmark run with simulated system load..." -ForegroundColor Gray
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

        # Validate checkpoint schema
        $valResult = (node $StatsUtil validate-checkpoint $ckPath) | ConvertFrom-Json
        Assert-Condition ($valResult.valid) "Gate F checkpoint schema validation succeeded on stabilized checkpoint" ($valResult.errors -join "; ")

        # Check stability
        $rsd = $ckData.metrics.summary.wall_time.rsd_pct
        Write-Host "  Stabilized wall time median: $($ckData.metrics.summary.wall_time.median)ms | RSD: $rsd%" -ForegroundColor Cyan
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

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "Tier 3 Stress & Stability Summary: $TestsPassed Passed, $TestsFailed Failed" -ForegroundColor $(if ($TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================================" -ForegroundColor Cyan

if ($TestsFailed -gt 0) {
    exit 1
}
exit 0
