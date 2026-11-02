#Requires -Version 5.1
<#
.SYNOPSIS
    Automated self-improvement benchmarking loop and differential gate runner.
.DESCRIPTION
    Executes full quality and performance evaluation suites:
    1. Tier 2 Lifecycle & Executable Shim Differential Suite (test-differential-lifecycle-shim.ps1)
    2. Tier 2 Mutation Differential Suite: uninstall, update, pack (test-differential-tier2-mutations.ps1)
    3. Gate F Checkpoint Generation & Comparison across Pristine Cold, Warm Install, and Hot Noop states
    4. Evaluates Gate C, Gate D, and Gate F criteria
#>

[CmdletBinding()]
param(
    [string]$RegistryUrl = "http://127.0.0.1:4873",
    [string]$RnpmPath = "",
    [string]$NpmPath = "npm.cmd",
    [switch]$SkipBenchmarks,
    [switch]$FailOnRegression
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
        throw "rnpm executable not found in target\release or target\debug."
    }
}

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Automated Self-Improvement & Benchmark Loop (AGY 5) " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "rnpm binary: $RnpmPath" -ForegroundColor DarkGray
Write-Host "npm binary:  $NpmPath" -ForegroundColor DarkGray
Write-Host "Registry:    $RegistryUrl`n" -ForegroundColor DarkGray

# 1. Run Lifecycle & Shim Differential Suite
Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
Write-Host "[Step 1/3] Running Lifecycle & Shim Differential Suite..." -ForegroundColor Yellow
Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptDir "test-differential-lifecycle-shim.ps1") -RegistryUrl $RegistryUrl -RnpmPath $RnpmPath -NpmPath $NpmPath
if ($LASTEXITCODE -ne 0) {
    throw "Lifecycle & Shim Differential Suite failed with exit code $LASTEXITCODE"
}

# 2. Run Tier 2 Mutation Differential Suite
Write-Host "`n--------------------------------------------------------" -ForegroundColor Yellow
Write-Host "[Step 2/3] Running Tier 2 Mutation Differential Suite..." -ForegroundColor Yellow
Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptDir "test-differential-tier2-mutations.ps1") -RegistryUrl $RegistryUrl -RnpmPath $RnpmPath -NpmPath $NpmPath
if ($LASTEXITCODE -ne 0) {
    throw "Tier 2 Mutation Differential Suite failed with exit code $LASTEXITCODE"
}

# 3. Run Benchmark Scenarios & Differential Performance Checks
if (-not $SkipBenchmarks) {
    Write-Host "`n--------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "[Step 3/3] Running Gate F Benchmarks (Cold, Warm, Hot)..." -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------" -ForegroundColor Yellow

    $scenarios = @("pristine-cold", "warm-install", "hot-noop")
    $fixture = "tier1-single-dep"
    $resultsDir = Join-Path $ScriptDir "results\baseline"

    foreach ($sc in $scenarios) {
        Write-Host "`n>>> Benchmark Scenario: $fixture | $sc <<<" -ForegroundColor Magenta

        # Run npm
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptDir "run-npm.ps1") `
            -Fixture $fixture -CacheState $sc -Tool "npm" -NpmPath $NpmPath -RegistryUrl $RegistryUrl -StartMockServer
        if ($LASTEXITCODE -ne 0) { throw "npm benchmark failed for $sc" }

        # Run rnpm
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptDir "run-npm.ps1") `
            -Fixture $fixture -CacheState $sc -Tool "rnpm" -RnpmPath $RnpmPath -RegistryUrl $RegistryUrl -StartMockServer
        if ($LASTEXITCODE -ne 0) { throw "rnpm benchmark failed for $sc" }

        # Compare Results
        $npmCk = Join-Path $resultsDir "checkpoint-npm-$fixture-$sc.json"
        $rnpmCk = Join-Path $resultsDir "checkpoint-rnpm-$fixture-$sc.json"
        $repFile = Join-Path $resultsDir "report-$fixture-$sc.md"

        $cmpArgs = @(
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $ScriptDir "compare-results.ps1"),
            "-NpmCheckpoint", $npmCk,
            "-RnpmCheckpoint", $rnpmCk,
            "-ReportFile", $repFile
        )
        if ($FailOnRegression) { $cmpArgs += "-FailOnRegression" }

        & powershell.exe -NoProfile @cmpArgs
        if ($LASTEXITCODE -ne 0) { throw "Comparison failed for $sc" }
    }
}

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host "All Differential Tests & Benchmarks Passed Successfully!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
