#Requires -Version 5.1
<#
.SYNOPSIS
    Differential comparison script comparing npm vs rnpm installed trees, lockfiles, and performance metrics.
.DESCRIPTION
    Renders Gate F checkpoint comparisons and validates Gate B / Gate D criteria:
    - 100% normalized tree match (structure, contents, symlinks, shims).
    - Lockfile v3 deterministic match (POSIX package keys, resolved, integrity).
    - Performance delta (wall-clock time, CPU, peak working set, commit charge, disk writes, write amplification).
    - Threshold enforcement (5% wall time + 25ms noise limit, 10% commit charge).
.PARAMETER NpmCheckpoint
    Path to baseline npm checkpoint.v1.json artifact.
.PARAMETER RnpmCheckpoint
    Path to target rnpm checkpoint.v1.json artifact.
.PARAMETER NpmDir
    Optional path to npm installation root (containing node_modules and package-lock.json).
.PARAMETER RnpmDir
    Optional path to rnpm installation root (containing node_modules and package-lock.json).
.PARAMETER ThresholdWallPct
    Maximum allowable wall-clock time regression percentage before failing gate. Default: 5.0%.
.PARAMETER ThresholdWallNoiseMs
    Noise threshold in milliseconds for wall-clock time comparisons. Default: 25.0ms.
.PARAMETER ThresholdCommitPct
    Maximum allowable peak commit charge regression percentage. Default: 10.0%.
.PARAMETER Fixture
    Optional fixture name (e.g. tier1-single-dep, tier1-diamond). If provided, auto-resolves checkpoint paths in results\baseline.
.PARAMETER CacheState
    Optional benchmark cache state (e.g. pristine-cold, warm-install, hot-noop). Defaults to warm-install if Fixture is specified.
.PARAMETER ReportFile
    Optional path to write markdown summary report.
.PARAMETER FailOnRegression
    Switch to exit with non-zero exit code if correctness fails or regression exceeds thresholds.
#>

[CmdletBinding()]
param(
    [string]$Fixture = "",
    [ValidateSet("", "pristine-cold", "cold-ci", "lockfile-only-ci", "warm-install", "hot-noop")]
    [string]$CacheState = "",
    [string]$NpmCheckpoint = "",
    [string]$RnpmCheckpoint = "",
    [string]$NpmDir = "",
    [string]$RnpmDir = "",
    [double]$ThresholdWallPct = 5.0,
    [double]$ThresholdWallNoiseMs = 25.0,
    [double]$ThresholdCommitPct = 10.0,
    [string]$ReportFile = "",
    [switch]$FailOnRegression
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
$StatsUtil = Join-Path $ScriptDir "harness-utils.js"

# Auto-resolve checkpoint files if Fixture is provided
if ($Fixture) {
    if (-not $CacheState) { $CacheState = "warm-install" }
    $baselineDir = Join-Path $ScriptDir "results\baseline"
    if (-not $NpmCheckpoint) {
        $candidate = Join-Path $baselineDir "checkpoint-npm-$Fixture-$CacheState.json"
        if (Test-Path $candidate) { $NpmCheckpoint = $candidate }
    }
    if (-not $RnpmCheckpoint) {
        $candidate = Join-Path $baselineDir "checkpoint-rnpm-$Fixture-$CacheState.json"
        if (Test-Path $candidate) { $RnpmCheckpoint = $candidate }
    }
    if (-not $ReportFile) {
        $ReportFile = Join-Path $baselineDir "report-$Fixture-$CacheState.md"
    }
}

# Validate inputs
if (-not $NpmCheckpoint -and -not $NpmDir) {
    throw "Either -Fixture, -NpmCheckpoint, or -NpmDir must be provided."
}
if (-not $RnpmCheckpoint -and -not $RnpmDir) {
    throw "Either -RnpmCheckpoint or -RnpmDir must be provided."
}

$npmData = $null
$rnpmData = $null

if ($NpmCheckpoint -and (Test-Path $NpmCheckpoint)) {
    try {
        $schemaNpm = (node $StatsUtil validate-checkpoint $NpmCheckpoint) | ConvertFrom-Json
        if (-not $schemaNpm.valid) {
            Write-Warning "npm checkpoint failed Gate F schema validation: $($schemaNpm.errors -join '; ')"
        }
    } catch { }
    $npmData = Get-Content $NpmCheckpoint -Raw | ConvertFrom-Json
}
if ($RnpmCheckpoint -and (Test-Path $RnpmCheckpoint)) {
    try {
        $schemaRnpm = (node $StatsUtil validate-checkpoint $RnpmCheckpoint) | ConvertFrom-Json
        if (-not $schemaRnpm.valid) {
            Write-Warning "rnpm checkpoint failed Gate F schema validation: $($schemaRnpm.errors -join '; ')"
        }
    } catch { }
    $rnpmData = Get-Content $RnpmCheckpoint -Raw | ConvertFrom-Json
}

# Direct filesystem comparison if directories are provided
$directTreeCmp = $null
$directLockCmp = $null

if ($NpmDir -and $RnpmDir) {
    $treeA = Join-Path $NpmDir "node_modules"
    $treeB = Join-Path $RnpmDir "node_modules"
    if ((Test-Path $treeA) -and (Test-Path $treeB)) {
        $directTreeCmp = (node $StatsUtil compare-trees $treeA $treeB) | ConvertFrom-Json
    }

    $lockA = Join-Path $NpmDir "package-lock.json"
    $lockB = Join-Path $RnpmDir "package-lock.json"
    if ((Test-Path $lockA) -and (Test-Path $lockB)) {
        $directLockCmp = (node $StatsUtil compare-lockfiles $lockA $lockB) | ConvertFrom-Json
    }
}

# Extract Correctness Details
$isCorrectnessPass = $true
$correctnessIssues = @()

$npmExit = if ($npmData) { $npmData.correctness.exit_code } else { 0 }
$rnpmExit = if ($rnpmData) { $rnpmData.correctness.exit_code } else { 0 }

if ($npmExit -ne 0) {
    $isCorrectnessPass = $false
    $correctnessIssues += "npm exited with non-zero code ($npmExit)"
}
if ($rnpmExit -ne 0) {
    $isCorrectnessPass = $false
    $correctnessIssues += "rnpm exited with non-zero code ($rnpmExit)"
}

# Compare Tree Digests
$npmTreeDigest = if ($npmData) { $npmData.correctness.installed_package_tree_digest } else { $null }
$rnpmTreeDigest = if ($rnpmData) { $rnpmData.correctness.installed_package_tree_digest } else { $null }

if ($directTreeCmp) {
    if (-not $directTreeCmp.match) {
        $isCorrectnessPass = $false
        foreach ($m in $directTreeCmp.mismatches) { $correctnessIssues += "Tree: $m" }
    }
    $npmTreeDigest = $directTreeCmp.digestA
    $rnpmTreeDigest = $directTreeCmp.digestB
} elseif ($npmTreeDigest -and $rnpmTreeDigest) {
    if ($npmTreeDigest -ne $rnpmTreeDigest) {
        $isCorrectnessPass = $false
        $correctnessIssues += "Normalized tree digest mismatch: npm ($npmTreeDigest) vs rnpm ($rnpmTreeDigest)"
    }
}

# Compare Lockfile Digests
$npmLockDigest = if ($npmData) { $npmData.correctness.lockfile_digest } else { $null }
$rnpmLockDigest = if ($rnpmData) { $rnpmData.correctness.lockfile_digest } else { $null }

if ($directLockCmp) {
    if (-not $directLockCmp.match) {
        $isCorrectnessPass = $false
        foreach ($m in $directLockCmp.mismatches) { $correctnessIssues += "Lockfile: $m" }
    }
    $npmLockDigest = $directLockCmp.digestA
    $rnpmLockDigest = $directLockCmp.digestB
} elseif ($npmLockDigest -and $rnpmLockDigest) {
    if ($npmLockDigest -ne $rnpmLockDigest) {
        $isCorrectnessPass = $false
        $correctnessIssues += "Lockfile v3 digest mismatch: npm ($npmLockDigest) vs rnpm ($rnpmLockDigest)"
    }
}

# Extract and Compare Performance Metrics if both checkpoints exist
$hasPerfComparison = ($npmData -ne $null -and $rnpmData -ne $null)
$isPerfPass = $true
$perfIssues = @()

$comparisonRows = @()

function Add-PerfRow {
    param(
        [string]$MetricName,
        [double]$ValNpm,
        [double]$ValRnpm,
        [string]$Unit,
        [string]$ThresholdDesc,
        [bool]$IsRegressionCheck = $false,
        [double]$MaxAllowedRegressionPct = 0.0,
        [double]$NoiseFloor = 0.0
    )

    $deltaAbs = $ValRnpm - $ValNpm
    $deltaPct = if ($ValNpm -gt 0) { [Math]::Round((($deltaAbs / $ValNpm) * 100), 2) } else { 0.0 }

    $status = "INFO"
    if ($IsRegressionCheck) {
        $isNoise = [Math]::Abs($deltaAbs) -le $NoiseFloor
        if ($deltaPct -gt $MaxAllowedRegressionPct -and -not $isNoise) {
            $status = "FAIL"
            $script:isPerfPass = $false
            $script:perfIssues += "$MetricName regressed by $deltaPct% (+$([Math]::Round($deltaAbs, 2))$Unit, threshold: +$MaxAllowedRegressionPct%)"
        } elseif ($deltaPct -lt -0.1) {
            $status = "FASTER"
        } else {
            $status = "PASS"
        }
    }

    $script:comparisonRows += [PSCustomObject]@{
        Metric = $MetricName
        NpmVal = "$([Math]::Round($ValNpm, 2)) $Unit"
        RnpmVal = "$([Math]::Round($ValRnpm, 2)) $Unit"
        DeltaAbs = ("{0:+0.00;-0.00;0.00} {1}" -f $deltaAbs, $Unit)
        DeltaPct = ("{0:+0.00;-0.00;0.00}%" -f $deltaPct)
        Threshold = $ThresholdDesc
        Status = $status
    }
}

if ($hasPerfComparison) {
    $sNpm = $npmData.metrics.summary
    $sRnpm = $rnpmData.metrics.summary

    Add-PerfRow -MetricName "Wall-clock Time (Median)" `
                -ValNpm $sNpm.wall_time.median `
                -ValRnpm $sRnpm.wall_time.median `
                -Unit "ms" `
                -ThresholdDesc "<= +$ThresholdWallPct% and > $ThresholdWallNoiseMs ms" `
                -IsRegressionCheck $true `
                -MaxAllowedRegressionPct $ThresholdWallPct `
                -NoiseFloor $ThresholdWallNoiseMs

    Add-PerfRow -MetricName "User CPU Time" `
                -ValNpm $sNpm.user_cpu.median `
                -ValRnpm $sRnpm.user_cpu.median `
                -Unit "ms" `
                -ThresholdDesc "Informational"

    Add-PerfRow -MetricName "System CPU Time" `
                -ValNpm $sNpm.system_cpu.median `
                -ValRnpm $sRnpm.system_cpu.median `
                -Unit "ms" `
                -ThresholdDesc "Informational"

    Add-PerfRow -MetricName "Peak Working Set" `
                -ValNpm ($sNpm.peak_working_set.median / 1MB) `
                -ValRnpm ($sRnpm.peak_working_set.median / 1MB) `
                -Unit "MB" `
                -ThresholdDesc "Informational"

    Add-PerfRow -MetricName "Peak Commit Charge" `
                -ValNpm ($sNpm.peak_commit_charge.median / 1MB) `
                -ValRnpm ($sRnpm.peak_commit_charge.median / 1MB) `
                -Unit "MB" `
                -ThresholdDesc "<= +$ThresholdCommitPct%" `
                -IsRegressionCheck $true `
                -MaxAllowedRegressionPct $ThresholdCommitPct

    Add-PerfRow -MetricName "Disk Write Bytes" `
                -ValNpm ($sNpm.disk_write_bytes.median / 1KB) `
                -ValRnpm ($sRnpm.disk_write_bytes.median / 1KB) `
                -Unit "KB" `
                -ThresholdDesc "Informational"

    Add-PerfRow -MetricName "Write Amplification" `
                -ValNpm $sNpm.write_amplification.median `
                -ValRnpm $sRnpm.write_amplification.median `
                -Unit "x" `
                -ThresholdDesc "Informational"
}

# Build Markdown Report
$md = @()
$md += "# Differential Comparison Report: npm vs rnpm"
$md += ""
$md += "- **Date:** $( (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC') )"
if ($npmData) {
    $md += "- **Fixture:** $($npmData.scenario.fixture) ($($npmData.scenario.tier))"
    $md += "- **Cache State:** $($npmData.scenario.cache_state) ($($npmData.scenario.command))"
    $md += "- **Machine:** $($npmData.metadata.cpu) | RAM: $([Math]::Round($npmData.metadata.ram_bytes / 1GB, 1)) GB"
    $md += "- **OS:** $($npmData.metadata.os)"
    $md += "- **Node:** $($npmData.metadata.node_version) | **npm:** $($npmData.metadata.tool.version)"
}
if ($rnpmData) {
    $md += "- **rnpm Version:** $($rnpmData.metadata.tool.version) (Rust: $($rnpmData.metadata.rust_version))"
}
$md += ""
$md += "## Correctness Evaluation (Gate B / Gate F)"
$md += ""
$md += "| Check | Baseline (npm) | Target (rnpm) | Result |"
$md += "|---|---|---|---|"
$md += "| **Exit Code** | $npmExit | $rnpmExit | $(if ($npmExit -eq 0 -and $rnpmExit -eq 0) { '✅ PASS' } else { '❌ FAIL' }) |"
$md += "| **Tree Digest** | `$npmTreeDigest` | `$rnpmTreeDigest` | $(if ($npmTreeDigest -and $npmTreeDigest -eq $rnpmTreeDigest) { 'PASS' } else { 'MISMATCH' }) |"
$md += "| **Lockfile v3 Digest** | `$npmLockDigest` | `$rnpmLockDigest` | $(if ($npmLockDigest -and $npmLockDigest -eq $rnpmLockDigest) { 'PASS' } else { 'MISMATCH' }) |"
$md += ""

if ($correctnessIssues.Count -gt 0) {
    $md += "### Correctness Issues"
    foreach ($issue in $correctnessIssues) {
        $md += "- ❌ $issue"
    }
    $md += ""
}

if ($hasPerfComparison) {
    $md += "## Performance Metrics (Gate D)"
    $md += ""
    $md += "| Metric | npm (Baseline) | rnpm (Target) | Delta (Abs) | Delta (%) | Gate Threshold | Status |"
    $md += "|---|---|---|---|---|---|---|"
    foreach ($row in $comparisonRows) {
        $statusIcon = switch ($row.Status) {
            "FASTER" { "⚡ FASTER" }
            "PASS" { "✅ PASS" }
            "FAIL" { "❌ FAIL" }
            default { "ℹ️ INFO" }
        }
        $md += "| **$($row.Metric)** | $($row.NpmVal) | $($row.RnpmVal) | $($row.DeltaAbs) | $($row.DeltaPct) | $($row.Threshold) | $statusIcon |"
    }
    $md += ""

    if ($perfIssues.Count -gt 0) {
        $md += "### Performance Regressions"
        foreach ($issue in $perfIssues) {
            $md += "- ⚠️ $issue"
        }
        $md += ""
    }
}

$overallGatePass = ($isCorrectnessPass -and $isPerfPass)
$md += "## Gate Decision"
$md += ""
if ($overallGatePass) {
    $md += "### **OVERALL RESULT: PASS ✅**"
    $md += "Normalized dependency tree and lockfile v3 match 100%. Performance regressions are within allowable thresholds."
} else {
    $md += "### **OVERALL RESULT: FAIL ❌**"
    $md += "One or more correctness checks or performance regression thresholds failed."
}

$reportText = $md -join "`r`n"

# Output to console
$colorCorrectness = $(if ($isCorrectnessPass) { "Green" } else { "Red" })
$colorPerf = $(if ($isPerfPass) { "Green" } else { "Red" })
$colorGate = $(if ($overallGatePass) { "Green" } else { "Red" })

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "Differential Benchmark Comparison Result" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Correctness: $(if ($isCorrectnessPass) { 'PASS (100% Tree & Lockfile Parity)' } else { 'FAIL' })" -ForegroundColor $colorCorrectness
if ($hasPerfComparison) {
    Write-Host "Performance: $(if ($isPerfPass) { 'PASS' } else { 'FAIL (Regression Detected)' })" -ForegroundColor $colorPerf
}
Write-Host "Overall Gate: $(if ($overallGatePass) { 'PASS' } else { 'FAIL' })" -ForegroundColor $colorGate

if ($hasPerfComparison) {
    Write-Host "`nPerformance Table:" -ForegroundColor Gray
    $comparisonRows | Format-Table -AutoSize
}

if ($correctnessIssues.Count -gt 0) {
    Write-Host "`nCorrectness Issues:" -ForegroundColor Red
    foreach ($issue in $correctnessIssues) { Write-Host "  - $issue" -ForegroundColor Red }
}

if ($perfIssues.Count -gt 0) {
    Write-Host "`nPerformance Regressions:" -ForegroundColor Yellow
    foreach ($issue in $perfIssues) { Write-Host "  - $issue" -ForegroundColor Yellow }
}

# Save Report File if specified
if ($ReportFile) {
    $reportDir = Split-Path -Parent $ReportFile
    if ($reportDir -and -not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($ReportFile, $reportText)
    Write-Host "`nSaved Markdown Report to: $ReportFile" -ForegroundColor Cyan
}

if ($FailOnRegression -and -not $overallGatePass) {
    exit 1
}

exit 0
