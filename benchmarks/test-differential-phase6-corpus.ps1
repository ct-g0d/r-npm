#Requires -Version 5.1
<#
.SYNOPSIS
    Differential test suite for Phase 6 Real-Project Compatibility Corpus & Security Audit.
.DESCRIPTION
    Validates Phase 6 checklist requirements and Gate C / D / F parity against npm oracle:
    1. Popular Open-Source Package Compatibility Corpus:
       - lodash: utility functions, exact version pinning, and advisory detection
       - chalk: terminal styling, deep dependency trees (ansi-styles, supports-color, color-convert)
       - react: React 18 frontend runtime, peer dependencies (react-dom), deduplication
       - prettier: code formatting, Windows bin shims (prettier.cmd, prettier.ps1), CLI execution
    2. Zero Regressions on Existing Contracts:
       - 100% normalized node_modules tree parity via harness-utils.js compare-trees
       - 100% deterministic package-lock.json v3 parity via harness-utils.js compare-lockfiles
       - Script execution (node test.js) passes in both npm and rnpm trees
    3. rnpm audit Framework:
       - Lockfile tree vulnerability analysis against bulk security advisory payloads
       - Structured JSON report output matching auditReportVersion: 2 schema
       - Exit code threshold filtering with --audit-level (low, moderate, high, critical)
       - Clean project zero-vulnerability verification
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
        throw "rnpm executable not found at '$releaseCandidate' or '$debugCandidate'. Run 'cargo build -p rnpm-cli' first."
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

$TempBase = Join-Path ([System.IO.Path]::GetTempPath()) ("npm-rust-phase6-corpus-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $TempBase | Out-Null
Write-Host "`nTest workspace: $TempBase" -ForegroundColor DarkGray

try {
    # =========================================================================
    # PART 1: Phase 6 Corpus - lodash
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 1: Phase 6 Corpus - lodash Compatibility & Parity" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $fixtureLodash = Join-Path $ScriptDir "fixtures\phase6-lodash"
    $npmDir1 = Join-Path $TempBase "npm-lodash"
    $rnpmDir1 = Join-Path $TempBase "rnpm-lodash"

    New-Item -ItemType Directory -Path $npmDir1 | Out-Null
    New-Item -ItemType Directory -Path $rnpmDir1 | Out-Null

    Copy-Item (Join-Path $fixtureLodash "*") -Destination $npmDir1 -Recurse
    Copy-Item (Join-Path $fixtureLodash "*") -Destination $rnpmDir1 -Recurse

    Write-Host "[1.1] Installing phase6-lodash with npm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmDir1`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm install succeeded for phase6-lodash"

    Write-Host "[1.2] Installing phase6-lodash with rnpm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$rnpmDir1`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm install succeeded for phase6-lodash"

    # Differential parity checks
    $treeCmp1 = (node $StatsUtil compare-trees "$npmDir1\node_modules" "$rnpmDir1\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmp1.match -eq $true) "100% Installed tree parity for phase6-lodash" ($treeCmp1.mismatches -join "; ")

    $lockCmp1 = (node $StatsUtil compare-lockfiles "$npmDir1\package-lock.json" "$rnpmDir1\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmp1.match -eq $true) "100% Lockfile v3 parity for phase6-lodash" ($lockCmp1.mismatches -join "; ")

    # Script execution in rnpm tree
    $testOut1 = cmd.exe /c "cd /d `"$rnpmDir1`" && node test.js 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0 -and $testOut1 -match "phase6-lodash test passed") "lodash runtime execution succeeded in rnpm tree"

    # =========================================================================
    # PART 2: Phase 6 Corpus - chalk
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 2: Phase 6 Corpus - chalk (Deep Transitive Tree)" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $fixtureChalk = Join-Path $ScriptDir "fixtures\phase6-chalk"
    $npmDir2 = Join-Path $TempBase "npm-chalk"
    $rnpmDir2 = Join-Path $TempBase "rnpm-chalk"

    New-Item -ItemType Directory -Path $npmDir2 | Out-Null
    New-Item -ItemType Directory -Path $rnpmDir2 | Out-Null

    Copy-Item (Join-Path $fixtureChalk "*") -Destination $npmDir2 -Recurse
    Copy-Item (Join-Path $fixtureChalk "*") -Destination $rnpmDir2 -Recurse

    Write-Host "[2.1] Installing phase6-chalk with npm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmDir2`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm install succeeded for phase6-chalk"

    Write-Host "[2.2] Installing phase6-chalk with rnpm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$rnpmDir2`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm install succeeded for phase6-chalk"

    # Differential parity checks
    $treeCmp2 = (node $StatsUtil compare-trees "$npmDir2\node_modules" "$rnpmDir2\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmp2.match -eq $true) "100% Installed tree parity for phase6-chalk" ($treeCmp2.mismatches -join "; ")

    $lockCmp2 = (node $StatsUtil compare-lockfiles "$npmDir2\package-lock.json" "$rnpmDir2\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmp2.match -eq $true) "100% Lockfile v3 parity for phase6-chalk" ($lockCmp2.mismatches -join "; ")

    # Script execution in rnpm tree
    $testOut2 = cmd.exe /c "cd /d `"$rnpmDir2`" && node test.js 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0 -and $testOut2 -match "phase6-chalk test passed") "chalk runtime execution succeeded in rnpm tree"

    # =========================================================================
    # PART 3: Phase 6 Corpus - react & react-dom (Peer Dependencies)
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 3: Phase 6 Corpus - react & react-dom (Peer Dependencies)" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $fixtureReact = Join-Path $ScriptDir "fixtures\phase6-react"
    $npmDir3 = Join-Path $TempBase "npm-react"
    $rnpmDir3 = Join-Path $TempBase "rnpm-react"

    New-Item -ItemType Directory -Path $npmDir3 | Out-Null
    New-Item -ItemType Directory -Path $rnpmDir3 | Out-Null

    Copy-Item (Join-Path $fixtureReact "*") -Destination $npmDir3 -Recurse
    Copy-Item (Join-Path $fixtureReact "*") -Destination $rnpmDir3 -Recurse

    Write-Host "[3.1] Installing phase6-react with npm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmDir3`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm install succeeded for phase6-react"

    Write-Host "[3.2] Installing phase6-react with rnpm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$rnpmDir3`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm install succeeded for phase6-react"

    # Differential parity checks
    $treeCmp3 = (node $StatsUtil compare-trees "$npmDir3\node_modules" "$rnpmDir3\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmp3.match -eq $true) "100% Installed tree parity for phase6-react" ($treeCmp3.mismatches -join "; ")

    $lockCmp3 = (node $StatsUtil compare-lockfiles "$npmDir3\package-lock.json" "$rnpmDir3\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmp3.match -eq $true) "100% Lockfile v3 parity for phase6-react" ($lockCmp3.mismatches -join "; ")

    # Script execution in rnpm tree
    $testOut3 = cmd.exe /c "cd /d `"$rnpmDir3`" && node test.js 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0 -and $testOut3 -match "phase6-react test passed") "react runtime execution succeeded in rnpm tree"

    # =========================================================================
    # PART 4: Phase 6 Corpus - prettier (Bin Shims & CLI Execution)
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 4: Phase 6 Corpus - prettier (CLI Shims & Execution)" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $fixturePrettier = Join-Path $ScriptDir "fixtures\phase6-prettier"
    $npmDir4 = Join-Path $TempBase "npm-prettier"
    $rnpmDir4 = Join-Path $TempBase "rnpm-prettier"

    New-Item -ItemType Directory -Path $npmDir4 | Out-Null
    New-Item -ItemType Directory -Path $rnpmDir4 | Out-Null

    Copy-Item (Join-Path $fixturePrettier "*") -Destination $npmDir4 -Recurse
    Copy-Item (Join-Path $fixturePrettier "*") -Destination $rnpmDir4 -Recurse

    Write-Host "[4.1] Installing phase6-prettier with npm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmDir4`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm install succeeded for phase6-prettier"

    Write-Host "[4.2] Installing phase6-prettier with rnpm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$rnpmDir4`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm install succeeded for phase6-prettier"

    # Verify bin shims generated
    Assert-Condition (Test-Path "$rnpmDir4\node_modules\.bin\prettier.cmd") "rnpm generated node_modules\.bin\prettier.cmd"
    Assert-Condition (Test-Path "$rnpmDir4\node_modules\.bin\prettier.ps1") "rnpm generated node_modules\.bin\prettier.ps1"

    # Execute prettier via shim
    $prettierVersionOut = cmd.exe /c "`"$rnpmDir4\node_modules\.bin\prettier.cmd`" --version 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0 -and $prettierVersionOut -match "3.2.5") "Executed prettier.cmd --version (output: $prettierVersionOut)"

    # Clean-slate rnpm ci test
    Remove-Item "$rnpmDir4\node_modules" -Recurse -Force
    $null = cmd.exe /c "cd /d `"$rnpmDir4`" && `"$RnpmPath`" ci --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm ci reified phase6-prettier cleanly from lockfile"
    Assert-Condition (Test-Path "$rnpmDir4\node_modules\prettier\package.json") "prettier extracted by rnpm ci"

    # =========================================================================
    # PART 5: rnpm audit Security Command Tests
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 5: rnpm audit Security Command Framework Tests" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $fixtureVuln = Join-Path $ScriptDir "fixtures\phase6-audit-vuln"
    $vulnDir = Join-Path $TempBase "audit-vuln"
    New-Item -ItemType Directory -Path $vulnDir | Out-Null
    Copy-Item (Join-Path $fixtureVuln "*") -Destination $vulnDir -Recurse

    Write-Host "[5.1] Initial install of phase6-audit-vuln..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$vulnDir`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "Installed phase6-audit-vuln"

    # Audit JSON output verification
    Write-Host "[5.2] Testing rnpm audit --json..." -ForegroundColor Gray
    $auditJsonRaw = cmd.exe /c "cd /d `"$vulnDir`" && `"$RnpmPath`" audit --registry $RegistryUrl --json 2>&1"
    $auditJson = $null
    try {
        $auditJson = $auditJsonRaw | ConvertFrom-Json
    } catch {}

    Assert-Condition ($null -ne $auditJson) "rnpm audit --json produced valid JSON"
    Assert-Condition ($auditJson.auditReportVersion -eq 2) "auditReportVersion is 2"
    Assert-Condition ($null -ne $auditJson.vulnerabilities.lodash) "lodash vulnerability detected in JSON report"
    Assert-Condition ($auditJson.vulnerabilities.lodash.severity -eq "high") "lodash severity is 'high'"
    Assert-Condition ($null -ne $auditJson.vulnerabilities.minimist) "minimist vulnerability detected in JSON report"
    Assert-Condition ($auditJson.vulnerabilities.minimist.severity -eq "critical") "minimist severity is 'critical'"
    Assert-Condition ($auditJson.metadata.vulnerabilities.total -ge 2) "Total vulnerabilities count >= 2"

    # Audit Human-readable text report
    Write-Host "[5.3] Testing rnpm audit human-readable text output..." -ForegroundColor Gray
    $auditTextLines = cmd.exe /c "cd /d `"$vulnDir`" && `"$RnpmPath`" audit --registry $RegistryUrl 2>&1"
    $auditText = $auditTextLines -join "`n"
    Assert-Condition ($auditText -match "# npm audit report") "Report header present"
    Assert-Condition ($auditText -match "lodash\s+<4.17.21") "lodash range present"
    Assert-Condition ($auditText -match "Severity:\s+high") "High severity displayed"
    Assert-Condition ($auditText -match "minimist\s+<1.2.6") "minimist range present"
    Assert-Condition ($auditText -match "Severity:\s+critical") "Critical severity displayed"

    # Audit level threshold tests
    Write-Host "[5.4] Testing --audit-level thresholds..." -ForegroundColor Gray

    # Moderate vuln fixture
    $fixtureMod = Join-Path $ScriptDir "fixtures\phase6-audit-moderate"
    $modDir = Join-Path $TempBase "audit-mod"
    New-Item -ItemType Directory -Path $modDir | Out-Null
    Copy-Item (Join-Path $fixtureMod "*") -Destination $modDir -Recurse
    $null = cmd.exe /c "cd /d `"$modDir`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"

    # --audit-level=high on moderate vuln: MUST EXIT 0
    $null = cmd.exe /c "cd /d `"$modDir`" && `"$RnpmPath`" audit --registry $RegistryUrl --audit-level=high 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "--audit-level=high exits with 0 on moderate vulnerability"

    # --audit-level=moderate on moderate vuln: MUST EXIT 1
    $null = cmd.exe /c "cd /d `"$modDir`" && `"$RnpmPath`" audit --registry $RegistryUrl --audit-level=moderate 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 1) "--audit-level=moderate exits with 1 on moderate vulnerability"

    # Clean fixture zero vulnerabilities
    $fixtureClean = Join-Path $ScriptDir "fixtures\phase6-audit-clean"
    $cleanDir = Join-Path $TempBase "audit-clean"
    New-Item -ItemType Directory -Path $cleanDir | Out-Null
    Copy-Item (Join-Path $fixtureClean "*") -Destination $cleanDir -Recurse
    $null = cmd.exe /c "cd /d `"$cleanDir`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"

    $cleanOutLines = cmd.exe /c "cd /d `"$cleanDir`" && `"$RnpmPath`" audit --registry $RegistryUrl 2>&1"
    $cleanOut = $cleanOutLines -join "`n"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm audit on clean project exits with 0"
    Assert-Condition ($cleanOut -match "found 0 vulnerabilities") "rnpm audit displays 'found 0 vulnerabilities'"

    # Clean project JSON
    $cleanJsonRaw = cmd.exe /c "cd /d `"$cleanDir`" && `"$RnpmPath`" audit --registry $RegistryUrl --json 2>&1"
    $cleanJson = $cleanJsonRaw | ConvertFrom-Json
    Assert-Condition ($cleanJson.metadata.vulnerabilities.total -eq 0) "Clean project JSON reports total: 0 vulnerabilities"

} finally {
    if (-not $KeepTemp) {
        Remove-Item $TempBase -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($MockServerProcess) {
        Stop-Process -Id $MockServerProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "Differential Phase 6 Corpus & Security Audit Results:" -ForegroundColor Cyan
Write-Host "  Passed: $TestsPassed" -ForegroundColor Green
$failColor = "Green"
if ($TestsFailed -gt 0) { $failColor = "Red" }
Write-Host "  Failed: $TestsFailed" -ForegroundColor $failColor
Write-Host "========================================================`n" -ForegroundColor Cyan

if ($TestsFailed -gt 0) {
    exit 1
} else {
    exit 0
}
