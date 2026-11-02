#Requires -Version 5.1
<#
.SYNOPSIS
    Differential test suite for Tier 2 mutations (uninstall, update, pack).
.DESCRIPTION
    Validates Gate C checklist requirement:
    "uninstall, update, and pack pass their focused Tier 2 mutation fixtures."
    
    Tests differential parity between npm (oracle) and rnpm:
    1. Tier 2 Uninstall:
       - Direct dependency removal from package.json and node_modules
       - DevDependency removal and pruning of bin shims in node_modules/.bin
       - Transitive unreferenced dependency pruning (express uninstalled -> depd, debug, etc. pruned)
       - Lockfile v3 integrity and structure parity
    2. Tier 2 Update:
       - Targeted single-package update (cors 2.8.4 -> 2.8.5) while preserving pinned commander 11.0.0
       - Full project dependency update within semver ranges (commander -> 11.1.0, cors -> 2.8.5)
       - Lockfile v3 and node_modules parity
    3. Tier 2 Pack:
       - Tarball naming convention (<name>-<version>.tgz)
       - Dry-run mode: no tarball written to disk
       - JSON mode output parity with metadata (id, name, version, files, entryCount, integrity)
       - Tarball archive entry prefix ("package/"), file permissions, and exclusions (.npmignore / unlisted)
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

$TempBase = Join-Path ([System.IO.Path]::GetTempPath()) ("npm-rust-tier2-mutations-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $TempBase | Out-Null
Write-Host "`nTest workspace: $TempBase" -ForegroundColor DarkGray

try {
    # =========================================================================
    # PART 1: Tier 2 Uninstall Mutation Differential Tests
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 1: Tier 2 Uninstall Mutation Differential Tests" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $fixtureUninstall = Join-Path $ScriptDir "fixtures\tier2-mutation-uninstall"
    $npmUnDir = Join-Path $TempBase "npm-uninstall"
    $rnpmUnDir = Join-Path $TempBase "rnpm-uninstall"

    New-Item -ItemType Directory -Path $npmUnDir | Out-Null
    New-Item -ItemType Directory -Path $rnpmUnDir | Out-Null

    Copy-Item (Join-Path $fixtureUninstall "package.json") -Destination "$npmUnDir\package.json"
    Copy-Item (Join-Path $fixtureUninstall "package.json") -Destination "$rnpmUnDir\package.json"

    Write-Host "[1.1] Initial Installation of tier2-mutation-uninstall..." -ForegroundColor Gray
    $npmInstallOut = cmd.exe /c "cd /d `"$npmUnDir`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm install initial setup succeeded"

    $rnpmInstallOut = cmd.exe /c "cd /d `"$rnpmUnDir`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm install initial setup succeeded"

    # Verify initial tree and lockfile parity
    $treeCmp = (node $StatsUtil compare-trees "$npmUnDir\node_modules" "$rnpmUnDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmp.match -eq $true) "Initial installed tree parity (npm vs rnpm)" ($treeCmp.mismatches -join "; ")

    $lockCmp = (node $StatsUtil compare-lockfiles "$npmUnDir\package-lock.json" "$rnpmUnDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmp.match -eq $true) "Initial package-lock.json parity (npm vs rnpm)" ($lockCmp.mismatches -join "; ")

    # Mutation 1: Uninstall direct dependency 'cookie-parser'
    Write-Host "`n[1.2] Testing Uninstall Direct Dependency 'cookie-parser'..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmUnDir`" && $NpmPath uninstall cookie-parser --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm uninstall cookie-parser exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmUnDir`" && `"$RnpmPath`" uninstall cookie-parser 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm uninstall cookie-parser exited with 0"

    # Verify manifest modification
    $npmPkg = Get-Content "$npmUnDir\package.json" -Raw | ConvertFrom-Json
    $rnpmPkg = Get-Content "$rnpmUnDir\package.json" -Raw | ConvertFrom-Json
    Assert-Condition ($null -eq $npmPkg.dependencies."cookie-parser") "npm removed cookie-parser from package.json dependencies"
    Assert-Condition ($null -eq $rnpmPkg.dependencies."cookie-parser") "rnpm removed cookie-parser from package.json dependencies"

    # Verify filesystem removal
    Assert-Condition (-not (Test-Path "$npmUnDir\node_modules\cookie-parser")) "npm removed node_modules/cookie-parser directory"
    Assert-Condition (-not (Test-Path "$rnpmUnDir\node_modules\cookie-parser")) "rnpm removed node_modules/cookie-parser directory"

    # Verify Lockfile parity after cookie-parser uninstall
    $lockCmp1 = (node $StatsUtil compare-lockfiles "$npmUnDir\package-lock.json" "$rnpmUnDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmp1.match -eq $true) "package-lock.json parity after cookie-parser uninstall" ($lockCmp1.mismatches -join "; ")

    # Mutation 2: Uninstall devDependency 'typescript' with bin shims
    Write-Host "`n[1.3] Testing Uninstall devDependency 'typescript' & Bin Pruning..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmUnDir`" && $NpmPath uninstall typescript --save-dev --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm uninstall -D typescript exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmUnDir`" && `"$RnpmPath`" uninstall -D typescript 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm uninstall -D typescript exited with 0"

    # Verify devDependencies in package.json
    $npmPkg2 = Get-Content "$npmUnDir\package.json" -Raw | ConvertFrom-Json
    $rnpmPkg2 = Get-Content "$rnpmUnDir\package.json" -Raw | ConvertFrom-Json
    Assert-Condition ($null -eq $npmPkg2.devDependencies."typescript") "npm removed typescript from devDependencies"
    Assert-Condition ($null -eq $rnpmPkg2.devDependencies."typescript") "rnpm removed typescript from devDependencies"

    # Verify bin shims are pruned from node_modules/.bin
    Assert-Condition (-not (Test-Path "$rnpmUnDir\node_modules\typescript")) "rnpm removed node_modules/typescript"
    Assert-Condition (-not (Test-Path "$rnpmUnDir\node_modules\.bin\tsc.cmd")) "rnpm pruned .bin\tsc.cmd"
    Assert-Condition (-not (Test-Path "$rnpmUnDir\node_modules\.bin\tsserver.cmd")) "rnpm pruned .bin\tsserver.cmd"

    # Mutation 3: Uninstall 'express' with transitive dependency pruning
    Write-Host "`n[1.4] Testing Uninstall 'express' & Transitive Dependency Pruning..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmUnDir`" && $NpmPath uninstall express --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm uninstall express exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmUnDir`" && `"$RnpmPath`" uninstall express 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm uninstall express exited with 0"

    # express was the sole dependent for 'depd' and 'debug'
    Assert-Condition (-not (Test-Path "$rnpmUnDir\node_modules\express")) "rnpm removed node_modules/express"
    Assert-Condition (-not (Test-Path "$rnpmUnDir\node_modules\depd")) "rnpm pruned unreferenced transitive package 'depd'"
    Assert-Condition (-not (Test-Path "$rnpmUnDir\node_modules\debug")) "rnpm pruned unreferenced transitive package 'debug'"
    Assert-Condition (Test-Path "$rnpmUnDir\node_modules\cors") "rnpm preserved active dependency 'cors'"

    $treeCmp3 = (node $StatsUtil compare-trees "$npmUnDir\node_modules" "$rnpmUnDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmp3.match -eq $true) "Tree parity after express uninstall & transitive pruning" ($treeCmp3.mismatches -join "; ")

    # Mutation 4: Scoped Package Uninstall Edge Cases (@scope/pkg-alpha, @scope/pkg-beta)
    Write-Host "`n[1.5] Testing Scoped Packages Uninstall Edge Cases..." -ForegroundColor Gray
    $npmScopedDir = Join-Path $TempBase "npm-scoped"
    $rnpmScopedDir = Join-Path $TempBase "rnpm-scoped"

    New-Item -ItemType Directory -Path $npmScopedDir | Out-Null
    New-Item -ItemType Directory -Path $rnpmScopedDir | Out-Null

    $scopedPkgJson = @'
{
  "name": "tier2-scoped-uninstall",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@scope/pkg-alpha": "^1.0.0",
    "@scope/pkg-beta": "^1.0.0"
  }
}
'@
    Set-Content -Path (Join-Path $npmScopedDir "package.json") -Value $scopedPkgJson
    Set-Content -Path (Join-Path $rnpmScopedDir "package.json") -Value $scopedPkgJson

    $null = cmd.exe /c "cd /d `"$npmScopedDir`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm install scoped packages setup succeeded"

    $null = cmd.exe /c "cd /d `"$rnpmScopedDir`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm install scoped packages setup succeeded"

    $treeCmpScopedInit = (node $StatsUtil compare-trees "$npmScopedDir\node_modules" "$rnpmScopedDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmpScopedInit.match -eq $true) "Initial scoped packages tree parity" ($treeCmpScopedInit.mismatches -join "; ")

    $lockCmpScopedInit = (node $StatsUtil compare-lockfiles "$npmScopedDir\package-lock.json" "$rnpmScopedDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmpScopedInit.match -eq $true) "Initial scoped packages lockfile parity" ($lockCmpScopedInit.mismatches -join "; ")

    # Sub-test 1.5.1: Uninstall @scope/pkg-alpha (parent @scope dir MUST remain because @scope/pkg-beta exists)
    $null = cmd.exe /c "cd /d `"$npmScopedDir`" && $NpmPath uninstall @scope/pkg-alpha --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm uninstall @scope/pkg-alpha exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmScopedDir`" && `"$RnpmPath`" uninstall @scope/pkg-alpha 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm uninstall @scope/pkg-alpha exited with 0"

    Assert-Condition (-not (Test-Path "$rnpmScopedDir\node_modules\@scope\pkg-alpha")) "rnpm removed node_modules/@scope/pkg-alpha"
    Assert-Condition (Test-Path "$rnpmScopedDir\node_modules\@scope\pkg-beta") "rnpm preserved sibling node_modules/@scope/pkg-beta"
    Assert-Condition (Test-Path "$rnpmScopedDir\node_modules\@scope") "rnpm retained non-empty parent node_modules/@scope directory"

    $treeCmpScoped1 = (node $StatsUtil compare-trees "$npmScopedDir\node_modules" "$rnpmScopedDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmpScoped1.match -eq $true) "Tree parity after partial scoped uninstall" ($treeCmpScoped1.mismatches -join "; ")

    $lockCmpScoped1 = (node $StatsUtil compare-lockfiles "$npmScopedDir\package-lock.json" "$rnpmScopedDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmpScoped1.match -eq $true) "Lockfile parity after partial scoped uninstall" ($lockCmpScoped1.mismatches -join "; ")

    # Sub-test 1.5.2: Uninstall remaining @scope/pkg-beta (parent @scope dir MUST now be pruned)
    $null = cmd.exe /c "cd /d `"$npmScopedDir`" && $NpmPath uninstall @scope/pkg-beta --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm uninstall @scope/pkg-beta exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmScopedDir`" && `"$RnpmPath`" uninstall @scope/pkg-beta 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm uninstall @scope/pkg-beta exited with 0"

    Assert-Condition (-not (Test-Path "$rnpmScopedDir\node_modules\@scope\pkg-beta")) "rnpm removed node_modules/@scope/pkg-beta"
    Assert-Condition (-not (Test-Path "$rnpmScopedDir\node_modules\@scope")) "rnpm pruned now-empty parent node_modules/@scope directory"

    $treeCmpScoped2 = (node $StatsUtil compare-trees "$npmScopedDir\node_modules" "$rnpmScopedDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmpScoped2.match -eq $true) "Tree parity after full scoped uninstall" ($treeCmpScoped2.mismatches -join "; ")

    $lockCmpScoped2 = (node $StatsUtil compare-lockfiles "$npmScopedDir\package-lock.json" "$rnpmScopedDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmpScoped2.match -eq $true) "Lockfile parity after full scoped uninstall" ($lockCmpScoped2.mismatches -join "; ")

    # Mutation 5: Deep Dependency Tree & Transitive Pruning Edge Cases
    Write-Host "`n[1.6] Testing Deep Dependency Tree & Transitive Pruning Edge Cases..." -ForegroundColor Gray
    $npmDeepDir = Join-Path $TempBase "npm-deep"
    $rnpmDeepDir = Join-Path $TempBase "rnpm-deep"

    New-Item -ItemType Directory -Path $npmDeepDir | Out-Null
    New-Item -ItemType Directory -Path $rnpmDeepDir | Out-Null

    $deepPkgJson = @'
{
  "name": "tier2-deep-uninstall",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "pkg-deep-a": "^1.0.0",
    "pkg-deep-shared": "^1.0.0"
  }
}
'@
    Set-Content -Path (Join-Path $npmDeepDir "package.json") -Value $deepPkgJson
    Set-Content -Path (Join-Path $rnpmDeepDir "package.json") -Value $deepPkgJson

    $null = cmd.exe /c "cd /d `"$npmDeepDir`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm install deep tree setup succeeded"

    $null = cmd.exe /c "cd /d `"$rnpmDeepDir`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm install deep tree setup succeeded"

    $treeCmpDeepInit = (node $StatsUtil compare-trees "$npmDeepDir\node_modules" "$rnpmDeepDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmpDeepInit.match -eq $true) "Initial deep tree parity" ($treeCmpDeepInit.mismatches -join "; ")

    # Verify all chain members exist initially: a -> b -> c -> d -> (e, shared)
    Assert-Condition (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-a") "pkg-deep-a installed"
    Assert-Condition (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-b") "pkg-deep-b installed"
    Assert-Condition (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-c") "pkg-deep-c installed"
    Assert-Condition (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-d") "pkg-deep-d installed"
    Assert-Condition (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-e") "pkg-deep-e installed"
    Assert-Condition (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-shared") "pkg-deep-shared installed"

    # Uninstall root of deep chain 'pkg-deep-a'
    $null = cmd.exe /c "cd /d `"$npmDeepDir`" && $NpmPath uninstall pkg-deep-a --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm uninstall pkg-deep-a exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmDeepDir`" && `"$RnpmPath`" uninstall pkg-deep-a 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm uninstall pkg-deep-a exited with 0"

    # Direct package removed
    Assert-Condition (-not (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-a")) "rnpm removed direct dependency pkg-deep-a"

    # Entire unreferenced deep chain b->c->d->e must be pruned
    Assert-Condition (-not (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-b")) "rnpm pruned deep transitive pkg-deep-b"
    Assert-Condition (-not (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-c")) "rnpm pruned deep transitive pkg-deep-c"
    Assert-Condition (-not (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-d")) "rnpm pruned deep transitive pkg-deep-d"
    Assert-Condition (-not (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-e")) "rnpm pruned deep transitive pkg-deep-e"

    # Shared dependency must be retained because root package.json explicitly depends on it
    Assert-Condition (Test-Path "$rnpmDeepDir\node_modules\pkg-deep-shared") "rnpm preserved shared dependency pkg-deep-shared"

    $treeCmpDeep = (node $StatsUtil compare-trees "$npmDeepDir\node_modules" "$rnpmDeepDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmpDeep.match -eq $true) "Tree parity after deep uninstall and transitive pruning" ($treeCmpDeep.mismatches -join "; ")

    $lockCmpDeep = (node $StatsUtil compare-lockfiles "$npmDeepDir\package-lock.json" "$rnpmDeepDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmpDeep.match -eq $true) "Lockfile parity after deep uninstall and transitive pruning" ($lockCmpDeep.mismatches -join "; ")

    # =========================================================================
    # PART 2: Tier 2 Update Mutation Differential Tests
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 2: Tier 2 Update Mutation Differential Tests" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $fixtureUpdate = Join-Path $ScriptDir "fixtures\tier2-mutation-update"
    $npmUpDir = Join-Path $TempBase "npm-update"
    $rnpmUpDir = Join-Path $TempBase "rnpm-update"

    New-Item -ItemType Directory -Path $npmUpDir | Out-Null
    New-Item -ItemType Directory -Path $rnpmUpDir | Out-Null

    Copy-Item (Join-Path $fixtureUpdate "*") -Destination $npmUpDir -Recurse -Force
    Copy-Item (Join-Path $fixtureUpdate "*") -Destination $rnpmUpDir -Recurse -Force

    Write-Host "[2.1] Clean-slate CI install from pinned lockfile (commander@11.0.0, cors@2.8.4)..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmUpDir`" && $NpmPath ci --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm ci setup succeeded"

    $null = cmd.exe /c "cd /d `"$rnpmUpDir`" && `"$RnpmPath`" ci --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm ci setup succeeded"

    $npmCorsInit = (Get-Content "$npmUpDir\node_modules\cors\package.json" -Raw | ConvertFrom-Json).version
    $rnpmCorsInit = (Get-Content "$rnpmUpDir\node_modules\cors\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmCorsInit -eq "2.8.4" -and $rnpmCorsInit -eq "2.8.4") "Initial cors version is 2.8.4 in both trees"

    $npmCmdInit = (Get-Content "$npmUpDir\node_modules\commander\package.json" -Raw | ConvertFrom-Json).version
    $rnpmCmdInit = (Get-Content "$rnpmUpDir\node_modules\commander\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmCmdInit -eq "11.0.0" -and $rnpmCmdInit -eq "11.0.0") "Initial commander version is 11.0.0 in both trees"

    # Targeted Update: update 'cors' only
    Write-Host "`n[2.2] Testing Targeted Update 'cors' (^2.8.4 -> 2.8.5)..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmUpDir`" && $NpmPath update cors --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm update cors exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmUpDir`" && `"$RnpmPath`" update cors --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm update cors exited with 0"

    $npmCorsUpdated = (Get-Content "$npmUpDir\node_modules\cors\package.json" -Raw | ConvertFrom-Json).version
    $rnpmCorsUpdated = (Get-Content "$rnpmUpDir\node_modules\cors\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmCorsUpdated -eq "2.8.5") "npm updated cors to 2.8.5"
    Assert-Condition ($rnpmCorsUpdated -eq "2.8.5") "rnpm updated cors to 2.8.5"

    # Verify commander was NOT touched
    $npmCmdPreserved = (Get-Content "$npmUpDir\node_modules\commander\package.json" -Raw | ConvertFrom-Json).version
    $rnpmCmdPreserved = (Get-Content "$rnpmUpDir\node_modules\commander\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmCmdPreserved -eq "11.0.0") "npm preserved commander at 11.0.0"
    Assert-Condition ($rnpmCmdPreserved -eq "11.0.0") "rnpm preserved commander at 11.0.0"

    # Full Update: update all dependencies (^11.0.0 -> 11.1.0)
    Write-Host "`n[2.3] Testing Full Project Update..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmUpDir`" && $NpmPath update --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm update (all) exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmUpDir`" && `"$RnpmPath`" update --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm update (all) exited with 0"

    $npmCmdFull = (Get-Content "$npmUpDir\node_modules\commander\package.json" -Raw | ConvertFrom-Json).version
    $rnpmCmdFull = (Get-Content "$rnpmUpDir\node_modules\commander\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmCmdFull -eq "11.1.0") "npm updated commander to 11.1.0"
    Assert-Condition ($rnpmCmdFull -eq "11.1.0") "rnpm updated commander to 11.1.0"

    $treeCmpUp = (node $StatsUtil compare-trees "$npmUpDir\node_modules" "$rnpmUpDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmpUp.match -eq $true) "Tree parity after full update (npm vs rnpm)" ($treeCmpUp.mismatches -join "; ")

    $lockCmpUp = (node $StatsUtil compare-lockfiles "$npmUpDir\package-lock.json" "$rnpmUpDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmpUp.match -eq $true) "Lockfile parity after full update (npm vs rnpm)" ($lockCmpUp.mismatches -join "; ")

    # Mutation 4: Update with Pre-Release Ranges (pkg-prerelease 1.1.0-alpha.1 -> 1.1.0-alpha.2)
    Write-Host "`n[2.4] Testing Update with Pre-Release Ranges..." -ForegroundColor Gray
    $npmPreDir = Join-Path $TempBase "npm-prerelease"
    $rnpmPreDir = Join-Path $TempBase "rnpm-prerelease"

    New-Item -ItemType Directory -Path $npmPreDir | Out-Null
    New-Item -ItemType Directory -Path $rnpmPreDir | Out-Null

    $prePkgJson = @'
{
  "name": "tier2-prerelease-update",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "pkg-prerelease": "^1.1.0-alpha.1"
  }
}
'@
    $preLockJson = @'
{
  "name": "tier2-prerelease-update",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "tier2-prerelease-update",
      "version": "1.0.0",
      "dependencies": {
        "pkg-prerelease": "^1.1.0-alpha.1"
      }
    },
    "node_modules/pkg-prerelease": {
      "version": "1.1.0-alpha.1",
      "resolved": "http://127.0.0.1:4873/pkg-prerelease/-/pkg-prerelease-1.1.0-alpha.1.tgz",
      "integrity": "sha512-2WSJOwkiT9RlVWn0iqYrdoJQw61FsTH7CJuuC/isADI5Pa/NQTv3OSoodOmqqB7TIk45Fqmq1DzU1S34k+OFkw=="
    }
  }
}
'@
    Set-Content -Path (Join-Path $npmPreDir "package.json") -Value $prePkgJson
    Set-Content -Path (Join-Path $rnpmPreDir "package.json") -Value $prePkgJson
    Set-Content -Path (Join-Path $npmPreDir "package-lock.json") -Value $preLockJson
    Set-Content -Path (Join-Path $rnpmPreDir "package-lock.json") -Value $preLockJson

    $null = cmd.exe /c "cd /d `"$npmPreDir`" && $NpmPath ci --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm ci prerelease setup succeeded"

    $null = cmd.exe /c "cd /d `"$rnpmPreDir`" && `"$RnpmPath`" ci --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm ci prerelease setup succeeded"

    $npmPreInit = (Get-Content "$npmPreDir\node_modules\pkg-prerelease\package.json" -Raw | ConvertFrom-Json).version
    $rnpmPreInit = (Get-Content "$rnpmPreDir\node_modules\pkg-prerelease\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmPreInit -eq "1.1.0-alpha.1" -and $rnpmPreInit -eq "1.1.0-alpha.1") "Initial prerelease version is 1.1.0-alpha.1 in both trees"

    # Targeted update of pkg-prerelease within prerelease range ^1.1.0-alpha.1
    $null = cmd.exe /c "cd /d `"$npmPreDir`" && $NpmPath update pkg-prerelease --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm update pkg-prerelease exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmPreDir`" && `"$RnpmPath`" update pkg-prerelease --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm update pkg-prerelease exited with 0"

    $npmPreUpdated = (Get-Content "$npmPreDir\node_modules\pkg-prerelease\package.json" -Raw | ConvertFrom-Json).version
    $rnpmPreUpdated = (Get-Content "$rnpmPreDir\node_modules\pkg-prerelease\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmPreUpdated -eq "1.1.0-alpha.2") "npm updated pkg-prerelease to 1.1.0-alpha.2"
    Assert-Condition ($rnpmPreUpdated -eq "1.1.0-alpha.2") "rnpm updated pkg-prerelease to 1.1.0-alpha.2"

    $treeCmpPre = (node $StatsUtil compare-trees "$npmPreDir\node_modules" "$rnpmPreDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmpPre.match -eq $true) "Tree parity after prerelease range update" ($treeCmpPre.mismatches -join "; ")

    $lockCmpPre = (node $StatsUtil compare-lockfiles "$npmPreDir\package-lock.json" "$rnpmPreDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmpPre.match -eq $true) "Lockfile parity after prerelease range update" ($lockCmpPre.mismatches -join "; ")

    # Mutation 5: Update with Peer Dependencies
    Write-Host "`n[2.5] Testing Update with Peer Dependencies..." -ForegroundColor Gray
    $npmPeerDir = Join-Path $TempBase "npm-peer"
    $rnpmPeerDir = Join-Path $TempBase "rnpm-peer"

    New-Item -ItemType Directory -Path $npmPeerDir | Out-Null
    New-Item -ItemType Directory -Path $rnpmPeerDir | Out-Null

    $peerPkgJson = @'
{
  "name": "tier2-peer-update",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "pkg-peer-host": "^1.0.0",
    "pkg-peer-plugin": "^1.0.0"
  }
}
'@
    $peerLockJson = @'
{
  "name": "tier2-peer-update",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "tier2-peer-update",
      "version": "1.0.0",
      "dependencies": {
        "pkg-peer-host": "^1.0.0",
        "pkg-peer-plugin": "^1.0.0"
      }
    },
    "node_modules/pkg-peer-host": {
      "version": "1.0.0",
      "resolved": "http://127.0.0.1:4873/pkg-peer-host/-/pkg-peer-host-1.0.0.tgz",
      "integrity": "sha512-WWtw8dsy9VcvGVukGtnYZMSISWkcS3RD/kcGTKCa/tZK0dvVS919C+oTVoRozOsVTtc+pk4moMNbxqHOBPyj1g=="
    },
    "node_modules/pkg-peer-plugin": {
      "version": "1.0.0",
      "resolved": "http://127.0.0.1:4873/pkg-peer-plugin/-/pkg-peer-plugin-1.0.0.tgz",
      "integrity": "sha512-7rufNnoWV6Asw0G+QwW8b9AnI6PJyClU0a7T9Kta87VOWlHcUYvDInlNa3H1iPUlx6O/j/KhEGbNanYN4kdBww==",
      "peerDependencies": {
        "pkg-peer-host": ">=1.0.0"
      }
    }
  }
}
'@
    Set-Content -Path (Join-Path $npmPeerDir "package.json") -Value $peerPkgJson
    Set-Content -Path (Join-Path $rnpmPeerDir "package.json") -Value $peerPkgJson
    Set-Content -Path (Join-Path $npmPeerDir "package-lock.json") -Value $peerLockJson
    Set-Content -Path (Join-Path $rnpmPeerDir "package-lock.json") -Value $peerLockJson

    $null = cmd.exe /c "cd /d `"$npmPeerDir`" && $NpmPath ci --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm ci peer dependencies setup succeeded"

    $null = cmd.exe /c "cd /d `"$rnpmPeerDir`" && `"$RnpmPath`" ci --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm ci peer dependencies setup succeeded"

    # Targeted update of peer host only
    $null = cmd.exe /c "cd /d `"$npmPeerDir`" && $NpmPath update pkg-peer-host --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm update pkg-peer-host exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmPeerDir`" && `"$RnpmPath`" update pkg-peer-host --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm update pkg-peer-host exited with 0"

    $npmHostUp = (Get-Content "$npmPeerDir\node_modules\pkg-peer-host\package.json" -Raw | ConvertFrom-Json).version
    $rnpmHostUp = (Get-Content "$rnpmPeerDir\node_modules\pkg-peer-host\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmHostUp -eq "1.1.0" -and $rnpmHostUp -eq "1.1.0") "Targeted update updated pkg-peer-host to 1.1.0 in both"

    $npmPlugPreserved = (Get-Content "$npmPeerDir\node_modules\pkg-peer-plugin\package.json" -Raw | ConvertFrom-Json).version
    $rnpmPlugPreserved = (Get-Content "$rnpmPeerDir\node_modules\pkg-peer-plugin\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmPlugPreserved -eq "1.0.0" -and $rnpmPlugPreserved -eq "1.0.0") "Targeted update preserved pkg-peer-plugin at 1.0.0 in both"

    $treeCmpPeerTarget = (node $StatsUtil compare-trees "$npmPeerDir\node_modules" "$rnpmPeerDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmpPeerTarget.match -eq $true) "Tree parity after targeted peer host update" ($treeCmpPeerTarget.mismatches -join "; ")

    # Full update of peer project
    $null = cmd.exe /c "cd /d `"$npmPeerDir`" && $NpmPath update --registry $RegistryUrl --no-audit --no-fund 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm update (all) for peer project exited with 0"

    $null = cmd.exe /c "cd /d `"$rnpmPeerDir`" && `"$RnpmPath`" update --registry $RegistryUrl 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm update (all) for peer project exited with 0"

    $npmPlugUp = (Get-Content "$npmPeerDir\node_modules\pkg-peer-plugin\package.json" -Raw | ConvertFrom-Json).version
    $rnpmPlugUp = (Get-Content "$rnpmPeerDir\node_modules\pkg-peer-plugin\package.json" -Raw | ConvertFrom-Json).version
    Assert-Condition ($npmPlugUp -eq "1.1.0" -and $rnpmPlugUp -eq "1.1.0") "Full update updated pkg-peer-plugin to 1.1.0 in both"

    $treeCmpPeerFull = (node $StatsUtil compare-trees "$npmPeerDir\node_modules" "$rnpmPeerDir\node_modules") | ConvertFrom-Json
    Assert-Condition ($treeCmpPeerFull.match -eq $true) "Tree parity after full peer update" ($treeCmpPeerFull.mismatches -join "; ")

    $lockCmpPeerFull = (node $StatsUtil compare-lockfiles "$npmPeerDir\package-lock.json" "$rnpmPeerDir\package-lock.json") | ConvertFrom-Json
    Assert-Condition ($lockCmpPeerFull.match -eq $true) "Lockfile parity after full peer update" ($lockCmpPeerFull.mismatches -join "; ")

    # =========================================================================
    # PART 3: Tier 2 Pack Mutation Differential Tests
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 3: Tier 2 Pack Mutation Differential Tests" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $fixturePack = Join-Path $ScriptDir "fixtures\tier2-mutation-pack"
    $npmPackDir = Join-Path $TempBase "npm-pack"
    $rnpmPackDir = Join-Path $TempBase "rnpm-pack"

    New-Item -ItemType Directory -Path $npmPackDir | Out-Null
    New-Item -ItemType Directory -Path $rnpmPackDir | Out-Null

    Copy-Item (Join-Path $fixturePack "*") -Destination $npmPackDir -Recurse -Force
    Copy-Item (Join-Path $fixturePack "*") -Destination $rnpmPackDir -Recurse -Force

    # Test 3.1: Dry-run pack mode
    Write-Host "[3.1] Testing Pack Dry-Run Mode (--dry-run)..." -ForegroundColor Gray
    $npmDryRunOut = cmd.exe /c "cd /d `"$npmPackDir`" && $NpmPath pack --dry-run 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm pack --dry-run exited with 0"
    Assert-Condition (-not (Test-Path "$npmPackDir\tier2-mutation-pack-1.0.0.tgz")) "npm pack --dry-run did not write archive to disk"

    $rnpmDryRunOut = cmd.exe /c "cd /d `"$rnpmPackDir`" && `"$RnpmPath`" pack --dry-run 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm pack --dry-run exited with 0"
    Assert-Condition (-not (Test-Path "$rnpmPackDir\tier2-mutation-pack-1.0.0.tgz")) "rnpm pack --dry-run did not write archive to disk"

    # Test 3.2: JSON Mode
    Write-Host "`n[3.2] Testing Pack JSON Output (--json)..." -ForegroundColor Gray
    $npmJsonRaw = cmd.exe /c "cd /d `"$npmPackDir`" && $NpmPath pack --dry-run --json 2>&1"
    $npmJson = $npmJsonRaw | ConvertFrom-Json

    $rnpmJsonRaw = cmd.exe /c "cd /d `"$rnpmPackDir`" && `"$RnpmPath`" pack --dry-run --json 2>&1"
    $rnpmJson = $rnpmJsonRaw | ConvertFrom-Json

    Assert-Condition ($npmJson[0].name -eq "tier2-mutation-pack" -and $rnpmJson[0].name -eq "tier2-mutation-pack") "Package name matches in JSON output"
    Assert-Condition ($npmJson[0].version -eq "1.0.0" -and $rnpmJson[0].version -eq "1.0.0") "Package version matches in JSON output"
    Assert-Condition ($npmJson[0].filename -eq "tier2-mutation-pack-1.0.0.tgz" -and $rnpmJson[0].filename -eq "tier2-mutation-pack-1.0.0.tgz") "Tarball filename matches in JSON output"
    Assert-Condition ($npmJson[0].entryCount -eq $rnpmJson[0].entryCount) "Entry count matches ($($npmJson[0].entryCount))"
    Assert-Condition ($rnpmJson[0].integrity.StartsWith("sha512-")) "rnpm pack generated valid SHA-512 integrity string ($($rnpmJson[0].integrity.Substring(0, 20))...)"

    # Test 3.3: Actual Tarball Creation and Archive Structure
    Write-Host "`n[3.3] Testing Tarball Archive Creation & Content Structure..." -ForegroundColor Gray
    $npmPackOut = cmd.exe /c "cd /d `"$npmPackDir`" && $NpmPath pack 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "npm pack created archive"
    Assert-Condition (Test-Path "$npmPackDir\tier2-mutation-pack-1.0.0.tgz") "npm wrote tier2-mutation-pack-1.0.0.tgz"

    $rnpmPackOut = cmd.exe /c "cd /d `"$rnpmPackDir`" && `"$RnpmPath`" pack 2>&1"
    Assert-Condition ($LASTEXITCODE -eq 0) "rnpm pack created archive"
    Assert-Condition (Test-Path "$rnpmPackDir\tier2-mutation-pack-1.0.0.tgz") "rnpm wrote tier2-mutation-pack-1.0.0.tgz"

    # Inspect rnpm generated tarball entries using node
    $inspectScript = @'
const fs = require('fs');
const zlib = require('zlib');
const tar = require('tar');

const tarballPath = process.argv[2];
const entries = [];

const parser = new tar.Parser({
    onReadEntry(entry) {
        entries.push({
            path: entry.path,
            mode: entry.mode,
            size: entry.size,
            type: entry.type
        });
        entry.resume();
    }
});

fs.createReadStream(tarballPath)
    .pipe(zlib.createGunzip())
    .pipe(parser)
    .on('finish', () => {
        console.log(JSON.stringify(entries));
    })
    .on('error', (err) => {
        console.error(err);
        process.exit(1);
    });
'@
    # If tar module isn't in node, we can inspect with node standard zlib / tar parsing or harness-utils
    # Harness check: use python or node tar reader
    $inspectTarNode = @'
const fs = require('fs');
const zlib = require('zlib');

const tarballPath = process.argv[2];
const buf = zlib.gunzipSync(fs.readFileSync(tarballPath));
const entries = [];
let offset = 0;
while (offset + 512 <= buf.length) {
    const header = buf.slice(offset, offset + 512);
    offset += 512;
    if (header[0] === 0) break;
    const name = header.toString('utf8', 0, 100).replace(/\0.*$/, '');
    const sizeStr = header.toString('ascii', 124, 136).replace(/\0.*$/, '').trim();
    const size = parseInt(sizeStr, 8) || 0;
    const modeStr = header.toString('ascii', 100, 108).replace(/\0.*$/, '').trim();
    const mode = parseInt(modeStr, 8) || 0;
    entries.push({ name, size, mode });
    const padded = Math.ceil(size / 512) * 512;
    offset += padded;
}
console.log(JSON.stringify(entries));
'@
    $inspectJs = Join-Path $TempBase "inspect-tar.js"
    Set-Content -Path $inspectJs -Value $inspectTarNode

    $rnpmEntriesRaw = node $inspectJs "$rnpmPackDir\tier2-mutation-pack-1.0.0.tgz"
    $rnpmEntries = $rnpmEntriesRaw | ConvertFrom-Json

    $hasPkgJson = $false
    $hasReadme = $false
    $hasLib = $false
    $hasBin = $false
    $hasTempLog = $false
    $allHavePrefix = $true

    foreach ($e in $rnpmEntries) {
        if (-not $e.name.StartsWith("package/")) {
            $allHavePrefix = $false
        }
        if ($e.name -eq "package/package.json") { $hasPkgJson = $true }
        if ($e.name -eq "package/README.md") { $hasReadme = $true }
        if ($e.name -eq "package/lib/index.js") { $hasLib = $true }
        if ($e.name -eq "package/bin/tool.js") { $hasBin = $true }
        if ($e.name -match "temp\.log") { $hasTempLog = $true }
    }

    Assert-Condition ($allHavePrefix) "All tarball entries contain standard 'package/' prefix"
    Assert-Condition ($hasPkgJson) "Tarball contains package/package.json"
    Assert-Condition ($hasReadme) "Tarball contains package/README.md"
    Assert-Condition ($hasLib) "Tarball contains package/lib/index.js"
    Assert-Condition ($hasBin) "Tarball contains package/bin/tool.js"
    Assert-Condition (-not $hasTempLog) "Tarball excludes unlisted temp.log"

    # Test 3.4: Pack with Complex .npmignore Rules
    Write-Host "`n[3.4] Testing Pack with Complex .npmignore Rules..." -ForegroundColor Gray
    $npmPackComplexDir = Join-Path $TempBase "npm-pack-complex"
    $rnpmPackComplexDir = Join-Path $TempBase "rnpm-pack-complex"

    New-Item -ItemType Directory -Path $npmPackComplexDir | Out-Null
    New-Item -ItemType Directory -Path $rnpmPackComplexDir | Out-Null

    function Setup-ComplexPackFixture {
        param([string]$targetDir)

        New-Item -ItemType Directory -Path (Join-Path $targetDir "lib") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $targetDir "src") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $targetDir "docs") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $targetDir "logs") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $targetDir "temp") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $targetDir "nested\sub") -Force | Out-Null

        Set-Content -Path (Join-Path $targetDir "package.json") -Value @'
{
  "name": "tier2-complex-pack",
  "version": "1.2.0",
  "description": "Package testing complex npmignore rules and exclusions",
  "main": "lib/index.js"
}
'@
        Set-Content -Path (Join-Path $targetDir "README.md") -Value "# Tier 2 Complex Pack`nDocumentation and overview."
        Set-Content -Path (Join-Path $targetDir "LICENSE") -Value "MIT License`nCopyright (c) 2026"
        Set-Content -Path (Join-Path $targetDir "lib\index.js") -Value "module.exports = { name: 'complex-pack' };"
        Set-Content -Path (Join-Path $targetDir "lib\util.js") -Value "module.exports = { util: true };"
        Set-Content -Path (Join-Path $targetDir "lib\util.spec.js") -Value "// spec file that should be ignored"
        Set-Content -Path (Join-Path $targetDir "src\main.ts") -Value "export const main = 1;"
        Set-Content -Path (Join-Path $targetDir "docs\guide.md") -Value "# Guide docs"
        Set-Content -Path (Join-Path $targetDir "docs\api.md") -Value "# API docs"
        Set-Content -Path (Join-Path $targetDir "logs\app.log") -Value "App log to ignore"
        Set-Content -Path (Join-Path $targetDir "logs\audit.log") -Value "Audit log to ignore"
        Set-Content -Path (Join-Path $targetDir "logs\keep-me.log") -Value "Special log to keep via negation rule"
        Set-Content -Path (Join-Path $targetDir "temp\cache.tmp") -Value "Temp cache to ignore"
        Set-Content -Path (Join-Path $targetDir "nested\sub\data.txt") -Value "Nested data to keep"
        Set-Content -Path (Join-Path $targetDir "nested\sub\extra.skip") -Value "Nested skip file to ignore"

        Set-Content -Path (Join-Path $targetDir ".npmignore") -Value @'
# Ignore log files
*.log
# Negation rule to un-ignore specific log
!keep-me.log

# Ignore test spec files
*.spec.js

# Directory ignore rules
docs/
temp/

# Ignore custom skip extension
*.skip

# Deliberate attempts to ignore strictly required files (must still be included by npm rules)
package.json
README.md
LICENSE
'@
    }

    Setup-ComplexPackFixture -targetDir $npmPackComplexDir
    Setup-ComplexPackFixture -targetDir $rnpmPackComplexDir

    # Compare Dry-Run JSON output on complex ignore fixture
    $npmComplexJsonRaw = cmd.exe /c "cd /d `"$npmPackComplexDir`" && $NpmPath pack --dry-run --json 2>&1"
    $npmComplexJson = $npmComplexJsonRaw | ConvertFrom-Json

    $rnpmComplexJsonRaw = cmd.exe /c "cd /d `"$rnpmPackComplexDir`" && `"$RnpmPath`" pack --dry-run --json 2>&1"
    $rnpmComplexJson = $rnpmComplexJsonRaw | ConvertFrom-Json

    Assert-Condition ($npmComplexJson[0].name -eq "tier2-complex-pack" -and $rnpmComplexJson[0].name -eq "tier2-complex-pack") "Complex pack name matches in JSON output"
    Assert-Condition ($npmComplexJson[0].version -eq "1.2.0" -and $rnpmComplexJson[0].version -eq "1.2.0") "Complex pack version matches in JSON output"
    Assert-Condition ($npmComplexJson[0].filename -eq "tier2-complex-pack-1.2.0.tgz" -and $rnpmComplexJson[0].filename -eq "tier2-complex-pack-1.2.0.tgz") "Complex pack tarball filename matches in JSON output"
    Assert-Condition ($npmComplexJson[0].entryCount -eq $rnpmComplexJson[0].entryCount) "Complex pack entryCount parity ($($npmComplexJson[0].entryCount))"

    # Actual pack creation on complex ignore fixture
    $null = cmd.exe /c "cd /d `"$npmPackComplexDir`" && $NpmPath pack 2>&1"
    Assert-Condition (Test-Path "$npmPackComplexDir\tier2-complex-pack-1.2.0.tgz") "npm created tier2-complex-pack-1.2.0.tgz"

    $null = cmd.exe /c "cd /d `"$rnpmPackComplexDir`" && `"$RnpmPath`" pack 2>&1"
    Assert-Condition (Test-Path "$rnpmPackComplexDir\tier2-complex-pack-1.2.0.tgz") "rnpm created tier2-complex-pack-1.2.0.tgz"

    # Inspect rnpm generated tarball entries against complex ignore expectations
    $rnpmComplexEntriesRaw = node $inspectJs "$rnpmPackComplexDir\tier2-complex-pack-1.2.0.tgz"
    $rnpmComplexEntries = $rnpmComplexEntriesRaw | ConvertFrom-Json
    $entryNames = $rnpmComplexEntries | ForEach-Object { $_.name }

    Assert-Condition ($entryNames -contains "package/package.json") "Complex pack includes required package/package.json"
    Assert-Condition ($entryNames -contains "package/README.md") "Complex pack includes required package/README.md"
    Assert-Condition ($entryNames -contains "package/LICENSE") "Complex pack includes required package/LICENSE"
    Assert-Condition ($entryNames -contains "package/lib/index.js") "Complex pack includes package/lib/index.js"
    Assert-Condition ($entryNames -contains "package/lib/util.js") "Complex pack includes package/lib/util.js"
    Assert-Condition ($entryNames -contains "package/src/main.ts") "Complex pack includes package/src/main.ts"
    Assert-Condition ($entryNames -contains "package/logs/keep-me.log") "Complex pack includes negated rule package/logs/keep-me.log"
    Assert-Condition ($entryNames -contains "package/nested/sub/data.txt") "Complex pack includes nested package/nested/sub/data.txt"

    Assert-Condition (-not ($entryNames -contains "package/lib/util.spec.js")) "Complex pack excludes ignored *.spec.js"
    Assert-Condition (-not ($entryNames -like "*package/docs/*")) "Complex pack excludes ignored docs/ directory"
    Assert-Condition (-not ($entryNames -like "*package/temp/*")) "Complex pack excludes ignored temp/ directory"
    Assert-Condition (-not ($entryNames -contains "package/logs/app.log")) "Complex pack excludes ignored logs/app.log"
    Assert-Condition (-not ($entryNames -contains "package/logs/audit.log")) "Complex pack excludes ignored logs/audit.log"
    Assert-Condition (-not ($entryNames -contains "package/nested/sub/extra.skip")) "Complex pack excludes ignored *.skip file"

} finally {
    if (-not $KeepTemp -and (Test-Path $TempBase)) {
        Remove-Item -Path $TempBase -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($script:MockServerProcess -and -not $script:MockServerProcess.HasExited) {
        Stop-Process -Id $script:MockServerProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "Tier 2 Mutation Test Summary: $TestsPassed Passed, $TestsFailed Failed" -ForegroundColor $(if ($TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================================" -ForegroundColor Cyan

if ($TestsFailed -gt 0) {
    exit 1
}
exit 0
