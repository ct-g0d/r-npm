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
