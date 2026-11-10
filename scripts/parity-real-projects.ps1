<#
.SYNOPSIS
    Real-project parity harness comparing rnpm against npm 11.20 on Windows.
.DESCRIPTION
    Runs real-world fixtures under benchmarks/fixtures/real-*/ through:
    1. ci --no-audit --no-fund (with lockfile)
    2. install with no lockfile
    3. ls --all
    4. install <one new pkg>
    5. uninstall <pkg>
    6. run <script>
    Compares exit codes, node_modules file lists and hashes, .bin contents,
    package-lock.json (normalized JSON diff), and package.json bytes.
    Fails on any mismatch without tolerance or skip lists.
#>
param(
    [string[]]$Fixtures = @(
        "real-vite-react",
        "real-nextjs",
        "real-express-ts",
        "real-electron",
        "real-monorepo-workspaces",
        "real-git-deps",
        "real-optional-platform",
        "real-peer-conflicts",
        "real-lifecycle-scripts",
        "real-bundled-deps",
        "project-486",
        "real-angular-cli"
    ),
    [switch]$KeepTemp = $false,
    [string]$NewPkg = "is-sorted@1.0.2",
    [string]$UninstallPkg = "is-sorted"
)

$ErrorActionPreference = "Continue"
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$rnpmBin = Join-Path $repoRoot "target\release\rnpm.exe"

if (-not (Test-Path $rnpmBin)) {
    Write-Error "rnpm release binary not found at $rnpmBin. Run 'cargo build --release' first."
    exit 1
}

$npmVer = & npm.cmd --version
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " rnpm Real-Project Parity Sweep Harness" -ForegroundColor Cyan
Write-Host " npm version:  $npmVer" -ForegroundColor Cyan
Write-Host " rnpm binary:  $rnpmBin" -ForegroundColor Cyan
Write-Host " Fixtures:     $($Fixtures -join ', ')" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# Set environment variable to ensure electron doesn't attempt huge binary download
$env:ELECTRON_SKIP_BINARY_DOWNLOAD = "1"

$sweepResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Compare-DirectoryTrees {
    param([string]$PathA, [string]$PathB, [string]$DirLabel = "node_modules")

    if (-not (Test-Path $PathA) -and -not (Test-Path $PathB)) {
        return @{ Identical = $true; Reason = "Both absent"; CountA = 0; CountB = 0 }
    }
    if (-not (Test-Path $PathA) -or -not (Test-Path $PathB)) {
        return @{
            Identical = $false
            Reason = "$DirLabel existence mismatch (A: $(Test-Path $PathA), B: $(Test-Path $PathB))"
            CountA = 0
            CountB = 0
            MissingInRnpm = @()
            MissingInNpm = @()
            HashMismatches = @()
        }
    }

    $nodeScript = @'
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function walk(dir, base, map) {
    if (!fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
        if (e.name.startsWith('.rnpm')) continue;
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
            walk(full, base, map);
        } else if (e.isFile()) {
            const rel = path.relative(base, full).replace(/\\/g, '/');
            const stat = fs.statSync(full);
            map.set(rel, stat.size);
        }
    }
}

const mapA = new Map(), mapB = new Map();
walk(process.argv[1], process.argv[1], mapA);
walk(process.argv[2], process.argv[2], mapB);

const missingInB = [];
const missingInA = [];
const hashMismatches = [];

for (const [k, sizeA] of mapA) {
    if (!mapB.has(k)) {
        missingInB.push(k);
    } else {
        const sizeB = mapB.get(k);
        if (sizeA !== sizeB) {
            hashMismatches.push(k);
        } else {
            const bufA = fs.readFileSync(path.join(process.argv[1], k));
            const bufB = fs.readFileSync(path.join(process.argv[2], k));
            if (!bufA.equals(bufB)) {
                hashMismatches.push(k);
            }
        }
    }
}

for (const k of mapB.keys()) {
    if (!mapA.has(k)) {
        missingInA.push(k);
    }
}

const countA = mapA.size;
const countB = mapB.size;
const identical = missingInB.length === 0 && missingInA.length === 0 && hashMismatches.length === 0;

console.log(JSON.stringify({
    identical,
    countA,
    countB,
    missingInB,
    missingInA,
    hashMismatches
}));
'@

    $jsonStr = & node -e $nodeScript $PathA $PathB
    $res = $jsonStr | ConvertFrom-Json
    if (-not $res.identical) {
        return @{
            Identical = $false
            CountA = $res.countA
            CountB = $res.countB
            MissingInRnpm = $res.missingInB
            MissingInNpm = $res.missingInA
            HashMismatches = $res.hashMismatches
            Reason = "$DirLabel content mismatch (npm: $($res.countA), rnpm: $($res.countB)). Missing in rnpm: $($res.missingInB.Count), missing in npm: $($res.missingInA.Count), hash mismatches: $($res.hashMismatches.Count)"
        }
    }

    return @{ Identical = $true; CountA = $res.countA; CountB = $res.countB; Reason = "Identical ($($res.countA) files)" }
}

function Compare-LockfilesNormalized {
    param([string]$LockA, [string]$LockB)

    if (-not (Test-Path $LockA) -and -not (Test-Path $LockB)) {
        return @{ Identical = $true; Reason = "Both absent" }
    }
    if (-not (Test-Path $LockA) -or -not (Test-Path $LockB)) {
        return @{ Identical = $false; Reason = "One lockfile missing (A: $(Test-Path $LockA), B: $(Test-Path $LockB))" }
    }

    $nodeScript = @'
const fs = require('fs');

function normalize(val) {
    if (val === null || typeof val !== 'object') {
        return val;
    }
    if (Array.isArray(val)) {
        return val.map(normalize);
    }
    const sorted = {};
    for (const key of Object.keys(val).sort()) {
        sorted[key] = normalize(val[key]);
    }
    return sorted;
}

try {
    const jsonA = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
    const jsonB = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
    const normA = JSON.stringify(normalize(jsonA), null, 2);
    const normB = JSON.stringify(normalize(jsonB), null, 2);

    if (normA === normB) {
        console.log(JSON.stringify({ identical: true, reason: 'Identical normalized JSON' }));
    } else {
        // Find top-level package differences
        const pkgsA = Object.keys(jsonA.packages || {});
        const pkgsB = Object.keys(jsonB.packages || {});
        const missingInB = pkgsA.filter(k => !(k in (jsonB.packages || {})));
        const missingInA = pkgsB.filter(k => !(k in (jsonA.packages || {})));
        const diffEntries = [];
        for (const k of pkgsA) {
            if (k in (jsonB.packages || {})) {
                const sA = JSON.stringify(normalize(jsonA.packages[k]));
                const sB = JSON.stringify(normalize(jsonB.packages[k]));
                if (sA !== sB) {
                    diffEntries.push({ key: k, a: jsonA.packages[k], b: jsonB.packages[k] });
                }
            }
        }
        console.log(JSON.stringify({
            identical: false,
            reason: `Normalized lockfile diff (missing in rnpm: ${missingInB.length}, missing in npm: ${missingInA.length}, package entry diffs: ${diffEntries.length})`,
            missingInRnpm: missingInB,
            missingInNpm: missingInA,
            diffEntries: diffEntries.slice(0, 5)
        }));
    }
} catch (e) {
    console.log(JSON.stringify({ identical: false, reason: 'JSON parse error: ' + e.message }));
}
'@

    $jsonStr = & node -e $nodeScript $LockA $LockB
    $res = $jsonStr | ConvertFrom-Json
    return @{
        Identical = $res.identical
        Reason = $res.reason
        MissingInRnpm = $res.missingInRnpm
        MissingInNpm = $res.missingInNpm
        DiffEntries = $res.diffEntries
    }
}

function Compare-PackageJsonBytes {
    param([string]$FileA, [string]$FileB)

    if (-not (Test-Path $FileA) -and -not (Test-Path $FileB)) {
        return @{ Identical = $true; Reason = "Both absent" }
    }
    if (-not (Test-Path $FileA) -or -not (Test-Path $FileB)) {
        return @{ Identical = $false; Reason = "One package.json missing (A: $(Test-Path $FileA), B: $(Test-Path $FileB))" }
    }

    $bytesA = [System.IO.File]::ReadAllBytes($FileA)
    $bytesB = [System.IO.File]::ReadAllBytes($FileB)

    if ($bytesA.Length -ne $bytesB.Length) {
        return @{ Identical = $false; Reason = "package.json size mismatch (npm: $($bytesA.Length) bytes, rnpm: $($bytesB.Length) bytes)" }
    }

    for ($i = 0; $i -lt $bytesA.Length; $i++) {
        if ($bytesA[$i] -ne $bytesB[$i]) {
            return @{ Identical = $false; Reason = "package.json byte mismatch at offset $i" }
        }
    }

    return @{ Identical = $true; Reason = "Identical ($($bytesA.Length) bytes)" }
}

# Run through each fixture sequentially
foreach ($fixtureName in $Fixtures) {
    Write-Host "`n>>> Running Real Project Parity: $fixtureName" -ForegroundColor Yellow
    $fixtureSource = Join-Path $repoRoot "benchmarks\fixtures\$fixtureName"

    if (-not (Test-Path $fixtureSource)) {
        Write-Error "Fixture $fixtureName not found at $fixtureSource"
        $sweepResults.Add([PSCustomObject]@{
            Fixture = $fixtureName
            CI = "NOT_FOUND"
            InstallNoLock = "NOT_FOUND"
            LsAll = "NOT_FOUND"
            InstallPkg = "NOT_FOUND"
            UninstallPkg = "NOT_FOUND"
            RunScript = "NOT_FOUND"
            Overall = "FAIL"
        })
        continue
    }

    $tempBase = Join-Path $env:TEMP "rnpm-real-$fixtureName-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $tempBase -Force | Out-Null

    $ciNpmDir = Join-Path $tempBase "ci-npm"
    $ciRnpmDir = Join-Path $tempBase "ci-rnpm"
    $flowNpmDir = Join-Path $tempBase "flow-npm"
    $flowRnpmDir = Join-Path $tempBase "flow-rnpm"

    New-Item -ItemType Directory -Path $ciNpmDir -Force | Out-Null
    New-Item -ItemType Directory -Path $ciRnpmDir -Force | Out-Null
    New-Item -ItemType Directory -Path $flowNpmDir -Force | Out-Null
    New-Item -ItemType Directory -Path $flowRnpmDir -Force | Out-Null

    $stepCiPass = $false
    $stepInstallPass = $false
    $stepLsPass = $false
    $stepInstallPkgPass = $false
    $stepUninstallPkgPass = $false
    $stepRunScriptPass = $false

    try {
        # ====================================================
        # Phase 1: ci --no-audit --no-fund (with lockfile)
        # ====================================================
        Write-Host "  [Step 1/6] Running ci --no-audit --no-fund..." -ForegroundColor Gray
        Copy-Item -Path "$fixtureSource\*" -Destination $ciNpmDir -Recurse -Force
        Copy-Item -Path "$fixtureSource\*" -Destination $ciRnpmDir -Recurse -Force

        Push-Location $ciNpmDir
        $ciNpmOut = & npm.cmd ci --no-audit --no-fund 2>&1
        $ciNpmExit = $LASTEXITCODE
        Pop-Location

        Push-Location $ciRnpmDir
        $ciRnpmOut = & $rnpmBin ci --no-audit --no-fund 2>&1
        $ciRnpmExit = $LASTEXITCODE
        Pop-Location

        $ciExitMatch = ($ciNpmExit -eq $ciRnpmExit)
        $ciTreeCmp = Compare-DirectoryTrees (Join-Path $ciNpmDir "node_modules") (Join-Path $ciRnpmDir "node_modules") "node_modules"
        $ciBinCmp = Compare-DirectoryTrees (Join-Path $ciNpmDir "node_modules\.bin") (Join-Path $ciRnpmDir "node_modules\.bin") ".bin"
        $ciLockCmp = Compare-LockfilesNormalized (Join-Path $ciNpmDir "package-lock.json") (Join-Path $ciRnpmDir "package-lock.json")
        $ciPkgCmp = Compare-PackageJsonBytes (Join-Path $ciNpmDir "package.json") (Join-Path $ciRnpmDir "package.json")

        $stepCiPass = $ciExitMatch -and $ciTreeCmp.Identical -and $ciBinCmp.Identical -and $ciLockCmp.Identical -and $ciPkgCmp.Identical
        if (-not $stepCiPass) {
            Write-Host "    CI Mismatch details:" -ForegroundColor Red
            Write-Host "      Exit codes: npm=$ciNpmExit, rnpm=$ciRnpmExit (Match: $ciExitMatch)" -ForegroundColor Yellow
            Write-Host "      node_modules: $($ciTreeCmp.Reason)" -ForegroundColor Yellow
            if ($ciTreeCmp.MissingInRnpm) { Write-Host "        Missing in rnpm: $($ciTreeCmp.MissingInRnpm -join ', ')" -ForegroundColor DarkYellow }
            if ($ciTreeCmp.MissingInNpm) { Write-Host "        Missing in npm: $($ciTreeCmp.MissingInNpm -join ', ')" -ForegroundColor DarkYellow }
            if ($ciTreeCmp.HashMismatches) { Write-Host "        Hash mismatches: $($ciTreeCmp.HashMismatches -join ', ')" -ForegroundColor DarkYellow }
            Write-Host "      .bin:         $($ciBinCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      lockfile:     $($ciLockCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      package.json: $($ciPkgCmp.Reason)" -ForegroundColor Yellow
        } else {
            Write-Host "    CI: PASS (exit: $ciNpmExit, tree: $($ciTreeCmp.CountA) files, bin: $($ciBinCmp.CountA) files)" -ForegroundColor Green
        }

        # ====================================================
        # Phase 2: Flow in fresh temp dirs starting with NO lockfile
        # ====================================================
        # Copy fixture but exclude package-lock.json
        Get-ChildItem -Path $fixtureSource | Where-Object { $_.Name -ne "package-lock.json" -and $_.Name -ne "node_modules" } | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $flowNpmDir -Recurse -Force
            Copy-Item -Path $_.FullName -Destination $flowRnpmDir -Recurse -Force
        }

        # Step 2: install with no lockfile
        Write-Host "  [Step 2/6] Running install with no lockfile..." -ForegroundColor Gray
        Push-Location $flowNpmDir
        $installNpmOut = & npm.cmd install --no-audit --no-fund 2>&1
        $installNpmExit = $LASTEXITCODE
        Pop-Location

        Push-Location $flowRnpmDir
        $installRnpmOut = & $rnpmBin install --no-audit --no-fund 2>&1
        $installRnpmExit = $LASTEXITCODE
        Pop-Location

        $instExitMatch = ($installNpmExit -eq $installRnpmExit)
        $instTreeCmp = Compare-DirectoryTrees (Join-Path $flowNpmDir "node_modules") (Join-Path $flowRnpmDir "node_modules") "node_modules"
        $instBinCmp = Compare-DirectoryTrees (Join-Path $flowNpmDir "node_modules\.bin") (Join-Path $flowRnpmDir "node_modules\.bin") ".bin"
        $instLockCmp = Compare-LockfilesNormalized (Join-Path $flowNpmDir "package-lock.json") (Join-Path $flowRnpmDir "package-lock.json")
        $instPkgCmp = Compare-PackageJsonBytes (Join-Path $flowNpmDir "package.json") (Join-Path $flowRnpmDir "package.json")

        $stepInstallPass = $instExitMatch -and $instTreeCmp.Identical -and $instBinCmp.Identical -and $instLockCmp.Identical -and $instPkgCmp.Identical
        if (-not $stepInstallPass) {
            Write-Host "    Install Mismatch details:" -ForegroundColor Red
            Write-Host "      Exit codes: npm=$installNpmExit, rnpm=$installRnpmExit (Match: $instExitMatch)" -ForegroundColor Yellow
            if ($installRnpmExit -ne 0) {
                Write-Host "      rnpm install output: $installRnpmOut" -ForegroundColor DarkRed
            }
            Write-Host "      node_modules: $($instTreeCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      .bin:         $($instBinCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      lockfile:     $($instLockCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      package.json: $($instPkgCmp.Reason)" -ForegroundColor Yellow
        } else {
            Write-Host "    Install: PASS (exit: $installNpmExit, tree: $($instTreeCmp.CountA) files, bin: $($instBinCmp.CountA) files)" -ForegroundColor Green
        }

        # Step 3: ls --all
        Write-Host "  [Step 3/6] Running ls --all..." -ForegroundColor Gray
        Push-Location $flowNpmDir
        $lsNpmOut = & npm.cmd ls --all 2>&1
        $lsNpmExit = $LASTEXITCODE
        Pop-Location

        Push-Location $flowRnpmDir
        $lsRnpmOut = & $rnpmBin ls --all 2>&1
        $lsRnpmExit = $LASTEXITCODE
        Pop-Location

        $stepLsPass = ($lsNpmExit -eq $lsRnpmExit)
        if (-not $stepLsPass) {
            Write-Host "    ls --all Mismatch: npm=$lsNpmExit, rnpm=$lsRnpmExit" -ForegroundColor Red
        } else {
            Write-Host "    ls --all: PASS (exit: $lsNpmExit)" -ForegroundColor Green
        }

        # Step 4: install <one new pkg>
        Write-Host "  [Step 4/6] Running install $NewPkg..." -ForegroundColor Gray
        Push-Location $flowNpmDir
        $addNpmOut = & npm.cmd install $NewPkg --no-audit --no-fund 2>&1
        $addNpmExit = $LASTEXITCODE
        Pop-Location

        Push-Location $flowRnpmDir
        $addRnpmOut = & $rnpmBin install $NewPkg --no-audit --no-fund 2>&1
        $addRnpmExit = $LASTEXITCODE
        Pop-Location

        $addExitMatch = ($addNpmExit -eq $addRnpmExit)
        $addTreeCmp = Compare-DirectoryTrees (Join-Path $flowNpmDir "node_modules") (Join-Path $flowRnpmDir "node_modules") "node_modules"
        $addBinCmp = Compare-DirectoryTrees (Join-Path $flowNpmDir "node_modules\.bin") (Join-Path $flowRnpmDir "node_modules\.bin") ".bin"
        $addLockCmp = Compare-LockfilesNormalized (Join-Path $flowNpmDir "package-lock.json") (Join-Path $flowRnpmDir "package-lock.json")
        $addPkgCmp = Compare-PackageJsonBytes (Join-Path $flowNpmDir "package.json") (Join-Path $flowRnpmDir "package.json")

        $stepInstallPkgPass = $addExitMatch -and $addTreeCmp.Identical -and $addBinCmp.Identical -and $addLockCmp.Identical -and $addPkgCmp.Identical
        if (-not $stepInstallPkgPass) {
            Write-Host "    Install Pkg Mismatch details:" -ForegroundColor Red
            Write-Host "      Exit codes: npm=$addNpmExit, rnpm=$addRnpmExit (Match: $addExitMatch)" -ForegroundColor Yellow
            Write-Host "      node_modules: $($addTreeCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      .bin:         $($addBinCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      lockfile:     $($addLockCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      package.json: $($addPkgCmp.Reason)" -ForegroundColor Yellow
        } else {
            Write-Host "    Install Pkg: PASS (exit: $addNpmExit, tree: $($addTreeCmp.CountA) files)" -ForegroundColor Green
        }

        # Step 5: uninstall <pkg>
        Write-Host "  [Step 5/6] Running uninstall $UninstallPkg..." -ForegroundColor Gray
        Push-Location $flowNpmDir
        $unNpmOut = & npm.cmd uninstall $UninstallPkg --no-audit --no-fund 2>&1
        $unNpmExit = $LASTEXITCODE
        Pop-Location

        Push-Location $flowRnpmDir
        $unRnpmOut = & $rnpmBin uninstall $UninstallPkg --no-audit --no-fund 2>&1
        $unRnpmExit = $LASTEXITCODE
        Pop-Location

        $unExitMatch = ($unNpmExit -eq $unRnpmExit)
        $unTreeCmp = Compare-DirectoryTrees (Join-Path $flowNpmDir "node_modules") (Join-Path $flowRnpmDir "node_modules") "node_modules"
        $unBinCmp = Compare-DirectoryTrees (Join-Path $flowNpmDir "node_modules\.bin") (Join-Path $flowRnpmDir "node_modules\.bin") ".bin"
        $unLockCmp = Compare-LockfilesNormalized (Join-Path $flowNpmDir "package-lock.json") (Join-Path $flowRnpmDir "package-lock.json")
        $unPkgCmp = Compare-PackageJsonBytes (Join-Path $flowNpmDir "package.json") (Join-Path $flowRnpmDir "package.json")

        $stepUninstallPkgPass = $unExitMatch -and $unTreeCmp.Identical -and $unBinCmp.Identical -and $unLockCmp.Identical -and $unPkgCmp.Identical
        if (-not $stepUninstallPkgPass) {
            Write-Host "    Uninstall Pkg Mismatch details:" -ForegroundColor Red
            Write-Host "      Exit codes: npm=$unNpmExit, rnpm=$unRnpmExit (Match: $unExitMatch)" -ForegroundColor Yellow
            Write-Host "      node_modules: $($unTreeCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      .bin:         $($unBinCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      lockfile:     $($unLockCmp.Reason)" -ForegroundColor Yellow
            Write-Host "      package.json: $($unPkgCmp.Reason)" -ForegroundColor Yellow
        } else {
            Write-Host "    Uninstall Pkg: PASS (exit: $unNpmExit, tree: $($unTreeCmp.CountA) files)" -ForegroundColor Green
        }

        # Step 6: run <script>
        $pjContent = Get-Content (Join-Path $flowNpmDir "package.json") -Raw | ConvertFrom-Json
        $scriptName = "test"
        if ($pjContent.scripts -and (-not $pjContent.scripts.test)) {
            $propNames = $pjContent.scripts | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
            if ($propNames.Count -gt 0) { $scriptName = $propNames[0] }
        }

        Write-Host "  [Step 6/6] Running run $scriptName..." -ForegroundColor Gray
        Push-Location $flowNpmDir
        $runNpmOut = & npm.cmd run $scriptName 2>&1
        $runNpmExit = $LASTEXITCODE
        Pop-Location

        Push-Location $flowRnpmDir
        $runRnpmOut = & $rnpmBin run $scriptName 2>&1
        $runRnpmExit = $LASTEXITCODE
        Pop-Location

        $stepRunScriptPass = ($runNpmExit -eq $runRnpmExit)
        if (-not $stepRunScriptPass) {
            Write-Host "    run ${scriptName} Mismatch: npm=$runNpmExit, rnpm=$runRnpmExit" -ForegroundColor Red
        } else {
            Write-Host "    run ${scriptName}: PASS (exit: $runNpmExit)" -ForegroundColor Green
        }

    } finally {
        if (-not $KeepTemp) {
            cmd.exe /c "rd /s /q `"$tempBase`"" 2>$null
            if (Test-Path $tempBase) {
                Remove-Item $tempBase -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $allPass = $stepCiPass -and $stepInstallPass -and $stepLsPass -and $stepInstallPkgPass -and $stepUninstallPkgPass -and $stepRunScriptPass
    $statusStr = if ($allPass) { "PASS" } else { "FAIL" }

    $sweepResults.Add([PSCustomObject]@{
        Fixture = $fixtureName
        CI = if ($stepCiPass) { "PASS" } else { "FAIL" }
        InstallNoLock = if ($stepInstallPass) { "PASS" } else { "FAIL" }
        LsAll = if ($stepLsPass) { "PASS" } else { "FAIL" }
        InstallPkg = if ($stepInstallPkgPass) { "PASS" } else { "FAIL" }
        UninstallPkg = if ($stepUninstallPkgPass) { "PASS" } else { "FAIL" }
        RunScript = if ($stepRunScriptPass) { "PASS" } else { "FAIL" }
        Overall = $statusStr
    })
}

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host " Real Projects Parity Summary Table" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
$sweepResults | Format-Table -Property Fixture, CI, InstallNoLock, LsAll, InstallPkg, UninstallPkg, RunScript, Overall -AutoSize

$failing = @($sweepResults | Where-Object { $_.Overall -ne "PASS" })
if ($failing.Count -gt 0) {
    Write-Host "`n[FAIL] The following fixtures had parity mismatches:" -ForegroundColor Red
    foreach ($f in $failing) {
        Write-Host " - $($f.Fixture)" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "`n[SUCCESS] All real-project fixtures passed parity sweep with 100% fidelity!" -ForegroundColor Green
    exit 0
}
