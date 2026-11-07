param(
    [string[]]$Scenarios = @(
        "audit-fix",
        "install-lockfile",
        "resolve-no-lockfile",
        "version-updates",
        "workspaces",
        "overrides",
        "git-file-deps",
        "uninstall-dedupe-prune"
    ),
    [switch]$KeepTemp = $false
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
Write-Host " rnpm Parity Gate Harness" -ForegroundColor Cyan
Write-Host " npm version:  $npmVer" -ForegroundColor Cyan
Write-Host " rnpm binary:  $rnpmBin" -ForegroundColor Cyan
Write-Host " Scenarios:    $($Scenarios -join ', ')" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$gateResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Compare-Directories {
    param([string]$PathA, [string]$PathB, [string]$ExcludePattern = "^\.rnpm")
    
    if (-not (Test-Path $PathA) -and -not (Test-Path $PathB)) {
        return @{ Identical = $true; Reason = "Both absent" }
    }
    if (-not (Test-Path $PathA) -or -not (Test-Path $PathB)) {
        return @{ Identical = $false; Reason = "One directory missing (A: $(Test-Path $PathA), B: $(Test-Path $PathB))" }
    }

    $filesA = Get-ChildItem -Path $PathA -Recurse -File | Where-Object { $_.FullName -notmatch [regex]::Escape($PathA) + "[\\/]\.rnpm" }
    $filesB = Get-ChildItem -Path $PathB -Recurse -File | Where-Object { $_.FullName -notmatch [regex]::Escape($PathB) + "[\\/]\.rnpm" }

    $mapA = @{}
    foreach ($f in $filesA) {
        $rel = $f.FullName.Substring($PathA.Length).TrimStart('\', '/')
        $mapA[$rel] = $f.Length
    }

    $mapB = @{}
    foreach ($f in $filesB) {
        $rel = $f.FullName.Substring($PathB.Length).TrimStart('\', '/')
        $mapB[$rel] = $f.Length
    }

    $missingInB = @()
    foreach ($k in $mapA.Keys) {
        if (-not $mapB.ContainsKey($k)) {
            $missingInB += $k
        }
    }

    $missingInA = @()
    foreach ($k in $mapB.Keys) {
        if (-not $mapA.ContainsKey($k)) {
            $missingInA += $k
        }
    }

    if ($missingInB.Count -gt 0 -or $missingInA.Count -gt 0) {
        $pkgsA = $missingInB | ForEach-Object { ($_ -split '[\\/]')[0] } | Select-Object -Unique
        $pkgsB = $missingInA | ForEach-Object { ($_ -split '[\\/]')[0] } | Select-Object -Unique
        if ($pkgsA) { Write-Host "    Missing in rnpm: $($pkgsA -join ', ')" -ForegroundColor DarkYellow }
        if ($pkgsB) { Write-Host "    Missing in npm: $($pkgsB -join ', ')" -ForegroundColor DarkYellow }
        return @{
            Identical = $false
            CountA = $mapA.Count
            CountB = $mapB.Count
            MissingInRnpm = $missingInB
            MissingInNpm = $missingInA
            Reason = "File count mismatch (npm: $($mapA.Count), rnpm: $($mapB.Count)). Missing in rnpm: $($missingInB.Count), missing in npm: $($missingInA.Count)"
        }
    }

    return @{ Identical = $true; Count = $mapA.Count }
}

function Compare-FilesByteForByte {
    param([string]$FileA, [string]$FileB)

    if (-not (Test-Path $FileA) -and -not (Test-Path $FileB)) {
        return @{ Identical = $true; Reason = "Both absent" }
    }
    if (-not (Test-Path $FileA) -or -not (Test-Path $FileB)) {
        return @{ Identical = $false; Reason = "One file missing (A: $(Test-Path $FileA), B: $(Test-Path $FileB))" }
    }

    $bytesA = [System.IO.File]::ReadAllBytes($FileA)
    $bytesB = [System.IO.File]::ReadAllBytes($FileB)

    if ($bytesA.Length -ne $bytesB.Length) {
        return @{ Identical = $false; Reason = "Size mismatch (A: $($bytesA.Length) bytes, B: $($bytesB.Length) bytes)" }
    }

    for ($i = 0; $i -lt $bytesA.Length; $i++) {
        if ($bytesA[$i] -ne $bytesB[$i]) {
            return @{ Identical = $false; Reason = "Byte mismatch at offset $i (A: 0x$($bytesA[$i].ToString('X2')), B: 0x$($bytesB[$i].ToString('X2')))" }
        }
    }

    return @{ Identical = $true; Size = $bytesA.Length }
}

function Run-GateCheck {
    param(
        [string]$ScenarioName,
        [scriptblock]$SetupBlock,
        [scriptblock]$NpmCommand,
        [scriptblock]$RnpmCommand
    )

    Write-Host "`n>>> Running Gate Scenario: $ScenarioName" -ForegroundColor Yellow
    $tempBase = Join-Path $env:TEMP "rnpm-gate-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    $npmDir = Join-Path $tempBase "npm-run"
    $rnpmDir = Join-Path $tempBase "rnpm-run"
    New-Item -ItemType Directory -Path $npmDir -Force | Out-Null
    New-Item -ItemType Directory -Path $rnpmDir -Force | Out-Null

    try {
        & $SetupBlock -NpmDir $npmDir -RnpmDir $rnpmDir

        Write-Host "  -> Running npm 11..." -ForegroundColor Gray
        Push-Location $npmDir
        try {
            & $NpmCommand -TargetDir $npmDir
        } finally {
            Pop-Location
        }

        Write-Host "  -> Running rnpm..." -ForegroundColor Gray
        Push-Location $rnpmDir
        try {
            & $RnpmCommand -TargetDir $rnpmDir -RnpmBin $rnpmBin
        } finally {
            Pop-Location
        }

        # Check 1: node_modules file tree identical (excluding .rnpm*)
        $nmA = Join-Path $npmDir "node_modules"
        $nmB = Join-Path $rnpmDir "node_modules"
        $treeCmp = Compare-Directories $nmA $nmB
        $c1 = $treeCmp.Identical

        # Check 2: package-lock.json byte-identical
        $lockA = Join-Path $npmDir "package-lock.json"
        $lockB = Join-Path $rnpmDir "package-lock.json"
        $lockCmp = Compare-FilesByteForByte $lockA $lockB
        $c2 = $lockCmp.Identical

        # Check 3: node_modules/.package-lock.json byte-identical
        $hLockA = Join-Path $npmDir "node_modules\.package-lock.json"
        $hLockB = Join-Path $rnpmDir "node_modules\.package-lock.json"
        $hLockCmp = Compare-FilesByteForByte $hLockA $hLockB
        $c3 = $hLockCmp.Identical

        # Check 4: npm ls --all exits 0 on rnpm's tree
        Push-Location $rnpmDir
        $lsOut = & npm.cmd ls --all 2>&1
        $lsExit = $LASTEXITCODE
        Pop-Location
        $c4 = ($lsExit -eq 0)

        # Check 5: Both npm ci and rnpm ci succeed on fresh copy of rnpm's output
        $ciTestDirNpm = Join-Path $tempBase "ci-test-npm"
        $ciTestDirRnpm = Join-Path $tempBase "ci-test-rnpm"
        New-Item -ItemType Directory -Path $ciTestDirNpm -Force | Out-Null
        New-Item -ItemType Directory -Path $ciTestDirRnpm -Force | Out-Null
        Get-ChildItem -Path $rnpmDir | Where-Object { $_.Name -ne "node_modules" } | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $ciTestDirNpm -Recurse
            Copy-Item -Path $_.FullName -Destination $ciTestDirRnpm -Recurse
        }

        Push-Location $ciTestDirNpm
        & npm.cmd ci 2>&1 | Out-Null
        $npmCiExit = $LASTEXITCODE
        Pop-Location

        Push-Location $ciTestDirRnpm
        & $rnpmBin ci 2>&1 | Out-Null
        $rnpmCiExit = $LASTEXITCODE
        Pop-Location
        $c5 = ($npmCiExit -eq 0 -and $rnpmCiExit -eq 0)

        $allPass = $c1 -and $c2 -and $c3 -and $c4 -and $c5
        $statusStr = if ($allPass) { "PASS" } else { "FAIL" }
        $color = if ($allPass) { "Green" } else { "Red" }

        Write-Host "  Result: $statusStr" -ForegroundColor $color
        Write-Host "    [1] node_modules identical:      $c1 ($($treeCmp.Reason))"
        Write-Host "    [2] package-lock byte-identical:  $c2 ($($lockCmp.Reason))"
        Write-Host "    [3] hidden-lock byte-identical:   $c3 ($($hLockCmp.Reason))"
        Write-Host "    [4] npm ls --all exit 0:          $c4 (exit code $lsExit)"
        Write-Host "    [5] npm ci & rnpm ci succeed:     $c5 (npm: $npmCiExit, rnpm: $rnpmCiExit)"

        $gateResults.Add([PSCustomObject]@{
            Scenario = $ScenarioName
            Status = $statusStr
            NodeModulesIdentical = $c1
            LockfileByteIdentical = $c2
            HiddenLockByteIdentical = $c3
            NpmLsZero = $c4
            CiSucceeds = $c5
            Details = @{
                Tree = $treeCmp
                Lock = $lockCmp
                HiddenLock = $hLockCmp
                LsExit = $lsExit
                NpmCiExit = $npmCiExit
                RnpmCiExit = $rnpmCiExit
            }
        })
    } finally {
        if (-not $KeepTemp) {
            Remove-Item $tempBase -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ----------------------------------------------------
# Scenario 1: audit fix (vulnerable project)
# ----------------------------------------------------
if ($Scenarios -contains "audit-fix") {
    Run-GateCheck -ScenarioName "audit fix" -SetupBlock {
        param($NpmDir, $RnpmDir)
        $vulnFixture = Join-Path $repoRoot "benchmarks\fixtures\vulnerable-project"
        Copy-Item (Join-Path $vulnFixture "package.json") $NpmDir
        Copy-Item (Join-Path $vulnFixture "package-lock.json") $NpmDir
        Copy-Item (Join-Path $vulnFixture "package.json") $RnpmDir
        Copy-Item (Join-Path $vulnFixture "package-lock.json") $RnpmDir
    } -NpmCommand {
        param($TargetDir)
        & npm.cmd audit fix 2>&1 | Out-Null
    } -RnpmCommand {
        param($TargetDir, $RnpmBin)
        & $RnpmBin audit fix 2>&1 | Out-Null
    }
}

# ----------------------------------------------------
# Scenario 2: Install from lockfile (project-486)
# ----------------------------------------------------
if ($Scenarios -contains "install-lockfile") {
    Run-GateCheck -ScenarioName "Install from lockfile" -SetupBlock {
        param($NpmDir, $RnpmDir)
        $p486 = Join-Path $repoRoot "benchmarks\fixtures\project-486"
        Copy-Item (Join-Path $p486 "package.json") $NpmDir
        Copy-Item (Join-Path $p486 "package-lock.json") $NpmDir
        Copy-Item (Join-Path $p486 "package.json") $RnpmDir
        Copy-Item (Join-Path $p486 "package-lock.json") $RnpmDir
    } -NpmCommand {
        param($TargetDir)
        & npm.cmd install 2>&1 | Out-Null
    } -RnpmCommand {
        param($TargetDir, $RnpmBin)
        & $RnpmBin install 2>&1 | Out-Null
    }
}

# ----------------------------------------------------
# Scenario 3: Resolve with no lockfile
# ----------------------------------------------------
if ($Scenarios -contains "resolve-no-lockfile") {
    Run-GateCheck -ScenarioName "Resolve with no lockfile" -SetupBlock {
        param($NpmDir, $RnpmDir)
        $pkgJson = @"
{
  "name": "resolve-bare-test",
  "version": "1.0.0",
  "dependencies": {
    "axios": "^1.6.7",
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  }
}
"@
        [System.IO.File]::WriteAllText((Join-Path $NpmDir "package.json"), $pkgJson.Replace("`r`n", "`n"))
        [System.IO.File]::WriteAllText((Join-Path $RnpmDir "package.json"), $pkgJson.Replace("`r`n", "`n"))
    } -NpmCommand {
        param($TargetDir)
        & npm.cmd install 2>&1 | Out-Null
    } -RnpmCommand {
        param($TargetDir, $RnpmBin)
        & $RnpmBin install 2>&1 | Out-Null
    }
}

# ----------------------------------------------------
# Scenario 4: Version updates
# ----------------------------------------------------
if ($Scenarios -contains "version-updates") {
    Run-GateCheck -ScenarioName "Version updates" -SetupBlock {
        param($NpmDir, $RnpmDir)
        $p486 = Join-Path $repoRoot "benchmarks\fixtures\project-486"
        Copy-Item (Join-Path $p486 "package.json") $NpmDir
        Copy-Item (Join-Path $p486 "package-lock.json") $NpmDir
        Copy-Item (Join-Path $p486 "package.json") $RnpmDir
        Copy-Item (Join-Path $p486 "package-lock.json") $RnpmDir
    } -NpmCommand {
        param($TargetDir)
        & npm.cmd update axios 2>&1 | Out-Null
    } -RnpmCommand {
        param($TargetDir, $RnpmBin)
        & $RnpmBin update axios 2>&1 | Out-Null
    }
}

# ----------------------------------------------------
# Scenario 5: Workspaces
# ----------------------------------------------------
if ($Scenarios -contains "workspaces") {
    Run-GateCheck -ScenarioName "Workspaces" -SetupBlock {
        param($NpmDir, $RnpmDir)
        $wsFixture = Join-Path $repoRoot "benchmarks\fixtures\extreme-monorepo-50"
        Copy-Item -Path "$wsFixture\*" -Destination $NpmDir -Recurse
        Copy-Item -Path "$wsFixture\*" -Destination $RnpmDir -Recurse
    } -NpmCommand {
        param($TargetDir)
        & npm.cmd install 2>&1 | Out-Null
    } -RnpmCommand {
        param($TargetDir, $RnpmBin)
        & $RnpmBin install 2>&1 | Out-Null
    }
}

# ----------------------------------------------------
# Scenario 6: overrides
# ----------------------------------------------------
if ($Scenarios -contains "overrides") {
    Run-GateCheck -ScenarioName "overrides" -SetupBlock {
        param($NpmDir, $RnpmDir)
        $pkgJson = @"
{
  "name": "overrides-fixture",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.17.1"
  },
  "overrides": {
    "qs": "6.9.7"
  }
}
"@
        [System.IO.File]::WriteAllText((Join-Path $NpmDir "package.json"), $pkgJson.Replace("`r`n", "`n"))
        [System.IO.File]::WriteAllText((Join-Path $RnpmDir "package.json"), $pkgJson.Replace("`r`n", "`n"))
    } -NpmCommand {
        param($TargetDir)
        & npm.cmd install 2>&1 | Out-Null
    } -RnpmCommand {
        param($TargetDir, $RnpmBin)
        & $RnpmBin install 2>&1 | Out-Null
    }
}

# ----------------------------------------------------
# Scenario 7: Git and file deps
# ----------------------------------------------------
if ($Scenarios -contains "git-file-deps") {
    Run-GateCheck -ScenarioName "Git and file deps" -SetupBlock {
        param($NpmDir, $RnpmDir)
        foreach ($d in @($NpmDir, $RnpmDir)) {
            $localPkgDir = Join-Path $d "local-folder"
            New-Item -ItemType Directory -Path $localPkgDir -Force | Out-Null
            $localPkgJson = @'
{
  "name": "local-folder-pkg",
  "version": "1.0.0"
}
'@
            [System.IO.File]::WriteAllText((Join-Path $localPkgDir "package.json"), $localPkgJson.Replace("`r`n", "`n"))
            
            $pkgJson = @'
{
  "name": "git-file-fixture",
  "version": "1.0.0",
  "dependencies": {
    "local-folder-pkg": "file:./local-folder",
    "inherits": "git+https://github.com/isaacs/inherits.git#v2.0.4"
  }
}
'@
            [System.IO.File]::WriteAllText((Join-Path $d "package.json"), $pkgJson.Replace("`r`n", "`n"))
        }
    } -NpmCommand {
        param($TargetDir)
        & npm.cmd install 2>&1 | Out-Null
    } -RnpmCommand {
        param($TargetDir, $RnpmBin)
        & $RnpmBin install 2>&1 | Out-Null
    }
}

# ----------------------------------------------------
# Scenario 8: uninstall, dedupe, prune
# ----------------------------------------------------
if ($Scenarios -contains "uninstall-dedupe-prune") {
    Run-GateCheck -ScenarioName "uninstall, dedupe, prune" -SetupBlock {
        param($NpmDir, $RnpmDir)
        $p486 = Join-Path $repoRoot "benchmarks\fixtures\project-486"
        Copy-Item (Join-Path $p486 "package.json") $NpmDir
        Copy-Item (Join-Path $p486 "package-lock.json") $NpmDir
        Push-Location $NpmDir
        & npm.cmd ci 2>&1 | Out-Null
        Pop-Location
        Copy-Item (Join-Path $NpmDir "*") $RnpmDir -Recurse
    } -NpmCommand {
        param($TargetDir)
        & npm.cmd uninstall lodash 2>&1 | Out-Null
        & npm.cmd dedupe 2>&1 | Out-Null
        & npm.cmd prune 2>&1 | Out-Null
    } -RnpmCommand {
        param($TargetDir, $RnpmBin)
        & $RnpmBin uninstall lodash 2>&1 | Out-Null
        & $RnpmBin dedupe 2>&1 | Out-Null
        & $RnpmBin prune 2>&1 | Out-Null
    }
}

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host " Parity Gate Summary Table" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
$gateResults | Format-Table -Property Scenario, Status, NodeModulesIdentical, LockfileByteIdentical, HiddenLockByteIdentical, NpmLsZero, CiSucceeds -AutoSize

$failing = @($gateResults | Where-Object { $_.Status -ne "PASS" })
if ($failing.Count -gt 0) {
    Write-Host "`n[FAIL] The following gates failed:" -ForegroundColor Red
    foreach ($f in $failing) {
        Write-Host " - $($f.Scenario)" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "`n[SUCCESS] All gates passed with 100% parity!" -ForegroundColor Green
    exit 0
}
