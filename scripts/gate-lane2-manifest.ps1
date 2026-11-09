param(
    [switch]$SkipCargo = $false,
    [switch]$SkipParity = $false,
    [switch]$KeepTemp = $false,
    [switch]$SelfTest = $false
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
Write-Host " LANE 2 GATE: Manifest, Save Specs, Workspaces, CI, LS" -ForegroundColor Cyan
Write-Host " npm version:  $npmVer" -ForegroundColor Cyan
Write-Host " rnpm binary:  $rnpmBin" -ForegroundColor Cyan
if ($SelfTest) {
    Write-Host " [MODE] SelfTest active: deliberate corruption will be introduced" -ForegroundColor Magenta
}
Write-Host "====================================================" -ForegroundColor Cyan

$allPass = $true
$testResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:selfTestTriggered = $false

function Record-Result {
    param([string]$Gate, [string]$Name, [bool]$Passed, [string]$Details = "")
    $script:testResults.Add([PSCustomObject]@{
        Gate = $Gate
        Test = $Name
        Passed = $Passed
        Details = $Details
    })
    if ($Passed) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    } else {
        $script:allPass = $false
        Write-Host "  [FAIL] $($Name): $Details" -ForegroundColor Red
    }
}

function Assert-ValidJson([string]$JsonStr, [string]$Name) {
    try {
        $clean = $JsonStr.TrimStart([char]0xFEFF)
        $null = ConvertFrom-Json $clean -ErrorAction Stop
    } catch {
        Write-Error "FATAL: Fixture '$Name' is INVALID JSON: $_"
        exit 1
    }
}

# ==============================================================================
# GATE 1: Package.json formatting fidelity & save specs (byte-identical to npm)
# ==============================================================================
Write-Host "`n>>> GATE 1: Package.json formatting fidelity & save specs <<<" -ForegroundColor Yellow

function Test-ManifestFidelity {
    param(
        [string]$Name,
        [string]$InitialJson,
        [string[]]$NpmArgs,
        [string[]]$RnpmArgs,
        [bool]$ExpectModified = $true
    )

    Assert-ValidJson -JsonStr $InitialJson -Name $Name

    $tempBase = Join-Path $env:TEMP ("gate2-fid-" + [Guid]::NewGuid().ToString("N"))
    $npmDir = Join-Path $tempBase "npm"
    $rnpmDir = Join-Path $tempBase "rnpm"
    New-Item -ItemType Directory -Path $npmDir -Force | Out-Null
    New-Item -ItemType Directory -Path $rnpmDir -Force | Out-Null

    try {
        $initBytes = [System.Text.Encoding]::UTF8.GetBytes($InitialJson)
        [System.IO.File]::WriteAllBytes((Join-Path $npmDir "package.json"), $initBytes)
        [System.IO.File]::WriteAllBytes((Join-Path $rnpmDir "package.json"), $initBytes)

        Push-Location $npmDir
        & npm.cmd @NpmArgs 2>&1 | Out-Null
        $npmExit = $LASTEXITCODE
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin @RnpmArgs 2>&1 | Out-Null
        $rnpmExit = $LASTEXITCODE
        Pop-Location

        $bytesNpm = [System.IO.File]::ReadAllBytes((Join-Path $npmDir "package.json"))
        $bytesRnpm = [System.IO.File]::ReadAllBytes((Join-Path $rnpmDir "package.json"))

        if ($SelfTest -and -not $script:selfTestTriggered) {
            $script:selfTestTriggered = $true
            # Deliberately flip the first byte of rnpm's output to verify gate detects corruption
            $bytesRnpm[0] = [byte]($bytesRnpm[0] -bxor 0xFF)
        }

        # Assert exit codes
        $exitSuccess = ($npmExit -eq 0 -and $rnpmExit -eq 0)

        # Assert byte match
        $strNpm = [System.Text.Encoding]::UTF8.GetString($bytesNpm)
        $strRnpm = [System.Text.Encoding]::UTF8.GetString($bytesRnpm)
        $match = ($strNpm -eq $strRnpm)

        # Assert modification if expected (content changed vs input)
        $npmModified = -not [System.Linq.Enumerable]::SequenceEqual($bytesNpm, $initBytes)
        $modSuccess = if ($ExpectModified) { $npmModified } else { -not $npmModified }

        $passed = $exitSuccess -and $match -and $modSuccess
        $details = "npm exit: $npmExit, rnpm exit: $rnpmExit, in: $($initBytes.Length) B, npm: $($bytesNpm.Length) B, rnpm: $($bytesRnpm.Length) B, modified: $npmModified, match: $match"
        Record-Result -Gate "Gate 1: Fidelity" -Name $Name -Passed $passed -Details $details
    } finally {
        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempBase -ErrorAction SilentlyContinue
        }
    }
}

$crlf = [string][char]13 + [string][char]10
$lf = [string][char]10
$tab = [string][char]9

$crlf4 = "{" + $crlf +
    "    `"version`": `"1.0.0`"," + $crlf +
    "    `"name`": `"test-crlf`"," + $crlf +
    "    `"private`": true" + $crlf +
    "}" + $crlf

Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 (^ save)" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7") -RnpmArgs @("install", "is-number@7")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7.0.0 --save-exact" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7.0.0", "--save-exact") -RnpmArgs @("install", "is-number@7.0.0", "--save-exact")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 --save-dev" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7", "--save-dev") -RnpmArgs @("install", "is-number@7", "--save-dev")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 --save-optional" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7", "--save-optional") -RnpmArgs @("install", "is-number@7", "--save-optional")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 --save-peer" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7", "--save-peer") -RnpmArgs @("install", "is-number@7", "--save-peer")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 --no-save" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7", "--no-save") -RnpmArgs @("install", "is-number@7", "--no-save") -ExpectModified $false

$lfTab = "{" + $lf +
    $tab + "`"name`": `"test-tab`"," + $lf +
    $tab + "`"version`": `"1.0.0`"" + $lf +
    "}" + $lf
Test-ManifestFidelity -Name "LF tab: install is-number@7" -InitialJson $lfTab -NpmArgs @("install", "is-number@7") -RnpmArgs @("install", "is-number@7")

$lf2 = "{" + $lf +
    "  `"name`": `"test-lf2`"," + $lf +
    "  `"version`": `"1.0.0`"" + $lf +
    "}" + $lf
Test-ManifestFidelity -Name "LF 2-space: install is-number@7" -InitialJson $lf2 -NpmArgs @("install", "is-number@7") -RnpmArgs @("install", "is-number@7")

$withDep = "{" + $crlf +
    "    `"name`": `"test-un`"," + $crlf +
    "    `"version`": `"1.0.0`"," + $crlf +
    "    `"dependencies`": {" + $crlf +
    "        `"is-number`": `"^7.0.0`"" + $crlf +
    "    }" + $crlf +
    "}" + $crlf
Test-ManifestFidelity -Name "CRLF 4-space: uninstall is-number" -InitialJson $withDep -NpmArgs @("uninstall", "is-number") -RnpmArgs @("uninstall", "is-number")

$noNl = "{" + $lf +
    "  `"name`": `"test-nonl`"," + $lf +
    "  `"version`": `"1.0.0`"" + $lf +
    "}"
Test-ManifestFidelity -Name "No trailing newline: install is-number@7" -InitialJson $noNl -NpmArgs @("install", "is-number@7") -RnpmArgs @("install", "is-number@7")

$bomJson = [System.Text.Encoding]::UTF8.GetString([byte[]]@(0xEF, 0xBB, 0xBF)) + "{" + $lf +
    "  `"name`": `"test-bom`"," + $lf +
    "  `"version`": `"1.0.0`"" + $lf +
    "}" + $lf
Test-ManifestFidelity -Name "UTF-8 BOM preservation: install is-number@7" -InitialJson $bomJson -NpmArgs @("install", "is-number@7") -RnpmArgs @("install", "is-number@7")

$verJson = "{" + $lf +
    "  `"name`": `"test-ver`"," + $lf +
    "  `"version`": `"1.0.0`"" + $lf +
    "}" + $lf
Test-ManifestFidelity -Name "npm version patch byte fidelity" -InitialJson $verJson -NpmArgs @("version", "patch", "--no-git-tag-version") -RnpmArgs @("version", "patch", "--no-git-tag-version")

$pkgJson = "{" + $lf +
    "  `"name`": `"test-pkg`"," + $lf +
    "  `"version`": `"1.0.0`"" + $lf +
    "}" + $lf
Test-ManifestFidelity -Name "npm pkg set byte fidelity" -InitialJson $pkgJson -NpmArgs @("pkg", "set", "scripts.test=test") -RnpmArgs @("pkg", "set", "scripts.test=test")

$pkgDelJson = "{" + $lf +
    "  `"name`": `"test-pkg`"," + $lf +
    "  `"version`": `"1.0.0`"," + $lf +
    "  `"scripts`": {" + $lf +
    "    `"test`": `"echo 1`"" + $lf +
    "  }" + $lf +
    "}" + $lf
Test-ManifestFidelity -Name "npm pkg delete byte fidelity" -InitialJson $pkgDelJson -NpmArgs @("pkg", "delete", "scripts.test") -RnpmArgs @("pkg", "delete", "scripts.test")

# ==============================================================================
# GATE 2: Workspaces install & uninstall parity (-w, --workspaces)
# ==============================================================================
Write-Host "`n>>> GATE 2: Workspaces install & uninstall (-w, --workspaces) <<<" -ForegroundColor Yellow

function Test-WorkspaceParity {
    $tempBase = Join-Path $env:TEMP ("gate2-ws-" + [Guid]::NewGuid().ToString("N"))
    $npmDir = Join-Path $tempBase "npm"
    $rnpmDir = Join-Path $tempBase "rnpm"

    function Setup-WsTree([string]$targetDir) {
        New-Item -ItemType Directory -Path (Join-Path $targetDir "packages\a") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $targetDir "packages\b") -Force | Out-Null
        $rootPkg = @{
            name = "ws-root"
            version = "1.0.0"
            private = $true
            workspaces = @("packages/*")
        } | ConvertTo-Json
        $pkgA = @{
            name = "a"
            version = "1.0.0"
        } | ConvertTo-Json
        $pkgB = @{
            name = "b"
            version = "1.0.0"
        } | ConvertTo-Json
        Set-Content (Join-Path $targetDir "package.json") ($rootPkg + "`n")
        Set-Content (Join-Path $targetDir "packages\a\package.json") ($pkgA + "`n")
        Set-Content (Join-Path $targetDir "packages\b\package.json") ($pkgB + "`n")
    }

    function Diff-LockfilePackages([string]$dir1, [string]$dir2) {
        $nodeDiff = @"
const fs = require('fs');
const assert = require('assert');
try {
  const p1 = JSON.parse(fs.readFileSync(process.argv[1] + '/package-lock.json', 'utf8'));
  const p2 = JSON.parse(fs.readFileSync(process.argv[2] + '/package-lock.json', 'utf8'));
  assert.deepStrictEqual(p1.packages, p2.packages);
  process.exit(0);
} catch (e) {
  process.exit(1);
}
"@
        & node -e $nodeDiff $dir1 $dir2 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    }

    try {
        Setup-WsTree $npmDir
        Setup-WsTree $rnpmDir

        # 1. install is-number@7 -w a
        Push-Location $npmDir
        & npm.cmd install is-number@7 -w a 2>&1 | Out-Null
        $npmExit1 = $LASTEXITCODE
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin install is-number@7 -w a 2>&1 | Out-Null
        $rnpmExit1 = $LASTEXITCODE
        Pop-Location

        $aNpm = [System.IO.File]::ReadAllText((Join-Path $npmDir "packages\a\package.json"))
        $aRnpm = [System.IO.File]::ReadAllText((Join-Path $rnpmDir "packages\a\package.json"))
        $rootNpm = [System.IO.File]::ReadAllText((Join-Path $npmDir "package.json"))
        $rootRnpm = [System.IO.File]::ReadAllText((Join-Path $rnpmDir "package.json"))

        $lockBytesNpm1 = [System.IO.File]::ReadAllBytes((Join-Path $npmDir "package-lock.json"))
        $lockBytesRnpm1 = [System.IO.File]::ReadAllBytes((Join-Path $rnpmDir "package-lock.json"))
        $lockByteMatch1 = [System.Linq.Enumerable]::SequenceEqual($lockBytesNpm1, $lockBytesRnpm1)
        $diffPkgs1 = Diff-LockfilePackages $npmDir $rnpmDir

        $matchA1 = ($aNpm -eq $aRnpm)
        $matchRoot1 = ($rootNpm -eq $rootRnpm)
        $exitSuccess1 = ($npmExit1 -eq 0 -and $rnpmExit1 -eq 0)

        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 -w a (member package.json byte match)" -Passed ($exitSuccess1 -and $matchA1) -Details "packages/a/package.json match: $matchA1 (npm exit: $npmExit1, rnpm exit: $rnpmExit1)"
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 -w a (root package.json untouched byte match)" -Passed ($exitSuccess1 -and $matchRoot1) -Details "root package.json match: $matchRoot1"
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 -w a (full lockfile byte-for-byte identical)" -Passed ($exitSuccess1 -and $lockByteMatch1) -Details "npm lock: $($lockBytesNpm1.Length) B, rnpm lock: $($lockBytesRnpm1.Length) B, byte match: $lockByteMatch1"
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 -w a (full lockfile packages section deep equality)" -Passed ($exitSuccess1 -and $diffPkgs1) -Details "full packages diff equal: $diffPkgs1"

        # 2. uninstall is-number -w a
        Push-Location $npmDir
        & npm.cmd uninstall is-number -w a 2>&1 | Out-Null
        $npmExit2 = $LASTEXITCODE
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin uninstall is-number -w a 2>&1 | Out-Null
        $rnpmExit2 = $LASTEXITCODE
        Pop-Location

        $aNpmUn = [System.IO.File]::ReadAllText((Join-Path $npmDir "packages\a\package.json"))
        $aRnpmUn = [System.IO.File]::ReadAllText((Join-Path $rnpmDir "packages\a\package.json"))
        $rootNpmUn = [System.IO.File]::ReadAllText((Join-Path $npmDir "package.json"))
        $rootRnpmUn = [System.IO.File]::ReadAllText((Join-Path $rnpmDir "package.json"))

        $lockBytesNpm2 = [System.IO.File]::ReadAllBytes((Join-Path $npmDir "package-lock.json"))
        $lockBytesRnpm2 = [System.IO.File]::ReadAllBytes((Join-Path $rnpmDir "package-lock.json"))
        $lockByteMatch2 = [System.Linq.Enumerable]::SequenceEqual($lockBytesNpm2, $lockBytesRnpm2)
        $diffPkgs2 = Diff-LockfilePackages $npmDir $rnpmDir

        $matchUnA = ($aNpmUn -eq $aRnpmUn)
        $matchUnRoot = ($rootNpmUn -eq $rootRnpmUn)
        $exitSuccess2 = ($npmExit2 -eq 0 -and $rnpmExit2 -eq 0)

        Record-Result -Gate "Gate 2: Workspaces" -Name "uninstall is-number -w a (member package.json byte match)" -Passed ($exitSuccess2 -and $matchUnA) -Details "packages/a/package.json match after uninstall: $matchUnA (npm exit: $npmExit2, rnpm exit: $rnpmExit2)"
        Record-Result -Gate "Gate 2: Workspaces" -Name "uninstall is-number -w a (root package.json untouched byte match)" -Passed ($exitSuccess2 -and $matchUnRoot) -Details "root package.json match after uninstall: $matchUnRoot"
        Record-Result -Gate "Gate 2: Workspaces" -Name "uninstall is-number -w a (full lockfile byte-for-byte identical)" -Passed ($exitSuccess2 -and $lockByteMatch2) -Details "npm lock: $($lockBytesNpm2.Length) B, rnpm lock: $($lockBytesRnpm2.Length) B, byte match: $lockByteMatch2"
        Record-Result -Gate "Gate 2: Workspaces" -Name "uninstall is-number -w a (full lockfile packages section deep equality)" -Passed ($exitSuccess2 -and $diffPkgs2) -Details "full packages diff equal: $diffPkgs2"

        # 3. install is-number@7 --workspaces (in fresh workspace trees)
        $tempBase3 = Join-Path $env:TEMP ("gate2-ws3-" + [Guid]::NewGuid().ToString("N"))
        $npmDir3 = Join-Path $tempBase3 "npm"
        $rnpmDir3 = Join-Path $tempBase3 "rnpm"
        Setup-WsTree $npmDir3
        Setup-WsTree $rnpmDir3

        Push-Location $npmDir3
        & npm.cmd install is-number@7 --workspaces 2>&1 | Out-Null
        $npmExit3 = $LASTEXITCODE
        Pop-Location

        Push-Location $rnpmDir3
        & $rnpmBin install is-number@7 --workspaces 2>&1 | Out-Null
        $rnpmExit3 = $LASTEXITCODE
        Pop-Location

        $aNpmWs = [System.IO.File]::ReadAllText((Join-Path $npmDir3 "packages\a\package.json"))
        $aRnpmWs = [System.IO.File]::ReadAllText((Join-Path $rnpmDir3 "packages\a\package.json"))
        $bNpmWs = [System.IO.File]::ReadAllText((Join-Path $npmDir3 "packages\b\package.json"))
        $bRnpmWs = [System.IO.File]::ReadAllText((Join-Path $rnpmDir3 "packages\b\package.json"))
        $rootNpmWs = [System.IO.File]::ReadAllText((Join-Path $npmDir3 "package.json"))
        $rootRnpmWs = [System.IO.File]::ReadAllText((Join-Path $rnpmDir3 "package.json"))

        $lockBytesNpm3 = [System.IO.File]::ReadAllBytes((Join-Path $npmDir3 "package-lock.json"))
        $lockBytesRnpm3 = [System.IO.File]::ReadAllBytes((Join-Path $rnpmDir3 "package-lock.json"))
        $lockByteMatch3 = [System.Linq.Enumerable]::SequenceEqual($lockBytesNpm3, $lockBytesRnpm3)
        $diffPkgs3 = Diff-LockfilePackages $npmDir3 $rnpmDir3

        $matchAllWs = ($aNpmWs -eq $aRnpmWs) -and ($bNpmWs -eq $bRnpmWs)
        $matchWsRoot = ($rootNpmWs -eq $rootRnpmWs)
        $exitSuccess3 = ($npmExit3 -eq 0 -and $rnpmExit3 -eq 0)

        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 --workspaces (all members byte match)" -Passed ($exitSuccess3 -and $matchAllWs) -Details "a match: $($aNpmWs -eq $aRnpmWs), b match: $($bNpmWs -eq $bRnpmWs) (npm exit: $npmExit3, rnpm exit: $rnpmExit3)"
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 --workspaces (root package.json byte match)" -Passed ($exitSuccess3 -and $matchWsRoot) -Details "root package.json match: $matchWsRoot"
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 --workspaces (full lockfile byte-for-byte identical)" -Passed ($exitSuccess3 -and $lockByteMatch3) -Details "npm lock: $($lockBytesNpm3.Length) B, rnpm lock: $($lockBytesRnpm3.Length) B, byte match: $lockByteMatch3"
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 --workspaces (full lockfile packages section deep equality)" -Passed ($exitSuccess3 -and $diffPkgs3) -Details "full packages diff equal: $diffPkgs3"

        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempBase3 -ErrorAction SilentlyContinue
        }

        # 4. install is-number@7 --include-workspace-root (in fresh workspace trees)
        $tempBase4 = Join-Path $env:TEMP ("gate2-ws4-" + [Guid]::NewGuid().ToString("N"))
        $npmDir4 = Join-Path $tempBase4 "npm"
        $rnpmDir4 = Join-Path $tempBase4 "rnpm"
        Setup-WsTree $npmDir4
        Setup-WsTree $rnpmDir4

        Push-Location $npmDir4
        & npm.cmd install is-number@7 --include-workspace-root 2>&1 | Out-Null
        $npmExit4 = $LASTEXITCODE
        Pop-Location

        Push-Location $rnpmDir4
        & $rnpmBin install is-number@7 --include-workspace-root 2>&1 | Out-Null
        $rnpmExit4 = $LASTEXITCODE
        Pop-Location

        $rootNpmInc = [System.IO.File]::ReadAllText((Join-Path $npmDir4 "package.json"))
        $rootRnpmInc = [System.IO.File]::ReadAllText((Join-Path $rnpmDir4 "package.json"))

        $lockBytesNpm4 = [System.IO.File]::ReadAllBytes((Join-Path $npmDir4 "package-lock.json"))
        $lockBytesRnpm4 = [System.IO.File]::ReadAllBytes((Join-Path $rnpmDir4 "package-lock.json"))
        $lockByteMatch4 = [System.Linq.Enumerable]::SequenceEqual($lockBytesNpm4, $lockBytesRnpm4)
        $diffPkgs4 = Diff-LockfilePackages $npmDir4 $rnpmDir4

        $matchIncRoot = ($rootNpmInc -eq $rootRnpmInc)
        $exitSuccess4 = ($npmExit4 -eq 0 -and $rnpmExit4 -eq 0)

        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 --include-workspace-root (root package.json byte match)" -Passed ($exitSuccess4 -and $matchIncRoot) -Details "root package.json match: $matchIncRoot (npm exit: $npmExit4, rnpm exit: $rnpmExit4)"
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 --include-workspace-root (full lockfile byte-for-byte identical)" -Passed ($exitSuccess4 -and $lockByteMatch4) -Details "npm lock: $($lockBytesNpm4.Length) B, rnpm lock: $($lockBytesRnpm4.Length) B, byte match: $lockByteMatch4"
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 --include-workspace-root (full lockfile packages section deep equality)" -Passed ($exitSuccess4 -and $diffPkgs4) -Details "full packages diff equal: $diffPkgs4"

        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempBase4 -ErrorAction SilentlyContinue
        }

    } finally {
        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempBase -ErrorAction SilentlyContinue
        }
    }
}
Test-WorkspaceParity

# ==============================================================================
# GATE 3: CI Lockfile validation parity vs npm across drift scenarios
# ==============================================================================
Write-Host "`n>>> GATE 3: CI lockfile validation parity <<<" -ForegroundColor Yellow

function Test-CiScenarioParity {
    param(
        [string]$Name,
        [scriptblock]$SetupBlock
    )

    $tempBase = Join-Path $env:TEMP ("gate2-ci-" + [Guid]::NewGuid().ToString("N"))
    $npmDir = Join-Path $tempBase "npm"
    $rnpmDir = Join-Path $tempBase "rnpm"
    New-Item -ItemType Directory -Path $npmDir -Force | Out-Null
    New-Item -ItemType Directory -Path $rnpmDir -Force | Out-Null

    try {
        & $SetupBlock $npmDir
        & $SetupBlock $rnpmDir

        Push-Location $npmDir
        & npm.cmd ci 2>&1 | Out-Null
        $npmCode = $LASTEXITCODE
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin ci 2>&1 | Out-Null
        $rnpmCode = $LASTEXITCODE
        Pop-Location

        $passed = ($npmCode -eq 0 -and $rnpmCode -eq 0) -or ($npmCode -ne 0 -and $rnpmCode -ne 0)
        Record-Result -Gate "Gate 3: CI" -Name $Name -Passed $passed -Details "npm exit: $npmCode, rnpm exit: $rnpmCode"
    } finally {
        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempBase -ErrorAction SilentlyContinue
        }
    }
}

# 1a. Lockfile root has range "^7.0.0" (locked 7.0.0), package.json rewritten to exact "7.0.0"
Test-CiScenarioParity -Name "CI: 1a. exact package.json (7.0.0) vs range lockfile (^7.0.0) exits 0" -SetupBlock {
    param($dir)
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"^7.0.0"}}'
    Push-Location $dir; & npm.cmd install --package-lock-only 2>&1 | Out-Null; Pop-Location
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"7.0.0"}}'
}

# 1b. Lockfile root has exact "7.0.0" (locked 7.0.0), package.json rewritten to range "^7.0.0"
Test-CiScenarioParity -Name "CI: 1b. range package.json (^7.0.0) vs exact lockfile (7.0.0) exits 0" -SetupBlock {
    param($dir)
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"7.0.0"}}'
    Push-Location $dir; & npm.cmd install --package-lock-only 2>&1 | Out-Null; Pop-Location
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"^7.0.0"}}'
}

Test-CiScenarioParity -Name "CI: 2. incompatible version mismatch (exit non-zero)" -SetupBlock {
    param($dir)
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"^7.0.0"}}'
    Push-Location $dir; & npm.cmd install --package-lock-only 2>&1 | Out-Null; Pop-Location
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"^6.0.0"}}'
}

Test-CiScenarioParity -Name "CI: 3. dep in package.json missing from lock (exit non-zero)" -SetupBlock {
    param($dir)
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"^7.0.0"}}'
    Push-Location $dir; & npm.cmd install --package-lock-only 2>&1 | Out-Null; Pop-Location
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"^7.0.0","is-odd":"^3.0.1"}}'
}

Test-CiScenarioParity -Name "CI: 4. dep removed from package.json but in lockfile (exit 0)" -SetupBlock {
    param($dir)
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"^7.0.0"}}'
    Push-Location $dir; & npm.cmd install --package-lock-only 2>&1 | Out-Null; Pop-Location
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0"}'
}

Test-CiScenarioParity -Name "CI: 5. devDependencies version mismatch (exit non-zero)" -SetupBlock {
    param($dir)
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","devDependencies":{"is-number":"^7.0.0"}}'
    Push-Location $dir; & npm.cmd install --package-lock-only 2>&1 | Out-Null; Pop-Location
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","devDependencies":{"is-number":"^6.0.0"}}'
}

Test-CiScenarioParity -Name "CI: 6. npm: alias spec (exit 0)" -SetupBlock {
    param($dir)
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"my-num":"npm:is-number@^7.0.0"}}'
    Push-Location $dir; & npm.cmd install --package-lock-only 2>&1 | Out-Null; Pop-Location
}

Test-CiScenarioParity -Name "CI: 7. file: spec (exit 0)" -SetupBlock {
    param($dir)
    $localPkg = Join-Path $dir "local-pkg"
    New-Item -ItemType Directory -Path $localPkg -Force | Out-Null
    Set-Content (Join-Path $localPkg "package.json") '{"name":"local-pkg","version":"1.0.0"}'
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"local-pkg":"file:local-pkg"}}'
    Push-Location $dir; & npm.cmd install --package-lock-only 2>&1 | Out-Null; Pop-Location
}

Test-CiScenarioParity -Name "CI: 8. lockfile root spec differs & node_modules missing (exit non-zero)" -SetupBlock {
    param($dir)
    Set-Content (Join-Path $dir "package.json") '{"name":"t","version":"1.0.0","dependencies":{"is-number":"^7.0.0"}}'
    Push-Location $dir; & npm.cmd install --package-lock-only 2>&1 | Out-Null; Pop-Location
    $lockPath = Join-Path $dir "package-lock.json"
    $nodeScript = @"
const fs = require('fs');
const lock = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
delete lock.packages['node_modules/is-number'];
lock.packages[''].dependencies['is-number'] = '7.0.0';
fs.writeFileSync(process.argv[1], JSON.stringify(lock, null, 2));
"@
    & node -e $nodeScript $lockPath
}

# ==============================================================================
# GATE 4: ls --all on project-486 (exit code 0 and stdout parity)
# ==============================================================================
Write-Host "`n>>> GATE 4: ls --all on project-486 <<<" -ForegroundColor Yellow

function Test-LsParity {
    $fixtureDir = Join-Path $repoRoot "benchmarks\fixtures\project-486"
    if (-not (Test-Path $fixtureDir)) {
        Record-Result -Gate "Gate 4: LS" -Name "Fixture project-486 exists" -Passed $false -Details "Path not found: $fixtureDir"
        return
    }

    $tempDir = Join-Path $env:TEMP ("gate2-ls-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    Copy-Item (Join-Path $fixtureDir "*") $tempDir -Recurse

    try {
        Push-Location $tempDir
        # Warm node_modules with rnpm ci
        & $rnpmBin ci 2>&1 | Out-Null

        $npmOut = & npm.cmd ls --all 2>&1
        $npmExit = $LASTEXITCODE

        $rnpmOut = & $rnpmBin ls --all 2>&1
        $rnpmExit = $LASTEXITCODE
        Pop-Location

        $exitMatch = ($npmExit -eq 0 -and $rnpmExit -eq 0)
        Record-Result -Gate "Gate 4: LS" -Name "ls --all exit code 0 on project-486 (optional peers ignored)" -Passed $exitMatch -Details "npm: $npmExit, rnpm: $rnpmExit"

        # Compare output lines skipping the first line (project root path)
        $npmLines = ($npmOut | Out-String) -split "`r?`n" | Where-Object { $_ -ne "" }
        $rnpmLines = ($rnpmOut | Out-String) -split "`r?`n" | Where-Object { $_ -ne "" }

        $npmTail = if ($npmLines.Count -gt 1) { $npmLines[1..($npmLines.Count - 1)] } else { @() }
        $rnpmTail = if ($rnpmLines.Count -gt 1) { $rnpmLines[1..($rnpmLines.Count - 1)] } else { @() }

        $tailMatch = (($npmTail -join "`n") -eq ($rnpmTail -join "`n"))
        $unmetCount = ($rnpmTail | Where-Object { $_ -match "UNMET OPTIONAL DEPENDENCY" }).Count
        $details = "Lines match: $tailMatch (npm: $($npmTail.Count) lines, rnpm: $($rnpmTail.Count) lines, $unmetCount UNMET OPTIONAL lines)"
        Record-Result -Gate "Gate 4: LS" -Name "ls --all stdout matches npm exactly" -Passed $tailMatch -Details $details
    } finally {
        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
        }
    }
}
Test-LsParity

# ==============================================================================
# GATE 5: Speed benchmarks (5 runs with 1 warmup discarded, true median, warm cache)
# ==============================================================================
Write-Host "`n>>> GATE 5: Speed benchmarks (5 runs, 1 warmup discarded, true median) <<<" -ForegroundColor Yellow

function Get-Median([double[]]$Values) {
    $sorted = $Values | Sort-Object
    $count = $sorted.Count
    if ($count % 2 -eq 1) {
        return $sorted[[Math]::Floor($count / 2)]
    } else {
        $mid = [int]($count / 2)
        return ($sorted[$mid - 1] + $sorted[$mid]) / 2.0
    }
}

function Test-SpeedBenchmarks {
    $fixtureDir = Join-Path $repoRoot "benchmarks\fixtures\project-486"
    $tempDir = Join-Path $env:TEMP ("gate2-speed-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    Copy-Item (Join-Path $fixtureDir "*") $tempDir -Recurse

    try {
        Push-Location $tempDir
        & $rnpmBin ci 2>&1 | Out-Null

        # No-op install measurement: 6 runs (run 0 warmup, runs 1-5 measured, true median)
        # Cache state: npm cache warm (populated local cache environment), alternated runs
        $rnpmInstallTimes = @()
        $npmInstallTimes = @()
        for ($i = 0; $i -lt 6; $i++) {
            $sw1 = [System.Diagnostics.Stopwatch]::StartNew()
            & $rnpmBin install 2>&1 | Out-Null
            $sw1.Stop()

            $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
            & npm.cmd install 2>&1 | Out-Null
            $sw2.Stop()

            if ($i -gt 0) {
                $rnpmInstallTimes += $sw1.Elapsed.TotalMilliseconds
                $npmInstallTimes += $sw2.Elapsed.TotalMilliseconds
            }
        }

        $rnpmInstallMed = Get-Median $rnpmInstallTimes
        $npmInstallMed = Get-Median $npmInstallTimes
        $installRatio = $npmInstallMed / [Math]::Max(1.0, $rnpmInstallMed)

        $passInstall = ($installRatio -ge 3.0)
        Record-Result -Gate "Gate 5: Speed" -Name "No-op install >= 3x faster than npm (median over 5 runs, warm cache)" -Passed $passInstall -Details ("rnpm: {0:N1}ms, npm: {1:N1}ms -> {2:N2}x faster" -f $rnpmInstallMed, $npmInstallMed, $installRatio)

        # LS measurement: 6 runs (run 0 warmup, runs 1-5 measured, true median), alternated runs
        $rnpmLsTimes = @()
        $npmLsTimes = @()
        for ($i = 0; $i -lt 6; $i++) {
            $sw1 = [System.Diagnostics.Stopwatch]::StartNew()
            & $rnpmBin ls 2>&1 | Out-Null
            $sw1.Stop()

            $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
            & npm.cmd ls 2>&1 | Out-Null
            $sw2.Stop()

            if ($i -gt 0) {
                $rnpmLsTimes += $sw1.Elapsed.TotalMilliseconds
                $npmLsTimes += $sw2.Elapsed.TotalMilliseconds
            }
        }

        $rnpmLsMed = Get-Median $rnpmLsTimes
        $npmLsMed = Get-Median $npmLsTimes
        $lsRatio = $npmLsMed / [Math]::Max(1.0, $rnpmLsMed)

        $passLs = ($lsRatio -ge 2.0)
        Record-Result -Gate "Gate 5: Speed" -Name "ls >= 2x faster than npm (median over 5 runs, warm cache)" -Passed $passLs -Details ("rnpm: {0:N1}ms, npm: {1:N1}ms -> {2:N2}x faster" -f $rnpmLsMed, $npmLsMed, $lsRatio)

        Pop-Location
    } finally {
        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
        }
    }
}
Test-SpeedBenchmarks

# ==============================================================================
# GATE 6: Cargo tests, clippy, and parity gate
# ==============================================================================
if (-not $SkipCargo) {
    Write-Host "`n>>> GATE 6: Cargo tests & clippy <<<" -ForegroundColor Yellow

    Push-Location $repoRoot
    try {
        Write-Host "Running cargo test --workspace..."
        $testOut = cargo test --workspace 2>&1
        $testExit = $LASTEXITCODE
        $passTest = ($testExit -eq 0)
        if (-not $passTest) {
            $testOut | ForEach-Object { Write-Host $_ }
        }
        Record-Result -Gate "Gate 6: Quality" -Name "cargo test --workspace passes" -Passed $passTest -Details "Exit code: $testExit"

        Write-Host "Running cargo clippy --workspace -- -D warnings..."
        $clipOut = cargo clippy --workspace -- -D warnings 2>&1
        $clipExit = $LASTEXITCODE
        $passClip = ($clipExit -eq 0)
        if (-not $passClip) {
            $clipOut | ForEach-Object { Write-Host $_ }
        }
        Record-Result -Gate "Gate 6: Quality" -Name "cargo clippy --workspace -- -D warnings passes" -Passed $passClip -Details "Exit code: $clipExit"
    } finally {
        Pop-Location
    }
}

if (-not $SkipParity) {
    Write-Host "`n>>> GATE 7: Parity gate baseline check <<<" -ForegroundColor Yellow
    $parityScript = Join-Path $repoRoot "scripts\parity-gate.ps1"
    if (Test-Path $parityScript) {
        Write-Host "Running scripts/parity-gate.ps1..."
        & powershell -ExecutionPolicy Bypass -File $parityScript
        $parityExit = $LASTEXITCODE
        $passParity = ($parityExit -eq 0)
        Record-Result -Gate "Gate 7: Parity" -Name "scripts/parity-gate.ps1 passes" -Passed $passParity -Details "Exit code: $parityExit"
    }
}

# ==============================================================================
# SUMMARY REPORT
# ==============================================================================
Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host " LANE 2 GATE SUMMARY" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$passCount = ($testResults | Where-Object { $_.Passed }).Count
$totalCount = $testResults.Count

foreach ($r in $testResults) {
    $col = if ($r.Passed) { "Green" } else { "Red" }
    $status = if ($r.Passed) { "PASS" } else { "FAIL" }
    Write-Host ("[{0}] {1,-20} | {2,-50} | {3}" -f $status, $r.Gate, $r.Test, $r.Details) -ForegroundColor $col
}

Write-Host "====================================================" -ForegroundColor Cyan
$summaryColor = if ($allPass) { "Green" } else { "Red" }
Write-Host (" TOTAL: {0}/{1} checks passed" -f $passCount, $totalCount) -ForegroundColor $summaryColor
Write-Host "====================================================" -ForegroundColor Cyan

if ($allPass) {
    exit 0
} else {
    exit 1
}
