param(
    [switch]$SkipCargo = $false,
    [switch]$SkipParity = $false,
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
Write-Host " LANE 2 GATE: Manifest, Save Specs, Workspaces, CI, LS" -ForegroundColor Cyan
Write-Host " npm version:  $npmVer" -ForegroundColor Cyan
Write-Host " rnpm binary:  $rnpmBin" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$allPass = $true
$testResults = [System.Collections.Generic.List[PSCustomObject]]::new()

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

# ==============================================================================
# GATE 1: Package.json formatting fidelity & save specs (byte-identical to npm)
# ==============================================================================
Write-Host "`n>>> GATE 1: Package.json formatting fidelity & save specs <<<" -ForegroundColor Yellow

function Test-ManifestFidelity {
    param(
        [string]$Name,
        [string]$InitialJson,
        [string[]]$NpmArgs,
        [string[]]$RnpmArgs
    )

    $tempBase = Join-Path $env:TEMP ("gate2-fid-" + [Guid]::NewGuid().ToString("N"))
    $npmDir = Join-Path $tempBase "npm"
    $rnpmDir = Join-Path $tempBase "rnpm"
    New-Item -ItemType Directory -Path $npmDir -Force | Out-Null
    New-Item -ItemType Directory -Path $rnpmDir -Force | Out-Null

    try {
        [System.IO.File]::WriteAllBytes((Join-Path $npmDir "package.json"), [System.Text.Encoding]::UTF8.GetBytes($InitialJson))
        [System.IO.File]::WriteAllBytes((Join-Path $rnpmDir "package.json"), [System.Text.Encoding]::UTF8.GetBytes($InitialJson))

        Push-Location $npmDir
        & npm.cmd @NpmArgs 2>&1 | Out-Null
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin @RnpmArgs 2>&1 | Out-Null
        Pop-Location

        $bytesNpm = [System.IO.File]::ReadAllBytes((Join-Path $npmDir "package.json"))
        $bytesRnpm = [System.IO.File]::ReadAllBytes((Join-Path $rnpmDir "package.json"))

        $strNpm = [System.Text.Encoding]::UTF8.GetString($bytesNpm)
        $strRnpm = [System.Text.Encoding]::UTF8.GetString($bytesRnpm)

        $match = ($strNpm -eq $strRnpm)
        $details = if ($match) { "Byte-identical ($($bytesNpm.Length) bytes)" } else { "Mismatch! npm: $($bytesNpm.Length) bytes, rnpm: $($bytesRnpm.Length) bytes" }
        Record-Result -Gate "Gate 1: Fidelity" -Name $Name -Passed $match -Details $details
    } finally {
        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempBase -ErrorAction SilentlyContinue
        }
    }
}

$crlf4 = "{\r\n    `"version`": `"1.0.0`",\r\n    `"name`": `"test-crlf`",\r\n    `"private`": true\r\n}\r\n"
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 (^ save)" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7") -RnpmArgs @("install", "is-number@7")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7.0.0 --save-exact" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7.0.0", "--save-exact") -RnpmArgs @("install", "is-number@7.0.0", "--save-exact")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 --save-dev" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7", "--save-dev") -RnpmArgs @("install", "is-number@7", "--save-dev")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 --save-optional" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7", "--save-optional") -RnpmArgs @("install", "is-number@7", "--save-optional")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 --save-peer" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7", "--save-peer") -RnpmArgs @("install", "is-number@7", "--save-peer")
Test-ManifestFidelity -Name "CRLF 4-space: install is-number@7 --no-save" -InitialJson $crlf4 -NpmArgs @("install", "is-number@7", "--no-save") -RnpmArgs @("install", "is-number@7", "--no-save")

$lfTab = "{\n\t`"name`": `"test-tab`",\n\t`"version`": `"1.0.0`"\n}\n"
Test-ManifestFidelity -Name "LF tab: install is-number@7" -InitialJson $lfTab -NpmArgs @("install", "is-number@7") -RnpmArgs @("install", "is-number@7")

$lf2 = "{\n  `"name`": `"test-lf2`",\n  `"version`": `"1.0.0`"\n}\n"
Test-ManifestFidelity -Name "LF 2-space: install is-number@7" -InitialJson $lf2 -NpmArgs @("install", "is-number@7") -RnpmArgs @("install", "is-number@7")

$withDep = "{\r\n    `"name`": `"test-un`",\r\n    `"version`": `"1.0.0`",\r\n    `"dependencies`": {\r\n        `"is-number`": `"^7.0.0`"\r\n    }\r\n}\r\n"
Test-ManifestFidelity -Name "CRLF 4-space: uninstall is-number" -InitialJson $withDep -NpmArgs @("uninstall", "is-number") -RnpmArgs @("uninstall", "is-number")

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
        Set-Content (Join-Path $targetDir "package.json") $rootPkg
        Set-Content (Join-Path $targetDir "packages\a\package.json") $pkgA
        Set-Content (Join-Path $targetDir "packages\b\package.json") $pkgB
    }

    try {
        Setup-WsTree $npmDir
        Setup-WsTree $rnpmDir

        # 1. install is-number@7 -w a
        Push-Location $npmDir
        & npm.cmd install is-number@7 -w a 2>&1 | Out-Null
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin install is-number@7 -w a 2>&1 | Out-Null
        Pop-Location

        $aNpm = [System.IO.File]::ReadAllText((Join-Path $npmDir "packages\a\package.json"))
        $aRnpm = [System.IO.File]::ReadAllText((Join-Path $rnpmDir "packages\a\package.json"))
        $rootNpm = [System.IO.File]::ReadAllText((Join-Path $npmDir "package.json"))
        $rootRnpm = [System.IO.File]::ReadAllText((Join-Path $rnpmDir "package.json"))

        $matchA = ($aNpm -eq $aRnpm)
        $matchRoot = ($rootNpm -eq $rootRnpm)
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 -w a (member package.json byte match)" -Passed $matchA -Details "packages/a/package.json match: $matchA"
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 -w a (root package.json untouched byte match)" -Passed $matchRoot -Details "root package.json match: $matchRoot"

        # Check lockfile packages["packages/a"].dependencies has is-number
        $nodeCheck = "const fs = require('fs'); const r = JSON.parse(fs.readFileSync(process.argv[1],'utf8')); const n = JSON.parse(fs.readFileSync(process.argv[2],'utf8')); const rs = r.packages['packages/a']?.dependencies?.['is-number']; const ns = n.packages['packages/a']?.dependencies?.['is-number']; process.exit((rs === ns && !!rs) ? 0 : 1);"
        & node -e $nodeCheck (Join-Path $rnpmDir "package-lock.json") (Join-Path $npmDir "package-lock.json") 2>&1 | Out-Null
        $lockMatch = ($LASTEXITCODE -eq 0)
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 -w a (lockfile packages/a spec match)" -Passed $lockMatch -Details "packages/a spec match: $lockMatch"

        # 2. uninstall is-number -w a
        Push-Location $npmDir
        & npm.cmd uninstall is-number -w a 2>&1 | Out-Null
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin uninstall is-number -w a 2>&1 | Out-Null
        Pop-Location

        $aNpmUn = [System.IO.File]::ReadAllText((Join-Path $npmDir "packages\a\package.json"))
        $aRnpmUn = [System.IO.File]::ReadAllText((Join-Path $rnpmDir "packages\a\package.json"))
        $matchUn = ($aNpmUn -eq $aRnpmUn)
        Record-Result -Gate "Gate 2: Workspaces" -Name "uninstall is-number -w a (member package.json byte match)" -Passed $matchUn -Details "packages/a/package.json match after uninstall: $matchUn"

        # 3. install is-number@7 --workspaces
        Push-Location $npmDir
        & npm.cmd install is-number@7 --workspaces 2>&1 | Out-Null
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin install is-number@7 --workspaces 2>&1 | Out-Null
        Pop-Location

        $aNpmWs = [System.IO.File]::ReadAllText((Join-Path $npmDir "packages\a\package.json"))
        $aRnpmWs = [System.IO.File]::ReadAllText((Join-Path $rnpmDir "packages\a\package.json"))
        $bNpmWs = [System.IO.File]::ReadAllText((Join-Path $npmDir "packages\b\package.json"))
        $bRnpmWs = [System.IO.File]::ReadAllText((Join-Path $rnpmDir "packages\b\package.json"))

        $matchAllWs = ($aNpmWs -eq $aRnpmWs) -and ($bNpmWs -eq $bRnpmWs)
        Record-Result -Gate "Gate 2: Workspaces" -Name "install is-number@7 --workspaces (all members byte match)" -Passed $matchAllWs -Details "a match: $($aNpmWs -eq $aRnpmWs), b match: $($bNpmWs -eq $bRnpmWs)"

    } finally {
        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempBase -ErrorAction SilentlyContinue
        }
    }
}
Test-WorkspaceParity

# ==============================================================================
# GATE 3: CI Lockfile validation (exact vs range and mismatch)
# ==============================================================================
Write-Host "`n>>> GATE 3: CI lockfile validation <<<" -ForegroundColor Yellow

function Test-CiLockfileValidation {
    $tempBase = Join-Path $env:TEMP ("gate2-ci-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempBase -Force | Out-Null

    try {
        # Generate lockfile with is-number ^7.0.0
        $pkgJson = @{
            name = "ci-test"
            version = "1.0.0"
            dependencies = @{
                "is-number" = "^7.0.0"
            }
        } | ConvertTo-Json
        Set-Content -Path (Join-Path $tempBase "package.json") -Value $pkgJson

        Push-Location $tempBase
        & npm.cmd install --package-lock-only 2>&1 | Out-Null
        Pop-Location

        # Case A: package.json has exact "7.0.0", lockfile has "^7.0.0"
        $pkgJsonExact = @{
            name = "ci-test"
            version = "1.0.0"
            dependencies = @{
                "is-number" = "7.0.0"
            }
        } | ConvertTo-Json
        Set-Content -Path (Join-Path $tempBase "package.json") -Value $pkgJsonExact

        $npmDir = Join-Path $env:TEMP ("gate2-ci-npm-" + [Guid]::NewGuid().ToString("N"))
        $rnpmDir = Join-Path $env:TEMP ("gate2-ci-rnpm-" + [Guid]::NewGuid().ToString("N"))
        Copy-Item -Recurse $tempBase $npmDir
        Copy-Item -Recurse $tempBase $rnpmDir

        Push-Location $npmDir
        & npm.cmd ci 2>&1 | Out-Null
        $npmExitA = $LASTEXITCODE
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin ci 2>&1 | Out-Null
        $rnpmExitA = $LASTEXITCODE
        Pop-Location

        $passA = ($npmExitA -eq 0 -and $rnpmExitA -eq 0)
        Record-Result -Gate "Gate 3: CI" -Name "CI exact package.json vs range lockfile exits 0" -Passed $passA -Details "npm: $npmExitA, rnpm: $rnpmExitA"

        # Case B: package.json has incompatible "8.0.0", lockfile has "^7.0.0"
        $pkgJsonMismatch = @{
            name = "ci-test"
            version = "1.0.0"
            dependencies = @{
                "is-number" = "8.0.0"
            }
        } | ConvertTo-Json
        Set-Content -Path (Join-Path $npmDir "package.json") -Value $pkgJsonMismatch
        Set-Content -Path (Join-Path $rnpmDir "package.json") -Value $pkgJsonMismatch

        Push-Location $npmDir
        & npm.cmd ci 2>&1 | Out-Null
        $npmExitB = $LASTEXITCODE
        Pop-Location

        Push-Location $rnpmDir
        & $rnpmBin ci 2>&1 | Out-Null
        $rnpmExitB = $LASTEXITCODE
        Pop-Location

        $passB = ($npmExitB -ne 0 -and $rnpmExitB -ne 0)
        Record-Result -Gate "Gate 3: CI" -Name "CI spec mismatch exits non-zero" -Passed $passB -Details "npm: $npmExitB, rnpm: $rnpmExitB"

        Remove-Item -Recurse -Force $npmDir -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force $rnpmDir -ErrorAction SilentlyContinue
    } finally {
        if (-not $KeepTemp) {
            Remove-Item -Recurse -Force $tempBase -ErrorAction SilentlyContinue
        }
    }
}
Test-CiLockfileValidation

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
# GATE 5: Speed benchmarks (no-op install >= 3x, ls >= 2x)
# ==============================================================================
Write-Host "`n>>> GATE 5: Speed benchmarks <<<" -ForegroundColor Yellow

function Test-SpeedBenchmarks {
    $fixtureDir = Join-Path $repoRoot "benchmarks\fixtures\project-486"
    $tempDir = Join-Path $env:TEMP ("gate2-speed-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    Copy-Item (Join-Path $fixtureDir "*") $tempDir -Recurse

    try {
        Push-Location $tempDir
        & $rnpmBin ci 2>&1 | Out-Null

        # No-op install measurement
        $rnpmInstallTimes = @()
        for ($i = 0; $i -lt 3; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            & $rnpmBin install 2>&1 | Out-Null
            $sw.Stop()
            $rnpmInstallTimes += $sw.Elapsed.TotalMilliseconds
        }

        $npmInstallTimes = @()
        for ($i = 0; $i -lt 3; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            & npm.cmd install 2>&1 | Out-Null
            $sw.Stop()
            $npmInstallTimes += $sw.Elapsed.TotalMilliseconds
        }

        $rnpmInstallMed = ($rnpmInstallTimes | Measure-Object -Average).Average
        $npmInstallMed = ($npmInstallTimes | Measure-Object -Average).Average
        $installRatio = $npmInstallMed / [Math]::Max(1.0, $rnpmInstallMed)

        $passInstall = ($installRatio -ge 3.0)
        Record-Result -Gate "Gate 5: Speed" -Name "No-op install >= 3x faster than npm" -Passed $passInstall -Details ("rnpm: {0:N1}ms, npm: {1:N1}ms -> {2:N2}x faster" -f $rnpmInstallMed, $npmInstallMed, $installRatio)

        # LS measurement
        $rnpmLsTimes = @()
        for ($i = 0; $i -lt 3; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            & $rnpmBin ls 2>&1 | Out-Null
            $sw.Stop()
            $rnpmLsTimes += $sw.Elapsed.TotalMilliseconds
        }

        $npmLsTimes = @()
        for ($i = 0; $i -lt 3; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            & npm.cmd ls 2>&1 | Out-Null
            $sw.Stop()
            $npmLsTimes += $sw.Elapsed.TotalMilliseconds
        }

        $rnpmLsMed = ($rnpmLsTimes | Measure-Object -Average).Average
        $npmLsMed = ($npmLsTimes | Measure-Object -Average).Average
        $lsRatio = $npmLsMed / [Math]::Max(1.0, $rnpmLsMed)

        $passLs = ($lsRatio -ge 2.0)
        Record-Result -Gate "Gate 5: Speed" -Name "ls >= 2x faster than npm" -Passed $passLs -Details ("rnpm: {0:N1}ms, npm: {1:N1}ms -> {2:N2}x faster" -f $rnpmLsMed, $npmLsMed, $lsRatio)

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

    Write-Host "Running cargo test --workspace --jobs 2..."
    $testOut = cargo test --workspace --jobs 2 2>&1
    $testExit = $LASTEXITCODE
    $passTest = ($testExit -eq 0)
    Record-Result -Gate "Gate 6: Quality" -Name "cargo test --workspace passes" -Passed $passTest -Details "Exit code: $testExit"

    Write-Host "Running cargo clippy --workspace -- -D warnings..."
    $clipOut = cargo clippy --workspace -- -D warnings 2>&1
    $clipExit = $LASTEXITCODE
    $passClip = ($clipExit -eq 0)
    Record-Result -Gate "Gate 6: Quality" -Name "cargo clippy --workspace -- -D warnings passes" -Passed $passClip -Details "Exit code: $clipExit"
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
    Write-Host ("[{0}] {1,-20} | {2,-45} | {3}" -f $status, $r.Gate, $r.Test, $r.Details) -ForegroundColor $col
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
