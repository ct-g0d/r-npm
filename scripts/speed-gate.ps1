param(
    [int]$Runs = 5,
    [switch]$KeepTemp = $false
)

$ErrorActionPreference = "Continue"
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$rnpmBin = Join-Path $repoRoot "target\release\rnpm.exe"

if (-not (Test-Path $rnpmBin)) {
    Write-Error "rnpm release binary not found at $rnpmBin. Run 'cargo build --release' first."
    exit 1
}

$fixtureDir = Join-Path $repoRoot "benchmarks\fixtures\project-486"
if (-not (Test-Path $fixtureDir)) {
    Write-Error "Fixture project-486 not found at $fixtureDir."
    exit 1
}

function Restore-EnvVar([string]$name, $origVal) {
    if ($null -eq $origVal) {
        Remove-Item "env:$name" -ErrorAction SilentlyContinue
    } else {
        Set-Item "env:$name" $origVal
    }
}

# Preserve original environment
$origNpmConfigPrefix       = $env:NPM_CONFIG_PREFIX
$origPrefix                = $env:PREFIX
$origNpmConfigUserconfig   = $env:NPM_CONFIG_USERCONFIG
$origNpmConfigGlobalconfig = $env:NPM_CONFIG_GLOBALCONFIG
$origNpmConfigCache        = $env:NPM_CONFIG_CACHE
$origAppData               = $env:APPDATA
$origLocalAppData          = $env:LOCALAPPDATA

# Setup isolated environment
$isolationBase = Join-Path $env:TEMP "speed-gate-env-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
$isolatedPrefix = Join-Path $isolationBase "isolated-prefix"
$isolatedCache = Join-Path $isolationBase "isolated-cache"
$isolatedAppData = Join-Path $isolationBase "isolated-appdata\Roaming"
$isolatedLocalAppData = Join-Path $isolationBase "isolated-appdata\Local"
$isolatedUserconfig = Join-Path $isolationBase "isolated-user.npmrc"
$isolatedGlobalconfig = Join-Path $isolationBase "isolated-global.npmrc"

New-Item -ItemType Directory -Path $isolatedPrefix -Force | Out-Null
New-Item -ItemType Directory -Path $isolatedCache -Force | Out-Null
New-Item -ItemType Directory -Path $isolatedAppData -Force | Out-Null
New-Item -ItemType Directory -Path $isolatedLocalAppData -Force | Out-Null
Set-Content $isolatedUserconfig ""
Set-Content $isolatedGlobalconfig ""

$env:NPM_CONFIG_PREFIX       = $isolatedPrefix
$env:PREFIX                  = $isolatedPrefix
$env:NPM_CONFIG_USERCONFIG   = $isolatedUserconfig
$env:NPM_CONFIG_GLOBALCONFIG = $isolatedGlobalconfig
$env:NPM_CONFIG_CACHE        = $isolatedCache
$env:APPDATA                 = $isolatedAppData
$env:LOCALAPPDATA            = $isolatedLocalAppData

try {

$npmVer = & npm.cmd --version
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " rnpm Speed Gate Harness" -ForegroundColor Cyan
Write-Host " npm version:      $npmVer" -ForegroundColor Cyan
Write-Host " rnpm binary:      $rnpmBin" -ForegroundColor Cyan
Write-Host " Project fixture:  $fixtureDir" -ForegroundColor Cyan
Write-Host " Benchmark runs:   $Runs (alternated)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

function Measure-CommandMs {
    param([scriptblock]$Action)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $Action
    $sw.Stop()
    return $sw.Elapsed.TotalMilliseconds
}

function Get-Median {
    param([System.Collections.Generic.List[double]]$List)
    $sorted = $List | Sort-Object
    $count = $sorted.Count
    if ($count -eq 0) { return 0 }
    if ($count % 2 -eq 1) {
        return $sorted[[math]::Floor($count / 2)]
    } else {
        $mid = $count / 2
        return ($sorted[$mid - 1] + $sorted[$mid]) / 2.0
    }
}

# Step 1: Ensure a warm baseline node_modules exists for robocopy measurement
$warmBaselineDir = Join-Path $env:TEMP "rnpm-warm-baseline-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $warmBaselineDir -Force | Out-Null
Copy-Item (Join-Path $fixtureDir "package.json") $warmBaselineDir
Copy-Item (Join-Path $fixtureDir "package-lock.json") $warmBaselineDir
Write-Host "`n[Setup] Populating warm cache and baseline node_modules..." -ForegroundColor Gray
Push-Location $warmBaselineDir
& $rnpmBin ci 2>&1 | Out-Null
$setupExitCode = $LASTEXITCODE
Pop-Location

if ($setupExitCode -ne 0) {
    Write-Host "[FAIL] Setup rnpm ci failed with exit code $setupExitCode" -ForegroundColor Red
    exit 1
}

$baselineFileCount = (Get-ChildItem -Path (Join-Path $warmBaselineDir "node_modules") -Recurse -File).Count
if ($baselineFileCount -lt 1000) {
    Write-Host "[FAIL] Baseline node_modules has suspiciously few files: $baselineFileCount" -ForegroundColor Red
    exit 1
}
Write-Host "  Baseline file count: $baselineFileCount files" -ForegroundColor Gray

# Pre-warm the isolated npm cache so npm ci runs warm without changing what is timed
$warmNpmSeedDir = Join-Path $env:TEMP "npm-warm-seed-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $warmNpmSeedDir -Force | Out-Null
Copy-Item (Join-Path $fixtureDir "package.json") $warmNpmSeedDir
Copy-Item (Join-Path $fixtureDir "package-lock.json") $warmNpmSeedDir
Write-Host "  Pre-warming isolated npm cache..." -ForegroundColor Gray
Push-Location $warmNpmSeedDir
try {
    & npm.cmd ci 2>&1 | Out-Null
    $npmSetupExitCode = $LASTEXITCODE
} finally {
    Pop-Location
    Remove-Item $warmNpmSeedDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($npmSetupExitCode -ne 0) {
    Write-Host "[FAIL] Setup npm ci pre-warm failed with exit code $npmSetupExitCode" -ForegroundColor Red
    exit 1
}

$robocopyTimes = [System.Collections.Generic.List[double]]::new()
$rnpmTimes = [System.Collections.Generic.List[double]]::new()
$npmTimes = [System.Collections.Generic.List[double]]::new()

try {
    for ($i = 1; $i -le $Runs; $i++) {
        Write-Host "`n--- Run $i of $Runs ---\" -ForegroundColor Yellow

        # 1. Robocopy baseline (using /MT:16 multithreaded copy)
        $roboDest = Join-Path $env:TEMP "robo-dest-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        $srcNm = Join-Path $warmBaselineDir "node_modules"
        $dstNm = Join-Path $roboDest "node_modules"
        New-Item -ItemType Directory -Path $dstNm -Force | Out-Null
        
        $roboMs = Measure-CommandMs {
            & robocopy $srcNm $dstNm /E /MT:16 /NFL /NDL /NJH /NJS /NC /NS /NP *>$null
        }
        $robocopyTimes.Add($roboMs)
        Write-Host ("  Robocopy baseline (/MT:16): {0,8:N1} ms ({1:N2} s)" -f $roboMs, ($roboMs / 1000.0)) -ForegroundColor Gray
        Remove-Item $roboDest -Recurse -Force -ErrorAction SilentlyContinue

        # 2. rnpm ci on fresh copy
        $rnpmRunDir = Join-Path $env:TEMP "rnpm-ci-run-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        New-Item -ItemType Directory -Path $rnpmRunDir -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $rnpmRunDir
        Copy-Item (Join-Path $fixtureDir "package-lock.json") $rnpmRunDir

        $rnpmExitCode = 0
        $rnpmMs = Measure-CommandMs {
            Push-Location $rnpmRunDir
            try {
                & $rnpmBin ci 2>&1 | Out-Null
                $rnpmExitCode = $LASTEXITCODE
            } finally {
                Pop-Location
            }
        }
        if ($rnpmExitCode -ne 0) {
            Write-Host "`n[FAIL] rnpm ci exited with code $rnpmExitCode" -ForegroundColor Red
            exit 1
        }
        $rnpmFileCount = (Get-ChildItem -Path (Join-Path $rnpmRunDir "node_modules") -Recurse -File).Count
        if ($rnpmFileCount -ne $baselineFileCount) {
            Write-Host "`n[FAIL] rnpm ci file count mismatch: got $rnpmFileCount, expected $baselineFileCount" -ForegroundColor Red
            exit 1
        }
        $rnpmTimes.Add($rnpmMs)
        Write-Host ("  rnpm ci:                   {0,8:N1} ms ({1:N2} s)" -f $rnpmMs, ($rnpmMs / 1000.0)) -ForegroundColor Cyan
        Remove-Item $rnpmRunDir -Recurse -Force -ErrorAction SilentlyContinue

        # 3. npm ci on fresh copy
        $npmRunDir = Join-Path $env:TEMP "npm-ci-run-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        New-Item -ItemType Directory -Path $npmRunDir -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $npmRunDir
        Copy-Item (Join-Path $fixtureDir "package-lock.json") $npmRunDir

        $npmExitCode = 0
        $npmMs = Measure-CommandMs {
            Push-Location $npmRunDir
            try {
                & npm.cmd ci 2>&1 | Out-Null
                $npmExitCode = $LASTEXITCODE
            } finally {
                Pop-Location
            }
        }
        if ($npmExitCode -ne 0) {
            Write-Host "`n[FAIL] npm ci exited with code $npmExitCode" -ForegroundColor Red
            exit 1
        }
        $npmTimes.Add($npmMs)
        Write-Host ("  npm ci:                    {0,8:N1} ms ({1:N2} s)" -f $npmMs, ($npmMs / 1000.0)) -ForegroundColor Magenta
        Remove-Item $npmRunDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item $warmBaselineDir -Recurse -Force -ErrorAction SilentlyContinue
}

$roboMedian = Get-Median $robocopyTimes
$rnpmMedian = Get-Median $rnpmTimes
$npmMedian = Get-Median $npmTimes

$ratioVsNpm = if ($npmMedian -gt 0) { $npmMedian / $rnpmMedian } else { 0 }
$ratioVsRobo = if ($roboMedian -gt 0) { $rnpmMedian / $roboMedian } else { 0 }

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host " Speed Gate Summary & Medians" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host (" Robocopy median (/MT:16): {0,8:N1} ms ({1:N2} s)" -f $roboMedian, ($roboMedian / 1000.0))
Write-Host (" rnpm ci median:          {0,8:N1} ms ({1:N2} s)" -f $rnpmMedian, ($rnpmMedian / 1000.0)) -ForegroundColor Cyan
Write-Host (" npm ci median:           {0,8:N1} ms ({1:N2} s)" -f $npmMedian, ($npmMedian / 1000.0)) -ForegroundColor Magenta
Write-Host (" Speedup vs npm:          {0:N2}x faster" -f $ratioVsNpm)
Write-Host (" Ratio vs robocopy:       {0:N2}x" -f $ratioVsRobo)



$gatePassed = $true
if ($rnpmMedian -gt $npmMedian) {
    Write-Host "`n[FAIL] rnpm ci ($($rnpmMedian / 1000.0)s) is slower than npm ci ($($npmMedian / 1000.0)s)" -ForegroundColor Red
    $gatePassed = $false
} else {
    Write-Host "`n[PASS] rnpm ci is faster than npm ci ($([math]::Round($ratioVsNpm, 2))x)" -ForegroundColor Green
}

if ($ratioVsRobo -gt 2.0) {
    Write-Host "[FAIL] rnpm ci ($([math]::Round($ratioVsRobo, 2))x robocopy) is slower than 2x robocopy" -ForegroundColor Red
    $gatePassed = $false
} else {
    Write-Host "[PASS] rnpm ci ($([math]::Round($ratioVsRobo, 2))x robocopy) is within 2x robocopy" -ForegroundColor Green
}

if ($gatePassed) {
    Write-Host "`n[SUCCESS] Speed Gate PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n[FAIL] Speed Gate FAILED" -ForegroundColor Red
    exit 1
}
} finally {
    Restore-EnvVar "NPM_CONFIG_PREFIX"       $origNpmConfigPrefix
    Restore-EnvVar "PREFIX"                  $origPrefix
    Restore-EnvVar "NPM_CONFIG_USERCONFIG"   $origNpmConfigUserconfig
    Restore-EnvVar "NPM_CONFIG_GLOBALCONFIG" $origNpmConfigGlobalconfig
    Restore-EnvVar "NPM_CONFIG_CACHE"        $origNpmConfigCache
    Restore-EnvVar "APPDATA"                 $origAppData
    Restore-EnvVar "LOCALAPPDATA"            $origLocalAppData

    if (-not $KeepTemp) {
        Remove-Item $isolationBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
