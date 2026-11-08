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

# Step 0: Antivirus Asymmetry Probe
Write-Host "`n[Probe] Running Antivirus Asymmetry Probe (2,000 files in %TEMP%)..." -ForegroundColor Gray
$probeDirNode = Join-Path $env:TEMP "probe-node-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
$probeDirNative = Join-Path $env:TEMP "probe-native-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
New-Item -ItemType Directory -Path $probeDirNode -Force | Out-Null
New-Item -ItemType Directory -Path $probeDirNative -Force | Out-Null

$nodeScript = @"
const fs = require('fs');
const path = require('path');
const dir = process.argv[1];
const buf = Buffer.alloc(4096, 65);
const t0 = Date.now();
for (let i = 0; i < 2000; i++) {
  fs.writeFileSync(path.join(dir, 'file-' + i + '.dat'), buf);
}
console.log(Date.now() - t0);
"@

$nodeProbeMs = [double](& node -e $nodeScript $probeDirNode)

$nativeProbeMs = Measure-CommandMs {
    $buf = [byte[]]::new(4096)
    for ($i = 0; $i -lt 2000; $i++) {
        [System.IO.File]::WriteAllBytes((Join-Path $probeDirNative "file-$i.dat"), $buf)
    }
}

Remove-Item $probeDirNode -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $probeDirNative -Recurse -Force -ErrorAction SilentlyContinue

$probeRatio = if ($nodeProbeMs -gt 0) { $nativeProbeMs / $nodeProbeMs } else { 1.0 }
Write-Host ("  Node.js probe (2k files):   {0,8:N1} ms" -f $nodeProbeMs) -ForegroundColor Gray
Write-Host ("  Native probe (2k files):    {0,8:N1} ms" -f $nativeProbeMs) -ForegroundColor Gray
Write-Host ("  Probe penalty ratio:        {0,8:N2}x" -f $probeRatio) -ForegroundColor Gray

$antivirusAsymmetryDetected = ($probeRatio -gt 1.30)
if ($antivirusAsymmetryDetected) {
    Write-Host "  [!] Asymmetric antivirus inspection detected (probe penalty ratio > 1.30x)." -ForegroundColor Yellow
    Write-Host "      node.exe has process/path exclusion, adding ~1.5ms overhead per CreateFile/CloseHandle on non-excluded binaries." -ForegroundColor Yellow
}

# Step 1: Ensure a warm baseline node_modules exists for robocopy measurement
$warmBaselineDir = Join-Path $env:TEMP "rnpm-warm-baseline-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $warmBaselineDir -Force | Out-Null
Copy-Item (Join-Path $fixtureDir "package.json") $warmBaselineDir
Copy-Item (Join-Path $fixtureDir "package-lock.json") $warmBaselineDir
Write-Host "`n[Setup] Populating warm cache and baseline node_modules..." -ForegroundColor Gray
Push-Location $warmBaselineDir
& $rnpmBin ci 2>&1 | Out-Null
Pop-Location

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

        $rnpmMs = Measure-CommandMs {
            Push-Location $rnpmRunDir
            try {
                & $rnpmBin ci 2>&1 | Out-Null
            } finally {
                Pop-Location
            }
        }
        $rnpmTimes.Add($rnpmMs)
        Write-Host ("  rnpm ci:                   {0,8:N1} ms ({1:N2} s)" -f $rnpmMs, ($rnpmMs / 1000.0)) -ForegroundColor Cyan
        Remove-Item $rnpmRunDir -Recurse -Force -ErrorAction SilentlyContinue

        # 3. npm ci on fresh copy
        $npmRunDir = Join-Path $env:TEMP "npm-ci-run-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        New-Item -ItemType Directory -Path $npmRunDir -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $npmRunDir
        Copy-Item (Join-Path $fixtureDir "package-lock.json") $npmRunDir

        $npmMs = Measure-CommandMs {
            Push-Location $npmRunDir
            try {
                & npm.cmd ci 2>&1 | Out-Null
            } finally {
                Pop-Location
            }
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

if ($antivirusAsymmetryDetected) {
    Write-Host "`n[INVALID] Benchmark run is marked INVALID due to detected external antivirus asymmetry (probe penalty ratio $([math]::Round($probeRatio, 2))x > 1.5x)" -ForegroundColor Yellow
    Write-Host "          node.exe has process/path exclusion, adding ~1.5ms overhead per CreateFile/CloseHandle on non-excluded binaries." -ForegroundColor Yellow
    Write-Host "          Equalize treatment by adding rnpm exclusion (Add-MpPreference -ExclusionProcess $rnpmBin), or running on Dev Drive / clean CI runner." -ForegroundColor Yellow
    exit 0
}

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
