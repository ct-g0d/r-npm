$ErrorActionPreference = 'Continue'
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$rnpmBin = Join-Path $repoRoot 'target\release\rnpm.exe'
$fixtureDir = Join-Path $repoRoot 'benchmarks\fixtures\project-486'

function Wait-For-Idle {
    $threshold = 20.0
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        $cpu = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
        if ($null -eq $cpu -or $cpu -lt $threshold) {
            return
        }
        Start-Sleep -Seconds 2
    }
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

function Get-Spread {
    param([System.Collections.Generic.List[double]]$List)
    if ($List.Count -lt 2) { return 0.0 }
    $min = ($List | Measure-Object -Minimum).Minimum
    $max = ($List | Measure-Object -Maximum).Maximum
    if ($min -le 0) { return 0.0 }
    return (($max - $min) / $min) * 100.0
}

# Pre-populate shared tarball cache once
$sharedCacheDir = Join-Path $env:TEMP ('sweep-shared-cache-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
$setupTestDir = Join-Path $env:TEMP ('sweep-setup-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
$setupStoreDir = Join-Path $env:TEMP ('sweep-setup-store-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
New-Item -ItemType Directory -Path $setupTestDir -Force | Out-Null
Copy-Item (Join-Path $fixtureDir 'package.json') $setupTestDir
Copy-Item (Join-Path $fixtureDir 'package-lock.json') $setupTestDir

Push-Location $setupTestDir
try {
    $env:RNPM_STORE_DIR = $setupStoreDir
    & $rnpmBin ci --no-audit --no-fund --cache $sharedCacheDir 2>&1 | Out-Null
} finally {
    Pop-Location
    Remove-Item $setupTestDir, $setupStoreDir -Recurse -Force -ErrorAction SilentlyContinue
}

$concurrencies = @(16, 32, 64)
$uvSizes = @(16, 32, 64)

$results = @()

foreach ($conc in $concurrencies) {
    foreach ($uv in $uvSizes) {
        $times = [System.Collections.Generic.List[double]]::new()
        $maxAttempts = 5
        $attempt = 0

        while ($times.Count -lt 3 -and $attempt -lt $maxAttempts) {
            $attempt++
            Wait-For-Idle

            $runDir = Join-Path $env:TEMP ('sweep-run-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
            $runStore = Join-Path $env:TEMP ('sweep-store-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
            New-Item -ItemType Directory -Path $runDir -Force | Out-Null
            Copy-Item (Join-Path $fixtureDir 'package.json') $runDir
            Copy-Item (Join-Path $fixtureDir 'package-lock.json') $runDir

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            Push-Location $runDir
            try {
                $env:RNPM_STORE_DIR = $runStore
                $env:RNPM_NODE_WRITER_CONCURRENCY = "$conc"
                $env:UV_THREADPOOL_SIZE = "$uv"
                & $rnpmBin ci --no-audit --no-fund --cache $sharedCacheDir 2>&1 | Out-Null
            } finally {
                Pop-Location
                $sw.Stop()
                Remove-Item $runDir, $runStore -Recurse -Force -ErrorAction SilentlyContinue
            }

            $elapsedMs = $sw.Elapsed.TotalMilliseconds
            $times.Add($elapsedMs)

            if ($times.Count -eq 3) {
                $spread = Get-Spread $times
                if ($spread -gt 25.0 -and $attempt -lt $maxAttempts) {
                    # Discard worst outlier and retry
                    $maxVal = ($times | Measure-Object -Maximum).Maximum
                    $times.Remove($maxVal)
                }
            }
        }

        $median = Get-Median $times
        $spread = Get-Spread $times
        $results += [PSCustomObject]@{
            Concurrency = $conc
            UVThreadpool = $uv
            MedianMs = [math]::Round($median, 1)
            MedianSec = [math]::Round($median / 1000.0, 2)
            SpreadPct = [math]::Round($spread, 1)
            Runs = ($times | ForEach-Object { [math]::Round($_ / 1000.0, 2) }) -join ", "
        }
    }
}

Remove-Item $sharedCacheDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n### Writer-Drain Sweep Matrix (Warm-Tarball / Empty-Store)"
Write-Host "| Concurrency | UV_THREADPOOL_SIZE | Median Duration (s) | Spread (%) | Runs (s) |"
Write-Host "|---|---|---|---|---|"
foreach ($r in $results) {
    Write-Host ("| {0} | {1} | {2:N2}s | {3:N1}% | [{4}] |" -f $r.Concurrency, $r.UVThreadpool, $r.MedianSec, $r.SpreadPct, $r.Runs)
}
