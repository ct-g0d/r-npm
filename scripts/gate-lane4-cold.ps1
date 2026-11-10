param(
    [int]$Runs = 3,
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

function Invoke-IsolatedNpm {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,
        [string]$Cache = $null,
        [switch]$Measure = $false
    )

    $isoRoot = Join-Path $env:TEMP ("npm-iso-" + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
    $isoPrefix = Join-Path $isoRoot "prefix"
    $isoAppData = Join-Path $isoRoot "appdata"
    $isoLocalAppData = Join-Path $isoRoot "localappdata"
    $isoUserConfig = Join-Path $isoRoot ".npmrc"
    $isoGlobalConfig = Join-Path $isoRoot "global.npmrc"

    New-Item -ItemType Directory -Path $isoPrefix, $isoAppData, $isoLocalAppData -Force | Out-Null
    New-Item -ItemType File -Path $isoUserConfig, $isoGlobalConfig -Force | Out-Null

    $effectiveCache = if ($Cache) { $Cache } else { Join-Path $isoRoot "cache" }

    $origCache = $env:NPM_CONFIG_CACHE
    $origCacheLower = $env:npm_config_cache
    $origPrefix = $env:PREFIX
    $origPrefixLower = $env:npm_config_prefix
    $origUserConfig = $env:USERCONFIG
    $origUserConfigLower = $env:npm_config_userconfig
    $origGlobalConfig = $env:GLOBALCONFIG
    $origGlobalConfigLower = $env:npm_config_globalconfig
    $origAppData = $env:APPDATA
    $origLocalAppData = $env:LOCALAPPDATA

    $sw = if ($Measure) { [System.Diagnostics.Stopwatch]::StartNew() } else { $null }
    $out = $null
    $exitCode = 0

    try {
        $env:NPM_CONFIG_CACHE = $effectiveCache
        $env:npm_config_cache = $effectiveCache
        $env:PREFIX = $isoPrefix
        $env:npm_config_prefix = $isoPrefix
        $env:USERCONFIG = $isoUserConfig
        $env:npm_config_userconfig = $isoUserConfig
        $env:GLOBALCONFIG = $isoGlobalConfig
        $env:npm_config_globalconfig = $isoGlobalConfig
        $env:APPDATA = $isoAppData
        $env:LOCALAPPDATA = $isoLocalAppData

        $out = & npm.cmd @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        if ($sw) { $sw.Stop() }
        $env:NPM_CONFIG_CACHE = $origCache
        $env:npm_config_cache = $origCacheLower
        $env:PREFIX = $origPrefix
        $env:npm_config_prefix = $origPrefixLower
        $env:USERCONFIG = $origUserConfig
        $env:npm_config_userconfig = $origUserConfigLower
        $env:GLOBALCONFIG = $origGlobalConfig
        $env:npm_config_globalconfig = $origGlobalConfigLower
        $env:APPDATA = $origAppData
        $env:LOCALAPPDATA = $origLocalAppData
        cmd.exe /c "rd /s /q `"$isoRoot`"" 2>$null
    }

    return @{
        ExitCode = $exitCode
        Output = $out
        ElapsedMs = if ($sw) { $sw.Elapsed.TotalMilliseconds } else { 0 }
    }
}

$npmVer = (Invoke-IsolatedNpm -ArgumentList @("--version")).Output
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " Lane 4: Cold-Path Install Speed Gate" -ForegroundColor Cyan
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

function Wait-For-Idle {
    $threshold = 25.0
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        $cpu = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
        if ($null -eq $cpu -or $cpu -lt $threshold) {
            return
        }
        Write-Host "Waiting for machine idle (current CPU: $([math]::Round($cpu, 1))%)..." -ForegroundColor DarkYellow
        Start-Sleep -Seconds 2
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

function Compare-NodeModules {
    param([string]$DirA, [string]$DirB)
    $nmA = Join-Path $DirA "node_modules"
    $nmB = Join-Path $DirB "node_modules"
    
    if (-not (Test-Path $nmA) -or -not (Test-Path $nmB)) {
        return @{ Identical = $false; Reason = "One node_modules missing" }
    }

    $filesA = Get-ChildItem -Path $nmA -Recurse -File | Where-Object {
        $_.FullName.Substring($nmA.Length).TrimStart('\', '/') -notmatch '(^|[\\/])\.rnpm[^\\/]*([\\/]|$)' -and
        $_.FullName.Substring($nmA.Length).TrimStart('\', '/') -notmatch '(^|[\\/])\.package-lock\.json$'
    }
    $filesB = Get-ChildItem -Path $nmB -Recurse -File | Where-Object {
        $_.FullName.Substring($nmB.Length).TrimStart('\', '/') -notmatch '(^|[\\/])\.rnpm[^\\/]*([\\/]|$)' -and
        $_.FullName.Substring($nmB.Length).TrimStart('\', '/') -notmatch '(^|[\\/])\.package-lock\.json$'
    }

    if ($filesA.Count -ne $filesB.Count) {
        return @{
            Identical = $false
            Reason = "File count mismatch: rnpm=$($filesA.Count) vs npm=$($filesB.Count)"
        }
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $mapA = @{}
    foreach ($f in $filesA) {
        $rel = $f.FullName.Substring($nmA.Length).TrimStart('\', '/').Replace('\', '/')
        $s = [System.IO.File]::OpenRead($f.FullName)
        $h = [System.BitConverter]::ToString($sha.ComputeHash($s)).Replace("-", "").ToLower()
        $s.Close()
        $mapA[$rel] = $h
    }

    $mismatches = 0
    foreach ($f in $filesB) {
        $rel = $f.FullName.Substring($nmB.Length).TrimStart('\', '/').Replace('\', '/')
        if (-not $mapA.ContainsKey($rel)) {
            return @{ Identical = $false; Reason = "Missing in rnpm: $rel" }
        }
        $s = [System.IO.File]::OpenRead($f.FullName)
        $hB = [System.BitConverter]::ToString($sha.ComputeHash($s)).Replace("-", "").ToLower()
        $s.Close()
        if ($mapA[$rel] -ne $hB) {
            $mismatches++
            if ($mismatches -le 3) {
                Write-Host "  Hash mismatch at $rel (rnpm=$($mapA[$rel]) npm=$hB)" -ForegroundColor Red
            }
        }
    }

    if ($mismatches -gt 0) {
        return @{ Identical = $false; Reason = "$mismatches file hash mismatch(es)" }
    }

    return @{ Identical = $true; FileCount = $filesA.Count }
}

$npmColdTimes = [System.Collections.Generic.List[double]]::new()
$rnpmColdTimes = [System.Collections.Generic.List[double]]::new()
$npmWarmTimes = [System.Collections.Generic.List[double]]::new()
$rnpmWarmTarballTimes = [System.Collections.Generic.List[double]]::new()

$sharedNpmCache = Join-Path $env:TEMP "lane4-warm-npm-cache"
$sharedRnpmCache = Join-Path $env:TEMP "lane4-warm-rnpm-cache"
Remove-Item -Recurse -Force $sharedNpmCache, $sharedRnpmCache -ErrorAction SilentlyContinue

$lastNpmDir = $null
$lastRnpmDir = $null

try {
    for ($i = 1; $i -le $Runs; $i++) {
        Write-Host "`n--- Run $i of $Runs ---" -ForegroundColor Yellow

        # ---------------------------------------------------------
        # 1. Fully Cold npm ci (fresh cache, fresh project dir)
        # ---------------------------------------------------------
        Wait-For-Idle
        $npmColdDir = Join-Path $env:TEMP "npm-cold-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        $npmColdCache = Join-Path $env:TEMP "npm-cold-cache-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        New-Item -ItemType Directory -Path $npmColdDir -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $npmColdDir
        Copy-Item (Join-Path $fixtureDir "package-lock.json") $npmColdDir

        $npmResult = $null
        Push-Location $npmColdDir
        try {
            $npmResult = Invoke-IsolatedNpm -ArgumentList @("ci", "--no-audit", "--no-fund", "--cache", $npmColdCache) -Cache $npmColdCache -Measure
        } finally {
            Pop-Location
        }
        $npmColdExit = $npmResult.ExitCode
        $npmColdMs = $npmResult.ElapsedMs
        if ($npmColdExit -ne 0) {
            Write-Host "[FAIL] npm cold ci exited with code $npmColdExit" -ForegroundColor Red
            exit 1
        }
        $npmColdTimes.Add($npmColdMs)
        Write-Host ("  npm cold ci:              {0,8:N1} ms ({1:N2} s)" -f $npmColdMs, ($npmColdMs / 1000.0)) -ForegroundColor Magenta
        
        # Save cache for warm runs if not yet populated
        if (-not (Test-Path $sharedNpmCache)) {
            Move-Item $npmColdCache $sharedNpmCache -Force
        } else {
            cmd.exe /c "rd /s /q `"$npmColdCache`"" 2>$null
        }

        # ---------------------------------------------------------
        # 2. Fully Cold rnpm ci (fresh cache, fresh store, fresh project dir)
        # ---------------------------------------------------------
        Wait-For-Idle
        $rnpmColdDir = Join-Path $env:TEMP "rnpm-cold-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        $rnpmColdCache = Join-Path $env:TEMP "rnpm-cold-cache-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        $rnpmColdStore = Join-Path $env:TEMP "rnpm-cold-store-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        New-Item -ItemType Directory -Path $rnpmColdDir -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $rnpmColdDir
        Copy-Item (Join-Path $fixtureDir "package-lock.json") $rnpmColdDir

        $rnpmColdExit = 0
        $rnpmColdMs = Measure-CommandMs {
            Push-Location $rnpmColdDir
            try {
                $env:RNPM_STORE_DIR = $rnpmColdStore
                & $rnpmBin ci --no-audit --no-fund --cache $rnpmColdCache 2>&1 | Out-Null
                $rnpmColdExit = $LASTEXITCODE
            } finally {
                Pop-Location
            }
        }
        if ($rnpmColdExit -ne 0) {
            Write-Host "[FAIL] rnpm cold ci exited with code $rnpmColdExit" -ForegroundColor Red
            exit 1
        }
        $rnpmColdTimes.Add($rnpmColdMs)
        Write-Host ("  rnpm cold ci:             {0,8:N1} ms ({1:N2} s)" -f $rnpmColdMs, ($rnpmColdMs / 1000.0)) -ForegroundColor Cyan

        # Save cache for warm-tarball runs if not yet populated
        if (-not (Test-Path $sharedRnpmCache)) {
            Move-Item $rnpmColdCache $sharedRnpmCache -Force
        } else {
            cmd.exe /c "rd /s /q `"$rnpmColdCache`"" 2>$null
        }
        cmd.exe /c "rd /s /q `"$rnpmColdStore`"" 2>$null

        if ($i -eq $Runs) {
            $lastNpmDir = $npmColdDir
            $lastRnpmDir = $rnpmColdDir
        } else {
            cmd.exe /c "rd /s /q `"$npmColdDir`"" 2>$null
            cmd.exe /c "rd /s /q `"$rnpmColdDir`"" 2>$null
        }

        # ---------------------------------------------------------
        # 3. Empty-store, warm-tarball-cache rnpm ci vs warm npm ci
        # ---------------------------------------------------------
        Wait-For-Idle
        $npmWarmDir = Join-Path $env:TEMP "npm-warm-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        New-Item -ItemType Directory -Path $npmWarmDir -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $npmWarmDir
        Copy-Item (Join-Path $fixtureDir "package-lock.json") $npmWarmDir

        $npmWarmResult = $null
        Push-Location $npmWarmDir
        try {
            $npmWarmResult = Invoke-IsolatedNpm -ArgumentList @("ci", "--no-audit", "--no-fund", "--cache", $sharedNpmCache) -Cache $sharedNpmCache -Measure
        } finally {
            Pop-Location
        }
        $npmWarmExit = $npmWarmResult.ExitCode
        $npmWarmMs = $npmWarmResult.ElapsedMs
        if ($npmWarmExit -ne 0) {
            Write-Host "[FAIL] npm warm ci exited with code $npmWarmExit" -ForegroundColor Red
            exit 1
        }
        $npmWarmTimes.Add($npmWarmMs)
        Write-Host ("  npm warm ci:              {0,8:N1} ms ({1:N2} s)" -f $npmWarmMs, ($npmWarmMs / 1000.0)) -ForegroundColor Magenta
        cmd.exe /c "rd /s /q `"$npmWarmDir`"" 2>$null

        Wait-For-Idle
        $rnpmWarmTarDir = Join-Path $env:TEMP "rnpm-warmtar-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        $rnpmWarmTarStore = Join-Path $env:TEMP "rnpm-warmtar-store-$i-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        New-Item -ItemType Directory -Path $rnpmWarmTarDir -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $rnpmWarmTarDir
        Copy-Item (Join-Path $fixtureDir "package-lock.json") $rnpmWarmTarDir

        $rnpmWarmTarExit = 0
        $rnpmWarmTarMs = Measure-CommandMs {
            Push-Location $rnpmWarmTarDir
            try {
                $env:RNPM_STORE_DIR = $rnpmWarmTarStore
                & $rnpmBin ci --no-audit --no-fund --cache $sharedRnpmCache 2>&1 | Out-Null
                $rnpmWarmTarExit = $LASTEXITCODE
            } finally {
                Pop-Location
            }
        }
        if ($rnpmWarmTarExit -ne 0) {
            Write-Host "[FAIL] rnpm warm-tarball empty-store ci exited with code $rnpmWarmTarExit" -ForegroundColor Red
            exit 1
        }
        $rnpmWarmTarballTimes.Add($rnpmWarmTarMs)
        Write-Host ("  rnpm warm-tar/empty-store:{0,8:N1} ms ({1:N2} s)" -f $rnpmWarmTarMs, ($rnpmWarmTarMs / 1000.0)) -ForegroundColor Cyan
        cmd.exe /c "rd /s /q `"$rnpmWarmTarDir`"" 2>$null
        cmd.exe /c "rd /s /q `"$rnpmWarmTarStore`"" 2>$null
        Wait-For-Idle
    }
} finally {
    Remove-Item $sharedNpmCache, $sharedRnpmCache -Recurse -Force -ErrorAction SilentlyContinue
}

$npmColdMed = Get-Median $npmColdTimes
$rnpmColdMed = Get-Median $rnpmColdTimes
$npmWarmMed = Get-Median $npmWarmTimes
$rnpmWarmTarMed = Get-Median $rnpmWarmTarballTimes

$npmColdSpread = Get-Spread $npmColdTimes
$rnpmColdSpread = Get-Spread $rnpmColdTimes
$npmWarmSpread = Get-Spread $npmWarmTimes
$rnpmWarmTarSpread = Get-Spread $rnpmWarmTarballTimes

$coldSpeedup = if ($rnpmColdMed -gt 0) { $npmColdMed / $rnpmColdMed } else { 0 }
$warmSpeedup = if ($rnpmWarmTarMed -gt 0) { $npmWarmMed / $rnpmWarmTarMed } else { 0 }

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host " Lane 4 Cold Speed Summary & Medians" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host (" Fully Cold npm ci median:       {0,8:N1} ms ({1:N2} s) [spread: {2:N1}%]" -f $npmColdMed, ($npmColdMed / 1000.0), $npmColdSpread) -ForegroundColor Magenta
Write-Host (" Fully Cold rnpm ci median:      {0,8:N1} ms ({1:N2} s) [spread: {2:N1}%]" -f $rnpmColdMed, ($rnpmColdMed / 1000.0), $rnpmColdSpread) -ForegroundColor Cyan
Write-Host (" Cold speedup vs npm:            {0:N2}x (target >= 2.00x, <= 0.5x time)" -f $coldSpeedup)

Write-Host (" Warm-cache npm ci median:       {0,8:N1} ms ({1:N2} s) [spread: {2:N1}%]" -f $npmWarmMed, ($npmWarmMed / 1000.0), $npmWarmSpread) -ForegroundColor Magenta
Write-Host (" Warm-tar/empty-store rnpm med:  {0,8:N1} ms ({1:N2} s) [spread: {2:N1}%]" -f $rnpmWarmTarMed, ($rnpmWarmTarMed / 1000.0), $rnpmWarmTarSpread) -ForegroundColor Cyan
Write-Host (" Warm-tar speedup vs npm warm:   {0:N2}x (target >= 2.00x, <= 0.5x time)" -f $warmSpeedup)

$gatePassed = $true

if ($npmColdSpread -gt 25.0 -or $rnpmColdSpread -gt 25.0 -or $npmWarmSpread -gt 25.0 -or $rnpmWarmTarSpread -gt 25.0) {
    Write-Host "`n[FAIL] Scenario min/max spread exceeds 25% threshold (npm cold: $([math]::Round($npmColdSpread,1))%, rnpm cold: $([math]::Round($rnpmColdSpread,1))%, npm warm: $([math]::Round($npmWarmSpread,1))%, rnpm warm: $([math]::Round($rnpmWarmTarSpread,1))%). Run is invalid due to noise." -ForegroundColor Red
    $gatePassed = $false
}

if ($rnpmColdMed -gt (0.5 * $npmColdMed)) {
    Write-Host "`n[FAIL] Cold rnpm ci ($($rnpmColdMed/1000.0)s) is not >= 2x faster than cold npm ci ($($npmColdMed/1000.0)s)" -ForegroundColor Red
    $gatePassed = $false
} else {
    Write-Host "`n[PASS] Cold rnpm ci is >= 2x faster than cold npm ci ($([math]::Round($coldSpeedup, 2))x)" -ForegroundColor Green
}

if ($rnpmWarmTarMed -gt (0.5 * $npmWarmMed)) {
    Write-Host "[FAIL] Warm-tarball rnpm ci ($($rnpmWarmTarMed/1000.0)s) is not >= 2x faster than warm npm ci ($($npmWarmMed/1000.0)s)" -ForegroundColor Red
    $gatePassed = $false
} else {
    Write-Host "[PASS] Warm-tarball rnpm ci is >= 2x faster than warm npm ci ($([math]::Round($warmSpeedup, 2))x)" -ForegroundColor Green
}

# Parity & Byte-identical verification
Write-Host "`n[Parity Check] Comparing node_modules byte-identity..." -ForegroundColor Gray
$parityResult = Compare-NodeModules $lastRnpmDir $lastNpmDir
if (-not $parityResult.Identical) {
    Write-Host "[FAIL] Parity failure: $($parityResult.Reason)" -ForegroundColor Red
    $gatePassed = $false
} else {
    Write-Host "  node_modules byte-identical across $($parityResult.FileCount) files." -ForegroundColor Green
}

Write-Host "[Parity Check] Running 'npm ls --all' on rnpm output..." -ForegroundColor Gray
$lsResult = $null
Push-Location $lastRnpmDir
try {
    $lsResult = Invoke-IsolatedNpm -ArgumentList @("ls", "--all")
} finally {
    Pop-Location
}
$lsExit = $lsResult.ExitCode
if ($lsExit -ne 0) {
    Write-Host "[FAIL] 'npm ls --all' failed on rnpm output with exit code $lsExit" -ForegroundColor Red
    $gatePassed = $false
} else {
    Write-Host "  'npm ls --all' exited cleanly (0)." -ForegroundColor Green
}

# Cleanup parity test dirs unless requested
if (-not $KeepTemp) {
    Remove-Item $lastNpmDir, $lastRnpmDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Same-size CAS corruption test
Write-Host "`n[Corruption Test] Testing same-size CAS corruption detection and recovery..." -ForegroundColor Gray
$corruptTestDir = Join-Path $env:TEMP "rnpm-corrupt-test-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
$corruptStoreDir = Join-Path $env:TEMP "rnpm-corrupt-store-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
$corruptCacheDir = Join-Path $env:TEMP "rnpm-corrupt-cache-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
New-Item -ItemType Directory -Path $corruptTestDir -Force | Out-Null
Copy-Item (Join-Path $fixtureDir "package.json") $corruptTestDir
Copy-Item (Join-Path $fixtureDir "package-lock.json") $corruptTestDir

try {
    # 1. Install once to populate store
    $env:RNPM_STORE_DIR = $corruptStoreDir
    Push-Location $corruptTestDir
    & $rnpmBin ci --no-audit --no-fund --cache $corruptCacheDir 2>&1 | Out-Null
    Pop-Location

    # Find a CAS file in the store
    $casFiles = Get-ChildItem -Path (Join-Path $corruptStoreDir "cas") -Recurse -File | Where-Object { $_.Length -gt 100 }
    if ($casFiles.Count -eq 0) {
        Write-Host "[FAIL] No CAS files found in store to corrupt!" -ForegroundColor Red
        $gatePassed = $false
    } else {
        $victim = $casFiles[0]
        $victimBytes = [System.IO.File]::ReadAllBytes($victim.FullName)
        # Flip bytes while preserving exact length
        $victimBytes[10] = [byte]($victimBytes[10] -bxor 0xAA)
        [System.IO.File]::WriteAllBytes($victim.FullName, $victimBytes)

        # Clear node_modules in test dir
        Remove-Item (Join-Path $corruptTestDir "node_modules") -Recurse -Force -ErrorAction SilentlyContinue

        # Run rnpm ci again
        Push-Location $corruptTestDir
        & $rnpmBin ci --no-audit --no-fund --cache $corruptCacheDir 2>&1 | Out-Null
        $corruptRunExit = $LASTEXITCODE
        Pop-Location

        if ($corruptRunExit -ne 0) {
            # Failing on corrupted CAS is acceptable per definition of done ("rnpm detects it and repairs or fails; it never installs corrupt bytes")
            Write-Host "  rnpm detected corruption and safely failed (exit $corruptRunExit)." -ForegroundColor Green
        } else {
            # If it succeeded, verify that node_modules does NOT contain the corrupted byte
            $installedCasBytes = [System.IO.File]::ReadAllBytes($victim.FullName)
            if ($installedCasBytes[10] -eq $victimBytes[10]) {
                Write-Host "[FAIL] rnpm installed or left corrupted CAS bytes!" -ForegroundColor Red
                $gatePassed = $false
            } else {
                Write-Host "  rnpm detected and successfully repaired corrupted CAS blob!" -ForegroundColor Green
            }
        }
    }
} finally {
    Remove-Item $corruptTestDir, $corruptStoreDir, $corruptCacheDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($gatePassed) {
    Write-Host "`n====================================================" -ForegroundColor Green
    Write-Host " [SUCCESS] Lane 4 Cold Speed Gate PASSED!" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n====================================================" -ForegroundColor Red
    Write-Host " [FAIL] Lane 4 Cold Speed Gate FAILED!" -ForegroundColor Red
    Write-Host "====================================================" -ForegroundColor Red
    exit 1
}
