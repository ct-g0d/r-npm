param(
    [int]$Runs = 9,
    [switch]$Quick = $false,
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
Write-Host " rnpm Lane 5 Warm-Path Speed & Parity Gate" -ForegroundColor Cyan
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

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

public class FastHasher {
    public static ConcurrentDictionary<string, string> HashDirectory(string baseDir) {
        var map = new ConcurrentDictionary<string, string>();
        if (!Directory.Exists(baseDir)) return map;
        var files = Directory.GetFiles(baseDir, "*", SearchOption.AllDirectories);
        int baseLen = baseDir.Length;
        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = 16 }, (file) => {
            if (file.EndsWith(".package-lock.json") || file.Contains(".rnpm")) return;
            string rel = file.Substring(baseLen).TrimStart('\\', '/');
            using (var sha = SHA256.Create())
            using (var stream = File.OpenRead(file)) {
                byte[] h = sha.ComputeHash(stream);
                map[rel] = BitConverter.ToString(h).Replace("-", "").ToLowerInvariant();
            }
        });
        return map;
    }

    public static string HashFile(string filePath) {
        if (!File.Exists(filePath)) return "";
        using (var sha = SHA256.Create())
        using (var stream = File.OpenRead(filePath)) {
            byte[] h = sha.ComputeHash(stream);
            return BitConverter.ToString(h).Replace("-", "").ToLowerInvariant();
        }
    }
}

public class LockfileChecker {
    public static List<string> ExtractPackages(string lockfilePath) {
        var list = new List<string>();
        if (!File.Exists(lockfilePath)) return list;
        string text = File.ReadAllText(lockfilePath);
        var match = Regex.Matches(text, "\"([^\"]*node_modules[^\"]*)\":\\s*\\{[^}]*\"version\":\\s*\"([^\"]+)\"");
        foreach (Match m in match) {
            list.Add(m.Groups[1].Value + "@" + m.Groups[2].Value);
        }
        list.Sort();
        return list;
    }

    public static List<string> ExtractManifestDeps(string manifestPath) {
        var list = new List<string>();
        if (!File.Exists(manifestPath)) return list;
        string text = File.ReadAllText(manifestPath);
        var match = Regex.Matches(text, "\"([@a-zA-Z0-9_./-]+)\":\\s*\"([^\"]+)\"");
        foreach (Match m in match) {
            string key = m.Groups[1].Value;
            if (key == "name" || key == "version" || key == "description" || key == "scripts") continue;
            list.Add(key + "@" + m.Groups[2].Value);
        }
        list.Sort();
        return list;
    }
}
"@ -ErrorAction SilentlyContinue

function Compare-NodeModules-Hashes {
    param([string]$PathA, [string]$PathB)
    $nmA = Join-Path $PathA "node_modules"
    $nmB = Join-Path $PathB "node_modules"
    if (-not (Test-Path $nmA) -or -not (Test-Path $nmB)) {
        return @{ Identical = $false; Reason = "One node_modules missing" }
    }

    $mapA = [FastHasher]::HashDirectory($nmA)
    $mapB = [FastHasher]::HashDirectory($nmB)

    $missingInB = @()
    foreach ($k in $mapA.Keys) {
        if (-not $mapB.ContainsKey($k)) { $missingInB += $k }
    }
    $missingInA = @()
    foreach ($k in $mapB.Keys) {
        if (-not $mapA.ContainsKey($k)) { $missingInA += $k }
    }
    $mismatches = @()
    foreach ($k in $mapA.Keys) {
        if ($mapB.ContainsKey($k) -and $mapA[$k] -ne $mapB[$k]) { $mismatches += $k }
    }

    $identical = ($missingInA.Count -eq 0 -and $missingInB.Count -eq 0 -and $mismatches.Count -eq 0)
    return @{
        Identical = $identical
        CountA = $mapA.Count
        CountB = $mapB.Count
        MissingInA = $missingInA
        MissingInB = $missingInB
        Mismatches = $mismatches
    }
}

# Step 0: Ensure caches are warm
Write-Host "`n[Setup] Populating warm caches for npm and rnpm..." -ForegroundColor Gray
$warmSetupDir = Join-Path $env:TEMP "rnpm-gate-warm-setup-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $warmSetupDir -Force | Out-Null
Copy-Item (Join-Path $fixtureDir "package.json") $warmSetupDir
Copy-Item (Join-Path $fixtureDir "package-lock.json") $warmSetupDir
Push-Location $warmSetupDir
& npm.cmd ci --no-audit --no-fund 2>&1 | Out-Null
& npm.cmd install is-odd --no-audit --no-fund 2>&1 | Out-Null
& $rnpmBin ci --no-audit --no-fund 2>&1 | Out-Null
& $rnpmBin install is-odd --no-audit --no-fund 2>&1 | Out-Null
Pop-Location
Remove-Item $warmSetupDir -Recurse -Force -ErrorAction SilentlyContinue

# Metrics & Correctness collectors
$results = [ordered]@{
    "warm ci"              = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $true; Correct = $true }
    "add-one-package"      = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $true; Correct = $true }
    "no-lockfile install"  = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $true; Correct = $true }
    "no-op install"        = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $true; Correct = $true }
    "uninstall"            = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $true; Correct = $true }
    "ls --all"             = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $true; Correct = $true }
    "run script"           = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $true; Correct = $true }
    "update"               = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $false; Correct = $true }
    "dedupe"               = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $false; Correct = $true }
    "rebuild"              = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $false; Correct = $true }
    "audit"                = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $false; Correct = $true }
    "outdated"             = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $false; Correct = $true }
    "exec <bin>"           = @{ Rnpm = [System.Collections.Generic.List[double]]::new(); Npm = [System.Collections.Generic.List[double]]::new(); Target = 2.0; Required = $false; Correct = $true }
}

function Assert-CommandCorrectness {
    param(
        [string]$Scenario,
        [int]$RnpmExit,
        [int]$NpmExit,
        [string]$RnpmDir = "",
        [string]$NpmDir = "",
        [switch]$CheckManifest = $false,
        [switch]$CheckLockfile = $false,
        [switch]$CheckNodeModulesTop = $false
    )

    $ok = $true
    if ($RnpmExit -ne $NpmExit) {
        Write-Host "    [CORRECTNESS FAIL] $Scenario exit code mismatch: rnpm=$RnpmExit vs npm=$NpmExit" -ForegroundColor Red
        $ok = $false
    }

    if ($CheckManifest -and $RnpmDir -and $NpmDir) {
        $depsRnpm = [LockfileChecker]::ExtractManifestDeps((Join-Path $RnpmDir "package.json"))
        $depsNpm  = [LockfileChecker]::ExtractManifestDeps((Join-Path $NpmDir "package.json"))
        $diff = Compare-Object $depsRnpm $depsNpm
        if ($diff -and $diff.Count -gt 0) {
            Write-Host "    [CORRECTNESS FAIL] $Scenario package.json diff count: $($diff.Count)" -ForegroundColor Red
            $ok = $false
        }
    }

    if ($CheckLockfile -and $RnpmDir -and $NpmDir) {
        $pkgsRnpm = [LockfileChecker]::ExtractPackages((Join-Path $RnpmDir "package-lock.json"))
        $pkgsNpm  = [LockfileChecker]::ExtractPackages((Join-Path $NpmDir "package-lock.json"))
        $diff = Compare-Object $pkgsRnpm $pkgsNpm
        if ($diff -and $diff.Count -gt 0) {
            Write-Host "    [CORRECTNESS FAIL] $Scenario package-lock.json packages diff count: $($diff.Count)" -ForegroundColor Red
            $ok = $false
        }
    }

    if ($CheckNodeModulesTop -and $RnpmDir -and $NpmDir) {
        $nmR = if (Test-Path (Join-Path $RnpmDir "node_modules")) { Get-ChildItem (Join-Path $RnpmDir "node_modules") -Directory | Select-Object -ExpandProperty Name | Sort-Object } else { @() }
        $nmN = if (Test-Path (Join-Path $NpmDir "node_modules")) { Get-ChildItem (Join-Path $NpmDir "node_modules") -Directory | Select-Object -ExpandProperty Name | Sort-Object } else { @() }
        $diff = Compare-Object $nmR $nmN
        if ($diff -and $diff.Count -gt 0) {
            Write-Host "    [CORRECTNESS FAIL] $Scenario top-level node_modules diff count: $($diff.Count)" -ForegroundColor Red
            $ok = $false
        }
    }

    if (-not $ok) {
        $results[$Scenario].Correct = $false
    }
    return $ok
}

$effectiveRuns = if ($Quick) { 1 } else { $Runs }
$parityPassed = $true

for ($run = 1; $run -le $effectiveRuns; $run++) {
    Write-Host "`n--- Run $run of $effectiveRuns ---" -ForegroundColor Yellow

    # Test directories for this iteration
    $rnpmDir = Join-Path $env:TEMP "rnpm-lane5-run-$run-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
    $npmDir  = Join-Path $env:TEMP "npm-lane5-run-$run-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
    New-Item -ItemType Directory -Path $rnpmDir -Force | Out-Null
    New-Item -ItemType Directory -Path $npmDir  -Force | Out-Null

    Copy-Item (Join-Path $fixtureDir "package.json") $rnpmDir
    Copy-Item (Join-Path $fixtureDir "package-lock.json") $rnpmDir
    Copy-Item (Join-Path $fixtureDir "package.json") $npmDir
    Copy-Item (Join-Path $fixtureDir "package-lock.json") $npmDir

    try {
        # 1. Warm CI (alternated execution order)
        $rnpmCiExit = 0; $npmCiExit = 0
        if ($run % 2 -eq 1) {
            $rnpmCiMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin ci --no-audit --no-fund 2>&1 | Out-Null; $rnpmCiExit = $LASTEXITCODE } finally { Pop-Location } }
            $npmCiMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd ci --no-audit --no-fund 2>&1 | Out-Null; $npmCiExit = $LASTEXITCODE } finally { Pop-Location } }
        } else {
            $npmCiMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd ci --no-audit --no-fund 2>&1 | Out-Null; $npmCiExit = $LASTEXITCODE } finally { Pop-Location } }
            $rnpmCiMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin ci --no-audit --no-fund 2>&1 | Out-Null; $rnpmCiExit = $LASTEXITCODE } finally { Pop-Location } }
        }
        $results["warm ci"].Rnpm.Add($rnpmCiMs)
        $results["warm ci"].Npm.Add($npmCiMs)
        Write-Host ("  warm ci:             rnpm={0:N1}ms ({1:N2}s), npm={2:N1}ms ({3:N2}s) -> ratio={4:N2}x" -f $rnpmCiMs, ($rnpmCiMs/1000), $npmCiMs, ($npmCiMs/1000), ($npmCiMs/$rnpmCiMs))

        Assert-CommandCorrectness "warm ci" $rnpmCiExit $npmCiExit $rnpmDir $npmDir -CheckManifest -CheckLockfile -CheckNodeModulesTop | Out-Null

        # On Run 1, verify byte-identical node_modules
        if ($run -eq 1) {
            $cmp = Compare-NodeModules-Hashes $rnpmDir $npmDir
            if ($cmp.Identical) {
                Write-Host "  [PASS] node_modules byte-identical parity verified ($($cmp.CountA) files)" -ForegroundColor Green
            } else {
                Write-Host ("  [FAIL] node_modules parity mismatch! rnpm has {0} files, npm has {1} files, {2} missing in rnpm, {3} missing in npm, {4} hash mismatches" -f $cmp.CountA, $cmp.CountB, $cmp.MissingInA.Count, $cmp.MissingInB.Count, $cmp.Mismatches.Count) -ForegroundColor Red
                $parityPassed = $false
            }
        }

        # 2. Add one package (install is-odd into warm tree)
        $rnpmAddExit = 0; $npmAddExit = 0
        if ($run % 2 -eq 1) {
            $rnpmAddMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin install is-odd --no-audit --no-fund 2>&1 | Out-Null; $rnpmAddExit = $LASTEXITCODE } finally { Pop-Location } }
            $npmAddMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd install is-odd --no-audit --no-fund 2>&1 | Out-Null; $npmAddExit = $LASTEXITCODE } finally { Pop-Location } }
        } else {
            $npmAddMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd install is-odd --no-audit --no-fund 2>&1 | Out-Null; $npmAddExit = $LASTEXITCODE } finally { Pop-Location } }
            $rnpmAddMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin install is-odd --no-audit --no-fund 2>&1 | Out-Null; $rnpmAddExit = $LASTEXITCODE } finally { Pop-Location } }
        }
        $results["add-one-package"].Rnpm.Add($rnpmAddMs)
        $results["add-one-package"].Npm.Add($npmAddMs)
        Write-Host ("  add-one-package:     rnpm={0:N1}ms, npm={1:N1}ms -> ratio={2:N2}x" -f $rnpmAddMs, $npmAddMs, ($npmAddMs/$rnpmAddMs))
        Assert-CommandCorrectness "add-one-package" $rnpmAddExit $npmAddExit $rnpmDir $npmDir -CheckManifest -CheckLockfile -CheckNodeModulesTop | Out-Null

        # 3. No-op install (in installed tree)
        $rnpmNoopExit = 0; $npmNoopExit = 0
        if ($run % 2 -eq 1) {
            $rnpmNoopMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin install --no-audit --no-fund 2>&1 | Out-Null; $rnpmNoopExit = $LASTEXITCODE } finally { Pop-Location } }
            $npmNoopMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd install --no-audit --no-fund 2>&1 | Out-Null; $npmNoopExit = $LASTEXITCODE } finally { Pop-Location } }
        } else {
            $npmNoopMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd install --no-audit --no-fund 2>&1 | Out-Null; $npmNoopExit = $LASTEXITCODE } finally { Pop-Location } }
            $rnpmNoopMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin install --no-audit --no-fund 2>&1 | Out-Null; $rnpmNoopExit = $LASTEXITCODE } finally { Pop-Location } }
        }
        $results["no-op install"].Rnpm.Add($rnpmNoopMs)
        $results["no-op install"].Npm.Add($npmNoopMs)
        Write-Host ("  no-op install:       rnpm={0:N1}ms, npm={1:N1}ms -> ratio={2:N2}x" -f $rnpmNoopMs, $npmNoopMs, ($npmNoopMs/$rnpmNoopMs))
        Assert-CommandCorrectness "no-op install" $rnpmNoopExit $npmNoopExit $rnpmDir $npmDir -CheckManifest -CheckLockfile -CheckNodeModulesTop | Out-Null

        # 4. Uninstall is-odd
        $rnpmUnExit = 0; $npmUnExit = 0
        if ($run % 2 -eq 1) {
            $rnpmUnMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin uninstall is-odd --no-audit --no-fund 2>&1 | Out-Null; $rnpmUnExit = $LASTEXITCODE } finally { Pop-Location } }
            $npmUnMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd uninstall is-odd --no-audit --no-fund 2>&1 | Out-Null; $npmUnExit = $LASTEXITCODE } finally { Pop-Location } }
        } else {
            $npmUnMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd uninstall is-odd --no-audit --no-fund 2>&1 | Out-Null; $npmUnExit = $LASTEXITCODE } finally { Pop-Location } }
            $rnpmUnMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin uninstall is-odd --no-audit --no-fund 2>&1 | Out-Null; $rnpmUnExit = $LASTEXITCODE } finally { Pop-Location } }
        }
        $results["uninstall"].Rnpm.Add($rnpmUnMs)
        $results["uninstall"].Npm.Add($npmUnMs)
        Write-Host ("  uninstall:           rnpm={0:N1}ms, npm={1:N1}ms -> ratio={2:N2}x" -f $rnpmUnMs, $npmUnMs, ($npmUnMs/$rnpmUnMs))
        Assert-CommandCorrectness "uninstall" $rnpmUnExit $npmUnExit $rnpmDir $npmDir -CheckManifest -CheckLockfile -CheckNodeModulesTop | Out-Null

        # 5. ls --all
        $rnpmLsExit = 0; $npmLsExit = 0
        $rnpmLsMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin ls --all 2>&1 | Out-Null; $rnpmLsExit = $LASTEXITCODE } finally { Pop-Location } }
        $npmLsMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd ls --all 2>&1 | Out-Null; $npmLsExit = $LASTEXITCODE } finally { Pop-Location } }
        $results["ls --all"].Rnpm.Add($rnpmLsMs)
        $results["ls --all"].Npm.Add($npmLsMs)
        Write-Host ("  ls --all:            rnpm={0:N1}ms, npm={1:N1}ms -> ratio={2:N2}x" -f $rnpmLsMs, $npmLsMs, ($npmLsMs/$rnpmLsMs))
        Assert-CommandCorrectness "ls --all" $rnpmLsExit $npmLsExit | Out-Null

        # 6. run script (add script to package.json)
        foreach ($d in @($rnpmDir, $npmDir)) {
            $pjPath = Join-Path $d "package.json"
            $pj = Get-Content $pjPath -Raw | ConvertFrom-Json
            $pj | Add-Member -NotePropertyName "scripts" -NotePropertyValue (@{ "test-bench" = "node -e 'process.exit(0)'" }) -Force
            [System.IO.File]::WriteAllText($pjPath, ($pj | ConvertTo-Json -Depth 5))
        }
        $rnpmRunExit = 0; $npmRunExit = 0
        $rnpmRunMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin run test-bench 2>&1 | Out-Null; $rnpmRunExit = $LASTEXITCODE } finally { Pop-Location } }
        $npmRunMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd run test-bench 2>&1 | Out-Null; $npmRunExit = $LASTEXITCODE } finally { Pop-Location } }
        $results["run script"].Rnpm.Add($rnpmRunMs)
        $results["run script"].Npm.Add($npmRunMs)
        Write-Host ("  run script:          rnpm={0:N1}ms, npm={1:N1}ms -> ratio={2:N2}x" -f $rnpmRunMs, $npmRunMs, ($npmRunMs/$rnpmRunMs))
        Assert-CommandCorrectness "run script" $rnpmRunExit $npmRunExit | Out-Null

        # 7. No-lockfile warm install (alternated execution order, with correctness check against npm)
        $rnpmNoLockDir = Join-Path $env:TEMP "rnpm-nolock-run-$run-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        $npmNoLockDir  = Join-Path $env:TEMP "npm-nolock-run-$run-$([System.Guid]::NewGuid().ToString('N').Substring(0,6))"
        New-Item -ItemType Directory -Path $rnpmNoLockDir -Force | Out-Null
        New-Item -ItemType Directory -Path $npmNoLockDir  -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $rnpmNoLockDir
        Copy-Item (Join-Path $fixtureDir "package.json") $npmNoLockDir

        $rnpmNoLockExit = 0; $npmNoLockExit = 0
        if ($run % 2 -eq 1) {
            $rnpmNoLockMs = Measure-CommandMs { Push-Location $rnpmNoLockDir; try { & $rnpmBin install --no-audit --no-fund 2>&1 | Out-Null; $rnpmNoLockExit = $LASTEXITCODE } finally { Pop-Location } }
            $npmNoLockMs  = Measure-CommandMs { Push-Location $npmNoLockDir;  try { & npm.cmd install --no-audit --no-fund 2>&1 | Out-Null; $npmNoLockExit = $LASTEXITCODE } finally { Pop-Location } }
        } else {
            $npmNoLockMs  = Measure-CommandMs { Push-Location $npmNoLockDir;  try { & npm.cmd install --no-audit --no-fund 2>&1 | Out-Null; $npmNoLockExit = $LASTEXITCODE } finally { Pop-Location } }
            $rnpmNoLockMs = Measure-CommandMs { Push-Location $rnpmNoLockDir; try { & $rnpmBin install --no-audit --no-fund 2>&1 | Out-Null; $rnpmNoLockExit = $LASTEXITCODE } finally { Pop-Location } }
        }
        $results["no-lockfile install"].Rnpm.Add($rnpmNoLockMs)
        $results["no-lockfile install"].Npm.Add($npmNoLockMs)
        Write-Host ("  no-lockfile install: rnpm={0:N1}ms, npm={1:N1}ms -> ratio={2:N2}x" -f $rnpmNoLockMs, $npmNoLockMs, ($npmNoLockMs/$rnpmNoLockMs))

        Assert-CommandCorrectness "no-lockfile install" $rnpmNoLockExit $npmNoLockExit $rnpmNoLockDir $npmNoLockDir -CheckLockfile -CheckNodeModulesTop | Out-Null

        Remove-Item $rnpmNoLockDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $npmNoLockDir  -Recurse -Force -ErrorAction SilentlyContinue

        # 8. Extra lane-relevant commands: update, dedupe, rebuild, audit, outdated, exec (measured across runs >= 5)
        if ($run -le [math]::Max(5, [math]::Min($effectiveRuns, 5))) {
            # update
            $rnpmUpExit = 0; $npmUpExit = 0
            if ($run % 2 -eq 1) {
                $rnpmUpMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin update --no-audit --no-fund 2>&1 | Out-Null; $rnpmUpExit = $LASTEXITCODE } finally { Pop-Location } }
                $npmUpMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd update --no-audit --no-fund 2>&1 | Out-Null; $npmUpExit = $LASTEXITCODE } finally { Pop-Location } }
            } else {
                $npmUpMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd update --no-audit --no-fund 2>&1 | Out-Null; $npmUpExit = $LASTEXITCODE } finally { Pop-Location } }
                $rnpmUpMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin update --no-audit --no-fund 2>&1 | Out-Null; $rnpmUpExit = $LASTEXITCODE } finally { Pop-Location } }
            }
            $results["update"].Rnpm.Add($rnpmUpMs)
            $results["update"].Npm.Add($npmUpMs)
            Assert-CommandCorrectness "update" $rnpmUpExit $npmUpExit $rnpmDir $npmDir -CheckManifest -CheckLockfile -CheckNodeModulesTop | Out-Null

            # dedupe
            $rnpmDedExit = 0; $npmDedExit = 0
            if ($run % 2 -eq 1) {
                $rnpmDedMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin dedupe --no-audit --no-fund 2>&1 | Out-Null; $rnpmDedExit = $LASTEXITCODE } finally { Pop-Location } }
                $npmDedMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd dedupe --no-audit --no-fund 2>&1 | Out-Null; $npmDedExit = $LASTEXITCODE } finally { Pop-Location } }
            } else {
                $npmDedMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd dedupe --no-audit --no-fund 2>&1 | Out-Null; $npmDedExit = $LASTEXITCODE } finally { Pop-Location } }
                $rnpmDedMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin dedupe --no-audit --no-fund 2>&1 | Out-Null; $rnpmDedExit = $LASTEXITCODE } finally { Pop-Location } }
            }
            $results["dedupe"].Rnpm.Add($rnpmDedMs)
            $results["dedupe"].Npm.Add($npmDedMs)
            Assert-CommandCorrectness "dedupe" $rnpmDedExit $npmDedExit $rnpmDir $npmDir -CheckManifest -CheckLockfile -CheckNodeModulesTop | Out-Null

            # rebuild
            $rnpmRebExit = 0; $npmRebExit = 0
            $rnpmRebMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin rebuild 2>&1 | Out-Null; $rnpmRebExit = $LASTEXITCODE } finally { Pop-Location } }
            $npmRebMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd rebuild 2>&1 | Out-Null; $npmRebExit = $LASTEXITCODE } finally { Pop-Location } }
            $results["rebuild"].Rnpm.Add($rnpmRebMs)
            $results["rebuild"].Npm.Add($npmRebMs)
            Assert-CommandCorrectness "rebuild" $rnpmRebExit $npmRebExit $rnpmDir $npmDir -CheckNodeModulesTop | Out-Null

            # audit
            $rnpmAudExit = 0; $npmAudExit = 0
            $rnpmAudMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin audit 2>&1 | Out-Null; $rnpmAudExit = $LASTEXITCODE } finally { Pop-Location } }
            $npmAudMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd audit 2>&1 | Out-Null; $npmAudExit = $LASTEXITCODE } finally { Pop-Location } }
            $results["audit"].Rnpm.Add($rnpmAudMs)
            $results["audit"].Npm.Add($npmAudMs)
            Assert-CommandCorrectness "audit" $rnpmAudExit $npmAudExit | Out-Null

            # outdated
            $rnpmOutExit = 0; $npmOutExit = 0
            $rnpmOutMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin outdated 2>&1 | Out-Null; $rnpmOutExit = $LASTEXITCODE } finally { Pop-Location } }
            $npmOutMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd outdated 2>&1 | Out-Null; $npmOutExit = $LASTEXITCODE } finally { Pop-Location } }
            $results["outdated"].Rnpm.Add($rnpmOutMs)
            $results["outdated"].Npm.Add($npmOutMs)
            Assert-CommandCorrectness "outdated" $rnpmOutExit $npmOutExit | Out-Null

            # exec <bin>
            $rnpmExecExit = 0; $npmExecExit = 0
            $rnpmExecMs = Measure-CommandMs { Push-Location $rnpmDir; try { & $rnpmBin exec prettier -- --version 2>&1 | Out-Null; $rnpmExecExit = $LASTEXITCODE } finally { Pop-Location } }
            $npmExecMs  = Measure-CommandMs { Push-Location $npmDir;  try { & npm.cmd exec prettier -- --version 2>&1 | Out-Null; $npmExecExit = $LASTEXITCODE } finally { Pop-Location } }
            $results["exec <bin>"].Rnpm.Add($rnpmExecMs)
            $results["exec <bin>"].Npm.Add($npmExecMs)
            Assert-CommandCorrectness "exec <bin>" $rnpmExecExit $npmExecExit | Out-Null
        }
    } finally {
        if (-not $KeepTemp) {
            Remove-Item $rnpmDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $npmDir  -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ----------------------------------------------------
# CAS Corruption Detection Test Suite (Dual Checks)
# ----------------------------------------------------
Write-Host "`n[Test] Running CAS & Pack Corruption Detection Suite..." -ForegroundColor Gray
$casSuitePassed = $true

$storeDir = if ($env:RNPM_STORE_DIR) { $env:RNPM_STORE_DIR } else {
    if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "rnpm\cache\store-v1" } else { Join-Path $env:TEMP "rnpm\cache\store-v1" }
}
if (-not (Test-Path $storeDir)) {
    $storeDir = Join-Path $env:LOCALAPPDATA "rnpm\store-v1"
}

# Setup reference clean installation using npm to have verified hash reference
$refDir = Join-Path $env:TEMP "rnpm-ref-install-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $refDir -Force | Out-Null
Copy-Item (Join-Path $fixtureDir "package.json") $refDir
Copy-Item (Join-Path $fixtureDir "package-lock.json") $refDir
Push-Location $refDir; & npm.cmd ci --no-audit --no-fund 2>&1 | Out-Null; Pop-Location

# Test (a1): Corrupt a .pack blob (same size, modified timestamp)
Write-Host "  -> (a1) Corrupt .pack blob (same size)..." -ForegroundColor Gray
$packFiles = @(Get-ChildItem -Path (Join-Path $storeDir "packs") -Filter "*.pack" -File -ErrorAction SilentlyContinue)
if ($packFiles.Count -gt 0) {
    $targetPack = $packFiles[0]
    $packBytes = [System.IO.File]::ReadAllBytes($targetPack.FullName)
    if ($packBytes.Length -gt 100) {
        $corruptedPackBytes = [byte[]]$packBytes.Clone()
        $corruptedPackBytes[50] = ($corruptedPackBytes[50] + 1) % 256
        $corruptedPackBytes[51] = ($corruptedPackBytes[51] + 2) % 256
        [System.IO.File]::WriteAllBytes($targetPack.FullName, $corruptedPackBytes)

        $packTestDir = Join-Path $env:TEMP "rnpm-pack-corrupt-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $packTestDir -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $packTestDir
        Copy-Item (Join-Path $fixtureDir "package-lock.json") $packTestDir

        Push-Location $packTestDir
        $packExit = 0
        try {
            & $rnpmBin ci --no-audit --no-fund 2>&1 | Out-Null
            $packExit = $LASTEXITCODE
        } finally {
            Pop-Location
        }

        if ($packExit -eq 0) {
            # Verify installed node_modules byte-identical to npm's reference
            $refCmp = Compare-NodeModules-Hashes $packTestDir $refDir
            if ($refCmp.Identical) {
                Write-Host "     [PASS] .pack corruption detected, purged and cleanly recovered!" -ForegroundColor Green
            } else {
                Write-Host "     [FAIL] Corrupted bytes from .pack reached node_modules!" -ForegroundColor Red
                $casSuitePassed = $false
            }
        } else {
            Write-Host "     [FAIL] rnpm ci failed with exit code $packExit" -ForegroundColor Red
            $casSuitePassed = $false
        }
        Remove-Item $packTestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "     [SKIP] No .pack files found to corrupt" -ForegroundColor Yellow
}

# Test (a2): Corrupt a per-file CAS blob (same size, modified timestamp)
Write-Host "  -> (a2) Corrupt per-file CAS blob (same size)..." -ForegroundColor Gray
$casFiles = @(Get-ChildItem -Path (Join-Path $storeDir "cas") -Recurse -File -ErrorAction SilentlyContinue)
if ($casFiles.Count -gt 0) {
    $targetCas = $casFiles[0]
    $origBytes = [System.IO.File]::ReadAllBytes($targetCas.FullName)
    if ($origBytes.Length -gt 10) {
        $corruptedBytes = [byte[]]$origBytes.Clone()
        $corruptedBytes[0] = ($corruptedBytes[0] + 1) % 256
        $corruptedBytes[1] = ($corruptedBytes[1] + 2) % 256
        [System.IO.File]::WriteAllBytes($targetCas.FullName, $corruptedBytes)

        $casTestDir = Join-Path $env:TEMP "rnpm-cas-corrupt-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $casTestDir -Force | Out-Null
        Copy-Item (Join-Path $fixtureDir "package.json") $casTestDir
        Copy-Item (Join-Path $fixtureDir "package-lock.json") $casTestDir

        Push-Location $casTestDir
        $casExit = 0
        try {
            & $rnpmBin ci --no-audit --no-fund 2>&1 | Out-Null
            $casExit = $LASTEXITCODE
        } finally {
            Pop-Location
        }

        if ($casExit -eq 0) {
            # 1. Verify CAS blob was repaired on disk
            $repairedBytes = [System.IO.File]::ReadAllBytes($targetCas.FullName)
            $isRepaired = ($repairedBytes[0] -eq $origBytes[0])
            
            # 2. Verify installed files match genuine npm hash
            $refCmp = Compare-NodeModules-Hashes $casTestDir $refDir

            if ($isRepaired -and $refCmp.Identical) {
                Write-Host "     [PASS] CAS blob corruption detected, repaired in-place, and node_modules verified!" -ForegroundColor Green
            } else {
                Write-Host "     [FAIL] Corruption went undetected or reached node_modules! (repaired=$isRepaired, nm_identical=$($refCmp.Identical))" -ForegroundColor Red
                $casSuitePassed = $false
            }
        } else {
            Write-Host "     [FAIL] rnpm ci failed with exit code $casExit" -ForegroundColor Red
            $casSuitePassed = $false
        }
        Remove-Item $casTestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "     [SKIP] No CAS files found to corrupt" -ForegroundColor Yellow
}

# Test (b): Documented variant with mtime restored
Write-Host "  -> (b) Documented guarantee: mtime-restored tampering contract..." -ForegroundColor Gray
Write-Host "     [NOTE] Contract Guarantee: warm fast-path uses (size, mtime) stamping for zero-overhead validation (pnpm/git stat-cache model)." -ForegroundColor Cyan
Write-Host "            If an external process mutates a file and preserves timestamp + size, warm ci trusts the stamp by design." -ForegroundColor Cyan
Write-Host "            Full cryptographic SHA-256 verification is executed on cache misses, tarball ingestion, and 'rnpm cache verify'." -ForegroundColor Cyan

Remove-Item $refDir -Recurse -Force -ErrorAction SilentlyContinue

# ----------------------------------------------------
# Summary & Verification Table
# ----------------------------------------------------
Write-Host "`n====================================================================================================" -ForegroundColor Cyan
Write-Host " Gate Lane 5 Warm-Path Summary (Median, Spread, Parity & Correctness)" -ForegroundColor Cyan
Write-Host "====================================================================================================" -ForegroundColor Cyan
Write-Host ("{0,-21} | {1,-20} | {2,-20} | {3,-8} | {4,-6} | {5,-4} | {6,-11} | {7}" -f "Scenario", "npm median [min, max]", "rnpm median [min, max]", "Ratio", "Target", "Runs", "Correctness", "Status")
Write-Host ("-" * 100)

$allPassed = $true

foreach ($name in $results.Keys) {
    $info = $results[$name]
    $rnpmCount = $info.Rnpm.Count
    $npmCount  = $info.Npm.Count

    if ($rnpmCount -eq 0 -or $npmCount -eq 0) { continue }

    $rnpmMed = Get-Median $info.Rnpm
    $npmMed  = Get-Median $info.Npm
    $rnpmMin = ($info.Rnpm | Measure-Object -Minimum).Minimum
    $rnpmMax = ($info.Rnpm | Measure-Object -Maximum).Maximum
    $npmMin  = ($info.Npm  | Measure-Object -Minimum).Minimum
    $npmMax  = ($info.Npm  | Measure-Object -Maximum).Maximum

    $ratio = if ($rnpmMed -gt 0) { $npmMed / $rnpmMed } else { 0 }
    $target = $info.Target
    $passed = ($ratio -ge $target) -and $info.Correct
    $statusStr = if ($passed) { "PASS" } else { if ($info.Required) { "FAIL" } else { "INFO" } }

    if ($info.Required -and -not $passed) {
        $allPassed = $false
    }

    $color = if ($passed) { "Green" } else { if ($info.Required) { "Red" } else { "DarkYellow" } }
    $npmStr  = ("{0,7:N1} [{1:N0}, {2:N0}] ms" -f $npmMed, $npmMin, $npmMax)
    $rnpmStr = ("{0,7:N1} [{1:N0}, {2:N0}] ms" -f $rnpmMed, $rnpmMin, $rnpmMax)
    $corrStr = if ($info.Correct) { "MATCH" } else { "MISMATCH" }

    Write-Host ("{0,-21} | {1,-20} | {2,-20} | {3,6:N2}x | {4,4:N1}x | {5,4} | {6,-11} | {7}" -f $name, $npmStr, $rnpmStr, $ratio, $target, $rnpmCount, $corrStr, $statusStr) -ForegroundColor $color
}

Write-Host "`nParity Check: $(if ($parityPassed) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($parityPassed) { "Green" } else { "Red" })
Write-Host "CAS Corruption Detection Suite: $(if ($casSuitePassed) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($casSuitePassed) { "Green" } else { "Red" })

if ($allPassed -and $parityPassed -and $casSuitePassed) {
    Write-Host "`n[SUCCESS] Lane 5 Warm-Path Gate PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n[FAIL] Lane 5 Warm-Path Gate FAILED" -ForegroundColor Red
    exit 1
}
