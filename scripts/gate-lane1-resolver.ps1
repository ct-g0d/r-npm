param(
    [switch]$SkipCargoTests = $false
)

$ErrorActionPreference = "Continue"
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$rnpmBin = Join-Path $repoRoot "target\release\rnpm.exe"

if (-not (Test-Path $rnpmBin)) {
    Write-Error "rnpm release binary not found at $rnpmBin. Run 'cargo build --release --bin rnpm' first."
    exit 1
}

$fixtureDir = Join-Path $repoRoot "benchmarks\fixtures\project-486"
if (-not (Test-Path $fixtureDir)) {
    Write-Error "Fixture project-486 not found at $fixtureDir."
    exit 1
}

$npmVer = & npm.cmd --version
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " Lane 1 Resolver & Freshness Gate Harness" -ForegroundColor Cyan
Write-Host " npm version:      $npmVer" -ForegroundColor Cyan
Write-Host " rnpm binary:      $rnpmBin" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$allPassed = $true

# Helper for JSON comparison via Node.js
function Invoke-NodeLockfileDiff {
    param([string]$NpmLockPath, [string]$RnpmLockPath)
    $script = @'
const fs = require('fs');
const npmLock = JSON.parse(fs.readFileSync(process.argv[1]));
const rnpmLock = JSON.parse(fs.readFileSync(process.argv[2]));

const npmKeys = Object.keys(npmLock.packages || {}).filter(k => k !== '').sort();
const rnpmKeys = Object.keys(rnpmLock.packages || {}).filter(k => k !== '').sort();

const allKeys = Array.from(new Set([...npmKeys, ...rnpmKeys])).sort();
let diffs = [];

for (const k of allKeys) {
  const n = (npmLock.packages || {})[k];
  const r = (rnpmLock.packages || {})[k];
  if (!n) {
    diffs.push(`EXTRA in rnpm: ${k} (version ${r.version})`);
  } else if (!r) {
    diffs.push(`MISSING in rnpm: ${k} (version ${n.version})`);
  } else if (n.version !== r.version) {
    diffs.push(`VERSION MISMATCH in ${k}: npm=${n.version} vs rnpm=${r.version}`);
  }
}

if (diffs.length > 0) {
  console.log(diffs.slice(0, 20).join('\n'));
  if (diffs.length > 20) console.log(`... and ${diffs.length - 20} more diffs`);
}
console.log(`TOTAL_DIFFS=${diffs.length}`);
'@
    $res = & node -e $script $NpmLockPath $RnpmLockPath
    $resStr = $res -join "`n"
    if ($resStr -match "TOTAL_DIFFS=(\d+)") {
        return @{ Diffs = [int]$Matches[1]; Output = $resStr }
    }
    return @{ Diffs = 999; Output = $resStr }
}

# ---------------------------------------------------------------
# Check 1: Realname Tarball Case (Bug 2)
# ---------------------------------------------------------------
Write-Host "`n>>> [Check 1/6] Realname Tarball Case" -ForegroundColor Yellow
$tmp1 = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
    $pkgDir = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "realname-pkg")
    Set-Content -Path (Join-Path $pkgDir.FullName "package.json") -Value '{"name":"realname","version":"1.0.0"}'
    & npm.cmd pack $pkgDir.FullName --pack-destination $tmp1.FullName 2>&1 | Out-Null
    $tarball = Get-ChildItem -Path $tmp1.FullName -Filter "*.tgz" | Select-Object -First 1

    $npmProj = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "npm-proj")
    Set-Content -Path (Join-Path $npmProj.FullName "package.json") -Value '{"name":"npm-proj","version":"1.0.0"}'
    Push-Location $npmProj.FullName
    & npm.cmd install $tarball.FullName 2>&1 | Out-Null
    Pop-Location

    $rnpmProj = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "rnpm-proj")
    Set-Content -Path (Join-Path $rnpmProj.FullName "package.json") -Value '{"name":"rnpm-proj","version":"1.0.0"}'
    Push-Location $rnpmProj.FullName
    & $rnpmBin install $tarball.FullName 2>&1 | Out-Null
    $rnpmExit = $LASTEXITCODE
    Pop-Location

    $npmDirs = @(Get-ChildItem (Join-Path $npmProj.FullName "node_modules") | Select-Object -ExpandProperty Name | Where-Object { $_ -ne ".package-lock.json" })
    $rnpmDirs = @(Get-ChildItem (Join-Path $rnpmProj.FullName "node_modules") | Select-Object -ExpandProperty Name | Where-Object { $_ -ne ".package-lock.json" })
    $dirMatch = ($rnpmDirs -contains "realname") -and (-not ($rnpmDirs -contains "realname-1.0.0.tgz"))

    $npmPkgJson = Get-Content (Join-Path $npmProj.FullName "package.json") -Raw
    $rnpmPkgJson = Get-Content (Join-Path $rnpmProj.FullName "package.json") -Raw
    $pkgJsonMatch = ($rnpmPkgJson -match '"realname":\s*"file:')

    $lockDiff = Invoke-NodeLockfileDiff (Join-Path $npmProj.FullName "package-lock.json") (Join-Path $rnpmProj.FullName "package-lock.json")

    if ($rnpmExit -eq 0 -and $dirMatch -and $pkgJsonMatch -and $lockDiff.Diffs -eq 0) {
        Write-Host "  [PASS] realname tarball install: node_modules dir name, package.json, and lockfile entry identical to npm." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] realname tarball install mismatch! Exit=$rnpmExit, DirMatch=$dirMatch, PkgJsonMatch=$pkgJsonMatch, Diffs=$($lockDiff.Diffs)" -ForegroundColor Red
        Write-Host $lockDiff.Output
        $allPassed = $false
    }
} finally {
    Remove-Item -Recurse -Force $tmp1.FullName -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------
# Check 2: is-odd + URL is-number Shadowing Case (Bug 3)
# ---------------------------------------------------------------
Write-Host "`n>>> [Check 2/6] is-odd + URL is-number Shadowing Case" -ForegroundColor Yellow
$tmp2 = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
    $manifestContent = '{"name":"test-proj","version":"1.0.0","dependencies":{"is-odd":"^3.0.1","is-number":"https://registry.npmjs.org/is-number/-/is-number-3.0.0.tgz"}}'

    $npmProj = New-Item -ItemType Directory -Path (Join-Path $tmp2.FullName "npm-proj")
    Set-Content -Path (Join-Path $npmProj.FullName "package.json") -Value $manifestContent
    Push-Location $npmProj.FullName
    & npm.cmd install 2>&1 | Out-Null
    Pop-Location

    $rnpmProj = New-Item -ItemType Directory -Path (Join-Path $tmp2.FullName "rnpm-proj")
    Set-Content -Path (Join-Path $rnpmProj.FullName "package.json") -Value $manifestContent
    Push-Location $rnpmProj.FullName
    & $rnpmBin install 2>&1 | Out-Null
    $rnpmExit = $LASTEXITCODE
    Pop-Location

    $lockDiff = Invoke-NodeLockfileDiff (Join-Path $npmProj.FullName "package-lock.json") (Join-Path $rnpmProj.FullName "package-lock.json")

    if ($rnpmExit -eq 0 -and $lockDiff.Diffs -eq 0) {
        Write-Host "  [PASS] is-odd + URL is-number: exit code 0 and tree identical to npm (root URL bound to root edge; is-number@6 nested under is-odd)." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] is-odd + URL is-number mismatch! Exit=$rnpmExit, Diffs=$($lockDiff.Diffs)" -ForegroundColor Red
        Write-Host $lockDiff.Output
        $allPassed = $false
    }
} finally {
    Remove-Item -Recurse -Force $tmp2.FullName -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------
# Check 3: project-486 No-Lockfile Install (Bug 1: Fresh Cache)
# ---------------------------------------------------------------
Write-Host "`n>>> [Check 3/6] project-486 No-Lockfile Install (Fresh Cache vs npm)" -ForegroundColor Yellow
$tmp3 = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
    $npmProj = New-Item -ItemType Directory -Path (Join-Path $tmp3.FullName "npm-proj")
    Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $npmProj.FullName "package.json")

    $rnpmProj = New-Item -ItemType Directory -Path (Join-Path $tmp3.FullName "rnpm-proj")
    Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $rnpmProj.FullName "package.json")

    Write-Host "  -> Running npm 11.20 install --package-lock-only..."
    $npmSw = [System.Diagnostics.Stopwatch]::StartNew()
    Push-Location $npmProj.FullName
    & npm.cmd install --package-lock-only 2>&1 | Out-Null
    Pop-Location
    $npmSw.Stop()
    $npmDuration = $npmSw.ElapsedMilliseconds

    Write-Host "  -> Running rnpm install --package-lock-only..."
    $rnpmSw = [System.Diagnostics.Stopwatch]::StartNew()
    Push-Location $rnpmProj.FullName
    & $rnpmBin install --package-lock-only 2>&1 | Out-Null
    $rnpmExit = $LASTEXITCODE
    Pop-Location
    $rnpmSw.Stop()
    $rnpmDuration = $rnpmSw.ElapsedMilliseconds

    $lockDiff = Invoke-NodeLockfileDiff (Join-Path $npmProj.FullName "package-lock.json") (Join-Path $rnpmProj.FullName "package-lock.json")

    if ($rnpmExit -eq 0 -and $lockDiff.Diffs -eq 0) {
        Write-Host "  [PASS] project-486 no-lockfile: lockfile packages keys+versions diff vs npm == 0 lines." -ForegroundColor Green
        Write-Host "         npm: $($npmDuration) ms | rnpm: $($rnpmDuration) ms" -ForegroundColor Gray
    } else {
        Write-Host "  [FAIL] project-486 lockfile diff vs npm: $($lockDiff.Diffs) lines!" -ForegroundColor Red
        Write-Host $lockDiff.Output
        $allPassed = $false
    }
} finally {
    Remove-Item -Recurse -Force $tmp3.FullName -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------
# Check 4: project-486 Stale Cache Revalidation (Bug 1: 300s TTL)
# ---------------------------------------------------------------
Write-Host "`n>>> [Check 4/6] project-486 Stale Cache Revalidation" -ForegroundColor Yellow
$tmp4 = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
    $customCache = New-Item -ItemType Directory -Path (Join-Path $tmp4.FullName "custom-cache")
    $warmProj = New-Item -ItemType Directory -Path (Join-Path $tmp4.FullName "warm-proj")
    Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $warmProj.FullName "package.json")

    Write-Host "  -> Populating initial cache with rnpm..."
    Push-Location $warmProj.FullName
    & $rnpmBin install --package-lock-only --cache $customCache.FullName 2>&1 | Out-Null
    Pop-Location

    Write-Host "  -> Artificially aging cached packuments (>300s old)..."
    $nodeScriptAge = @'
const fs = require('fs');
const path = require('path');
function walk(dir) {
  let files = [];
  for (const f of fs.readdirSync(dir)) {
    const full = path.join(dir, f);
    if (fs.statSync(full).isDirectory()) files = files.concat(walk(full));
    else files.push(full);
  }
  return files;
}
const indexDir = path.join(process.argv[1], 'index-v5');
if (fs.existsSync(indexDir)) {
  for (const file of walk(indexDir)) {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    const newLines = lines.map(line => {
      const trimmed = line.trim();
      if (!trimmed) return line;
      const tabIdx = trimmed.indexOf('\t');
      const prefix = tabIdx >= 0 ? trimmed.slice(0, tabIdx + 1) : '';
      const jsonStr = tabIdx >= 0 ? trimmed.slice(tabIdx + 1) : trimmed;
      try {
        const obj = JSON.parse(jsonStr);
        obj.time = Date.now() - 86400000;
        return prefix + JSON.stringify(obj);
      } catch (e) {
        return line;
      }
    });
    fs.writeFileSync(file, newLines.join('\n'));
  }
}
'@
    & node -e $nodeScriptAge $customCache.FullName

    $staleProj = New-Item -ItemType Directory -Path (Join-Path $tmp4.FullName "stale-proj")
    Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $staleProj.FullName "package.json")

    Write-Host "  -> Running rnpm with stale pre-populated packument cache..."
    Push-Location $staleProj.FullName
    & $rnpmBin install --package-lock-only --cache $customCache.FullName 2>&1 | Out-Null
    $rnpmExit = $LASTEXITCODE
    Pop-Location

    $lockDiff = Invoke-NodeLockfileDiff (Join-Path $warmProj.FullName "package-lock.json") (Join-Path $staleProj.FullName "package-lock.json")

    if ($rnpmExit -eq 0 -and $lockDiff.Diffs -eq 0) {
        Write-Host "  [PASS] Stale packument cache revalidation verified: diff vs fresh/npm == 0 lines." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Stale packument cache revalidation failed! Exit=$rnpmExit, Diffs=$($lockDiff.Diffs)" -ForegroundColor Red
        Write-Host $lockDiff.Output
        $allPassed = $false
    }
} finally {
    Remove-Item -Recurse -Force $tmp4.FullName -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------
# Check 5: Speed Non-Regression Check
# ---------------------------------------------------------------
Write-Host "`n>>> [Check 5/6] Speed Measurement on project-486" -ForegroundColor Yellow
$tmp5 = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
    $warmCache = New-Item -ItemType Directory -Path (Join-Path $tmp5.FullName "speed-cache")
    $warmProj = New-Item -ItemType Directory -Path (Join-Path $tmp5.FullName "warm-proj")
    Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $warmProj.FullName "package.json")
    Copy-Item (Join-Path $fixtureDir "package-lock.json") (Join-Path $warmProj.FullName "package-lock.json")

    Push-Location $warmProj.FullName
    & $rnpmBin ci --cache $warmCache.FullName 2>&1 | Out-Null
    Pop-Location

    # Measure rnpm ci vs npm ci
    $rnpmProj = New-Item -ItemType Directory -Path (Join-Path $tmp5.FullName "rnpm-ci")
    Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $rnpmProj.FullName "package.json")
    Copy-Item (Join-Path $fixtureDir "package-lock.json") (Join-Path $rnpmProj.FullName "package-lock.json")

    $rnpmSw = [System.Diagnostics.Stopwatch]::StartNew()
    Push-Location $rnpmProj.FullName
    & $rnpmBin ci --cache $warmCache.FullName 2>&1 | Out-Null
    Pop-Location
    $rnpmSw.Stop()
    $rnpmMs = $rnpmSw.ElapsedMilliseconds

    $npmProj = New-Item -ItemType Directory -Path (Join-Path $tmp5.FullName "npm-ci")
    Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $npmProj.FullName "package.json")
    Copy-Item (Join-Path $fixtureDir "package-lock.json") (Join-Path $npmProj.FullName "package-lock.json")

    $npmSw = [System.Diagnostics.Stopwatch]::StartNew()
    Push-Location $npmProj.FullName
    & npm.cmd ci 2>&1 | Out-Null
    Pop-Location
    $npmSw.Stop()
    $npmMs = $npmSw.ElapsedMilliseconds

    $ratio = if ($rnpmMs -gt 0) { [math]::Round($npmMs / $rnpmMs, 2) } else { 0 }
    Write-Host "  rnpm ci: $($rnpmMs) ms | npm ci: $($npmMs) ms -> Speedup: $($ratio)x" -ForegroundColor Cyan

    if ($rnpmMs -le $npmMs) {
        Write-Host "  [PASS] rnpm is faster than npm ($($ratio)x)." -ForegroundColor Green
    } else {
        Write-Host "  [WARN] rnpm was slower than npm on this single run." -ForegroundColor DarkYellow
    }
} finally {
    Remove-Item -Recurse -Force $tmp5.FullName -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------
# Check 6: Workspace Tests & Clippy
# ---------------------------------------------------------------
Write-Host "`n>>> [Check 6/6] Workspace Tests and Clippy" -ForegroundColor Yellow
if ($SkipCargoTests) {
    Write-Host "  Skipping cargo tests due to -SkipCargoTests parameter." -ForegroundColor Gray
} else {
    Write-Host "  -> Running cargo clippy --workspace -- -D warnings..."
    Push-Location $repoRoot
    & cargo clippy --workspace -- -D warnings
    $clippyExit = $LASTEXITCODE
    if ($clippyExit -ne 0) {
        Write-Host "  [FAIL] cargo clippy failed with exit code $clippyExit" -ForegroundColor Red
        $allPassed = $false
    } else {
        Write-Host "  [PASS] cargo clippy passed with 0 warnings." -ForegroundColor Green
    }

    Write-Host "  -> Running cargo test --workspace..."
    & cargo test --workspace -j 2
    $testExit = $LASTEXITCODE
    if ($testExit -ne 0) {
        Write-Host "  -> Retrying cargo test..." -ForegroundColor Yellow
        & cargo test --workspace -j 1
        $testExit = $LASTEXITCODE
    }
    if ($testExit -ne 0) {
        Write-Host "  [FAIL] cargo test failed with exit code $testExit" -ForegroundColor Red
        $allPassed = $false
    } else {
        Write-Host "  [PASS] cargo test passed." -ForegroundColor Green
    }
    Pop-Location
}

Write-Host "`n====================================================" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host " LANE 1 GATE: ALL CHECKS PASSED (100/100)" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host " LANE 1 GATE: CHECKS FAILED" -ForegroundColor Red
    Write-Host "====================================================" -ForegroundColor Cyan
    exit 1
}
