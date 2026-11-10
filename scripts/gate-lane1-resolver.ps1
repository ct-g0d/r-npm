param(
    [switch]$SkipCargoTests = $false,
    [switch]$SkipNpm = $false,
    [int]$WarmRuns = 5,
    [int]$FreshRuns = 5,
    [int]$NpmWarmRuns = 0,
    $Checks = @("1", "2", "3", "4", "5", "6"),
    [switch]$KeepTemp = $false
)

if ($Checks -is [string]) {
    $Checks = $Checks -split ','
}
$Checks = @($Checks | ForEach-Object { "$_".Trim() })

$ErrorActionPreference = "Continue"
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$rnpmBin = Join-Path $repoRoot "target\release\rnpm.exe"
$baseBin = Join-Path $repoRoot "target\base-79a19fd\rnpm.exe"

if (-not (Test-Path $rnpmBin)) {
    Write-Error "rnpm release binary not found at $rnpmBin. Run 'cargo build --release --bin rnpm' first."
    exit 1
}

if (-not (Test-Path $baseBin)) {
    $baseBin = $rnpmBin
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
$isolationBase = Join-Path $env:TEMP "gate1-env-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
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
Write-Host " Lane 1 Resolver & Freshness Gate Harness (Honest)" -ForegroundColor Cyan
Write-Host " npm version:      $npmVer" -ForegroundColor Cyan
Write-Host " HEAD binary:      $rnpmBin" -ForegroundColor Cyan
Write-Host " 79a19fd binary:   $baseBin" -ForegroundColor Cyan
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
# Check 1: Tarball / Path / Scoped / URL / Git specs (Exact vs npm)
# ---------------------------------------------------------------
if ($Checks -contains "1") {
Write-Host "`n>>> [Check 1/6] Tarball / Path / Scoped / URL / Git Specs (Exact Parity vs npm)" -ForegroundColor Yellow
$tmp1 = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
    # 1. Standard tarball: realname-1.0.0.tgz
    $stdDir = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "std-src")
    Set-Content -Path (Join-Path $stdDir.FullName "package.json") -Value '{"name":"realname","version":"1.0.0"}'
    & npm.cmd pack $stdDir.FullName --pack-destination $tmp1.FullName 2>&1 | Out-Null
    $stdTgz = (Get-ChildItem -Path $tmp1.FullName -Filter "realname-1.0.0.tgz" | Select-Object -First 1).FullName

    # 2. Mismatched filename tarball: weird.tgz containing name "realname"
    $weirdTgz = Join-Path $tmp1.FullName "weird.tgz"
    Copy-Item $stdTgz $weirdTgz

    # 3. Scoped tarball: @scope/realname
    $scopedDir = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "scoped-src")
    Set-Content -Path (Join-Path $scopedDir.FullName "package.json") -Value '{"name":"@scope/realname","version":"2.0.0"}'
    & npm.cmd pack $scopedDir.FullName --pack-destination $tmp1.FullName 2>&1 | Out-Null
    $scopedTgz = (Get-ChildItem -Path $tmp1.FullName -Filter "*scope*realname*.tgz" | Select-Object -First 1).FullName

    # 4. Directory file: spec
    $localDir = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "local-dir")
    Set-Content -Path (Join-Path $localDir.FullName "package.json") -Value '{"name":"local-dir-pkg","version":"1.5.0"}'

    # 5. Non-registry URL tarball
    $urlDir = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "url-src")
    Set-Content -Path (Join-Path $urlDir.FullName "package.json") -Value '{"name":"custom-url-pkg","version":"3.2.1"}'
    & npm.cmd pack $urlDir.FullName --pack-destination $tmp1.FullName 2>&1 | Out-Null
    $urlTgz = (Get-ChildItem -Path $tmp1.FullName -Filter "custom-url-pkg*.tgz" | Select-Object -First 1).FullName
    $serverScript = @"
const http = require('http');
const fs = require('fs');
const server = http.createServer((req, res) => {
  const data = fs.readFileSync('$($urlTgz -replace '\\','/')');
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': data.length });
  res.end(data);
});
server.listen(19876, '127.0.0.1');
"@
    $serverPath = Join-Path $tmp1.FullName "server.js"
    Set-Content -Path $serverPath -Value $serverScript
    $serverProc = Start-Process node -ArgumentList $serverPath -PassThru
    Start-Sleep -Milliseconds 800

    # 6. Git spec: local git repository
    $gitRepo = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "local-git-repo")
    Set-Content -Path (Join-Path $gitRepo.FullName "package.json") -Value '{"name":"git-pkg","version":"1.0.0"}'
    & git -C $gitRepo.FullName init -b main 2>&1 | Out-Null
    & git -C $gitRepo.FullName config user.email "test@test.com" 2>&1 | Out-Null
    & git -C $gitRepo.FullName config user.name "test" 2>&1 | Out-Null
    & git -C $gitRepo.FullName add . 2>&1 | Out-Null
    & git -C $gitRepo.FullName commit -m "initial" 2>&1 | Out-Null
    $gitUrl = 'git+file://' + ($gitRepo.FullName -replace '\\','/')

    # Test each spec against npm and rnpm
    $cases = @(
        @{ Name = "Standard Tarball"; Spec = $stdTgz; Key = "realname" },
        @{ Name = "Mismatched Filename Tarball"; Spec = $weirdTgz; Key = "realname" },
        @{ Name = "Scoped Package Tarball"; Spec = $scopedTgz; Key = "@scope/realname" },
        @{ Name = "Directory File Spec"; Spec = $localDir.FullName; Key = "local-dir-pkg" },
        @{ Name = "Non-Registry URL Tarball"; Spec = "http://127.0.0.1:19876/custom.tgz"; Key = "custom-url-pkg" },
        @{ Name = "Git Spec"; Spec = $gitUrl; Key = "git-pkg" }
    )

    $checkParityJs = Join-Path $tmp1.FullName "check_parity.js"
    $checkParityCode = @'
const fs = require('fs');
const path = require('path');

const npmProj = process.argv[2];
const rnpmProj = process.argv[3];
const key = process.argv[4];
let errors = [];

try {
  const np = JSON.parse(fs.readFileSync(path.join(npmProj, 'package.json')));
  const rp = JSON.parse(fs.readFileSync(path.join(rnpmProj, 'package.json')));
  const nDep = (np.dependencies || {})[key];
  const rDep = (rp.dependencies || {})[key];
  if (!nDep) errors.push(`npm package.json missing dep ${key}`);
  if (!rDep) errors.push(`rnpm package.json missing dep ${key}`);
} catch (e) {
  errors.push(`package.json read error: ${e.message}`);
}

const nmDir = path.join(rnpmProj, 'node_modules', key);
if (!fs.existsSync(nmDir)) {
  errors.push(`node_modules/${key} does not exist in rnpm`);
}

try {
  const nl = JSON.parse(fs.readFileSync(path.join(npmProj, 'package-lock.json')));
  const rl = JSON.parse(fs.readFileSync(path.join(rnpmProj, 'package-lock.json')));
  const lockKey = `node_modules/${key}`;
  const nEnt = (nl.packages || {})[lockKey];
  const rEnt = (rl.packages || {})[lockKey];
  if (!nEnt) errors.push(`npm lockfile missing ${lockKey}`);
  if (!rEnt) errors.push(`rnpm lockfile missing ${lockKey}`);
  if (nEnt && rEnt && nEnt.version !== rEnt.version) {
    errors.push(`version mismatch: npm=${nEnt.version} vs rnpm=${rEnt.version}`);
  }
} catch (e) {
  errors.push(`lockfile read error: ${e.message}`);
}

if (errors.length > 0) {
  console.log('FAIL: ' + errors.join('; '));
  process.exit(1);
} else {
  console.log('PASS');
}
'@
    Set-Content -Path $checkParityJs -Value $checkParityCode

    $check1AllPassed = $true
    foreach ($c in $cases) {
        $cName = $c.Name
        $cSpec = $c.Spec
        $cKey = $c.Key
        $cSlug = ($cName -replace '[^a-zA-Z0-9]','-').ToLower()

        $npmProj = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "npm-$cSlug")
        Set-Content -Path (Join-Path $npmProj.FullName "package.json") -Value '{"name":"test-proj","version":"1.0.0"}'
        Push-Location $npmProj.FullName
        & npm.cmd install $cSpec 2>&1 | Out-Null
        Pop-Location

        $rnpmProj = New-Item -ItemType Directory -Path (Join-Path $tmp1.FullName "rnpm-$cSlug")
        Set-Content -Path (Join-Path $rnpmProj.FullName "package.json") -Value '{"name":"test-proj","version":"1.0.0"}'
        Push-Location $rnpmProj.FullName
        & $rnpmBin install $cSpec 2>&1 | Out-Null
        $rnpmExit = $LASTEXITCODE
        Pop-Location

        $parityRes = & node $checkParityJs $npmProj.FullName $rnpmProj.FullName $cKey
        $parityExit = $LASTEXITCODE

        if ($rnpmExit -eq 0 -and $parityExit -eq 0) {
            Write-Host "  [PASS] $cName ($cKey): package.json saved, node_modules directory, and lockfile entry match npm." -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] $cName ($cKey) mismatch! Exit=$rnpmExit, ParityExit=$parityExit -> $parityRes" -ForegroundColor Red
            $check1AllPassed = $false
            $allPassed = $false
        }
    }

    if ($serverProc -and -not $serverProc.HasExited) {
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    }
} finally {
    Start-Sleep -Milliseconds 300
    Remove-Item -Recurse -Force $tmp1.FullName -ErrorAction SilentlyContinue
}
}

# ---------------------------------------------------------------
# Check 2: is-odd + URL is-number Shadowing Case (Bug 3)
# ---------------------------------------------------------------
if ($Checks -contains "2") {
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

    # Also assert structure: root has is-number 3.0.0; is-odd has nested is-number
    $structJs = Join-Path $tmp2.FullName "check_struct.js"
    $structCode = @'
const fs = require('fs');
const lock = JSON.parse(fs.readFileSync(process.argv[2]));
const pkgs = lock.packages || {};
const rootIsNum = pkgs["node_modules/is-number"];
const nestedIsNum = pkgs["node_modules/is-odd/node_modules/is-number"];
if (!rootIsNum || rootIsNum.version !== "3.0.0") {
  console.log("FAIL: root is-number missing or not 3.0.0");
  process.exit(1);
}
if (!nestedIsNum) {
  console.log("FAIL: nested is-number missing under is-odd");
  process.exit(1);
}
console.log("PASS");
'@
    Set-Content -Path $structJs -Value $structCode
    $structRes = & node $structJs (Join-Path $rnpmProj.FullName "package-lock.json")
    $structOk = ($LASTEXITCODE -eq 0)

    if ($rnpmExit -eq 0 -and $lockDiff.Diffs -eq 0 -and $structOk) {
        Write-Host "  [PASS] is-odd + URL is-number: exit code 0, lockfile diff == 0, root URL bound to root edge; nested is-number under is-odd." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] is-odd + URL is-number mismatch! Exit=$rnpmExit, Diffs=$($lockDiff.Diffs), StructOk=$structOk" -ForegroundColor Red
        Write-Host $lockDiff.Output
        $allPassed = $false
    }
} finally {
    Start-Sleep -Milliseconds 300
    Remove-Item -Recurse -Force $tmp2.FullName -ErrorAction SilentlyContinue
}
}

# ---------------------------------------------------------------
# Check 3: project-486 Bare Install (Fresh Empty Caches on Both Sides)
# ---------------------------------------------------------------
if ($Checks -contains "3") {
Write-Host "`n>>> [Check 3/6] project-486 Bare Install (Fresh Empty Caches vs npm)" -ForegroundColor Yellow
$tmp3 = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
    $npmCache = New-Item -ItemType Directory -Path (Join-Path $tmp3.FullName "npm-cache")
    $rnpmCache = New-Item -ItemType Directory -Path (Join-Path $tmp3.FullName "rnpm-cache")

    $npmProj = New-Item -ItemType Directory -Path (Join-Path $tmp3.FullName "npm-proj")
    Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $npmProj.FullName "package.json")

    $rnpmProj = New-Item -ItemType Directory -Path (Join-Path $tmp3.FullName "rnpm-proj")
    Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $rnpmProj.FullName "package.json")

    Write-Host "  -> Running npm install --cache <fresh-tmp>..."
    $npmSw = [System.Diagnostics.Stopwatch]::StartNew()
    Push-Location $npmProj.FullName
    & npm.cmd install --cache $npmCache.FullName 2>&1 | Out-Null
    Pop-Location
    $npmSw.Stop()
    $npmDuration = $npmSw.ElapsedMilliseconds

    Write-Host "  -> Running rnpm install --cache <fresh-tmp>..."
    $rnpmSw = [System.Diagnostics.Stopwatch]::StartNew()
    Push-Location $rnpmProj.FullName
    & $rnpmBin install --cache $rnpmCache.FullName 2>&1 | Out-Null
    $rnpmExit = $LASTEXITCODE
    Pop-Location
    $rnpmSw.Stop()
    $rnpmDuration = $rnpmSw.ElapsedMilliseconds

    $lockDiff = Invoke-NodeLockfileDiff (Join-Path $npmProj.FullName "package-lock.json") (Join-Path $rnpmProj.FullName "package-lock.json")

    # Diff the physical node_modules directory trees
    $treeDiffScript = @'
const fs = require('fs');
const path = require('path');

function getInstalled(dir) {
  const nm = path.join(dir, 'node_modules');
  if (!fs.existsSync(nm)) return {};
  const pkgs = {};
  function scan(curr, prefix) {
    for (const ent of fs.readdirSync(curr, { withFileTypes: true })) {
      if (ent.name.startsWith('.')) continue;
      const full = path.join(curr, ent.name);
      if (ent.isDirectory()) {
        if (ent.name.startsWith('@')) {
          scan(full, ent.name + '/');
        } else {
          const pkgName = prefix + ent.name;
          const pjson = path.join(full, 'package.json');
          let ver = 'unknown';
          if (fs.existsSync(pjson)) {
            try { ver = JSON.parse(fs.readFileSync(pjson, 'utf8')).version || 'unknown'; } catch(e) {}
          }
          pkgs[pkgName] = ver;
        }
      }
    }
  }
  scan(nm, '');
  return pkgs;
}

const npmPkgs = getInstalled(process.argv[1]);
const rnpmPkgs = getInstalled(process.argv[2]);

const all = Array.from(new Set([...Object.keys(npmPkgs), ...Object.keys(rnpmPkgs)])).sort();
let diffs = 0;
for (const k of all) {
  if (npmPkgs[k] !== rnpmPkgs[k]) {
    console.log(`NM DIFF: ${k} (npm=${npmPkgs[k]} vs rnpm=${rnpmPkgs[k]})`);
    diffs++;
  }
}
console.log(`TOTAL_NM_DIFFS=${diffs}`);
'@
    $nmDiffRes = & node -e $treeDiffScript $npmProj.FullName $rnpmProj.FullName
    $nmDiffStr = $nmDiffRes -join "`n"
    $nmDiffCount = 999
    if ($nmDiffStr -match "TOTAL_NM_DIFFS=(\d+)") {
        $nmDiffCount = [int]$Matches[1]
    }

    if ($rnpmExit -eq 0 -and $lockDiff.Diffs -eq 0 -and $nmDiffCount -eq 0) {
        Write-Host "  [PASS] project-486 bare install with fresh caches: lockfile diff == 0, physical node_modules diff == 0." -ForegroundColor Green
        Write-Host "         npm duration: $($npmDuration) ms | rnpm duration: $($rnpmDuration) ms" -ForegroundColor Gray
    } else {
        Write-Host "  [FAIL] project-486 mismatch! Exit=$rnpmExit, LockfileDiffs=$($lockDiff.Diffs), NMDiffs=$nmDiffCount" -ForegroundColor Red
        Write-Host $lockDiff.Output
        Write-Host $nmDiffStr
        $allPassed = $false
    }
} finally {
    Start-Sleep -Milliseconds 300
    Remove-Item -Recurse -Force $tmp3.FullName -ErrorAction SilentlyContinue
}
}

# ---------------------------------------------------------------
# Check 4: Stale Packument Cache Revalidation & --prefer-offline
# ---------------------------------------------------------------
if ($Checks -contains "4") {
Write-Host "`n>>> [Check 4/6] Stale Packument Cache Revalidation (Doctor-Seeded Packument)" -ForegroundColor Yellow
$tmp4 = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
    $customCache = New-Item -ItemType Directory -Path (Join-Path $tmp4.FullName "custom-cache")
    $warmProj = New-Item -ItemType Directory -Path (Join-Path $tmp4.FullName "warm-proj")
    Set-Content -Path (Join-Path $warmProj.FullName "package.json") -Value '{"name":"test-stale","version":"1.0.0","dependencies":{"@eslint-community/regexpp":"^4.12.1"}}'

    Write-Host "  -> Populating initial cache with rnpm..."
    Push-Location $warmProj.FullName
    & $rnpmBin install --package-lock-only --cache $customCache.FullName 2>&1 | Out-Null
    Pop-Location

    Write-Host "  -> Doctoring cached @eslint-community/regexpp packument (removing 4.12.3, setting latest=4.12.2, bogus ETag, aging >300s)..."
    $doctorScript = @'
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function walk(dir) {
  let files = [];
  if (!fs.existsSync(dir)) return files;
  for (const f of fs.readdirSync(dir)) {
    const full = path.join(dir, f);
    if (fs.statSync(full).isDirectory()) files = files.concat(walk(full));
    else files.push(full);
  }
  return files;
}

const cacheDir = process.argv[2];
const indexDir = path.join(cacheDir, 'index-v5');
const contentDir = path.join(cacheDir, 'content-v2', 'sha512');

let foundPackument = false;
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
      if (obj.key && obj.key.includes('@eslint-community/regexpp')) {
        for (const cFile of walk(contentDir)) {
          let raw = fs.readFileSync(cFile, 'utf8');
          try {
            const packument = JSON.parse(raw);
            if (packument.versions && packument.versions['4.12.3']) {
              delete packument.versions['4.12.3'];
              if (packument['dist-tags']) {
                packument['dist-tags'].latest = '4.12.2';
              }
              const newRaw = JSON.stringify(packument);
              const newHex = crypto.createHash('sha512').update(newRaw).digest('hex');
              const newB64 = crypto.createHash('sha512').update(newRaw).digest('base64');
              const targetDir = path.join(contentDir, newHex.slice(0, 2), newHex.slice(2, 4));
              fs.mkdirSync(targetDir, { recursive: true });
              fs.writeFileSync(path.join(targetDir, newHex), newRaw);

              obj.integrity = `sha512-${newB64}`;
              obj.sha512_hex = newHex;
              obj.size = Buffer.byteLength(newRaw);
              foundPackument = true;
            }
          } catch(e) {}
        }
        obj.time = Date.now() - 3600000; // 1 hour ago (>300s TTL)
        obj.metadata = obj.metadata || {};
        obj.metadata.etag = 'W/"stale-etag-bogus-12345"';
        return prefix + JSON.stringify(obj);
      }
      return line;
    } catch(e) {
      return line;
    }
  });
  fs.writeFileSync(file, newLines.join('\n'));
}
console.log(`DOCTORED=${foundPackument}`);
'@
    $doctorJs = Join-Path $tmp4.FullName "doctor.js"
    Set-Content -Path $doctorJs -Value $doctorScript
    $docRes = & node $doctorJs $customCache.FullName
    Write-Host "     Doctoring result: $docRes" -ForegroundColor Gray

    $verJs = Join-Path $tmp4.FullName "check_ver.js"
    $verCode = @'
const fs = require('fs');
const lock = JSON.parse(fs.readFileSync(process.argv[2]));
const ent = (lock.packages || {})["node_modules/@eslint-community/regexpp"];
console.log(ent ? ent.version || '' : '');
'@
    Set-Content -Path $verJs -Value $verCode

    # Compare against npm baseline
    $projNpm = New-Item -ItemType Directory -Path (Join-Path $tmp4.FullName "proj-npm")
    Set-Content -Path (Join-Path $projNpm.FullName "package.json") -Value '{"name":"test-stale","version":"1.0.0","dependencies":{"@eslint-community/regexpp":"^4.12.1"}}'
    Push-Location $projNpm.FullName
    & npm.cmd install --package-lock-only 2>&1 | Out-Null
    Pop-Location
    $npmVer = (& node $verJs (Join-Path $projNpm.FullName "package-lock.json")).Trim()

    # Sub-case A: Regular install with stale cache MUST revalidate, fetch 4.12.3, and match npm
    Write-Host "  -> Running Sub-case A (revalidation): rnpm install with stale cache..."
    $projA = New-Item -ItemType Directory -Path (Join-Path $tmp4.FullName "proj-a")
    Set-Content -Path (Join-Path $projA.FullName "package.json") -Value '{"name":"test-stale","version":"1.0.0","dependencies":{"@eslint-community/regexpp":"^4.12.1"}}'
    Push-Location $projA.FullName
    & $rnpmBin install --package-lock-only --cache $customCache.FullName 2>&1 | Out-Null
    $rnpmExitA = $LASTEXITCODE
    Pop-Location

    $verA = (& node $verJs (Join-Path $projA.FullName "package-lock.json")).Trim()
    $caseAPassed = ($rnpmExitA -eq 0) -and ($verA -eq "4.12.3") -and ($verA -eq $npmVer)

    # Sub-case B: Same doctored cache with prefer-offline MUST skip revalidation and keep 4.12.2
    # Re-doctor to ensure aged and stale
    & node $doctorJs $customCache.FullName | Out-Null
    Write-Host "  -> Running Sub-case B (prefer-offline): rnpm install with stale cache..."
    $projB = New-Item -ItemType Directory -Path (Join-Path $tmp4.FullName "proj-b")
    Set-Content -Path (Join-Path $projB.FullName "package.json") -Value '{"name":"test-stale","version":"1.0.0","dependencies":{"@eslint-community/regexpp":"^4.12.1"}}'
    $env:npm_config_prefer_offline = "true"
    Push-Location $projB.FullName
    & $rnpmBin install --package-lock-only --cache $customCache.FullName 2>&1 | Out-Null
    $rnpmExitB = $LASTEXITCODE
    Pop-Location
    Remove-Item env:npm_config_prefer_offline -ErrorAction SilentlyContinue

    $verB = (& node $verJs (Join-Path $projB.FullName "package-lock.json")).Trim()
    $caseBPassed = ($rnpmExitB -eq 0) -and ($verB -eq "4.12.2")

    if ($caseAPassed -and $caseBPassed) {
        Write-Host "  [PASS] Stale packument revalidation verified:" -ForegroundColor Green
        Write-Host "         Sub-case A (default): revalidated stale cache -> $verA (matches npm $npmVer)" -ForegroundColor Green
        Write-Host "         Sub-case B (prefer-offline): skipped revalidation -> kept stale 4.12.2" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Stale packument test failed! CaseA=$verA (npm=$npmVer), CaseB=$verB" -ForegroundColor Red
        $allPassed = $false
    }
} finally {
    Start-Sleep -Milliseconds 300
    Remove-Item -Recurse -Force $tmp4.FullName -ErrorAction SilentlyContinue
}
}

# ---------------------------------------------------------------
# Check 5: Speed Non-Regression & Benchmark (project-486 Medians)
# ---------------------------------------------------------------
if ($Checks -contains "5" -or $Checks -contains "5w" -or $Checks -contains "5f") {
Write-Host "`n>>> [Check 5/6] Speed Non-Regression Measurement on project-486 (Warm: $WarmRuns runs, Fresh: $FreshRuns runs)" -ForegroundColor Yellow
$tmp5 = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
    function Get-Median {
        param([double[]]$Values)
        $sorted = $Values | Sort-Object
        $count = $sorted.Count
        if ($count -eq 0) { return 0 }
        if ($count % 2 -eq 1) {
            return $sorted[[math]::Floor($count / 2)]
        } else {
            return ($sorted[($count / 2) - 1] + $sorted[$count / 2]) / 2.0
        }
    }

    # Function to time no-lockfile install
    $script:speedRunErrors = @()
    function Measure-NoLockfileInstall {
        param([string]$BinCmd, [string]$CachePath, [string]$Label, [int]$Runs)
        $times = @()
        for ($i = 1; $i -le $Runs; $i++) {
            $projDir = Join-Path $tmp5.FullName "run-$([System.Guid]::NewGuid().ToString())"
            New-Item -ItemType Directory -Path $projDir | Out-Null
            Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $projDir "package.json")

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            Push-Location $projDir
            if ($BinCmd -eq "npm.cmd") {
                & npm.cmd install --cache $CachePath 2>&1 | Out-Null
            } else {
                & $BinCmd install --cache $CachePath 2>&1 | Out-Null
            }
            $ec = $LASTEXITCODE
            $hasHiddenLock = Test-Path (Join-Path $projDir "node_modules\.package-lock.json")
            Pop-Location
            $sw.Stop()
            $ms = $sw.ElapsedMilliseconds
            $times += $ms
            Write-Host "    $Label run $i/${Runs}: $ms ms" -ForegroundColor Gray

            if ($ec -ne 0) {
                Write-Host "    [ERROR] $Label run $i failed with exit code $ec" -ForegroundColor Red
                $script:speedRunErrors += "$Label run $i failed with exit code $ec"
                $script:allPassed = $false
            }
            if (-not $hasHiddenLock) {
                Write-Host "    [ERROR] $Label run $i missing node_modules\.package-lock.json" -ForegroundColor Red
                $script:speedRunErrors += "$Label run $i missing node_modules\.package-lock.json"
                $script:allPassed = $false
            }

            Start-Process -FilePath "cmd.exe" -ArgumentList "/c rd /s /q `"$projDir`"" -WindowStyle Hidden
        }
        $med = Get-Median $times
        return @{ Times = $times; Median = $med }
    }

    $runWarm = ($Checks -contains "5" -or $Checks -contains "5w")
    $runFresh = ($Checks -contains "5" -or $Checks -contains "5f")

    if ((-not $runWarm) -and (-not $runFresh)) {
        Write-Host "  Speed check skipped." -ForegroundColor Gray
    } else {
        if ($runWarm) {
            if ($WarmRuns -gt 0) {
            # Warm caches setup: seed each in an isolated directory
            Write-Host "  -> Setting up warm caches..."
            $warmCache79 = Join-Path $tmp5.FullName "warm-cache-79"
            $warmCacheHead = Join-Path $tmp5.FullName "warm-cache-head"
            $warmCacheNpm = Join-Path $tmp5.FullName "warm-cache-npm"

            $seedHead = Join-Path $tmp5.FullName "seed-head"
            New-Item -ItemType Directory -Path $seedHead | Out-Null
            Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $seedHead "package.json")
            Push-Location $seedHead
            & $rnpmBin install --cache $warmCacheHead 2>&1 | Out-Null
            Pop-Location
            Remove-Item -Recurse -Force $seedHead -ErrorAction SilentlyContinue

            $seed79 = Join-Path $tmp5.FullName "seed-79"
            New-Item -ItemType Directory -Path $seed79 | Out-Null
            Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $seed79 "package.json")
            Push-Location $seed79
            & $baseBin install --cache $warmCache79 2>&1 | Out-Null
            Pop-Location
            Remove-Item -Recurse -Force $seed79 -ErrorAction SilentlyContinue

            if (-not $SkipNpm) {
                $seedNpm = Join-Path $tmp5.FullName "seed-npm"
                New-Item -ItemType Directory -Path $seedNpm | Out-Null
                Copy-Item (Join-Path $fixtureDir "package.json") (Join-Path $seedNpm "package.json")
                Push-Location $seedNpm
                & npm.cmd install --cache $warmCacheNpm 2>&1 | Out-Null
                Pop-Location
                Remove-Item -Recurse -Force $seedNpm -ErrorAction SilentlyContinue
            }

            Write-Host "`n  -> Measuring WARM cache no-lockfile install ($WarmRuns runs each)..."
            $resHeadWarm = Measure-NoLockfileInstall $rnpmBin $warmCacheHead "HEAD (warm)" $WarmRuns
            $res79Warm = Measure-NoLockfileInstall $baseBin $warmCache79 "79a19fd (warm)" $WarmRuns
            $actualNpmWarmRuns = if ($NpmWarmRuns -gt 0) { $NpmWarmRuns } else { $WarmRuns }
            if (-not $SkipNpm) {
                $resNpmWarm = Measure-NoLockfileInstall "npm.cmd" $warmCacheNpm "npm (warm)" $actualNpmWarmRuns
            } else {
                $resNpmWarm = $null
            }

            Write-Host "`n  === Warm Speed Summary ===" -ForegroundColor Cyan
            if ($resNpmWarm -ne $null) {
                Write-Host ("  WARM Cache:`n    HEAD ({0} runs):    {1} ms`n    79a19fd ({0} runs): {2} ms`n    npm ({3} runs):     {4} ms" -f $WarmRuns, $resHeadWarm.Median, $res79Warm.Median, $actualNpmWarmRuns, $resNpmWarm.Median) -ForegroundColor White
            } else {
                Write-Host ("  WARM Cache:`n    HEAD ({0} runs):    {1} ms`n    79a19fd ({0} runs): {2} ms`n    npm:               NOT MEASURED" -f $WarmRuns, $resHeadWarm.Median, $res79Warm.Median) -ForegroundColor White
            }
            $warmVs79 = [math]::Round($resHeadWarm.Median / [math]::Max($res79Warm.Median, 1), 3)
            Write-Host "    HEAD vs 79a19fd ratio: ${warmVs79}x (must be <= 1.05x)" -ForegroundColor Cyan
            if ($resNpmWarm -ne $null) {
                $warmVsNpm = [math]::Round($resNpmWarm.Median / [math]::Max($resHeadWarm.Median, 1), 2)
                Write-Host "    HEAD vs npm speedup:   ${warmVsNpm}x (target >= 2.0x, lanes 4/5 fetch/materialize domain)" -ForegroundColor Cyan
            }

            $warmNonRegression = $resHeadWarm.Median -le ($res79Warm.Median * 1.05)
            if (-not $warmNonRegression) {
                Write-Host "  [FAIL] Warm non-regression failed! HEAD=$($resHeadWarm.Median) ms > 79a19fd=$($res79Warm.Median) ms * 1.05" -ForegroundColor Red
                $allPassed = $false
            } else {
                Write-Host "  [PASS] Warm speed non-regression verified (HEAD <= 1.05x 79a19fd)." -ForegroundColor Green
            }
            } else {
                Write-Host "  [FAIL] Warm runs count is 0 (NOT RUN)" -ForegroundColor Red
                $allPassed = $false
            }
        }

        if ($runFresh) {
            if ($FreshRuns -gt 0) {
            Write-Host "`n  -> Measuring FRESH empty cache no-lockfile install ($FreshRuns runs each)..."
            $timesHeadFresh = @()
            $times79Fresh = @()
            $timesNpmFresh = @()
            for ($i = 1; $i -le $FreshRuns; $i++) {
                $cHead = Join-Path $tmp5.FullName "fresh-head-$i"
                $c79 = Join-Path $tmp5.FullName "fresh-79-$i"
                $cNpm = Join-Path $tmp5.FullName "fresh-npm-$i"

                $mHead = Measure-NoLockfileInstall $rnpmBin $cHead "HEAD (fresh)" 1
                $timesHeadFresh += $mHead.Times[0]

                $m79 = Measure-NoLockfileInstall $baseBin $c79 "79a19fd (fresh)" 1
                $times79Fresh += $m79.Times[0]

                $mNpm = Measure-NoLockfileInstall "npm.cmd" $cNpm "npm (fresh)" 1
                $timesNpmFresh += $mNpm.Times[0]
            }
            $resHeadFresh = @{ Times = $timesHeadFresh; Median = (Get-Median $timesHeadFresh) }
            $res79Fresh = @{ Times = $times79Fresh; Median = (Get-Median $times79Fresh) }
            $resNpmFresh = @{ Times = $timesNpmFresh; Median = (Get-Median $timesNpmFresh) }

            Write-Host "`n  === Fresh Speed Summary ===" -ForegroundColor Cyan
            Write-Host ("  FRESH Cache (Medians of {0} runs):`n    HEAD:    {1} ms`n    79a19fd: {2} ms`n    npm:     {3} ms" -f $FreshRuns, $resHeadFresh.Median, $res79Fresh.Median, $resNpmFresh.Median) -ForegroundColor White
            $freshVs79 = [math]::Round($resHeadFresh.Median / [math]::Max($res79Fresh.Median, 1), 3)
            $freshVsNpm = [math]::Round($resNpmFresh.Median / [math]::Max($resHeadFresh.Median, 1), 2)
            Write-Host "    HEAD vs 79a19fd ratio: ${freshVs79}x (must be <= 1.05x)" -ForegroundColor Cyan
            Write-Host "    HEAD vs npm speedup:   ${freshVsNpm}x (target >= 2.0x)" -ForegroundColor Cyan

            $freshNonRegression = $resHeadFresh.Median -le ($res79Fresh.Median * 1.05)
            $fresh2xPassed = $freshVsNpm -ge 2.0
            if (-not $freshNonRegression) {
                Write-Host "  [FAIL] Fresh non-regression failed! HEAD=$($resHeadFresh.Median) ms > 79a19fd=$($res79Fresh.Median) ms * 1.05" -ForegroundColor Red
                $allPassed = $false
            }
            if (-not $fresh2xPassed) {
                Write-Host "  [FAIL] Fresh 2x target failed! HEAD vs npm is ${freshVsNpm}x (< 2.0x)" -ForegroundColor Red
                $allPassed = $false
            }
            if ($freshNonRegression -and $fresh2xPassed) {
                Write-Host "  [PASS] Fresh speed non-regression and >=2x target verified." -ForegroundColor Green
            }
            } else {
                Write-Host "  [FAIL] Fresh runs count is 0 (NOT RUN)" -ForegroundColor Red
                $allPassed = $false
            }
        }
    }
} finally {
    Start-Sleep -Milliseconds 300
    Remove-Item -Recurse -Force $tmp5.FullName -ErrorAction SilentlyContinue
}
}

# ---------------------------------------------------------------
# Check 6: Workspace Tests & Clippy
# ---------------------------------------------------------------
if ($Checks -contains "6") {
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
}

$isFullRun = ($Checks.Count -eq 6) -and (-not $SkipCargoTests) -and ($WarmRuns -ge 5) -and ($FreshRuns -ge 3)
Write-Host "`n====================================================" -ForegroundColor Cyan
if ($allPassed -and $isFullRun) {
    Write-Host " LANE 1 GATE: ALL CHECKS PASSED HONESTLY" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Cyan
    exit 0
} elseif ($allPassed -and (-not $isFullRun)) {
    Write-Host " LANE 1 GATE: INCOMPLETE (SOME CHECKS SKIPPED OR RUN COUNTS REDUCED)" -ForegroundColor Yellow
    Write-Host "====================================================" -ForegroundColor Cyan
    exit 2
} else {
    Write-Host " LANE 1 GATE: CHECKS FAILED" -ForegroundColor Red
    Write-Host "====================================================" -ForegroundColor Cyan
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

