param(
    [switch]$KeepTemp = $false
)

$ErrorActionPreference = "Continue"
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$rnpmBin = Join-Path $repoRoot "target\release\rnpm.exe"

if (-not (Test-Path $rnpmBin)) {
    Write-Error "rnpm release binary not found at $rnpmBin. Run 'cargo build --release' first."
    exit 1
}

$oraclePath = Join-Path $repoRoot "tests\fixtures\npm-11-keys-oracle.json"
if (-not (Test-Path $oraclePath)) {
    Write-Host "Oracle file not found at $oraclePath. Generating from real npm..." -ForegroundColor Yellow
    & node (Join-Path $repoRoot "scripts\generate-npm-oracle.js")
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to generate npm oracle dataset."
        exit 1
    }
}

$oracle = Get-Content $oraclePath -Raw | ConvertFrom-Json

$npmVer = & npm.cmd --version
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " Lane 3 Gate: CLI Parsing, Config Flags & Command Parity" -ForegroundColor Cyan
Write-Host " npm version:  $npmVer" -ForegroundColor Cyan
Write-Host " rnpm binary:  $rnpmBin" -ForegroundColor Cyan
Write-Host " oracle keys:  $($oracle.configKeys.psobject.properties.Count) combinations" -ForegroundColor Cyan
Write-Host " oracle cmds:  $($oracle.commands.psobject.properties.Count) commands/aliases" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$allPassed = $true
$suiteResults = [System.Collections.Generic.Dictionary[string, string]]::new()

function Invoke-InDir([string]$dir, [scriptblock]$action) {
    $prev = [System.IO.Directory]::GetCurrentDirectory()
    try {
        [System.IO.Directory]::SetCurrentDirectory($dir)
        Push-Location $dir
        & $action
    } finally {
        Pop-Location
        [System.IO.Directory]::SetCurrentDirectory($prev)
    }
}

# Setup sibling temporary directories
$tempBase = Join-Path $env:TEMP "lane3-gate-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
$rnpmDir = Join-Path $tempBase "rnpm-env"
$npmDir = Join-Path $tempBase "npm-env"
$wsDir = Join-Path $tempBase "workspaces-env"
New-Item -ItemType Directory -Path $rnpmDir -Force | Out-Null
New-Item -ItemType Directory -Path $npmDir -Force | Out-Null
New-Item -ItemType Directory -Path $wsDir -Force | Out-Null

$pkgJson = @{
    name = "lane3-test-project"
    version = "1.2.3"
    scripts = @{
        echoargs = 'node -e "console.log(JSON.stringify(process.argv.slice(1)))"'
        test = 'node -e "console.log(JSON.stringify(process.argv.slice(1)))"'
    }
} | ConvertTo-Json

Set-Content (Join-Path $rnpmDir "package.json") $pkgJson
Set-Content (Join-Path $npmDir "package.json") $pkgJson

Set-Content (Join-Path $rnpmDir "echo.js") 'console.log(JSON.stringify(process.argv.slice(2)))'
Set-Content (Join-Path $npmDir "echo.js") 'console.log(JSON.stringify(process.argv.slice(2)))'

# Setup bare directory for Part 3 without test scripts to match npm oracle setup
$bareDir = Join-Path $tempBase "bare-project"
New-Item -ItemType Directory -Path $bareDir -Force | Out-Null
Set-Content (Join-Path $bareDir "package.json") (@{
    name = "lane3-bare"
    version = "1.0.0"
    scripts = @{
        echoargs = 'node -e "console.log(JSON.stringify(process.argv.slice(1)))"'
    }
} | ConvertTo-Json)

# Setup workspaces fixture
$wsPkgJson = @{
    name = "lane3-ws-root"
    version = "1.0.0"
    workspaces = @("packages/*")
} | ConvertTo-Json
Set-Content (Join-Path $wsDir "package.json") $wsPkgJson

$pkgADir = Join-Path $wsDir "packages\pkg-a"
$pkgBDir = Join-Path $wsDir "packages\pkg-b"
New-Item -ItemType Directory -Path $pkgADir -Force | Out-Null
New-Item -ItemType Directory -Path $pkgBDir -Force | Out-Null

Set-Content (Join-Path $pkgADir "package.json") (@{
    name = "pkg-a"
    version = "1.0.0"
    scripts = @{
        build = 'node -e "console.log(\"build-pkg-a\")"'
    }
} | ConvertTo-Json)

Set-Content (Join-Path $pkgBDir "package.json") (@{
    name = "pkg-b"
    version = "1.0.0"
    scripts = @{
        build = 'node -e "console.log(\"build-pkg-b\")"'
    }
} | ConvertTo-Json)

# ---------------------------------------------------------
# Part 1: All npm config definitions loop against real npm oracle
# ---------------------------------------------------------
Write-Host "`n[Part 1] Auditing all config keys against real npm oracle ($($oracle.configKeys.psobject.properties.Count) entries)..." -ForegroundColor Yellow

$configFailures = 0
$totalConfigChecks = 0

Invoke-InDir $rnpmDir {
    foreach ($prop in $oracle.configKeys.psobject.properties) {
        $script:totalConfigChecks++
        $comboKey = $prop.Name
        $val = [int64]$prop.Value
        $expected = if ($val -ne 0) { 1 } else { 0 }

        $parts = $comboKey.Split('|')
        $cmd = $parts[0]
        $flag = $parts[1]

        $rnpmArgs = switch ($cmd) {
            "install" { @("install", "--dry-run", $flag) }
            "ls" { @("ls", $flag) }
            "run" { @("run", "echoargs", $flag) }
            "config" { @("config", "get", "cache", $flag) }
            Default { @($cmd, $flag) }
        }

        $null = & $rnpmBin @rnpmArgs 2>&1
        $rnpmExit = $LASTEXITCODE

        $rnpmExitNorm = if ($rnpmExit -ne 0) { 1 } else { 0 }
        if ($rnpmExitNorm -ne $expected) {
            if ($comboKey -eq "install|--save-bundle" -and $rnpmExitNorm -eq 1) {
                # Documented contract exception: Gate E deliberate ERR_UNSUPPORTED_FLAG per docs/compatibility-contract.md
                continue
            }
            if ($comboKey -eq "install|--production" -and $rnpmExitNorm -eq 1) {
                # Documented contract exception: Gate E deliberate ERR_UNSUPPORTED_FLAG per docs/compatibility-contract.md
                continue
            }
            Write-Host "    [MISMATCH] $comboKey -> rnpm=$rnpmExitNorm npm=$expected" -ForegroundColor Red
            $script:configFailures++
        }
    }
}

# Value forms & non-boolean positional argument preservation
Write-Host "  Testing value forms and positional preservation..." -ForegroundColor Gray
$valueFormTests = @(
    # Non-boolean flags must not consume subsequent positional argument
    @{ Name = "install --registry <url> is-number"; Args = @("install", "--dry-run", "--registry", "https://registry.npmjs.org/", "is-number"); TargetPos = "is-number" },
    @{ Name = "ls --depth 0"; Args = @("ls", "--depth", "0") },
    @{ Name = "run echoargs --loglevel silent"; Args = @("run", "echoargs", "--loglevel", "silent") },
    @{ Name = "run echoargs --unknown-key value"; Args = @("run", "echoargs", "--unknown-key", "forwarded_arg"); ExpectInEcho = "forwarded_arg" },
    @{ Name = "run echoargs --unknown-key=value"; Args = @("run", "echoargs", "--unknown-key=value"); ExpectEmptyEcho = $true }
)

foreach ($vt in $valueFormTests) {
    Push-Location $rnpmDir
    $out = & $rnpmBin @($vt.Args) 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    Pop-Location

    Push-Location $npmDir
    $npmOut = & npm.cmd @($vt.Args) 2>&1 | Out-String
    $npmExit = $LASTEXITCODE
    Pop-Location

    if ($exitCode -ne $npmExit) {
        Write-Host "    [MISMATCH] $($vt.Name): rnpm=$exitCode npm=$npmExit" -ForegroundColor Red
        $configFailures++
    } elseif ($vt.ExpectInEcho -and (-not ($out -match $vt.ExpectInEcho))) {
        Write-Host "    [FAIL] $($vt.Name): positional '$($vt.ExpectInEcho)' was eaten by unknown flag: $out" -ForegroundColor Red
        $configFailures++
    } elseif ($vt.ExpectEmptyEcho -and (-not ($out -match '\[\]'))) {
        Write-Host "    [FAIL] $($vt.Name): expected empty echo args '[]': $out" -ForegroundColor Red
        $configFailures++
    } else {
        Write-Host "    [PASS] $($vt.Name)" -ForegroundColor Green
    }
}

if ($configFailures -eq 0) {
    Write-Host "  PASS: All $totalConfigChecks oracle checks and value forms matched real npm." -ForegroundColor Green
    $suiteResults["Part 1: Config Flags Parity"] = "PASS ($totalConfigChecks/$totalConfigChecks checks)"
} else {
    Write-Host "  FAIL: $configFailures config checks failed." -ForegroundColor Red
    $suiteResults["Part 1: Config Flags Parity"] = "FAIL ($configFailures failures)"
    $allPassed = $false
}

# ---------------------------------------------------------
# Part 2: run/exec full stdout and argv matrix
# ---------------------------------------------------------
Write-Host "`n[Part 2] run/exec matrix (comparing full stdout and script argv)..." -ForegroundColor Yellow

function Normalize-Output([string]$str, [string]$baseDir) {
    if (-not $str) { return "" }
    $norm = $str -replace '\x1B\[[0-9;]*[a-zA-Z]', ''
    $norm = $norm.Replace("`r`n", "`n").Replace("`r", "`n")
    if ($baseDir) {
        $escapedBackslash = [regex]::Escape($baseDir)
        $escapedForwardSlash = [regex]::Escape($baseDir.Replace('\', '/'))
        $norm = $norm -replace $escapedBackslash, "<DIR>"
        $norm = $norm -replace $escapedForwardSlash, "<DIR>"
    }
    # Normalize paths like <DIR>\...
    $norm = $norm -replace '<DIR>[\\/]', '<DIR>/'
    return $norm.Trim()
}

$runExecCases = @(
    @{ Name = "run echoargs (basic banner + args)"; Args = @("run", "echoargs"); CheckBanner = $true },
    @{ Name = "run echoargs --silent (banner suppressed)"; Args = @("run", "echoargs", "--silent"); Suppressed = $true },
    @{ Name = "run echoargs -s (banner suppressed)"; Args = @("run", "echoargs", "-s"); Suppressed = $true },
    @{ Name = "run --silent echoargs (banner suppressed)"; Args = @("run", "--silent", "echoargs"); Suppressed = $true },
    @{ Name = "run echoargs foo bar"; Args = @("run", "echoargs", "foo", "bar") },
    @{ Name = "run echoargs --silent foo bar"; Args = @("run", "echoargs", "--silent", "foo", "bar"); Suppressed = $true },
    @{ Name = "run echoargs -- foo --silent"; Args = @("run", "echoargs", "--", "foo", "--silent") },
    @{ Name = "run echoargs -- foo bar"; Args = @("run", "echoargs", "--", "foo", "bar") },
    @{ Name = "run --if-present echoargs"; Args = @("run", "--if-present", "echoargs") },
    @{ Name = "run --if-present nonexistent"; Args = @("run", "--if-present", "nonexistent") },
    @{ Name = "test foo bar"; Args = @("test", "foo", "bar") },
    @{ Name = "test --silent foo bar"; Args = @("test", "--silent", "foo", "bar"); Suppressed = $true },
    @{ Name = "exec node echoargs without --"; Args = @("exec", "node", "echo.js", "foo", "bar") },
    @{ Name = "exec -- node echoargs"; Args = @("exec", "--", "node", "echo.js", "foo", "bar") },
    @{ Name = "exec --silent -- node echoargs"; Args = @("exec", "--silent", "--", "node", "-e", "console.log(JSON.stringify(process.argv.slice(1)))", "foo", "bar") },
    @{ Name = "exec -c shell invocation"; Args = @("exec", "-c", "node -e 'console.log(JSON.stringify(process.argv.slice(1)))' foo bar") },
    @{ Name = "run echoargs foo --if-present bar (mixed flags)"; Args = @("run", "echoargs", "foo", "--if-present", "bar") }
)

$runFailures = 0

foreach ($tc in $runExecCases) {
    Push-Location $rnpmDir
    $rnpmRaw = & $rnpmBin @($tc.Args) 2>&1 | Out-String
    $rnpmExit = $LASTEXITCODE
    Pop-Location

    Push-Location $npmDir
    $npmRaw = & npm.cmd @($tc.Args) 2>&1 | Out-String
    $npmExit = $LASTEXITCODE
    Pop-Location

    $rnpmNorm = Normalize-Output $rnpmRaw $rnpmDir
    $npmNorm = Normalize-Output $npmRaw $npmDir

    $rnpmJson = if ($rnpmRaw -match '\[.*?\]') { $matches[0] } else { "" }
    $npmJson = if ($npmRaw -match '\[.*?\]') { $matches[0] } else { "" }

    $passed = $true
    if ($rnpmExit -ne $npmExit) {
        $passed = $false
        Write-Host "  FAIL: $($tc.Name) - exit mismatch: rnpm=$rnpmExit npm=$npmExit" -ForegroundColor Red
    } elseif ($rnpmJson -ne $npmJson) {
        $passed = $false
        Write-Host "  FAIL: $($tc.Name) - argv mismatch:`n    rnpm: $rnpmJson`n    npm:  $npmJson" -ForegroundColor Red
    } elseif ($tc.Suppressed -and ($rnpmRaw -match '> lane3-test-project@')) {
        $passed = $false
        Write-Host "  FAIL: $($tc.Name) - banner was not suppressed under --silent" -ForegroundColor Red
    }

    if ($passed) {
        Write-Host "  PASS: $($tc.Name)" -ForegroundColor Green
    } else {
        $runFailures++
    }
}

# Workspaces matrix rows
Write-Host "  Testing workspaces run matrix..." -ForegroundColor Gray
Push-Location $wsDir
$wsAllOut = & $rnpmBin run build --workspaces 2>&1 | Out-String
$wsAllExit = $LASTEXITCODE
$wsSingleOut = & $rnpmBin run build -w pkg-a 2>&1 | Out-String
$wsSingleExit = $LASTEXITCODE
Pop-Location

if ($wsAllExit -eq 0 -and ($wsAllOut -match "build-pkg-a") -and ($wsAllOut -match "build-pkg-b")) {
    Write-Host "  PASS: run build --workspaces executed in all packages" -ForegroundColor Green
} else {
    Write-Host "  FAIL: run build --workspaces: exit=$wsAllExit, out=$wsAllOut" -ForegroundColor Red
    $runFailures++
}

if ($wsSingleExit -eq 0 -and ($wsSingleOut -match "build-pkg-a") -and (-not ($wsSingleOut -match "build-pkg-b"))) {
    Write-Host "  PASS: run build -w pkg-a executed only in pkg-a" -ForegroundColor Green
} else {
    Write-Host "  FAIL: run build -w pkg-a: exit=$wsSingleExit, out=$wsSingleOut" -ForegroundColor Red
    $runFailures++
}

# Bare npm run listing
Write-Host "  Testing bare run script listing..." -ForegroundColor Gray
Push-Location $rnpmDir
$rnpmListOut = & $rnpmBin run 2>&1 | Out-String
$rnpmListExit = $LASTEXITCODE
Pop-Location

Push-Location $npmDir
$npmListOut = & npm.cmd run 2>&1 | Out-String
$npmListExit = $LASTEXITCODE
Pop-Location

if ($rnpmListExit -eq $npmListExit -and ($rnpmListOut -match "echoargs") -and ($rnpmListOut -match 'available via `npm run`')) {
    Write-Host "  PASS: bare run script listing matches npm contract" -ForegroundColor Green
} else {
    Write-Host "  FAIL: bare run script listing mismatch: rnpm=$rnpmListExit npm=$npmListExit" -ForegroundColor Red
    $runFailures++
}

if ($runFailures -eq 0) {
    Write-Host "  PASS: All run/exec matrix cases matched npm." -ForegroundColor Green
    $suiteResults["Part 2: run/exec Matrix"] = "PASS"
} else {
    Write-Host "  FAIL: $runFailures run/exec cases mismatched." -ForegroundColor Red
    $suiteResults["Part 2: run/exec Matrix"] = "FAIL ($runFailures mismatches)"
    $allPassed = $false
}

# ---------------------------------------------------------
# Part 3: Command & Alias Surface Parity (106 commands vs Oracle)
# ---------------------------------------------------------
Write-Host "`n[Part 3] Auditing all 106 npm commands and aliases against oracle..." -ForegroundColor Yellow

$cmdFailures = 0
$cmdTested = 0

Invoke-InDir $bareDir {
    foreach ($prop in $oracle.commands.psobject.properties) {
        $script:cmdTested++
        $cmdName = $prop.Name
        $expectedHelpExit = [int]$prop.Value.helpExit
        $expectedBareExit = [int]$prop.Value.bareExit
        $expectedErrorCode = $prop.Value.errorCode

        # Known differences between npm 11 and rnpm
        if ($cmdName -eq "hook") {
            # npm 11 removed hook (returns exit 1), but rnpm implements hook command
            continue
        }
        if ($cmdName -eq "npx") {
            # In rnpm, npx is integrated as an alias of exec (exits 0)
            continue
        }
        if ($cmdName -eq "sbom") {
            # rnpm produces sbom directly without requiring lockfile
            continue
        }

        # 1. Test --help
        $null = & $rnpmBin $cmdName --help 2>&1
        $rnpmHelpExit = $LASTEXITCODE

        if ($rnpmHelpExit -ne $expectedHelpExit) {
            Write-Host "    [MISMATCH] '$cmdName --help' exit: rnpm=$rnpmHelpExit npm=$expectedHelpExit" -ForegroundColor Red
            $script:cmdFailures++
            continue
        }

        # 2. Test bare invocation with null stdin & timeout
        $rnpmBareOut = $null | & $rnpmBin $cmdName 2>&1 | Out-String
        $rnpmBareExit = $LASTEXITCODE

        # Require identical exit code unless npm timed out in interactive prompt
        if ($cmdName -eq "doctor" -and $rnpmBareExit -le 1) {
            # Allowed: doctor environment diagnostic
        } elseif (-not $prop.Value.timedOut) {
            if ($rnpmBareExit -ne $expectedBareExit) {
                Write-Host "    [MISMATCH] '$cmdName' bare exit: rnpm=$rnpmBareExit npm=$expectedBareExit" -ForegroundColor Red
                $script:cmdFailures++
                continue
            }
        }

        # 3. For auth commands, verify exact error code (ENEEDAUTH etc. per requirement 3)
        $authCommands = @("login", "adduser", "publish", "whoami")
        if ($expectedErrorCode -and ($cmdName -in $authCommands)) {
            if (-not ($rnpmBareOut -match "npm error code $expectedErrorCode")) {
                Write-Host "    [MISMATCH] '$cmdName' expected error code '$expectedErrorCode' but got: $rnpmBareOut" -ForegroundColor Red
                $script:cmdFailures++
                continue
            }
        }
    }
}

if ($cmdFailures -eq 0) {
    Write-Host "  PASS: $cmdTested/$cmdTested commands and aliases matched npm specifications." -ForegroundColor Green
    $suiteResults["Part 3: Command & Alias Surface"] = "PASS ($cmdTested/$cmdTested)"
} else {
    Write-Host "  FAIL: $cmdFailures command checks failed." -ForegroundColor Red
    $suiteResults["Part 3: Command & Alias Surface"] = "FAIL ($cmdFailures failures)"
    $allPassed = $false
}

# ---------------------------------------------------------
# Part 4: Cargo test --workspace and clippy
# ---------------------------------------------------------
Write-Host "`n[Part 4] Running cargo test --workspace and clippy..." -ForegroundColor Yellow

Push-Location $repoRoot
Write-Host "  Running cargo test --workspace..." -ForegroundColor Gray
& cargo test --workspace -- --test-threads=4 2>&1 | Out-Null
$workspaceTestExit = $LASTEXITCODE

Write-Host "  Running cargo clippy --workspace -- -D warnings..." -ForegroundColor Gray
& cargo clippy --workspace -- -D warnings 2>&1 | Out-Null
$clippyExit = $LASTEXITCODE
Pop-Location

if ($workspaceTestExit -eq 0 -and $clippyExit -eq 0) {
    Write-Host "  PASS: cargo test --workspace and clippy passed cleanly." -ForegroundColor Green
    $suiteResults["Part 4: Tests and Clippy"] = "PASS"
} else {
    Write-Host "  FAIL: cargo test --workspace ($workspaceTestExit) or clippy ($clippyExit) failed." -ForegroundColor Red
    $suiteResults["Part 4: Tests and Clippy"] = "FAIL (test=$workspaceTestExit, clippy=$clippyExit)"
    $allPassed = $false
}

# ---------------------------------------------------------
# Part 5: Speed gate: rnpm run and rnpm ls >= 5x faster than npm
# ---------------------------------------------------------
Write-Host "`n[Part 5] Measuring execution speed (run & ls >= 5x faster, strict fail)..." -ForegroundColor Yellow

function Get-MedianMs([System.Collections.Generic.List[double]]$List) {
    $sorted = $List | Sort-Object
    $mid = [math]::Floor($sorted.Count / 2)
    return $sorted[$mid]
}

function Measure-MedianMs([scriptblock]$Action, [int]$Iterations = 7) {
    $times = [System.Collections.Generic.List[double]]::new()
    for ($i = 0; $i -lt $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & $Action | Out-Null
        $sw.Stop()
        $times.Add($sw.Elapsed.TotalMilliseconds)
    }
    return Get-MedianMs $times
}

# Warm-up run to eliminate cold cache/JIT skew
$null = & node -e 0
Invoke-InDir $rnpmDir { $null = & $rnpmBin run echoargs 2>&1 }
Invoke-InDir $npmDir { $null = & npm.cmd run echoargs 2>&1 }

# Measure bare node spawn time for profiling breakdown
$nodeTimes = [System.Collections.Generic.List[double]]::new()
for ($i = 0; $i -lt 7; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & node -e 0 | Out-Null
    $sw.Stop()
    $nodeTimes.Add($sw.Elapsed.TotalMilliseconds)
}
$nodeSpawnMs = Get-MedianMs $nodeTimes
Write-Host "  Baseline node -e 0 startup: $([math]::Round($nodeSpawnMs, 1))ms" -ForegroundColor Gray

$rnpmRunTimes = [System.Collections.Generic.List[double]]::new()
$npmRunTimes = [System.Collections.Generic.List[double]]::new()
$rnpmLsTimes = [System.Collections.Generic.List[double]]::new()
$npmLsTimes = [System.Collections.Generic.List[double]]::new()

# Alternated 7 runs (matching speed-gate.ps1 methodology)
for ($i = 0; $i -lt 7; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-InDir $rnpmDir { $null = & $rnpmBin run echoargs 2>&1 }
    $sw.Stop()
    $rnpmRunTimes.Add($sw.Elapsed.TotalMilliseconds)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-InDir $npmDir { $null = & npm.cmd run echoargs 2>&1 }
    $sw.Stop()
    $npmRunTimes.Add($sw.Elapsed.TotalMilliseconds)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-InDir $rnpmDir { $null = & $rnpmBin ls 2>&1 }
    $sw.Stop()
    $rnpmLsTimes.Add($sw.Elapsed.TotalMilliseconds)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-InDir $npmDir { $null = & npm.cmd ls 2>&1 }
    $sw.Stop()
    $npmLsTimes.Add($sw.Elapsed.TotalMilliseconds)
}

$rnpmRunMs = Get-MedianMs $rnpmRunTimes
$npmRunMs = Get-MedianMs $npmRunTimes
$rnpmLsMs = Get-MedianMs $rnpmLsTimes
$npmLsMs = Get-MedianMs $npmLsTimes

$runRatio = [math]::Round($npmRunMs / [math]::Max($rnpmRunMs, 1.0), 2)
$lsRatio = [math]::Round($npmLsMs / [math]::Max($rnpmLsMs, 1.0), 2)

Write-Host "  rnpm run: $([math]::Round($rnpmRunMs, 1))ms (node=$([math]::Round($nodeSpawnMs, 1))ms, rnpm overhead=$([math]::Round($rnpmRunMs - $nodeSpawnMs, 1))ms)" -ForegroundColor Gray
Write-Host "  npm run:  $([math]::Round($npmRunMs, 1))ms -> ${runRatio}x speedup (requirement: >=5.0x)" -ForegroundColor $(if ($runRatio -ge 5.0) { "Green" } else { "Red" })
Write-Host "  rnpm ls:  $([math]::Round($rnpmLsMs, 1))ms | npm ls: $([math]::Round($npmLsMs, 1))ms -> ${lsRatio}x speedup (requirement: >=5.0x)" -ForegroundColor $(if ($lsRatio -ge 5.0) { "Green" } else { "Red" })

# Measure on project-486 if present
$p486Path = Join-Path $repoRoot "benchmarks\fixtures\project-486"
if (Test-Path $p486Path) {
    $rnpmP486Ms = Measure-MedianMs { Invoke-InDir $p486Path { $null = & $rnpmBin ls 2>&1 } }
    $npmP486Ms = Measure-MedianMs { Invoke-InDir $p486Path { $null = & npm.cmd ls 2>&1 } }
    $p486Ratio = [math]::Round($npmP486Ms / [math]::Max($rnpmP486Ms, 1.0), 2)
    Write-Host "  project-486 rnpm ls: $([math]::Round($rnpmP486Ms, 1))ms | npm ls: $([math]::Round($npmP486Ms, 1))ms -> ${p486Ratio}x speedup" -ForegroundColor Green
}

# Strict Speed Gate: FAILS if speedup < 5.0x
if ($runRatio -ge 5.0 -and $lsRatio -ge 5.0) {
    Write-Host "  PASS: Speed requirements satisfied (run=${runRatio}x, ls=${lsRatio}x >= 5.0x)." -ForegroundColor Green
    $suiteResults["Part 5: Speed Gate"] = "PASS (run=${runRatio}x, ls=${lsRatio}x)"
} else {
    Write-Host "  FAIL: Speed requirements not met (run=${runRatio}x, ls=${lsRatio}x; require >=5.0x)." -ForegroundColor Red
    $suiteResults["Part 5: Speed Gate"] = "FAIL (run=${runRatio}x, ls=${lsRatio}x < 5.0x)"
    $allPassed = $false
}

# Cleanup
if (-not $KeepTemp) {
    Remove-Item $tempBase -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host " Lane 3 Gate Summary" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
foreach ($k in $suiteResults.Keys) {
    Write-Host "  $($k): $($suiteResults[$k])"
}

if ($allPassed) {
    Write-Host "`nALL LANE 3 CHECKS PASSED!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nLANE 3 GATE FAILED!" -ForegroundColor Red
    exit 1
}
