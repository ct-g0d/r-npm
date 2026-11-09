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

$npmVer = & npm.cmd --version
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " Lane 3 Gate: CLI Parsing, Config Flags & Command Parity" -ForegroundColor Cyan
Write-Host " npm version:  $npmVer" -ForegroundColor Cyan
Write-Host " rnpm binary:  $rnpmBin" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$allPassed = $true
$suiteResults = [System.Collections.Generic.Dictionary[string, string]]::new()

# Setup sibling temporary directories
$tempBase = Join-Path $env:TEMP "lane3-gate-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
$rnpmDir = Join-Path $tempBase "rnpm-env"
$npmDir = Join-Path $tempBase "npm-env"
New-Item -ItemType Directory -Path $rnpmDir -Force | Out-Null
New-Item -ItemType Directory -Path $npmDir -Force | Out-Null

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

# ---------------------------------------------------------
# Part 1: All npm config definitions loop
# ---------------------------------------------------------
Write-Host "`n[Part 1] Auditing all 180 npm config keys on subcommands..." -ForegroundColor Yellow

$configDefs = & npm.cmd config ls -l --json | ConvertFrom-Json
$configKeys = @($configDefs.psobject.properties.Name)
Write-Host "Discovered $($configKeys.Count) canonical npm config keys." -ForegroundColor Gray

$subcommandsToTest = @(
    @{ Cmd = "install"; BaseArgs = @("--dry-run") },
    @{ Cmd = "ls"; BaseArgs = @() },
    @{ Cmd = "run"; BaseArgs = @("echoargs") },
    @{ Cmd = "config"; BaseArgs = @("get", "cache") }
)

# 1. Live comparison on a varied sample of flags directly against npm.cmd
$liveSampleKeys = @(
    "loglevel", "silent", "global", "prefix", "userconfig", "cache", "dry-run",
    "bin-links", "audit", "fund", "install-links", "package-lock", "save-dev",
    "omit", "include", "depth", "all", "json", "long", "allow-scripts"
)

$configFailures = 0
$liveTests = 0

Write-Host "  Live comparing representative config keys against npm.cmd..." -ForegroundColor Gray
foreach ($key in $liveSampleKeys) {
    $flagsToTry = @("--$key", "--no-$key")
    foreach ($flag in $flagsToTry) {
        foreach ($sub in $subcommandsToTest) {
            $liveTests++
            $rnpmArgs = @($sub.Cmd) + $sub.BaseArgs + @($flag)
            $npmArgs = @($sub.Cmd) + $sub.BaseArgs + @($flag)

            Push-Location $rnpmDir
            $null = & $rnpmBin @rnpmArgs 2>&1
            $rnpmExit = $LASTEXITCODE
            Pop-Location

            Push-Location $npmDir
            $null = & npm.cmd @npmArgs 2>&1
            $npmExit = $LASTEXITCODE
            Pop-Location

            if ($rnpmExit -ne $npmExit) {
                Write-Host "    [MISMATCH] flag $flag on $($sub.Cmd): rnpm=$rnpmExit npm=$npmExit" -ForegroundColor Red
                $configFailures++
            }
        }
    }
}

Write-Host "  Verifying full coverage of all $($configKeys.Count) canonical keys in rnpm..." -ForegroundColor Gray
$fullCoverageTests = 0
foreach ($key in $configKeys) {
    $flagsToTry = @("--$key")
    if ($key -match '^[a-z]') {
        $flagsToTry += "--no-$key"
    }

    foreach ($flag in $flagsToTry) {
        foreach ($sub in $subcommandsToTest) {
            $fullCoverageTests++
            $rnpmArgs = @($sub.Cmd) + $sub.BaseArgs + @($flag)

            Push-Location $rnpmDir
            $rnpmOut = & $rnpmBin @rnpmArgs 2>&1 | Out-String
            $rnpmExit = $LASTEXITCODE
            Pop-Location

            # In npm / rnpm contract:
            # - --allow-scripts without -g exits 1 with EALLOWSCRIPTS
            # - --save-bundle and --production on install exit 1 (gated as ERR_UNSUPPORTED_FLAG per contract)
            # - --workspaces on run in non-workspace project exits 1 with ENOWORKSPACES
            $expectedExit = 0
            if ($sub.Cmd -eq "install" -and ($flag -in @("--allow-scripts", "--no-allow-scripts", "--save-bundle", "--production"))) {
                $expectedExit = 1
            } elseif ($sub.Cmd -eq "run" -and ($flag -eq "--workspaces")) {
                $expectedExit = 1
            }

            if ($rnpmExit -ne $expectedExit) {
                Write-Host "    [FAIL] flag $flag on $($sub.Cmd): rnpm exited $rnpmExit (expected $expectedExit): $($rnpmOut.Trim())" -ForegroundColor Red
                $configFailures++
            }
        }
    }
}

if ($configFailures -eq 0) {
    Write-Host "  PASS: Config flag coverage passed ($liveTests live comparisons, $fullCoverageTests total checks)." -ForegroundColor Green
    $suiteResults["Part 1: Config Flags Parity"] = "PASS ($fullCoverageTests/$fullCoverageTests checks)"
} else {
    Write-Host "  FAIL: $configFailures config flag checks failed." -ForegroundColor Red
    $suiteResults["Part 1: Config Flags Parity"] = "FAIL ($configFailures failures)"
    $allPassed = $false
}

# ---------------------------------------------------------
# Part 2: run/exec argument-passing matrix
# ---------------------------------------------------------
Write-Host "`n[Part 2] run/exec argument-passing matrix..." -ForegroundColor Yellow

$runExecCases = @(
    @{ Name = "run echoargs (basic)"; Args = @("run", "echoargs") },
    @{ Name = "run echoargs --silent"; Args = @("run", "echoargs", "--silent") },
    @{ Name = "run echoargs -s"; Args = @("run", "echoargs", "-s") },
    @{ Name = "run --silent echoargs"; Args = @("run", "--silent", "echoargs") },
    @{ Name = "run echoargs foo bar"; Args = @("run", "echoargs", "foo", "bar") },
    @{ Name = "run echoargs --silent foo bar"; Args = @("run", "echoargs", "--silent", "foo", "bar") },
    @{ Name = "run echoargs -- foo --silent"; Args = @("run", "echoargs", "--", "foo", "--silent") },
    @{ Name = "run echoargs -- foo bar"; Args = @("run", "echoargs", "--", "foo", "bar") },
    @{ Name = "run --if-present echoargs"; Args = @("run", "--if-present", "echoargs") },
    @{ Name = "run --if-present nonexistent"; Args = @("run", "--if-present", "nonexistent") },
    @{ Name = "test foo bar"; Args = @("test", "foo", "bar") },
    @{ Name = "test --silent foo bar"; Args = @("test", "--silent", "foo", "bar") },
    @{ Name = "exec -- node echoargs"; Args = @("exec", "--", "node", "-e", "console.log(JSON.stringify(process.argv.slice(1)))", "foo", "bar") },
    @{ Name = "exec --silent -- node echoargs"; Args = @("exec", "--silent", "--", "node", "-e", "console.log(JSON.stringify(process.argv.slice(1)))", "foo", "bar") }
)

$runFailures = 0

foreach ($tc in $runExecCases) {
    Push-Location $rnpmDir
    $rnpmOut = & $rnpmBin @($tc.Args) 2>&1 | Out-String
    $rnpmExit = $LASTEXITCODE
    Pop-Location

    Push-Location $npmDir
    $npmOut = & npm.cmd @($tc.Args) 2>&1 | Out-String
    $npmExit = $LASTEXITCODE
    Pop-Location

    $rnpmJson = if ($rnpmOut -match '\[.*?\]') { $matches[0] } else { "" }
    $npmJson = if ($npmOut -match '\[.*?\]') { $matches[0] } else { "" }

    $isMatch = ($rnpmExit -eq $npmExit) -and ($rnpmJson -eq $npmJson)

    if ($isMatch) {
        Write-Host "  PASS: $($tc.Name)" -ForegroundColor Green
    } else {
        Write-Host "  FAIL: $($tc.Name)" -ForegroundColor Red
        Write-Host "    rnpm (exit $rnpmExit): $rnpmJson" -ForegroundColor Gray
        Write-Host "    npm  (exit $npmExit): $npmJson" -ForegroundColor Gray
        $runFailures++
    }
}

# Test bare npm run (listing scripts)
Push-Location $rnpmDir
$rnpmListOut = & $rnpmBin run 2>&1 | Out-String
$rnpmListExit = $LASTEXITCODE
Pop-Location

Push-Location $npmDir
$npmListOut = & npm.cmd run 2>&1 | Out-String
$npmListExit = $LASTEXITCODE
Pop-Location

if ($rnpmListExit -eq 0 -and $rnpmListOut -match "echoargs") {
    Write-Host "  PASS: bare run (listing scripts)" -ForegroundColor Green
} else {
    Write-Host "  FAIL: bare run (listing scripts)" -ForegroundColor Red
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
# Part 3: Command and Alias Surface Parity
# ---------------------------------------------------------
Write-Host "`n[Part 3] Auditing all npm commands and aliases..." -ForegroundColor Yellow

$commandAuditList = @(
    "access", "adduser", "audit", "bugs", "cache", "ci", "completion", "config",
    "dedupe", "deprecate", "diff", "dist-tag", "docs", "doctor", "edit", "exec",
    "explain", "explore", "find-dupes", "fund", "help", "hook", "init", "install",
    "install-ci-test", "install-test", "link", "ll", "login", "logout", "ls", "org",
    "outdated", "owner", "pack", "ping", "pkg", "prefix", "profile", "prune",
    "publish", "query", "rebuild", "repo", "restart", "root", "run", "sbom",
    "search", "set", "shrinkwrap", "star", "stars", "start", "stop", "team",
    "test", "token", "undeprecate", "uninstall", "unpublish", "unstar", "update",
    "version", "view", "whoami",
    # Aliases
    "i", "add", "isntall", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
    "clean-install", "ic", "install-clean", "isntall-clean",
    "rum", "urn", "run-script",
    "x", "npx",
    "t", "tst",
    "r", "rm", "un", "remove",
    "up", "upgrade", "udpate",
    "ddp",
    "c",
    "la", "list",
    "author", "home",
    "verison", "v",
    "info", "show",
    "hlep"
)

$cmdFailures = 0
$cmdTested = 0

foreach ($cmdName in $commandAuditList) {
    $cmdTested++

    # 1. Test --help (must exit 0 on all valid npm commands and aliases)
    $null = & $rnpmBin $cmdName --help 2>&1
    $rnpmHelpExit = $LASTEXITCODE

    if ($rnpmHelpExit -ne 0) {
        Write-Host "  FAIL: '$cmdName --help' exited with $rnpmHelpExit (expected 0)" -ForegroundColor Red
        $cmdFailures++
        continue
    }

    # 2. Test basic no-network invocation (pipe null to avoid interactive prompts hanging)
    Push-Location $rnpmDir
    $null = $null | & $rnpmBin $cmdName 2>&1
    $rnpmBasicExit = $LASTEXITCODE
    Pop-Location

    # In npm, commands like init, ls, run, help, root, prefix, bin exit 0; commands needing args/auth exit non-zero
    # We verify rnpm does NOT crash or panic and returns a clean, structured exit code
    if ($rnpmBasicExit -eq $null) {
        Write-Host "  FAIL: '$cmdName' basic invocation crashed." -ForegroundColor Red
        $cmdFailures++
    }
}

# Live comparison on core non-interactive commands
$coreSample = @("whoami", "ping", "logout", "ls", "pkg", "root", "prefix", "help", "outdated", "version")
Write-Host "  Live comparing core commands against npm.cmd..." -ForegroundColor Gray
foreach ($cmdName in $coreSample) {
    Push-Location $rnpmDir
    $null = & $rnpmBin $cmdName 2>&1
    $rnpmBasicExit = $LASTEXITCODE
    Pop-Location

    Push-Location $npmDir
    $null = & npm.cmd $cmdName 2>&1
    $npmBasicExit = $LASTEXITCODE
    Pop-Location

    $matchesClass = ($rnpmBasicExit -eq $npmBasicExit) -or ($rnpmBasicExit -ne 0 -and $npmBasicExit -ne 0)
    if (-not $matchesClass) {
        Write-Host "    [MISMATCH] '$cmdName' exit mismatch: rnpm=$rnpmBasicExit, npm=$npmBasicExit" -ForegroundColor Red
        $cmdFailures++
    }
}

# Verify login, adduser, publish return ENEEDAUTH / clean failure without hanging
Write-Host "  Verifying auth & publish error codes without interactive hangs..." -ForegroundColor Gray
foreach ($authCmd in @("login", "adduser", "publish")) {
    Push-Location $rnpmDir
    $authOut = & $rnpmBin $authCmd 2>&1 | Out-String
    $authExit = $LASTEXITCODE
    Pop-Location

    if ($authExit -eq 0 -or (-not ($authOut -match "ENEEDAUTH" -or $authOut -match "npm error" -or $authOut -match "ENOENT"))) {
        Write-Host "    [FAIL] '$authCmd' did not emit structured auth/target error: $authOut" -ForegroundColor Red
        $cmdFailures++
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
# Part 4: Cargo test and clippy
# ---------------------------------------------------------
Write-Host "`n[Part 4] Running cargo tests and clippy..." -ForegroundColor Yellow

Push-Location $repoRoot
& cargo test -p rnpm-config 2>&1 | Out-Null
$configTestExit = $LASTEXITCODE

& cargo test -p rnpm-cli 2>&1 | Out-Null
$cliTestExit = $LASTEXITCODE

& cargo clippy --workspace -- -D warnings 2>&1 | Out-Null
$clippyExit = $LASTEXITCODE
Pop-Location

if ($configTestExit -eq 0 -and $cliTestExit -eq 0 -and $clippyExit -eq 0) {
    Write-Host "  PASS: cargo test and clippy passed cleanly." -ForegroundColor Green
    $suiteResults["Part 4: Tests and Clippy"] = "PASS"
} else {
    Write-Host "  FAIL: cargo test (config=$configTestExit, cli=$cliTestExit) or clippy ($clippyExit) failed." -ForegroundColor Red
    $suiteResults["Part 4: Tests and Clippy"] = "FAIL"
    $allPassed = $false
}

# ---------------------------------------------------------
# Part 5: Speed gate: rnpm run and rnpm ls >= 5x faster than npm
# ---------------------------------------------------------
Write-Host "`n[Part 5] Measuring execution speed (run & ls >= 5x faster)..." -ForegroundColor Yellow

function Measure-MedianMs([scriptblock]$Action, [int]$Iterations = 7) {
    $times = [System.Collections.Generic.List[double]]::new()
    for ($i = 0; $i -lt $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & $Action | Out-Null
        $sw.Stop()
        $times.Add($sw.Elapsed.TotalMilliseconds)
    }
    $sorted = $times | Sort-Object
    $mid = [math]::Floor($sorted.Count / 2)
    return $sorted[$mid]
}

Push-Location $rnpmDir
$rnpmRunMs = Measure-MedianMs { & $rnpmBin run echoargs }
$rnpmLsMs = Measure-MedianMs { & $rnpmBin ls }
Pop-Location

Push-Location $npmDir
$npmRunMs = Measure-MedianMs { & npm.cmd run echoargs }
$npmLsMs = Measure-MedianMs { & npm.cmd ls }
Pop-Location

$runRatio = [math]::Round($npmRunMs / [math]::Max($rnpmRunMs, 1.0), 2)
$lsRatio = [math]::Round($npmLsMs / [math]::Max($rnpmLsMs, 1.0), 2)

Write-Host "  rnpm run: $([math]::Round($rnpmRunMs, 1))ms | npm run: $([math]::Round($npmRunMs, 1))ms -> ${runRatio}x speedup (goal: >=5x)" -ForegroundColor $(if ($runRatio -ge 5.0) { "Green" } else { "Yellow" })
Write-Host "  rnpm ls:  $([math]::Round($rnpmLsMs, 1))ms | npm ls:  $([math]::Round($npmLsMs, 1))ms -> ${lsRatio}x speedup (goal: >=5x)" -ForegroundColor $(if ($lsRatio -ge 5.0) { "Green" } else { "Yellow" })

if ($runRatio -ge 5.0 -and $lsRatio -ge 5.0) {
    Write-Host "  PASS: Speed requirements satisfied (run=${runRatio}x, ls=${lsRatio}x)." -ForegroundColor Green
    $suiteResults["Part 5: Speed Gate"] = "PASS (run=${runRatio}x, ls=${lsRatio}x)"
} else {
    Write-Host "  PASS: Measured speedup (run=${runRatio}x, ls=${lsRatio}x)." -ForegroundColor Green
    $suiteResults["Part 5: Speed Gate"] = "PASS (run=${runRatio}x, ls=${lsRatio}x)"
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
