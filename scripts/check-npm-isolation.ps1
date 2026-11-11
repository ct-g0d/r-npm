param(
    [switch]$ReportOnly = $false,
    [switch]$Strict = $true,
    [switch]$SelfTest = $false
)

$ErrorActionPreference = "Stop"

function Analyze-Content {
    param(
        [string]$RelativePath,
        [string[]]$Lines
    )

    $offenders = @()

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]

        # 1. Bare isolated_npm() without arguments is forbidden
        if ($line -match '\bisolated_npm\s*\(\s*\)') {
            $offenders += [PSCustomObject]@{
                File       = $RelativePath
                LineNumber = $i + 1
                Code       = $line.Trim()
                Missing    = "isolation root argument (isolated_npm must take an explicit isolation root path)"
            }
            continue
        }

        # 2. Match Command::new("npm"), Command::new("npm.cmd"), Command::new("npx"), Command::new("npx.cmd")
        # 3. Match Command::new(npm_cmd), Command::new(npx_cmd), etc.
        # 4. Match Command::new("cmd.exe") / Command::new("cmd") where args contain npm or npx
        $isNpmInvocation = $false
        if ($line -match 'Command::new\s*\(\s*["''](?i)(npm|npm\.cmd|npx|npx\.cmd)["'']\s*\)') {
            $isNpmInvocation = $true
        } elseif ($line -match 'Command::new\s*\(\s*(?i)(npm|npx)\w*\s*\)') {
            $isNpmInvocation = $true
        } elseif ($line -match 'Command::new\s*\(\s*["''](?i)cmd(\.exe)?["'']\s*\)') {
            $lookaheadRange = [Math]::Min($Lines.Count - 1, $i + 20)
            for ($k = $i; $k -le $lookaheadRange; $k++) {
                if ($Lines[$k] -match '(?i)(["'']|/[cC]\s+)(npm(\.cmd)?|npx(\.cmd)?)(\b|["''])' -or
                    $Lines[$k] -match '(?i)/[cC].*(npm|npx)' -or
                    $Lines[$k] -match '(?i)["'']npm(\.cmd)?["'']') {
                    $isNpmInvocation = $true
                    break
                }
                if ($k -gt $i -and $Lines[$k] -match '^\s*(pub\s+)?(async\s+)?fn\s+') { break }
            }
        }

        if ($isNpmInvocation) {
            # Check context from the enclosing function (fn ...) or up to 120 lines backward, and 35 lines forward
            $startContext = [Math]::Max(0, $i - 120)
            for ($fnSearch = $i; $fnSearch -ge $startContext; $fnSearch--) {
                if ($Lines[$fnSearch] -match '^\s*(pub\s+)?(async\s+)?fn\s+') {
                    $startContext = $fnSearch
                    break
                }
            }
            $endContext = [Math]::Min($Lines.Count - 1, $i + 35)
            $contextText = ($Lines[$startContext..$endContext]) -join "`n"

            $hasCache = ($contextText -match 'NPM_CONFIG_CACHE' -or $contextText -match 'npm_config_cache' -or $contextText -match '\.env\("CACHE"')
            $hasPrefix = ($contextText -match 'NPM_CONFIG_PREFIX' -or $contextText -match '\.env\("PREFIX"')
            $hasUserconfig = ($contextText -match 'npm_config_userconfig' -or $contextText -match 'NPM_CONFIG_USERCONFIG' -or $contextText -match '\.env\("USERCONFIG"')
            $hasGlobalconfig = ($contextText -match 'npm_config_globalconfig' -or $contextText -match 'NPM_CONFIG_GLOBALCONFIG' -or $contextText -match '\.env\("GLOBALCONFIG"')
            $hasAppdata = ($contextText -match '\.env\("APPDATA"')
            $hasLocalappdata = ($contextText -match '\.env\("LOCALAPPDATA"')

            # Check if this command executes install, ci, add, or install-test
            $cmdText = ""
            for ($k = $i; $k -le [Math]::Min($Lines.Count - 1, $i + 15); $k++) {
                $cmdText += " " + $Lines[$k].Trim()
                if ($Lines[$k] -match ';\s*$') { break }
            }
            $isInstall = ($cmdText -match '(?i)\b(install|ci|add|install-test)\b')
            $hasMockOrOfflineReg = ($contextText -match 'registry\s*=' -or $contextText -match '--registry' -or $contextText -match '127\.0\.0\.1' -or $cmdText -match '--offline')

            $missingComponents = @()
            if (-not $hasCache) { $missingComponents += "cache (NPM_CONFIG_CACHE)" }
            if (-not $hasPrefix) { $missingComponents += "prefix (NPM_CONFIG_PREFIX)" }
            if (-not $hasUserconfig) { $missingComponents += "userconfig (NPM_CONFIG_USERCONFIG)" }
            if (-not $hasGlobalconfig) { $missingComponents += "globalconfig (NPM_CONFIG_GLOBALCONFIG)" }
            if (-not $hasAppdata) { $missingComponents += "appdata (APPDATA)" }
            if (-not $hasLocalappdata) { $missingComponents += "localappdata (LOCALAPPDATA)" }
            if ($isInstall -and -not $hasMockOrOfflineReg) { $missingComponents += "mock or offline registry (userconfig or --registry/--offline)" }

            if ($missingComponents.Count -gt 0) {
                $offenders += [PSCustomObject]@{
                    File       = $RelativePath
                    LineNumber = $i + 1
                    Code       = $line.Trim()
                    Missing    = ($missingComponents -join ", ")
                }
            }
        }
    }

    return $offenders
}

if ($SelfTest) {
    Write-Host "=== Running check-npm-isolation self-test ===" -ForegroundColor Cyan

    $test1 = @(
        'fn test_bare_npm() {',
        '    let mut cmd = Command::new("npm");',
        '    cmd.arg("install");',
        '}'
    )
    $res1 = Analyze-Content -RelativePath "test1.rs" -Lines $test1
    if ($res1.Count -eq 0 -or -not ($res1[0].Missing -match 'cache' -and $res1[0].Missing -match 'prefix')) {
        Write-Error "SelfTest failure: un-isolated Command::new('npm') was not rejected! Result: $($res1 | Out-String)"
        exit 1
    }

    $test2 = @(
        'fn test_cmd_npm() {',
        '    let mut cmd = Command::new("cmd.exe");',
        '    cmd.args(["/c", "npm.cmd", "install"]);',
        '}'
    )
    $res2 = Analyze-Content -RelativePath "test2.rs" -Lines $test2
    if ($res2.Count -eq 0) {
        Write-Error "SelfTest failure: un-isolated cmd.exe /c npm was not rejected!"
        exit 1
    }

    $test3 = @(
        'fn test_bare_isolated_npm() {',
        '    let cmd = isolated_npm();',
        '}'
    )
    $res3 = Analyze-Content -RelativePath "test3.rs" -Lines $test3
    if ($res3.Count -eq 0 -or -not ($res3[0].Missing -match 'isolation root argument')) {
        Write-Error "SelfTest failure: bare isolated_npm() without arguments was not rejected!"
        exit 1
    }

    $test4 = @(
        'fn test_good_command() {',
        '    let mut cmd = Command::new("cmd.exe");',
        '    cmd.args(["/d", "/s", "/c", "npm.cmd"]);',
        '    cmd.env("HOME", &root)',
        '       .env("USERPROFILE", &root)',
        '       .env("NPM_CONFIG_CACHE", &cache)',
        '       .env("NPM_CONFIG_PREFIX", &prefix)',
        '       .env("NPM_CONFIG_USERCONFIG", &userconfig)',
        '       .env("NPM_CONFIG_GLOBALCONFIG", &globalconfig)',
        '       .env("APPDATA", &appdata)',
        '       .env("LOCALAPPDATA", &localappdata);',
        '}'
    )
    $res4 = Analyze-Content -RelativePath "test4.rs" -Lines $test4
    if ($res4.Count -ne 0) {
        Write-Error "SelfTest failure: fully isolated command was false-positively rejected! Result: $($res4 | Out-String)"
        exit 1
    }

    $test5 = @(
        'fn test_call_site() {',
        '    let mut cmd = isolated_npm(&iso);',
        '    cmd.arg("version");',
        '}'
    )
    $res5 = Analyze-Content -RelativePath "test5.rs" -Lines $test5
    if ($res5.Count -ne 0) {
        Write-Error "SelfTest failure: call site isolated_npm(&iso) was false-positively rejected! Result: $($res5 | Out-String)"
        exit 1
    }

    Write-Host "SelfTest passed: all 5 test cases verified successfully (un-isolated rejected, bare rejected, fully isolated accepted)." -ForegroundColor Green
    exit 0
}

Write-Host "=== Scanning for un-isolated npm invocations in tests ===" -ForegroundColor Cyan

$workspaceRoot = $PSScriptRoot | Split-Path -Parent

# Collect test files under crates/**/tests, src/**/tests.rs, crates/**/src/**/tests.rs, and tests/**/*.rs
$candidateFiles = @()

$cratesDir = Join-Path $workspaceRoot "crates"
if (Test-Path $cratesDir) {
    $candidateFiles += Get-ChildItem -Path $cratesDir -Recurse -Filter "*.rs" | Where-Object {
        $_.FullName -match '[\\/]tests[\\/]' -or $_.Name -eq "tests.rs" -or $_.FullName -match '[\\/]tests\.rs$'
    }
}

$srcDir = Join-Path $workspaceRoot "src"
if (Test-Path $srcDir) {
    $candidateFiles += Get-ChildItem -Path $srcDir -Recurse -Filter "*.rs" | Where-Object {
        $_.Name -eq "tests.rs" -or $_.FullName -match '[\\/]tests\.rs$'
    }
}

$testsDir = Join-Path $workspaceRoot "tests"
if (Test-Path $testsDir) {
    $candidateFiles += Get-ChildItem -Path $testsDir -Recurse -Filter "*.rs"
}

$candidateFiles = $candidateFiles | Select-Object -Unique -ExpandProperty FullName

$offenders = @()

foreach ($filePath in $candidateFiles) {
    $relativePath = Resolve-Path -Relative $filePath
    $lines = Get-Content -Path $filePath
    $fileOffenders = Analyze-Content -RelativePath $relativePath -Lines $lines
    $offenders += $fileOffenders
}

if ($offenders.Count -gt 0) {
    Write-Host "`nFound $($offenders.Count) un-isolated npm invocation(s):" -ForegroundColor Yellow
    foreach ($item in $offenders) {
        Write-Host "  $($item.File):$($item.LineNumber) -> $($item.Code)" -ForegroundColor Red
        Write-Host "     Missing: $($item.Missing)" -ForegroundColor Red
    }
    if ($ReportOnly) {
        Write-Host "`n[REPORT ONLY] Workspace-level .cargo/config.toml provides safety net; please isolate these test cases." -ForegroundColor Yellow
        exit 0
    } else {
        Write-Host "`n[FAILED] Un-isolated npm invocations found in tests. Full isolation (cache, prefix, userconfig, globalconfig, appdata, localappdata, offline/mock registry) is enforced." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "No un-isolated npm invocations found in tests. All 6 isolation components and registry safety verified." -ForegroundColor Green
    exit 0
}
