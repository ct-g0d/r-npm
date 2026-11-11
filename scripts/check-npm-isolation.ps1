param(
    [switch]$ReportOnly = $false,
    [switch]$Strict = $true
)

$ErrorActionPreference = "Stop"

Write-Host "=== Scanning for un-isolated npm invocations in tests ===" -ForegroundColor Cyan

$workspaceRoot = $PSScriptRoot | Split-Path -Parent

# Collect test files under crates/**/tests, src/**/tests.rs, crates/**/src/**/tests.rs, and tests/**/*.rs
$candidateFiles = @()

$cratesDir = Join-Path $workspaceRoot "crates"
if (Test-Path $cratesDir) {
    # crates/**/tests/**/*.rs, src/**/tests.rs
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

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        # 1. Match Command::new("npm"), Command::new("npm.cmd"), Command::new("npx"), Command::new("npx.cmd")
        # 2. Match Command::new(npm_cmd), Command::new(npx_cmd), etc.
        # 3. Match Command::new("cmd.exe") / Command::new("cmd") where args contain npm, npm.cmd, npx, npx.cmd,
        #    or arguments matching /C npm ..., /c npm ..., /C npx ..., /c npx ...
        $isNpmInvocation = $false
        if ($line -match 'Command::new\s*\(\s*["''](?i)(npm|npm\.cmd|npx|npx\.cmd)["'']\s*\)') {
            $isNpmInvocation = $true
        } elseif ($line -match 'Command::new\s*\(\s*(?i)(npm|npx)\w*\s*\)') {
            $isNpmInvocation = $true
        } elseif ($line -match 'Command::new\s*\(\s*["''](?i)cmd(\.exe)?["'']\s*\)') {
            # Check chained or nearby arguments referencing npm or npx
            $lookaheadRange = [Math]::Min($lines.Count - 1, $i + 20)
            for ($k = $i; $k -le $lookaheadRange; $k++) {
                if ($lines[$k] -match '(?i)(["'']|/[cC]\s+)(npm(\.cmd)?|npx(\.cmd)?)(\b|["''])' -or
                    $lines[$k] -match '(?i)/[cC].*(npm|npx)') {
                    $isNpmInvocation = $true
                    break
                }
                if ($lines[$k] -match ';\s*$') { break }
            }
        }

        if ($isNpmInvocation) {
            # Check context from the enclosing function (fn ...) or up to 120 lines backward, and 35 lines forward
            $startContext = [Math]::Max(0, $i - 120)
            for ($fnSearch = $i; $fnSearch -ge $startContext; $fnSearch--) {
                if ($lines[$fnSearch] -match '^\s*(pub\s+)?(async\s+)?fn\s+') {
                    $startContext = $fnSearch
                    break
                }
            }
            $endContext = [Math]::Min($lines.Count - 1, $i + 35)
            $contextText = ($lines[$startContext..$endContext]) -join "`n"

            $isHelper = ($contextText -match 'isolated_(cmd|npm|rnpm|process)' -or $line -match 'isolated_')

            $hasCache = ($contextText -match 'NPM_CONFIG_CACHE' -or $contextText -match 'npm_config_cache')
            $hasPrefix = ($contextText -match 'NPM_CONFIG_PREFIX' -or $contextText -match '\.env\("PREFIX"')
            $hasUserconfig = ($contextText -match 'npm_config_userconfig' -or $contextText -match 'NPM_CONFIG_USERCONFIG' -or $contextText -match '\.env\("USERCONFIG"')
            $hasGlobalconfig = ($contextText -match 'npm_config_globalconfig' -or $contextText -match 'NPM_CONFIG_GLOBALCONFIG' -or $contextText -match '\.env\("GLOBALCONFIG"')
            $hasAppdata = ($contextText -match '\.env\("APPDATA"')
            $hasLocalappdata = ($contextText -match '\.env\("LOCALAPPDATA"')

            # Check if this command executes install, ci, add, or install-test
            $cmdText = ""
            for ($k = $i; $k -le [Math]::Min($lines.Count - 1, $i + 15); $k++) {
                $cmdText += " " + $lines[$k].Trim()
                if ($lines[$k] -match ';\s*$') { break }
            }
            $isInstall = ($cmdText -match '(?i)\b(install|ci|add|install-test)\b')
            $hasMockOrOfflineReg = ($contextText -match 'registry\s*=' -or $contextText -match '--registry' -or $contextText -match '127\.0\.0\.1' -or $cmdText -match '--offline')

            $missingComponents = @()
            if (-not $isHelper) {
                if (-not $hasCache) { $missingComponents += "cache (NPM_CONFIG_CACHE)" }
                if (-not $hasPrefix) { $missingComponents += "prefix (NPM_CONFIG_PREFIX)" }
                if (-not $hasUserconfig) { $missingComponents += "userconfig (NPM_CONFIG_USERCONFIG)" }
                if (-not $hasGlobalconfig) { $missingComponents += "globalconfig (NPM_CONFIG_GLOBALCONFIG)" }
                if (-not $hasAppdata) { $missingComponents += "appdata (APPDATA)" }
                if (-not $hasLocalappdata) { $missingComponents += "localappdata (LOCALAPPDATA)" }
                if ($isInstall -and -not $hasMockOrOfflineReg) { $missingComponents += "mock or offline registry (userconfig or --registry/--offline)" }
            }

            if ($missingComponents.Count -gt 0) {
                $offenders += [PSCustomObject]@{
                    File       = $relativePath
                    LineNumber = $i + 1
                    Code       = $line.Trim()
                    Missing    = ($missingComponents -join ", ")
                }
            }
        }
    }
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
