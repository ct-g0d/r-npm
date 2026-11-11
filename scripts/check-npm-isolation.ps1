param(
    [switch]$Strict = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=== Scanning for un-isolated npm invocations in tests ===" -ForegroundColor Cyan

$workspaceRoot = $PSScriptRoot | Split-Path -Parent

# Collect test files under crates/**/tests, src/**/tests.rs, crates/**/src/**/tests.rs, and tests/**/*.rs
$candidateFiles = @()

$cratesDir = Join-Path $workspaceRoot "crates"
if (Test-Path $cratesDir) {
    # crates/**/tests/**/*.rs
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

        # Match Command::new("npm"), Command::new("npm.cmd"), Command::new("npx"),
        # Command::new(npm_cmd), or Command::new("cmd.exe") where args contain npm.cmd/npm/npx
        $isNpmInvocation = $false
        if ($line -match 'Command::new\s*\(\s*["''](npm|npm\.cmd|npx)["'']\s*\)') {
            $isNpmInvocation = $true
        } elseif ($line -match 'Command::new\s*\(\s*npm_cmd\s*\)') {
            $isNpmInvocation = $true
        } elseif ($line -match 'Command::new\s*\(\s*["'']cmd(\.exe)?["'']\s*\)') {
            # Check if nearby arguments reference npm / npm.cmd / npx
            $lookaheadRange = [Math]::Min($lines.Count - 1, $i + 15)
            for ($k = $i; $k -le $lookaheadRange; $k++) {
                if ($lines[$k] -match '["''](npm|npm\.cmd|npx)["'']') {
                    $isNpmInvocation = $true
                    break
                }
                if ($lines[$k] -match ';\s*$') { break }
            }
        }

        if ($isNpmInvocation) {
            # Check if this invocation goes through an isolation helper or explicitly sets NPM_CONFIG_CACHE
            # Check 25 lines backward and 25 lines forward for isolation indicators
            $startContext = [Math]::Max(0, $i - 25)
            $endContext = [Math]::Min($lines.Count - 1, $i + 25)
            $contextText = ($lines[$startContext..$endContext]) -join "`n"

            $isIsolated = $false
            if ($contextText -match 'NPM_CONFIG_CACHE') {
                $isIsolated = $true
            } elseif ($contextText -match 'isolated_(cmd|npm|rnpm|process)') {
                $isIsolated = $true
            } elseif ($line -match 'isolated_') {
                $isIsolated = $true
            }

            if (-not $isIsolated) {
                $offenders += [PSCustomObject]@{
                    File       = $relativePath
                    LineNumber = $i + 1
                    Code       = $line.Trim()
                }
            }
        }
    }
}

if ($offenders.Count -gt 0) {
    Write-Host "`nFound $($offenders.Count) un-isolated npm invocation(s):" -ForegroundColor Yellow
    foreach ($item in $offenders) {
        Write-Host "  $($item.File):$($item.LineNumber) -> $($item.Code)" -ForegroundColor Red
    }
    Write-Host "`n[REPORT ONLY] Workspace-level .cargo/config.toml provides safety net; please isolate these test cases." -ForegroundColor Yellow
} else {
    Write-Host "No un-isolated npm invocations found in tests." -ForegroundColor Green
}

if ($Strict -and $offenders.Count -gt 0) {
    Write-Host "`n[FAILED] Un-isolated npm invocations found in strict mode." -ForegroundColor Red
    exit 1
}

exit 0
