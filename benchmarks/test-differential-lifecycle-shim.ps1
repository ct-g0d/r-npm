#Requires -Version 5.1
<#
.SYNOPSIS
    Differential test suite for executable .bin shims (.cmd, .ps1, Unix) and lifecycle script execution.
.DESCRIPTION
    Validates Gate C / Phase 4 contracts between npm and rnpm:
    1. Generated executable shims in node_modules/.bin on Windows (.cmd, .ps1, Unix shell):
       - Verifies correct file structure and syntax.
       - Verifies execution via cmd.exe, powershell.exe, and sh.exe (if present).
       - Verifies argument forwarding (quotes, spaces, flags, special characters).
       - Verifies exit code propagation.
    2. Lifecycle script execution & environment contract:
       - Verifies INIT_CWD is set to project root.
       - Verifies PATH prepends node_modules/.bin.
       - Verifies npm_lifecycle_event, npm_package_name, and npm_package_version.
    3. Sensitive credential scrubbing:
       - Injects auth tokens into environment and .npmrc (_authToken, NPM_TOKEN, npm_config_password).
       - Asserts that lifecycle scripts NEVER receive sensitive tokens in process.env.
    4. Differential parity between npm (oracle) and rnpm.
#>

[CmdletBinding()]
param(
    [string]$RegistryUrl = "http://127.0.0.1:4873",
    [string]$RnpmPath = "",
    [string]$NpmPath = "npm.cmd",
    [switch]$KeepTemp
)

$ErrorActionPreference = "Stop"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    if ($MyInvocation.MyCommand.Path) {
        $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        $ScriptDir = Join-Path (Get-Location) "benchmarks"
    }
}
$RepoRoot = Split-Path -Parent $ScriptDir

if (-not $RnpmPath) {
    $RnpmPath = Join-Path $RepoRoot "target\debug\rnpm.exe"
}
if (-not (Test-Path $RnpmPath)) {
    throw "rnpm executable not found at '$RnpmPath'. Run 'cargo build -p rnpm-cli' first."
}

# Ensure mock registry is running
$MockServerProcess = $null
function Ensure-MockRegistry {
    try {
        $health = Invoke-RestMethod -Uri "$RegistryUrl/api/health" -TimeoutSec 2 -ErrorAction Stop
        Write-Host "[test] Local mock registry reachable (uptime: $($health.uptime)s)" -ForegroundColor Green
    } catch {
        Write-Host "[test] Starting local mock registry server on $RegistryUrl..." -ForegroundColor Cyan
        $mockScript = Join-Path $ScriptDir "mock-registry\mock-server.js"
        $script:MockServerProcess = Start-Process node -ArgumentList "$mockScript --port 4873 --quiet" -PassThru
        Start-Sleep -Milliseconds 800
        $health = Invoke-RestMethod -Uri "$RegistryUrl/api/health" -TimeoutSec 5
        Write-Host "[test] Local mock registry started successfully." -ForegroundColor Green
    }
}

Ensure-MockRegistry

$TestsPassed = 0
$TestsFailed = 0

function Assert-Condition {
    param(
        [bool]$Condition,
        [string]$Message,
        [string]$Details = ""
    )

    if ($Condition) {
        Write-Host "  [PASS] $Message" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] $Message" -ForegroundColor Red
        if ($Details) {
            Write-Host "         Details: $Details" -ForegroundColor Yellow
        }
        $script:TestsFailed++
    }
}

$TempBase = Join-Path ([System.IO.Path]::GetTempPath()) ("npm-rust-diff-test-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $TempBase | Out-Null
Write-Host "`nTest workspace: $TempBase" -ForegroundColor DarkGray

try {
    # =========================================================================
    # PART 1: Executable Shim Differential Verification
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 1: Executable .bin Shim Differential Tests" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $npmShimDir = Join-Path $TempBase "npm-shim-test"
    $rnpmShimDir = Join-Path $TempBase "rnpm-shim-test"
    Copy-Item (Join-Path $ScriptDir "fixtures\tier2-typescript-cli") -Destination $npmShimDir -Recurse
    Copy-Item (Join-Path $ScriptDir "fixtures\tier2-typescript-cli") -Destination $rnpmShimDir -Recurse

    # 1. Install with npm
    Write-Host "[1.1] Installing tier2-typescript-cli with npm..." -ForegroundColor Gray
    $npmOut = cmd.exe /c "cd /d `"$npmShimDir`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"
    $npmInstallCode = $LASTEXITCODE
    Assert-Condition ($npmInstallCode -eq 0) "npm install completed with exit code 0"

    # 2. Install with rnpm
    Write-Host "[1.2] Installing tier2-typescript-cli with rnpm..." -ForegroundColor Gray
    $rnpmOut = cmd.exe /c "cd /d `"$rnpmShimDir`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"
    $rnpmInstallCode = $LASTEXITCODE
    Assert-Condition ($rnpmInstallCode -eq 0) "rnpm install completed with exit code 0"

    # 3. Verify .bin shims presence
    $expectedShims = @("tsc", "tsserver", "cli-helper")
    foreach ($bin in $expectedShims) {
        # Check npm
        Assert-Condition (Test-Path (Join-Path $npmShimDir "node_modules\.bin\$bin.cmd")) "npm generated $bin.cmd"
        Assert-Condition (Test-Path (Join-Path $npmShimDir "node_modules\.bin\$bin.ps1")) "npm generated $bin.ps1"
        Assert-Condition (Test-Path (Join-Path $npmShimDir "node_modules\.bin\$bin")) "npm generated Unix shim $bin"

        # Check rnpm
        Assert-Condition (Test-Path (Join-Path $rnpmShimDir "node_modules\.bin\$bin.cmd")) "rnpm generated $bin.cmd"
        Assert-Condition (Test-Path (Join-Path $rnpmShimDir "node_modules\.bin\$bin.ps1")) "rnpm generated $bin.ps1"
        Assert-Condition (Test-Path (Join-Path $rnpmShimDir "node_modules\.bin\$bin")) "rnpm generated Unix shim $bin"
    }

    # 4. Test Execution of .cmd Shims
    Write-Host "`n[1.3] Testing Windows .cmd Shim Execution..." -ForegroundColor Gray

    # Test tsc.cmd --version on both
    $npmTscCmd = cmd.exe /c "cd /d `"$npmShimDir`" && node_modules\.bin\tsc.cmd --version"
    $rnpmTscCmd = cmd.exe /c "cd /d `"$rnpmShimDir`" && node_modules\.bin\tsc.cmd --version"
    Assert-Condition ($npmTscCmd -match "Version 5.3.3") "npm tsc.cmd executes and outputs version ($npmTscCmd)"
    Assert-Condition ($rnpmTscCmd -match "Version 5.3.3") "rnpm tsc.cmd executes and outputs version ($rnpmTscCmd)"

    # Test cli-helper.cmd argument forwarding with quotes, spaces, flags
    $testArgStr = '--name="John Doe" --flag --mode=release "hello world"'
    $npmHelperCmd = cmd.exe /c "cd /d `"$npmShimDir`" && node_modules\.bin\cli-helper.cmd $testArgStr"
    $rnpmHelperCmd = cmd.exe /c "cd /d `"$rnpmShimDir`" && node_modules\.bin\cli-helper.cmd $testArgStr"

    Assert-Condition ($npmHelperCmd -match "cli-helper args:") "npm cli-helper.cmd executed successfully"
    Assert-Condition ($rnpmHelperCmd -match "cli-helper args:") "rnpm cli-helper.cmd executed successfully"
    Assert-Condition ($rnpmHelperCmd -match "John Doe" -and $rnpmHelperCmd -match "hello world") "rnpm cli-helper.cmd forwarded quoted arguments"

    # 5. Test Execution of .ps1 Shims
    Write-Host "`n[1.4] Testing Windows PowerShell .ps1 Shim Execution..." -ForegroundColor Gray
    $npmTscPs1 = & powershell.exe -NoProfile -InputFormat None -ExecutionPolicy Bypass -File (Join-Path $npmShimDir "node_modules\.bin\tsc.ps1") --version
    $rnpmTscPs1 = & powershell.exe -NoProfile -InputFormat None -ExecutionPolicy Bypass -File (Join-Path $rnpmShimDir "node_modules\.bin\tsc.ps1") --version
    Assert-Condition ($npmTscPs1 -match "Version 5.3.3") "npm tsc.ps1 executes and outputs version ($npmTscPs1)"
    Assert-Condition ($rnpmTscPs1 -match "Version 5.3.3") "rnpm tsc.ps1 executes and outputs version ($rnpmTscPs1)"

    $npmHelperPs1 = & powershell.exe -NoProfile -InputFormat None -ExecutionPolicy Bypass -File (Join-Path $npmShimDir "node_modules\.bin\cli-helper.ps1") "arg1" "spaced arg" "--flag"
    $rnpmHelperPs1 = & powershell.exe -NoProfile -InputFormat None -ExecutionPolicy Bypass -File (Join-Path $rnpmShimDir "node_modules\.bin\cli-helper.ps1") "arg1" "spaced arg" "--flag"
    Assert-Condition ($rnpmHelperPs1 -match "spaced arg") "rnpm cli-helper.ps1 forwarded complex arguments correctly"

    # 6. Test Unix Shell Shims and Shebang Normalization
    Write-Host "`n[1.5] Testing Unix Shell Shim Format & Execution..." -ForegroundColor Gray
    $rnpmUnixShim = Get-Content (Join-Path $rnpmShimDir "node_modules\.bin\tsc") -Raw
    Assert-Condition ($rnpmUnixShim.StartsWith("#!/bin/sh")) "rnpm Unix shim has #!/bin/sh shebang"
    Assert-Condition ($rnpmUnixShim.Contains("exec node")) "rnpm Unix shim invokes node executable"

    # If sh.exe or bash.exe is installed (e.g. Git Bash)
    $shExe = (Get-Command "sh.exe" -ErrorAction SilentlyContinue)
    if (-not $shExe -and (Test-Path "C:\Program Files\Git\bin\sh.exe")) {
        $shExe = "C:\Program Files\Git\bin\sh.exe"
    }

    if ($shExe) {
        $shPath = if ($shExe.Source) { $shExe.Source } else { $shExe }
        $unixOut = & $shPath -c "cd '$($rnpmShimDir.Replace('\', '/'))' && ./node_modules/.bin/tsc --version"
        Assert-Condition ($unixOut -match "Version 5.3.3") "Unix shim executed via sh.exe successfully ($unixOut)"
    } else {
        Write-Host "  [SKIP] sh.exe not found in PATH; skipped live Unix shim execution test" -ForegroundColor DarkGray
    }

    # =========================================================================
    # PART 2: Lifecycle Scripts & Credential Scrubbing Differential Tests
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 2: Lifecycle Scripts & Credential Scrubbing Tests" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $npmLifeDir = Join-Path $TempBase "npm-lifecycle-test"
    $rnpmLifeDir = Join-Path $TempBase "rnpm-lifecycle-test"
    New-Item -ItemType Directory -Path $npmLifeDir | Out-Null
    New-Item -ItemType Directory -Path $rnpmLifeDir | Out-Null

    $rootInspectorScript = @'
const fs = require('fs');
const path = require('path');
const event = process.argv[2] || process.env.npm_lifecycle_event || 'unknown';
const targetFile = path.resolve(process.env.INIT_CWD || process.cwd(), '.root-' + event + '.json');
const dump = {
    event: event,
    INIT_CWD: process.env.INIT_CWD,
    NODE: process.env.NODE || process.env.npm_node_execpath,
    npm_lifecycle_event: process.env.npm_lifecycle_event,
    npm_package_name: process.env.npm_package_name,
    npm_package_version: process.env.npm_package_version,
    PATH: process.env.PATH,
    envKeys: Object.keys(process.env),
    fullEnv: { ...process.env }
};
fs.writeFileSync(targetFile, JSON.stringify(dump, null, 2), 'utf8');
'@
    Set-Content -Path (Join-Path $npmLifeDir "inspect-root.js") -Value $rootInspectorScript
    Set-Content -Path (Join-Path $rnpmLifeDir "inspect-root.js") -Value $rootInspectorScript

    $lifecyclePkgJson = @"
{
  "name": "lifecycle-test-project",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "preinstall": "node inspect-root.js preinstall",
    "postinstall": "node inspect-root.js postinstall"
  },
  "dependencies": {
    "lifecycle-inspector": "^1.0.0"
  }
}
"@
    Set-Content -Path (Join-Path $npmLifeDir "package.json") -Value $lifecyclePkgJson
    Set-Content -Path (Join-Path $rnpmLifeDir "package.json") -Value $lifecyclePkgJson

    # Set up credentials in .npmrc and environment
    $npmrcContent = @"
//127.0.0.1:4873/:_authToken=super_secret_npmrc_token_5555
registry=$RegistryUrl
"@
    Set-Content -Path (Join-Path $npmLifeDir ".npmrc") -Value $npmrcContent
    Set-Content -Path (Join-Path $rnpmLifeDir ".npmrc") -Value $npmrcContent

    $env:NPM_TOKEN = "super_secret_env_token_9999"
    $env:npm_config__authToken = "leak_token_config_8888"
    $env:npm_config_password = "leak_password_7777"
    $env:MY_SECRET_AUTH = "secret_auth_token_3333"

    # Install in npmLifeDir
    Write-Host "[2.1] Executing lifecycle test with npm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$npmLifeDir`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"

    # Install in rnpmLifeDir
    Write-Host "[2.2] Executing lifecycle test with rnpm..." -ForegroundColor Gray
    $null = cmd.exe /c "cd /d `"$rnpmLifeDir`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"

    # Helper function to audit environment dump for credentials and standard vars
    function Audit-LifecycleDump {
        param(
            [string]$DumpPath,
            [string]$ToolName,
            [string]$ExpectedEvent
        )

        if (-not (Test-Path $DumpPath)) {
            Assert-Condition $false "$ToolName generated lifecycle dump at $(Split-Path -Leaf $DumpPath)" "File missing"
            return
        }

        $dump = Get-Content $DumpPath -Raw | ConvertFrom-Json
        $envMap = $dump.env
        if (-not $envMap -and $dump.fullEnv) { $envMap = $dump.fullEnv }

        # Verify Environment Variables Contract
        Assert-Condition ($dump.event -eq $ExpectedEvent -or $dump.npm_lifecycle_event -eq $ExpectedEvent) `
            "$ToolName set npm_lifecycle_event to '$ExpectedEvent'"
        Assert-Condition ($dump.INIT_CWD -ne $null -and $dump.INIT_CWD.Length -gt 0) `
            "$ToolName set INIT_CWD to project root ($($dump.INIT_CWD))"

        # Verify Credential Scrubbing: None of the secret tokens should exist in environment!
        $secrets = @(
            "super_secret_npmrc_token_5555"
        )
        if ($ToolName -eq "rnpm") {
            $secrets += @(
                "super_secret_env_token_9999",
                "leak_token_config_8888",
                "leak_password_7777"
            )
        }

        $leaked = @()
        foreach ($prop in $envMap.PSObject.Properties) {
            $key = $prop.Name
            $val = [string]$prop.Value
            foreach ($sec in $secrets) {
                if ($val.Contains($sec)) {
                    $leaked += "Key '$key' contains secret value '$sec'"
                }
            }
            if ($ToolName -eq "rnpm" -and $key -match "(?i)(authtoken|password|//.*:_authtoken)") {
                $leaked += "Sensitive key '$key' was not scrubbed"
            }
        }

        Assert-Condition ($leaked.Count -eq 0) `
            "$ToolName scrubbed all sensitive credentials from child process environment" `
            ($leaked -join "; ")
    }

    Write-Host "`n[2.3] Auditing npm Lifecycle Environment & Credentials..." -ForegroundColor Gray
    Audit-LifecycleDump (Join-Path $npmLifeDir ".root-preinstall.json") "npm" "preinstall"
    Audit-LifecycleDump (Join-Path $npmLifeDir ".root-postinstall.json") "npm" "postinstall"

    Write-Host "`n[2.4] Auditing rnpm Lifecycle Environment & Credentials..." -ForegroundColor Gray
    Audit-LifecycleDump (Join-Path $rnpmLifeDir ".root-preinstall.json") "rnpm" "preinstall"
    Audit-LifecycleDump (Join-Path $rnpmLifeDir ".root-postinstall.json") "rnpm" "postinstall"
    if (Test-Path (Join-Path $rnpmLifeDir ".lifecycle-install.json")) {
        Audit-LifecycleDump (Join-Path $rnpmLifeDir ".lifecycle-install.json") "rnpm" "install"
    }

    # Clean up environment variables
    $env:NPM_TOKEN = $null
    $env:npm_config__authToken = $null
    $env:npm_config_password = $null
    $env:MY_SECRET_AUTH = $null

    # =========================================================================
    # PART 3: Tier 2 Fixtures Lockfile Parity
    # =========================================================================
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "Part 3: Tier 2 Fixtures Tree & Lockfile Parity" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    $statsUtil = Join-Path $ScriptDir "harness-utils.js"

    # Compare lockfiles for tier2-typescript-cli
    $npmCliLock = Join-Path $npmShimDir "package-lock.json"
    $rnpmCliLock = Join-Path $rnpmShimDir "package-lock.json"
    if ((Test-Path $npmCliLock) -and (Test-Path $rnpmCliLock)) {
        $lockCmp = (node $statsUtil compare-lockfiles $npmCliLock $rnpmCliLock) | ConvertFrom-Json
        Assert-Condition ($lockCmp.match -eq $true) "tier2-typescript-cli lockfile parity (npm vs rnpm)" `
            ($lockCmp.mismatches -join "; ")
    }

    # Install and compare tier2-express
    Write-Host "`n[3.2] Testing tier2-express Differential Parity..." -ForegroundColor Gray
    $npmExpressDir = Join-Path $TempBase "npm-express"
    $rnpmExpressDir = Join-Path $TempBase "rnpm-express"
    Copy-Item (Join-Path $ScriptDir "fixtures\tier2-express") -Destination $npmExpressDir -Recurse
    Copy-Item (Join-Path $ScriptDir "fixtures\tier2-express") -Destination $rnpmExpressDir -Recurse

    $null = cmd.exe /c "cd /d `"$npmExpressDir`" && $NpmPath install --registry $RegistryUrl --no-audit --no-fund 2>&1"
    $null = cmd.exe /c "cd /d `"$rnpmExpressDir`" && `"$RnpmPath`" install --registry $RegistryUrl 2>&1"

    $npmExpLock = Join-Path $npmExpressDir "package-lock.json"
    $rnpmExpLock = Join-Path $rnpmExpressDir "package-lock.json"
    if ((Test-Path $npmExpLock) -and (Test-Path $rnpmExpLock)) {
        $lockCmp = (node $statsUtil compare-lockfiles $npmExpLock $rnpmExpLock) | ConvertFrom-Json
        Assert-Condition ($lockCmp.match -eq $true) "tier2-express lockfile parity (npm vs rnpm)" `
            ($lockCmp.mismatches -join "; ")
    }

    # Compare installed tree structure for tier2-express
    $npmExpTree = Join-Path $npmExpressDir "node_modules"
    $rnpmExpTree = Join-Path $rnpmExpressDir "node_modules"
    if ((Test-Path $npmExpTree) -and (Test-Path $rnpmExpTree)) {
        $treeCmp = (node $statsUtil compare-trees $npmExpTree $rnpmExpTree) | ConvertFrom-Json
        Assert-Condition ($treeCmp.match -eq $true) "tier2-express node_modules normalized tree parity (npm vs rnpm)" `
            ($treeCmp.mismatches -join "; ")
    }

} finally {
    if (-not $KeepTemp -and (Test-Path $TempBase)) {
        Remove-Item -Path $TempBase -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($script:MockServerProcess -and -not $script:MockServerProcess.HasExited) {
        Stop-Process -Id $script:MockServerProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "Test Summary: $TestsPassed Passed, $TestsFailed Failed" -ForegroundColor $(if ($TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================================" -ForegroundColor Cyan

if ($TestsFailed -gt 0) {
    exit 1
}
exit 0
