$ErrorActionPreference = "Continue"

$rnpm = (Resolve-Path "target\release\rnpm.exe").Path
$fixtureDir = (Resolve-Path "benchmarks\fixtures\project-486").Path

$env:RNPM_COUNT_HTTP = "1"

function Invoke-IsolatedNpm {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$NpmArgs
    )

    $isoBase = Join-Path $env:TEMP ("npm-iso-" + [System.Guid]::NewGuid().ToString('N'))
    $isoCache = Join-Path $isoBase "cache"
    $isoPrefix = Join-Path $isoBase "prefix"
    $isoUserConfig = Join-Path $isoBase ".npmrc"
    $isoGlobalConfig = Join-Path $isoBase "global.npmrc"
    $isoAppData = Join-Path $isoBase "roaming"
    $isoLocalAppData = Join-Path $isoBase "local"

    New-Item -ItemType Directory -Path $isoCache, $isoPrefix, $isoAppData, $isoLocalAppData -Force | Out-Null
    Set-Content -Path $isoUserConfig -Value "" -Encoding utf8
    Set-Content -Path $isoGlobalConfig -Value "" -Encoding utf8

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

    try {
        $env:NPM_CONFIG_CACHE = $isoCache
        $env:npm_config_cache = $isoCache
        $env:PREFIX = $isoPrefix
        $env:npm_config_prefix = $isoPrefix
        $env:USERCONFIG = $isoUserConfig
        $env:npm_config_userconfig = $isoUserConfig
        $env:GLOBALCONFIG = $isoGlobalConfig
        $env:npm_config_globalconfig = $isoGlobalConfig
        $env:APPDATA = $isoAppData
        $env:LOCALAPPDATA = $isoLocalAppData

        $npmOutput = & npm.cmd @NpmArgs 2>&1
        $script:LastNpmExitCode = $LASTEXITCODE
        return $npmOutput
    } finally {
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

        cmd.exe /c "rd /s /q `"$isoBase`"" 2>$null
    }
}

function Run-Step($name, [string[]]$cmdArgs, $workDir) {
    Write-Host "`n=== Testing: $name ==="
    $logFile = [System.IO.Path]::GetTempFileName()
    Push-Location $workDir
    try {
        & $rnpm @cmdArgs 2>&1 | Out-File -FilePath $logFile -Encoding utf8
    }
    finally {
        Pop-Location
    }
    $lines = Get-Content $logFile
    Remove-Item -Force $logFile -ErrorAction SilentlyContinue

    $httpLines = $lines | Where-Object { $_ -match "^\[http-request" }
    $count = $httpLines.Count
    Write-Host "HTTP Requests: $count"
    foreach ($line in $httpLines) {
        Write-Host "  $line"
    }
    $lastFew = $lines | Select-Object -Last 10
    foreach ($l in $lastFew) {
        Write-Host "  [output] $l"
    }
    return $count
}

# 1. Warm-up run in temp dir to ensure cache is warm
$tmpWarm = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
Copy-Item -Recurse $fixtureDir $tmpWarm
Write-Host "Warming up cache in $tmpWarm..."
Push-Location $tmpWarm
& $rnpm install --no-audit --no-fund
Pop-Location
Remove-Item -Recurse -Force $tmpWarm

# 2. Test in fresh directory with warm cache
$testDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
Copy-Item -Recurse $fixtureDir $testDir

try {
    $cInstall = Run-Step "1. install (warm cache)" @("install", "--no-audit", "--no-fund") $testDir
    $cNoop    = Run-Step "2. no-op install" @("install", "--no-audit", "--no-fund") $testDir
    $cAddPkg  = Run-Step "3. install <pkg> (is-sorted@1.0.2)" @("install", "is-sorted@1.0.2", "--no-audit", "--no-fund") $testDir
    $cUninst  = Run-Step "4. uninstall <pkg> (is-sorted)" @("uninstall", "is-sorted", "--no-audit", "--no-fund") $testDir

    Write-Host "`n=========================================="
    Write-Host "HTTP Request Count Results on project-486"
    Write-Host "=========================================="
    Write-Host "install:               $cInstall"
    Write-Host "no-op install:         $cNoop"
    Write-Host "install <pkg>:         $cAddPkg"
    Write-Host "uninstall:             $cUninst"
    Write-Host "=========================================="
}
finally {
    Remove-Item -Recurse -Force $testDir
}
