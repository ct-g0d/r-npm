$ErrorActionPreference = 'Continue'
$env:RNPM_TIMING_DEBUG = '1'
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$rnpmBin = Join-Path $repoRoot 'target\release\rnpm.exe'
$fixtureDir = Join-Path $repoRoot 'benchmarks\fixtures\project-486'

$testDir = Join-Path $env:TEMP ('warmtar-test-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
$cacheDir = Join-Path $env:TEMP ('warmtar-cache-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
$storeDir = Join-Path $env:TEMP ('warmtar-store-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))

New-Item -ItemType Directory -Path $testDir -Force | Out-Null
Copy-Item (Join-Path $fixtureDir 'package.json') $testDir
Copy-Item (Join-Path $fixtureDir 'package-lock.json') $testDir

# First populate cache
Push-Location $testDir
try {
    $env:RNPM_STORE_DIR = $storeDir
    & $rnpmBin ci --no-audit --no-fund --cache $cacheDir 2>&1 | Out-Null
} finally {
    Pop-Location
}

# Now clear store and node_modules, keep cacheDir
Remove-Item $storeDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $testDir 'node_modules') -Recurse -Force -ErrorAction SilentlyContinue

# Run warm-tar/empty-store with --timing
Push-Location $testDir
try {
    $env:RNPM_STORE_DIR = $storeDir
    & $rnpmBin ci --no-audit --no-fund --cache $cacheDir --timing
} finally {
    Pop-Location
    Remove-Item $testDir, $cacheDir, $storeDir -Recurse -Force -ErrorAction SilentlyContinue
}
