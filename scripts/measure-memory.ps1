param(
    [string]$Scenario = "cold"
)

$rnpmBin = 'C:\Users\charl_qez1ct5\.t3\worktrees\npm-rust\lane4-cold-speed\target\release\rnpm.exe'
$fixtureDir = 'C:\Users\charl_qez1ct5\.t3\worktrees\npm-rust\lane4-cold-speed\benchmarks\fixtures\project-486'

$testDir = Join-Path $env:TEMP ('mem-test-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
$cacheDir = Join-Path $env:TEMP ('mem-cache-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
$storeDir = Join-Path $env:TEMP ('mem-store-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))

New-Item -ItemType Directory -Path $testDir -Force | Out-Null
Copy-Item (Join-Path $fixtureDir 'package.json') $testDir
Copy-Item (Join-Path $fixtureDir 'package-lock.json') $testDir

if ($Scenario -eq "warm-tar") {
    # Pre-populate cache
    Push-Location $testDir
    try {
        $env:RNPM_STORE_DIR = $storeDir
        & $rnpmBin ci --no-audit --no-fund --cache $cacheDir 2>&1 | Out-Null
    } finally {
        Pop-Location
    }
    Remove-Item $storeDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $testDir 'node_modules') -Recurse -Force -ErrorAction SilentlyContinue
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $rnpmBin
$psi.Arguments = "ci --no-audit --no-fund --cache `"$cacheDir`""
$psi.WorkingDirectory = $testDir
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.EnvironmentVariables["RNPM_STORE_DIR"] = $storeDir

$proc = [System.Diagnostics.Process]::Start($psi)

$peakWs = 0
$nodePeakWs = 0

while (-not $proc.HasExited) {
    try {
        $ws = $proc.WorkingSet64
        if ($ws -gt $peakWs) { $peakWs = $ws }
    } catch {}
    
    # Also track any child node processes
    try {
        $nodeProcs = Get-Process -Name "node" -ErrorAction SilentlyContinue
        foreach ($np in $nodeProcs) {
            $nws = $np.WorkingSet64
            if ($nws -gt $nodePeakWs) { $nodePeakWs = $nws }
        }
    } catch {}

    Start-Sleep -Milliseconds 10
}

try {
    $ws = $proc.PeakWorkingSet64
    if ($ws -gt $peakWs) { $peakWs = $ws }
} catch {}

Write-Host ("[$Scenario] rnpm Peak Working Set: {0:N1} MB ({1:N2} GB)" -f ($peakWs / 1MB), ($peakWs / 1GB))
Write-Host ("[$Scenario] Node.js Peak Working Set: {0:N1} MB ({1:N2} GB)" -f ($nodePeakWs / 1MB), ($nodePeakWs / 1GB))
Write-Host ("[$Scenario] Combined Peak Working Set: {0:N1} MB ({1:N2} GB)" -f (($peakWs + $nodePeakWs) / 1MB), (($peakWs + $nodePeakWs) / 1GB))

Remove-Item $testDir, $cacheDir, $storeDir -Recurse -Force -ErrorAction SilentlyContinue
