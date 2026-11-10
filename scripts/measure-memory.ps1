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
if ($env:RNPM_CHANNEL_BOUND) {
    $psi.EnvironmentVariables["RNPM_CHANNEL_BOUND"] = $env:RNPM_CHANNEL_BOUND
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$proc = [System.Diagnostics.Process]::Start($psi)
$rootPid = $proc.Id

$peakRnpm = 0
$peakNode = 0
$peakCombined = 0
$knownNodePids = [System.Collections.Generic.HashSet[int]]::new()

while (-not $proc.HasExited) {
    try {
        $proc.Refresh()
        $rws = $proc.WorkingSet64
        if ($rws -gt $peakRnpm) { $peakRnpm = $rws }
    } catch {
        $rws = 0
    }
    
    # Track child node processes belonging to this rnpm run
    try {
        $nodeProcs = Get-Process -Name "node" -ErrorAction SilentlyContinue
        foreach ($np in $nodeProcs) {
            if ($knownNodePids.Contains($np.Id)) {
                $nws = $np.WorkingSet64
                if ($nws -gt $peakNode) { $peakNode = $nws }
            } else {
                $parent = (Get-CimInstance Win32_Process -Filter "ProcessId = $($np.Id)" -ErrorAction SilentlyContinue).ParentProcessId
                if ($parent -eq $rootPid) {
                    $knownNodePids.Add($np.Id) | Out-Null
                    $nws = $np.WorkingSet64
                    if ($nws -gt $peakNode) { $peakNode = $nws }
                }
            }
        }
    } catch {}

    $currentTree = $rws
    foreach ($npid in $knownNodePids) {
        try {
            $np = Get-Process -Id $npid -ErrorAction SilentlyContinue
            if ($np) {
                $currentTree += $np.WorkingSet64
            }
        } catch {}
    }
    if ($currentTree -gt $peakCombined) {
        $peakCombined = $currentTree
    }

    Start-Sleep -Milliseconds 15
}

$proc.WaitForExit()
$sw.Stop()

Write-Host ("Process exited in {0:N2}s with code {1}" -f $sw.Elapsed.TotalSeconds, $proc.ExitCode)

try {
    $proc.Refresh()
    $ws = $proc.PeakWorkingSet64
    if ($ws -gt $peakRnpm) { $peakRnpm = $ws }
} catch {}

Write-Host ("[$Scenario] rnpm Peak Working Set:     {0:N1} MB ({1:N2} GB)" -f ($peakRnpm / 1MB), ($peakRnpm / 1GB))
Write-Host ("[$Scenario] Node.js Peak Working Set:  {0:N1} MB ({1:N2} GB)" -f ($peakNode / 1MB), ($peakNode / 1GB))
Write-Host ("[$Scenario] Combined Peak Working Set: {0:N1} MB ({1:N2} GB)" -f ($peakCombined / 1MB), ($peakCombined / 1GB))

Remove-Item $testDir, $cacheDir, $storeDir -Recurse -Force -ErrorAction SilentlyContinue
