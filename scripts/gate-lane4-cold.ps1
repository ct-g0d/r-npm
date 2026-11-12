param(
    [ValidateRange(1, 100)]
    [int]$Runs = 3,
    [switch]$KeepTemp = $false
)

$ErrorActionPreference = 'Stop'
$gateArgs = @((Join-Path $PSScriptRoot 'gate-lane4-cold.mjs'), '--runs', "$Runs")
if ($KeepTemp) { $gateArgs += '--keep-temp' }
& node @gateArgs
exit $LASTEXITCODE
