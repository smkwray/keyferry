$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
$null, $buildJobs = [int[]]((python (Join-Path $PSScriptRoot 'build_governor.py') --budget) -split ' ')
if ($LASTEXITCODE -ne 0) { throw 'Build CPU budget is unavailable.' }
$runtimeConfig = Join-Path $projectRoot 'secrets\first-hil\keyferryd\runtime.json'
if (-not (Test-Path -LiteralPath $runtimeConfig -PathType Leaf)) {
    throw 'Private first-HIL runtime configuration is absent.'
}

Push-Location $projectRoot
try {
    cargo run --locked --offline --quiet --jobs $buildJobs -p keyferry-pairing -- validate
    if ($LASTEXITCODE -ne 0) { throw 'Private pairing validation failed.' }
    cargo run --locked --offline --quiet --jobs $buildJobs -p keyferryd -- --first-hil
    if ($LASTEXITCODE -ne 0) { throw 'keyferryd stopped with an error.' }
} finally {
    Pop-Location
}
