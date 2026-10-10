$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
$buildJobs = [Math]::Max(1, [Math]::Floor([Environment]::ProcessorCount * [int](([regex]::Match((Get-Content -LiteralPath (Join-Path $projectRoot 'project.toml') -Raw), '(?m)^cpu_percent\s*=\s*(\d+)')).Groups[1].Value) / 100))
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
