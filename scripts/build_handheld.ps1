# Build the AMOLED handheld Board Check image under the build governor.
param(
    [ValidatePattern('^build/[A-Za-z0-9._-]+$')]
    [string]$BuildDir = 'build/handheld-check',

    [ValidateRange(0, 256)]
    [int]$Jobs = 0,

    [switch]$NoCcache,

    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

python (Join-Path $PSScriptRoot 'build_governor.py') --probe
if ($LASTEXITCODE -ne 0) {
    $parameters = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $PSBoundParameters -Compress)))
    python (Join-Path $PSScriptRoot 'build_governor.py') -- pwsh -NoProfile -File (Join-Path $PSScriptRoot 'build_governor.ps1') -Script $PSCommandPath -Parameters $parameters
    exit $LASTEXITCODE
}

$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $cpuPercent, $buildJobCeiling = [int[]]((python (Join-Path $PSScriptRoot 'build_governor.py') --budget) -split ' ')
    if ($LASTEXITCODE -ne 0) { throw 'Build CPU budget is unavailable.' }
    if ($Jobs -gt $buildJobCeiling) {
        throw "Requested build concurrency $Jobs exceeds the cpu_percent $cpuPercent ceiling of $buildJobCeiling jobs."
    }
    $buildJobs = if ($Jobs -eq 0) { $buildJobCeiling } else { $Jobs }
    if (-not $env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH = "$(git log -1 --format=%ct)".Trim() }
    $env:IDF_PY_BUILD_JOBS = $buildJobs
    $env:CMAKE_BUILD_PARALLEL_LEVEL = $buildJobs
    . (Join-Path $PSScriptRoot 'idf_env.ps1') -ToolchainRoot $projectRoot -NoCcache:$NoCcache
    $cacheArgument = if ($NoCcache) { '--no-ccache' } else { '--ccache' }
    idf.py $cacheArgument -C firmware/esp32s3/handheld/check -B $BuildDir `
        "-DCMAKE_NINJA_FORCE_RESPONSE_FILE=ON" "-DKEYFERRY_HANDHELD_SELFTEST=$(if ($SelfTest) { 'ON' } else { 'OFF' })" build
    if ($LASTEXITCODE -ne 0) { throw 'Handheld firmware build failed.' }
} finally {
    Pop-Location
}
