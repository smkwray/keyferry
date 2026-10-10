param(
    [ValidatePattern('^build/[A-Za-z0-9._-]+$')]
    [string]$BuildDir = '',

    [ValidatePattern('^[a-z0-9][a-z0-9_]*$')]
    [string]$BoardProfile = 'waveshare_geek_v1_1_reference',

    [ValidateSet('off', 'security', 'hid')]
    [string]$BleHidSpike = 'off',

    [string]$PrivateHeader = '',

    [switch]$ResourceOnly,

    [string]$ToolchainRoot = '',

    [switch]$MscSizeProbe,

    [switch]$MscMemoryProbe,

    [switch]$FileHandoff,

    [switch]$PointerExtended,

    [string]$BaselineDir = '',

    [ValidateRange(0, 256)]
    [int]$Jobs = 0,

    [switch]$NoCcache
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Jobs -gt 0) {
    $env:CARGO_BUILD_JOBS = [string]$(if ($env:CARGO_BUILD_JOBS) {
        [Math]::Min([int]$env:CARGO_BUILD_JOBS, $Jobs)
    } else { $Jobs })
}
python (Join-Path $PSScriptRoot 'build_governor.py') --probe
if ($LASTEXITCODE -ne 0) {
    $parameters = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $PSBoundParameters -Compress)))
    python (Join-Path $PSScriptRoot 'build_governor.py') -- pwsh -NoProfile -File (Join-Path $PSScriptRoot 'build_governor.ps1') -Script $PSCommandPath -Parameters $parameters
    exit $LASTEXITCODE
}

$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $BuildDir) { $BuildDir = "build/first-hil-$BoardProfile" }
if ([string]::IsNullOrWhiteSpace($ToolchainRoot)) { $ToolchainRoot = $projectRoot }
$idfExport = Join-Path $ToolchainRoot '.tools\esp-idf-v6.0.3\export.ps1'
$idfTools = Join-Path $ToolchainRoot '.tools\idf-tools-v6.0.3'
if (-not (Test-Path -LiteralPath $idfExport -PathType Leaf)) {
    throw 'Pinned ESP-IDF v6.0.3 is absent; run the project toolchain setup first.'
}
if (-not (Test-Path -LiteralPath $idfTools -PathType Container)) {
    throw 'Pinned ESP-IDF v6.0.3 tools are absent; run the project toolchain setup first.'
}

Push-Location $projectRoot
try {
    $buildJobCeiling = [Math]::Max(1, [Math]::Floor([Environment]::ProcessorCount * [int](([regex]::Match((Get-Content -LiteralPath (Join-Path $projectRoot 'project.toml') -Raw), '(?m)^cpu_percent\s*=\s*(\d+)')).Groups[1].Value) / 100))
    if ($Jobs -gt $buildJobCeiling) {
        throw "Requested build concurrency $Jobs exceeds the project.toml cpu_percent ceiling of $buildJobCeiling jobs."
    }
    $buildJobs = [Math]::Min([int]$env:CARGO_BUILD_JOBS, $(if ($Jobs -eq 0) { $buildJobCeiling } else { $Jobs }))
    if ($MscMemoryProbe -and
        ($BaselineDir -notmatch '^build/[A-Za-z0-9._-]+$' -or
         -not (Test-Path -LiteralPath (Join-Path $projectRoot $BaselineDir) -PathType Container))) {
        throw 'MscMemoryProbe requires -BaselineDir build/<name> from a completed matching baseline build.'
    }
    Write-Output "Build concurrency: $buildJobs jobs (cpu_percent ceiling: $buildJobCeiling)"
    $sourceEpoch = (git log -1 --format=%ct).Trim()
    if ($sourceEpoch -notmatch '^[0-9]+$') {
        throw 'Could not derive deterministic SOURCE_DATE_EPOCH from Git.'
    }
    if (-not $env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH = $sourceEpoch }
    if ($env:SOURCE_DATE_EPOCH -notmatch '^[0-9]+$') { throw 'Invalid SOURCE_DATE_EPOCH.' }
    $env:IDF_PY_BUILD_JOBS = $buildJobs
    $env:CMAKE_BUILD_PARALLEL_LEVEL = $buildJobs
    $privateHeaderArgument = @()
    if ($ResourceOnly) {
        if (-not [string]::IsNullOrWhiteSpace($PrivateHeader)) {
            throw 'ResourceOnly cannot use private credentials.'
        }
    } elseif ([string]::IsNullOrWhiteSpace($PrivateHeader)) {
        $privateConfig = Join-Path $projectRoot "$BuildDir/private-config"
        python scripts/materialize_private_config.py --root $projectRoot --output $privateConfig
        if ($LASTEXITCODE -ne 0) { throw 'Private pairing materialization failed.' }
        $privateHeaderArgument = @("-DKEYFERRY_PRIVATE_HEADER=$privateConfig/keyferry_hil_private.h")
    } else {
        $resolvedPrivateHeader = (Resolve-Path -LiteralPath $PrivateHeader -ErrorAction Stop).Path
        if (-not (Test-Path -LiteralPath $resolvedPrivateHeader -PathType Leaf) -or
            (Split-Path -Leaf $resolvedPrivateHeader) -ne 'keyferry_hil_private.h') {
            throw 'PrivateHeader must name a generated keyferry_hil_private.h file.'
        }
        $privateHeaderSize = (Get-Item -LiteralPath $resolvedPrivateHeader).Length
        if ($privateHeaderSize -lt 1 -or $privateHeaderSize -gt 16384) {
            throw 'PrivateHeader must contain 1 through 16384 bytes.'
        }
        $privateHeaderArgument = @("-DKEYFERRY_PRIVATE_HEADER=$resolvedPrivateHeader")
    }
    $env:CCACHE_DIR = 'C:\tools\keyferry-idf-ccache'
    $env:IDF_CCACHE_ENABLE = if ($NoCcache) { '0' } else { '1' }
    $env:IDF_TOOLS_PATH = $idfTools
    . $idfExport | Out-Null
    if (-not $NoCcache -and -not (Get-Command ccache -ErrorAction SilentlyContinue)) {
        throw 'Pinned ESP-IDF tools do not provide Windows ccache; use -NoCcache explicitly.'
    }
    $mscProbeArg = if ($MscSizeProbe -or $MscMemoryProbe) { 'ON' } else { 'OFF' }
    $mscMemoryArg = if ($MscMemoryProbe) { 'ON' } else { 'OFF' }
    $fileHandoffArg = if ($FileHandoff) { 'ON' } else { 'OFF' }
    $resourceOnlyArg = if ($ResourceOnly) { 'ON' } else { 'OFF' }
    $pointerExtendedArg = if ($PointerExtended -or $BoardProfile -eq 'm5stack_atoms3_lite') { 'ON' } else { 'OFF' }
    $cacheArgument = if ($NoCcache) { '--no-ccache' } else { '--ccache' }
    idf.py $cacheArgument -C firmware/esp32s3/hil_endpoint -B $BuildDir `
        "-DKEYFERRY_BOARD=$BoardProfile" `
        "-DKEYFERRY_RESOURCE_ONLY=$resourceOnlyArg" `
        "-DCMAKE_NINJA_FORCE_RESPONSE_FILE=ON" `
        "-DKEYFERRY_BLE_HID_SPIKE=$BleHidSpike" `
        "-DKEYFERRY_MSC_SIZE_PROBE=$mscProbeArg" `
        "-DKEYFERRY_MSC_MEMORY_PROBE=$mscMemoryArg" `
        "-DKEYFERRY_FILE_HANDOFF=$fileHandoffArg" `
        "-DKEYFERRY_POINTER_EXTENDED=$pointerExtendedArg" `
        @privateHeaderArgument build
    if ($LASTEXITCODE -ne 0) { throw 'First-HIL firmware build failed.' }
    if ($FileHandoff) {
        python scripts/check_msc_size_probe.py --build-dir $BuildDir --file-handoff
        if ($LASTEXITCODE -ne 0) { throw 'USB file firmware build inspection failed.' }
    } elseif ($MscMemoryProbe) {
        python scripts/check_msc_size_probe.py --build-dir $BuildDir --baseline-dir $BaselineDir
        if ($LASTEXITCODE -ne 0) { throw 'MSC memory probe inspection failed.' }
    } elseif ($MscSizeProbe) {
        python scripts/check_msc_size_probe.py --build-dir $BuildDir
        if ($LASTEXITCODE -ne 0) { throw 'MSC size probe inspection failed.' }
    } elseif ($BleHidSpike -eq 'off') {
        python scripts/check_esp_transport.py --build-dir $BuildDir
        if ($LASTEXITCODE -ne 0) { throw 'First-HIL firmware inspection failed.' }
        python scripts/check_ble_hid_spike.py --build-dir $BuildDir --level hid
        if ($LASTEXITCODE -ne 0) { throw 'BLE HID production inspection failed.' }
    } else {
        python scripts/check_ble_hid_spike.py --build-dir $BuildDir --level $BleHidSpike
        if ($LASTEXITCODE -ne 0) { throw 'BLE HID spike inspection failed.' }
    }
    if ($pointerExtendedArg -eq 'ON') {
        python scripts/check_hil_pointer.py --build-dir $BuildDir
        if ($LASTEXITCODE -ne 0) { throw 'Extended pointer inspection failed.' }
    }
} finally {
    Pop-Location
}
