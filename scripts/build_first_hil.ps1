param(
    [ValidatePattern('^build/[A-Za-z0-9._-]+$')]
    [string]$BuildDir = 'build/first-hil',

    [ValidatePattern('^[a-z0-9][a-z0-9_]*$')]
    [string]$BoardProfile = 'waveshare_geek_v1_1_reference',

    [ValidateSet('off', 'security', 'hid')]
    [string]$BleHidSpike = 'off',

    [string]$PrivateHeader = '',

    [switch]$MscSizeProbe,

    [switch]$MscMemoryProbe,

    [switch]$FileHandoff,

    [string]$BaselineDir = '',

    [ValidateRange(0, 256)]
    [int]$Jobs = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
$idfExport = Join-Path $projectRoot '.tools\esp-idf-v6.0.3\export.ps1'
$idfTools = Join-Path $projectRoot '.tools\idf-tools-v6.0.3'
if (-not (Test-Path -LiteralPath $idfExport -PathType Leaf)) {
    throw 'Pinned ESP-IDF v6.0.3 is absent; run the project toolchain setup first.'
}
if (-not (Test-Path -LiteralPath $idfTools -PathType Container)) {
    throw 'Pinned ESP-IDF v6.0.3 tools are absent; run the project toolchain setup first.'
}

Push-Location $projectRoot
try {
    $buildJobCeiling = [Math]::Max(1, [Math]::Floor([Environment]::ProcessorCount * 0.60))
    if ($Jobs -gt $buildJobCeiling) {
        throw "Requested build concurrency $Jobs exceeds the 60% ceiling of $buildJobCeiling jobs."
    }
    $buildJobs = if ($Jobs -eq 0) { $buildJobCeiling } else { $Jobs }
    if ($MscMemoryProbe -and
        ($BaselineDir -notmatch '^build/[A-Za-z0-9._-]+$' -or
         -not (Test-Path -LiteralPath (Join-Path $projectRoot $BaselineDir) -PathType Container))) {
        throw 'MscMemoryProbe requires -BaselineDir build/<name> from a completed matching baseline build.'
    }
    Write-Output "Build concurrency: $buildJobs jobs (60% ceiling: $buildJobCeiling)"
    $sourceEpoch = (git log -1 --format=%ct).Trim()
    if ($sourceEpoch -notmatch '^[0-9]+$') {
        throw 'Could not derive deterministic SOURCE_DATE_EPOCH from Git.'
    }
    $env:SOURCE_DATE_EPOCH = $sourceEpoch
    $env:IDF_PY_BUILD_JOBS = $buildJobs
    $privateHeaderArgument = @()
    if ([string]::IsNullOrWhiteSpace($PrivateHeader)) {
        cargo run --locked --offline --quiet --jobs $buildJobs -p keyferry-pairing -- validate
        if ($LASTEXITCODE -ne 0) { throw 'Private pairing validation failed.' }
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
    $env:IDF_TOOLS_PATH = $idfTools
    . $idfExport | Out-Null
    $mscProbeArg = if ($MscSizeProbe -or $MscMemoryProbe) { 'ON' } else { 'OFF' }
    $mscMemoryArg = if ($MscMemoryProbe) { 'ON' } else { 'OFF' }
    $fileHandoffArg = if ($FileHandoff) { 'ON' } else { 'OFF' }
    idf.py -C firmware/esp32s3/hil_endpoint -B $BuildDir `
        "-DKEYFERRY_BOARD=$BoardProfile" `
        "-DKEYFERRY_BLE_HID_SPIKE=$BleHidSpike" `
        "-DKEYFERRY_MSC_SIZE_PROBE=$mscProbeArg" `
        "-DKEYFERRY_MSC_MEMORY_PROBE=$mscMemoryArg" `
        "-DKEYFERRY_FILE_HANDOFF=$fileHandoffArg" `
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
} finally {
    Pop-Location
}
