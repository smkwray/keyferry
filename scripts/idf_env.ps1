# Dot-source to enter the pinned ESP-IDF v6.0.3 environment in the caller's scope
# (export.ps1 defines idf.py and friends there). Shared by every firmware build script.
param([Parameter(Mandatory)][string]$ToolchainRoot, [switch]$NoCcache)

$idfExport = Join-Path $ToolchainRoot '.tools\esp-idf-v6.0.3\export.ps1'
$idfTools = Join-Path $ToolchainRoot '.tools\idf-tools-v6.0.3'
if (-not (Test-Path -LiteralPath $idfExport -PathType Leaf)) {
    throw 'Pinned ESP-IDF v6.0.3 is absent; run the project toolchain setup first.'
}
if (-not (Test-Path -LiteralPath $idfTools -PathType Container)) {
    throw 'Pinned ESP-IDF v6.0.3 tools are absent; run the project toolchain setup first.'
}
$env:CCACHE_DIR = 'C:\tools\keyferry-idf-ccache'
$env:IDF_CCACHE_ENABLE = if ($NoCcache) { '0' } else { '1' }
$env:IDF_TOOLS_PATH = $idfTools
# export.ps1 selects the environment by the PATH interpreter's version, so put the pinned
# environment's own base interpreter first; a builder's default Python may differ.
$pythonEnvironments = @(Get-ChildItem -LiteralPath (Join-Path $idfTools 'python_env') -Directory)
if ($pythonEnvironments.Count -ne 1) { throw 'Expected exactly one pinned ESP-IDF Python environment.' }
$pythonHome = @(Get-Content -LiteralPath (Join-Path $pythonEnvironments[0].FullName 'pyvenv.cfg') |
    Where-Object { $_ -match '^home\s*=' } | ForEach-Object { ($_ -split '=', 2)[1].Trim() })
if ($pythonHome.Count -ne 1 -or -not (Test-Path -LiteralPath (Join-Path $pythonHome[0] 'python.exe') -PathType Leaf)) {
    throw 'The pinned ESP-IDF Python environment has no installed base interpreter.'
}
$env:PATH = "$($pythonHome[0]);$env:PATH"
. $idfExport | Out-Null
if (-not $NoCcache -and -not (Get-Command ccache -ErrorAction SilentlyContinue)) {
    throw 'Pinned ESP-IDF tools do not provide Windows ccache; use -NoCcache explicitly.'
}
