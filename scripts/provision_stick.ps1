param(
    [ValidatePattern('^[a-z0-9][a-z0-9_]*$')]
    [string]$BoardProfile = 'm5stack_atoms3_lite',
    [string]$MainRoot = '',
    [string]$Settings = '',
    [switch]$DryRun,
    [switch]$NewDevice,
    [ValidatePattern('^(|COM[1-9][0-9]{0,2})$')]
    [string]$Port = '',
    # Internal adapter; uses the existing program+credential installer, not a
    # second install implementation. The Python state machine invokes it once.
    [string]$ApplyInstallation = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
if (-not $MainRoot) {
    $common = (& git -C $root rev-parse --path-format=absolute --git-common-dir).Trim()
    if ($LASTEXITCODE) { throw 'Cannot locate main checkout.' }
    $MainRoot = Split-Path -Parent $common
}
if (-not $Settings) { $Settings = Join-Path $MainRoot 'hardware/evidence/private/provision-settings.json' }
if ($ApplyInstallation) {
    if ($DryRun) { throw 'DryRun cannot apply an installation.' }
    $config = Get-Content -LiteralPath $Settings -Raw | ConvertFrom-Json
    $package = $config.package_directory
    $task = Get-ScheduledTask -TaskName 'Keyferry Desktop' -ErrorAction Stop
    $actions = @($task.Actions)
    if ($actions.Count -ne 1) { throw 'Ambiguous installed controller settings.' }
    $arguments = $actions[0].Arguments
    $interfaces = @([regex]::Matches($arguments, '--lan-interface "([^"]+)"') |
        ForEach-Object { $_.Groups[1].Value })
    if ($interfaces.Count -eq 0) { throw 'Cannot preserve existing LAN settings.' }
    $bluetoothMatches = [regex]::Matches($arguments, '(?:^|\s)--bluetooth (off|auto)(?:\s|$)')
    if ($bluetoothMatches.Count -ne 1) { throw 'Cannot preserve existing Bluetooth setting.' }
    $install = @{
        ControllerExecutable = Join-Path $package 'keyferry.exe'
        DaemonExecutable = Join-Path $package 'keyferryd.exe'
        PairingExecutable = Join-Path $package 'keyferry-pairing.exe'
        CliExecutable = Join-Path $package 'keyctl.exe'
        InstallationDirectory = $ApplyInstallation
        LanInterface = $interfaces
        Bluetooth = $bluetoothMatches[0].Groups[1].Value
        Mode = 'Apply'
    }
    & "$PSScriptRoot/install_windows_controller.ps1" @install
    if (-not $?) { throw 'Controller Apply failed; inspect rollback state.' }
    Start-Process -FilePath (Join-Path $env:LOCALAPPDATA 'Programs/Keyferry/keyferry.exe')
    exit 0
}
$python = if ($DryRun) { (Get-Command python -ErrorAction Stop).Source } else {
    $environments = @(Get-ChildItem -LiteralPath (Join-Path $MainRoot '.tools/idf-tools-v6.0.3/python_env') -Directory)
    if ($environments.Count -ne 1) { throw 'One pinned IDF Python environment required.' }
    Join-Path $environments[0].FullName 'Scripts/python.exe'
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Pinned Python unavailable.' }
$argsList = @("$PSScriptRoot/provision_stick.py", '--main-root', $MainRoot,
    '--board-profile', $BoardProfile, '--settings', $Settings)
if ($DryRun) { $argsList += '--dry-run' }
if ($NewDevice) { $argsList += '--new-device' }
if ($Port) { $argsList += @('--port', $Port) }
& $python @argsList
exit $LASTEXITCODE
