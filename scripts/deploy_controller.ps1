# Fast program-only deploy of controller programs on this Windows host. Builds only the named
# programs with [profile.deploy] in a worktree-local target dir, runs their crates' tests, then
# reuses the standard installer with existing credentials and LAN/Bluetooth settings.
# Published packages still go through check_windows_package.ps1 and [profile.release].
param(
    [Parameter(Mandatory)]
    [ValidateSet('keyctl', 'keyferryd', 'keyferry', 'keyferry-pairing')]
    [string[]]$Program,
    [switch]$SkipTests,
    [switch]$BuildOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $root 'target' }
python (Join-Path $PSScriptRoot 'build_governor.py') --probe
if ($LASTEXITCODE -ne 0) {
    $buildParameters = @{} + $PSBoundParameters
    $buildParameters['BuildOnly'] = $true
    $parameters = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $buildParameters -Compress)))
    python (Join-Path $PSScriptRoot 'build_governor.py') -- pwsh -NoProfile -File (Join-Path $PSScriptRoot 'build_governor.ps1') -Script $PSCommandPath -Parameters $parameters
    if ($LASTEXITCODE) { throw 'Governed build failed; nothing deployed.' }
    if ($BuildOnly) { return }
} else {
    $toml = Get-Content -LiteralPath (Join-Path $root 'project.toml') -Raw
    $cpuPercent = [int]([regex]::Match($toml, '(?m)^cpu_percent\s*=\s*([0-9]+)').Groups[1].Value)
    $jobs = [Math]::Min([int]$env:CARGO_BUILD_JOBS, [Math]::Max(1, [Math]::Floor([Environment]::ProcessorCount * $cpuPercent / 100)))
    $packages = @($Program | ForEach-Object { '-p'; $_ })

    Push-Location -LiteralPath $root
    try {
        python scripts/check_process_spawns.py
        if ($LASTEXITCODE) { throw 'Process spawning policy failed.' }
        if (-not $SkipTests) {
            cargo test --locked --jobs $jobs @packages
            if ($LASTEXITCODE) { throw 'Tests failed; nothing deployed.' }
        }
        cargo build --locked --profile deploy --jobs $jobs @packages
        if ($LASTEXITCODE) { throw 'Build failed; nothing deployed.' }
    } finally { Pop-Location }
    if ($BuildOnly) { return }
    throw 'Deployment must run outside the build Job Object.'
}

$installed = Join-Path $env:LOCALAPPDATA 'Programs\Keyferry'
$stage = Join-Path 'C:\tools' ('kf-deploy-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
New-Item -ItemType Directory -Path $stage | Out-Null
$files = @{ 'keyferry' = 'keyferry.exe'; 'keyferryd' = 'keyferryd.exe'; 'keyferry-pairing' = 'keyferry-pairing.exe'; 'keyctl' = 'keyctl.exe' }
foreach ($name in $files.Keys) {
    $source = if ($Program -contains $name) { Join-Path $env:CARGO_TARGET_DIR "deploy\$($files[$name])" } else { Join-Path $installed $files[$name] }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage $files[$name])
}

$actions = @((Get-ScheduledTask -TaskName 'Keyferry Desktop' -ErrorAction Stop).Actions)
if ($actions.Count -ne 1) { throw 'Ambiguous installed launch settings.' }
$arguments = $actions[0].Arguments
$lan = @([regex]::Matches($arguments, '--lan-interface "([^"\r\n]+)"') | ForEach-Object { $_.Groups[1].Value })
$bluetooth = [regex]::Match($arguments, '--bluetooth (auto|off)').Groups[1].Value
if ($lan.Count -eq 0 -or -not $bluetooth) { throw 'Cannot preserve installed LAN/Bluetooth settings.' }

$install = @{
    ControllerExecutable = Join-Path $stage 'keyferry.exe'
    DaemonExecutable = Join-Path $stage 'keyferryd.exe'
    PairingExecutable = Join-Path $stage 'keyferry-pairing.exe'
    CliExecutable = Join-Path $stage 'keyctl.exe'
    LanInterface = $lan
    Bluetooth = $bluetooth
    Mode = 'Apply'
}
& (Join-Path $PSScriptRoot 'install_windows_controller.ps1') @install
if (-not $?) { throw 'Install failed; inspect rollback state.' }
Write-Output "Deployed: $($Program -join ', ')"
