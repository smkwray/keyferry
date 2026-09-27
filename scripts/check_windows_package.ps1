$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'check_windows_package.ps1 must run on Windows.'
}

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $projectRoot
$logicalCpus = [Environment]::ProcessorCount
$buildJobs = [Math]::Max(1, [Math]::Floor($logicalCpus * 0.60))
$env:CARGO_BUILD_JOBS = [string]$buildJobs
Write-Output "build concurrency: $buildJobs jobs (60% of $logicalCpus logical CPUs)"
# Panic locations embed source paths. Map the home, Cargo, and project prefixes (last match wins)
# so no builder's account reaches a release binary; check_public_tree.py rejects any that remain.
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$env:CARGO_ENCODED_RUSTFLAGS = @(
    "--remap-path-prefix=$env:USERPROFILE=~",
    "--remap-path-prefix=$cargoHome=cargo",
    "--remap-path-prefix=$projectRoot=."
) -join [char]0x1f

cargo test --locked --release -p keyferryd
if ($LASTEXITCODE -ne 0) { throw 'Windows daemon tests failed.' }
cargo build --locked --release -p keyferry -p keyferryd -p keyferry-pairing -p keyctl
if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed.' }

$releaseRoot = Join-Path $projectRoot 'target\release'
$controller = Join-Path $releaseRoot 'keyferry.exe'
$daemon = Join-Path $releaseRoot 'keyferryd.exe'
$pairing = Join-Path $releaseRoot 'keyferry-pairing.exe'
$cli = Join-Path $releaseRoot 'keyctl.exe'
foreach ($executable in @($controller, $daemon, $pairing, $cli)) {
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Release executable is missing: $executable"
    }
}

Add-Type -AssemblyName System.Drawing
$sourceIconPath = Join-Path $projectRoot 'apps\keyferry\assets\icons\keyferry.ico'
$embeddedIcon = [Drawing.Icon]::ExtractAssociatedIcon($controller)
if ($null -eq $embeddedIcon) {
    throw 'Windows controller does not contain an application icon.'
}
$embeddedBitmap = $embeddedIcon.ToBitmap()
$extractedIconPath = [IO.Path]::GetTempFileName()
try {
    $embeddedBitmap.Save($extractedIconPath, [Drawing.Imaging.ImageFormat]::Png)
    python scripts\check_windows_icon.py --source $sourceIconPath --extracted $extractedIconPath
    if ($LASTEXITCODE -ne 0) { throw 'Embedded Windows controller icon validation failed.' }
} finally {
    $embeddedBitmap.Dispose()
    $embeddedIcon.Dispose()
    Remove-Item -LiteralPath $extractedIconPath -Force -ErrorAction SilentlyContinue
}

$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$stage = Join-Path $temporaryRoot ('keyferry-windows-package-gate-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    $privateBundle = Join-Path $stage 'pairing-bundle'
    $firmwareRoot = Join-Path $privateBundle 'firmware'
    $recoveryRoot = Join-Path $privateBundle 'recovery'
    New-Item -ItemType Directory -Path $firmwareRoot, $recoveryRoot | Out-Null
    $device = [ordered]@{
        schema_version = 1
        device_id = [Guid]::NewGuid().ToString()
        link_secret_hex = ''
        host_address = '127.0.0.1'
        host_port = 1
        host_certificate_der = ''
        host_spki_der = ''
        host_spki_sha256 = ''
    } | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $firmwareRoot 'device.json'), $device + "`n")
    $recoverySecret = New-Object byte[] 32
    $passphraseBytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($recoverySecret)
        $rng.GetBytes($passphraseBytes)
    } finally {
        $rng.Dispose()
    }
    [IO.File]::WriteAllBytes((Join-Path $recoveryRoot 'secret.bin'), $recoverySecret)

    $passphrase = ([BitConverter]::ToString($passphraseBytes)).Replace('-', '')
    $ownerKit = Join-Path $stage 'owner-kit.json'
    "$passphrase`n$passphrase" | & $pairing --bundle $privateBundle create-owner-kit --output $ownerKit | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic owner-kit creation failed.' }
    $installation = Join-Path $stage 'installation'
    $passphrase | & $pairing issue-installation --owner-kit $ownerKit --output $installation | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic installation issuance failed.' }
    & $pairing validate-installation --input $installation | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic installation validation failed.' }

    $newPassphrase = $passphrase + 'x'
    "$passphrase`n$newPassphrase`n$newPassphrase" |
        & $pairing change-owner-kit-passphrase --owner-kit $ownerKit | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic owner-kit password change failed.' }
    $oldPasswordInstallation = Join-Path $stage 'old-password-installation'
    $oldPasswordExit = $null
    try {
        $ErrorActionPreference = 'Continue'
        $passphrase |
            & $pairing issue-installation --owner-kit $ownerKit --output $oldPasswordInstallation `
                2>$null | Out-Null
        $oldPasswordExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = 'Stop'
    }
    if ($oldPasswordExit -eq 0) { throw 'Old owner-kit password remained valid after change.' }
    $rekeyedInstallation = Join-Path $stage 'rekeyed-installation'
    $newPassphrase |
        & $pairing issue-installation --owner-kit $ownerKit --output $rekeyedInstallation |
        Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Changed owner-kit password could not issue credentials.' }
    & $pairing validate-installation --input $rekeyedInstallation | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Credentials issued after password change are invalid.' }
    if (Test-Path -LiteralPath ([IO.Path]::ChangeExtension($ownerKit, 'rekey.lock'))) {
        throw 'Owner-kit password change left a stale rekey lock.'
    }

    foreach ($privatePath in @($ownerKit, $installation, $rekeyedInstallation)) {
        if (-not (Get-Acl -LiteralPath $privatePath).AreAccessRulesProtected) {
            throw "Private path still inherits access rules: $privatePath"
        }
    }

    $privateIdentifiers = Join-Path $stage 'private-identifiers.txt'
    $privateMarker = [guid]::NewGuid().ToString('D')
    [IO.File]::WriteAllText($privateIdentifiers, "$privateMarker`n")
    $release = Join-Path $stage 'keyferry-windows-x64.zip'
    python scripts\package_controller_release.py `
        --platform windows `
        --controller $controller `
        --daemon $daemon `
        --pairing $pairing `
        --cli $cli `
        --output $release `
        --version 0.0.0-package-gate `
        --private-identifiers $privateIdentifiers
    if ($LASTEXITCODE -ne 0) { throw 'Windows generic controller release creation failed.' }
    python scripts\check_public_tree.py --artifact $release `
        --private-identifiers $privateIdentifiers --require-private-registry
    if ($LASTEXITCODE -ne 0) { throw 'Windows final ZIP privacy scan failed.' }

    & scripts\install_windows_controller.ps1 `
        -ControllerExecutable $controller `
        -DaemonExecutable $daemon `
        -PairingExecutable $pairing `
        -CliExecutable $cli `
        -InstallationDirectory $installation `
        -LanInterface 'Ethernet 2' `
        -Mode Plan | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Windows installer planning failed.' }

    Write-Output 'Windows package gate: ok'
} finally {
    if (Test-Path -LiteralPath $stage) {
        $resolvedStage = (Resolve-Path -LiteralPath $stage).Path
        if ((Split-Path -Parent $resolvedStage) -cne $temporaryRoot -or
            -not (Split-Path -Leaf $resolvedStage).StartsWith('keyferry-windows-package-gate-')) {
            throw 'Refusing to remove an unexpected package-gate directory.'
        }
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}
