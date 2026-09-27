[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$InstallationName,

    [string]$Bundle,
    [string]$OwnerKit,

    [ValidatePattern('^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})$')]
    [string]$DeviceId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Bundle)) {
    $Bundle = Join-Path $projectRoot 'secrets\first-hil'
}
if ([string]::IsNullOrWhiteSpace($OwnerKit)) {
    $OwnerKit = Join-Path $projectRoot 'secrets\owner-kit.json'
}
$installationRoot = Join-Path $projectRoot 'secrets\installations'
$installation = Join-Path $installationRoot $InstallationName
$pairing = Join-Path $projectRoot 'target\debug\keyferry-pairing.exe'
$buildJobs = [Math]::Max(1, [Math]::Floor([Environment]::ProcessorCount * 0.60))

function Convert-SecretToText {
    param([Security.SecureString]$Secret)
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
}

function Assert-ValidOwnerPassphrase {
    param([string]$Text)
    $byteCount = [Text.Encoding]::UTF8.GetByteCount($Text)
    if ($byteCount -eq 0 -or $byteCount -gt 1024 -or
        $Text.Contains([char]0) -or $Text.Contains("`r") -or $Text.Contains("`n")) {
        throw 'Owner-kit passphrase must be nonempty, at most 1024 UTF-8 bytes, and contain no line breaks.'
    }
}

function Invoke-PairingWithSecret {
    param(
        [string[]]$Arguments,
        [string[]]$SecretLines
    )
    # PowerShell's native-command pipeline appends one line terminator. Supplying
    # another here would turn a confirmed two-line secret into three lines.
    $inputText = $SecretLines -join "`n"
    try {
        $inputText | & $pairing @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "keyferry-pairing failed with exit code $LASTEXITCODE"
        }
    } finally {
        $inputText = $null
    }
}

if (-not (Test-Path -LiteralPath $Bundle -PathType Container)) {
    throw "Private pairing bundle is absent: $Bundle"
}
if (Test-Path -LiteralPath $installation) {
    throw "Installation credentials already exist: $installation"
}
if ((Test-Path -LiteralPath $OwnerKit -PathType Leaf) -and
    [string]::IsNullOrWhiteSpace($DeviceId)) {
    try {
        $ownerKitSchema = (Get-Content -LiteralPath $OwnerKit -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop).schema_version
    } catch {
        throw 'Owner kit is not readable; no installation was issued.'
    }
    if ($ownerKitSchema -eq 3) {
        throw 'This multi-device owner kit requires -DeviceId with the exact device UUID.'
    }
}

Push-Location $projectRoot
try {
    $env:CARGO_BUILD_JOBS = [string]$buildJobs
    cargo build --locked --offline --jobs $buildJobs -p keyferry-pairing
    if ($LASTEXITCODE -ne 0) { throw 'Could not build keyferry-pairing.' }

    $passphrase = $null
    $passphraseText = $null
    if (-not (Test-Path -LiteralPath $OwnerKit -PathType Leaf)) {
        $first = Read-Host 'Create owner-kit passphrase' -AsSecureString
        $second = Read-Host 'Confirm owner-kit passphrase' -AsSecureString
        $firstText = $null
        $secondText = $null
        try {
            $firstText = Convert-SecretToText $first
            $secondText = Convert-SecretToText $second
            Assert-ValidOwnerPassphrase $firstText
            if ($firstText -cne $secondText) {
                throw 'Owner-kit passphrase confirmation does not match.'
            }
            $createArguments = @('--bundle', $Bundle, 'create-owner-kit', '--output', $OwnerKit)
            Invoke-PairingWithSecret -Arguments $createArguments -SecretLines @($firstText, $secondText)
            $passphraseText = $firstText
        } finally {
            $firstText = $null
            $secondText = $null
            $first.Dispose()
            $second.Dispose()
        }
    } else {
        $passphrase = Read-Host 'Owner-kit passphrase' -AsSecureString
        $passphraseText = Convert-SecretToText $passphrase
        Assert-ValidOwnerPassphrase $passphraseText
    }

    try {
        $issueArguments = @('issue-installation', '--owner-kit', $OwnerKit)
        if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {
            if ($DeviceId.Length -eq 32) {
                $DeviceId = '{0}-{1}-{2}-{3}-{4}' -f $DeviceId.Substring(0, 8), $DeviceId.Substring(8, 4), $DeviceId.Substring(12, 4), $DeviceId.Substring(16, 4), $DeviceId.Substring(20, 12)
            }
            $issueArguments += @('--device', $DeviceId)
        }
        $issueArguments += @('--output', $installation)
        Invoke-PairingWithSecret -Arguments $issueArguments -SecretLines @($passphraseText)
    } finally {
        $passphraseText = $null
        if ($null -ne $passphrase) {
            $passphrase.Dispose()
        }
    }

    & $pairing validate-installation --input $installation
    if ($LASTEXITCODE -ne 0) { throw 'Issued installation failed validation.' }
    Write-Host "Created owner-issued installation credentials: $installation"
} finally {
    Pop-Location
}
