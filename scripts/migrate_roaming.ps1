[CmdletBinding()]
param(
    [string]$Bundle,
    [string]$OwnerKit,
    [string]$PairingExecutable,
    [ValidateSet('Plan', 'Apply')]
    [string]$Mode = 'Plan'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($Bundle)) {
    $Bundle = Join-Path $projectRoot 'secrets\first-hil'
}
if ([string]::IsNullOrWhiteSpace($OwnerKit)) {
    $OwnerKit = Join-Path $projectRoot 'secrets\owner-kit.json'
}
if ([string]::IsNullOrWhiteSpace($PairingExecutable)) {
    $PairingExecutable = Join-Path $projectRoot 'target\release\keyferry-pairing.exe'
}

$resolvedBundle = (Resolve-Path -LiteralPath $Bundle -ErrorAction Stop).Path
$resolvedOwnerKit = (Resolve-Path -LiteralPath $OwnerKit -ErrorAction Stop).Path
$resolvedPairing = (Resolve-Path -LiteralPath $PairingExecutable -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $resolvedBundle -PathType Container)) {
    throw 'The private pairing bundle is not a directory.'
}
if (-not (Test-Path -LiteralPath $resolvedOwnerKit -PathType Leaf)) {
    throw 'The encrypted owner kit is not a regular file.'
}
if (-not (Test-Path -LiteralPath $resolvedPairing -PathType Leaf)) {
    throw 'The pairing helper is not a regular file.'
}

& $resolvedPairing --bundle $resolvedBundle validate | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'The private pairing bundle failed validation.'
}
$helpText = (& $resolvedPairing --help 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0 -or $helpText -notmatch 'migrate-roaming --owner-kit') {
    throw 'The pairing helper does not support the roaming migration.'
}

if ($Mode -eq 'Plan') {
    [pscustomobject]@{
        Operation = 'legacy-to-owner-roaming'
        Bundle = $resolvedBundle
        OwnerKit = $resolvedOwnerKit
        PairingExecutable = $resolvedPairing
        PairingSHA256 = (Get-FileHash -LiteralPath $resolvedPairing -Algorithm SHA256).Hash
        DeviceWrites = 'one journaled policy migration; safe to resume after an unknown outcome'
    }
    exit 0
}

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

$securePassphrase = Read-Host 'Owner-kit passphrase' -AsSecureString
$passphrase = $null
try {
    $passphrase = Convert-SecretToText $securePassphrase
    $byteCount = [Text.Encoding]::UTF8.GetByteCount($passphrase)
    if ($byteCount -eq 0 -or $byteCount -gt 1024 -or
        $passphrase.Contains([char]0) -or $passphrase.Contains("`r") -or
        $passphrase.Contains("`n")) {
        throw 'Owner-kit passphrase must be nonempty, at most 1024 UTF-8 bytes, and contain no line breaks.'
    }

    # The native pipeline supplies the one terminating newline expected by the
    # helper. The secret is never placed in argv, output, or an environment variable.
    $passphrase | & $resolvedPairing --bundle $resolvedBundle migrate-roaming `
        --owner-kit $resolvedOwnerKit
    if ($LASTEXITCODE -ne 0) {
        throw "Roaming migration did not complete (exit code $LASTEXITCODE). Rerun this same command to resume its durable transaction."
    }
} finally {
    $passphrase = $null
    $securePassphrase.Dispose()
}
