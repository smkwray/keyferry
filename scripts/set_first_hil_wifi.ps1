$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
$buildJobs = [Math]::Max(1, [Math]::Floor([Environment]::ProcessorCount * 0.60))
$ssid = Read-Host 'Wi-Fi SSID'
$securePassword = Read-Host 'Wi-Fi password' -AsSecureString
$passwordPointer = [IntPtr]::Zero
$password = $null
$payload = $null

Push-Location $projectRoot
try {
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    $payload = [ordered]@{
        schema_version = 1
        ssid = $ssid
        password = $password
    } | ConvertTo-Json -Compress

    $payload | cargo run --locked --offline --quiet --jobs $buildJobs -p keyferry-pairing -- set-wifi
    if ($LASTEXITCODE -ne 0) { throw 'Wi-Fi credential storage failed.' }
    cargo run --locked --offline --quiet --jobs $buildJobs -p keyferry-pairing -- validate
    if ($LASTEXITCODE -ne 0) { throw 'Private pairing validation failed.' }
} finally {
    if ($passwordPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
    $password = $null
    $payload = $null
    $securePassword.Dispose()
    Pop-Location
}
