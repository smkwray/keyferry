# Run one governed build on a remote Windows builder (D-20261010-07) and bring back its receipt.
# remrun reconciles this checkout, uncommitted edits included, to the same path on the device. The
# build runs over SSH because remrun's runner Job Object forbids the governor's breakaway, so the
# host-wide cap and slots still come from that device's project.toml budget. remrun excludes *.lock,
# so Cargo.lock is copied separately. Every returned file is checked against the remote SHA256.
#   pwsh -NoProfile -File scripts/remote_build.ps1 -Name deploy -Command 'cargo build --locked --profile deploy -p keyctl'
param(
    [ValidatePattern('^[A-Za-z0-9-]+$')]
    [string]$Device = 'example-host',
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Name,
    [ValidatePattern('^[A-Za-z0-9._/-]+$')]
    [string[]]$Fetch = @(),
    # PowerShell command line run on the device under the governor.
    [Parameter(Mandatory)]
    [string]$Command
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$ssh = "example-host@$($Device.ToLowerInvariant())"
$local = Join-Path $root "build/remote/$Device"
function Quote([string]$Text) { "'" + $Text.Replace("'", "''") + "'" }
function Invoke-Remote([string]$Script) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(
        "`$ErrorActionPreference = 'Stop'; Set-Location -LiteralPath $(Quote $root)`n$Script"))
    ssh -o BatchMode=yes $ssh "pwsh -NoProfile -NonInteractive -EncodedCommand $encoded"
}
function Copy-Verified([string]$Relative, [string]$LocalPath, [switch]$Receive) {
    $remotePath = "${ssh}:$((Join-Path $root $Relative).Replace('\', '/'))"
    if ($Receive) { scp -q -o BatchMode=yes $remotePath $LocalPath } else { scp -q -o BatchMode=yes $LocalPath $remotePath }
    if ($LASTEXITCODE) { throw "Transfer failed: $Relative" }
    $remote = "$(Invoke-Remote "(Get-FileHash -LiteralPath $(Quote $Relative)).Hash")".Trim()
    if ($remote -ne (Get-FileHash -LiteralPath $LocalPath).Hash) { throw "SHA256 mismatch after transfer: $Relative" }
    Write-Output "verified $Relative SHA256 $remote"
}

$env:REMRUN_ALLOW_WORKTREE = '1'
& 'C:\sync\malus\remrun\bin\remrun.cmd' run $Device -- python -c pass
if ($LASTEXITCODE) { throw "remrun could not reconcile this checkout to $Device." }
Copy-Verified 'Cargo.lock' (Join-Path $root 'Cargo.lock')

$epoch = if ($env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH } else { "$(git -C $root log -1 --format=%ct)".Trim() }
$receipt = "build/remote/$Name.json"
Invoke-Remote @"
`$env:PATH = "`$HOME\.cargo\bin;`$env:PATH"
`$env:SOURCE_DATE_EPOCH = $(Quote $epoch)
python scripts/build_governor.py --receipt $(Quote $receipt) -- $Command
exit `$LASTEXITCODE
"@
$code = $LASTEXITCODE
New-Item -ItemType Directory -Force -Path $local | Out-Null
Copy-Verified $receipt (Join-Path $local "$Name.json") -Receive
if ($code) { throw "Remote build on $Device failed with exit code $code." }
foreach ($relative in $Fetch) {
    $destination = Join-Path $local $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Verified $relative $destination -Receive
}
