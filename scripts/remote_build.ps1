# Run one governed build on a remote Windows builder and bring back its receipt.
# remrun reconciles this checkout, uncommitted edits included, to the same path on the device. The
# build runs over SSH because remrun's runner Job Object forbids the governor's breakaway, so the
# host-wide cap and slots still come from that device's project.toml budget. remrun excludes *.lock,
# so the tracked lock files are copied separately. Every returned file is checked against the remote SHA256.
#   pwsh -NoProfile -File scripts/remote_build.ps1 -Device buildhost -SshUser builder -Name deploy -Command 'cargo build --locked --profile deploy -p keyctl'
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9-]+$')]
    [string]$Device,
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$SshUser,
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
$ssh = "$SshUser@$($Device.ToLowerInvariant())"
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
$remrun = (Get-Command remrun -CommandType Application -ErrorAction Stop).Source
& $remrun run $Device -- python -c pass
if ($LASTEXITCODE) { throw "remrun could not reconcile this checkout to $Device." }
# Cargo.lock and the ESP-IDF dependencies.lock files pin the build; without them the device
# resolves newer crates or components and the output diverges.
$locks = @(git -C $root ls-files -- '*.lock')
if (-not $locks -or $locks -notcontains 'Cargo.lock') { throw 'Tracked lock files are missing.' }
foreach ($lock in $locks) { Copy-Verified $lock (Join-Path $root $lock) }

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
