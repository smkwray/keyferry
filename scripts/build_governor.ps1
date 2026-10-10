# Re-enter a build script with its exact named parameters, inside the governor's job.
param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][string]$Parameters)
$ErrorActionPreference = 'Stop'
$bound = ConvertFrom-Json -AsHashtable ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Parameters)))
foreach ($key in @($bound.Keys)) {
    if ($bound[$key] -is [System.Collections.IDictionary] -and $bound[$key].Contains('IsPresent')) {
        $bound[$key] = [bool]$bound[$key]['IsPresent']
    }
}
& $Script @bound
if (-not $?) { exit 1 }
