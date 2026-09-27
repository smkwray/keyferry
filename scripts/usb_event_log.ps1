# Passive USB arrival/removal logger. Confirms whether a reset attempt actually
# reached the MCU, without touching the restore path. Never launches avrdude.
param([int]$TimeoutSec = 900)
$ErrorActionPreference = 'Stop'
$snap = { (Get-CimInstance Win32_PnPEntity -Filter "PNPClass='USB' OR PNPClass='Ports'" |
           Select-Object -ExpandProperty PNPDeviceID) }
$prev = & $snap
Write-Output "USB LOG LIVE $(Get-Date -f HH:mm:ss) - $($prev.Count) devices. Try the reset now."
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 150
  $now = & $snap
  foreach ($d in ($now | Where-Object { $prev -notcontains $_ })) {
    Write-Output "$(Get-Date -f HH:mm:ss.fff)  + $d"
  }
  foreach ($d in ($prev | Where-Object { $now -notcontains $_ })) {
    Write-Output "$(Get-Date -f HH:mm:ss.fff)  - $d"
  }
  $prev = $now
}
Write-Output "log ended $(Get-Date -f HH:mm:ss)"
