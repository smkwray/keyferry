# Watch for the Caterina (AVR109) bootloader on a Cactus WHID ATmega32U4 and
# restore the application region the instant it enumerates.
#
# The bootloader window is ~8 s, so this polls COM port names (cheap) rather
# than CIM, and only resolves VID/PID when a new port appears. Exactly one
# avrdude invocation is launched; the watcher exits after it.
param(
  [string]$Image   = "hardware/evidence/private/32u4-app-restore.hex",
  [string]$Avrdude = "$env:LOCALAPPDATA\keyferry-tools\avrdude\avrdude.exe",
  [int]$TimeoutSec = 900
)

$ErrorActionPreference = 'Stop'
$image = (Resolve-Path $Image).Path
if (-not (Test-Path $Avrdude)) { throw "avrdude not found: $Avrdude" }

$baseline = [System.IO.Ports.SerialPort]::GetPortNames()
Write-Output "WATCHER LIVE $(Get-Date -f HH:mm:ss) - baseline ports: $($baseline -join ',')"
Write-Output "image: $image"
Write-Output "Do the double reset now. Timeout ${TimeoutSec}s."

$deadline = (Get-Date).AddSeconds($TimeoutSec)
$port = $null
while ((Get-Date) -lt $deadline) {
  $now = [System.IO.Ports.SerialPort]::GetPortNames()
  $new = $now | Where-Object { $baseline -notcontains $_ }
  if ($new) {
    $port = $new[0]
    Write-Output "NEW PORT $port at $(Get-Date -f HH:mm:ss.fff)"
    break
  }
  Start-Sleep -Milliseconds 25
}

if (-not $port) { Write-Output "TIMEOUT: no new COM port appeared."; exit 1 }

# Identify it, but never let identification cost the window.
try {
  $id = (Get-CimInstance Win32_PnPEntity -Filter "Name LIKE '%($port)%'" |
         Select-Object -First 1).PNPDeviceID
  Write-Output "device: $id"
} catch { Write-Output "device: (id lookup failed, proceeding)" }

$avrArgs = @('-v','-p','atmega32u4','-c','avr109','-P',$port,'-b','57600','-D',
          '-U',"flash:w:${image}:i")
Write-Output "RUNNING: avrdude $($avrArgs -join ' ')"
& $Avrdude @avrArgs 2>&1 | ForEach-Object { Write-Output $_ }
Write-Output "avrdude exit: $LASTEXITCODE"
