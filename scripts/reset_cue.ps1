# Audible cue for the Caterina double-reset. The bootloader's 750 ms external-reset
# window only advances while RESET is released, so exactly one interval matters:
# the gap between LIFT and DROP. Beeps are 400 ms apart, leaving human reaction
# latency (roughly constant) well inside the window.
param([int]$Rounds = 5)
for ($i = 1; $i -le $Rounds; $i++) {
  Write-Output "Round $i/$Rounds - RESET held low (probe on / magnet on). Confirm contact."
  Start-Sleep -Seconds 3
  Write-Output "  ...ready"
  Start-Sleep -Seconds 1
  [Console]::Beep(1400, 60)   # RELEASE (lift probe / magnet)
  Start-Sleep -Milliseconds 340
  [Console]::Beep(1400, 60)   # RE-ASSERT (400 ms after the release cue)
  Write-Output "  released + re-asserted - hold it low"
  Start-Sleep -Seconds 2
  [Console]::Beep(700, 250)   # final release, stay clear
  Write-Output "  release and stay clear"
  Start-Sleep -Seconds 12
}
Write-Output "cue sequence complete"
