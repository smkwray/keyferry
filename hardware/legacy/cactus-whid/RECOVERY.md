# Legacy Cactus WHID recovery

This runbook preserves the last known recovery path for the owner's original Cactus WHID / ESPloit
v2.7.41 unit. That unit's ATmega32U4 application was left non-working during the Phase 0 exercise.
Recovery was not completed. Keep this material for a future owner-present attempt, but do not apply
any of it to an ESP32-S3 board.

## Preserved inputs

- Measured device and bootloader evidence:
  `hardware/evidence/2026-09-01-innocuous-dongle/report.md`.
- Upstream ESPloit recovery references:
  `hardware/evidence/2026-09-01-innocuous-dongle/recovery-reference.md`.
- Private, gitignored recovery images:
  `hardware/evidence/private/32u4-flash-backup.hex`,
  `32u4-eeprom-backup.hex`, and `32u4-app-restore.hex`.
- Purpose-built helpers: `scripts/whid_restore_watch.ps1`, `scripts/reset_cue.ps1`,
  `scripts/usb_event_log.ps1`, and `scripts/split_flash_image.py`.

Recorded SHA-256 values for the original reads:

| File | SHA-256 |
| --- | --- |
| `32u4-flash-backup.hex` | `a5a7d7bb83f59342b1285d71668c78842b3ff781103b9ff204615ec8613dc7aa` |
| `32u4-eeprom-backup.hex` | `aa51d57ffda6661a4d9bc0d825cb303b6f01ff6531c6293772021c3a07f008aa` |

The application-only restore image is derived from the full flash backup by retaining addresses
below `0x7000`. Never ask Caterina to overwrite its own boot section.

## Last recommended attempt

This is a conditional procedure, not a claim that the unit is recoverable.

1. With USB unplugged, use continuity mode to identify the six-hole P1 ISP header. From the RESET
   end, the upstream order is `RESET, MISO, MOSI, SCK, GND, VCC`. Verify orientation electrically:
   exactly one pad should have continuity to the ESP shield can (GND); VCC is at the far end next to
   GND; RESET is at the opposite end. Do not infer the order from photographs alone.
2. Powered, in DC-voltage mode with black on the verified P1 GND, require VCC `3.0-3.6 V`, RESET at
   least `0.9 * VCC` when idle, RESET no more than `0.1 * VCC` when asserted, and RESET returning high
   when released. Stop if those checks fail.
3. Start `scripts/whid_restore_watch.ps1` with the application-only
   `hardware/evidence/private/32u4-app-restore.hex`. It must launch exactly one avrdude write only
   after a new Caterina serial port appears.
4. Use the DMM in DC-mA mode as the temporary RESET-to-GND bridge. A stable `0.05-0.50 mA` reading
   during both low phases confirms contact. Lift immediately above `1 mA`.
5. Perform exactly one double reset: hold low; release on the first high cue; reassert on the second
   high cue 400 ms later; release and stay clear on the low cue two seconds later. The released gap,
   not the duration of either low phase, must fit Caterina's approximately 750 ms sentinel window.
6. Classify the result and stop: PID `1B4F:9207` plus avrdude exit 0 means recovered; PID present with
   avrdude failure is a transport/image problem; two electrically confirmed low phases with no PID
   is terminal for this no-programmer method.

If the terminal case occurs, do not keep trying magnet, brown-out, or host USB resets. The next tool
that can change the evidence is a verified 3.3 V-capable AVR ISP programmer on P1. The first operation
must be signature and fuse reads, not a write. The expected measured signature is `1E 95 87`; the
previously inferred fuse values must not be trusted until read live.

## Separation from the active project

The current target family uses one ESP32-S3 for networking and native USB. It has a ROM download
mode and an entirely different flash/recovery model. AVR109, Caterina, P1, the 32u4 restore watcher,
and these images are legacy-only.
