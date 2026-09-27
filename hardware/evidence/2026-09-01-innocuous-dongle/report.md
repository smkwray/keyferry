# Phase 0 evidence — read-only, preliminary

- Date: 2026-09-01
- Method: read-only observation only. No write, no flash, no bootloader entry, no serial port opened.
  (A 1200-baud open of the CDC port triggers a Caterina bootloader reset, so COM7 was NOT opened.)
- Device label: "innocuous-dongle" (provisional, from the broadcast SSID).

## A. Wi-Fi side (controller host: `netsh wlan show interfaces`)

Unit is powered and running STOCK firmware in access-point mode:

| Field | Value |
| --- | --- |
| SSID | `Innocuous` |
| Band / channel | 2.4 GHz / 6 |
| Radio type | 802.11g |
| Authentication | WPA2-Personal |
| Cipher | CCMP |

2.4 GHz-only b/g is consistent with an ESP8266 radio. The Wi-Fi passphrase is intentionally NOT
recorded (secret). keyferry's own design has NO auto-AP, so this AP is the firmware being replaced.

## B. USB side (Windows PnP enumeration, read-only)

**Measured** (device is attached to this controller host):

| Field | Value |
| --- | --- |
| VID:PID (application mode) | `1B4F:9208` |
| bcdDevice | `REV_0100` |
| USB product string | **`LilyPad USB`** |
| Serial string | `HIDFG` |
| Device class | Composite (`usbccgp`), `DevClass_00` |
| Interface MI_00 | CDC ACM (`Class_02 SubClass_02 Prot_01`) -> **COM7** via `usbser` |
| Interface MI_02 | HID (`Class_03 SubClass_00 Prot_00`), two collections |
| MI_02 Col01 | HID-compliant **mouse** |
| MI_02 Col02 | HID **keyboard** (active in `Win32_Keyboard`) |
| Attached via | hub `05E3:0610`, Port_#0001.Hub_#0005 |

VID `1B4F` is SparkFun; `1B4F:9208` with product string "LilyPad USB" is the ATmega32U4 LilyPad USB
application profile. This **confirms by measurement** the ATmega32U4 assumption and the seed's
provisional `board = LilyPadUSB` PlatformIO target.

**Firmware version (measured, from the device's own web UI at 192.168.1.1, read-only GET):**
`ESPloit v2.7.41` — "WiFi controlled HID Keyboard Emulator". So the running image is ESPloit **v2**
(family: `exploitagency/ESPloitV2`), not v1. Only the landing page was read; no config/payload
controls were touched and no Wi-Fi secret was captured.

**Live exposure while attached:** the stock image presents an operational keyboard AND mouse to this
host. It is an HID-injection-capable device on a working machine.

## E. AVR bootloader (MEASURED, non-destructive)

Entered by a 1200-baud open/close ("touch") on the application CDC port; the ESPloit v2.7.41 firmware
honors it. The bootloader appears for ~8 s, then jumps back to the application on its own with no flash
written. Confirmed twice; the device self-recovered to the application (PID 9208) both times.

| Field | Value |
| --- | --- |
| Bootloader VID:PID | `1B4F:9207` |
| bcdDevice | `REV_0001` |
| BusReportedDeviceDesc | `LilyPadUSB` |
| Enumerates as | CDC serial (`usbser`), a COM port (COM10 this run; number varies) |
| Entry method | 1200-baud touch on the app CDC port |
| Self-recovery window | ~8 s to auto-jump back to the application |
| Application VID:PID | `1B4F:9208` |

This is a standard Caterina / AVR109 CDC bootloader (avrdude `-c avr109 -p atmega32u4 -P <bootloader COM>`).
Entry and self-recovery are proven; NO flash has been read or written yet.

## F. Silicon signature + firmware backup (MEASURED)

Read over the Caterina bootloader with avrdude v7.1 (`-c avr109 -p atmega32u4 -b 57600`).

- **Device signature `0x1E9587` = ATmega32U4** (0x1E Atmel, 0x95 32 KiB flash, 0x87 32U4). This
  CONFIRMS the MCU by direct silicon read, not inference from the USB product string.
- Full non-destructive backup of THIS unit captured (READ only, no write):

| Dump | Size (Intel HEX) | SHA-256 | Location |
| --- | --- | --- | --- |
| 32u4 flash | 92,153 B | `a5a7d7bb83f59342b1285d71668c78842b3ff781103b9ff204615ec8613dc7aa` | `hardware/evidence/private/32u4-flash-backup.hex` (gitignored) |
| 32u4 eeprom | 2,893 B | `aa51d57ffda6661a4d9bc0d825cb303b6f01ff6531c6293772021c3a07f008aa` | `hardware/evidence/private/32u4-eeprom-backup.hex` (gitignored) |

Tool: avrdude 7.1 (mariusgreuel Windows build). Command (bootloader COM number varies per entry):
`avrdude -c avr109 -p atmega32u4 -P <bootloaderCOM> -b 57600 -U flash:r:...:i -U eeprom:r:...:i`.
Device returned to the application (1B4F:9208) after the read.

This is the "known original" restore target for THIS unit (supersedes the upstream reference as the
authoritative 32u4 restore image). The ESP-side image is NOT yet backed up (it sits behind the AVR
and needs the bridge sketch, a write).

## C. Stock personality vs. keyferry v1 target

| Aspect | Stock (measured) | keyferry v1 target |
| --- | --- | --- |
| Interfaces | CDC ACM + HID(mouse+keyboard) | boot keyboard + vendor HID, **no CDC in normal runtime** |
| HID subclass/protocol | `00/00` (report protocol) | **`01/01` boot protocol** (preboot/BIOS support) |
| Mouse | present | **excluded in v1** |
| VID:PID | `1B4F:9208` (SparkFun/LilyPad) | own descriptors, to be selected in Phase 2 |

## D. Inferred, NOT measured (must not enter the board manifest yet)

- ATmega32U4 clock/voltage: the LilyPad USB profile implies 8 MHz / 3.3 V, but this is inferred from
  the product string, not measured on the board.
- Bootloader VID:PID (expected `1B4F:9207`) NOT observed — observing it requires entering the
  bootloader, which is a write-adjacent action and is owner-reserved.
- ESP8266 module marking, flash size, UART pins/baud, reset path: not observable over USB (the ESP
  sits behind the AVR) and not yet inspected.

Also present on the same hub: `USB\VID_0000&PID_0001` "Unknown USB Device (Port Reset Failed)"
(ProblemCode 22, Port_#0004). Not attributed to this dongle; recorded only so it is not confused
with it later.

## Gate status

Phase 0: **OPEN**. Section B is solid measured USB identity; the board manifest still needs the
bootloader route, the ESP-side facts, and two complete recovery demonstrations. Nothing here
authorizes a write.

## G. Recovery toolchain staged (no write performed)

- avrdude 7.1 (mariusgreuel Windows build), device-local.
- arduino-cli 1.5.1 + `arduino:avr` core; board `arduino:avr:LilyPadUSB`.
- Harmless recovery-test image compiled from `harmless-test-image.ino` (this folder): empty sketch,
  3454 B program, CDC-only, NO HID. Compiled `harmless.ino.hex` sha256 prefix `6a7b01a1`.
- Backup restore image: `private/32u4-flash-backup.hex` (sha256 in section F).

Planned recovery demonstration (each step gated on owner-present monitoring; NOT yet run):
1. flash harmless image (write) -> confirm CDC-only, no keyboard/mouse;
2. 1200-baud touch -> bootloader (proves software re-entry from the harmless image);
3. restore `32u4-flash-backup.hex` (write) -> confirm ESPloit HID personality + signature return;
4. repeat once (gate requires two clean cycles);
5. separately: erase to a non-running app, prove bootloader reachable (may need one owner replug),
   then restore. Satisfies "recover from a non-running application state".
