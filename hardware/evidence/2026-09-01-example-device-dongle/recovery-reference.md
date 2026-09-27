# Recovery route — UPSTREAM REFERENCE (unverified), not evidence, not manifest

Purpose: plan the two-way recovery exercise before any write. Everything here is from public
upstream docs for the Cactus WHID / ESPloit family. Per `docs/recovery.md`, NONE of it may enter
an ignored exact-unit manifest until this physical unit confirms it. Cross-checked where possible against
the read-only USB measurement in `report.md`.

## What the measurement already confirms (see report.md section B)

- 32u4 side: composite CDC + HID, product string "LilyPad USB", VID:PID 1B4F:9208 -> AVR is an
  ATmega32U4 on the LilyPad USB profile, Caterina (AVR109) bootloader. CONFIRMED by measurement.

## Upstream reference (Cactus WHID / ESPloit) — TREAT AS HYPOTHESIS

| Fact | Upstream value | Status |
| --- | --- | --- |
| ESP module | ESP-12S | matches our design assumption; not yet visually confirmed on this board |
| ESP flash | 4 MB (`--flash_size 32m`, "4M (3M SPIFFS)") | reference only |
| ESP flash baud (esptool) | 115200 | reference only |
| ESP program path | via the 32u4 as a USB-serial bridge (flash an `esp8266Programmer` sketch to the 32u4 first, then esptool over the CDC port) | reference only — this is the key recovery mechanism |
| 32u4 board / bootloader | "LilyPad Arduino USB", AVR109/Caterina | **MEASURED: bootloader is 1B4F:9207, 1200-baud touch, ~8s window, self-recovering** |
| 32u4 upload baud (avrdude) | 57600 | reference only |
| Config console baud | 38400 (ESPloit serial monitor) | reference only |
| Internal 32u4<->ESP UART baud | NOT stated consistently upstream (wifi-ducky forks vary) | UNKNOWN — must be read from source or measured; DO NOT guess |
| ESP flash-mode strapping (GPIO0) | not documented in these sources | UNKNOWN |
| Firmware version on THIS unit | **ESPloit v2.7.41** | MEASURED via the device web UI (read-only) — it is v2, not v1 |

## Implied recovery sequence (to be proven twice, owner-authorized, before it is trusted)

    AVR Caterina bootloader (avrdude AVR109 @ 57600, board LilyPadUSB)
      -> flash esp8266Programmer bridge sketch to the 32u4       [WRITE — owner-reserved]
      -> esptool over the CDC port: read/verify then write ESP flash (4 MB)   [WRITE]
      -> re-enter AVR Caterina bootloader
      -> restore the 32u4 application                            [WRITE]
      -> confirm prior USB + Wi-Fi behavior

Note: a true backup of THIS unit's current flash requires the bridge sketch (a write) to read the ESP
over the bridge, and the 32u4 application cannot be assumed backed up unless read-protection behavior
proves it (`docs/recovery.md`). Upstream public images are candidate RESTORE targets, not a dump of
this unit.

## Images worth preserving once the version is known (candidate restore targets)

- Confirmed v2.7.41 -> preserve `exploitagency/ESPloitV2` (ESP `ESP_Code` + `Arduino_32u4_code` +
  the `esp8266Programmer` bridge sketch). The repo HEAD may differ slightly from 2.7.41; capture the
  nearest tagged release/source.
- April Brother Cactus WHID factory image, if published.

## Sources

- https://github.com/exploitagency/ESPloitV2
- https://github.com/exploitagency/ESPloitV2/blob/master/README.md
- https://wiki.aprbrother.com/en/cactus_whid.html
- https://github.com/whid-injector/WHID/wiki
