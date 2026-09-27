# ESP32-S3-GEEK Phase 0 recovery report

Status: **CLOSED** on 2026-09-08 for the first owner unit.

The externally identified Waveshare ESP32-S3-GEEK matched the official current model and directly
measured as an ESP32-S3 QFN56 revision v0.2 with 2 MiB embedded PSRAM, 16 MiB 3.3 V quad flash, and
native USB Serial/JTAG. Secure Boot, flash encryption, Secure Download Mode, anti-rollback, and
download/USB/JTAG disabling state were inactive. No HID interface appeared during qualification.

Two complete 16 MiB as-received backups matched byte-for-byte. The single validated partition table
was at `0x8000`. Cycle A wrote and booted the no-HID/no-radio qualification image, then restored and
independently read back the entire owner image exactly. Cycle B erased only the qualifier's proven
4 KiB application-header sector at `0x10000`, observed that no app was bootable, re-entered ROM using
physical BOOT with no application cooperation, and again restored and independently read back the
entire owner image exactly. Before/after/final eFuse inventories matched byte-for-byte.

Factory-image SHA-256: `90A34805D3016396DA4D47B9ADED9888E695D29400FF222C40AA0BF4FC4694B2`.
The raw dump, device identifier, full transcripts, and eFuse inventory remain in ignored private
evidence. The backup was captured after one initial normal factory boot and is therefore the
authoritative as-received recovery baseline, not a pristine manufacturing image.

Recovery qualification does not promote LCD, touch, TF-card, or other optional board peripherals.
It also does not qualify production HID/network firmware or eFuse-backed security changes.
