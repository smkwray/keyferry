# Firmware workspace

The active endpoints are ESP32-S3 boards with native USB. Native ESP-IDF v6.0.3 is the pinned
qualification authority; the canonical build is CMake/Ninja through `idf.py`. A required
`KEYFERRY_BOARD` selection loads one strict `boards/<profile>/board.json` manifest and generates the
only C++ view used by firmware. Generic firmware branches on declared controller/capability enums,
never on a vendor or board name.

Current profiles:

| Profile | Display | Qualification |
| --- | --- | --- |
| `waveshare_geek_v1_1_reference` | ST7789, 240×135 | recovery and production qualified on the bound owner unit |
| `lilygo_t_dongle_s3` | ST7735, 160×80 | existing control/input image qualified on the owner unit; USB file capacity unqualified |

The reusable board profile contains wiring, display geometry/orientation, electrical polarity,
flash size, and optional capabilities. Per-unit MAC, factory backup, security state, secrets, and
qualification remain private unit records and never enter a reusable board profile. Runtime pin
autodetection is intentionally absent: a shared ESP32-S3 identity cannot prove board wiring.
Firmware advertising `DISPLAY_ORIENTATION_V1` may persist a per-dongle Normal/180° override. Missing
or malformed override data safely falls back to the board profile's declared `madctl` orientation.

In ordinary `ble-hid` builds, USB has a provisioning-only HID personality (`303A:4005`). It has no
keyboard or mouse interface and cannot emit target input. This lets the desktop repair Wi-Fi and
configuration through the cable while keyboard output remains exclusively Bluetooth. The ordinary
`303A:4004` composite keyboard/provisioning/mouse personality is exclusive to `usb-hid` mode. The
file-handoff build adds read-only MSC to both personalities under separate USB identities below.

## USB file handoff

The opt-in `KEYFERRY_FILE_HANDOFF=ON` build adds one volatile, read-only FAT12 volume named
`KEYFERRY`. The original protocol publishes `MESSAGE.TXT` with `keyctl file DEVICE PATH`.
Firmware advertising the file-set v2 capability also accepts `keyctl files DEVICE PATH...` to
publish 1–16 named files sharing a 256 KiB content limit. Names are 1–64 ASCII bytes using letters,
digits, spaces, dots, underscores and hyphens; leading or trailing spaces and dots, reserved Windows
names, and names that differ only by case are rejected. `keyctl file-status DEVICE` lists the
published contents on v2 firmware, and `keyctl file-clear DEVICE` clears the whole drive. The
desktop's Send page offers **Save as USB file** and, on v2 firmware, **Choose USB files…**.
Publishing replaces the complete set in RAM after withdrawing the previous snapshot. Incomplete,
invalid or digest-mismatched uploads expose no files. Power or controller-session loss clears the
drive. Publishing does not copy files into a target folder or type keys; the target may retain its
own copies after clearing.

File builds allocate only the requested payload length. On the Waveshare GEEK profile, the
payload prefers its optional 2 MiB quad PSRAM when detected; otherwise it uses internal RAM.
The LILYGO profile has no PSRAM path. Both paths require at least 32 KiB of internal heap and
a contiguous inbound TLS-record reserve after allocation. File builds release idle TLS record
buffers between messages without changing their 16 KiB inbound/4 KiB outbound limits or
certificate validation. A file request returns a memory error if these guards cannot be met.

This build uses USB identities `303A:4008` (keyboard/provisioning/mouse/file) and `303A:4009`
(provisioning/file with Bluetooth keyboard output). It requires the separate 2 MiB app layout at
`0x120000`; ordinary app-only updates retain their original 1 MiB limits. Build with
`scripts/build_first_hil.ps1 -FileHandoff -BuildDir build/usb-file -BoardProfile PROFILE`.
The bounded installer `scripts/install_file_firmware.py` requires an exact-unit current backup,
validated package/image and a digest-authorized plan. Never use generated full flash arguments:
the file layout preserves the installed bootloader, original app and pairing/settings in place.
If normal startup changed NVS after the backup, `refresh-config` captures only the current
configuration span twice into an empty private directory with owner-only permissions. Re-plan with
`--current-config DIR`; every other saved-region comparison remains unchanged.
The exact Waveshare owner unit published and read back `MESSAGE.TXT` byte-for-byte at 256 KiB on
Windows with the original protocol. With file-set v2 firmware, the same named Waveshare-to-Windows
path read back all 16 file names and all 256 KiB of content with matching SHA-256 digests. Clearing
removed the old entries; a new two-file set then read back exactly; and a target write attempt was
rejected. LILYGO USB file capacity and Mac/Linux USB mounting remain physically unqualified.

## Qualification image

`esp32s3/` builds `keyferry_qualification`, a UART0 heartbeat mirrored to the S3's
fixed-function USB Serial/JTAG console for enclosure-safe observation. It initializes no USB device
class, TinyUSB/HID, Wi-Fi, Bluetooth, display, touch, removable storage, NVS, PSRAM, secure boot, flash
encryption, anti-rollback, or eFuse mutation path. `scripts/check_qualification.py` enforces those
negative requirements both in source/defaults and, when passed a build directory, in generated
artifacts.

Build preparation is allowed before the board arrives:

```text
idf.py -C firmware/esp32s3 -B build/qualification-waveshare-v1_1 \
  -DKEYFERRY_BOARD=waveshare_geek_v1_1_reference build
python scripts/check_qualification.py --build-dir build/qualification-waveshare-v1_1
```

Generated commands and offsets are for inspection. Flash a board only after its recovery path
(ROM download mode and a full backup) has been proven.

## Offline USB-executor slice

`esp32s3/usb_executor/` is a separate, non-networked production-path slice. It exposes exactly one
boot-keyboard HID interface and uses the shared `kf_hid_core` state machine, which starts disarmed,
requires an accepted all-zero report before arming, rejects stale or overlapping submissions, and
requests release-all after transport loss, disarm, or fault. The image has no command input, so this
slice never arms or emits a nonzero report on its own.

```text
idf.py -C firmware/esp32s3/usb_executor -B build/usb-executor-waveshare-v1_1 \
  -DKEYFERRY_BOARD=waveshare_geek_v1_1_reference build
python scripts/check_usb_executor.py --build-dir build/usb-executor-waveshare-v1_1
```

This image is build evidence, not approval to flash. TinyUSB owns the S3 internal USB PHY, so UART0
is the only configured console for this slice; the device remains operable without opening its
enclosure, but its logs are not observable unless a board exposes UART0 externally.

## Portable boundary

```text
esp32s3/
  main/                 qualification composition only
  boards/<profile>/     pin map, electrical assumptions, optional capabilities
  components/           portable core and narrow adapters
  partitions.csv        qualification-only single factory app
common/                  cross-language protocol codec and host tests
```

Exactly one compile-time board profile is selected. Future security, protocol, persistence, and USB
executor code must not name a vendor, display/touch controller, or GPIO. Optional peripherals use
bounded adapters; none may arm the device, authorize input, or block release-all. Safety and current
report state must remain in internal RAM. The portable `kf_status` component converts fixed runtime
metadata into a bounded semantic presentation without colors, pixels, pins, or an input callback.
The selected board adapter alone maps that presentation onto its display. A false display capability,
initialization failure, transfer failure, or future local page-selection input leaves the headless core
running and cannot reach command or HID authority.

Validate a profile without configuring ESP-IDF:

```text
python scripts/gen_board_profile.py \
  --input firmware/esp32s3/boards/lilygo_t_dongle_s3/board.json
```

Build the same production composition for a selected profile:

```text
powershell -File scripts/build_first_hil.ps1 \
  -BuildDir build/lilygo-hil -BoardProfile lilygo_t_dongle_s3
```

The runner defaults to 60% of logical CPUs. Use `-Jobs N` for a lower-impact build; values above
that ceiling are rejected.

This is build evidence only. A profile whose `qualified` field is false cannot inherit another
unit's recovery or physical acceptance.

## Promotion boundary

The named owner units have their own recovery and production evidence. The qualification image and
offline USB-executor slice do not provide networking; the production HIL endpoint uses authenticated
Wi-Fi and Bluetooth. Any hardware activation remains an owner-visible write: retain the exact
artifact hash, selected board, generated flash plan, and result.

BLE is absent from the qualification image. Secure Boot, flash encryption, anti-rollback, and eFuse
mutation are prohibited during qualification and require separate promotion on an identical
sacrificial revision.

## Legacy Cactus WHID

The obsolete ESP8266, ATmega32U4, and temporary-programmer stubs were removed from the active firmware
surface. Git history remains available; the actual recovery assets and exact conditional procedure
are preserved under `hardware/legacy/cactus-whid/`. Never apply Caterina/AVR109 steps to an ESP32-S3.
