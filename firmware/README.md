# Firmware

The boards are ESP32-S3 boards with native USB. Firmware builds with ESP-IDF v6.0.3 through
`idf.py`, for exactly one board profile under `esp32s3/boards/<profile>/`.

| Profile | Display | Tested |
| --- | --- | --- |
| `waveshare_geek_v1_1_reference` | ST7789, 240×135 | recovery and production firmware on one unit |
| `lilygo_t_dongle_s3` | ST7735, 160×80 | control and USB input on one unit; USB file capacity untested |
| `m5stack_atoms3_lite` | none (RGB LED) | control, USB keyboard and pointer used with Windows targets; full profile not yet tested |
| `waveshare_amoled_1_8` | CO5300 AMOLED, 368×448, touch | handheld shell (`esp32s3/handheld/`); its Keyferry function authenticated over the Bluetooth control link on one unit; full profile not yet tested |

Results on one board do not carry over to another, and a successful build says nothing about how
the firmware behaves on hardware.

## Building

Validate a board profile without ESP-IDF:

```text
python scripts/gen_board_profile.py \
  --input firmware/esp32s3/boards/lilygo_t_dongle_s3/board.json
```

Build the firmware for a profile:

```text
powershell -File scripts/build_first_hil.ps1 \
  -BuildDir build/lilygo -BoardProfile lilygo_t_dongle_s3 \
  -PrivateHeader PATH/keyferry_hil_private.h
```

Each image is built for one board and carries that board's credentials, from the
`keyferry_hil_private.h` that `keyferry-pairing prepare-stick` or `materialize-device-bootstrap`
writes from your owner kit. Keep that header and the build directory private. `-Jobs N` lowers
build concurrency; builds use at most the CPU share set in `project.toml`.

## USB identities

| USB ID | Mode |
| --- | --- |
| `303A:4004` | USB keyboard mode: keyboard, mouse and configuration interface |
| `303A:4005` | Bluetooth keyboard mode: configuration interface only, no keyboard or mouse |
| `303A:4008` | USB keyboard mode with the file drive |
| `303A:4009` | Bluetooth keyboard mode with the file drive |

In Bluetooth keyboard mode the USB cable still lets the desktop app repair Wi-Fi and settings, but
the board cannot type over USB.

## USB file handoff

`-FileHandoff` builds firmware with a read-only USB drive named `KEYFERRY` held in RAM.
`keyctl file DEVICE PATH` publishes `MESSAGE.TXT`. Firmware with multi-file support also accepts
`keyctl files DEVICE PATH...` for 1–16 named files sharing 256 KiB. Names are 1–64 ASCII bytes of
letters, digits, spaces, dots, underscores and hyphens; leading or trailing spaces and dots,
reserved Windows names, and names that differ only by case are rejected. `keyctl file-status
DEVICE` lists what is published, and `keyctl file-clear DEVICE` clears the drive.

Publishing replaces the whole set. An incomplete or invalid upload shows no files, and power or
controller-session loss clears the drive. Publishing does not copy files into a folder on the
target or type them, and the target may keep its own copies after the drive is cleared. A file
request fails with a memory error when the board lacks the memory for it.

File firmware needs a different flash layout, so install it with `scripts/install_file_firmware.py`
(`--help` lists its steps), never with generated full-flash commands. It needs a current full backup
of that board, keeps the installed bootloader, original app and pairing settings in place, and
asks for the plan's digest before writing. USB file handoff is tested on one Waveshare GEEK with a
Windows target; LILYGO file capacity and Mac or Linux drive mounting are not yet tested.

## Flashing safely

Before you flash a board, confirm you can put it into ROM download mode and keep a full backup of
its flash. Keyferry does not use Secure Boot, flash encryption, anti-rollback or eFuse changes.
eFuse changes are permanent; never try them on a board you cannot replace.
