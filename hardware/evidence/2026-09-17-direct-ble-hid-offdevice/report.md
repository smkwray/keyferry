# Direct BLE keyboard off-device gate

Date: 2026-09-17

Producer commit: `58e6dc840a13dcfb20ac84e0b89c8400bb9ce88d`

ESP-IDF: project-pinned 6.0.3

## Scope

This gate covers the production direct-BLE-keyboard implementation and its host control plane. It
does not claim a hardware write, pairing success, target keystroke delivery, bond persistence, or a
live-memory measurement.

The implementation provides mutually exclusive USB and BLE keyboard output, persisted mode
selection through the authenticated daemon, CLI and desktop controls, an exact BLE-specific result
contract, and a one-boot USB recovery gesture. When BLE output is stored, tapping BOOT during the
first three seconds selects USB output for that boot without changing the stored choice. Holding
BOOT across power-on remains the ESP32-S3 ROM downloader gesture.

## Verification

The full strict project check passed before the final mechanical result-helper refactor except for
the clippy finding that prompted that refactor. Afterward, the affected suites and clippy were
rerun. The first combined test invocation exposed one incorrect new UI source assertion; that
assertion was corrected and its binary suite then passed:

```text
cargo test -p keyctl -p keyferry -p keyferryd --locked --offline
  keyctl: 10 passed; 2 Windows console signal tests ignored by their focused gate
  keyferry library: 51 passed
  initial keyferry binary run: 35 passed, 1 incorrect assertion failed

cargo test -p keyferry --bin keyferry --locked --offline
  keyferry binary after correcting the assertion: 36 passed

cargo test -p keyferryd --locked --offline
  keyferryd library: 124 passed
  keyferryd binary: 9 passed

cargo clippy -p keyctl -p keyferry -p keyferryd --all-targets --locked --offline -- -D warnings
  passed

cargo fmt --all -- --check
  passed
```

The strict native C++ test driver passed, including `kf_output_mode`, before the committed rebuild.
Both exact committed-source board builds passed their transport and BLE-HID checkers:

```text
pwsh -NoProfile -File scripts/build_first_hil.ps1 \
  -BoardProfile lilygo_t_dongle_s3 \
  -BuildDir build/ble-hid-output-lilygo \
  -BleHidSpike off

pwsh -NoProfile -File scripts/build_first_hil.ps1 \
  -BoardProfile waveshare_geek_v1_1_reference \
  -BuildDir build/ble-hid-output-waveshare \
  -BleHidSpike off
```

## Exact images

| Board | Binary bytes | SHA-256 | Raw app free | Margin beyond retained 32 KiB reserve |
| --- | ---: | --- | ---: | ---: |
| LILYGO T-Dongle-S3 | 994,384 | `d6a716410bfa3cd8dd9fb1eceeb3825627d0c1414ec941ff3f638f5590c275eb` | 54,192 | 21,424 |
| Waveshare ESP32-GEEK | 994,304 | `5dc0e97aae6aeaecf1b25195758d378ad3781c5643009ab67a7e447fa3448e49` | 54,272 | 21,504 |

## Gate disposition

| Gate | Result |
| --- | --- |
| Production firmware compilation, both board profiles | PASS |
| 32 KiB application reserve | PASS |
| Host API, CLI, desktop mode selection | PASS, off-device |
| Strict mode/status wire correlation | PASS, off-device |
| BLE result does not falsely claim USB terminal-zero evidence | PASS, off-device |
| One-boot USB recovery selection | PASS, native logic test and target compilation |
| Hardware write | NOT RUN |
| BLE pairing and keyboard reports on Windows/macOS | OPEN |
| Bond persistence and one-peer admission | OPEN |
| Added live-memory high-water gate | OPEN |

The next bounded step is one separately authorized app-image write to the currently attached board,
then pairing and a short KeyTest sequence. No bootloader, partition table, NVS, configuration, or
eFuse write is needed for that qualification step.
