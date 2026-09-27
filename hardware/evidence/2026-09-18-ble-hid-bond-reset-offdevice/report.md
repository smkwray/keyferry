# BLE HID bond reset off-device evidence

Date: 2026-09-18

## Scope

This report covers the authenticated host-to-device operation that forgets only the stored
Bluetooth HID target bond and restarts the endpoint in pairing mode, plus the exact Waveshare
application update, capability observation, one intentional physical bond reset, and the immediate
fresh macOS recovery pairing.

## Contract and safety properties

- `BLE_HID_BOND_RESET_V1` explicitly gates the API, CLI, desktop control, wire request, and
  firmware implementation.
- The endpoint accepts the empty reset request only while BLE-HID output is active, the command
  executor is idle and disarmed, keyboard state is zero, and no release is in flight.
- The firmware disconnects the current HID central and deletes only its NimBLE peer security and
  CCCD records with `ble_store_util_delete_peer`. It does not erase Wi-Fi, ownership, recovery,
  output-mode, or other NVS data.
- The response is sequence-correlated and distinguishes no stored bond, a forgotten bond, and
  failure. A successful response schedules a restart. The host never automatically retries an
  unconfirmed reset.
- The desktop requires a separate visible confirmation and states the exact preserved data.

## Verification

The following completed successfully on Windows with build concurrency limited to 12 jobs, 60% of
the 20 logical processors:

```text
python scripts/check.py --strict
pwsh -NoProfile -File scripts/build_first_hil.ps1 -BoardProfile waveshare_geek_v1_1_reference -BuildDir build/bond-reset-waveshare -BleHidSpike off
pwsh -NoProfile -File scripts/build_first_hil.ps1 -BoardProfile lilygo_t_dongle_s3 -BuildDir build/bond-reset-lilygo -BleHidSpike off
```

The strict gate covered the full locked/offline Rust workspace, warnings-as-errors Clippy,
generated protocol agreement, static firmware checks, and native C++17 tests under MSVC `/W4
/WX`. The two ESP-IDF builds compiled the production NimBLE implementation and passed
`check_esp_transport.py` and `check_ble_hid_spike.py`.

The application-only updater's stale 64-KiB reserve was reconciled to the accepted ADR 0011 and
production-checker 32-KiB reserve before packaging. Unit tests accept the exact 32-KiB boundary and
reject a one-byte-over-boundary image.

| Board profile | App bytes | Raw app free | Free after 32-KiB reserve | SHA-256 |
| --- | ---: | ---: | ---: | --- |
| `waveshare_geek_v1_1_reference` | 995,152 | 53,424 | 20,656 | `359C0779683CDAFB0388693B875689924185265BD8F08024C7DA9D8218314EFD` |
| `lilygo_t_dongle_s3` | 995,200 | 53,376 | 20,608 | `4BC21CACD3F30FDA96FEE65B1503FD949FBF787B0095CA5C7DBCF11065D1E125` |

The Waveshare application image was written only at `0x10000` and read back with the exact packaged
SHA-256 above. Normal boot retained the existing Windows Bluetooth keyboard bond; both Bluetooth
PnP nodes remained `OK`. After a bounded idle gateway handoff from controller A to controller B, the installed CLI
observed an authenticated Wi-Fi session, `active=ble-hid`, `stored=ble-hid`, no restart pending, and
both `ble_hid_output_v1` and `ble_hid_bond_reset_v1`. Controller A's Keyferry LaunchAgent was restarted and
verified running immediately after the handoff. No command was active and the endpoint was
disarmed.

## Gate status

- Off-device implementation: **CLOSED**.
- Exact Waveshare application installation and capability visibility: **CLOSED**.
- Intentional physical bond deletion: **CLOSED**. After a Mac pairing attempt left no saved macOS
  device, the authenticated operation returned `bond_was_present=true`, scheduled restart, and the
  endpoint returned authenticated, idle, disarmed, and Bluetooth-output capable. Wi-Fi, ownership,
  recovery, and output mode were preserved.
- Fresh macOS recovery pairing and application-visible text delivery on controller A: **CLOSED** by owner
  observation after the reset. This proves the exact recovery path, not repeat-pair reliability
  across arbitrary hosts.
