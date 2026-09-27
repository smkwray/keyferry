# BLE HID off-device feasibility spike

Date: 2026-09-17

Baseline commit: `1929f4e`

ESP-IDF: project-pinned 6.0.3

Target boards: `lilygo_t_dongle_s3`, `waveshare_geek_v1_1_reference`

## Scope and disposition

This is a compile-and-measure spike for the proposed mutually exclusive direct
BLE keyboard mode. It now includes the allocation-free release-redundancy state
machine, but it does not implement the persisted output-mode or production BLE
HID adapters, it is not a flashable release artifact, and it was not written to
hardware. Ordinary firmware remains unchanged when
`KEYFERRY_BLE_HID_SPIKE=off`.

The resource gate passes narrowly. The pinned NimBLE notification API reports
only that transmission was attempted and accepted by the host stack; it does
not provide report-correlated peer receipt for the final neutral keyboard
notification. The accepted BLE-specific contract therefore sends three
release-all reports across distinct connection intervals, never retries a
nonzero report, and reports only local-stack acceptance rather than peer or
application delivery. Direct BLE HID remains unpromoted until the production
mode and physical gates pass.

## Reproduction

Each board was built in three configurations with `scripts/build_first_hil.ps1`:

```text
-BleHidSpike off
-BleHidSpike security
-BleHidSpike hid
```

The complete form was, for example:

```powershell
pwsh -File scripts/build_first_hil.ps1 `
  -BoardProfile lilygo_t_dongle_s3 `
  -BuildDir build/ble-hid-final2-lilygo-hid `
  -BleHidSpike hid
```

Spike images were inspected with:

```powershell
python scripts/check_ble_hid_spike.py `
  --build-dir build/ble-hid-final2-lilygo-hid --level hid
```

The checker requires the secure configuration, linked HID service and report
submission symbols, map and binary artifacts, and a binary no larger than
1,015,808 bytes (the 1 MiB application slot less the retained 32 KiB reserve).
Memory summaries came from the pinned `idf_size.py --format text` over each
linked map.

## Exact build measurements

| Board | Configuration | `.bin` bytes | IDF image bytes | Flash code | Flash data | DIRAM used | DIRAM free | BSS | Data | Margin before 32 KiB reserve |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| LILYGO | ordinary | 971,136 | 971,016 | 702,112 | 146,520 | 237,020 | 104,740 | 131,056 | 23,897 | 44,672 |
| LILYGO | security | 1,005,984 | 1,005,864 | 732,376 | 151,104 | 237,084 | 104,676 | 131,120 | 23,897 | 9,824 |
| LILYGO | security + HID + release policy | 1,011,840 | 1,011,720 | 736,800 | 152,440 | 237,196 | 104,564 | 131,136 | 23,993 | 3,968 |
| Waveshare | ordinary | 971,056 | 970,944 | 702,024 | 146,536 | 238,300 | 103,460 | 132,336 | 23,897 | 44,752 |
| Waveshare | security | 1,005,904 | 1,005,792 | 732,288 | 151,120 | 238,364 | 103,396 | 132,400 | 23,897 | 9,904 |
| Waveshare | security + HID + release policy | 1,011,760 | 1,011,648 | 736,712 | 152,456 | 238,476 | 103,284 | 132,416 | 23,993 | 4,048 |

For both boards, the complete spike adds 40,704 binary bytes and 176 bytes of
statically linked DIRAM relative to the ordinary build. Both ordinary rebuilds
retain their prior exact binary and section sizes and pass the normal transport
checker.

The linked target types establish a minimum dynamic service allocation of
3,088 bytes: 3,048 bytes for `ble_svc_hid_static_vars_t` and 40 bytes for
`ble_svc_dis_data`. That is a lower bound only. A target run is still required
to measure GATT registry, controller, NimBLE host, task-stack, pairing, and bond
high-water marks. The proposed 8 KiB added live-memory gate is consequently
open even though the measured static delta passes.

## Security, services, and persistence

The spike enables Secure Connections, disables legacy pairing and debug keys,
requires encrypted authenticated level-3 attributes, enables controller
security and host privacy, persists bonds in NVS, and retains one connection.
The pinned HID service source only adds its encrypted/authenticated GATT flags
for security levels 2 and 3; a trial level-4 configuration was discarded
because it silently omitted those flags. Level 3 plus `SM_SC_ONLY=1`, runtime
MITM, and runtime SC is the measured configuration.

The exact service definition contains 43 attributes and three CCCDs:

| Service group | Attributes |
| --- | ---: |
| HID keyboard (input, LED output, boot/report paths) | 22 |
| Battery | 3 |
| Device Information (model number and PnP ID) | 5 |
| GAP (name and appearance) | 5 |
| GATT | 8 |
| **Total** | **43** |

The three CCCDs are GATT Service Changed, HID boot-keyboard input, and HID
report-mode input; the compile-time capacity is four.

The existing `nvs` partition remains unchanged at `0x3000` (12 KiB). ESP-IDF
6.0.3 with GCC 15 fails its warnings-as-errors compile when the NimBLE bond
array is exactly one element because `ble_store_nvs.c` contains guarded but
statically out-of-bounds index-1 accesses. The spike therefore measures the
conservative two-entry allocation. Product policy remains one admitted bond,
with a second peer rejected rather than evicting the first. Exact persistent
NVS consumption and that one-bond admission behavior were not run on target.

## Terminal-neutral evidence trace

The existing custom gateway BLE pipe uses indications. Its callback accepts
only `BLE_HS_EDONE`, which NimBLE documents as receipt of the indication
confirmation (`firmware/esp32s3/components/kf_ble_transport/src/idf_ble_transport.cpp:337`).

HID over GATT uses notifications instead:

- Pinned `ble_gatts_notify_custom()` sends the notification and immediately
  calls `ble_gap_notify_tx_event`; its source comment says only that a
  notification transmission "was attempted"
  (`components/bt/host/nimble/nimble/nimble/host/src/ble_gattc.c:5449` and
  `:5509`).
- The public event contract defines status zero as "Command successfully sent"
  and reserves `BLE_HS_EDONE` for an indication acknowledgement
  (`.../host/include/host/ble_gap.h:969`).
- The controller's HCI Number Of Completed Packets handler only reduces the
  connection-wide outstanding-packet count and wakes transmit processing
  (`.../host/src/ble_hs_hci_evt.c:648`). It exposes no public callback carrying
  the originating HID report or logical command token.

Therefore a successful BLE HID notification submission proves possible
execution, but the pinned public API cannot correlate later controller progress
to the final all-zero report. It cannot support the existing meanings of
`EMITTED` or confirmed terminal neutral unchanged. RF receipt and target
application delivery would remain even stronger, unproved claims.

## Lower-layer correlation investigation

The follow-up source trace tested whether a narrow hook below NimBLE could
close that gap while retaining exactly one outstanding HID report.

A patch could technically identify the outgoing packet and correlate it with
the controller's aggregate completion counter:

1. The complete eight-byte HID report is one 15-byte HCI ACL payload after the
   L2CAP and ATT notification headers, so it is not fragmented at the pinned
   controller's minimum 27-byte LE ACL capacity.
2. The final outgoing packet can be identified by connection handle, ATT
   notification opcode, HID value handle, and report bytes at
   `ble_hci_trans_hs_acl_tx()`, then bound to the sole expected application
   token plus authenticated epoch and connection generation.
3. A per-connection FIFO containing every successfully submitted HCI ACL packet
   could consume the batched counts in the Number Of Completed Packets event.
   Disconnect and controller reset would invalidate, never complete, remaining
   tokens.

This would require a maintained patch to the pinned Bluetooth stack. The only
ESP VHCI receive callback is installed by `esp_nimble_hci_init()` from the
file-local `vhci_host_cb`; the inbound `host_rcv_pkt()` and NimBLE's Number Of
Completed Packets handler are also file-local. No supported observer or
per-packet completion callback exists at those interception points
(`esp_nimble_hci.c:271,337,359`; `ble_hs_hci_evt.c:126,648`).

More importantly, the FIFO would prove only **controller-buffer completion**.
The Bluetooth Core HCI flow-control specification says a packet is completed
when the Controller no longer needs that buffer. It says this nominally occurs
after transmission or flush, but may occur early when an implementation moves
the data to other storage. LE ACL packets are non-automatically-flushable, which
removes the automatic-flush case but not the explicitly permitted early-buffer
completion case. See the Bluetooth SIG
[HCI flow-control specification](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host-controller-interface/host-controller-interface-functional-specification.html).

An ATT acknowledgement would close a stronger boundary, but the GATT
notification procedure intentionally has no ATT-layer acknowledgement; only an
indication has one. The HID Report Host conformance surface requires enabling
notifications for input reports, and an ordinary OS HID host cannot be assumed
to subscribe to a nonstandard indication barrier. See the Bluetooth SIG
[GATT notification and indication procedures](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host/generic-attribute-profile--gatt-.html)
and [HOGP conformance statement](https://files.bluetooth.com/wp-content/uploads/2024/10/HOGP.ICS.p8.pdf).

The proposed small hook is therefore **not sufficient** for the existing
terminal-neutral contract. Proving peer receipt would require an unavailable
controller/link-layer acknowledgement hook or a cooperating target-side
protocol, neither of which is ordinary BLE HID. No hook or FIFO prototype was
added because it would validate the wrong boundary.

## Gate result

| Gate | Result | Evidence |
| --- | --- | --- |
| 32 KiB application reserve | **PASS, narrow** | 3,968-byte LILYGO and 4,048-byte Waveshare remaining margin |
| Added static DIRAM <= 8 KiB | **PASS** | 176-byte delta on both boards |
| Added live memory <= 8 KiB | **OPEN** | 3,088-byte known service lower bound; no target high-water measurement |
| 12 KiB NVS / one admitted bond | **OPEN** | partition unchanged; persistence and admission not exercised |
| BLE-specific release contract | **ACCEPTED** | three zero reports on separate intervals; local-stack acceptance is not described as peer receipt |
| Release-redundancy scheduler | **PASS, off-device** | allocation-free generation-bound state machine; native tests cover spacing, failures, stale callbacks, reconnect, and deadline saturation |
| HCI lower-layer correlation | **INSUFFICIENT** | exact FIFO correlation can prove buffer completion, which the Core permits before transmission completion |
| Normal firmware regression | **PASS** | both ordinary profiles rebuilt with exact prior sizes and normal checker |
| Native/physical BLE HID behavior | **NOT APPLICABLE** | no runtime implementation and no hardware write |

The source-level hook investigation is closed. The owner accepted the separate
BLE outcome and redundant-release contract on 2026-09-17. Production mode,
pairing, UI, live-memory measurement, and physical behavior remain open; no
hardware write occurred in this slice.
