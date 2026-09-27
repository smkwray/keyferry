# Keyferry BLE byte transport v1

This transport carries the existing Keyferry TLS 1.2 byte stream between an ESP32-S3 peripheral
and one nearby gateway. It does not carry commands, device status, identities, or authentication in
the clear. TLS host-key pinning and device HMAC authentication remain mandatory and unchanged.

## GATT surface

The UUIDs and numeric limits in `messages.yaml` are normative and generated into both Rust and C++.
The device advertises only the primary service UUID. It publishes no Bluetooth HID service, local
name, device ID, host ID, status value, or readable characteristic.

- Gateway-to-device characteristic: Write With Response only.
- Device-to-gateway characteristic: Indicate only.
- One connection, no pairing, no bonding, and no BLE peer persistence.
- ATT permissions are open because every characteristic value is TLS ciphertext.

## Stream mapping

Each successful write or indication contributes the next contiguous bytes to its direction of the
TLS stream. There is no BLE fragment header, sequence, checksum, retransmission, or application
frame. The fragment payload is `min(244, negotiated ATT MTU - 3)` and must work at MTU 23.

Only one write request and one indication may be outstanding. The device does not reuse the
indication buffer before acknowledgement. Overflow, truncation, GATT failure, disabled indications,
timeout, or an event from a stale connection generation closes the candidate stream without
silently dropping bytes.

## Authority and failure behavior

One transport manager owns the only endpoint session. Wi-Fi and BLE are mutually exclusive links
beneath it; neither owns command state. The first candidate to complete TLS, HMAC, and
`SESSION_READY` becomes active. Losing either candidate or active link cannot fault an unrelated
healthy session. Losing the active link clears pending work, releases all keys, disarms, advances
the connection generation, and never retries a possibly started command.

At boot, Wi-Fi starts immediately. BLE advertising may begin after five seconds, but Wi-Fi keeps
preference for the first 15 seconds. A BLE connection made during that window waits before TLS
authentication. An authenticated path remains active until it is lost; the device never switches a
live session merely because the preferred radio becomes available. Three failed BLE candidates
force one complete Wi-Fi attempt before advertising resumes. The exact timers and failure count are
normative values generated from `messages.yaml`.

The nearby Windows or macOS bridge is an opaque byte adapter. It never terminates TLS, parses Keyferry
frames, stores secrets, accepts commands, or retries stream data. It connects to `keyferryd` through
an operating-system-private process channel; `keyferryd` remains the only command authority.
