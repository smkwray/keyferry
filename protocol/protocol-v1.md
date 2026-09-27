# HID Bridge Protocol v1

This document is normative for application frames carried between `keyferryd` and one ESP32-S3
endpoint over an authenticated TLS stream. The localhost HTTP API is specified in `docs/api-v1.md`.
The native USB executor is an in-process firmware component, not a second protocol peer.

## Design goals

- bounded parsing and deterministic cross-language encoding;
- explicit version/capability negotiation and framing-error recovery;
- no text or keyboard-layout interpretation on the endpoint;
- no ambiguous retry after native USB emission may have begun;
- one portable security/execution core independent of board peripherals.

## Layering and framing

The endpoint initiates an exactly pinned TLS 1.2 connection. A session is not command-capable until
`AUTH_CHALLENGE`, `AUTH_RESPONSE`, and `SESSION_READY` complete. TLS provides confidentiality,
integrity, and peer authentication. Application frames remain COBS encoded and zero-delimited because
TLS is a byte stream, not a message boundary; CRC-16/CCITT-FALSE gives deterministic corruption and
parser diagnostics but is never authentication.

All integers are little-endian. A decoded frame is:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 2 | magic bytes `H`, `B` (`0x48 0x42`) |
| 2 | 1 | major version, `1` |
| 3 | 1 | minor version, initially `0` |
| 4 | 1 | message type |
| 5 | 1 | flags |
| 6 | 4 | sequence number |
| 10 | 2 | payload length |
| 12 | N | payload |
| 12+N | 2 | CRC-16/CCITT-FALSE over every preceding decoded byte |

The decoded frame is at most 256 bytes, so payload is at most 242 bytes. Receivers reject frames
shorter than 14 bytes, over limit, with wrong magic/length/CRC, or containing an interior zero in the
COBS section. After malformed or overlength input they discard through the next delimiter.

## Versioning and reserved values

- Major mismatch permits only bounded diagnostics and returns `UNSUPPORTED_VERSION` for control.
- A newer minor is accepted only when all critical fields and capabilities are understood.
- Unknown optional TLVs (high tag bit clear) are ignored; unknown critical TLVs (high bit set) yield
  `UNKNOWN_CRITICAL_FIELD`.
- `0x10`, `0x12`, and `0x22` message IDs and error `0x000B` are reserved legacy two-MCU values. They
  must never be reinterpreted. Old vectors may retain them as codec compatibility fixtures only.

## Sequence and execution epoch

Each authenticated connection creates a fresh volatile execution epoch, random session identifier,
and sequence space. Every host control frame increments a 32-bit sequence. The endpoint accepts only
the next sequence or a byte-identical retransmission of the immediately prior command when it can
prove execution did not start. Wrap closes the session.

Reboot, USB reset, Wi-Fi/TLS reconnect, daemon restart, lease loss, or uncertain completion creates a
new epoch, clears pending work, starts disarmed, sets the desired report to zero, and emits zero when
the endpoint is ready. A command that may have started becomes `UNKNOWN` and is never replayed.

## Authentication

### `AUTH_CHALLENGE` (`0x40`)

```text
host_id             16 bytes
host_boot_nonce     16 bytes
challenge           32 bytes
selected_major       1 byte
selected_minor       1 byte
```

### `AUTH_RESPONSE` (`0x41`)

```text
device_id           16 bytes
device_nonce        32 bytes
hmac                32 bytes
```

HMAC input is exactly:

```text
ASCII "hidbridge-auth-v1" ||
host_id || device_id || host_boot_nonce || challenge || device_nonce || major || minor
```

The key is the distinct 32-byte link secret for this host/device pairing.

### `SESSION_READY` (`0x42`)

```text
session_id          16 bytes
accepted_major       1 byte
accepted_minor       1 byte
capability_mask      4 bytes
host_lease_ms        4 bytes
renew_every_ms       4 bytes
command_max_ms       4 bytes
```

Authentication never arms the device.

When the host advertises capability bit `FIRMWARE_IDENTITY_V1` (`0x00000040`), supporting firmware
immediately returns `CAPABILITIES` (`0x55`) on sequence 1 before any ordinary control frame. Its
payload is exactly 77 bytes:

```text
identity_schema        1 byte   # exactly 1
device_capability_mask 4 bytes  # little-endian
protocol_major         1 byte   # exactly 1
protocol_min_minor     1 byte   # exactly 0 in v1
protocol_max_minor     1 byte   # exactly 0 in v1
semantic_release      32 bytes  # 1-31 ASCII SemVer bytes, then NUL padding
board_compatibility_id 4 bytes  # little-endian; 1 = waveshare_geek_v1_1_reference, 2 = lilygo_t_dongle_s3
digest_kind            1 byte   # 1 = ESP application ELF SHA-256
elf_sha256             32 bytes
```

An old host does not advertise the bit, so new firmware sends no unsolicited response. A new host
waits two seconds for the identity response; on silence only, it closes the still-unarmed session and
permits one reconnect on that physical path advertising legacy `KEYBOARD` alone. A received malformed
response, TLS failure, or HMAC failure is a hard failure and never enters the legacy path. Firmware
identity is inventory, not attestation of live flash or partition state.

## Bluetooth keyboard bond reset

Capability `BLE_HID_BOND_RESET_V1` (`0x00100000`) is valid only with
`BLE_HID_OUTPUT_V1` (`0x00080000`). `RESET_BLE_HID_BOND` (`0x17`) has an empty payload and is
accepted only on an authenticated Wi-Fi session while `ble-hid` output is active and the endpoint
is idle, disarmed, and released. It deletes only persisted NimBLE HID peer records and schedules a
restart; it never erases Keyferry ownership, recovery, Wi-Fi, or output-mode storage.

The correlated `BLE_HID_BOND_STATUS` (`0x18`) payload is exactly two bytes:

```text
result              1 byte   # 0 no bond, 1 bond forgotten, 2 operation failed
restart_pending     1 byte   # exactly 1 for result 0 or 1; exactly 0 for result 2
```

## Display orientation

Capability `DISPLAY_ORIENTATION_V1` (`0x00400000`) declares an optional status display with a
persisted Normal/180° preference. `GET_DISPLAY_ORIENTATION` (`0x19`) has an empty payload;
`SET_DISPLAY_ORIENTATION` (`0x1B`) has exactly one byte (`0x01` normal, `0x02` rotated 180°).
Mutation is accepted only while authenticated, idle, disarmed, and released. The correlated
`DISPLAY_ORIENTATION_STATUS` (`0x1A`) payload is exactly two bytes: active-boot orientation followed
by stored next-boot orientation. A changed setting schedules restart only after that response.

A malformed response is a protocol fault. Loss after submission is uncertain and never authorizes
an automatic retry. After a successful response, the endpoint waits at least 250 ms before restart
so the response can leave the TLS transport.

## Screen power

Capability `SCREEN_POWER_V1` (`0x02000000`) declares live, persisted LCD power control.
`GET_SCREEN_POWER` (`0x1C`) has an empty payload. `SET_SCREEN_POWER` (`0x1E`) has exactly one byte:
`0x01` off or `0x02` on. Mutation requires an authenticated, idle, disarmed device; it does not
restart the endpoint. `SCREEN_POWER_STATUS` (`0x1D`) is a correlated three-byte response:
active power, stored preference, and display availability (`0x00` unavailable or `0x01` available).
When unavailable, active power does not prove the LCD's physical state. Active may differ from
stored while the display task applies the new setting, so the host may read status again. Unknown
values or lengths are protocol faults, and lost responses never trigger an automatic retry.

## Targeted gateway handoff

Capability `TARGETED_GATEWAY_HANDOFF_V1` (`0x00200000`) denotes the complete transaction below.
Unsupported endpoints reject it before leaving the active gateway. `GATEWAY_HANDOFF` (`0x59`)
carries one of three strict operation payloads; `GATEWAY_HANDOFF_STATUS` (`0x5A`) is exactly 94
bytes and echoes the operation and transaction.

```text
START  = schema:u8, operation:u8, transaction_id[16], target_installation_id[16],
         readiness_nonce[16], proof_digest[32], target_ipv4[4], target_port:u16LE,
         target_valid_ms:u32LE, recovery_ms:u32LE                         # 96 bytes
ACCEPT = schema:u8, operation:u8, transaction_id[16], readiness_nonce[16],
         proof_digest[32]                                                 # 66 bytes
QUERY  = schema:u8, operation:u8, transaction_id[16]                      # 18 bytes
STATUS = schema:u8, reply_operation:u8, status:u16LE, transaction_id[16],
         phase:u8, reason:u8, remaining_phase_ms:u32LE,
         remaining_recovery_ms:u32LE, target_installation_id[16],
         previous_installation_id[16], device_boot_nonce[16],
         current_endpoint_session[16]                                     # 94 bytes
```

START requires a fresh route-proof digest, an authenticated idle/disarmed session, and fixed
6,000-ms target and recovery budgets. The endpoint first completes input release, then disconnects.
During `TARGETING` it admits only the named target installation and address. A newly authenticated
target remains provisional until ACCEPT matches the transaction and nonce and its proof digest is
the digest of a route proof verified in that new session. Timeout enters `RESTORING`, which admits
only the exact previous installation over its recorded source route. START may arrive over Wi-Fi or
the qualified Bluetooth gateway pipe; the named target is Wi-Fi. A prior Wi-Fi route restores only
its saved address, while a prior Bluetooth route temporarily advertises only for the recorded
installation. QUERY is read-only and works only for the retained matching transaction. Terminal
phases are `TRANSFERRED`, `RESTORED`, `NOT_STARTED`, and
`RECOVERY_UNAVAILABLE`. No phase permits automatic START replay.

## Arm control

Arm control uses the authenticated session sequence space. A control request succeeds only after the
endpoint returns `ACK` on the same sequence with this payload:

```text
acked_message_type   1 byte
status               2 bytes  # little-endian; zero means success
```

Failure returns `ERROR`; silence or loss after a request was sent is uncertain and closes the
session. An `ACK` for another message, another sequence, a nonzero status, or the wrong payload length
is a protocol fault. Authentication alone never arms the endpoint.

`ARM` (`0x52`) payload:

```text
policy               1 byte   # 0x01 command-scoped, 0x02 temporary, 0x03 always-ready
lease_ms             4 bytes  # little-endian
```

Command-scoped arming is the required/default v1 mode and requires `lease_ms = 0`. It is consumed by
one accepted command and is also cleared by disarm, session loss, reboot, or fault. Temporary arming
requires `lease_ms` in `1..=600000`. Always-ready is an explicit opt-in and requires `lease_ms = 0`.
An endpoint may reject optional policies it has not qualified.

`DISARM` (`0x53`) has an empty payload. It clears pending work, changes the desired report to zero,
and attempts the zero report before acknowledging whenever USB remains usable.

`LEASE_RENEW` (`0x54`) payload:

```text
lease_ms             4 bytes  # little-endian; nonzero
```

Renewal never arms a disarmed endpoint and never changes its arm policy. An invalid or stale renewal
is rejected. The initial hardware slice enables command-scoped arming only and therefore does not
need arm-lease renewal.

## Command envelope

`COMMAND` (`0x50`) payload:

```text
command_id          16 bytes
valid_for_ms         4 bytes   # relative validity of this wire chunk, maximum 5000 in v1
profile_hash        32 bytes
command_kind         1 byte
body_length          2 bytes
body                  N bytes
```

Kinds are `0x01 EXECUTE_REPORT_CHUNK`, `0x02 CANCEL`, and `0x03 RELEASE_ALL`. The public daemon API
accepts text/tap/chord, but the endpoint receives only raw report actions. Invalid auth, arm state,
expiry, sequence, duplicate, size, capability, mode, or grammar rejects before executor dispatch.

`valid_for_ms` is evaluated independently for each authenticated wire `COMMAND`. It prevents a
queued chunk from starting stale; it is not the total-duration budget for a host-compiled sequence.
A host may send later chunks with fresh validity only under the same serialized command execution,
with every prior chunk terminal and released. Public first-start and total-runtime limits are host
policy and do not change this envelope.

## Internal report actions

For `EXECUTE_REPORT_CHUNK`, the body contains closed action records:

```text
tag               1 byte
length            1 byte
payload          length bytes
```

- `KEY_REPORT` (`0x01`, length 8): modifiers, zero reserved byte, six HID usages. It replaces the
  complete desired boot-keyboard report; duplicate nonzero usages and reserved modifier bits fail.
- `WAIT_MS` (`0x02`, length 2): little-endian duration, at most 100 ms.
- `RELEASE_ALL_ACTION` (`0x03`, length 0): desired report becomes zero and held-key accounting resets.
- `TAP_KEY` (`0x04`, length 6): modifiers, usage, key-down ms, release-gap ms; each duration 5–100 ms.

One chunk targets at most 500 ms and every normal chunk ends in release-all. The native USB executor
alone owns the last accepted report. Parser, auth, TLS, Wi-Fi, lease, queue, cancellation, optional
peripheral, USB, and watchdog faults invalidate the epoch, clear work, set desired report to zero, and
attempt zero whenever USB remains usable. No display, touch, button, LED, or storage path can arm,
approve, or block release-all.

## Results

`COMMAND_RESULT` (`0x51`) uses the same frame sequence as the `COMMAND` it answers:

```text
command_id          16 bytes
result_code          1 byte
```

For an execute chunk, `ACCEPTED` is emitted only after endpoint validation and `STARTED` only after
the first nonzero USB report is accepted. The successful order is `ACCEPTED`, `STARTED`, then
`EMITTED`; a missing, duplicated, or out-of-order nonterminal result is a protocol fault. A terminal
`ABORTED`, `REJECTED`, or `UNKNOWN` may end the request early. Transport readiness is never evidence
for `ACCEPTED` or `STARTED`.

| State | Meaning |
|---|---|
| `QUEUED` | daemon accepted locally; not yet sent |
| `ACCEPTED` | authenticated endpoint validated the command |
| `STARTED` | first nonzero keyboard report was accepted by the USB stack |
| `EMITTED` | all intended reports and terminal zero report were accepted by the USB stack |
| `ABORTED` | remaining work stopped and desired report is zero |
| `REJECTED` | command did not execute |
| `UNKNOWN` | evidence was lost after execution may have begun |

`EMITTED` never claims the target OS/application processed the reports.

The table defines one wire command result. When a host command contains several wire chunks, the
host reducer retains a high-water mark of possible execution. After any chunk reaches `STARTED`, a
later `REJECTED` cannot make the aggregate command `REJECTED`; the aggregate is `ABORTED` only when
terminal zero is confirmed and otherwise `UNKNOWN`.

## Retry, arm, and limits

Before `ACCEPTED`, the daemon may retransmit identical bytes under the same command ID. After
`ACCEPTED`, retry is allowed only with proof execution never started. After `STARTED`, no automatic
retry is permitted; manual resend requires a duplication warning.

```text
host lease                    30,000 ms
renew every                   10,000 ms
connection dead               45,000 ms
temporary arm maximum        600,000 ms
command start                  5,000 ms
held-key watchdog              2,000 ms
max decoded frame                256 bytes
max report actions                    64
max key usages/report                  6
max wait action                   100 ms
max expected chunk                 500 ms
max active commands                    1
max pending/offline commands            0
max paired hosts                       8
max Wi-Fi profiles                     8
```

## Golden vectors

`protocol/vectors/` contains semantic fields, decoded bytes, and COBS wire bytes. Current Rust and C++
code must agree exactly. Legacy `0x10` vectors test codec continuity only and do not authorize an
internal UART or current session message. Any semantic vector change requires explicit review.

## Volatile USB file control

`USB_FILE_HANDOFF_V1` advertises authenticated `FILE_REQUEST` (0x60) / `FILE_STATUS` (0x61).
IDs, limits and sizes come from `messages.yaml`. Requests carry the ordinary session sequence;
each reply must echo it. File operations require idle, disarmed, neutral state and never arm input.

Request byte 0 selects: 1 BEGIN followed by little-endian u32 byte length and SHA-256 (32 bytes);
2 CHUNK followed by little-endian u32 offset and 1..200 exact bytes; 3 COMMIT; 4 CLEAR; 5 STATUS.
BEGIN's size is bounded by `file_handoff.max_file_bytes` in `messages.yaml`. CHUNK offsets must
advance exactly; COMMIT requires the whole payload and matching digest. Empty files are valid. Status is exactly 10 bytes: u8 state, u8 error,
little-endian u32 total bytes and u32 received bytes. States are empty=0, receiving=1, published=2;
errors are ok=0, busy=1, limit=2, order=3, digest=4, memory=5, unavailable=6.

A published snapshot is immutable. BEGIN/CLEAR on a published medium can return explicit Busy
while USB detaches; only that explicit refusal may be retried. Lost replies never cause automatic
upload replay. The sole controller serializes the upload, rejects unsupported devices, and keeps
payloads in memory. POST/GET/DELETE `/v1/devices/{id}/file` publish/read/clear through normal
local authentication or owner-mTLS forwarding. POST accepts `{ "bytes": [0..255] }` within the
bounded body limit. Responses contain only state, size_bytes, received_bytes and max_size_bytes.
Filenames, hashes and payloads are not persisted or logged. The first volume exposes MESSAGE.TXT;
readiness means the target can read it, not that a target program copied it.

### Multiple named files

`USB_FILE_SET_V2` advertises `FILE_SET_REQUEST` (0x62) / `FILE_SET_STATUS` (0x63).
The original single-file messages remain unchanged. Both use the same medium and writer exclusion;
publishing through either interface replaces the complete previous snapshot. The new capability
must be checked before sending a file-set mutation. There is no append, in-place delete or folder
operation. Clear removes the whole set. No operation authorizes input or changes USB descriptors.

A set contains 1..16 files with at most 262,144 content bytes in total. Names contain 1..64 ASCII
bytes from letters, digits, space, dot, underscore and hyphen, with no leading or trailing dot or
space. Names must be unique ignoring ASCII case. The basename before the first dot, with trailing
spaces removed, cannot be
`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9` or `LPT1`..`LPT9`, ignoring case. Invalid names are
rejected rather than renamed. Zero-length files are valid. The registry governs these limits.

The transferred bundle is a u8 file count, followed by that many manifest records
`[u8 name_length, name bytes, u32 content_length]`, followed by all contents concatenated in
manifest order. Integers are little-endian. The declared lengths must consume the bundle exactly;
truncation, overflow, trailing data and aggregate content above the limit are errors. The maximum
bundle length is derived as `1 + max_files * (1 + max_name_bytes + 4) + max_file_bytes`.
SHA-256 covers every bundle byte, including the manifest. Digest success alone is insufficient:
the complete manifest must also pass validation before the medium becomes ready.

Request byte 0 selects: 1 BEGIN followed by u32 bundle length and 32-byte SHA-256; 2 CHUNK followed
by u32 offset and 1..200 bytes; 3 COMMIT; 4 CLEAR; 5 STATUS followed by a u8 index (`255` for a
summary, otherwise a zero-based file index). BEGIN and CHUNK lengths refer to bundle bytes.
Offsets advance exactly. State/error values match single-file control. An invalid manifest reports
`limit` and wipes staging. Bounds apply before allocation or field access.

Every response starts with u8 state, u8 error, u32 bundle length, u32 received bundle bytes, and
u8 published file count (11 bytes). A successful indexed STATUS for a published file appends
`[u8 index, u8 name_length, name bytes, u32 content_length]`. Summary and mutation responses contain
only the base. The controller serializes listing with mutations and rejects inconsistent responses;
the listing is an authenticated in-memory response, never a log or persistent receipt.

The FAT12 volume synthesizes long filename records, separate cluster chains and zero-filled tail
padding from the immutable validated bundle. Its geometry includes the worst-case per-file cluster
rounding independently of the payload capacity. Beginning replacement first withdraws and wipes the
previous snapshot. A failed replacement leaves the drive empty. Deliberate publication refresh
retains only the committed set; controller loss, power loss and fault discard it. A lost response
never triggers automatic replay after possible admission. Physical qualification of the original
single-file version does not qualify multi-file directory behavior on any target OS.

An old single-file STATUS request reports `unavailable` while a file-set transaction or snapshot
occupies the medium, rather than mislabeling it as MESSAGE.TXT or returning an oversized v1 length.
Single-file BEGIN and CLEAR can still replace or clear that snapshot using the same detach barrier.
Chunks and commits from the wrong protocol family are rejected without modifying published data.
Conversely, file-set STATUS can list a single-file publication as one MESSAGE.TXT entry. Its length
and received fields then reflect the original v1 transfer: content bytes alone, including zero for
an empty file. No synthetic manifest length is added to status. A controller validating its own v2
publication still requires the exact expected bundle length and complete file listing.
