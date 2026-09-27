# Keyferry Local Management v1

Local Management v1 is an authenticated administrative protocol over the existing fixed 64-byte
vendor HID OUT/IN interface. It is available in both USB product personalities and does not depend
on Wi-Fi, Bluetooth pairing, a selected gateway, or a running daemon. It never accepts an input
command and cannot emit a nonzero keyboard or mouse report.

All integers are little-endian. Every unused or reserved byte is zero. A response operation is its
request operation with bit 7 set. Unknown operations, versions, status pages, flags, or nonzero
reserved bytes fail closed.

## Key separation and authentication

The device and host derive the 32-byte local administration key as:

```text
HMAC-SHA256(recovery_secret,
            "keyferry/local-admin-key/v1" || device_id)
```

`CHALLENGE` (`0x10`) is side-effect-free. It resets only an earlier unauthenticated or authenticated
local-management session; it does not enter maintenance, stop networking, alter input state, or
touch storage. Its request is the operation byte followed by 63 zero bytes. Its response is:

| Bytes | Field |
| ---: | --- |
| 0 | `CHALLENGE | 0x80` |
| 1 | status |
| 2 | version `1` |
| 3–6 | capability mask `u32` |
| 7–22 | exact device ID |
| 23–54 | fresh 32-byte device nonce |
| 55–62 | fresh nonzero 8-byte session ID |
| 63 | zero |

`AUTHENTICATE` (`0x11`) request bytes are operation, version, session ID bytes 2–9, fresh 16-byte
host nonce bytes 10–25, a full 32-byte host proof bytes 26–57, and six zero bytes. The proof is:

```text
transcript = "keyferry/local-auth/v1" || version || device_id ||
             device_nonce || session_id || host_nonce
host_proof = HMAC-SHA256(local_admin_key, transcript)
session_key = HMAC-SHA256(local_admin_key,
                          "keyferry/local-session/v1" || transcript)
```

The response carries operation/status/version, zero flags, session ID bytes 4–11, a full 32-byte
device proof bytes 12–43, and zero through byte 63. The device proof is:

```text
HMAC-SHA256(session_key,
            "keyferry/local-device-proof/v1" || transcript)
```

Proof comparison is constant-time. An authentication failure wipes the candidate session and is
subject to bounded throttling. A session expires after 60 seconds idle or five minutes total and is
bound to one USB attachment generation.

## Authenticated envelope

After authentication, request reports have this exact layout:

| Bytes | Field |
| ---: | --- |
| 0 | operation, response bit clear |
| 1 | version `1` |
| 2–9 | session ID |
| 10–13 | exact monotonic sequence `u32`, starting at 1 |
| 14–29 | operation ID; nonzero for mutations, zero for reads |
| 30–47 | 18-byte operation payload |
| 48–63 | first 16 bytes of request HMAC-SHA256 |

Responses have operation-with-response-bit, status, version, flags, session ID bytes 4–11,
sequence bytes 12–15, operation ID bytes 16–31, 16-byte response payload bytes 32–47, and the first
16 bytes of response HMAC-SHA256 bytes 48–63.

The tag inputs are the domain followed by bytes 0–47 of the report:

```text
request_tag  = HMAC-SHA256(session_key, "keyferry/local-request/v1"  || report[0:48])[0:16]
response_tag = HMAC-SHA256(session_key, "keyferry/local-response/v1" || report[0:48])[0:16]
```

The firmware accepts exactly the next sequence. A skip, old value, replay, malformed authenticated
envelope, wrong session ID, or bad tag wipes that local session and requires fresh authentication.
The response echoes the accepted sequence and operation ID. A host timeout after writing a request
is unknown and is reconciled through the retained operation receipt; it never causes blind retry.

## Operations

| Operation | ID | ID rule | Purpose |
| --- | ---: | --- | --- |
| `GET_STATUS` | `0x12` | zero | Read one typed status page selected by payload byte 0. |
| `OPEN_MAINTENANCE` | `0x13` | nonzero | Cancel/disarm and prove both HID interfaces neutral before mutation. |
| `CLOSE_MAINTENANCE` | `0x14` | nonzero | Relinquish maintenance without another mutation. |
| `RESTART_NETWORK` | `0x15` | nonzero | Restart the network runtime without replacing policy. |
| `CLEAR_BLE_BOND_AND_ENROLL` | `0x16` | nonzero | Clear the sole/invalid bond set and open one 120-second enrollment window. |
| `CANCEL_ENROLLMENT` | `0x17` | nonzero | Close the enrollment window. |
| `SET_OUTPUT_MODE` | `0x18` | nonzero | Store the registered output mode and reconcile required restart. |
| `REBOOT` | `0x19` | nonzero | Schedule one restart after the durable receipt and response. |
| `GET_RECEIPT` | `0x1A` | zero | Read the receipt for the operation ID carried in payload bytes 0–15. |

`GET_STATUS` pages are `DEVICE`, `SAFETY`, `NETWORK`, `BLE_HID`, `POLICY`, and `LAST_RECEIPT`.
The opt-in, unflashed MSC memory probe additionally recognizes `PROBE_RUN` (`0x07`),
`PROBE_HEAP` (`0x08`), and `PROBE_STACK` (`0x09`). Normal firmware returns `UNSUPPORTED`
for those three pages. They are authenticated, read-only, volatile metadata, not a payload
or recovery channel. All `GET_STATUS` requests still use only page byte 0 and zero bytes 1–17.
Status data is typed and bounded; it never contains Wi-Fi credentials, secrets, peer addresses,
text, key names, command payloads, or raw storage. BLE bond state is exactly `NONE`, `SINGLE`,
`MULTIPLE_INVALID`, or `STORE_ERROR`.

Every status response payload is 16 bytes and begins with status schema `1`. The remaining fixed
layouts are:

| Page | Bytes 1–15 |
| --- | --- |
| `DEVICE` | active output mode, stored output mode, `u8` board compatibility ID, eight-byte printable ASCII release padded only at the end with zero, capability mask `u32LE` |
| `SAFETY` | flags, two zero bytes, USB attachment generation `u32LE`, eight zero bytes |
| `NETWORK` | Wi-Fi stage, active path, flags, Wi-Fi-profile count, paired-host count, policy state, zero, Wi-Fi error `i32LE`, NVS error `i32LE` |
| `BLE_HID` | bond state, peripheral stage, flags, error `i32LE`, generation `u32LE`, enrollment remaining milliseconds `u32LE` |
| `POLICY` | policy state, six zero bytes, policy sequence `u64LE` |
| `LAST_RECEIPT` | receipt state, operation, result, receipt flags, argument `u16LE`, nine zero bytes; state `NONE` requires all other bytes zero |
| `PROBE_RUN` | sample sequence `u16LE`, phase, uptime seconds `u32LE`, held flags, first outcome, second outcome, transport running, link path, output mode, two zero bytes |
| `PROBE_HEAP` | sample sequence `u16LE`, zero, exact internal free bytes `u32LE`, largest allocatable block bytes `u32LE`, local minimum free bytes `u32LE` |
| `PROBE_STACK` | sample sequence `u16LE`, zero, exact main, transport, and probe task stack high-water free bytes, each `u32LE` |

All three probe pages use schema `1` in byte 0 and the same nonzero sample sequence in bytes
1–2; a host retries if the sequence differs across pages. `PROBE_RUN` uses phase IDs 1 boot,
2 post-auth, 3 first-held, 4 first-failed, 5 second-held, 6 second-failed, 7 released,
8 interrupted, 9 floor-drop, 10 monitor-failed, 11 holding, 12 drift, and 13 waiting.
Held flag bits 0 and 1 mean the first and second 64 KiB buffers are held; bits 2–7 must
be zero. First/second outcomes are
0 not attempted, 1 success, 2 free-heap guard, 3 insufficient contiguous block,
4 allocation failed, or 5 post-allocation guard failed. The probe preserves terminal
outcomes after failure or release. Transport running is `0` or `1`, link path is `0`–`2`,
and output mode is the registered `1` USB HID or `2` BLE HID. Probe pages never contain
application text, filenames, secrets, or low-entropy payload hashes. The stack values are
ESP-IDF ESP32-S3 high-water marks in **bytes**; `PROBE_HEAP` values are unrounded bytes.

Safety flag bits 0–7 are maintenance active, command active, armed, USB mounted, keyboard neutral,
mouse neutral, restart pending, and receipt storage healthy. Network flag bits 0–4 are runtime
running, Wi-Fi available, gateway BLE available, endpoint authenticated, and configuration valid;
bits 5–7 are zero. BLE flag bits 0–5 are advertising, connected, authenticated, subscribed, ready,
and enrollment active; bits 6–7 are zero. Counts, stages, modes, states, flags, reserved bytes, and
the 120-second enrollment bound are validated before a page is returned.

Operation payloads have one canonical shape. `GET_STATUS` uses its page in byte 0 and zero in bytes
1–17. `GET_RECEIPT` uses the nonzero target operation ID in bytes 0–15 and zero in bytes 16–17.
`SET_OUTPUT_MODE` uses byte 0 (`1` USB HID, `2` Bluetooth HID) and zero in bytes 1–17. Every other
mutation has an all-zero payload. An unused nonzero byte is `BAD_REPORT`; it is never ignored.

Mutation receipts contain only the operation ID, operation, state, result, normalized non-secret
argument, and flags. The fixed receipt response payload is state, operation, result, receipt flags,
argument `u16LE`, and ten zero bytes. States are `IN_PROGRESS`, `COMMITTED`, `FAILED`, and `UNKNOWN`.
The mutation intent is durable before its effect. A final-receipt storage failure cannot authorize a
retry, and a durable `IN_PROGRESS` receipt found after restart is reconciled to `UNKNOWN` without
re-executing the operation.

The device retains the newest 16 receipts in a CRC-protected, generation-selected A/B journal. An
older evicted identifier returns `OP_UNKNOWN`; that loss of evidence never authorizes automatic
retry. Equal-generation disagreement, malformed metadata, I/O failure, generation exhaustion, or
more than one durable in-progress operation fails closed.

`OPEN_MAINTENANCE` first persists its intent, then requests cancel/disarm/release-only cleanup and
waits at most two seconds for confirmed keyboard and mouse neutral state. Other mutations require
that lease and current neutral evidence. A required device restart occurs only after the committed
receipt's matching authenticated response transfer completes.

When Bluetooth keyboard output has no ready peer and no active output transport, maintenance may
instead admit a stable local-zero state: no command is active or armed, all current and desired
reports are zero, and no transfer or release is in flight. The unavailable path cannot accept a
nonzero report, and any later ready transition begins with a zero report. This is not evidence that
a target application observed a release. An available USB or Bluetooth output still requires its
normal completion-backed neutral evidence.

Only one authenticated local session and one mutation may exist. Mutation admission requires a
maintenance lease and confirmed keyboard and mouse neutral state. Local management can request
cancel, disarm, and release-only cleanup, but cannot arm or construct nonzero input. USB loss wipes
staged data and releases the lease. If a mutation may have executed, its result is reconciled by its
128-bit operation ID and bounded durable receipt.

## Direct host commands

The agent-facing CLI reaches the vendor HID interface directly. It does not contact `keyferryd`,
select a gateway, or require a working network or Bluetooth control path:

```text
keyctl local-status --owner-kit PATH
keyctl local-probe --owner-kit PATH [--device UUID] [--samples N]
keyctl local-recover --owner-kit PATH ACTION
```

`ACTION` is exactly one of `restart-network`, `forget-bluetooth`, `cancel-enrollment`, `usb-hid`,
`ble-hid`, or `reboot`. The encrypted owner-kit passphrase is read once from stdin; it is never an
argument, environment value, log field, or result field. Status returns one compact
`keyferry.local-status.v1` JSON object containing only the typed pages above.

`local-probe` is an opt-in, authenticated read-only capture for a separately authorized
MSC memory-probe image. It emits metadata-only NDJSON samples with a sample index and
shared nonzero sample sequence. Each sample reads all three probe pages and retries a changing
sequence at most four times; sustained churn is an explicit error. `--samples` defaults to 1 and
accepts 1–86401; the host waits one second between reads, so the count does not guarantee an
exact wall-clock duration. The host renews its authenticated read session before the 300-second
hard timeout, at most 240 seconds after the previous authentication. Authentication, transport,
and unsupported-page errors terminate capture without silently retrying. The command makes no
maintenance request or hardware write, and records no application text, file content, secrets,
or payload hashes.

Recovery emits a `keyferry.local-recovery-attempt.v1` JSON object containing every operation ID
before the first mutation is submitted, followed by one `keyferry.local-recovery-result.v1` object.
Each mutation is submitted at most once. A response loss after the HID write is reconciled only by
authenticated `GET_RECEIPT`; missing or expired evidence is reported as unknown with the exact
operation ID and never causes an automatic retry. These commands cannot type, move a pointer, arm
the device, or send raw HID reports.

## Roaming-policy repair compatibility

A complete roaming policy remains larger than one authenticated Local Management envelope. Policy
replacement therefore reuses the existing bounded roaming `POLICY_STATUS` and authenticated
`CHALLENGE`/`BEGIN`/`DATA`/`COMMIT` transaction instead of defining a second bulk uploader.

The host validates and compiles the complete successor policy before mutation, authenticates Local
Management with the same owner authority, opens maintenance, and only then begins the staged roaming
transaction on that same HID handle. Firmware admits its provisioning challenge during local
maintenance only when the authenticated coordinator lease is active and both input interfaces remain
neutral. A pre-lease provisioning client cannot claim this path. Definite staging failure sends
`ABORT` and closes maintenance; possible commit execution is never retried and is reconciled only by
the existing target policy identity and transaction evidence. Successful commit retains the existing
completion-gated restart. This compatibility path changes no report layout and does not give Local
Management a request-body or nonzero-input channel.
