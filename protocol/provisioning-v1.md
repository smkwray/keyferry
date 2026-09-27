# USB provisioning protocols

This protocol uses fixed 64-byte reports on the vendor-specific HID interface. It is separate from
the COBS-framed TLS command protocol. The device exposes only non-sensitive status fields and never
echoes configuration, credentials, keys, certificates, authentication tags, or staged bytes.

All unused report bytes must be zero. Multibyte integers are little-endian. Every malformed report,
transport loss, timeout, failed authentication, or terminal result consumes the challenge and wipes
the staged transaction. Only one transaction can exist at a time, and data chunks must arrive at the
exact next offset. The challenge selects exactly one payload format and reports its fixed size.
Legacy format 1 uses the `kPayloadBytes` encoding owned by `kf_config_store`. Roaming format 2 uses
the `kRoamingConfigPayloadBytes` encoding defined by `roaming-v2.md`. A request using any other
format or size fails before authentication or storage. The device owns generation enforcement,
authentication, slot selection, commit markers, and readback verification.

The report size, protocol version, field sizes, 30-second idle timeout, authentication domain,
operation values, and status values are generated from `messages.yaml`. Each accepted challenge,
begin, or data report refreshes the idle deadline. USB unmount, suspend, or any other loss of the
vendor-HID transport wipes the same state immediately.

## Reports

Requests use the operation values generated from `messages.yaml`. Responses set bit 7 in the request
operation and put the generated status value in byte 1.

| Operation | Request layout | Successful response |
|---|---|---|
| `CHALLENGE` | byte 0 operation; remaining bytes zero | version byte 2; payload length u16 bytes 3-4; device ID bytes 5-20; random nonce bytes 21-52; current generation u64 bytes 53-60 |
| `BEGIN` | version byte 1; payload length u16 bytes 2-3; nonzero transaction ID bytes 4-19 | status only |
| `DATA` | transaction ID bytes 1-16; exact offset u16 bytes 17-18; length byte 19; up to 44 bytes data from byte 20 | status only |
| `COMMIT` | transaction ID bytes 1-16; HMAC-SHA256 bytes 17-48 | committed slot byte 2; generation u64 bytes 3-10 |
| `ABORT` | remaining bytes zero | status only |
| `POLICY_STATUS` | remaining bytes zero | policy state byte 2; epoch u64 bytes 3-10; sequence u64 bytes 11-18; policy hash bytes 19-50 |

`POLICY_STATUS` cancels and wipes any staged transaction before returning non-secret recovery
metadata. Policy state is generated as `LEGACY`, `ABSENT`, `MALFORMED`, `MIGRATION_PENDING`,
`ACTIVE`, or `STORAGE_ERROR`. Only pending and active states carry a nonzero epoch, sequence, and
hash; every other state returns those fields as zero. This operation is available even while
operational authority is locked so that a controller can reconcile an interrupted maintenance
transaction. It does not authenticate the caller, disclose configuration contents, or authorize a
write. A status client sends `POLICY_STATUS` directly: it must not send `CHALLENGE` first. Its
response is terminal for any legacy adapter session so an older challenge-plus-status client cannot
strand provisioning active.

Transport admission is driven by the bounded firmware request queue and completed IN transfers, not
by a host timing delay. One next request may wait while firmware observes the prior response
completion. Queue overflow, malformed reports, and response failure wipe the local transport state;
outside an admitted provisioning session they must not clear unrelated network or input state.

For legacy format 1, the HMAC transcript is exactly:

```text
ASCII "keyferry-provision-v1" ||
device_id[16] ||
challenge_nonce[32] ||
current_generation_u64_le ||
transaction_id[16] ||
payload_length_u32_le ||
canonical_config_payload[payload_length]
```

For roaming format 2, the layout is identical except that the domain is
`ASCII "keyferry/maintenance/v2"` and the payload is the fixed roaming-policy payload advertised by
the challenge. This domain separation prevents a valid legacy transaction from becoming a roaming
migration transaction.

The key is the current 256-bit administrative recovery secret. The device compares the tag in
constant time before decoding or writing the payload. Both payload formats must retain the device
ID. A legacy payload may rotate the recovery secret atomically; the first roaming migration retains
the existing recovery secret in the independent anchor. A successful commit requires verified
persistent state. The controller must treat success as requiring a reboot; no runtime network or
command state is updated in place.

The roaming successor image advertises format 2. Its first authenticated transaction migrates a
legacy claimed device without changing its existing recovery secret: it writes a pending independent
recovery anchor, writes and verifies both roaming-policy slots, and activates the anchor last. If
power is lost, the same authenticated transaction ID and policy may resume; a different request is
locked. Once the anchor is active, legacy slots and compiled bootstrap credentials can no longer
become operational authority.

After migration, the same format applies an authenticated successor policy only when its sequence is
exactly one above the active anchor floor and its predecessor sequence and hash name that floor. The
device commits and verifies the inactive policy slot before advancing the anchor. If power is lost
between those operations, repeating the exact transaction advances the anchor without writing the
policy slot again. Repeating the already-active policy is idempotent; an old, skipped, or forked
policy fails closed. A lost `COMMIT` response never authorizes a blind retry with a newly constructed
policy or transaction ID: the controller must first query the current policy identity and reconcile
the outcome.

## Claim and authority

The current private-bootstrap image is already claimed: its distinct recovery secret is generated
off-device, retained in the ignored private bundle, and compiled into that development image. An
ordinary target computer cannot establish configuration authority merely by being attached over USB.
Generic retail first claim remains closed until a physical-presence or manufacturing-root procedure
meets the same authenticated-write boundary. There is no unauthenticated first-write exception.
