# Keyferry portable roaming v2

Status: draft implementation contract. It does not authorize a firmware write until Work Order 08's
off-device security, recovery, package, size, and RAM gates close.

## Purpose

Portable roaming makes the stick the stable product identity. An owner-authorized Windows or macOS
installation can become its nearby gateway without a pre-existing gateway, known Wi-Fi network,
stick-side enrollment write, or operating-system Bluetooth pairing. Other authorized installations
on the same reachable tailnet discover and control the current route.

This protocol does not replace the command protocol, USB executor, or BLE byte pipe. It changes how
TLS peer authority and per-installation link keys are established.

## Roles and roots

- `D`: one Keyferry device, identified by a random 16-byte `device_id`.
- `I`: one desktop installation, identified from its P-256 public key.
- `O`: one offline owner CA and random 16-byte `owner_id`.
- `R_D`: one random 32-byte device recovery secret.
- `epoch`: nonzero 64-bit owner-authority epoch, initially 1.

The owner kit stores `O`'s private key and `R_D`. A normal installation stores its own private key,
the public owner chain, owner-issued certificates, and derived per-device secrets. It must not store
the owner CA private key or `R_D`.

## Portable owner kit and installation files

The owner kit is one create-new JSON envelope, bounded to 16 KiB. Its authenticated plaintext holds
the owner ID, owner P-256 CA key and certificate, one device ID and recovery secret, and the current
authority epoch. The envelope uses Argon2id v19 with 64 MiB memory, three iterations and one lane to
derive a 256-bit key, then AES-256-GCM with a random 16-byte salt, random 12-byte nonce, and the exact
AAD `keyferry/owner-kit-envelope/v2`. The KDF and cipher parameters are fixed by schema v2; a reader
rejects parameter changes before performing KDF work. Passphrases are supplied through a secret
input channel, never a command-line argument or log.

Unlocking the kit on a new desktop creates a new P-256 installation key locally and issues three
separate owner-signed leaves for that same key:

- the exact device DNS name with server-auth usage for the existing device-facing TLS channel;
- the exact installation DNS name with server-auth usage for the remote desktop API; and
- the exact installation DNS name with client-auth usage for the remote desktop API.

The installation directory contains only that installation's private key, the public owner root,
the three role-specific leaves, the public SPKI and manifest, and the two device-scoped derived
secrets. It never receives the owner CA key or device recovery secret. Publication is atomic and
create-new; ordinary issuance performs no device or configuration write.

The fixed binary identity files are `owner-id.bin`, `device-id.bin`, and
`installation-id.bin`. The cryptographic files are `owner-ca.der`, `installation-spki.der`,
`installation-key.der`, `device-server-cert.der`, `desktop-server-cert.der`,
`desktop-client-cert.der`, `device-link-secret.bin`, and `route-proof-secret.bin`.
`installation.json` is descriptive metadata; runtime identity is read from the fixed-width binary
files and checked against the installation SPKI. `keyferryd --installation DIRECTORY` consumes the
directory read-only and automatically enables the platform BLE gateway. It rejects a partial
directory, an all-zero identity or link key, a private-key/SPKI mismatch, a derived installation-ID
mismatch, or a device certificate that is not valid for the exact device DNS name.

## Canonical identities and keys

`SPKI_DER` is the complete DER SubjectPublicKeyInfo of the installation's P-256 key.

```text
installation_id = first_16(
  SHA256("keyferry/installation-id/v2" || SPKI_DER)
)

salt = SHA256(
  "keyferry/link-salt/v2" || owner_id || device_id || u64be(epoch)
)

link_secret = HKDF-SHA256(
  ikm = R_D,
  salt = salt,
  info = "keyferry/device-link/v2" || installation_id || SPKI_DER,
  length = 32
)
```

All literal domains are their ASCII bytes without a trailing NUL. Integers are unsigned big-endian.
Concatenation has no implicit padding. `SPKI_DER` is bounded to the exact 91-byte P-256 encoding
already enforced by the endpoint.

## Device-facing certificate profile

For each authorized `(D, I)`, the owner kit issues a leaf certificate over `I`'s installation key:

- ECDSA P-256/SHA-256;
- issuer: the owner CA;
- DNS SAN: `d-<lowercase device_id hex>.gateway.keyferry.invalid`;
- extended key usage: TLS server authentication;
- basic constraints: CA false;
- no wildcard names and no IP-address identity;
- leaf plus one owner root only; no arbitrary-length chain;
- each DER certificate at most 1,024 bytes.

The endpoint-facing validity interval is fixed by the profile and deliberately does not create a
wall-clock dependency for a powered-only device. Chain signature, basic constraints, key usage,
extended key usage, DNS name, P-256 SPKI shape, authority epoch, revocation, and HMAC remain
mandatory. An implementation may not achieve clock independence by enabling insecure ESP-TLS or by
clearing unrelated verification flags.

The daemon selects the device leaf by SNI. Absence of an exact SNI match aborts the handshake; it
never falls back to another device certificate.

## Device TLS admission

Both Wi-Fi and BLE begin with the unchanged TLS 1.2 stream. BLE characteristic bytes are ciphertext
from byte zero under `ble-gatt-v1`; Wi-Fi discovery input remains an untrusted address hint.

Before promotion, the device requires:

1. TLS 1.2;
2. `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`;
3. P-256 key exchange and a P-256 leaf SPKI;
4. a valid chain to the active owner CA;
5. the exact device DNS SAN;
6. server-auth usage and CA-false leaf constraints;
7. an `installation_id` absent from the active revocation set;
8. a successful existing Keyferry HMAC challenge under the derived `link_secret`; and
9. a current unchanged policy generation between candidate creation and promotion.

The challenge's `host_id` field becomes `installation_id`. The candidate starts disarmed and cannot
ARM or execute before `SESSION_READY`. There is one shared Wi-Fi/BLE candidate budget and exactly
one active endpoint session. A failed or stale candidate clears its volatile key material.

## Owner policy and revocation

Independent recovery state contains:

```text
owner_id[16]
owner_ca_sha256[32]
device_recovery_secret[32]
epoch:u64
policy_sequence:u64
policy_hash[32]
revoked_installation_ids[0..64][16]
```

The active A/B configuration contains the owner CA DER, owner ID, epoch, policy sequence, ordered
revocation IDs, zero through eight Wi-Fi profiles, and ordinary nonsecret settings. The independent
anchor contains the recovery secret and a sequence/hash floor; it never contains command payloads.

The v2 operational payload is exactly 3,064 bytes and uses this big-endian layout:

```text
device_id[16] | owner_id[16] | owner_ca_sha256[32] |
epoch:u64 | policy_sequence:u64 | previous_policy_sequence:u64 |
policy_hash[32] | previous_policy_hash[32] | policy_auth_tag[32] |
owner_ca_length:u16 | wifi_count:u8 | revoked_count:u8 | reserved_zero[4] |
owner_ca_der[1024] | revoked_installation_ids[64][16] |
wifi_profiles[8][103]
```

Unused certificate, revocation, and Wi-Fi storage is zero. Revocation IDs are nonzero and strictly
sorted bytewise. A zero-Wi-Fi policy is valid. Each operational slot is the existing 28-byte A/B
header followed by this payload, for 3,092 bytes total inside each unchanged 16 KiB partition. Its
magic is `KFC2`, format version is 2, and a v1 slot never decodes as v2 (or vice versa).

`policy_hash` is SHA-256 over the canonical policy fields excluding `policy_hash` and
`policy_auth_tag`. `policy_auth_tag` authenticates that hash with a key derived from `R_D`, the
owner/device identity, epoch, and the policy-update domain. CRC and structural validation alone do
not create an `AuthenticatedPolicyIdentity`; cryptographic verification of the CA hash, canonical
policy hash, and tag is mandatory before reconciliation with the recovery anchor.

The fixed recovery-anchor blob is 180 bytes. It uses big-endian integers and this exact layout:

```text
"KFR2"[4] | format_version:u16=1 | record_bytes:u16=180 |
phase:u8 | reserved_zero[7] | epoch:u64 | policy_sequence:u64 |
device_id[16] | owner_id[16] | owner_ca_sha256[32] |
device_recovery_secret[32] | policy_hash[32] | transaction_id[16] |
crc32:u32
```

The CRC-32 is the existing IEEE project CRC over the first 176 bytes. It detects storage damage but
is not authorization; authenticated policy/recovery operations provide authority. Phase 1 is
`MIGRATION_PENDING` and phase 2 is `ACTIVE`. A missing, malformed, or pending anchor never enables
compiled or legacy operational trust. The transaction ID is random and nonzero in both phases.

At boot, an active anchor admits a policy only when device, owner, CA hash, epoch, sequence, and
policy hash match its floor exactly. One authenticated successor may advance the floor when its
sequence is exactly `floor + 1`, its predecessor sequence/hash match exactly, and its epoch is
unchanged or exactly `epoch + 1`. Every other newer, older, forked, wrong-owner, or wrong-device
policy remains locked recovery. Initial migration can activate only after both v2 slots contain the
same authenticated sequence-1 policy named by the pending anchor.

An update is compare-and-swap: predecessor sequence/hash must equal the active policy, new sequence
is exactly predecessor + 1, and the new policy is authenticated by a recovery-derived administrative
key. A same-sequence identical hash is an idempotent receipt; any other same-sequence object is a
conflict. Revocation entries are sorted, unique, and never silently evicted. At 64 entries the owner
must rotate the epoch and reissue retained installation credentials.

Epoch rotation is exactly +1, may clear the revocation set, and changes all derived link secrets.
Old credentials can still chain to the CA but fail the device HMAC. A revoked identity cannot be
made valid by presenting an older configuration.

The owner maintenance tool accepts a complete desired-policy file rather than editing a hidden
partial copy. Version 1 of that private JSON contains `schema_version`, an ordered `wifi_profiles`
array of `ssid`, `password`, and numeric `priority`, plus the complete
`revoked_installation_ids` array as 16-byte lowercase hex identities. Zero Wi-Fi profiles is valid.
The tool obtains the active predecessor sequence and hash through USB `POLICY_STATUS`, constructs
and authenticates exactly one successor, and sends one compare-and-swap transaction. The policy
file path is non-secret command metadata; its contents and the owner-kit passphrase never appear in
process arguments or logs. An unknown commit outcome is reconciled against the returned policy hash
before any new update is constructed.

## Recovery and migration

Missing, malformed, ambiguous, or policy-stale operational slots enter maintenance-only locked
recovery. They do not zero the recovery authority and do not select compiled operational Wi-Fi,
host certificates, pins, or link keys. Erasing both A/B slots must not resurrect a prior host.

The v1-to-v2 migration is a journaled, authenticated transaction:

1. create and verify a `MIGRATION_PENDING` recovery anchor;
2. write and verify both v2 A/B records so no v1 operational fallback remains;
3. activate the matching policy sequence/hash floor; and
4. reboot into v2 disarmed operation.

Before sending `BEGIN`, the maintenance host atomically publishes an owner-only durable journal
containing the device ID, exact authenticated target-policy bytes, target epoch/sequence/hash, and
the random transaction ID. A fresh process resumes only those exact bytes and ID. It rejects a
truncated journal, authority/device mismatch, or target identity conflict before sending any
state-changing report. The journal remains until `POLICY_STATUS` and a format-2 challenge both
confirm the intended active epoch/sequence/hash; this also proves that legacy admission is gone.
File publication flushes the data before an atomic same-directory rename and durably commits that
rename on the host platform.

Every intermediate boot is either the verified old v1 state before activation or locked
maintenance. It is never an invented partial v2 authority. Rotation and repair use the same
release-first, maintenance-only transaction boundary and cannot ARM or execute.

## Remote desktop authentication

Each installation uses owner-issued desktop API certificates for the same installation key. The
remote listener requires mutual TLS, derives the caller identity from the verified peer SPKI, and
never trusts a caller header, hostname, tailnet name, IP address, or shared bearer as identity.

Desktop certificate profiles use role-appropriate EKUs and normal desktop clock validation. A
request for device `D` is admitted only while the gateway has a current authenticated session for
`D`, the caller identity is not revoked by `D`'s current policy, and the caller has the requested
controller role. Tailnet reachability supplies routing only.

### Generic tailnet candidate discovery

Every installation listens on the fixed Tailscale-only TCP port `18043` for one plaintext,
read-only route, `GET /v2/gateway/candidate`. Its bounded response contains only schema version 2
and the responding installation's 16-byte lowercase-hex installation ID. It exposes no device
inventory, status, command, credential, hostname, owner ID, or secret. The owner-authenticated mTLS
control API uses fixed port `18044`.

This candidate response is deliberately untrusted. A controller treats the returned installation
ID only as the exact synthetic SNI for an mTLS attempt at the same tailnet IP. The route becomes an
owner-authenticated gateway only after the server certificate chains to the controller's owner CA,
matches that exact installation name, and the server accepts the controller's owner-issued client
certificate. A spoofed candidate can therefore cause only a bounded failed connection attempt.
No per-machine trust registry, gateway export, named host, DNS entry, or Tailscale policy edit is
part of this discovery path. An administrator's existing tailnet deny policy remains authoritative.

Device inventory returned by mTLS is still insufficient for command admission. The fresh endpoint
route proof below binds the selected device and current live session before a controller may arm or
submit a command.

## Fresh route proof

A gateway's signature proves which installation answered, not that it currently owns `D`. Before a
controller selects a remote route, it supplies a fresh 32-byte nonce. The gateway relays a bounded
non-command route-proof request through the authenticated device session. The device response binds:

```text
"keyferry/route-proof/v2"
owner_id
device_id
epoch
policy_sequence
gateway_installation_id
controller_installation_id
controller_nonce
device_boot_nonce
endpoint_session_id
link_path
usb_ready
```

The owner kit gives each controller a device-specific route key:

```text
route_secret = HKDF-SHA256(
  ikm = R_D,
  salt = salt defined above,
  info = "keyferry/route-proof-key/v2" || controller_installation_id,
  length = 32
)
```

The response tag is HMAC-SHA256 under `route_secret` over the exact fixed fields above in listed
order; integers remain big-endian and booleans/enum values occupy one byte. The gateway identity is
taken from the active endpoint session, not caller input. The controller ID and nonce come from the
authenticated remote caller. A gateway can relay a fresh request but cannot verify or forge a proof
for another controller. A controller can forge only a statement to itself, which grants it no
device or other-controller authority. The endpoint exposes only this fixed statement, rate limits
requests, and never MACs arbitrary peer bytes.

A route proof expires after five seconds and is revalidated at command admission. It is not command
authority. Canonical vectors cover the 32-byte derived key, 201-byte tagged body, and 32-byte tag.

## Gateway transfer and outcomes

The device accepts the first fully authenticated, policy-current, release-ready candidate. A radio
connection or TLS ClientHello does not win. A healthy active gateway is not displaced by a preferred
radio or returning computer.

Planned transfer stops submissions, cancels unstarted work, disarms, obtains terminal zero, closes
the old session, advances the connection generation, and then admits a new candidate. Abrupt loss
uses the existing fail-closed path. No arming state, queued work, or possibly started command moves
between gateways. A command lacking an authenticated terminal outcome after possible start remains
`UNKNOWN` and is never retried automatically.

## Limits and prohibited shortcuts

- one active endpoint session;
- at most two unauthenticated candidates total and one per physical path;
- 64 revocation IDs;
- zero through eight Wi-Fi profiles;
- no BLE pairing or bonding as authority;
- no Bluetooth HID;
- no plaintext BLE command, status, ticket, certificate, or maintenance protocol;
- no shared installation private key;
- no owner CA or recovery secret in an ordinary installation;
- no compiled operational trust after migration;
- no policy rollback or silent revocation eviction;
- no device write for ordinary credential issuance or roaming;
- no firmware write authorized by this draft.

## Required vectors and negative cases

The generated registry must carry the literal domains and fixed limits. Rust and C++ independently
consume canonical vectors for installation ID, HKDF salt/link key, device DNS name, policy hash,
certificate chain/name/usage validation, revocation, epoch rotation, and interrupted migration.

Negative tests include wrong owner, device, SAN, EKU, curve, SPKI length, recovery secret, epoch,
policy generation, duplicate revocation, stale floor, missing SNI, unknown SNI, malformed chain,
oversize certificate, altered HMAC transcript, simultaneous gateways, transport loss at every
promotion step, and recovery without USB target readiness.
