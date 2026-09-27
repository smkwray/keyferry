# Security contract

`keyferry` controls a USB keyboard attached to another machine. Possession of a valid command path is
therefore equivalent to the ability to type at that target, potentially including lock, installer,
boot, or recovery screens. The system is deny-by-default and must fail closed.

## Assets

- Authorization to emit USB reports.
- Dictated or manually entered text in transit.
- Wi-Fi credentials stored on the dongle.
- Per-installation link secrets, accepted v1 host pins, and roaming owner-policy state.
- The administrative recovery secret.
- Host TLS private keys and local API token.
- Accurate transient command outcomes and explicitly enabled diagnostic metadata.

## Public artifact boundary

The public boundary is fail-closed. A release is acceptable only when the tracked source,
every reachable Git object, and the exact final ZIP pass the ignored private-identifier registry in
binary form. The release builder accepts a fixed program manifest, rejects links and extra members,
uses a canonical archive name, and scans both its staging tree and final ZIP.

Generic Windows/macOS program releases must contain no unique device ID, hardware MAC address,
eFuse fingerprint, computer name, installation ID, certificate, private key, link secret, recovery
secret, owner kit, or per-device grant. Executables must be identical for every computer of the same
platform and architecture. The desktop display name is read from the running host's operating-
system/Tailscale state.

Authorization is deliberately separate data. Each controller installation receives an independently
issued private credential directory, delivered out of band and supplied to the installer as a path.
That directory identifies a cryptographic principal so one lost computer can be revoked without
invalidating every controller; it does not define the computer's display name. Exact-unit hardware
records and installation credentials remain under ignored private paths and must never be placed in
a public release archive. This is credential-bound identity, not non-clonable physical-computer
identity: copying a credential directory clones that principal. Issue one directory per controller
computer and do not duplicate it.

Before publishing, run `python scripts/check_public_tree.py --history --require-private-registry`
with the ignored private-identifier registry present, then scan each exact canonical ZIP with
`--artifact ZIP --require-private-registry`. A clean current tree is not enough: any private value
retained by an earlier commit requires a clean-history export or an explicitly authorized history
rewrite before a public remote is added.

## Threats in scope

- An untrusted person joins or already has access to the local Wi-Fi.
- A nearby person captures, replays, or floods local network traffic.
- An unauthorized tailnet user can reach the relay computer.
- Software on the USB target probes the composite device's vendor-HID interface.
- In file-capable firmware, software on the target sends arbitrary SCSI commands, malformed block
  reads and writes, and resets while an immutable file snapshot is published.
- Multi-file manifests can contain overflowing lengths, duplicate or unsafe names, truncated
  records, or mismatched data. Directory entries and cluster chains must never expose staging,
  another file's bytes, or memory outside the validated snapshot.
- A command or response is duplicated, delayed, truncated, reordered, or lost.
- The ESP32-S3, USB stack, daemon, target, or network resets during a modifier chord or operation.
- A malicious or malformed packet reaches every parser boundary.
- A legitimate controller is later lost and must be revoked independently.

## Threats acknowledged but not fully solved on portable hardware

- Before a separately qualified secure-boot/flash-encryption promotion, a determined physical attacker
  may be able to read or replace firmware and recover stored Wi-Fi/link material.
- Radio jamming and network flooding can deny service.
- USB HID cannot observe the focused application or verify that the target displayed the intended
  text.
- A compromised authorized host or controller can issue authorized input.
- A compromised target can observe the keystrokes it receives and can attempt denial of service
  against the USB configuration interface.
- A target can retain a published USB file in its caches or copies after the stick clears it.
  Clearing the stick cannot erase target-side data.

Use a low-privilege IoT or travel-router Wi-Fi credential. Do not store target passwords, recovery
phrases, or a general-purpose secret vault on the dongle.

## Required layers

1. **Wi-Fi admission:** WPA2-Personal where available; open networks are allowed only with an explicit
   warning because application authentication remains mandatory.
2. **Host authentication:** accepted v1 uses an exact P-256 host pin. Roaming v2 uses TLS 1.2 chain
   validation to the stored owner CA, an exact device-scoped DNS SAN and server-auth role, then
   derives the installation identity from the retained P-256 SPKI and rejects revoked or stale-epoch
   identities.
3. **Device authentication:** HMAC-SHA256 challenge-response using a distinct 256-bit link secret per
   installation-device pair. Roaming v2 derives that secret from the device recovery secret, epoch,
   device identity and installation SPKI; an ordinary installation receives the result, never the
   recovery secret.
4. **Command integrity:** authenticated TLS session, monotonic session sequence, unique command ID,
   bounded first-start expiry, fresh bounded validity for each serialized wire chunk, structural
   sequence limits, and duplicate rejection.
5. **Remote authorization:** accepted v1 uses a listener bound only to the gateway's discovered
   Tailscale address, a fresh nonce-bound signed gateway proof, and a distinct remote bearer.
   Roaming v2 requires owner-rooted mutual TLS, a non-revoked installation principal, and a fresh
   device-backed route proof before command admission. Discovery carries no credential and tailnet
   membership alone grants no Keyferry authority. A controller with no local session to one of its
   configured devices forwards its loopback API's command and device-state requests to the owner
   controller that holds that device, as that holder's owner-mTLS client under its own installation
   identity. It uses a holder only after that endpoint's fresh route proof, bound to this
   installation, the device, and the holder, verifies under this installation's own secret, and
   repeats the proof before every request that can start input. Configuration, maintenance,
   handoff, and requests that themselves arrived remotely are never forwarded; nothing is retried
   after possible start. Trust boundary: the loopback bearer now carries that installation's
   owner-mTLS authority for its configured devices across the tailnet, which only a holder of the
   installation credential could exercise before.
6. **USB administration:** nonce-bound HMAC under a random 256-bit administrative recovery secret.
7. **Execution safety:** one active host sequence and one bounded endpoint chunk, one writer,
   daemon-atomic route-proof/command-scoped-arm/first-command ordering, cancellation between reports,
   aggregate possible-start tracking, release-all on completion/fault, and a two-second held-key
   watchdog.
8. **Discovery isolation:** a fixed-size UDP beacon may identify a configured host and suggest its
   source address only. The beacon carries no command, payload, secret, key, or trust decision; the
   dongle filters it to a selected local interface and known host ID, then still requires exact TLS
   key pinning and HMAC device authentication. Manual host addressing remains available.
9. **Bluetooth isolation:** in `usb-hid`, BLE is an unpaired, byte-only GATT carrier for the
   TLS/HMAC session from its first byte. In mutually exclusive `ble-hid`, BLE is a bonded keyboard
   output only and commands remain on authenticated Wi-Fi. Pairing never grants command authority.
   Explicit bond reset requires the same owner-authorized control plane, idle/disarmed/released
   state, deletes only NimBLE peer records, and never erases ownership, recovery, Wi-Fi, or output
   mode storage.
10. **Gateway transfer:** only an owner-mTLS caller with a fresh exact-device route proof may start a
    transaction aimed at one prepared installation and its live selected-interface listener. The old
    gateway challenges the target before START; the endpoint confirms neutral input, admits only the
    named target for six seconds, and otherwise restores only the exact previous installation during
    a separate bounded recovery phase. The target exposes no command authority before correlated
    ACCEPT. Lost START responses are observed and never retried; the controller changes authority
    only after the target proves `transferred`. See ADR 0012.
11. **Physical firmware update:** Plan accepts one strict package, qualified private unit record, and
    exact local serial port after manual ROM entry. It never discovers ports or manufactures boot
    mode. Live ROM, canonical eFuse summary, flash, security, and exact-length preserved-region
    evidence must match the private qualified-unit record before a public unit-binding hash is
    emitted. Apply re-observes the same values before any write and remains a separately hash-authorized operation and is
    unavailable until its physical gate is explicitly opened.

## Prohibited production patterns

The opt-in USB file-handoff build requires qualification on each named board/target path before
general promotion. It may expose one immutable, read-only snapshot bounded by the protocol registry
(up to the generated protocol limit) from volatile memory, only after an authenticated controller completes bounded transfer
and digest validation. The USB target cannot publish, replace, or clear that snapshot or use SCSI
as a command channel. Publication and withdrawal require the existing device writer exclusion,
idle/disarmed state and confirmed neutral input before deliberate re-enumeration. No file operation
arms HID. Incomplete staging is never readable; target reads cannot change a mounted generation.
The implementation must wipe buffers on clear, expiry, controller loss, detach or fault, preserving
only a committed snapshot across its own deliberate enumeration. File bytes, filenames, digests and
transfer receipts must not be persisted or logged. Uncertain commit responses are reconciled by
read-only status and never automatically replayed. Qualification probes are not release images.
Multi-file firmware bounds both the aggregate content and manifest independently. It authenticates
and hashes the entire manifest and contents before exposing any file. Names are flat, bounded ASCII
names with a restricted character set, case-insensitive uniqueness and Windows reserved-name
rejection. FAT long-name records preserve accepted names; short aliases cannot collide with them.
Per-file sector padding is synthesized as zeroes and does not consume the advertised content limit.
Replacing a set withdraws and wipes the previous set first; failure leaves no previous copy to
restore. Listing is authenticated and read-only. Selecting or removing a file in the controller's
pending selection does not edit a mounted volume: publication replaces the entire set at once.
Older firmware must reject the new capability-specific operation before any mutation, and the
single-file protocol remains available for existing installations.
The firmware installer rejects versions with a `probe` prerelease identifier even when they are
valid for authenticated inventory. An offline layout review never authorizes a partition-table
write; the existing app-only updater must continue rejecting the relocated qualification layout.
Probe memory readings use the existing owner-authenticated, read-only USB status operation.
They contain only bounded numeric measurements and allocation outcomes. Ordinary firmware returns
unsupported; the host rejects inconsistent samples and never retries a failed exchange.

- simultaneous USB/Bluetooth HID output, BLE command/status/ticket protocols, pairing as command
  authorization, automatic bond replacement, a plaintext BLE admission preface, or a BLE adapter
  that terminates Keyferry TLS;
- local USB management that can arm or emit nonzero input, depends on a daemon/gateway/network route,
  or lets malformed USB traffic tear down unrelated authenticated runtime state;

Production source under `apps/`, `crates/`, and `firmware/` must not contain:

- disabled TLS verification;
- a generic ESP web server, FTP server, captive portal, or command listener;
- a default or human-chosen controller password;
- trust based solely on SSID, IP address, MAC address, or Wi-Fi password;
- unauthenticated configuration writes over USB;
- an automatic payload at boot or insertion;
- a command queue persisted across reboot or reconnect;
- automatic command retry after execution may have begun;
- command history enabled by default or payload text in any log;
- a software reset path that bypasses the recovery secret;
- a success result that claims application-level delivery.
- aggregate `REJECTED` after any chunk may have started;
- replay or coalescing of an accepted relative movement token;
- mixed-input success or abort inferred without matching keyboard and mouse neutral completions;
- pointer APIs that claim pixels, screen coordinates, target focus, or application success;
- command payload text, named-key arrays, source JSON, or script source in errors or diagnostics;
- text-stream source bytes, filenames, child text, or low-entropy payload hashes in receipts, logs,
  events, errors, diagnostics, or crash output;
- writing text-stream metadata (lengths, offsets, counts, caller, or timing) to disk; text-stream
  receipts live only in daemon memory;
- treating a stream the daemon no longer knows (for example after a daemon restart) or a failed
  status poll as proof that nothing was typed; its outcome is unknown and is reported as possibly
  partially typed;
- automatic text-stream replay/resume, continuing past an uncertain child, or releasing the parent
  writer reservation between children;
- silent unsupported-character dropping or lossy text replacement without an explicit caller
  selection and a metadata-only replacement count;
- any BLE service or role other than the generated, bounded GATT byte pipe in the production
  ESP32-S3 profile;
- eFuse mutation, Secure Boot, flash encryption, or anti-rollback enabling in qualification builds.
- firmware port discovery, remote serial schemes, automatic boot-mode reset, unpinned update tools,
  arbitrary esptool arguments, or a firmware write without an exact separately approved Plan hash;
- wildcard/all-interface UDP beacon binding or discovery packets containing command data, payloads,
  credentials, keys, pins, or authentication tags.

`scripts/check_seed.py` checks a small set of forbidden source tokens. That scan is defense in depth,
not a security proof.

## Secret handling

- Development examples contain placeholders only.
- Secrets are generated locally from an operating-system CSPRNG.
- Controller secrets use the operating-system credential store once platform integration begins.
- The recovery secret is exportable once as a Base32 string and QR payload and may be re-exported only
  after fresh local authorization.
- No secret appears in command-line arguments where the process list can expose it.
- Command diagnostics are off by default. An explicit live subscriber may receive bounded metadata
  identifying device, caller, command ID, counts, timing, and result; text and secret bodies remain
  prohibited. Minimum transient outcome/deduplication state is never exposed as history.
- Mixed input plans use one daemon-owned writer, command-scoped arming, bounded atomic gestures,
  and a capability-gated result with separately correlated keyboard/mouse neutral evidence. Pointer
  paths, coordinates, button/key lists, and low-entropy plan hashes are payload and never logged.
- Crash reports and diagnostics must be scrubbed before export.

## Security-relevant changes

Any change to authentication, key storage, discovery, network binding, remote exposure, USB
interfaces, update/recovery, arm policy, retry semantics, or parser limits requires:

1. a focused threat-model update;
2. tests for both success and rejection paths;
3. an ADR when it changes a settled decision;
4. evidence that failure leaves the dongle disarmed with all keys released.

## Vulnerability handling

Keep reports private until the owner decides otherwise. A report should include the exact build,
hardware revision, reproduction steps, expected boundary, observed result, and whether unauthorized
input or secret exposure occurred. Never include real Wi-Fi, link, TLS, recovery, or dictated content
in a report.
