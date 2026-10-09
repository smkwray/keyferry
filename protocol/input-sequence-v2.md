# Input Sequence v2: F1-W pointer slice and ADR 0016 amendment

Status: off-device implementation; physical Windows/macOS qualification OPEN.
This narrow amendment follows the owner's 2026-10-09 pointer-slice instruction.
Consumer/system, keyboard LEDs, BOOT latch, wake and BLE mouse are separate lanes.

## USB personality

Opt-in `KEYFERRY_POINTER_EXTENDED=ON` replaces IF2 with HID class 03/00/00,
IN 0x83, 8-byte maximum packet, 10 ms polling. IF0 boot keyboard, IF1 vendor
provisioning and IF3 read-only MSC keep their interfaces/endpoints. Relative
report 1 is `[1,buttons(5),x:i8,y:i8,wheel:i8,pan:i8]`; absolute report 4 is
`[4,buttons(5),x:u16LE,y:u16LE,wheel:i8]`, Generic Desktop X/Y absolute 0..32767.
Only usages 1..3 are public. Consumer AC Pan is a relative pointer axis; no
Consumer Control or System Control reports are declared. The non-boot IF2
**drops the pre-OS BIOS boot mouse**; the boot keyboard remains.

AtomS3 Lite uses the same IF0/IF1/IF2, reports, capability and shared executor,
with no IF3/MSC, PSRAM or file handoff. Its board build defaults to extended
pointer and rejects a legacy-pointer or MSC configuration. Its USB-HID PID is
0x4004, bcdDevice 0x0102; Waveshare remains 0x4008 with MSC. Atom first install
uses the board's 3 MiB factory slot at 0x10000 after exact-unit recovery proof;
the Waveshare app-only procedure below does not apply to Atom. Static resource
fit does not close Atom runtime TLS heap, USB attach or target-input gates.

The existing personality PID is retained, with bcdDevice 0x0101 -> 0x0102.
No public PID allocation is requested by this lane. Microsoft's USB flags key
includes VID, PID and revision, and revision participates in hardware IDs:
[device registry](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-specific-registry-settings),
[standard descriptors](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/standard-usb-descriptors).
This gives the revised descriptor a distinct revision/usbflags identity, but
is **not proof** that every cached composite/HID child re-enumerates correctly.
Require a full detach/reattach and exact descriptor capture on both previously
used and fresh Windows/macOS paths; stop if the old boot descriptor remains.
Do not delete arbitrary HID devices. The report design follows ordinary Generic
Desktop absolute mouse axes, as used by
[PiKVM](https://github.com/pikvm/kvmd/blob/master/kvmd/apps/otg/hid/mouse.py).
macOS mapping, display arrangement, capture crops and host pointer policy remain
physical qualification questions. USB emission does not prove pixel placement.

## Public contract

Use `schema: keyferry.input-sequence.v2` at the existing `/input-sequences`
endpoint through the sole daemon writer. All V1 JSON/wire/vector bytes remain
unchanged. The new image advertises `POINTER_EXTENDED_V1` (0x08000000) instead
of `MOUSE_RELATIVE_V1`; a new host can also compile V1 gestures to V2 for that
image. Old images receive V1 only. Extended requests fail before ARM with
`pointer.capability_required` when the new capability is absent. Direct BLE HID
remains keyboard-only, and therefore never advertises the pointer capability.

New strict actions (unknown/duplicate/null fields still reject):

- `move_absolute`: either `x,y` finite normalized numbers in 0..1, or
  `x_px,y_px,frame_w,frame_h` integers, dimensions 2..65536 and pixels strictly
  inside the supplied frame. Round `normalized * 32767`; pixels use
  `round(pixel * 32767 / (dimension - 1))`. No geometry is inferred.
- `scroll`: required integer `vertical,horizontal` detents, each -127..127;
  `(0,0)` rejects. Positive vertical is wheel-up; positive horizontal AC Pan
  is right. OS natural-scrolling/remapping policy is outside this contract.
- `click`/`double_click`: Button 1/2/3, independent hold/gap 10..100 ms.
- `button_down`/`button_up`: one Button 1/2/3 held at a time; matching balanced
  edges in this request, one atomic chunk, at most 470 ms planned held span.
  Only absolute movement and bounded waits may intervene. No keyboard,
  scrolling, relative motion, nested press or cross-request held state.
- `drag`: `{type:drag,button:button_1,x:0.8,y:0.6,hold_ms:40}` means down at
  the current pointer, absolute move to the explicit destination, wait, up.
  Pixel destination fields are supported too. First move to a known start
  point in the same request when needed. This is one indivisible wire unit.

Repeats retain V1 leaf grammar. V2 middle clicks/new pointer actions are
currently top-level only. Resource limits, UUIDv7, command-scoped arm, start
expiry and never-resubmit policy retain V1 semantics. V2 fingerprints wrap the
unchanged canonical V1 fingerprint in SHA256 over
`keyferry.input-sequence.v2\0pointer-extended-v1\0 || v1_fingerprint`.

## Wire and safety

Generated identifiers: execute 0x07, cancel 0x08, release 0x09; result message
0x5B. Existing 55-byte command envelope and four-byte chunk prefix remain.
V2 accepts existing V1 action records (middle click additionally allowed), plus:

| Tag | Payload |
| --- | --- |
| 0x08 absolute | x:u16LE, y:u16LE, each 0..32767 |
| 0x09 scroll | wheel:i8, pan:i8, -127..127, not both zero |
| 0x0A down | button usage:u8, 1..3 |
| 0x0B up | matching button usage:u8, 1..3 |

V1 parsers reject these records. Firmware validates the full V2 chunk, balanced
button state and budgets before execution. New result is exactly 22 bytes:
`command_id[16],result:u8,neutral_required:u8,neutral_mask:u8,effect_flags:u8,reason:u16LE`.
This slice requires roles 0x03: keyboard and pointer only. Pointer proof requires
matching **both** report 1 zero and report 4 buttons/wheel zero at the retained
absolute position, after matching keyboard zero. Never zero absolute coordinates
as a release side effect. A button-up similarly drains both report IDs before
any following gesture. V2 neutral costs 30 ms, button-up 20 ms, click transfers
30 ms plus hold/gap; all chunks stay <=500 ms. V1 retains its 20 ms neutral,
10 ms single release and original gesture costs and bytes.

Position/wheel/pan are consumed one-use tokens at TinyUSB acceptance, never
cached as events for GET_REPORT, idle, release or retry. GET_REPORT exposes
only current buttons, retained absolute coordinates and zero relative deltas.
Held keys/buttons share the original independent 2-second watchdog deadline,
which movement or role changes never renew. Every cancellation, malformed frame,
executor fault, watchdog, disconnect, reset/reconnect requests all neutral roles;
reconnect starts disarmed and never resumes a command. Lost possible-start results
remain UNKNOWN even if a later generation is neutral. Correlation includes
report ID, exact serialized bytes/length, token, epoch and attachment generation.

## Off-device and physical gates

`python scripts/check.py`, generated-registry check, cargo fmt/clippy/workspace
suite, native C++ suite and `check_hil_pointer.py --build-dir BUILD` gate source,
protocol and the exact image. The legacy checker remains separate and checks
its unchanged boot descriptor. Frozen image requires SHA256/size for BIN/ELF,
map/static RAM/partition reserve, source commit, pinned locks, config and app-only
installer Plan. Build-time static RAM is not measured runtime free heap; obtain
runtime heap/internal-RAM observations during owner-authorized qualification.

The parent combines the Wi-Fi diagnostic lane and rebuilds before any reserved
write. An exact-unit app-only Plan, retained rollback image and new approval
are prerequisites. Physical gates stay OPEN until the same final image passes
Windows/macOS corners/centre, right/middle clicks, wheel/pan, drag and disconnect
release on an owner-approved idle target. No hardware contact belongs to this lane.
