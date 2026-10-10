# Input Sequence v1

This document is normative for the capability-gated mixed keyboard/relative-pointer extension. It
does not modify legacy command bodies or the existing keyboard and provisioning USB interfaces. Its
[Key names](#key-names) section also governs key names in `keyferry.keyboard-sequence.v1`
(`keyboard-sequence-v1.schema.json`); nothing else here changes that schema.

## Public model

`keyferry.input-sequence.v1` is accepted only at
`POST /v1/devices/{device_id}/input-sequences` and only when authenticated host and device both
offer `MOUSE_RELATIVE_V1`. Every request uses canonical UUIDv7 identity, `command-scoped` arm, a
1–5,000 ms first-start deadline, and the strict schema in `input-sequence-v1.schema.json`.

Actions are profile-mapped `text`, named physical `tap`, bounded one-report `chord`, bounded
`ordered_chord`, released `wait`,
non-nested bounded `repeat`, signed-count `move_relative`, complete single `click` of
`button_1` or `button_2`, and complete `double_click`. Relative counts are not pixels or screen
coordinates. The contract has no absolute position, wheel, pan, drag, held button, extra button,
raw report, consumer control, target observation, or application-success field.

`double_click` takes exactly the `click` fields, defaults, and 10–100 ms bounds. It compiles to one
atomic unit of two identical `MOUSE_CLICK` records that never spans chunks, costs
2 × (20 + hold + gap) ms, and counts as two effects. The wire carries only those two existing
records; there is no new record kind. The interval between the clicks is the first click's release
gap.

`ordered_chord` holds 2–6 named keys in listed order, waiting 20 ms between key-down edges,
then releases them in reverse order with 10 ms between releases and an all-keys-up terminal
record. The final key uses the selected key-down timing; the final release uses the selected
release gap. It is one atomic gesture and cannot span chunks. Use it for non-modifier prefixes
such as Space or CapsLock whose hotkeys require a distinct first key-down event. The existing
`chord` remains a simultaneous single-report gesture.

All JSON keys are unique. Unknown fields/types, null optionals, floats/exponents, invalid enums,
overflow, unsupported characters/keys, and resource-limit violations reject before ARM without
echoing source material. `keyboard_profile` is exactly `windows-us` and is required iff an expanded
keyboard gesture exists. `keyboard_timing` follows the same rule. `windows-us` is the unchanged
legacy wire mapping id: the one US-ASCII HID mapping, valid for Windows US and for a Mac identified
as ANSI with the U.S. or ABC input source.

## Key names

A key in `tap`, `chord`, or `ordered_chord` of this schema or `keyferry.keyboard-sequence.v1` is a
canonical name from `keyboard-key-registry-v1.csv` or an alias below. Names are case-sensitive
uppercase. An alias is never a registry row; it resolves to exactly its canonical key, so the
compiled chunks and fingerprint are identical to the canonical form. Chord duplicates are detected
on the resolved key: `["LEFT_GUI","COMMAND"]` rejects with `chord.duplicate_key`. The daemon
rewrites aliases to canonical names, keeping the command ID, before forwarding a sequence to the
holding controller, so a holder that predates aliases still accepts it. Canonical names are longer:
a forwarded body near the size limit can exceed it and is rejected before any input.

| Aliases | Canonical key |
| --- | --- |
| `COMMAND`, `CMD`, `LEFT_COMMAND`, `LEFT_CMD`, `WIN`, `WINDOWS`, `GUI`, `META`, `SUPER` | `LEFT_GUI` |
| `RIGHT_COMMAND`, `RIGHT_CMD` | `RIGHT_GUI` |
| `OPTION`, `OPT`, `LEFT_OPTION`, `LEFT_OPT`, `ALT` | `LEFT_ALT` |
| `RIGHT_OPTION`, `RIGHT_OPT` | `RIGHT_ALT` |
| `CTRL`, `CONTROL` | `LEFT_CONTROL` |
| `SHIFT` | `LEFT_SHIFT` |
| `RETURN` | `ENTER` |
| `ESC` | `ESCAPE` |

## Wire model

The frame protocol remains 1.0. New identifiers are generated from `messages.yaml`. Command kind
`EXECUTE_INPUT_CHUNK_V1` uses the existing 55-byte envelope and a body beginning with
`chunk_index:u16LE, chunk_count:u16LE`, followed by closed action records. Each chunk contains at
most 64 records, 183 action bytes after the four-byte prefix, and 500 ms planned time. It ends with
exactly one `NEUTRAL_ALL` record. Public plans contain at most 256 chunks, 60 seconds planned input,
and 120 seconds wall time.

`MOUSE_MOVE_RELATIVE` carries signed i16 X/Y totals in −4,096…4,096, excluding `(0,0)`. Firmware
splits each gesture into signed i8 reports in −127…127 using:

`part(d,i,N) = sign(d) * (floor(i*abs(d)/N) - floor((i-1)*abs(d)/N))`,

where `N = ceil(max(abs(dx),abs(dy))/127)`. Equal adjacent parts remain distinct one-use movement
tokens and are never coalesced or retried after USB acceptance. `MOUSE_CLICK` carries button usage
1 or 2 and independent 10–100 ms hold/gap values. Movement is forbidden while any Keyferry key or
button is held.

`INPUT_COMMAND_RESULT_V1` is exactly 21 bytes:

```text
command_id[16] | result:u8 | neutral_mask:u8 | effect_flags:u8 | reason:u16LE
```

Neutral-mask bit 0 is a matching post-effect keyboard-zero completion; bit 1 is a matching mouse
`[0,0,0]` completion. Effect bit 0 means input may have occurred. Other bits are zero. Evidence is
bound to command/control identity, frame sequence, authenticated epoch, interface, report bytes,
logical token, and USB attachment generation. Legacy results never prove a new command complete.

## Identity, replay, and outcomes

The normalized plan fingerprint is SHA-256 over:

```text
"keyferry.input-sequence.v1\0hid-relative-8-v1\0"
|| SHA256("windows-us" or "none")
|| start_within_ms:u32LE || command_scoped:01 || chunk_count:u16LE
|| each(body_length:u16LE || complete_chunk_body)
```

Command ID and timestamps are excluded. The daemon deduplicates retained IDs before mutation. The
endpoint additionally retains the 64 most recently admitted public IDs per authenticated epoch and
requires exact next chunk index/count/profile. Admitting a new ID ends every earlier one, so the
oldest (closed) ID makes room and admission never fails for capacity: a session outlives any number
of commands. No session rotation continues an uncertain command.

`EMITTED` requires all intended transfers and the final dual-neutral completion. `ABORTED` permits
prior effects but requires same-generation dual-neutral evidence. `REJECTED` proves no unresolved
possible input was admitted. Otherwise the result is `UNKNOWN`, the ID is retained, and no automatic
retry occurs. USB completion is not target-application acknowledgement.
