# Recipe v1

This document is normative for `keyferry.recipe.v1`, a saved and optionally parameterized input
plan. Routines extend this same format with host-side checkpoints and calibrated pointer steps. It is host-only: the daemon, tailnet forwarding, the wire, and firmware
never see a recipe. A legacy recipe with `actions` expands on the computer that runs it into one ordinary
`keyferry.keyboard-sequence.v1` or `keyferry.input-sequence.v1` request, so it has no authority
that a hand-written sequence lacks.

## Document

A recipe is one strict JSON object matching `recipe-v1.schema.json`: at most 65,536 bytes, unique
keys, integers only, no `null`, nesting at most 8, and unknown fields rejected.

| Field | Rule |
| --- | --- |
| `schema` | Exactly `keyferry.recipe.v1`. |
| `name` | `^[a-z0-9][a-z0-9-]{0,62}$`, not a Windows device name (`con`, `prn`, `aux`, `nul`, `com0`–`com9`, `lpt0`–`lpt9`). A library entry is `<name>.json`. |
| `revision` | Optional author counter, 0–4,294,967,295. Never a content hash. |
| `description` | Optional, at most 200 characters. |
| `parameters` | Optional, at most 16. Each is `{name, type, max_chars}` with name `^[a-z][a-z0-9_]{0,31}$`, unique; `type` is `text`; `max_chars` is 1–4,096 (default 256). |
| `timing` | Optional default keyboard timing, as `keyboard_timing` in Input Sequence v1. It is always bounds-checked; a recipe without a keyboard action expands without it. |
| `start_within_ms` | Optional, 1–5,000 (default 5,000). |
| `actions` | The Input Sequence v1 action vocabulary: `text`, `tap`, `chord`, `ordered_chord`, `wait`, `repeat`, `move_relative`, `click`, `double_click`. Key aliases are accepted. |

A `text` action has exactly one of a non-empty literal `value` or a `param` naming a declared
parameter. Every declared parameter is referenced at least once. A recipe has no arm policy,
command ID, device, unsupported-text policy, or wire profile; those are fixed or chosen per run.

## Validation

Validation parses the document, then compiles it with every parameter at its `max_chars` of `"`,
through the same compiler the run uses, and requires the expanded request body to fit 65,536 bytes.
Every supported parameter character costs one keystroke and `"` has the largest JSON encoding among
them, so a valid recipe cannot exceed a command limit or the body limit with any allowed parameter
value. Import and run both require validation to pass. The planned time that `validate` and
`inspect` report is this worst case, not the time of a particular run.

## Run

A run supplies a fresh UUIDv7 and the parameter values as one JSON object whose keys are exactly
the declared parameter names and whose values are non-empty strings within `max_chars`. When a
recipe declares parameters, keyctl reads that object only from standard input, bounded to 65,536
bytes, and refuses any extra argument.

Expansion substitutes the values, rewrites key aliases to canonical registry names, and produces
a `command-scoped` request with the legacy wire mapping `windows-us`:

- no `move_relative`, `click`, or `double_click`: a keyboard sequence posted once to
  `/v1/devices/{id}/sequences`, valid in USB and Bluetooth keyboard output;
- otherwise: an input sequence posted once to `/v1/devices/{id}/input-sequences`, which requires
  `MOUSE_RELATIVE_V1` (USB keyboard output).

A parameter value supports printable ASCII, TAB, LF, and CR, following the text-stream rule; any
other character, including ESC and backspace, is unsupported. Unsupported characters reject by
default. The caller may select replacement for that run only; each unsupported character then
becomes `?`, and the run reports the replacement count. Literal recipe text is never rewritten.

The result is the ordinary `keyferry.command-result.v2` object on standard output. A run rejected
for a parameter also writes one `keyferry.recipe-cli-error.v1` object with the code and parameter
index to standard error. A run is never retried after a possible start, resumes nothing, and saves
nothing: no parameter values, expansion, compiled plan, or last-run state.

## Library

The library is `KEYFERRY_RECIPE_DIR` if set, otherwise `recipes` under the per-user Keyferry state
directory. Import is its only writer: it validates the source first. Without replacement it creates
`<name>.json` exclusively, which fails if the name exists, so concurrent imports never overwrite
each other; with replacement it writes a complete temporary file and renames it over the entry. A new entry is
written in place, so an interrupted import can leave an entry that fails validation; listing
reports it and `--replace` repairs it. A recipe is explicitly saved user content and may hold literal text: on
Unix the library directory is created owner-only (0700) and each entry is written owner-only
(0600). Listing and inspection report metadata and validation results only, never an action body.

## Errors

Errors are stable codes. A parameter error also carries the zero-based parameter index. No error
contains a parameter value, key array, action body, or source JSON.

| Code | Meaning |
| --- | --- |
| `recipe.json`, `recipe.duplicate_field`, `recipe.limit` | Not one JSON object, a repeated key, or a size or nesting limit. |
| `recipe.schema` | Wrong `schema`, unknown or missing field, `null`, non-integer number, or wrong type. |
| `recipe.name`, `recipe.name_mismatch` | Invalid name, or a library file stem that differs from it. |
| `recipe.description` | Description over 200 characters. |
| `recipe.parameter_limit` | More than 16 parameters. |
| `recipe.parameter_name`, `recipe.parameter_duplicate`, `recipe.parameter_max_chars`, `recipe.parameter_unused` | The indexed parameter is invalid or never referenced. |
| `recipe.parameter_undeclared` | A `param` names no declared parameter. |
| `recipe.text` | A text action lacks exactly one non-empty `value` or `param`. |
| `params.json`, `params.duplicate`, `params.limit` | Run parameters are not one strict JSON object. |
| `params.unknown` | A supplied key is not a declared parameter. |
| `params.missing`, `params.not_string`, `params.empty`, `params.too_long` | The indexed parameter value is absent, not a string, empty, or over `max_chars`. |
| `text.unsupported_character` | With a parameter index: that value has an unsupported character under rejection. |
| `recipe.body_limit` | The expanded request body would exceed 65,536 bytes. |
| `recipe.not_found`, `recipe.unreadable` | The recipe file does not exist, or cannot be read. |
| `recipe.library_unreadable` | The library directory cannot be listed. |
| `recipe.exists` | Import without replacement found an entry with that name. |
| `recipe.write_failed` | Import could not create the library or publish the entry. |

Action shape and compilation failures use the Input Sequence v1 and keyboard-sequence codes, such
as `input.action_type`, `key.unknown`, `chord.duplicate_key`, and `sequence.duration_limit`.

## Routines (same recipe format)

Use `steps` instead of `actions` (exactly one is required), with `target_os` equal to
`macos`, `windows`, `linux`, or `any`. The target OS is declared by the author/caller; it is
never inferred from the controller OS or claimed as observed target identity. A run can assert
`target_os`; a mismatch rejects before input. Existing `actions` recipes retain their compiler.

Metadata: optional `tags` (16 strings, 1..32 characters), `author` (200 characters), and
`verified:false` until live success. After live observation use
`verified:{date:"YYYY-MM-DD",os_version:"observed OS version",success_count:1}`. Verification
metadata is an author's claim, never a hardware gate or automatic promotion. `true` alone rejects.
Parameters add `description`, full-match regex `pattern` (256 bytes, bounded compilation), and
`integer` type with required `minimum`/`maximum` in -127..10000. Text remains bounded by
`max_chars`; routine text rejects unsupported characters and never normalizes. Optional text
parameters (`optional:true`) default to empty, usable in an optional trailing OCR check.
Secret-like parameter names reject, except `type:secure` referenced only by `secure_text.param`.
Secure parameters have no supplied value, default, pattern or bound; runtime values are refused.
Never save secrets in literal text, descriptions, metadata or ordinary parameters either.

| Step `type` | Fields |
| --- | --- |
| `key` | `keys`: 1..14 registry names/aliases; one key taps, multiple form a chord. |
| `type_text` | `text`: supported ASCII, 1..4096 bytes, with `{parameter}` templates. |
| `wait` | `ms`: 1..10000, inside the input command. |
| `move`, `click` | `x,y`: screenshot pixels 0..1279; click adds optional left/right/middle `button`, `double`. |
| `scroll` | `x,y,dx,dy`: detents -127..127, not both zero. |
| `drag` | `from_x,from_y,to_x,to_y`, optional `button`; glides to the start, presses, glides while held, balanced 40 ms hold. |
| `repeat` | `count`: 1..1000; `delay_ms`: 0..10000 between iterations; `steps`: 1..32 input-only leaves. No nested repeat/checkpoints. |
| `expect_text` | Non-empty `query`, `timeout_ms`: 1..30000, optional `region`, `on_fail:stop`. `optional:true` skips only an empty optional marker. |
| `click_text` | As above plus `button`, `double`; requires exactly one OCR match, clicks its center using calibration. |
| `wait_for_change`, `wait_for_stable` | `timeout_ms`, optional screenshot-pixel `region`, `on_fail:stop`. |
| `secure_text` | Optional `param` naming a secure parameter; requests the owner-only dialog on this controller. No secret input or storage. |

Every pointer step glides, never jumps: eased absolute reports from the presumed position to the
target, 120-240 ms by distance, buttons and scrolls after arrival. A pointer stretch over the input
limits splits at step boundaries into consecutive commands that stop at the first failure.

Numeric fields may be an exact `{integer_parameter}` template; text/query fields substitute text
parameters within literals. Keys and regions are fixed. All unknown fields, nulls, non-integers,
unbound templates, unsupported text, malformed bounds and nested repeats reject before input.
Validation compiles each stretch using worst-case parameter sizes/counts through the production
input compiler (256 nodes, 4096 effects, 60 s per command, 65536-byte body). Total planned input
plus checkpoint time is bounded to 180 s; at most 256 top-level steps. Each run checks actual values
and compiles the full contiguous input-only stretch into ONE command before sending that stretch.
It never splits an over-limit stretch silently. Screens/checkpoints run between stretches. Input
receipts say `EMITTED` only for the entire correlated command; individual step completion is not
observable after partial failure. Failure stops immediately with step indices and command evidence,
without payloads or replay. A change check uses the pre-input capture baseline, so a fast transition
is not missed. OCR queries/results/frames stay in memory; receipts contain counts and frame IDs.
A final screenshot is returned once; capture failure preserves prior input receipts.

`secure_text` returns `REQUESTED`, not `EMITTED`, and opens the same masked, expiring owner dialog as
`keyctl secure-text`. A trailing request (or skipped optional desktop marker) returns
`awaiting_owner:true`. Further input cannot run until a screen checkpoint passes. An agent must run
this on the human's logged-in controller desktop; it cannot route a dialog to an unattended desktop.
A checkpoint failure never requests the dialog again or replays preceding clicks/input.

The shared layer is `KEYFERRY_ROUTINE_DIR`, set by the synced skill's launcher to its sibling
`routines` directory. Direct CLI calls also discover the installed `.codex`/`.agents` keyferry skill.
The existing per-user `recipes` library (or `KEYFERRY_RECIPE_DIR`) overrides shared entries by name.
A malformed local override is reported and never falls back. Missing shared storage and invalid
entries are explicit statuses/counts. `recipe list/inspect/validate/import/run` handles this same
format; `recipe import` writes the private layer. `routine list/run/save/validate` and MCP
`routines`, `routine_run`, `routine_save` use that same library/executor. Save validates first and
writes the shared layer using the same exclusive-create / explicit replace primitive as import.
No run updates verification counters or writes any parameter/run history.

MCP `batch` translates its existing input tools to the same steps and executor. Per-action
`repeat`/`delay_ms` repeats that action, optional `settle:true` inserts a stable checkpoint.
Top-level repeat/delay repeats an input-only list; nested repeats reject. Default top-level
`settle:true` observes the final stretch; set false when repeated dismissals may leave the screen
unchanged. Repeats/delays remain one bounded command and never a loop of retried input requests.

Additional stable codes: `recipe.metadata`, `recipe.verification`, `recipe.parameter_pattern`,
`recipe.parameter_bounds`, `recipe.secret_parameter`, `recipe.step`, `recipe.template`,
`recipe.query`, `recipe.checkpoint`, `recipe.duration_limit`, `recipe.routine_executor_required`,
`recipe.routine_required`, `recipe.shared_library_unavailable`, `recipe.target_os_mismatch`,
`recipe.checkpoint_failed`, `recipe.text_not_unique`, `recipe.owner_completion_required`,
`params.pattern`, `params.bounds`. All are payload-free.

## ADR: host routine extension to ADR 0016 H1

Status: implemented under the owner-approved generalized routine objective. The former per-user
import-only library gains a shared skill layer and an explicit shared writer, using the existing
validation/publication primitive. Target OS metadata is now needed because shortcut/navigation
behavior differs by target. Checkpoints require multiple host submissions; each still uses the
existing command-scoped daemon writer and release evidence. There is no firmware macro, persisted
command queue or new authority. Contiguous input is deliberately one command; another controller
can act between checkpoint-separated commands, so a checkpoint is an observation, not a global
exclusive routine lease. Rejecting an over-limit stretch avoids changing its admission/expiry
semantics. Shared definitions and local overrides use the same schema and executable path;
separate routine engines, automatic input retries and saved secret substitution are rejected.
