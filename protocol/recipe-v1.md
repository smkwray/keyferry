# Recipe v1

This document is normative for `keyferry.recipe.v1`, a saved and optionally parameterized input
plan kept on one computer. It is host-only: the daemon, tailnet forwarding, the wire, and firmware
never see a recipe. A recipe expands on the computer that runs it into one ordinary
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
