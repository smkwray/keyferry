# Agent screen control

`keyctl mcp` lets an agent see a target's screen through an HDMI capture dongle and act on it
with the stick's keyboard and pointer. This is the full reference; the
[README](../../README.md#agent-control) has the overview.

## MCP server

`keyctl mcp` exposes a
[stdio MCP server](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
with newline-delimited JSON-RPC, tool discovery, bounded JPEG/PNG images and structured results. It
creates no listener and never opens/restarts the controller app. Start the installed controller
normally; input uses its existing token and sole daemon command writer. Install FFmpeg on the
controllers with capture cards and grant Camera permission on macOS.

Configure your MCP client to launch the installed `keyctl` executable with `["mcp"]` as its
arguments, using the platform installation path in the README. The server uses stdio; no network
listener or per-device executable is needed. Registration needs no device UUID or capture source;
select those through the tools when discovery is ambiguous. Keep explicit device/source overrides
private. Rebuild and reinstall updated packages on each controller before starting a new MCP session.
For reusable routines and their storage configuration, see the [recipe format](../../protocol/recipe-v1.md).

### Device and source selection

With no `--device`, the server selects the single authenticated authorized stick, including one
held by another owner controller over the tailnet. A unique authenticated `POINTER_EXTENDED_V1`
stick is preferred when other keyboard-only sticks are present. Ambiguity never selects by list
position: call `list_devices` and `select_device`. Action tools require a selected device.
With no `--source`, use the single recognized local HDMI capture device; if none is local,
use the single recognized remote source. Multiple candidates require `list_capture_sources` and
`select_capture_source`. `status` reports the exact selections and whether each was automatic,
an argument override, or a selection tool. `--device UUID` and `--source NAME_OR_ID` remain available;
global `--url` and `--token-file` select the existing loopback daemon.

## Capture

The controller with the capture card owns one continuous FFmpeg stream per selected card, shared
by local and remote clients. Remote frames and OCR travel through the existing owner-mTLS tailnet
API. Eyes and hands may be on different controllers: both ends reprove the configured stick at
its actual holder, and the capture peer serves its own frames directly. There is no frame relay
chain or new listener. Capture source IDs include the authenticated controller installation;
calibration binds that source to the exact stick, even when input and capture are remote.

The read-only HTTP capture API is:

| Route | Listener | Response |
| --- | --- | --- |
| `GET /v1/capture/sources` | loopback bearer | local and authenticated peer inventories; local/peer discovery errors |
| `POST /v1/capture/frame` | loopback bearer | local latest frame or one direct owner-mTLS peer read |
| `GET /v1/devices/{id}/capture/sources` | existing owner-mTLS | that controller's local capture inventory only |
| `POST /v1/devices/{id}/capture/frame` | existing owner-mTLS + fresh device proof | that controller's latest frame and optional native OCR |

Frame JSON requests require `device` and `source`; optional `after`/`epoch` wait for a fresh serial
within the same daemon epoch, `region` crops native frame pixels, and `ocr:true` returns OCR boxes
from that exact frame. Without `max_width` the image fits 1280x1280 (the agent view); `max_width`
2..1920 bounds only the width, so 1920 returns native 1080p. OCR always reads native pixels and
reports boxes in returned-image pixels. Responses include base64 PNG, dimensions,
native dimensions, region, serial, daemon epoch, generation, frame age and capture status. Frames
are memory-only, PNG is bounded to 8 MiB and response JSON to about 11.7 MiB. A service admits one
read at a time, at most ten frame requests/second and four capture streams. MCP uses full-frame
geometry; direct API callers must account for region/scale before driving a pointer.

One continuous ffmpeg pipe of unfiltered PNG frames retains the latest RGB frame, scaled
proportionally to at most 1920 pixels on each axis; recognized cards stream a pinned native mode
from one table (the Hagibis MS2130: 1920x1080 YUYV at 30 fps). MCP screenshots, OCR boxes, pointer
coordinates and routines use the 1280-pixel agent view; OCR and calibration read native pixels.
Comparison frames are bounded and memory-only. Capture faults clear the latest frame, report an explicit error
and restart after backoff; counters remain visible. A stalled stream is a capture error, not a
stable screen. Capture children belong to the daemon and stop when its capture service is dropped.
`keyctl capture frame --out PATH` retains its independent one-shot behavior.

## Calibration

First call `status` and `screenshot`, locate the cursor tip, then call `calibrate` with its
`cursor_x,cursor_y` on a static, harmless approved target. Use `mode:"screen"` to bind without
movement. Take a fresh `screenshot` before subsequent pointer input. The target HDMI output must be its only display or mirror the main
display. Calibration sends eight absolute pointer probes (no clicks), isolates the cursor in
three-frame differences, fits independent affine axes and verifies another position. It handles
letterbox/pillarbox, scaling and modest overscan. Animation, ambiguous/missing cursor, rotated axes or
excessive residuals fail explicitly. "Cursor not seen: capture may show a different machine" is a
binding failure. Calibration is observational, not cryptographic proof of machine identity.

Only geometry is persisted per device UUID and resolved capture source in `capture-geometry` under
the user's Keyferry state directory. Persisted geometry is inspectable; each new session must reprove
binding. Resolution changes or capture restarts invalidate binding and require a fresh screenshot.
Recalibrate after any HDMI/display arrangement or stick/target change, even at the same resolution.
Coordinates are **screenshot pixels**, mapped to normalized HID and rounded to 0..32767 by the existing
compiler; points outside the measured active rectangle reject. Calibration is session-scoped
through MCP so the observed cursor and its capture stay together.

The current pointer position stays in session memory. After starting a session or changing sticks,
take a screenshot and supply its observed cursor tip as `cursor_x,cursor_y` to `calibrate`. Never
guess a starting position. Without it, pointer input and probe calibration refuse before sending
input; `mode:"screen"` can still bind without motion. This replaces the saved-position/centre-jump
fallback and preserves glides from the observed position.

Pointer tools refuse devices without authenticated `POINTER_EXTENDED_V1` (0x08000000); keyboard tools
remain available. Explicit per-call `uncalibrated:true` bypasses binding and uses full-frame linear
mapping, flagged in results. It still requires the capability and a fresh screenshot. This override
accepts the risk of driving a different target or a cropped/scaled display.

## Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `screenshot` | optional `format` = jpeg/png | image (JPEG by default), screenshot/native geometry, frame ID/age and capture status; no file export |
| `move` | integer `x,y`; optional `glide_ms`, `uncalibrated` | absolute move receipt |
| `click` | `x,y`; optional `button` = left/right/middle, `double`, `glide_ms`, `uncalibrated` | move then single/double click receipt |
| `drag` | `from_x,from_y,to_x,to_y`; optional `button`, `glide_ms`, `uncalibrated` | balanced atomic drag, 40 ms hold |
| `scroll` | `x,y,dx,dy`; optional `glide_ms`, `uncalibrated` | integer detents, each -127..127, not both zero |
| `type_text` | `text` (1..4096 supported ASCII characters) | ordinary US-mapped text; unsupported characters reject |
| `key` | `keys` (1..14 names/aliases) | tap or balanced chord through the `keyctl keys` table |
| `wait_for_stable` | `timeout_ms` (1..30000); optional `region` | matched after at least 3 fresh frames below 0.002 mean normalized RGB difference for 300 ms; otherwise timed_out |
| `wait_for_change` | same | matched above 0.01 mean difference from the initial frame; otherwise timed_out |
| `find_text` | optional `query` | capture-controller OCR line boxes in screenshot pixels, case-insensitive substring filter |
| `calibrate` | optional `mode` = probe/screen, observed `cursor_x,cursor_y` | binding and mapping; fresh sessions require the observed cursor position before any pointer motion; persists geometry only |
| `status` | none | chosen device/source, selection reasons, authenticated state, capture errors/restarts and binding |
| `list_devices` / `select_device` | none / exact `device` UUID | authorized inventory / choose authenticated stick and clear binding |
| `list_capture_sources` / `select_capture_source` | none / exact `source` ID | local/remote inventory / choose capture source and clear binding |

Optional `glide_ms` requests HID travel time: integer 120..5000 in multiples of 10 for
`move`, `click` and `scroll`; 120..280 for each leg of `drag` (approach and held drag).
Higher values slow the same eased path. Omission preserves the distance-based 12..24 samples
(about 120..240 ms). For example, `move {"x":800,"y":400,"glide_ms":1000}`.
Network, command/chunk neutral reports, clicks and settling add end-to-end latency.
This is per action, with no saved speed preference or firmware change. Older installed runtimes
may reject the field; rebuild/reinstall before relying on it. Physical qualification of this option
remains open.

A region is `{x,y,width,height}` in screenshot pixels, entirely inside the frame. Positive `dy` is
wheel-up, positive `dx` pan-right; target natural-scrolling policy can invert it. Schemas reject
unknown fields, null optionals and invalid ranges. Keyboard actions use the existing alias table and
reject unsupported ASCII controls. Ordinary text only: **secrets stay in the owner-only secure-text
dialog**. A routine can request the owner dialog; its content never enters MCP.

## Input guarantees

Every action submits once through `/input-sequences` with existing authentication, command-scoped
arm, admission and release guarantees. No cross-call held button, alternate writer or input retry
exists. Failed/possible-start UNKNOWN results return `isError:true` with command IDs and evidence.
Inspect/reconcile uncertain outcomes; never replay them. `EMITTED` proves emission, not visible target
behavior. MCP cancellation reaches the existing daemon cancellation mechanism.

Actions, batches and routines return receipts and observation metadata by default, without an
image. Internal fresh-frame observation and settling still run. Use `return_screenshot:true` on
the final action of a UI stretch, or call `screenshot` when a visual decision needs it; avoid both
for the same checkpoint. Neither emission nor `settled:true` proves the intended application
result. Wait tools and OCR can check intermediate steps without adding images to the conversation.

## Retention and OCR

Keyferry does not persist an execution history, submitted text, key/button lists, coordinates,
screens or OCR. MCP has no screenshot file export. The explicit CLI `capture frame --out` is for
deliberate exports; temporary inspection files must be removed as soon as inspection finishes.
Saved recipes are intentional reusable configuration, not a record of executions: use parameters
for task-specific text and never write run values or captured screens into recipes or reports.

MCP clients and model providers can retain tool arguments (including typed text and keystrokes),
results and images in their own conversations. Keyferry cannot erase or prevent that recording.
Do not describe an agent-mediated run as having no retained history unless the client and provider
also enforce it. Secrets belong to the owner-only secure-text dialog, outside MCP arguments.

OCR runs on the capture controller and uses its local Windows.Media.Ocr language packs, with no
cloud recognizer or downloaded model. A macOS or Linux agent can use OCR from a Windows capture
controller. Capture controllers on macOS/Linux report `ocr.unsupported_platform` explicitly.
Black/blue no-signal frames remain valid screenshots and may be stable; they are not target proof.
Exact firmware/OS physical gates remain OPEN until the hardware window qualifies them.

## One-shot CLI loop

The original one-shot CLI loop is also available. Connect the target's HDMI output to a USB
HDMI/UVC capture dongle on the controller host. `keyctl capture list` returns video source names
and platform IDs as JSON. Install [FFmpeg](https://ffmpeg.org/download.html) on PATH; capture uses
its [dshow, avfoundation or v4l2 backend](https://ffmpeg.org/ffmpeg-devices.html). On macOS, grant
Camera permission to the terminal/app in System Settings → Privacy & Security. Default selection
requires one recognized capture device; unknown or ambiguous sources require `--source NAME_OR_ID`
from the list. Listing does not probe capture modes or include supported sizes.

The loop is **capture → inspect/decide → input once → capture to verify**:

```text
keyctl capture frame --out before.png --source "Hagibis" --size 1920x1080
keyctl devices
keyctl status DEVICE
keyctl input-sequence --describe
keyctl input-sequence --validate --input action.json
keyctl input-sequence DEVICE --input action.json
keyctl capture frame --out after.png --source "Hagibis" --size 1920x1080
```

Every input needs the exact authenticated, idle/disarmed device; the daemon arms it for that command.
Input Sequence v2 uses absolute positions, wheel/pan and balanced drag on devices with
POINTER_EXTENDED_V1. Older images retain v1 relative-count motion, which undergoes target OS
acceleration and cannot be interpreted as pixels. Mixed keyboard actions require
`keyboard_profile:"windows-us"`; validate locally. Inspect the installed CLI
`input-sequence --describe` and authenticated firmware capabilities.
Never automatically resend input: missing responses or possible-start losses are **UNKNOWN**.
`EMITTED` proves emission; a subsequent capture verifies the visible target result.

Frames may show secrets. Capture writes one PNG **only to `--out`**, refuses existing paths, keeps
intermediate pixels in memory, and sends no image, statistics or capture path to the daemon.
Delete frames privately after inspection. `--size WxH` selects the input mode; optional
`--scale WxH` reduces output size (each dimension 1…4096); translate coordinates back to the full
frame before absolute input. The JSON `keyferry.capture-frame.v1` reports path, source, output
width/height, host UTC `captured_at`, `signal` and mean Rec.709 luma (0…255). Near-uniform black/blue
is `no-signal`; this heuristic can also label a blank real screen and cannot prove HDMI sync.
Each FFmpeg invocation is bounded to 15 seconds and killed on timeout, without retry or temp frames.
`capture --help` lists JSON error/exit conventions; `no-signal` itself is successful capture (exit 0).
