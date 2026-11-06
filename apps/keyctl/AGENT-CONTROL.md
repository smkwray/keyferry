# Agent screen control

`keyctl mcp` lets an agent see a target's screen through an HDMI capture dongle and act on it
with the stick's keyboard and pointer. This is the full reference; the
[README](../../README.md#agent-control) has the overview.

## MCP server

`keyctl mcp` is a
[stdio MCP server](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
with tool discovery, bounded JPEG/PNG images and structured results. It opens no network listener
and never starts or restarts the controller app: start the installed controller normally. Install
FFmpeg on the controllers with capture cards and grant Camera permission on macOS.

Configure your MCP client to launch the installed `keyctl` executable with `["mcp"]` as its
arguments, using the installation path in the README. Registration needs no device UUID or capture
source; select those through the tools when there is more than one. For reusable routines, see the
[recipe format](../../protocol/recipe-v1.md).

### Device and source selection

With no `--device`, the server selects the single authenticated stick, including one held by
another of your controllers over Tailscale. When several sticks are present, a single stick with
extended pointer support is preferred over keyboard-only sticks. If the choice is still ambiguous,
the server never picks by list position: call `list_devices` and `select_device`. Action tools
require a selected device.

With no `--source`, the server uses the single recognized local HDMI capture device; if none is
local, it uses the single recognized source on another controller. With several candidates, call
`list_capture_sources` and `select_capture_source`. `status` reports the selections and how each
was made. `--device UUID` and `--source NAME_OR_ID` set them explicitly; the global `--url` and
`--token-file` options select the local daemon.

## Capture

The controller with the capture card streams it continuously through FFmpeg and serves frames to
local and remote clients. The capture card and the stick can be on different controllers;
calibration binds the capture source to the exact stick. Frames and OCR stay in memory.

Screenshots, OCR boxes, pointer coordinates and routines use a 1280-pixel agent view of the frame;
OCR and calibration read the full-resolution frame. A capture fault clears the latest frame,
reports an error and restarts after a short delay. A stalled stream is reported as a capture error,
not as a stable screen.

## Calibration

First call `status` and `screenshot`, locate the cursor tip, then call `calibrate` with its
`cursor_x,cursor_y` on a static, harmless screen. `mode:"screen"` binds without moving the pointer.
Take a fresh `screenshot` before further pointer input. The target's HDMI output must be its only
display or mirror the main display.

Calibration sends eight absolute pointer moves (no clicks), finds the cursor in the captured
frames, fits the mapping and checks it at another position. It handles letterboxing, scaling and
modest overscan. Animation, a missing or ambiguous cursor, rotated axes or a poor fit fail with an
error. "Cursor not seen: capture may show a different machine" means the capture is not bound to
this stick. Calibration is an observation, not proof of which machine is on screen.

Only the geometry is saved, per device and capture source, in `capture-geometry` under the user's
Keyferry state directory. Each new session must calibrate again. A resolution change or capture
restart needs a fresh screenshot; recalibrate after any change to the HDMI or display arrangement,
the stick or the target. Coordinates are **screenshot pixels**; points outside the measured screen
area are rejected.

The pointer position is known only from the observed cursor. Never guess a starting position:
without `cursor_x,cursor_y`, pointer input and probe calibration refuse before sending anything,
while `mode:"screen"` can still bind without motion. Glides start from the observed position.

Pointer tools need a stick with extended pointer support; keyboard tools work on every stick.
A per-call `uncalibrated:true` skips binding and maps the full frame linearly, and results flag it.
It still needs a fresh screenshot, and it accepts the risk of driving a different target or a
cropped or scaled display.

## Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `screenshot` | optional `format` = jpeg/png | image (JPEG by default), geometry, frame ID/age and capture status; no file export |
| `move` | integer `x,y`; optional `glide_ms`, `uncalibrated` | absolute move receipt |
| `click` | `x,y`; optional `button` = left/right/middle, `double`, `glide_ms`, `uncalibrated` | move then single/double click receipt |
| `drag` | `from_x,from_y,to_x,to_y`; optional `button`, `glide_ms`, `uncalibrated` | complete drag with a 40 ms hold |
| `scroll` | `x,y,dx,dy`; optional `glide_ms`, `uncalibrated` | integer detents, each -127..127, not both zero |
| `type_text` | `text` (1..4096 supported ASCII characters) | ordinary US-mapped text; unsupported characters reject |
| `key` | `keys` (1..14 names/aliases) | tap or chord, using the `keyctl keys` names |
| `wait_for_stable` | `timeout_ms` (1..30000); optional `region` | matched after at least 3 fresh frames below 0.002 mean normalized RGB difference for 300 ms; otherwise timed_out |
| `wait_for_change` | same | matched above 0.01 mean difference from the initial frame; otherwise timed_out |
| `find_text` | optional `query` | OCR line boxes in screenshot pixels, case-insensitive substring filter |
| `calibrate` | optional `mode` = probe/screen, observed `cursor_x,cursor_y` | binding and mapping; saves geometry only |
| `status` | none | chosen device/source, how they were chosen, connection state, capture errors and binding |
| `list_devices` / `select_device` | none / exact `device` UUID | authorized sticks / choose one and clear binding |
| `list_capture_sources` / `select_capture_source` | none / exact `source` ID | local and remote sources / choose one and clear binding |

Optional `glide_ms` sets the pointer travel time: 120..5000 ms in multiples of 10 for `move`,
`click` and `scroll`, and 120..280 for each leg of `drag` (approach and held drag). Without it,
travel takes about 120..240 ms depending on distance. For example,
`move {"x":800,"y":400,"glide_ms":1000}`. Network delay, clicks and settling add to the total time.

A region is `{x,y,width,height}` in screenshot pixels, entirely inside the frame. Positive `dy`
scrolls up and positive `dx` pans right; the target's natural-scrolling setting can invert them.
Unknown fields, nulls and out-of-range values are rejected. Ordinary text only: **secrets stay in
the owner-only secure-text dialog**. A routine can request that dialog; its content never enters
MCP.

## Input guarantees

Every action is submitted once, with the daemon's normal authentication, arming and key-release
guarantees. No button stays held between calls, and input is never retried. A failed or uncertain
(`UNKNOWN`) result returns `isError:true` with its command IDs: inspect and reconcile it, never
replay it. `EMITTED` means the stick sent the input, not that the target did what you intended.
Cancelling an MCP call cancels the running command.

Actions, batches and routines return receipts without an image by default. Use
`return_screenshot:true` on the last action of a UI step, or call `screenshot` when a visual
decision needs it, but not both for the same check. Neither `EMITTED` nor `settled:true` proves the
intended result. Wait tools and OCR can check intermediate steps without adding images to the
conversation.

## Retention and OCR

Keyferry does not save an execution history, submitted text, keys, coordinates, screens or OCR.
MCP has no screenshot file export. `keyctl capture frame --out` writes a file only when you ask for
one; delete it when you are done, since frames can show secrets. Recipes are saved configuration:
use parameters for task-specific text and never put run values or captured screens in them.

MCP clients and model providers can retain tool arguments (including typed text and keystrokes),
results and images in their own conversations. Keyferry cannot erase or prevent that.

OCR runs on the capture controller with its local Windows.Media.Ocr language packs, with no cloud
service or downloaded model. An agent on macOS or Linux can use OCR from a Windows capture
controller; capture controllers on macOS or Linux report `ocr.unsupported_platform`. A black or
blue no-signal frame is a valid screenshot and may count as stable, but it does not show the
target. Agent control is not yet tested on every firmware and target operating system combination.

## One-shot CLI loop

Without MCP, connect the target's HDMI output to a USB HDMI/UVC capture dongle on the controller.
`keyctl capture list` returns video source names and platform IDs as JSON. Install
[FFmpeg](https://ffmpeg.org/download.html) on PATH; capture uses its
[dshow, avfoundation or v4l2 backend](https://ffmpeg.org/ffmpeg-devices.html). On macOS, grant
Camera permission to the terminal or app in System Settings → Privacy & Security. With one
recognized capture device it is used by default; otherwise pass `--source NAME_OR_ID` from the
list. Listing does not report supported sizes.

The loop is **capture → inspect and decide → input once → capture to verify**:

```text
keyctl capture frame --out before.png --source CAPTURE_NAME --size 1920x1080
keyctl devices
keyctl status DEVICE
keyctl input-sequence --describe
keyctl input-sequence --validate --input action.json
keyctl input-sequence DEVICE --input action.json
keyctl capture frame --out after.png --source CAPTURE_NAME --size 1920x1080
```

Every input needs the exact authenticated, idle and disarmed device; the daemon arms it for that
command. Sticks with extended pointer support accept absolute positions, wheel/pan and drag. Older
firmware supports only relative motion, which the target's pointer acceleration changes, so it
cannot be read as pixels. Actions that include keyboard input need `keyboard_profile:"windows-us"`;
validate locally first. `input-sequence --describe` and `keyctl status` show what the installed
CLI and the stick support. Never resend input automatically: a missing response or a lost
connection after submission is **UNKNOWN**. Capture again to see the result.

Frames may show secrets. Capture writes one PNG **only to `--out`**, refuses existing paths and
keeps intermediate pixels in memory. `--size WxH` selects the capture mode; optional `--scale WxH`
reduces the output size (each dimension 1…4096), so translate coordinates back to the full frame
before absolute input. The JSON result (`keyferry.capture-frame.v1`) reports path, source, output
width/height, UTC `captured_at`, `signal` and mean Rec.709 luma (0…255). A near-uniform black or
blue frame is `no-signal`; a blank real screen can also be labeled that way. Each FFmpeg run is
limited to 15 seconds and is not retried. `capture --help` lists the JSON errors and exit codes;
`no-signal` is a successful capture (exit 0).
