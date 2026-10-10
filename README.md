<div align="center">
  <img src="apps/keyferry/assets/icons/png/keyferry-256.png" width="120" alt="Keyferry"/>
  <h1>Keyferry</h1>
  <p>Send text through a portable USB or Bluetooth keyboard, and hand off files over USB.</p>
</div>

Keyferry is an ESP32-S3 stick that sends keyboard input to a computer (the *target*) over USB or
Bluetooth. USB keyboard mode also provides mouse input. The stick needs USB power in either mode,
but the target needs no Keyferry app. From a trusted Windows or macOS computer (the *controller*),
you send commands to the stick over Wi-Fi or, in USB keyboard mode, a separate Bluetooth control
link. If another authorized controller holds the stick, Keyferry can route through it over Tailscale.
File-capable firmware also provides a small read-only drive to the computer physically connected by USB.
It does not transfer files over Bluetooth or copy them into a computer's folder.

- **Text of any length**, typed at a steady, configurable pace, with progress and cancel.
- **Hotkeys in press order**, such as `Ctrl + L` or `CapsLock + Space + J`. Keys are pressed in the
  order given and released in reverse.
- **Sequences** that combine text, taps, key combinations, waits, and repeats.
- **USB or Bluetooth keyboard output.** USB mode includes a mouse; Bluetooth mode is keyboard-only.
- **Bluetooth or Wi-Fi control.** In USB keyboard mode, the stick connects out to an authorized
  controller over known Wi-Fi or a nearby Bluetooth control link. Bluetooth keyboard mode uses
  Wi-Fi control only.
- **Desktop app and command line** on Windows and macOS.
- **USB file handoff** on qualified firmware: publish one volatile `MESSAGE.TXT` or up to 16 named
  files sharing 256 KiB on the tested Waveshare-to-Windows path.

The multi-file firmware replaces the whole drive with each publication. On one Waveshare stick and
USB-connected Windows target, 16 files totaling 256 KiB were read back byte-for-byte; clear and
replacement with a two-file set also passed. Names can contain up to 64 ASCII letters, digits,
spaces, dots, underscores and hyphens; folders, reserved Windows names and names differing only by case are
rejected. Leading or trailing spaces and dots are also rejected. File contents can be any bytes.

Keyferry is still being qualified board by board. Control and USB input work on the Waveshare
ESP32-S3-GEEK and LILYGO T-Dongle-S3. Direct Bluetooth keyboard text output has been tested on a
Windows target; broader Bluetooth keyboard use remains unqualified. File handoff has been tested on
one Waveshare stick with a USB-connected Windows computer. LILYGO file capacity and Mac/Linux USB
mounting remain unqualified.

## How it works

```text
desktop app / keyctl
        |
        | local API (relay through another authorized controller when needed)
        v
keyferryd on controller
        ^
        | stick connects out over TLS: Wi-Fi, or BLE control in USB mode
        |
   ESP32-S3 stick
       /       \
USB cable       Bluetooth keyboard (Wi-Fi control only)
power, provisioning,          |
optional file drive,    paired target computer
keyboard/mouse in USB mode
       |
USB-connected computer
```

The USB cable powers the stick in both modes. Bluetooth keyboard mode has no Bluetooth controller
link or USB keyboard/mouse output. USB provisioning remains available when connected, and file
handoff on capable firmware still requires a physical USB connection. The USB-connected computer
can differ from the Bluetooth keyboard target.

`keyferryd` runs on each controller and is the only component that can issue commands. The stick
has no inbound network command listener; it opens one pinned, mutually authenticated TLS control
session to an authorized controller. Each controller holds its own credential, issued from the
owner's encrypted owner kit, so one computer can be revoked without affecting the others.

## Secure text

For passwords, use **Secure text…** on the Send page instead of the plain text box: it opens the
same masked dialog for the selected stick. An agent can request that dialog with
`keyctl secure-text DEVICE_UUID`. Run it on the computer where the human will
enter the text, in its logged-in desktop session with the local controller running. It opens a
separate masked dialog for that exact stick. With the target's password field focused, the human
enters text and presses Enter (or chooses **Send once**); Esc cancels, and a successful send closes
the dialog. **Press Enter after the text** is ticked by default; change that default under Typing. The command's
`REQUESTED` output means the prompt process started, not that typing or unlock succeeded.

The prompt expires after two minutes, rejects non-printable/non-ASCII text without replacement,
clears its editor after use, and sends no entered text to the agent, app logs, saved recipes or
files. Use U.S./ABC input and Caps Lock off. Do not put the secret into chat, arguments or stdin,
and do not let an agent inspect the dialog while entering it. Toolkit and OS transient memory is
outside the application's wiping guarantee. An uncertain send is never automatically retried.

An agent can also use `keyctl screen-power DEVICE_UUID off` (or `on`). Current source forwards
that exact setting through the authenticated holder when needed. It requires capable firmware and
an idle, disarmed device, persists the setting, and does not affect keyboard authority. After a
lost response, inspect `keyctl screen-power DEVICE_UUID` before deciding what to do next.

These additions are in source; the published preview packages do not include them yet. Software
checks do not verify physical target focus, macOS unlock, or preboot/FileVault input.

## Hardware

| Board | Display | Status |
| --- | --- | --- |
| Waveshare ESP32-S3-GEEK | 240×135 ST7789 | Qualified on one owner unit: control, USB input, and 256 KiB USB file handoff to Windows |
| LILYGO T-Dongle-S3 | 160×80 ST7735 | Control and USB input supported; USB file capacity unqualified |

Board differences live in one profile per board under `firmware/esp32s3/boards/`.

## Setup

These steps assume a provisioned stick and an owner kit. Preparing a new physical unit requires
board-specific recovery, backup, firmware installation, and authorization; this is not yet a
turnkey public setup flow. See [`firmware/README.md`](firmware/README.md) for board-specific build
and recovery guidance.

1. **Connect USB power to the stick.** For USB keyboard/mouse input or file handoff, plug it into the
   computer that should receive those functions. Bluetooth keyboard output can use another USB power
   source; nothing is installed on the target.
2. **Download and install Keyferry on the controller.** Get the Windows x64 or macOS Apple silicon
   package from [Releases](https://github.com/smkwray/keyferry/releases). The Windows ZIP contains
   `keyferry.exe` and its required helpers; the macOS ZIP contains `Keyferry.app`. Extract the whole
   package and follow its `README.txt` to run `install.ps1` or `install.sh`. The installer sets up
   Keyferry's background service but does not leave it running. By default the service listens for
   sticks on every active private home or office network (`--lan-interface auto`, never Tailscale or
   other point-to-point links); name an interface instead to restrict it. Installed services also
   acquire nearby sticks over Bluetooth by default; `--bluetooth off` makes a controller
   Wi-Fi/Tailscale-only (macOS then never asks for Bluetooth permission). You can also
   [build from source](#building-from-source).
3. **Open Keyferry and choose Authorize this computer.** Pick the owner-kit file, enter the owner
   password, and choose which stick this computer will control. The computer receives its own
   credential for that stick.
4. **Keep the control link reachable.** USB keyboard mode can use known Wi-Fi or the separate
   Bluetooth control link; on macOS, allow Bluetooth access when asked. Do not pair the controller
   to that control link in the operating system's Bluetooth settings. Bluetooth keyboard mode needs
   Wi-Fi control, including from a Mac controller.

These are preview builds. Windows executables are unsigned, and the macOS app is not notarized;
macOS may require [manual approval on first launch](https://support.apple.com/en-us/102445).

To type into a Bluetooth target, select the stick under **Devices**, then choose **Keyboard &
display → Bluetooth keyboard**. The stick restarts; pair its keyboard on the *target* through the
target's Bluetooth settings. To return to USB keyboard/mouse output, choose **USB keyboard** on the
same page; this also restarts the stick.

The **Send** page shows the stick's status, a text box, and a hotkey field. Send when it shows
**Ready**. **Stop** or Esc cancels active work. If another of your authorized controllers holds the
stick, Keyferry uses it over Tailscale
automatically when that controller is reachable.

The background service runs only while Keyferry is open. Opening Keyferry starts it; closing
Keyferry (including Cmd+Q on macOS) stops it. Nothing runs at login, and while Keyferry is closed
this computer cannot control the stick.

In USB keyboard mode, an unheld stick advertises its Bluetooth *control* link. Choose the stick
under **Devices**; there is no manual controller selection. Bluetooth keyboard pairing with the
target is separate.

Select a stick in **Devices** to open its **Connection / Wi-Fi**, **Keyboard & display**, or
**USB maintenance** controls. Each page shows the selected stick and its device ID. USB maintenance
requires that exact stick to be plugged into this computer and the owner-kit password; its buttons
act only on that stick. Preparing another stick is separate, under **Setup & security**.

On supported firmware, **Keyboard & display** offers **Screen on** and **Screen off** for the
selected stick. The choice survives unplugging and takes effect without restarting the stick.
The status distinguishes a saved choice from a change the display has finished applying.

## Command line

`keyctl` talks to the local daemon and opens the installed Keyferry app if its service is unavailable.
It is installed next to the app:

- Windows: `%LOCALAPPDATA%\Programs\Keyferry\keyctl.exe`
- macOS: `~/Applications/Keyferry.app/Contents/MacOS/keyctl`

```text
keyctl devices                                  # list sticks; use one whose link is "authenticated"
keyctl status DEVICE                            # read one stick's state, firmware and connection
keyctl capabilities                             # read the controller's supported API features
keyctl capture list                             # list local HDMI/UVC video sources (no daemon)
keyctl capture frame --out screen.png            # capture one PNG to a new private path
keyctl input-sequence --describe                 # supported pointer/keyboard actions and bounds
keyctl stream DEVICE --input message.txt        # type a UTF-8 file of any length
keyctl file DEVICE path/to/message.txt           # publish bytes as KEYFERRY/MESSAGE.TXT
keyctl files DEVICE path/to/a.txt path/to/b.txt   # replace the drive with named files (v2 firmware)
keyctl file-status DEVICE                        # inspect the published file or list
keyctl file-clear DEVICE                         # clear the whole drive
keyctl screen-power DEVICE off                   # turn off the screen; use on to light it again
keyctl screen-power DEVICE                       # read active and saved screen settings
keyctl sequence DEVICE < hotkey.json            # run a key sequence (JSON on stdin)
keyctl sequence --example                       # a valid starting sequence
keyctl keys                                     # physical key names and aliases (COMMAND, OPTION, ...)
keyctl recipe list                              # saved sequences on this computer (local)
keyctl recipe --example                         # a valid starting recipe
keyctl recipe import open-url.json              # validate and save a recipe (the only writer)
keyctl recipe inspect open-url                  # metadata, route and worst-case time; never actions
keyctl recipe run DEVICE open-url < params.json # run once; parameters as a JSON object on stdin
keyctl cancel DEVICE                            # stop the running command
```

For agents, `keyctl --help` works without credentials or a running app. Use an exact device ID
from `devices`; never choose silently between multiple sticks. `status DEVICE` includes the
firmware capability flags and `link_path`/`via` showing whether another computer holds the stick.
Check command exit status and its JSON result. A missing response, `UNKNOWN`, or a lost connection
after submission means the action may have happened: read status to reconcile it, never resend it
automatically. Sends use command-scoped arming; ordinary agents do not need a separate `arm` call.
`status DEVICE` reports `firmware.keyboard_lock_state`; it is `unsupported` on current firmware,
so Keyferry cannot see whether Caps Lock is on. Make sure it is off before sending text.

Saved sequences (recipes) are defined in `protocol/recipe-v1.md`. Only `recipe import` writes this
computer's library (`KEYFERRY_RECIPE_DIR`, or `recipes` in the per-user Keyferry state directory);
`recipe run DEVICE NAME` expands the recipe here, reads parameter values only from stdin, posts
one ordinary sequence and prints the usual `keyferry.command-result.v2` line. A run saves nothing.

| Control | CLI | Effect and connection required |
| --- | --- | --- |
| Screen | `keyctl screen-power DEVICE [on\|off]` | Without a value, reads active/saved state. Changes live and persists. |
| Screen rotation | `keyctl display-orientation DEVICE [normal\|rotated-180]` | A change restarts the stick. |
| Keyboard output | `keyctl output-mode DEVICE [usb-hid\|ble-hid]` | A change restarts the stick. This selects where keystrokes go. |
| Forget keyboard pairing | `keyctl forget-bluetooth DEVICE` | Forgets the bonded Bluetooth keyboard target and restarts pairing. |
| Release held input | `keyctl disarm DEVICE` | Releases input and disarms. `cancel DEVICE` stops active work. |
| USB status | `keyctl local-status --owner-kit PATH --device UUID` | Direct USB and owner password; reports safety/network metadata, not Wi-Fi passwords. |
| Restart networking | `keyctl local-recover --owner-kit PATH --device UUID restart-network` | Direct USB and owner password; interrupts the control connection and clears any published USB file. |

Screen, rotation, output mode and online pairing controls run on the computer holding the stick's
authenticated Wi-Fi or Bluetooth connection. Settings are not forwarded over Tailscale. Wi-Fi versus
Bluetooth **control** is selected automatically; `output-mode` changes the keyboard's output and
does not select the controller connection. For screen status, `stored` is the saved preference;
`active` can lag while the display task applies it. `available=false` does not prove the physical
screen state.

Local USB commands work even when the daemon or network is unavailable. Keep `--device UUID`
explicit with a multi-device owner kit. The owner supplies the password as one stdin line; never
put it in arguments, shell history, logs or an agent transcript. Other `local-recover` actions are
`forget-bluetooth`, `cancel-enrollment`, `usb-hid`, `ble-hid` and `reboot`. Its stdout is JSONL:
match the attempt's device/action and operation IDs to the terminal result. Partial output is not
success, and a nonzero exit alone does not prove that nothing happened.

Wi-Fi policy and owner administration use the installed sibling **`keyferry-pairing`** program;
`keyferry-pairing --help` lists its arguments and stdin requirements:

| Task | Helper command |
| --- | --- |
| Save an edited Wi-Fi policy file | `save-roaming-policy --output PATH --replace` (complete policy JSON on stdin) |
| Apply that policy to one stick | `update-roaming --owner-kit PATH --device UUID --policy PATH` |
| Recover the initial Wi-Fi policy into a new private file | `recover-initial-roaming-policy --owner-kit PATH --device UUID --output PATH` |
| List owner-authorized sticks | `list-owner-devices --owner-kit PATH` |
| Authorize a computer for one stick | `issue-installation --owner-kit PATH --device UUID --output DIRECTORY` |
| Prepare another stick | `add-owner-device`, `grant-device-to-installation`, `materialize-device-bootstrap` |
| Change the owner password | `change-owner-kit-passphrase --owner-kit PATH` (current/new/confirmation on stdin) |

Before a USB Wi-Fi policy operation, pause the selected stick on its holding controller with
`keyctl maintenance DEVICE begin`; afterwards run `keyctl maintenance DEVICE finish`, including
when the helper fails. Finish resumes controller availability and does not repeat the USB action.
Beginning maintenance interrupts the link and clears any published USB file.
If the app is closed, the helper can operate directly without starting a daemon. Policy files hold
Wi-Fi secrets: keep them private, preserve non-Wi-Fi policy fields, and do not print their contents.
Setup commands create credentials or bootstrap files; they do not themselves install or flash a
new stick. Owner administration should follow an explicit owner request.

A hotkey pressed in order:

```json
{"schema":"keyferry.keyboard-sequence.v1","profile":"windows-us","arm":"command-scoped",
 "start_within_ms":5000,"actions":[{"type":"ordered_chord","keys":["CAPS_LOCK","SPACE","J"]}]}
```

`chord` presses its keys together in one report; `ordered_chord` presses them one after another.
Both end with every key released. Key names are the registry names from `keyctl keys` or its
aliases: `COMMAND`/`CMD` for the GUI key and `OPTION`/`OPT` for Alt, with `LEFT_`/`RIGHT_` forms.

### Agent screen control

`keyctl mcp` exposes a
[stdio MCP server](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
with newline-delimited JSON-RPC, tool discovery, PNG images and structured results. It creates no
listener and never opens/restarts the controller app. Start the installed controller normally;
input uses its existing token and sole daemon command writer. Install FFmpeg on the controllers
with capture cards and grant Camera permission on macOS.

Register through the synced **keyferry skill's `keyferry-mcp` launcher and `/relink`**. The launcher
resolves the installed CLI on the current computer and runs `keyctl mcp` with no arguments;
explicit extra arguments pass through. For discovering, running and saving routine tasks, see the
synced **keyferry skill, Routines** section and [recipe format](protocol/recipe-v1.md). Registration needs no device UUID, capture card name or
per-device executable path. Rebuild and reinstall the updated packages on every controller,
then run `/relink` to synchronize agent registration. Keep any explicit overrides private.

With no `--device`, the server selects the single authenticated authorized stick, including one
held by another owner controller over the tailnet. A unique authenticated `POINTER_EXTENDED_V1`
stick is preferred when other keyboard-only sticks are present. Ambiguity never selects by list
position: call `list_devices` and `select_device`. Action tools require a selected device.
With no `--source`, use the single recognized local HDMI capture device; if none is local,
use the single recognized remote source. Multiple candidates require `list_capture_sources` and
`select_capture_source`. `status` reports the exact selections and whether each was automatic,
an argument override, or a selection tool. `--device UUID` and `--source NAME_OR_ID` remain available;
global `--url` and `--token-file` select the existing loopback daemon.

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
within the same daemon epoch, `region` crops screenshot pixels, `max_width` scales to 2..1280 pixels,
and `ocr:true` returns OCR boxes from that exact frame. Responses include base64 PNG, dimensions,
native dimensions, region, serial, daemon epoch, generation, frame age and capture status. Frames
are memory-only, PNG is bounded to 5 MiB and response JSON to 7 MiB. A service admits one read at a
time, at most ten frame requests/second and four capture streams. MCP uses full-frame geometry;
direct API callers must account for region/scale before driving a pointer.

First call `status`, then `calibrate` on a static, harmless approved target, then take a fresh
`screenshot` before pointer input. The target HDMI output must be its only display or mirror the main
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
compiler; points outside the measured active rectangle reject. The equivalent CLI is
`keyctl capture calibrate DEVICE [--source CAPTURE]`.

Pointer tools refuse devices without authenticated `POINTER_EXTENDED_V1` (0x08000000); keyboard tools
remain available. Explicit per-call `uncalibrated:true` bypasses binding and uses full-frame linear
mapping, flagged in results. It still requires the capability and a fresh screenshot. This override
accepts the risk of driving a different target or a cropped/scaled display.

| Tool | Arguments | Result |
| --- | --- | --- |
| `screenshot` | optional `save_path` (new file only) | PNG image, screenshot/native geometry, frame ID/age and capture status |
| `move` | integer `x,y`; optional `uncalibrated` | absolute move receipt |
| `click` | `x,y`; optional `button` = left/right/middle, `double`, `uncalibrated` | move then single/double click receipt |
| `drag` | `from_x,from_y,to_x,to_y`; optional `button`, `uncalibrated` | balanced atomic drag, 40 ms hold |
| `scroll` | `x,y,dx,dy`; optional `uncalibrated` | integer detents, each -127..127, not both zero |
| `type_text` | `text` (1..4096 supported ASCII characters) | ordinary US-mapped text; unsupported characters reject |
| `key` | `keys` (1..14 names/aliases) | tap or balanced chord through the `keyctl keys` table |
| `wait_for_stable` | `timeout_ms` (1..30000); optional `region` | matched after at least 3 fresh frames below 0.002 mean normalized RGB difference for 300 ms; otherwise timed_out |
| `wait_for_change` | same | matched above 0.01 mean difference from the initial frame; otherwise timed_out |
| `find_text` | optional `query` | capture-controller OCR line boxes in screenshot pixels, case-insensitive substring filter |
| `calibrate` | none | verified binding, mapping and probe receipts; persists geometry only |
| `status` | none | chosen device/source, selection reasons, authenticated state, capture errors/restarts and binding |
| `list_devices` / `select_device` | none / exact `device` UUID | authorized inventory / choose authenticated stick and clear binding |
| `list_capture_sources` / `select_capture_source` | none / exact `source` ID | local/remote inventory / choose capture source and clear binding |

A region is `{x,y,width,height}` in screenshot pixels, entirely inside the frame. Positive `dy` is
wheel-up, positive `dx` pan-right; target natural-scrolling policy can invert it. Schemas reject
unknown fields, null optionals and invalid ranges. Keyboard actions use the existing alias table and
reject unsupported ASCII controls. Ordinary text only: **secrets stay in the owner-only secure-text
dialog**. A routine can request the owner dialog; its content never enters MCP.

Every action submits once through `/input-sequences` with existing authentication, command-scoped
arm, admission and release guarantees. No cross-call held button, alternate writer or input retry
exists. Failed/possible-start UNKNOWN results return `isError:true` with command IDs and evidence.
Inspect/reconcile uncertain outcomes; never replay them. `EMITTED` proves emission, not visible target
behavior. MCP cancellation reaches the existing daemon cancellation mechanism.

One continuous ffmpeg rawvideo pipe retains the latest RGB frame, scaled proportionally to at most
1280 pixels on each axis. Comparison frames are bounded and memory-only. Capture faults clear the
latest frame, report an explicit error and restart after backoff; counters remain visible. A stalled
stream is a capture error, not a stable screen. Capture children belong to the daemon and stop
when its capture service is dropped.
`keyctl capture frame --out PATH` retains its independent one-shot behavior.

Screens and OCR may contain secrets. They are never logged or written except to an explicit
`screenshot.save_path` or CLI `--out`; clients receive the content and may retain conversations.
OCR runs on the capture controller and uses its local Windows.Media.Ocr language packs, with no
cloud recognizer or downloaded model. A macOS or Linux agent can use OCR from a Windows capture
controller. Capture controllers on macOS/Linux report `ocr.unsupported_platform` explicitly.
Black/blue no-signal frames remain valid screenshots and may be stable; they are not target proof. Exact firmware/OS physical gates remain
OPEN until the hardware window qualifies them.

The original one-shot CLI loop is also available:

Connect the target's HDMI output to a USB HDMI/UVC capture dongle on the controller host.
`keyctl capture list` returns video source names and platform IDs as JSON. Install
[FFmpeg](https://ffmpeg.org/download.html) on PATH; capture uses its
[dshow, avfoundation or v4l2 backend](https://ffmpeg.org/ffmpeg-devices.html).
On macOS, grant Camera permission to the terminal/app in System Settings → Privacy & Security.
Default selection requires one recognized capture device; unknown or ambiguous sources require
`--source NAME_OR_ID` from the list. Listing does not probe capture modes or include supported sizes.

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

### Mac targets

The profile `windows-us` is the wire name of the US-ASCII key mapping. It types correctly on a Mac
that identifies the stick as an ANSI keyboard and uses the U.S. or ABC input source; `windows-us`
does not claim that the target runs Windows. When Keyboard Setup Assistant appears after you plug in
the stick, choose ANSI or send the keys it asks for yourself; Keyferry never types into it on its
own. If the Mac treats the stick as ISO, `` ` `` and `~` come out as `§` and `±`: change the type in
System Settings > Keyboard > Change Keyboard Type. Caps Lock must be off. Smart quotes, automatic
capitalization and autocorrect can change typed text inside some apps. Mac typing is not yet
physically qualified.

The desktop's **Save as USB file** also publishes `MESSAGE.TXT` on the stick's read-only `KEYFERRY`
drive, replacing its previous contents. With multi-file firmware, **Choose USB files…** reviews a
set of names and sizes before publishing them together; **Refresh drive** shows the files currently
published. Open them on the computer physically connected by USB. Publishing does not copy them
into Downloads or type them.
The Waveshare-to-Windows path is qualified for 16 files sharing 256 KiB, including exact USB
readback, whole-drive clear and read-only enforcement. LILYGO file capacity and Mac/Linux USB
mounting remain unqualified. Files are held in volatile memory and clear on power or
controller-session loss. The USB-connected computer may retain a copy after you clear it.

A result of `EMITTED` means the stick sent the keystrokes. It does not confirm that the focused
application on the target received them. Commands that may have started are never retried.

## Safety

- The stick starts disarmed. Sending authorizes and arms it for that command; **Stop** or Esc cancels
  active work.
- Reboot, reconnect, cancellation, and every fault path release all keys. Pending work is discarded.
- The stick runs no web server, captive portal, or inbound listener, and has no automatic Wi-Fi
  access-point fallback. Knowing the Wi-Fi password grants no ability to type.
- Wi-Fi settings change only through an authenticated USB connection to the stick, never remotely.
- Text the target keyboard layout cannot type is rejected before sending, unless you choose to
  replace it with `?`. Keyferry cannot see Caps Lock; keep it off when sending text.

## Privacy

Keyferry does not persist sent payloads. It holds submitted text, hotkeys, sequences, and file
contents in memory while processing them. A USB file remains in the stick's volatile memory until
cleared or the power or controller session is lost; the target may save its own copy.

- Command outcomes are kept in memory for ten minutes so a client can ask how a send ended.
- The app clears the text box and hotkey field after sending. Its diagnostics view is off by
  default and held only in memory.
- The stick stores its configuration and pairing credentials persistently, but not payloads or
  keystrokes. USB file contents stay in RAM.
- On macOS the background service writes a connection log (link events and errors, no content) to
  `~/Library/Application Support/keyferry/logs/`.
- Saved sequences are the exception to not persisting: `keyctl recipe import` stores the recipe as
  written (owner-only on macOS) until you delete it. Put secrets in a parameter supplied at run
  time instead of literal recipe text. Runs and parameter values are never saved.
- Choosing a file with **Send a file…** may add its name to the operating system's recent-files
  list; pasting the path instead avoids that.

## Building from source

Requires Rust (pinned in `rust-toolchain.toml`), Python 3.11 or newer, and a C++17 compiler for the
strict checks. Firmware builds additionally require ESP-IDF v6.0.3.

```text
cargo fetch --locked              # populate dependencies for the offline checks
python scripts/check.py --strict  # formatting, lints, tests, protocol vectors, repository checks
```

Release archives are built by the native package gates, which also strip local paths from the
binaries:

```text
powershell -File scripts/check_windows_package.ps1    # Windows
sh scripts/check_macos_package.sh                     # macOS
python scripts/package_controller_release.py ...      # canonical, scanned release ZIP
```

Firmware builds require an explicit board profile. See `firmware/README.md`, `protocol/`, and
`SECURITY.md` for the device protocol and security model.

## Repository layout

```text
apps/keyferry/        desktop app (Slint)
apps/keyferryd/       controller daemon: command authority, TLS and Bluetooth links, local API
apps/keyctl/          command-line client
crates/               protocol, keyboard layouts, gateway credentials, simulator, local management
firmware/esp32s3/     stick firmware and board profiles
protocol/             protocol specification, key registry, golden vectors
tools/                pairing/credential helper and firmware update tool
scripts/              checks, installers, packaging
```

## License

MIT; see [`LICENSE`](LICENSE). Third-party components are listed in
[`THIRD_PARTY.md`](THIRD_PARTY.md).

The desktop app uses [Slint](https://slint.dev) under the Slint Royalty-free License 2.0.

<a href="https://slint.dev"><img src="https://raw.githubusercontent.com/slint-ui/slint/master/logo/MadeWithSlint-logo-whitebg.png" alt="Made with Slint" height="48"></a>
