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
2. **Build and install Keyferry on the controller.** No GitHub release archives are published yet.
   Build a Windows or macOS archive from source (see [Building from source](#building-from-source)),
   extract it, and run its installer (`install.ps1` or `install.sh`, described in the archive's
   `README.txt`). The installer sets up Keyferry's background service but does not leave it running.
3. **Open Keyferry and choose Authorize this computer.** Pick the owner-kit file, enter the owner
   password, and choose which stick this computer will control. The computer receives its own
   credential for that stick.
4. **Keep the control link reachable.** USB keyboard mode can use known Wi-Fi or the separate
   Bluetooth control link; on macOS, allow Bluetooth access when asked. Do not pair the controller
   to that control link in the operating system's Bluetooth settings. Bluetooth keyboard mode needs
   Wi-Fi control, including from a Mac controller.

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
keyctl stream DEVICE --input message.txt        # type a UTF-8 file of any length
keyctl file DEVICE path/to/message.txt           # publish bytes as KEYFERRY/MESSAGE.TXT
keyctl files DEVICE path/to/a.txt path/to/b.txt   # replace the drive with named files (v2 firmware)
keyctl file-status DEVICE                        # inspect the published file or list
keyctl file-clear DEVICE                         # clear the whole drive
keyctl screen-power DEVICE off                   # turn off the screen; use on to light it again
keyctl screen-power DEVICE                       # read active and saved screen settings
keyctl sequence DEVICE < hotkey.json            # run a key sequence (JSON on stdin)
keyctl sequence --example                       # a valid starting sequence
keyctl keys                                     # physical key names
keyctl cancel DEVICE                            # stop the running command
```

For agents, `keyctl --help` works without credentials or a running app. Use an exact device ID
from `devices`; never choose silently between multiple sticks. `status DEVICE` includes the
firmware capability flags and `link_path`/`via` showing whether another computer holds the stick.
Check command exit status and its JSON result. A missing response, `UNKNOWN`, or a lost connection
after submission means the action may have happened: read status to reconcile it, never resend it
automatically. Sends use command-scoped arming; ordinary agents do not need a separate `arm` call.

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
Both end with every key released.

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
  replace it with `?`.

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
