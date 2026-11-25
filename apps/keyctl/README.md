# Command-line reference

This page covers `keyctl`, Keyferry's command-line client; `keyferry-pairing`, the owner-administration helper; and the controller installers' network options. For agent screen control through `keyctl mcp`, see [AGENT-CONTROL.md](AGENT-CONTROL.md).

`keyctl` talks to the Keyferry service (`keyferryd`) on the same computer and starts the installed service when needed. Both helpers are installed next to the desktop app:

- Windows: `%LOCALAPPDATA%\Programs\Keyferry\keyctl.exe` and `keyferry-pairing.exe`
- macOS: `~/Applications/Keyferry.app/Contents/MacOS/keyctl` and `keyferry-pairing`

`keyctl --help` works without credentials or a running app and lists every command.

## Common commands

```text
keyctl devices                                  # list boards; use one whose link is "authenticated"
keyctl status DEVICE                            # one board's state, firmware and connection
keyctl capabilities                             # the local service's supported API features
keyctl stream DEVICE --input message.txt        # type a UTF-8 file of any length
keyctl sequence DEVICE < hotkey.json            # run a key sequence (JSON on stdin)
keyctl sequence --example                       # a valid starting sequence
keyctl keys                                     # key names and aliases (COMMAND, OPTION, ...)
keyctl cancel DEVICE                            # stop the running command
keyctl secure-text DEVICE                       # open the masked secure-text dialog
keyctl file DEVICE path/to/message.txt          # publish bytes as KEYFERRY/MESSAGE.TXT
keyctl files DEVICE a.txt b.txt                 # replace the drive with 1-16 named files
keyctl file-status DEVICE                       # inspect the published file or list
keyctl file-clear DEVICE                        # clear the whole drive
keyctl screen-power DEVICE [on|off]             # read, or set, the board's screen
keyctl recipe list                              # saved sequences on this computer
keyctl recipe --example                         # a valid starting recipe
keyctl recipe import open-url.json              # validate and save a recipe (the only writer)
keyctl recipe inspect open-url                  # metadata, route and worst-case time
keyctl recipe run DEVICE open-url < params.json # run once; parameters as JSON on stdin
keyctl routine --help                           # shared routines in KEYFERRY_ROUTINE_DIR
keyctl capture list                             # local HDMI/UVC video sources (no service needed)
keyctl capture frame --out screen.png           # capture one PNG to a new private path
keyctl input-sequence --describe                # supported pointer/keyboard actions and bounds
keyctl mcp                                      # stdio MCP server for agents
```

`stream` rejects text the keyboard layout cannot type; with `--unsupported replace` it types `?` in its place. Multi-file USB handoff (`files`) and screen power need firmware that supports them; `keyctl status DEVICE` lists the board's firmware capability flags.

## Key sequences

A hotkey pressed in order:

```json
{"schema":"keyferry.keyboard-sequence.v1","profile":"windows-us","arm":"command-scoped",
 "start_within_ms":5000,"actions":[{"type":"ordered_chord","keys":["CAPS_LOCK","SPACE","J"]}]}
```

`chord` presses its keys together in one report; `ordered_chord` presses them one after another and releases them in reverse. Both end with every key released. Sequences also combine text, taps, waits and repeats. Key names come from `keyctl keys`, with aliases such as `COMMAND`/`CMD` for the GUI key and `OPTION`/`OPT` for Alt, plus `LEFT_`/`RIGHT_` forms.

Save reusable sequences as recipes ([format](../../protocol/recipe-v1.md)). Recipes live in `KEYFERRY_RECIPE_DIR`, or in `recipes` under the per-user Keyferry state directory. `recipe run` expands a recipe locally, reads parameter values only from stdin, sends one ordinary sequence and saves nothing.

## Scripts and agents

- Use an exact device ID from `keyctl devices`, and never choose silently between several boards. `status` includes the firmware capability flags and `link_path`/`via`, which show whether another computer holds the board.
- Check the exit status and the JSON result. A missing response, `UNKNOWN`, or a lost connection after submission means the action may have happened: read the status to reconcile it, and never resend automatically. `EMITTED` means the board sent the keystrokes, not that the focused application received them.
- Each send arms the board for that command only, so ordinary callers need no separate `arm`.
- Keyferry cannot see Caps Lock (`firmware.keyboard_lock_state` is `unsupported`). Make sure it is off before sending text.

## Device settings and recovery

| Control | Command | Effect |
| --- | --- | --- |
| Screen | `keyctl screen-power DEVICE [on\|off]` | Without a value, reads the active and saved state. A change applies live and persists. |
| Screen rotation | `keyctl display-orientation DEVICE [normal\|rotated-180]` | A change restarts the board. |
| Keyboard output | `keyctl output-mode DEVICE [usb-hid\|ble-hid]` | Where keystrokes go. A change restarts the board. |
| Forget keyboard pairing | `keyctl forget-bluetooth DEVICE` | Forgets the bonded Bluetooth target and restarts pairing. |
| Release held input | `keyctl disarm DEVICE` | Releases input and disarms. `cancel DEVICE` stops active work. |
| USB status | `keyctl local-status --owner-kit PATH --device UUID` | Over USB with the owner password; safety and network metadata, never Wi-Fi passwords. |
| Restart networking | `keyctl local-recover --owner-kit PATH --device UUID restart-network` | Over USB with the owner password; interrupts control and clears any published USB file. |

Screen, rotation, output-mode and pairing commands run on the computer that holds the board's authenticated connection. Screen power is the only setting forwarded over Tailscale. It needs an idle, disarmed board; after a lost response, read the state before deciding what to do. In its status, `stored` is the saved preference, and `active` can lag while the display applies it. **Screen on** lights the display for 60 seconds after boot, a status change, a BOOT press or another **on**, then lets it sleep.

The local USB commands (`local-status`, `local-recover`) work without the service or a network. Give `--device UUID` whenever the owner kit covers several boards, and give the owner password as one line on stdin, never in arguments, shell history, logs or an agent transcript. The other `local-recover` actions are `forget-bluetooth`, `cancel-enrollment`, `usb-hid`, `ble-hid` and `reboot`. Output is JSON lines: match the device, action and operation IDs to the final result. Partial output is not success, and a nonzero exit alone does not prove that nothing happened.

## Owner administration

Wi-Fi policy and owner administration use `keyferry-pairing`; `keyferry-pairing --help` lists its arguments and what each command reads from stdin.

| Task | Command |
| --- | --- |
| Save an edited Wi-Fi policy file | `save-roaming-policy --output PATH --replace` (policy JSON on stdin) |
| Apply that policy to one board | `update-roaming --owner-kit PATH --device UUID --policy PATH` |
| Recover the initial Wi-Fi policy | `recover-initial-roaming-policy --owner-kit PATH --device UUID --output PATH` |
| List owner-authorized boards | `list-owner-devices --owner-kit PATH` |
| Authorize a computer for one board | `issue-installation --owner-kit PATH --device UUID --output DIRECTORY` |
| Prepare another board | `add-owner-device`, `grant-device-to-installation`, `materialize-device-bootstrap` |
| Change the owner password | `change-owner-kit-passphrase --owner-kit PATH` (current, new and confirmation on stdin) |

Before a Wi-Fi policy operation over USB, pause the board on the controller that holds it with `keyctl maintenance DEVICE begin`, and run `keyctl maintenance DEVICE finish` afterwards, even when the helper fails. Beginning maintenance interrupts the link and clears any published USB file. Policy files hold Wi-Fi passwords: keep them private and never print them. The setup commands create credentials and bootstrap files; they do not install or flash firmware.

## Controller network

The controller service looks for boards on every active private home or office network, never on Tailscale or other point-to-point links, and also finds nearby boards over Bluetooth. Installer options narrow both:

| Option | Windows (`install_windows_controller.ps1`) | macOS (`install_unix_controller.sh`) |
| --- | --- | --- |
| Listen only on named interfaces | `-LanInterface NAME` (one or more names) | `--lan-interface NAME` (repeatable) |
| Turn off Bluetooth discovery | `-Bluetooth off` | `--bluetooth off` |

With Bluetooth off, the controller uses only Wi-Fi and Tailscale, and macOS never asks for Bluetooth permission.

To reach a board held by another of your controllers, each controller accepts Keyferry traffic on TCP ports 18043 and 18044 of its own Tailscale address only. No Tailscale configuration is needed when your tailnet allows ordinary connections between your computers; a policy that blocks those ports stops forwarding.

## Mac targets

The `windows-us` profile is the wire name of the US-ASCII key mapping; it does not mean the target runs Windows. It types correctly on a Mac that treats the board as an ANSI keyboard with the U.S. or ABC input source. If Keyboard Setup Assistant appears, choose ANSI or press the keys it asks for yourself; Keyferry never types into it. If the Mac treats the board as ISO, `` ` `` and `~` come out as `§` and `±`: change the type in System Settings › Keyboard › Change Keyboard Type. Keep Caps Lock off; smart quotes, auto-capitalization and autocorrect can change typed text in some apps.
