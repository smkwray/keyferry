# Desktop app

The Keyferry desktop app runs on the controller. It sends text and hotkeys, manages each board's settings and USB files, and opens the secure-text dialog. Closing the app leaves the Keyferry service running.

## Send

**Send** shows the board's status, a text box and a hotkey field. Send when it shows **Ready**; **Stop** or Esc cancels active work. The text box and hotkey field clear after sending. **Send a file…** types the contents of a text file instead. Choosing a file this way may add its name to the operating system's recent files; pasting the path avoids that.

**Save as USB file** publishes the text as `MESSAGE.TXT` on the board's read-only `KEYFERRY` drive, replacing whatever was there. On firmware that supports several files, **Choose USB files…** shows names and sizes before publishing up to 16 files (256 KiB in all) together, and **Refresh drive** shows what is published. Open the files on the computer connected by USB; publishing does not copy them anywhere or type them. [Firmware](../../firmware/README.md#usb-file-handoff) describes the file name rules.

## Devices

**Devices** lists your boards by model (**LILYGO**, **Waveshare GEEK**, **AtomS3 Lite**, **Waveshare AMOLED**), as each board reports it, with the start of its device ID beside it. A board keeps its model name while offline; one this computer has never seen online shows **Unknown model**. The same name appears in the secure-text dialog, `keyctl devices` and the agent tools.

Select a board to open **Connection / Wi-Fi**, **Keyboard & display** or **USB maintenance**. Each page acts only on that board and shows its device ID. USB maintenance needs that board plugged into this computer and the owner-kit password.

To switch to Bluetooth keyboard output, choose **Bluetooth keyboard** under **Keyboard & display**; the board restarts, and you pair it from the target's Bluetooth settings. **USB keyboard** switches back.

**Screen on** and **Screen off** apply without a restart and persist across unplugging. To protect the panel, **Screen on** lights the display for 60 seconds after boot, a status change, a BOOT press or choosing **Screen on** again, then lets it sleep. The image shifts by a couple of pixels while lit.

In USB keyboard mode, a board that no controller holds advertises its Bluetooth control link; choose it under **Devices** (there is no manual controller selection). Pairing the board as a Bluetooth keyboard for the target is separate. **Setup & security** prepares additional boards.

## Secure text

For passwords, use **Secure text…** on the Send page instead of the text box. With the target's password field focused, type into the masked dialog and press Enter (or **Send once**); Esc cancels.

An agent can open the same dialog with `keyctl secure-text DEVICE_UUID [--wake none|mouse|mac-login]`; the request itself sends no input. Run it in the logged-in desktop session where the person will type, with the local Keyferry service running. On macOS the dialog keeps running after `keyctl` exits.

- The dialog accepts 1–256 printable ASCII characters and rejects anything else without replacing it. Use the U.S. or ABC input source with Caps Lock off. **Enter after text** is on by default; change the default under **Typing**.
- An optional wake step, not saved, runs first: **Mouse movement** (a tiny move out and back, no click; needs a board with relative mouse support) or **Mac login screen (Shift)** (a Shift tap, then a two-second wait). A failed or uncertain wake sends no text.
- The dialog keeps checking the board while it is open. If a Wi-Fi board is briefly reconnecting, **Send once** waits up to 10 seconds for it; a board that is busy, armed or in maintenance is never waited for, and nothing is sent.
- The dialog expires after two minutes, and its result closes after 30 seconds. `REQUESTED` means only that the dialog opened, not that typing or an unlock succeeded. Nothing is retried automatically.
- Never put the secret in chat, arguments or stdin, and never let an agent inspect the dialog.

Secure text keeps the secret out of agents, logs and files, but not out of the controller. It assumes the controller and its operating system are trusted: a program already running there can impersonate the local Keyferry service and capture the text. Copies in RAM, operating-system paging or crash files, and anything you copy or select in the dialog are outside Keyferry's control. Keyferry cannot see where the target's focus is, and it cannot confirm a macOS unlock or a FileVault password typed before startup.
