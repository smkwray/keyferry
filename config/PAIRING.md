# Private first-HIL pairing bundle

The generator writes exactly one device bundle to the Git-ignored `secrets/first-hil/` directory.
It creates a random device ID and 32-byte link secret, a P-256 host key and self-signed certificate,
the firmware certificate and SPKI pin inputs, and the exact `keyferryd` secret-store layout and
listener configuration. It refuses to replace an existing bundle.

```text
cargo run -p keyferry-pairing -- create --host-address 192.168.30.137 --host-port 7443
./scripts/set_first_hil_wifi.ps1
cargo run -p keyferry-pairing -- validate
```

`set_first_hil_wifi.ps1` prompts locally without echoing the password, then pipes one bounded JSON
object to `set-wifi`. The underlying command reads the public `wifi` definition in
`pairing-bundle.schema.json` from standard input. Supply that input through a private file or secure
provisioning UI; never place an SSID or password in a command line. Status output contains no device
identifier, network name, password, key, certificate, pin, or secret-store contents.

After first deployment, Wi-Fi changes use the same authenticated vendor-HID interface and do not
require a firmware flash. The desktop **Networks** page enters local daemon maintenance, which
disarms the device, waits for its terminal-zero confirmation, blocks reconnection, and invokes the pairing helper with
the password on standard input. A direct command-line equivalent is:

```powershell
$env:KEYFERRY_PAIRING_BUNDLE = 'C:\path\to\private-bundle'
'{"schema_version":1,"ssid":"new-network","password":"new-password"}' |
    keyferry-pairing set-wifi --replace
keyferry-pairing provision
```

Stop normal command authority before using that manual equivalent. `--bundle PATH` may precede the
command instead of using the environment variable. A lost COMMIT response has unknown outcome: do
not immediately repeat it; reconnect and run `keyferry-pairing status` to inspect the generation.
The desktop performs the maintenance/resume sequence automatically and exposes this workflow only
through the loopback daemon API, never the direct-tailnet API.

`validate` fails if the private bundle or Wi-Fi input is absent, any file is malformed, the host
certificate, private key, SPKI, or pin differ, or the firmware and `keyferryd` device IDs, endpoints,
or link secrets disagree. A successful validation is configuration evidence only; it does not build
or flash firmware and does not start the daemon.

On Windows the generator removes inherited access from its private directories and grants access to
the current user SID. POSIX directories and files are created with owner-only permissions.

The first-HIL firmware build consumes this bundle without putting credential values in command-line
arguments, CMake cache entries, source files, or status output:

```powershell
./scripts/build_first_hil.ps1
```

The build generates `keyferry_hil_private.h` only beneath the ignored build directory. It first
revalidates the host key/certificate/SPKI, endpoint, device ID, and link-secret agreement and fails
if any required private input is absent or mismatched. Every subsequent build repeats that validation.

Start the matching daemon adapter from the repository root with:

```powershell
./scripts/start_first_hil.ps1
```

The daemon reads the fixed private runtime file and secret-store layout selected by `--first-hil`;
the bind address, device ID, keys, and link secret are not passed in its command line or printed.

For the single-tap checkpoint, start the Windows Raw Input checker before submitting the command:

```powershell
cargo run --locked --offline -p keyferry-hil-check -- list
cargo run --locked --offline -p keyferry-hil-check -- capture --timeout-ms 10000
```

It requires exactly one keyboard-class raw-input device with Espressif VID `303A`, listens only to
that device handle, and passes only after one A-down followed by one A-up with no additional A event
for 500 ms. It reports only VID/PID, not the private USB instance path.
