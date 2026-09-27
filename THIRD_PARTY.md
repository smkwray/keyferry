# Third-party dependencies

Direct Rust dependencies for the daemon, CLI, GUI, and pairing tool are pinned in the
respective Cargo manifests and resolved in `Cargo.lock`.

| Crate | Version | Role | License | Source |
| --- | --- | --- | --- | --- |
| axum | 0.8.8 | Local HTTP/JSON and SSE routing | MIT | https://crates.io/crates/axum/0.8.8 |
| getrandom | 0.4.3 | Operating-system CSPRNG for bearer tokens, probe nonces, and session identifiers | MIT OR Apache-2.0 | https://crates.io/crates/getrandom/0.4.3 |
| getifaddrs | 0.6.2 | Active IPv4 interface and netmask discovery for portable directed LAN beacons | MIT OR Apache-2.0 | https://crates.io/crates/getifaddrs/0.6.2 |
| hyper | 1.10.1 | HTTP/1 server integration | MIT | https://crates.io/crates/hyper/1.10.1 |
| serde | 1.0.228 | Typed API serialization | MIT OR Apache-2.0 | https://crates.io/crates/serde/1.0.228 |
| serde_json | 1.0.151 | JSON wire encoding | MIT OR Apache-2.0 | https://crates.io/crates/serde_json/1.0.151 |
| tokio | 1.53.1 | Async runtime, networking, channels, lifecycle | MIT | https://crates.io/crates/tokio/1.53.1 |
| tokio-stream | 0.1.18 | Broadcast-to-SSE stream adapter | MIT | https://crates.io/crates/tokio-stream/0.1.18 |
| tower-service | 0.3.3 | HTTP router service test driving | MIT | https://crates.io/crates/tower-service/0.3.3 |
| uuid | 1.26.0 | UUID v7 command IDs and local token entropy | MIT OR Apache-2.0 | https://crates.io/crates/uuid/1.26.0 |
| keyferry-layouts | workspace | Shared host-side US keyboard text validation for the pre-send preview | MIT OR Apache-2.0 | workspace crate |
| slint | 1.17.1 | Cross-platform declarative desktop UI, software renderer, winit backend | GPL-3.0-only OR Royalty-free-2.0 OR Software-3.0 | https://crates.io/crates/slint/1.17.1 |
| slint-build | 1.17.1 | Compile embedded Slint markup at build time | GPL-3.0-only OR Royalty-free-2.0 OR Software-3.0 | https://crates.io/crates/slint-build/1.17.1 |
| rustls | 0.23.41 | Pinned TLS 1.2 server for the dongle link (ring provider) | Apache-2.0 OR ISC OR MIT | https://crates.io/crates/rustls/0.23.41 |
| tokio-rustls | 0.26.4 | Tokio integration for the rustls TLS server | MIT OR Apache-2.0 | https://crates.io/crates/tokio-rustls/0.26.4 |
| hmac | 0.12.1 | HMAC-SHA256 device and provisioning authentication | MIT OR Apache-2.0 | https://crates.io/crates/hmac/0.12.1 |
| sha2 | 0.10.9 | SHA-256 hash backing the HMAC | MIT OR Apache-2.0 | https://crates.io/crates/sha2/0.10.9 |
| argon2 | 0.5.3 | Argon2id key derivation for the encrypted portable owner kit | MIT OR Apache-2.0 | https://crates.io/crates/argon2/0.5.3 |
| rcgen | 0.14.8 | P-256 owner-root and role-specific installation certificate generation | MIT OR Apache-2.0 | https://crates.io/crates/rcgen/0.14.8 |
| ring | 0.17.14 | P-256 proofs plus AES-256-GCM owner-kit encryption | Apache-2.0 AND ISC | https://crates.io/crates/ring/0.17.14 |
| zeroize | 1.9.0 | Best-effort clearing of owner-kit passphrases, derived keys, and decrypted buffers | Apache-2.0 OR MIT | https://crates.io/crates/zeroize/1.9.0 |
| ureq | 3.4.1 | Bounded HTTPS gateway probing with platform certificate verification | MIT OR Apache-2.0 | https://crates.io/crates/ureq/3.4.1 |
| hidapi | 2.6.7 | Exact-interface USB HID access for authenticated provisioning | MIT | https://crates.io/crates/hidapi/2.6.7 |
| windows | 0.62.2 | Windows BLE GATT transport for the daemon | MIT OR Apache-2.0 | https://crates.io/crates/windows/0.62.2 |
| windows-future | 0.3.2 | Cancellation and cleanup of bounded WinRT BLE operations | MIT OR Apache-2.0 | https://crates.io/crates/windows-future/0.3.2 |

The command CLI uses the Rust standard library for its small localhost HTTP/1
client and does not speak the dongle protocol. The separate pairing tool uses
HIDAPI only for the authenticated configuration interface.

The qualification firmware pins ESP-IDF v6.0.3 at commit
`76f5dedd9950a3012fee8fb7d5586df21fc67802`; `firmware/esp32s3/dependencies.lock` records the IDF
constraint. ESP-IDF is Apache-2.0 licensed; its bundled component licenses remain subject to the
upstream manifest. Future managed components must be exactly locked and added here with source,
license, and integrity evidence.

Relevant hardware references to verify during Phase 0:

- Waveshare ESP32-S3-GEEK resources for the delivered SKU and PCB revision.
- Espressif ESP32-S3 boot-mode, USB, security, partition, and tooling documentation.
- Exact USB descriptors and board identity observed from the owner's physical unit.

Documentation is not a substitute for evidence from the exact device.
