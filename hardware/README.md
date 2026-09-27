# Hardware evidence

Exact-unit board manifests and recovery records belong under the ignored `evidence/private/` tree.
Public, redacted evidence may be committed under `evidence/`; unique MAC addresses, device IDs,
eFuse fingerprints, host names, raw flash dumps, and credentials must never enter the tracked tree.

The active hardware family is ESP32-S3 with board-specific display/input adapters. The first
Waveshare ESP32-S3-GEEK unit passed both recovery cycles. Its enclosed PCB silkscreen and optional
peripheral pinout remain unmeasured, so recovery qualification does not promote LCD, touch, TF-card,
or other board-specific adapters.

The original Cactus WHID is parked, not discarded. Its measured evidence and last recovery procedure
are indexed in `legacy/cactus-whid/RECOVERY.md`. Those AVR/Caterina instructions must never be reused
for an ESP32-S3 board.
