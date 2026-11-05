# Hardware evidence

Exact-unit board manifests and recovery records belong under the ignored `evidence/private/` tree.
Unique MAC addresses, device IDs, eFuse fingerprints, host names, raw flash dumps, and credentials
must never enter the tracked tree.

The supported hardware family is ESP32-S3 with board-specific display/input adapters. One Waveshare
ESP32-S3-GEEK unit passed two full recovery cycles. Its enclosed PCB silkscreen and optional
peripheral pinout are unmeasured, so that recovery result does not cover LCD, touch, TF-card, or
other board-specific adapters.
