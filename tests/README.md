# Test layers

- `crates/*` contains fast deterministic unit tests.
- `protocol/vectors/` is the cross-language byte contract.
- `firmware/common/test/` validates fixed-buffer C++ primitives on a host compiler.
- `tests/integration/` will hold daemon-to-simulator and daemon-to-firmware tests.
- `tests/fuzz/` will hold Rust and native parser fuzz targets.
- `tests/hil/` will hold exact-device harnesses and evidence instructions.

Never label simulator output as USB, radio, preboot, or exact-hardware proof.
