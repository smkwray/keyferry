# Test layers

- `crates/*` contains fast deterministic unit tests.
- `protocol/vectors/` is the cross-language byte contract.
- `firmware/common/test/` validates fixed-buffer C++ primitives on a host compiler.
- `tests/test_*.py` checks scripts, packaging and the public boundary
  (`python -m unittest discover -s tests`).
- `tests/hil/` lists what a hardware-in-loop run must record.

Never label simulator output as USB, radio, preboot, or exact-hardware proof.
