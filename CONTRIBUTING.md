# Contributing

Keep changes small and focused, and add a test for any behavior change.

Before opening a pull request, run:

```text
python scripts/check.py
cargo test --workspace
```

Changes to the device protocol must update `protocol/`, the generated constants
(`python scripts/gen_protocol.py`), and the golden vectors together. Security-relevant changes
should be read against `SECURITY.md`.
