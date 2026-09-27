# Golden vectors

Vectors whose filenames begin `execute-` retain the former `0x10` message value solely as codec
compatibility evidence. `0x10` is reserved and is not a current ESP32-S3 session message. New
semantic command vectors must use the `COMMAND` envelope and its internal `report_actions` body.
Input Sequence v1 vectors use the same envelope with generated `command_kinds`, explicit chunk
index/count, and `INPUT_COMMAND_RESULT_V1`; a legacy 17-byte result cannot satisfy them.

Each JSON file contains:

- semantic frame fields;
- payload bytes in hexadecimal;
- full decoded frame including CRC;
- COBS-encoded wire frame including the final zero delimiter.

`scripts/check_seed.py` independently recomputes every vector. The Rust and C++ codec tests must use
or reproduce these values. Do not update an expected byte sequence merely to match implementation
output; first resolve which side violates `protocol-v1.md`.
