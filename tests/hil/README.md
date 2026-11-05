# Hardware-in-loop tests

This directory holds documentation only. Every hardware-in-loop run must record:

- device label and hardware manifest hash;
- firmware, daemon, and controller commit/image hashes;
- host and target OS/build;
- AP/router model and relevant settings;
- exact test selection and result artifact;
- whether a human observed the target display or only USB report acknowledgments.

Tests must include a physical emergency power/reset path. Never run destructive or repeated-key tests
against a target containing unsaved work.
