#!/usr/bin/env python3
"""Static gates for the portable authenticated provisioning core."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"check_provisioning: {message}")


def main() -> None:
    header = (
        ROOT
        / "firmware/esp32s3/components/kf_provisioning/include/keyferry/provisioning.h"
    ).read_text(encoding="utf-8")
    source = (
        ROOT / "firmware/esp32s3/components/kf_provisioning/src/provisioning.cpp"
    ).read_text(encoding="utf-8")
    pairing = (ROOT / "tools/keyferry-pairing/src/main.rs").read_text(encoding="utf-8")
    protocol = (ROOT / "protocol/provisioning-v1.md").read_text(encoding="utf-8")

    for token in (
        "kAuthenticationDomain",
        "current_generation_",
        "DecodeConfigPayload",
        "EqualConstantTime",
        "effects_.Commit",
        "ClearTransaction(true)",
        "MonotonicMilliseconds",
        "Session::Expire",
        "TransportLost",
        "authority_valid_",
    ):
        if token not in header + source:
            fail(f"provisioning core is missing {token}")
    for forbidden in ("tud_hid", "CommandExecutor", "BootKeyboardReport", "esp_restart"):
        if forbidden in header + source:
            fail(f"portable provisioning core crosses forbidden boundary: {forbidden}")
    for token in ("RECOVERY_SECRET", "kProvisioningKey", "initialize-recovery"):
        if token not in pairing:
            fail(f"private recovery-root handling is missing {token}")
    if "MAX_CERTIFICATE_BYTES: u64 = 1024" not in pairing:
        fail("pairing input does not enforce the persistent certificate bound")
    if "kProvisioningIdleTimeoutMs" not in header:
        fail("provisioning layout is not governed by the generated registry")
    if "kProvisioningCommitTagOffset" not in source:
        fail("provisioning field offsets are not governed by the generated registry")
    if 'ASCII "keyferry-provision-v1"' not in protocol:
        fail("the authenticated transcript is not documented")
    for token in (
        'ASCII "keyferry/maintenance/v2"',
        "fixed roaming-policy payload",
        "pending independent",
    ):
        if token not in protocol:
            fail(f"roaming migration protocol is missing {token}")
    if "PayloadFormat::kRoamingV2" not in source:
        fail("provisioning core does not select the roaming authentication domain")
    if "effects_.MigrateToRoaming" not in source:
        fail("authenticated roaming payload does not reach migration storage")
    print("check_provisioning: ok")


if __name__ == "__main__":
    main()
