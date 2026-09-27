#!/usr/bin/env python3
"""Static and optional ESP-IDF build checks for the HIL transport image."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "firmware" / "esp32s3" / "components" / "kf_esp_transport"
PROJECT = ROOT / "firmware" / "esp32s3" / "hil_endpoint"
STATUS_COMPONENT = ROOT / "firmware" / "esp32s3" / "components" / "kf_status"
DISPLAY_COMPONENT = (
    ROOT / "firmware" / "esp32s3" / "components" / "kf_esp_status_display"
)
DISPLAY_ORIENTATION_COMPONENT = (
    ROOT / "firmware" / "esp32s3" / "components" / "kf_display_orientation"
)
BOARDS = ROOT / "firmware" / "esp32s3" / "boards"
BOARD_GENERATOR = ROOT / "scripts" / "gen_board_profile.py"


def fail(message: str) -> None:
    raise SystemExit(f"check_esp_transport: {message}")


def require_tokens(path: Path, tokens: tuple[str, ...]) -> None:
    text = path.read_text(encoding="utf-8")
    missing = [token for token in tokens if token not in text]
    if missing:
        fail(f"{path.relative_to(ROOT)} missing: {', '.join(missing)}")


def source_checks() -> None:
    status_header = STATUS_COMPONENT / "include" / "keyferry" / "status.h"
    status_source = STATUS_COMPONENT / "src" / "status.cpp"
    require_tokens(
        status_header,
        (
            "class Presentation final",
            "Presentation() = default",
            "Presentation BuildPresentation(",
            "PresentationDensity density = PresentationDensity::kNormal",
        ),
    )
    portable_status = status_header.read_text(
        encoding="utf-8"
    ) + status_source.read_text(encoding="utf-8")
    for forbidden in ("board_profile", "esp_lcd", "gpio", "RGB565"):
        if forbidden in portable_status:
            fail(f"portable status presentation contains device detail: {forbidden}")
    require_tokens(
        DISPLAY_COMPONENT / "include" / "keyferry" / "esp_status_display.h",
        ("bool Show(const Presentation& presentation)",),
    )
    manifests = sorted(BOARDS.glob("*/board.json"))
    if len(manifests) < 2:
        fail("expected at least two declarative board profiles")
    for manifest in manifests:
        subprocess.run(
            [sys.executable, str(BOARD_GENERATOR), "--input", str(manifest)],
            check=True,
            capture_output=True,
            text=True,
        )
    expected_profiles = {
        "waveshare_geek_v1_1_reference":
            (1, "st7789", "normal", 240, 135, True),
        "lilygo_t_dongle_s3":
            (2, "st7735", "compact", 160, 80, False),
    }
    for profile_id, expected in expected_profiles.items():
        profile = json.loads(
            (BOARDS / profile_id / "board.json").read_text(encoding="utf-8")
        )
        actual = (
            profile["compatibility_id"],
            profile["display"]["controller"],
            profile["display"]["presentation"],
            profile["display"]["width"],
            profile["display"]["height"],
            profile["qualified"],
        )
        if actual != expected:
            fail(f"board profile {profile_id} differs from reviewed facts: {actual!r}")
    require_tokens(
        DISPLAY_COMPONENT / "src" / "esp_status_display.cpp",
        (
            "board::DisplayController::kSt7735",
            "board::DisplayController::kSt7789",
            "board::display.swap_color_bytes",
            "board::display.x_gap",
            "board::display.y_gap",
            "board::display.madctl ^ 0xC0",
        ),
    )
    require_tokens(
        DISPLAY_ORIENTATION_COMPONENT / "src" / "idf_display_orientation_storage.cpp",
        (
            '"kf_display"',
            '"orient_v1"',
            "nvs_get_blob",
            "nvs_set_blob",
            "nvs_commit",
        ),
    )
    source = COMPONENT / "src" / "esp_transport.cpp"
    source_text = source.read_text(encoding="utf-8")
    require_tokens(
        source,
        (
            "WIFI_STORAGE_RAM",
            "WIFI_MODE_STA",
            "WIFI_AUTH_WPA2_PSK",
            "esp_wifi_sta_get_ap_info",
            "ESP_TLS_AF_INET",
            "ESP_TLS_VER_TLS_1_2",
            "kRequiredCipherSuite",
            "VerifyMbedTlsPeer",
            "mbedtls_md_hmac",
            "esp_fill_random",
            "kTcpKeepAliveIdleSeconds",
            "kTcpKeepAliveIntervalSeconds",
            "kTcpKeepAliveProbeCount",
            "tls_keep_alive_cfg_t keep_alive{true",
            "tls_config.keep_alive_cfg = &keep_alive",
            "bool EspTransport::ServiceEndpointRead(std::uint64_t now_ms)",
            "ble_peripheral_.Poll",
            "published_path_",
            "session_.TransportFault()",
            "{wifi_available, ble_initialization.ok}",
            "arbiter_.Disable(Path::kBluetooth",
            "StationReadyForTls()",
            "esp_netif_get_ip_info",
            "if (actions.fail_closed)",
            "handoff_previous_path_ = candidate_path_",
            "path = Path::kBluetooth",
            "handoff_candidate_installation_id_ != expected_installation",
            "handoff_candidate_installation_id_)",
            "ble_peripheral_.Stop()",
            "FailClosedGatewayHandoff()",
            "bool EspTransport::RequestRestart()",
            "restart_requested_.exchange(false",
            "void EspTransport::RestartRuntime",
        ),
    )
    lowered = source_text.lower()
    for forbidden in ("wifi_mode_ap", "esp_wifi_set_mode(wifi_mode_ap", "listen(", "accept("):
        if forbidden in lowered:
            fail(f"outbound-only source contains forbidden token: {forbidden}")

    require_tokens(
        COMPONENT / "include" / "keyferry" / "esp_transport.h",
        (
            "TransportArbiter arbiter_",
            "BleTlsLink ble_tls_",
            "ble::IdfBlePeripheral ble_peripheral_",
            "std::atomic<Path> published_path_",
            "Path handoff_previous_path_{Path::kNone}",
            "bool handoff_fail_closed_{false}",
            "std::atomic_bool restart_requested_{false}",
        ),
    )

    read_loop = source_text.split(
        "bool EspTransport::ServiceEndpointRead(std::uint64_t now_ms)", 1
    )[1].split(
        "void EspTransport::PollBle", 1
    )[0]
    for forbidden in ("kTlsIdleTimeout", "esp_timer_get_time()"):
        if forbidden in read_loop:
            fail(f"persistent TLS read loop contains an idle-disconnect mechanism: {forbidden}")
    if (
        "!session_.authenticated()" not in read_loop
        or "kBleAuthenticationTimeoutMs" not in read_loop
    ):
        fail("TLS setup deadline is not restricted to pre-authentication")

    peer_policy = COMPONENT / "src" / "mbedtls_peer_policy.cpp"
    require_tokens(
        peer_policy,
        (
            "MBEDTLS_SSL_KEEP_PEER_CERTIFICATE",
            "mbedtls_ssl_get_version_number(ssl)",
            "mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl)",
            "mbedtls_ssl_get_verify_result(ssl)",
            "mbedtls_ssl_get_peer_cert(ssl)",
            "kP256SpkiPrefix",
            "mbedtls_md(sha256",
        ),
    )
    require_tokens(
        COMPONENT / "src" / "ble_tls_link.cpp",
        (
            "mbedtls_ssl_set_bio",
            "MBEDTLS_SSL_VERSION_TLS1_2",
            "kRequiredCipherSuite",
            "MBEDTLS_SSL_SESSION_TICKETS_DISABLED",
            "MBEDTLS_SSL_MAX_FRAG_LEN_512",
            "VerifyMbedTlsPeer",
            "psa_crypto_init",
            "kBleAuthenticationTimeoutMs",
            "kBleProgressTimeoutMs",
            "MBEDTLS_ERR_SSL_WANT_READ",
            "MBEDTLS_ERR_SSL_WANT_WRITE",
            "authentication_complete || !DeadlineExpired(now_ms)",
        ),
    )
    require_tokens(
        ROOT
        / "firmware/esp32s3/components/kf_ble_transport/src/idf_ble_transport.cpp",
        (
            "g_state.advertise_requested &&",
            "const bool still_requested = g_state.advertise_requested",
            "if (!still_requested)",
            "g_state.characteristics[0].access_cb = CharacteristicAccess",
            "g_state.characteristics[1].access_cb = IndicationAccess",
            "g_state.characteristics[1].flags = BLE_GATT_CHR_F_INDICATE",
            "ble_svc_gatt_init()",
            "if (event->notify_tx.status == 0)",
            "event->notify_tx.status == BLE_HS_EDONE",
            "ble_hs_id_gen_rnd(0, &gateway_address)",
            "ble_hs_id_set_rnd(gateway_address.val)",
            "ble_hs_util_ensure_addr(0)",
            "PeripheralStage::kGattCount",
            "PeripheralStage::kGattAdd",
            "kHostSyncTimeoutMs",
            "bool StopAdvertisingAndReconcile()",
            "ReconcileAdvertisingStopState(",
            "BLE_HS_EALREADY, &g_state.advertising",
        ),
    )
    ble_source = (
        ROOT / "firmware/esp32s3/components/kf_ble_transport/src/idf_ble_transport.cpp"
    ).read_text(encoding="utf-8")
    indication_definition = ble_source.split(
        "g_state.characteristics[1].uuid", 1
    )[1].split("g_state.services[0].type", 1)[0]
    if "BLE_GATT_CHR_F_READ" in indication_definition:
        fail("outbound BLE characteristic gained a direct read surface")
    if ble_source.count("StopAdvertisingAndReconcile();") != 2:
        fail("both intentional advertising-stop paths must reconcile local state")
    if "(void)ble_gap_adv_stop();" in ble_source:
        fail("intentional advertising stop bypasses local-state reconciliation")
    if "nvs_flash_init" in ble_source:
        fail("BLE adapter still owns global NVS initialization")
    hid_source = (
        ROOT
        / "firmware/esp32s3/components/kf_ble_hid/src/idf_ble_hid_peripheral.cpp"
    ).read_text(encoding="utf-8")
    if "ble_hs_id_gen_rnd" in hid_source or "ble_hs_id_set_rnd" in hid_source:
        fail("direct Bluetooth HID must retain its bonded controller identity")
    require_tokens(
        source,
        (
            "ble_tls_.PollHealthy(now_ms, session_.authenticated())",
            "if (failed_path == Path::kBluetooth)",
            "ble_peripheral_.Disconnect()",
        ),
    )
    tls_verify = peer_policy.read_text(encoding="utf-8")
    peer_getter = tls_verify.index("mbedtls_ssl_get_peer_cert(ssl)")
    for policy_getter in (
        "mbedtls_ssl_get_version_number(ssl)",
        "mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl)",
        "mbedtls_ssl_get_verify_result(ssl)",
    ):
        if tls_verify.index(policy_getter) > peer_getter:
            fail("peer certificate is fetched before the final SSL policy getter")
    peer_use_end = tls_verify.index("mbedtls_md(sha256", peer_getter)
    if "mbedtls_ssl_" in tls_verify[peer_getter + len("mbedtls_ssl_get_peer_cert") : peer_use_end]:
        fail("SSL API is called while the borrowed peer certificate pointer is live")

    require_tokens(
        PROJECT / "sdkconfig.defaults",
        (
            "CONFIG_ESP_MAIN_TASK_STACK_SIZE=24576",
            "CONFIG_LOG_DEFAULT_LEVEL_WARN=y",
            "CONFIG_LOG_MAXIMUM_LEVEL=2",
            "CONFIG_ESP_WIFI_NVS_ENABLED=n",
            "CONFIG_BT_ENABLED=y",
            "CONFIG_BT_NIMBLE_ENABLED=y",
            "CONFIG_BT_NIMBLE_ROLE_PERIPHERAL=y",
            "# CONFIG_BT_NIMBLE_ROLE_CENTRAL is not set",
            "CONFIG_BT_NIMBLE_SECURITY_ENABLE=y",
            "CONFIG_BT_NIMBLE_HID_SERVICE=y",
            "CONFIG_BT_NIMBLE_GAP_SERVICE=y",
            "CONFIG_BT_NIMBLE_MAX_CONNECTIONS=1",
            "CONFIG_BT_NIMBLE_MAX_CCCDS=4",
            "CONFIG_BT_CTRL_BLE_MAX_ACT=2",
            "CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM=0",
            "# CONFIG_BT_CTRL_DTM_ENABLE is not set",
            "# CONFIG_BT_CTRL_BLE_SCAN is not set",
            "CONFIG_BT_CTRL_BLE_SECURITY_ENABLE=y",
            "# CONFIG_ESP_WIFI_ENABLE_WPA3_SAE is not set",
            "# CONFIG_ESP_WIFI_SOFTAP_SUPPORT is not set",
            "# CONFIG_ESP_WIFI_ENTERPRISE_SUPPORT is not set",
            "CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y",
            "# CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 is not set",
            "CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE=y",
            "CONFIG_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH=y",
            "CONFIG_TINYUSB_HID_COUNT=3",
            "CONFIG_TINYUSB_VENDOR_COUNT=0",
            "# CONFIG_SECURE_BOOT is not set",
            "# CONFIG_SECURE_FLASH_ENC_ENABLED is not set",
        ),
    )
    require_tokens(
        PROJECT / "main" / "app_main.cpp",
        (
            "KEYFERRY_HIL_PRIVATE_CONFIG",
            "class HilRuntime",
            "CommandExecutor command_",
            "HeldKeyDeadlineFired",
            "tud_hid_report",
            "tud_hid_report_complete_cb",
            "tud_hid_report_failed_cb",
            "TUD_HID_INOUT_DESCRIPTOR",
            "TUD_HID_REPORT_DESC_GENERIC_INOUT",
            "tud_hid_n_report",
            "kProvisioningHidInstance",
            "usb_transfer_in_flight_",
            "DisarmComplete",
            "MessageType::kCommandResult",
            "->Run()",
            "nvs_flash_init()",
            "heap_caps_get_minimum_free_size",
            "keyferry::board::capabilities.display",
            "keyferry::board::compatibility_id",
            "keyferry::board::display.presentation",
            "keyferry::status::PresentationDensity::kCompact",
            "keyferry::status::SelectPage(snapshot, elapsed_ms)",
            "constexpr std::uint32_t kTransportTaskStackBytes = 12288;",
            "kTransportTaskStackBytes / sizeof(StackType_t)",
            'xTaskCreateStatic(TransportTask, "kf-transport",',
            "transport_task_stack.size(), &*transport, 5,",
            "transport_task_stack.data()",
            "&transport_task_control",
            "MessageType::kResetBleHidBond",
            "SendBondResetStatus",
            "ble_hid_.ResetBond()",
            "MessageType::kGetDisplayOrientation",
            "MessageType::kSetDisplayOrientation",
            "SendDisplayOrientationStatus",
            "keyferry::display_orientation::Save(",
            "esp_restart()",
            "kBleControlConfigurationDescriptor",
            "kBleControlDeviceDescriptor",
            "ble_control_usb ? kBleControlConfigurationDescriptor",
        ),
    )
    ble_hid_source = ROOT / (
        "firmware/esp32s3/components/kf_ble_hid/src/"
        "idf_ble_hid_peripheral.cpp"
    )
    require_tokens(
        ble_hid_source,
        (
            "BondResetResult IdfBleHidPeripheral::ResetBond()",
            "ble_store_util_bonded_peers",
            "ble_store_util_delete_peer",
            "return BondResetResult::kForgotten",
            "BondStoreStatus IdfBleHidPeripheral::bond_status() const",
            "BondStoreState::kMultipleInvalid",
            "BondStoreState::kStoreError",
        ),
    )
    if "nvs_erase_all" in ble_hid_source.read_text(encoding="utf-8"):
        fail("Bluetooth keyboard bond reset erases an entire NVS namespace")
    require_tokens(
        ROOT
        / "firmware/esp32s3/components/kf_runtime_config/src/runtime_config.cpp",
        (
            "roaming_verification_workspace =",
            "&output->verification_workspace",
        ),
    )
    require_tokens(
        ROOT
        / "firmware/esp32s3/components/kf_esp_transport/src/mbedtls_peer_policy.cpp",
        (
            "RoamingPolicyVerificationWorkspace* workspace",
            "authorization, workspace",
        ),
    )
    require_tokens(
        PROJECT / "CMakeLists.txt",
        (
            'set(KEYFERRY_PRIVATE_HEADER "" CACHE FILEPATH',
            'configure_file("${KEYFERRY_PRIVATE_HEADER}"',
            '"${KEYFERRY_PRIVATE_CONFIG_DIR}/keyferry_hil_private.h" COPYONLY',
        ),
    )
    require_tokens(
        PROJECT / "main" / "CMakeLists.txt",
        (
            "${KEYFERRY_BOARD_INCLUDE_DIR}",
            "if(KEYFERRY_PRIVATE_HEADER)",
            '"${CMAKE_COMMAND}" -E copy_if_different',
        ),
    )
    require_tokens(
        ROOT / "scripts" / "build_first_hil.ps1",
        (
            "[string]$PrivateHeader = ''",
            "PrivateHeader must name a generated keyferry_hil_private.h file.",
            '"-DKEYFERRY_PRIVATE_HEADER=$resolvedPrivateHeader"',
        ),
    )
    require_tokens(
        PROJECT / "partitions.csv",
        (
            "factory,  app,  factory, 0x10000, 1M,",
            "kf_cfg_a, data, 0x40,     0x110000, 0x4000,",
            "kf_cfg_b, data, 0x41,     0x114000, 0x4000,",
            "nvs,      data, nvs,      0x118000, 0x3000,",
        ),
    )
    require_tokens(
        ROOT
        / "firmware/esp32s3/components/kf_config_store/src/idf_config_storage.cpp",
        (
            'esp_partition_find_first(ESP_PARTITION_TYPE_DATA',
            "partition->size == kConfigPartitionBytes",
            "partition->encrypted == false",
            "esp_partition_erase_range",
            "esp_partition_write",
        ),
    )
    require_tokens(
        ROOT / "firmware/esp32s3/components/kf_config_store/src/config_storage.cpp",
        (
            "kCommitOffset",
            "kCommitMarker",
            "InspectSlot(View(*scratch)).condition == SlotCondition::kValid",
        ),
    )
    require_tokens(
        ROOT / "firmware/esp32s3/components/kf_esp_discovery/src/esp_discovery.cpp",
        (
            "esp_netif_get_ip_info",
            "local.sin_addr.s_addr = info.ip.addr",
            "std::array<std::uint8_t, kBeaconSize + 1>",
            "SelectDiscoveredHost",
        ),
    )
    main_source = (
        ROOT / "firmware/esp32s3/hil_endpoint/main/app_main.cpp"
    ).read_text(encoding="utf-8")
    for token in (
        "IdfConfigStorage",
        "runtime_config::ResolveOperationalBoot",
        "IdfRecoveryAnchorStorage",
        "BuildPrivateBootstrapConfig",
        "configuration locked",
    ):
        if token not in main_source:
            fail(f"HIL boot configuration path is missing {token}")
    for forbidden in ("tud_hid_ready()", "tud_hid_report("):
        if forbidden in main_source:
            fail(f"multi-instance HIL source uses instance-0 shorthand: {forbidden}")
    if 'xTaskCreate(TransportTask, "kf-transport", 12288,' in main_source:
        fail("roaming peer admission regained its unsafe 12 KiB transport stack")
    if "vTaskDelay(pdMS_TO_TICKS(1))" in main_source:
        fail("HIL service loop delay truncates to zero at the configured 100 Hz tick rate")
    status_task = main_source.split("void StatusTask(void* context)", 1)[1].split(
        "\n}\n\n}  // namespace", 1
    )[0]
    for forbidden in (
        "FailClosed",
        "CommandScopedArm",
        "Disarm(",
        "AuthenticatedFrame",
        "tud_hid",
        "KEYFERRY_HIL_PRIVATE_CONFIG",
        "WifiProfile",
        "ssid",
        "password",
        "secret",
        "device_id",
        "ipv4",
    ):
        if forbidden in status_task:
            fail(f"optional status task gained command authority: {forbidden}")
    if "CommitConfig(" in main_source:
        fail("HIL boot path must never write configuration implicitly")
    provisioning_bridge = PROJECT / "main" / "provisioning_adapter.cpp"
    provisioning_bridge_source = provisioning_bridge.read_text(encoding="utf-8")
    require_tokens(
        provisioning_bridge,
        (
            "xQueueCreateStatic",
            "xQueueSend",
            "tud_hid_n_ready",
            "tud_hid_n_report",
            "policy_.CommitAllowed()",
            "policy_.ProvisioningCommitResponseCompleted()",
            "session_.TransportLost()",
            "operation == provisioning::Operation::kPolicyStatus",
        ),
    )
    if "accepting_request_" in provisioning_bridge_source:
        fail("USB provisioning transport regained host-timing admission")
    callback_body = provisioning_bridge_source.split(
        "void ProvisioningAdapter::SetReport", 1
    )[1].split("void ProvisioningAdapter::ReportCompleted", 1)[0]
    for forbidden in (
        "session_.Handle",
        "CommitConfig",
        "esp_partition",
        "esp_restart",
        "mbedtls",
    ):
        if forbidden in callback_body:
            fail(f"TinyUSB provisioning callback performs forbidden work: {forbidden}")
    provisioning_fault = main_source.split(
        "void ProvisioningFault() override", 1
    )[1].split("void ProvisioningCommitResponseCompleted() override", 1)[0]
    if "if (!provisioning_active_)" not in provisioning_fault:
        fail("inactive USB provisioning faults can disrupt unrelated runtime state")
    config_store = (
        ROOT / "firmware/esp32s3/components/kf_config_store/src/config_store.cpp"
    ).read_text(encoding="utf-8")
    for forbidden in ("WifiProfile profile{}", "PairedHost host{}"):
        if forbidden in config_store:
            fail("config slot inspection must not copy secrets into stack-local records")
    require_tokens(
        ROOT
        / "firmware/esp32s3/components/kf_config_store/include/keyferry/roaming_storage.h",
        ("RoamingEndpointConfig policy{}",),
    )
    roaming_storage = (
        ROOT / "firmware/esp32s3/components/kf_config_store/src/roaming_storage.cpp"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "RoamingEndpointConfig active{}",
        "RoamingEndpointConfig config_a{}",
        "RoamingEndpointConfig config_b{}",
        "std::array<std::uint8_t, kRoamingConfigSlotBytes> expected{}",
    ):
        if forbidden in roaming_storage:
            fail(f"roaming migration regained a large stack-local record: {forbidden}")
    esp_provisioning = (
        ROOT
        / "firmware/esp32s3/components/kf_esp_provisioning/src/esp_provisioning.cpp"
    ).read_text(encoding="utf-8")
    if "migration_request_ = {" in esp_provisioning:
        fail("ESP migration effects materialize the persistent request on the task stack")
    if (PROJECT / "main" / "keyferry_hil_private.h").exists():
        fail("real private header must not exist in the source tree")


def build_checks(build: Path) -> None:
    private_header = build / "private-config" / "keyferry_hil_private.h"
    if not private_header.is_file():
        fail("generated private HIL configuration is absent")
    description = json.loads((build / "project_description.json").read_text(encoding="utf-8"))
    components = set(description["build_components"])
    required = {
        "kf_command_executor",
        "kf_ble_transport",
        "kf_config_store",
        "kf_discovery",
        "kf_display_orientation",
        "kf_esp_discovery",
        "kf_esp_provisioning",
        "kf_esp_status_display",
        "kf_esp_transport",
        "kf_hid_core",
        "kf_provisioning",
        "kf_secure_endpoint",
        "kf_status",
        "espressif__esp_tinyusb",
        "esp_lcd",
        "esp_wifi",
        "esp_coex",
        "esp-tls",
        "mbedtls",
        "bt",
        "nvs_flash",
    }
    if missing := sorted(required - components):
        fail(f"build lacks required components: {', '.join(missing)}")
    sdkconfig = (build / "sdkconfig").read_text(encoding="utf-8")
    for token in (
        "CONFIG_ESP_MAIN_TASK_STACK_SIZE=24576",
        "CONFIG_LOG_DEFAULT_LEVEL_WARN=y",
        "CONFIG_LOG_MAXIMUM_LEVEL=2",
        "# CONFIG_ESP_WIFI_NVS_ENABLED is not set",
        "CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y",
        "# CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 is not set",
        "CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE=y",
        "# CONFIG_SECURE_BOOT is not set",
        "# CONFIG_SECURE_FLASH_ENC_ENABLED is not set",
        "CONFIG_TINYUSB_HID_COUNT=3",
        "CONFIG_BT_ENABLED=y",
        "CONFIG_BT_NIMBLE_ENABLED=y",
        "CONFIG_BT_NIMBLE_ROLE_PERIPHERAL=y",
        "# CONFIG_BT_NIMBLE_ROLE_CENTRAL is not set",
        "# CONFIG_BT_NIMBLE_ROLE_OBSERVER is not set",
        "CONFIG_BT_NIMBLE_GATT_SERVER=y",
        "CONFIG_BT_NIMBLE_SECURITY_ENABLE=y",
        "CONFIG_BT_NIMBLE_MAX_CONNECTIONS=1",
        "CONFIG_BT_NIMBLE_MAX_CCCDS=4",
        "CONFIG_BT_CTRL_BLE_MAX_ACT=2",
        "CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU=247",
        "CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM=0",
        "CONFIG_BT_NIMBLE_HID_SERVICE=y",
        "CONFIG_BT_NIMBLE_GAP_SERVICE=y",
        "CONFIG_BT_CTRL_BLE_SECURITY_ENABLE=y",
        "CONFIG_ESP_COEX_SW_COEXIST_ENABLE=y",
        "CONFIG_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH=y",
    ):
        if token not in sdkconfig:
            fail(f"built sdkconfig missing: {token}")

    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    if "KEYFERRY_MSC_SIZE_PROBE:BOOL=ON" in cache:
        fail("MSC size probe is unqualified and cannot pass production inspection")
    if re.search(r"^CONFIG_TINYUSB_MSC_ENABLED=y$", sdkconfig, re.MULTILINE):
        fail("MSC is unqualified and cannot pass production inspection")
    if "KEYFERRY_PRIVATE_CONFIG_DIR:" in cache:
        fail("private configuration directory became a CMake cache input")
    match = re.search(
        r"^KEYFERRY_BOARD:STRING=([a-z0-9][a-z0-9_]*)$", cache, re.MULTILINE
    )
    if match is None or not (BOARDS / match.group(1) / "board.json").is_file():
        fail("build lacks a valid declarative board profile")
    generated_profile = build / "generated-board" / "board_profile.h"
    expected_id = f'inline constexpr char id[] = "{match.group(1)}"'
    if (
        not generated_profile.is_file()
        or expected_id not in generated_profile.read_text(encoding="utf-8")
    ):
        fail("generated board profile does not match the selected manifest")

    archive = build / "esp-idf" / "kf_esp_transport" / "libkf_esp_transport.a"
    if not archive.is_file():
        fail("transport component archive is missing")
    ble_archive = build / "esp-idf" / "kf_ble_transport" / "libkf_ble_transport.a"
    if not ble_archive.is_file():
        fail("BLE transport component archive is missing")
    config_archive = build / "esp-idf" / "kf_config_store" / "libkf_config_store.a"
    if not config_archive.is_file():
        fail("config storage component archive is missing")
    provisioning_archive = (
        build / "esp-idf" / "kf_esp_provisioning" / "libkf_esp_provisioning.a"
    )
    if not provisioning_archive.is_file():
        fail("ESP provisioning component archive is missing")
    discovery_archive = build / "esp-idf" / "kf_esp_discovery" / "libkf_esp_discovery.a"
    if not discovery_archive.is_file():
        fail("ESP discovery component archive is missing")
    flash_args = (build / "flash_args").read_text(encoding="utf-8").lower()
    for forbidden in ("--force", "erase_flash", "erase-region"):
        if forbidden in flash_args:
            fail(f"unsafe flash token: {forbidden}")

    app = build / "keyferry_hil_endpoint.bin"
    app_partition_size = 0x100000
    minimum_headroom = 0x8000
    if not app.is_file():
        fail("application binary is missing")
    if app.stat().st_size > app_partition_size - minimum_headroom:
        fail(
            "application leaves less than 32 KiB in its 1 MiB partition: "
            f"{app.stat().st_size} bytes"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    source_checks()
    if args.build_dir:
        build_checks(args.build_dir.resolve())
    print("check_esp_transport: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
