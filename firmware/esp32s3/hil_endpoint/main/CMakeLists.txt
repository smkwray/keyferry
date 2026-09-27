idf_component_register(
    SRCS "app_main.cpp" "provisioning_adapter.cpp"
    INCLUDE_DIRS "."
    REQUIRES
        esp_tinyusb
        esp_app_format
        esp_driver_gpio
        freertos
        kf_ble_hid
        kf_command_executor
        kf_ble_transport
        kf_config_store
        kf_display_orientation
        kf_file_handoff
        kf_esp_provisioning
        kf_esp_status_display
        kf_esp_transport
        kf_output_mode
        kf_provisioning
        kf_runtime_config
        kf_status
        mbedtls
        nvs_flash
    PRIV_REQUIRES esp_psram
)

target_include_directories(${COMPONENT_LIB} BEFORE PRIVATE
    "${KEYFERRY_PRIVATE_CONFIG_DIR}"
    "${KEYFERRY_BOARD_INCLUDE_DIR}"
)
target_compile_definitions(${COMPONENT_LIB} PRIVATE KEYFERRY_HIL_PRIVATE_CONFIG=1)
if(KEYFERRY_MSC_SIZE_PROBE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        KEYFERRY_MSC_SIZE_PROBE=1)
endif()
if(KEYFERRY_MSC_MEMORY_PROBE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        KEYFERRY_MSC_MEMORY_PROBE=1)
endif()
if(KEYFERRY_FILE_HANDOFF)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        KEYFERRY_FILE_HANDOFF=1)
endif()
if(KEYFERRY_BLE_HID_SPIKE STREQUAL "hid")
    target_sources(${COMPONENT_LIB} PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/../spikes/ble_hid_spike.cpp")
    target_include_directories(${COMPONENT_LIB} PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/../spikes/include"
        "${CMAKE_CURRENT_LIST_DIR}/../../components/kf_ble_hid/include")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        KEYFERRY_BLE_HID_COMPILE_ONLY_SPIKE=1)
endif()

target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

if(KEYFERRY_PRIVATE_HEADER)
    add_custom_target(keyferry_private_config_refresh ALL
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${KEYFERRY_PRIVATE_HEADER}"
            "${KEYFERRY_PRIVATE_CONFIG_DIR}/keyferry_hil_private.h"
        COMMENT "Refreshing explicit private device configuration"
        VERBATIM
    )
else()
    add_custom_target(keyferry_private_config_refresh ALL
        COMMAND
            "${CMAKE_COMMAND}" -E env
            "KEYFERRY_PAIRING_OUTPUT_DIR=${KEYFERRY_PRIVATE_CONFIG_DIR}"
            "${KEYFERRY_CARGO_EXECUTABLE}" run --locked --offline --quiet
            -p keyferry-pairing -- materialize
        WORKING_DIRECTORY "${KEYFERRY_WORKSPACE_ROOT}"
        COMMENT "Validating private first-HIL configuration"
        VERBATIM
    )
endif()
add_dependencies(${COMPONENT_LIB} keyferry_private_config_refresh)
