cmake_minimum_required(VERSION 3.16)

set(IDF_TARGET "esp32s3" CACHE STRING "ESP-IDF target")
set(PROJECT_VER "0.1.0")
set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../components")
set(KEYFERRY_BOARD "" CACHE STRING "Compile-time keyferry board profile")
set(KEYFERRY_PRIVATE_HEADER "" CACHE FILEPATH
    "Optional pre-materialized private device header")
set(KEYFERRY_BLE_HID_SPIKE "off" CACHE STRING
    "Off-device BLE HID resource spike: off, security, or hid")
option(KEYFERRY_MSC_SIZE_PROBE
    "Unflashed, empty-medium MSC descriptor and resource measurement" OFF)
option(KEYFERRY_MSC_MEMORY_PROBE
    "Unflashed MSC internal-memory qualification image and candidate layout" OFF)
option(KEYFERRY_FILE_HANDOFF
    "Opt-in RAM-backed USB file handoff candidate" OFF)
if(KEYFERRY_FILE_HANDOFF AND KEYFERRY_MSC_SIZE_PROBE)
    message(FATAL_ERROR "File handoff and MSC probes are separate build modes")
endif()
if(KEYFERRY_MSC_MEMORY_PROBE AND NOT KEYFERRY_MSC_SIZE_PROBE)
    message(FATAL_ERROR "MSC memory probe requires the MSC size probe")
endif()
if(KEYFERRY_MSC_SIZE_PROBE)
    # Deliberately invalid as a release version so firmware-tool cannot plan
    # an app-only update from an exploratory image.
    set(PROJECT_VER "msc-size-probe")
endif()
if(KEYFERRY_MSC_MEMORY_PROBE)
    # The authenticated wire identity requires a valid SemVer. Firmware-tool
    # reserves this prerelease identifier so it cannot become an update image.
    set(PROJECT_VER "0.0.0-probe.mem")
endif()
if(KEYFERRY_FILE_HANDOFF)
    set(PROJECT_VER "0.2.0-file.3")
endif()
set_property(CACHE KEYFERRY_BLE_HID_SPIKE PROPERTY STRINGS off security hid)
set(KEYFERRY_WORKSPACE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../..")
set(KEYFERRY_PRIVATE_CONFIG_DIR "${CMAKE_BINARY_DIR}/private-config")

include("${CMAKE_CURRENT_LIST_DIR}/../boards/load_board_profile.cmake")

find_program(KEYFERRY_CARGO_EXECUTABLE cargo REQUIRED)
if(KEYFERRY_PRIVATE_HEADER)
    get_filename_component(KEYFERRY_PRIVATE_HEADER
        "${KEYFERRY_PRIVATE_HEADER}" ABSOLUTE)
    if(NOT EXISTS "${KEYFERRY_PRIVATE_HEADER}" OR
       IS_DIRECTORY "${KEYFERRY_PRIVATE_HEADER}")
        message(FATAL_ERROR "Explicit private device header is absent or invalid")
    endif()
    file(SIZE "${KEYFERRY_PRIVATE_HEADER}" KEYFERRY_PRIVATE_HEADER_SIZE)
    if(KEYFERRY_PRIVATE_HEADER_SIZE LESS 1 OR
       KEYFERRY_PRIVATE_HEADER_SIZE GREATER 16384)
        message(FATAL_ERROR "Explicit private device header has an invalid size")
    endif()
    file(MAKE_DIRECTORY "${KEYFERRY_PRIVATE_CONFIG_DIR}")
    configure_file("${KEYFERRY_PRIVATE_HEADER}"
        "${KEYFERRY_PRIVATE_CONFIG_DIR}/keyferry_hil_private.h" COPYONLY)
else()
    execute_process(
        COMMAND
            "${CMAKE_COMMAND}" -E env
            "KEYFERRY_PAIRING_OUTPUT_DIR=${KEYFERRY_PRIVATE_CONFIG_DIR}"
            "${KEYFERRY_CARGO_EXECUTABLE}" run --locked --offline --quiet
            -p keyferry-pairing -- materialize
        WORKING_DIRECTORY "${KEYFERRY_WORKSPACE_ROOT}"
        RESULT_VARIABLE KEYFERRY_PAIRING_RESULT
        OUTPUT_QUIET
        ERROR_VARIABLE KEYFERRY_PAIRING_ERROR
    )
    if(NOT KEYFERRY_PAIRING_RESULT EQUAL 0)
        string(STRIP "${KEYFERRY_PAIRING_ERROR}" KEYFERRY_PAIRING_ERROR)
        message(FATAL_ERROR
            "Private first-HIL pairing validation/materialization failed. "
            "Create and validate secrets/first-hil before configuring this image. "
            "${KEYFERRY_PAIRING_ERROR}"
        )
    endif()
endif()

list(APPEND SDKCONFIG_DEFAULTS
    "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults"
    "${KEYFERRY_BOARD_SDKCONFIG_DEFAULTS}")
if(KEYFERRY_MSC_SIZE_PROBE)
    list(APPEND SDKCONFIG_DEFAULTS
        "${CMAKE_CURRENT_LIST_DIR}/spikes/sdkconfig.msc-size.defaults")
endif()
if(KEYFERRY_MSC_MEMORY_PROBE)
    list(APPEND SDKCONFIG_DEFAULTS
        "${CMAKE_CURRENT_LIST_DIR}/spikes/sdkconfig.msc-memory.defaults")
endif()
if(KEYFERRY_FILE_HANDOFF)
    list(APPEND SDKCONFIG_DEFAULTS
        "${CMAKE_CURRENT_LIST_DIR}/spikes/sdkconfig.msc-size.defaults"
        "${CMAKE_CURRENT_LIST_DIR}/spikes/sdkconfig.msc-memory.defaults"
        "${CMAKE_CURRENT_LIST_DIR}/spikes/sdkconfig.file.defaults")
    if(KEYFERRY_BOARD STREQUAL "waveshare_geek_v1_1_reference")
        list(APPEND SDKCONFIG_DEFAULTS
            "${CMAKE_CURRENT_LIST_DIR}/spikes/sdkconfig.file-waveshare.defaults")
    endif()
endif()

if(KEYFERRY_BLE_HID_SPIKE STREQUAL "security" OR
   KEYFERRY_BLE_HID_SPIKE STREQUAL "hid")
    list(APPEND SDKCONFIG_DEFAULTS
        "${CMAKE_CURRENT_LIST_DIR}/spikes/sdkconfig.security.defaults")
endif()
if(KEYFERRY_BLE_HID_SPIKE STREQUAL "hid")
    list(APPEND SDKCONFIG_DEFAULTS
        "${CMAKE_CURRENT_LIST_DIR}/spikes/sdkconfig.hid.defaults")
elseif(NOT KEYFERRY_BLE_HID_SPIKE STREQUAL "off" AND
       NOT KEYFERRY_BLE_HID_SPIKE STREQUAL "security")
    message(FATAL_ERROR
        "Unsupported KEYFERRY_BLE_HID_SPIKE=${KEYFERRY_BLE_HID_SPIKE}; "
        "expected off, security, or hid"
    )
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(keyferry_hil_endpoint)

if((KEYFERRY_MSC_SIZE_PROBE OR KEYFERRY_FILE_HANDOFF) AND
   NOT CONFIG_TINYUSB_MSC_ENABLED)
    message(FATAL_ERROR "MSC build requires an MSC-enabled sdkconfig")
elseif(NOT KEYFERRY_MSC_SIZE_PROBE AND NOT KEYFERRY_FILE_HANDOFF AND
       CONFIG_TINYUSB_MSC_ENABLED)
    message(FATAL_ERROR
        "MSC sdkconfig cannot be reused as a production HIL image")
endif()
if(KEYFERRY_MSC_MEMORY_PROBE OR KEYFERRY_FILE_HANDOFF)
    if(NOT CONFIG_PARTITION_TABLE_FILENAME STREQUAL
            "spikes/partitions.msc-memory.csv")
        message(FATAL_ERROR
            "MSC memory probe requires the relocated candidate partition table")
    endif()
elseif(CONFIG_PARTITION_TABLE_FILENAME STREQUAL
        "spikes/partitions.msc-memory.csv")
    message(FATAL_ERROR
        "Candidate MSC partition table cannot be reused in another build")
endif()
if(KEYFERRY_FILE_HANDOFF)
    if(NOT CONFIG_MBEDTLS_DYNAMIC_BUFFER OR
       NOT CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN EQUAL 16384 OR
       NOT CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN EQUAL 4096)
        message(FATAL_ERROR
            "File handoff requires on-demand TLS buffers with unchanged record limits")
    endif()
    if(KEYFERRY_BOARD STREQUAL "waveshare_geek_v1_1_reference")
        if(NOT CONFIG_SPIRAM OR NOT CONFIG_SPIRAM_MODE_QUAD OR
           NOT CONFIG_SPIRAM_SPEED_40M OR
           NOT CONFIG_SPIRAM_USE_CAPS_ALLOC OR
           NOT CONFIG_SPIRAM_IGNORE_NOTFOUND)
            message(FATAL_ERROR
                "Waveshare file handoff requires guarded quad PSRAM caps allocation")
        endif()
    elseif(CONFIG_SPIRAM)
        message(FATAL_ERROR
            "PSRAM is not qualified for this file-handoff board")
    endif()
endif()

if(KEYFERRY_MSC_SIZE_PROBE OR KEYFERRY_FILE_HANDOFF)
    # ESP TinyUSB's managed MSC adapter brings flash/SD storage callbacks and
    # mount behavior. Exclude that adapter in the opt-in MSC builds; app_main
    # supplies read-only synthetic-medium callbacks instead.
    idf_component_get_property(KEYFERRY_ESP_TINYUSB_LIB
        espressif__esp_tinyusb COMPONENT_LIB)
    get_target_property(KEYFERRY_ESP_TINYUSB_SOURCES
        ${KEYFERRY_ESP_TINYUSB_LIB} SOURCES)
    foreach(KEYFERRY_MSC_ADAPTER_SOURCE IN ITEMS
            tinyusb_msc storage_spiflash storage_sdmmc)
        set(KEYFERRY_MSC_ADAPTER_MATCHES
            "${KEYFERRY_ESP_TINYUSB_SOURCES}")
        list(FILTER KEYFERRY_MSC_ADAPTER_MATCHES INCLUDE REGEX
            "[/\\\\]${KEYFERRY_MSC_ADAPTER_SOURCE}\\.c$")
        list(LENGTH KEYFERRY_MSC_ADAPTER_MATCHES
            KEYFERRY_MSC_ADAPTER_MATCH_COUNT)
        if(NOT KEYFERRY_MSC_ADAPTER_MATCH_COUNT EQUAL 1)
            message(FATAL_ERROR
                "Pinned ESP TinyUSB MSC adapter source changed: "
                "${KEYFERRY_MSC_ADAPTER_SOURCE}")
        endif()
    endforeach()
    list(FILTER KEYFERRY_ESP_TINYUSB_SOURCES EXCLUDE REGEX
        "[/\\\\](tinyusb_msc|storage_spiflash|storage_sdmmc)\\.c$")
    foreach(KEYFERRY_MSC_ADAPTER_SOURCE IN ITEMS
            tinyusb_msc storage_spiflash storage_sdmmc)
        set(KEYFERRY_MSC_ADAPTER_MATCHES
            "${KEYFERRY_ESP_TINYUSB_SOURCES}")
        list(FILTER KEYFERRY_MSC_ADAPTER_MATCHES INCLUDE REGEX
            "[/\\\\]${KEYFERRY_MSC_ADAPTER_SOURCE}\\.c$")
        if(KEYFERRY_MSC_ADAPTER_MATCHES)
            message(FATAL_ERROR
                "ESP TinyUSB MSC adapter remains in unflashed probe")
        endif()
    endforeach()
    set_property(TARGET ${KEYFERRY_ESP_TINYUSB_LIB} PROPERTY SOURCES
        "${KEYFERRY_ESP_TINYUSB_SOURCES}")
endif()
