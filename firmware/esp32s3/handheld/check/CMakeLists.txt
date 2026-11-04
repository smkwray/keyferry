# Board Check image for the AMOLED handheld: Home, Board Check and Settings only.
# No radio, no application USB class, no SD writes (ADR 0018 phase 1).
cmake_minimum_required(VERSION 3.16)
set(IDF_TARGET "esp32s3" CACHE STRING "ESP-IDF target")
set(PROJECT_VER "0.0.1-handheld-check")
set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../kf_handheld")
set(KEYFERRY_BOARD_DIR "${CMAKE_CURRENT_LIST_DIR}/../../boards/waveshare_amoled_1_8")
set(SDKCONFIG_DEFAULTS
    "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults"
    "${KEYFERRY_BOARD_DIR}/sdkconfig.defaults"
    "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.partitions.defaults")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(keyferry_handheld_check)
