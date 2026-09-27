cmake_minimum_required(VERSION 3.16)

set(IDF_TARGET "esp32s3" CACHE STRING "ESP-IDF target")
set(PROJECT_VER "offline-executor-v0")
set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../components")
set(KEYFERRY_BOARD "" CACHE STRING "Compile-time keyferry board profile")

include("${CMAKE_CURRENT_LIST_DIR}/../boards/load_board_profile.cmake")
list(APPEND SDKCONFIG_DEFAULTS
    "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults"
    "${KEYFERRY_BOARD_SDKCONFIG_DEFAULTS}"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(keyferry_usb_executor)
