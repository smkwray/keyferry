cmake_minimum_required(VERSION 3.16)

set(IDF_TARGET "esp32s3" CACHE STRING "ESP-IDF target")
set(PROJECT_VER "command-executor-compile-v0")
set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../..")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(keyferry_command_executor_compile)
