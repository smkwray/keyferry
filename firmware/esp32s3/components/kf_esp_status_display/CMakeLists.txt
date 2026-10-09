set(status_sources "src/esp_status_display.cpp" "src/status_display_layout.cpp")
set(status_requires esp_driver_gpio esp_driver_ledc esp_driver_spi esp_lcd kf_status)
if(KEYFERRY_BOARD STREQUAL "m5stack_atoms3_lite")
    list(APPEND status_sources "src/esp_status_led.cpp")
    list(APPEND status_requires esp_driver_rmt)
endif()
idf_component_register(
    SRCS ${status_sources}
    INCLUDE_DIRS "include" "../../../common/include"
    REQUIRES ${status_requires}
)

target_include_directories(${COMPONENT_LIB} PUBLIC "${KEYFERRY_BOARD_INCLUDE_DIR}")
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
