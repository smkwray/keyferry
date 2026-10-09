set(status_sources "src/esp_status_display.cpp" "src/status_display_layout.cpp")
if(KEYFERRY_BOARD STREQUAL "m5stack_atoms3_lite")
    list(APPEND status_sources "src/esp_status_led.cpp")
endif()
idf_component_register(
    SRCS ${status_sources}
    INCLUDE_DIRS "include" "../../../common/include"
    # IDF's early dependency pass has no project board selector. RMT is linked
    # only when the Atom source references it; other boards retain no RMT code.
    REQUIRES esp_driver_gpio esp_driver_ledc esp_driver_spi esp_lcd kf_status esp_driver_rmt
)

target_include_directories(${COMPONENT_LIB} PUBLIC "${KEYFERRY_BOARD_INCLUDE_DIR}")
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
