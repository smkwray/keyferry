idf_component_register(
    SRCS "src/esp_status_display.cpp" "src/status_display_layout.cpp" "src/esp_status_led.cpp"
    INCLUDE_DIRS "include" "../../../common/include"
    REQUIRES esp_driver_gpio esp_driver_ledc esp_driver_spi esp_lcd kf_status esp_driver_rmt
)

target_include_directories(${COMPONENT_LIB} PUBLIC "${KEYFERRY_BOARD_INCLUDE_DIR}")
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
