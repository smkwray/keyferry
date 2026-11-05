idf_component_register(SRCS "src/shell.cpp" "src/ui.cpp" "src/macros.cpp" "src/usb_device.cpp"
                            "src/keep_awake.cpp" "src/macro_pad.cpp" "src/drive.cpp" "src/mic.cpp"
                            "src/messages.cpp"
                       INCLUDE_DIRS "include"
                       PRIV_REQUIRES nvs_flash esp_timer esp_driver_gpio esp_driver_i2c
                                     esp_system esp_hal_usb esp_app_format sdmmc fatfs
                                     esp_driver_i2s)
# The Waveshare BSP registers its QSPI panel with lvgl_port_add_disp_rgb; shell.cpp redirects that
# call to the SPI/QSPI registration (see __wrap_lvgl_port_add_disp_rgb).
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=lvgl_port_add_disp_rgb")
