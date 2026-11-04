idf_component_register(SRCS "src/shell.cpp" "src/ui.cpp" "src/macros.cpp" "src/usb_hid.cpp"
                            "src/keep_awake.cpp" "src/macro_pad.cpp"
                       INCLUDE_DIRS "include"
                       PRIV_REQUIRES nvs_flash esp_timer esp_driver_gpio esp_driver_i2c
                                     esp_system esp_hal_usb esp_app_format sdmmc)
