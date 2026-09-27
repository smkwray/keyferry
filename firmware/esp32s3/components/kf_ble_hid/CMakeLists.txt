idf_component_register(
    SRCS
        "src/idf_ble_hid_peripheral.cpp"
        "src/release_burst.cpp"
    INCLUDE_DIRS "include"
    REQUIRES bt esp_timer
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
