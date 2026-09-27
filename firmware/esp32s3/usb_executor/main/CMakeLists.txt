idf_component_register(
    SRCS "app_main.cpp"
    INCLUDE_DIRS "."
    REQUIRES esp_tinyusb kf_hid_core
)

target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
