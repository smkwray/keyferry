idf_component_register(
    SRCS "src/esp_provisioning.cpp"
    INCLUDE_DIRS "include"
    REQUIRES
        bootloader_support
        esp_hw_support
        esp_timer
        kf_config_store
        kf_provisioning
        mbedtls
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
