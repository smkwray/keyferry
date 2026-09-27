idf_component_register(
    SRCS
        "../../../common/src/roaming_profile.cpp"
        "src/config_store.cpp"
        "src/config_storage.cpp"
        "src/idf_config_storage.cpp"
        "src/idf_recovery_anchor_storage.cpp"
        "src/idf_roaming_policy_crypto.cpp"
        "src/recovery_anchor.cpp"
        "src/roaming_config.cpp"
        "src/roaming_storage.cpp"
    INCLUDE_DIRS "include" "../../../common/include"
    REQUIRES esp_partition mbedtls nvs_flash
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
