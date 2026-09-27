idf_component_register(
    SRCS
        "src/local_management.cpp"
        "src/local_management_codec.cpp"
        "src/local_management_coordinator.cpp"
        "src/local_management_receipts.cpp"
        "src/local_management_status.cpp"
        "src/idf_local_management_receipts.cpp"
        "src/provisioning.cpp"
    INCLUDE_DIRS
        "include"
        "../../../common/include"
    REQUIRES kf_config_store nvs_flash
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
