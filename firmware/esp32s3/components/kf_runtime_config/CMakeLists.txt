idf_component_register(
    SRCS "src/runtime_config.cpp"
    INCLUDE_DIRS "include"
    REQUIRES kf_config_store kf_esp_transport
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
