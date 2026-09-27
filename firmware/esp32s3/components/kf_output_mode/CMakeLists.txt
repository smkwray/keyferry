idf_component_register(
    SRCS "src/output_mode.cpp" "src/idf_output_mode_storage.cpp"
    INCLUDE_DIRS "include" "../../../common/include"
    REQUIRES nvs_flash
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
