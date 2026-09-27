idf_component_register(
    SRCS "src/display_orientation.cpp" "src/idf_display_orientation_storage.cpp"
    INCLUDE_DIRS "include" "../../../common/include"
    REQUIRES nvs_flash
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
