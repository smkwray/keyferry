idf_component_register(
    SRCS "src/ble_transport.cpp" "src/idf_ble_transport.cpp"
    INCLUDE_DIRS "include" "../../../common/include"
    REQUIRES bt esp_timer freertos
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
