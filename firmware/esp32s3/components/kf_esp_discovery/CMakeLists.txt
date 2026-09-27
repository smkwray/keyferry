idf_component_register(
    SRCS "src/esp_discovery.cpp"
    INCLUDE_DIRS "include"
    REQUIRES kf_discovery esp_netif esp_timer lwip
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
