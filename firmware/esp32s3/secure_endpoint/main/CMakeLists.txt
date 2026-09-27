idf_component_register(
    SRCS "app_main.cpp"
    INCLUDE_DIRS "."
    REQUIRES kf_secure_endpoint mbedtls esp_wifi esp_netif esp_event
)

target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
