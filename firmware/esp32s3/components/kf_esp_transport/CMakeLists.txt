idf_component_register(
    SRCS
        "src/transport_policy.cpp"
        "src/transport_arbiter.cpp"
        "src/gateway_handoff.cpp"
        "src/mbedtls_peer_policy.cpp"
        "src/ble_tls_link.cpp"
        "src/esp_transport.cpp"
    INCLUDE_DIRS "include"
    REQUIRES
        kf_esp_discovery
        kf_ble_transport
        kf_config_store
        kf_secure_endpoint
        esp_wifi
        esp_netif
        esp_event
        esp_timer
        esp-tls
        mbedtls
        esp_hw_support
        freertos
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
