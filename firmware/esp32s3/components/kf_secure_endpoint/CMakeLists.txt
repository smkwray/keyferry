idf_component_register(
    SRCS
        "src/secure_endpoint.cpp"
        "../../../common/src/frame_codec.cpp"
        "../../../common/src/gateway_handoff.cpp"
    INCLUDE_DIRS
        "include"
        "../../../common/include"
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
