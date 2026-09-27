idf_component_register(
    SRCS
        "src/command_executor.cpp"
        "src/input_command.cpp"
        "src/idf_held_key_watchdog.cpp"
    INCLUDE_DIRS
        "include"
        "../../../common/include"
    REQUIRES
        kf_hid_core
        esp_timer
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
