idf_component_register(
    SRCS "app_main.cpp"
    INCLUDE_DIRS "." "${KEYFERRY_BOARD_INCLUDE_DIR}"
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE KEYFERRY_QUALIFICATION_IMAGE=1)
