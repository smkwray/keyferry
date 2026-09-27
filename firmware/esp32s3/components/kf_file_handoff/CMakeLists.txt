idf_component_register(SRCS "src/file_handoff.cpp" INCLUDE_DIRS "include" "../../../common/include")
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
