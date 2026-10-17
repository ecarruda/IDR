add_library(kbbuilder_core STATIC src/kb_tool.cpp)
target_link_libraries(kbbuilder_core PUBLIC idr_common idr_kb)
target_include_directories(kbbuilder_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(kbbuilder src/main.cpp)
target_link_libraries(kbbuilder PRIVATE kbbuilder_core)

add_subdirectory(tests)
