add_library(idr_cli_core STATIC src/scan_report.cpp)
target_link_libraries(idr_cli_core
  PUBLIC
    idr_common
    idr_pe
    idr_disasm
    idr_kb
    idr_target
    idr_analyze)
target_include_directories(idr_cli_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(idr_cli src/main.cpp)
target_link_libraries(idr_cli PRIVATE idr_cli_core)

add_subdirectory(tests)
