add_library(idr_common INTERFACE)
target_include_directories(idr_common INTERFACE ${CMAKE_SOURCE_DIR}/include)
add_subdirectory(tests)
