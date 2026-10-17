add_library(idr_pe STATIC src/image.cpp src/directories.cpp)
target_link_libraries(idr_pe PUBLIC idr_common)

add_library(idr_test_support INTERFACE)
target_include_directories(idr_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

add_subdirectory(tests)
