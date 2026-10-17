add_library(idr_analyze STATIC src/vmt_roots.cpp)
target_link_libraries(idr_analyze PUBLIC idr_pe idr_target)

add_subdirectory(tests)
