add_library(idr_target STATIC src/target_profile.cpp)
target_link_libraries(idr_target PUBLIC idr_common idr_pe idr_kb)

add_subdirectory(tests)
