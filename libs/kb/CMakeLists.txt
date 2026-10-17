add_library(idr_kb STATIC
  src/kb_equal.cpp
  src/knowledge_base.cpp
  src/v3_io.cpp
  src/v2_read.cpp)
target_link_libraries(idr_kb PUBLIC idr_common)
target_include_directories(idr_kb PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_subdirectory(tests)
