add_executable(idr_kb_tests kb_test.cpp parity_test.cpp)
target_link_libraries(idr_kb_tests PRIVATE idr_kb GTest::gtest_main)
target_compile_definitions(idr_kb_tests PRIVATE IDR_REPO_ROOT="${CMAKE_SOURCE_DIR}"
                                           _CRT_SECURE_NO_WARNINGS)
include(GoogleTest)
gtest_discover_tests(idr_kb_tests TEST_PREFIX "idr_kb.")
