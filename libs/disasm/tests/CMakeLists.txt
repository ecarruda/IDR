add_executable(idr_disasm_tests disasm_test.cpp)
target_link_libraries(idr_disasm_tests PRIVATE idr_disasm GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(idr_disasm_tests TEST_PREFIX "idr_disasm.")
