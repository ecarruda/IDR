add_executable(idr_analyze_tests vmt_roots_test.cpp)
target_link_libraries(idr_analyze_tests PRIVATE idr_analyze idr_pe idr_target idr_test_support GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(idr_analyze_tests TEST_PREFIX "idr_analyze.")
