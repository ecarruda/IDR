add_executable(idr_pe_tests image_test.cpp directories_test.cpp)
target_link_libraries(idr_pe_tests PRIVATE idr_pe idr_test_support GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(idr_pe_tests TEST_PREFIX "idr_pe.")
