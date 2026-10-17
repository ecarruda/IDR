add_executable(idr_common_tests result_test.cpp)
target_link_libraries(idr_common_tests PRIVATE idr_common GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(idr_common_tests)
