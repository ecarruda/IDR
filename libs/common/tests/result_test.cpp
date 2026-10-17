#include <gtest/gtest.h>
#include "idr/common/result.hpp"

TEST(Result, ok_holds_value) {
    auto r = idr::Result<int>::ok(42);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r.value(), 42);
}

TEST(Result, err_reports_code_and_message) {
    auto r = idr::Result<int>::err(idr::ErrorCode::truncated, "short buffer");
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), idr::ErrorCode::truncated);
    EXPECT_EQ(r.message(), "short buffer");
}
