#include <gtest/gtest.h>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "idr/kb/knowledge_base.hpp"

namespace fs = std::filesystem;

namespace {

// Reads `fixture` (v2), converts to v3, reads it back, and asserts content
// equality. Returns false only when a step failed (so callers can ASSERT).
// Content equality ignores the container format_version (see kb_equal), so a
// v2->v3 conversion is expected to compare equal.
testing::AssertionResult v2_v3_round_trip_is_lossless(const fs::path& fixture) {
    auto v2 = idr::kb::KnowledgeBase::open(fixture);
    if (!v2.has_value()) return testing::AssertionFailure() << v2.message();

    const fs::path out =
        fs::temp_directory_path() / (fixture.stem().string() + ".parity.v3.bin");
    if (!idr::kb::write_v3(out, v2.value().data()).has_value()) {
        fs::remove(out);
        return testing::AssertionFailure() << "write_v3 failed";
    }
    auto v3 = idr::kb::KnowledgeBase::open(out);
    fs::remove(out);
    if (!v3.has_value()) return testing::AssertionFailure() << v3.message();

    if (!idr::kb::kb_equal(v2.value().data(), v3.value().data())) {
        return testing::AssertionFailure() << "content differs after v2->v3";
    }
    return testing::AssertionSuccess();
}

}  // namespace

TEST(KbParity, syskb2014_round_trips_losslessly) {
    const fs::path f = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    if (!fs::exists(f)) GTEST_SKIP() << "syskb2014.bin absent";
    EXPECT_TRUE(v2_v3_round_trip_is_lossless(f));
}

TEST(KbParity, syskb2_locals_round_trip_losslessly) {
    const fs::path f = fs::path(IDR_REPO_ROOT) / "syskb2.bin";
    if (!fs::exists(f)) GTEST_SKIP() << "syskb2.bin absent";
    EXPECT_TRUE(v2_v3_round_trip_is_lossless(f));
}

TEST(KbParity, scale_fixture_round_trips_when_env_set) {
    const char* env = std::getenv("IDR_KB_SCALE_FIXTURE");
    if (env == nullptr || *env == '\0') {
        GTEST_SKIP() << "set IDR_KB_SCALE_FIXTURE to a full kb*.bin to run";
    }
    const fs::path f = env;
    if (!fs::exists(f)) GTEST_SKIP() << "scale fixture absent: " << f.string();
    EXPECT_TRUE(v2_v3_round_trip_is_lossless(f));
}