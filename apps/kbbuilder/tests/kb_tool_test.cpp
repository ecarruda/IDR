#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "kb_tool.hpp"

namespace fs = std::filesystem;

TEST(KbTool, info_reports_sections_of_a_real_v2_kb) {
    const fs::path f = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    if (!fs::exists(f)) GTEST_SKIP() << "syskb2014.bin absent";

    const std::string info = kb_info(f);
    EXPECT_NE(info.find("arch: x86"), std::string::npos);
    EXPECT_NE(info.find("procs: 1195"), std::string::npos);
    EXPECT_NE(info.find("vars: 82"), std::string::npos);
}

TEST(KbTool, convert_then_verify_a_real_v2_kb) {
    const fs::path in = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    if (!fs::exists(in)) GTEST_SKIP() << "syskb2014.bin absent";

    const fs::path out = fs::temp_directory_path() / "kbbuilder_out.v3.bin";
    auto converted = kb_convert(in, out);
    ASSERT_TRUE(converted.has_value()) << converted.message();
    ASSERT_TRUE(fs::exists(out));

    auto verified = kb_verify(in);
    EXPECT_TRUE(verified.has_value()) << verified.message();

    fs::remove(out);
}

TEST(KbTool, convert_reports_error_on_non_kb_input) {
    const fs::path bad = fs::temp_directory_path() / "kbbuilder_bad.bin";
    { std::ofstream(bad, std::ios::binary) << "not a kb"; }
    const fs::path out = fs::temp_directory_path() / "kbbuilder_bad.v3.bin";
    EXPECT_FALSE(kb_convert(bad, out).has_value());
    fs::remove(bad);
}
