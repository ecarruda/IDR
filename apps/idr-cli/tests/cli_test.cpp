#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "pe_builder.hpp"
#include "scan_report.hpp"

namespace fs = std::filesystem;

using idr::pe::Arch;
using idr::pe::test_detail::put_u32;

namespace {

// Writes `bytes` to a fresh temp file and returns its path.
fs::path write_temp(const std::string& name, const std::vector<std::byte>& bytes) {
    const fs::path dir = fs::temp_directory_path() / "idr_cli_tests";
    fs::create_directories(dir);
    const fs::path file = dir / name;
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    out.close();
    return file;
}

// Returns the integer following `label` on its report line, or -1 when the
// label or a number is absent.
int line_int(const std::string& report, const std::string& label) {
    const size_t at = report.find(label);
    if (at == std::string::npos) {
        return -1;
    }
    size_t i = at + label.size();
    while (i < report.size() && report[i] == ' ') {
        ++i;
    }
    int value = 0;
    bool any = false;
    while (i < report.size() && report[i] >= '0' && report[i] <= '9') {
        value = value * 10 + (report[i] - '0');
        any = true;
        ++i;
    }
    return any ? value : -1;
}

// Constants shared with pe_builder.hpp.
constexpr uint32_t kTextRva = 0x1000;
constexpr size_t kTextRawOffset = 0x200;
constexpr uint32_t kImageBase = 0x400000;
constexpr uint32_t kDataRva = 0x2000;

// Plants the >=2010 "extended init table" that routes TargetProfile::detect to
// the 2010 fallback (and thus a usable VMT layout with class_name = -0x38).
void plant_extended_init_table(std::vector<std::byte>& pe, uint32_t image_base) {
    constexpr uint32_t at = 0x10;
    put_u32(pe, kTextRawOffset + at - 4, 1);  // unit count
    put_u32(pe, kTextRawOffset + at, image_base + kTextRva + at + 20);
    put_u32(pe, kTextRawOffset + at + 20, image_base + kTextRva + 0x100);  // init
    put_u32(pe, kTextRawOffset + at + 24, 0);                              // finalize
}

}  // namespace

// A non-PE input must yield a report and never throw.
TEST(CliScanReport, non_pe_input_is_reported_and_does_not_throw) {
    const std::vector<std::byte> data(64, std::byte{'X'});
    const fs::path file = write_temp("not_a_pe.bin", data);

    std::string report;
    ASSERT_NO_THROW(
        report = scan_report(file, fs::temp_directory_path(), fs::temp_directory_path()));
    EXPECT_NE(report.find("not a PE"), std::string::npos) << report;
}

// A synthetic PE32 with a planted VMT root: arch, section and import lines are
// present and the VMT-root count is non-zero.
TEST(CliScanReport, synthetic_pe32_reports_arch_sections_imports_and_vmt_roots) {
    constexpr uint32_t kNameOffset = 0x120;
    constexpr uint32_t kVmtOffset = 0x80;
    constexpr uint32_t kNameBack = 0x38;  // -vmt_layout_for(2010).class_name

    std::vector<std::byte> data(0x200, std::byte{0});
    const char name[] = "TForm";
    data[kNameOffset] = std::byte{5};
    for (size_t i = 0; i < 5; ++i) {
        data[kNameOffset + 1 + i] = static_cast<std::byte>(name[i]);
    }
    // The vmtClassName pointer lives before the VMT base.
    put_u32(data, kVmtOffset - kNameBack, kImageBase + kDataRva + kNameOffset);

    auto bytes = make_pe_with_data(Arch::x86, data, kImageBase);
    plant_extended_init_table(bytes, kImageBase);
    const fs::path file = write_temp("synthetic_pe32.exe", bytes);

    std::string report;
    ASSERT_NO_THROW(
        report = scan_report(file, fs::temp_directory_path(), fs::temp_directory_path()));
    EXPECT_NE(report.find("arch: x86"), std::string::npos) << report;
    EXPECT_NE(report.find("sections:"), std::string::npos) << report;
    EXPECT_NE(report.find("imports:"), std::string::npos) << report;
    EXPECT_NE(report.find("vendor: embarcadero"), std::string::npos) << report;
    EXPECT_GT(line_int(report, "vmt roots:"), 0) << report;
}

// End-to-end: scan the real 32-bit Idr.exe. Skipped when the fixture is absent.
TEST(CliScanReport, idr_exe_reports_arch_and_version_line) {
    const fs::path exe = fs::path(IDR_REPO_ROOT) / "bin" / "Idr.exe";
    if (!fs::exists(exe)) {
        GTEST_SKIP() << "no bin/Idr.exe fixture";
    }
    const fs::path root = fs::path(IDR_REPO_ROOT);

    std::string report;
    ASSERT_NO_THROW(report = scan_report(exe, root, root));
    EXPECT_NE(report.find("arch: x86"), std::string::npos) << report;
    // Either a detected version or the explicit unknown report.
    const bool has_unknown = report.find("delphi version: unknown") != std::string::npos;
    const size_t version_at = report.find("delphi version: ");
    const bool has_number =
        version_at != std::string::npos && version_at + 16 < report.size() &&
        report[version_at + 16] >= '0' && report[version_at + 16] <= '9';
    EXPECT_TRUE(has_unknown || has_number) << report;
}
