#include <gtest/gtest.h>
#include "idr/pe/directories.hpp"
#include "pe_builder.hpp"

using idr::pe::Arch;

TEST(ParseImports, no_directory_is_empty) {
    auto bytes = make_minimal_pe(Arch::x86);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto imports = idr::pe::parse_imports(pe.value());
    ASSERT_TRUE(imports.has_value());
    EXPECT_TRUE(imports.value().empty());
}

TEST(ParseImports, single_named_import) {
    auto bytes = make_minimal_pe(Arch::x86, 0x400000);
    add_import(bytes, "KERNEL32.dll", {"GetProcAddress"});
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto imports = idr::pe::parse_imports(pe.value());
    ASSERT_TRUE(imports.has_value());
    ASSERT_EQ(imports.value().size(), 1u);

    const auto& imp = imports.value()[0];
    EXPECT_EQ(imp.module, "KERNEL32.dll");
    EXPECT_EQ(imp.name, "GetProcAddress");
    EXPECT_FALSE(imp.by_ordinal);
    // iat_va = image_base + FirstThunk (i == 0). FirstThunk lies in `.text`.
    EXPECT_GE(imp.iat_va, 0x400000ull + 0x1000);
    EXPECT_LT(imp.iat_va, 0x400000ull + 0x2000);
}

TEST(ParseImports, ordinal_import) {
    auto bytes = make_minimal_pe(Arch::x86);
    add_import_ordinal(bytes, "KERNEL32.dll", {42});
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto imports = idr::pe::parse_imports(pe.value());
    ASSERT_TRUE(imports.has_value());
    ASSERT_EQ(imports.value().size(), 1u);

    const auto& imp = imports.value()[0];
    EXPECT_EQ(imp.module, "KERNEL32.dll");
    EXPECT_TRUE(imp.by_ordinal);
    EXPECT_EQ(imp.ordinal, 42);
    EXPECT_TRUE(imp.name.empty());
}

TEST(ParseImports, x64_named_import) {
    auto bytes = make_minimal_pe(Arch::x64, 0x140000000ull);
    add_import(bytes, "KERNEL32.dll", {"GetProcAddress"});
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto imports = idr::pe::parse_imports(pe.value());
    ASSERT_TRUE(imports.has_value());
    ASSERT_EQ(imports.value().size(), 1u);
    EXPECT_EQ(imports.value()[0].module, "KERNEL32.dll");
    EXPECT_EQ(imports.value()[0].name, "GetProcAddress");
    EXPECT_GE(imports.value()[0].iat_va, 0x140000000ull + 0x1000);
}

TEST(ParseImports, x64_ordinal_import) {
    auto bytes = make_minimal_pe(Arch::x64, 0x140000000ull);
    add_import_ordinal(bytes, "KERNEL32.dll", {7});
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto imports = idr::pe::parse_imports(pe.value());
    ASSERT_TRUE(imports.has_value());
    ASSERT_EQ(imports.value().size(), 1u);
    EXPECT_EQ(imports.value()[0].module, "KERNEL32.dll");
    EXPECT_TRUE(imports.value()[0].by_ordinal);
    EXPECT_EQ(imports.value()[0].ordinal, 7);
}

TEST(ParseImports, truncated_directory_is_error) {
    auto bytes = make_minimal_pe(Arch::x86);
    // Point the import directory at the last mappable bytes so the 20-byte
    // descriptor read extends past the raw data and must fail bounds checks.
    idr::pe::test_detail::set_data_directory(bytes, 1, 0x11FC, 20);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto imports = idr::pe::parse_imports(pe.value());
    ASSERT_FALSE(imports.has_value());
    EXPECT_EQ(imports.error(), idr::ErrorCode::truncated);
}

TEST(ParseExports, no_directory_is_empty) {
    auto bytes = make_minimal_pe(Arch::x86);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto exports = idr::pe::parse_exports(pe.value());
    ASSERT_TRUE(exports.has_value());
    EXPECT_TRUE(exports.value().empty());
}

TEST(ParseExports, single_named_export) {
    auto bytes = make_minimal_pe(Arch::x86);
    add_export(bytes, {"MyFunc"});
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto exports = idr::pe::parse_exports(pe.value());
    ASSERT_TRUE(exports.has_value());
    ASSERT_EQ(exports.value().size(), 1u);

    const auto& exp = exports.value()[0];
    EXPECT_EQ(exp.name, "MyFunc");
    EXPECT_EQ(exp.rva, 0x1700u);
    EXPECT_EQ(exp.ordinal, 1);
}

// Minor 5: the descriptor walk must stop at the declared directory size. With a
// size covering a single descriptor, the terminating null descriptor lies
// outside the directory and the walk must fail closed instead of running on.
TEST(ParseImports, directory_size_caps_descriptor_walk) {
    auto bytes = make_minimal_pe(Arch::x86, 0x400000);
    add_import(bytes, "KERNEL32.dll", {"GetProcAddress"});
    idr::pe::test_detail::set_data_directory(bytes, 1, 0x1000, 20);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto imports = idr::pe::parse_imports(pe.value());
    ASSERT_FALSE(imports.has_value());
    EXPECT_EQ(imports.error(), idr::ErrorCode::truncated);
}

// Minor 5: the export name/ordinal/function table walks are likewise capped by
// the declared directory size.
TEST(ParseExports, directory_size_caps_table_walks) {
    auto bytes = make_minimal_pe(Arch::x86);
    add_export(bytes, {"MyFunc"});
    // Directory covering only the 40-byte header; the tables lie beyond it.
    idr::pe::test_detail::set_data_directory(bytes, 0, 0x1000, 40);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto exports = idr::pe::parse_exports(pe.value());
    ASSERT_FALSE(exports.has_value());
    EXPECT_EQ(exports.error(), idr::ErrorCode::truncated);
}
