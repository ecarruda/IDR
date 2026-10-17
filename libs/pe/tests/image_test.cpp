#include <gtest/gtest.h>
#include "idr/pe/image.hpp"
#include "pe_builder.hpp"

TEST(PeFile, parses_pe32_arch_and_entry) {
    auto bytes = make_minimal_pe(idr::pe::Arch::x86);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    EXPECT_EQ(pe.value().arch(), idr::pe::Arch::x86);
    EXPECT_FALSE(pe.value().is_64());
    EXPECT_NE(pe.value().entry_point_rva(), 0u);
}

TEST(PeFile, parses_pe32plus_as_x64) {
    auto bytes = make_minimal_pe(idr::pe::Arch::x64, 0x140000000ull);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    EXPECT_EQ(pe.value().arch(), idr::pe::Arch::x64);
    EXPECT_TRUE(pe.value().is_64());
    EXPECT_EQ(pe.value().image_base(), 0x140000000ull);
}

TEST(PeFile, truncated_buffer_is_rejected) {
    std::vector<std::byte> bytes(16, std::byte{0});
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_FALSE(pe.has_value());
    EXPECT_EQ(pe.error(), idr::ErrorCode::truncated);
}

TEST(PeFile, rva_to_offset_maps_section_and_bounds_checks) {
    auto bytes = make_minimal_pe(idr::pe::Arch::x86);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    ASSERT_EQ(pe.value().sections().size(), 1u);
    const uint32_t rva = pe.value().sections()[0].virtual_address;
    ASSERT_TRUE(pe.value().rva_to_offset(rva).has_value());
    EXPECT_FALSE(pe.value().at_rva(0xFFFFFF00u, 16).has_value());
}

TEST(PeFile, non_pe_is_rejected) {
    std::vector<std::byte> bytes(64, std::byte{'X'});
    bytes[0] = std::byte{'M'}; bytes[1] = std::byte{'Z'};
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_FALSE(pe.has_value());
    EXPECT_EQ(pe.error(), idr::ErrorCode::bad_magic);
}

TEST(PeFile, undersized_optional_header_is_rejected) {
    auto bytes = make_minimal_pe(idr::pe::Arch::x86);
    // Declare an optional header too small to contain AddressOfEntryPoint/ImageBase,
    // while keeping the buffer large enough so only the size check can reject it.
    set_size_of_optional_header(bytes, 0x10);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_FALSE(pe.has_value());
    EXPECT_EQ(pe.error(), idr::ErrorCode::unsupported_format);
}
