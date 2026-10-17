#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "idr/analyze/vmt_roots.hpp"
#include "idr/pe/image.hpp"
#include "idr/target/target_profile.hpp"
#include "pe_builder.hpp"

using idr::analyze::find_vmt_roots;
using idr::pe::Arch;
using idr::pe::PeFile;
using idr::target::TargetProfile;
using idr::target::Vendor;

namespace {

// RVA of the `.data` section make_pe_with_data appends (see pe_builder.hpp).
constexpr uint32_t kDataRva = 0x2000;
constexpr uint64_t kImageBase = 0x400000;

// Delphi 7's `vmtClassName` field offset (vmt_layout_for(7).class_name): the
// class-name pointer lives that many bytes *before* the VMT base.
constexpr int kClassNameOffset = -0x2C;

// `.data`-relative offsets of the two planted structures.
constexpr uint32_t kNameOffset = 0x80;
constexpr uint32_t kVmtOffset = 0x40;

// A profile that carries the Delphi 7 layout; `arch` selects the pointer width.
TargetProfile delphi7(Arch arch) {
    return TargetProfile::of(Vendor::embarcadero, 7, arch);
}

// Plants a Delphi shortstring (length byte followed by the bytes) at `offset`.
void plant_shortstring(std::vector<std::byte>& data, uint32_t offset, const char* text) {
    const size_t len = std::strlen(text);
    data[offset] = static_cast<std::byte>(len);
    for (size_t i = 0; i < len; ++i) {
        data[offset + 1 + i] = static_cast<std::byte>(text[i]);
    }
}

// Plants the class-name pointer the VMT root's `vmtClassName` field must hold:
// the pointer-width word `kClassNameOffset` bytes before `vmt_offset` receives
// the *image address* `value` (image base + RVA of the shortstring).
void plant_name_pointer(std::vector<std::byte>& data, uint32_t vmt_offset, std::size_t width,
                        uint64_t value) {
    const uint32_t ptr_offset =
        static_cast<uint32_t>(static_cast<int32_t>(vmt_offset) + kClassNameOffset);
    if (width == 8) {
        idr::pe::test_detail::put_u64(data, ptr_offset, value);
    } else {
        idr::pe::test_detail::put_u32(data, ptr_offset, static_cast<uint32_t>(value));
    }
}

// An x86 image whose `.data` holds a `TControl` shortstring at `kNameOffset` and
// the name pointer at `kVmtOffset + kClassNameOffset`.
std::vector<std::byte> tcontrol_image(std::size_t data_size,
                                      const char* name_text = "TControl",
                                      uint64_t name_pointer_value =
                                          kImageBase + kDataRva + kNameOffset) {
    std::vector<std::byte> data(data_size, std::byte{0});
    plant_shortstring(data, kNameOffset, name_text);
    plant_name_pointer(data, kVmtOffset, 4, name_pointer_value);
    return make_pe_with_data(Arch::x86, data);
}

bool contains(const std::vector<uint64_t>& roots, uint64_t value) {
    return std::find(roots.begin(), roots.end(), value) != roots.end();
}

}  // namespace

// The core contract: a `.data` word whose vmtClassName points at a printable
// shortstring is reported, by image address (image base + RVA).
TEST(VmtRoots, planted_class_vmt_is_reported_by_image_address) {
    const auto bytes = tcontrol_image(0x100);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    ASSERT_EQ(pe.value().image_base(), kImageBase);

    const auto roots = find_vmt_roots(pe.value(), delphi7(Arch::x86));

    ASSERT_TRUE(contains(roots, kImageBase + kDataRva + kVmtOffset));
    // Reported once, not once per section boundary or alignment.
    EXPECT_EQ(std::count(roots.begin(), roots.end(), kImageBase + kDataRva + kVmtOffset), 1u);
}

// A `.data` section of nothing but zeros holds no candidate.
TEST(VmtRoots, zeroed_data_section_yields_no_candidates) {
    const std::vector<std::byte> data(0x100, std::byte{0});
    auto bytes = make_pe_with_data(Arch::x86, data);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    EXPECT_TRUE(find_vmt_roots(pe.value(), delphi7(Arch::x86)).empty());
}

// A shortstring with non-printable bytes is not a class name, even when the
// pointer to it is well formed.
TEST(VmtRoots, non_printable_class_name_is_rejected) {
    auto bytes = tcontrol_image(0x100, "TCont\x01ol");
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    EXPECT_TRUE(find_vmt_roots(pe.value(), delphi7(Arch::x86)).empty());
}

// A zero-length name is not a class name.
TEST(VmtRoots, zero_length_class_name_is_rejected) {
    auto bytes = tcontrol_image(0x100, "");
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    EXPECT_TRUE(find_vmt_roots(pe.value(), delphi7(Arch::x86)).empty());
}

// A name pointer outside the image is skipped rather than dereferenced.
TEST(VmtRoots, name_pointer_outside_the_image_is_ignored) {
    auto bytes = tcontrol_image(0x100, "TControl", 0x7FFFFFFFu);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    EXPECT_TRUE(find_vmt_roots(pe.value(), delphi7(Arch::x86)).empty());
}

// The shortstring's length byte sits exactly on the mapped end of `.data`, so
// the name cannot be read at all and the candidate is dropped rather than read
// out of bounds. (The payload is longer than the mapped section, so the name
// bytes are physically in the file but unmapped.)
TEST(VmtRoots, class_name_truncated_by_section_end_is_ignored) {
    constexpr uint32_t kTruncatedVirtualSize = 0xF9;
    std::vector<std::byte> data(0x120, std::byte{0});
    plant_shortstring(data, kTruncatedVirtualSize, "TControl");
    plant_name_pointer(data, kVmtOffset, 4, kImageBase + kDataRva + kTruncatedVirtualSize);
    auto bytes = make_pe_with_data(Arch::x86, data, kImageBase, kTruncatedVirtualSize);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    ASSERT_FALSE(pe.value().at_rva(kDataRva + kTruncatedVirtualSize, 1).has_value());

    EXPECT_TRUE(find_vmt_roots(pe.value(), delphi7(Arch::x86)).empty());
}

// The pointer width follows the profile: a PE32+ image is scanned 8 bytes at a
// time and its name pointer is 8 bytes wide.
TEST(VmtRoots, pe32_plus_uses_eight_byte_pointers) {
    std::vector<std::byte> data(0x100, std::byte{0});
    plant_shortstring(data, kNameOffset, "TControl");
    plant_name_pointer(data, kVmtOffset, 8, kImageBase + kDataRva + kNameOffset);
    auto bytes = make_pe_with_data(Arch::x64, data);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    ASSERT_EQ(pe.value().image_base(), kImageBase);

    const auto roots = find_vmt_roots(pe.value(), delphi7(Arch::x64));

    EXPECT_TRUE(contains(roots, kImageBase + kDataRva + kVmtOffset));
}

// Without a known `class_name` offset there is no criterion to apply, so no
// candidate is reported.
TEST(VmtRoots, profile_without_a_class_name_offset_reports_nothing) {
    auto bytes = tcontrol_image(0x100);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    const auto roots = find_vmt_roots(
        pe.value(), TargetProfile::of(Vendor::unknown, 999, Arch::x86));

    EXPECT_TRUE(roots.empty());
}

// An image with no section headers maps nothing, so there is nothing to scan.
TEST(VmtRoots, image_without_sections_yields_no_candidates) {
    std::vector<std::byte> bytes = tcontrol_image(0x100);
    // Drop the section table: only the planted `.data` content remains, and no
    // RVA in it can be mapped any more.
    idr::pe::test_detail::put_u16(bytes, 0x40 + 4 + 0x02, 0);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    ASSERT_EQ(pe.value().sections().size(), 0u);

    EXPECT_TRUE(find_vmt_roots(pe.value(), delphi7(Arch::x86)).empty());
}
