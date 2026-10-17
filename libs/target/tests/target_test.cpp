#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <vector>

#include "idr/common/error.hpp"
#include "idr/kb/knowledge_base.hpp"
#include "idr/pe/image.hpp"
#include "idr/target/target_profile.hpp"
#include "pe_builder.hpp"

namespace fs = std::filesystem;
using idr::ErrorCode;
using idr::kb::KnowledgeBase;
using idr::pe::Arch;
using idr::pe::PeFile;
using idr::target::TargetProfile;
using idr::target::Vendor;
using idr::target::vmt_layout_for;

namespace {

constexpr uint32_t kTextRva = 0x1000;
constexpr size_t kTextRawOffset = 0x200;  // must match pe_builder.hpp
constexpr uint32_t kDefaultImageBase = 0x400000;

// Writes a 32-bit little-endian word at flattened `.text` position `pos`.
void plant_u32(std::vector<std::byte>& pe, uint32_t pos, uint32_t value) {
    idr::pe::test_detail::put_u32(pe, kTextRawOffset + pos, value);
}

// Plants the >=2010 "extended init table" pattern that the IsExtendedInitTab
// equivalent recognizes: at flattened position `i` a word equal to
// Pos2Adr(i) + 20, preceded by a unit count and followed by one
// {init = ini_adr, finalize = 0} entry per address. `at` is the `i` the table
// base is planted at.
void plant_extended_init_table(std::vector<std::byte>& pe, uint32_t image_base,
                               uint32_t at = 0x10,
                               std::vector<uint32_t> ini_addrs = {0}) {
    plant_u32(pe, at - 4, static_cast<uint32_t>(ini_addrs.size()));
    plant_u32(pe, at, image_base + kTextRva + at + 20);
    for (size_t k = 0; k < ini_addrs.size(); ++k) {
        plant_u32(pe, at + 20 + static_cast<uint32_t>(k * 8), ini_addrs[k]);
        plant_u32(pe, at + 24 + static_cast<uint32_t>(k * 8), 0);
    }
}

// Appends a second, raw-size-zero `.data` section to an x86 image produced by
// make_minimal_pe and widens SizeOfImage. Leaves [previous_end, va) as an
// inter-section gap.
void add_empty_section(std::vector<std::byte>& pe, uint32_t va, uint32_t vsize,
                       uint32_t size_of_image) {
    constexpr size_t kFileHeaderOff = 0x44;   // DOS(0x40) + "PE\0\0"(4)
    constexpr size_t kOptOff = 0x58;          // kFileHeaderOff + IMAGE_FILE_HEADER(20)
    constexpr size_t kSecTableOff = 0x138;    // kOptOff + 224 (PE32 optional header)
    idr::pe::test_detail::put_u16(pe, kFileHeaderOff + 0x02, 2);  // NumberOfSections
    idr::pe::test_detail::put_u32(pe, kOptOff + 0x38, size_of_image);

    const size_t s1 = kSecTableOff + 40;
    std::memcpy(pe.data() + s1, ".data", 5);
    idr::pe::test_detail::put_u32(pe, s1 + 0x08, vsize);
    idr::pe::test_detail::put_u32(pe, s1 + 0x0C, va);
    idr::pe::test_detail::put_u32(pe, s1 + 0x10, 0);  // SizeOfRawData
    idr::pe::test_detail::put_u32(pe, s1 + 0x14, 0);  // PointerToRawData
    idr::pe::test_detail::put_u32(pe, s1 + 0x24, 0xC0000040);
}

fs::path no_kb_dir() {
    return fs::temp_directory_path() / "idr_target_no_such_kb_dir";
}

}  // namespace

// --- VMT layouts (ported verbatim from SetVmtConsts, Main.cpp:2004) --------

TEST(VmtLayout, ported_constants_match_set_vmt_consts) {
    EXPECT_EQ(vmt_layout_for(7).type_info, -0x3C);
    EXPECT_EQ(vmt_layout_for(2009).type_info, -0x48);
    EXPECT_EQ(vmt_layout_for(2009).class_name, -0x38);
    EXPECT_EQ(vmt_layout_for(2010).self_ptr, -0x58);
}

TEST(VmtLayout, delphi_2_has_no_interface_or_safecall_fields) {
    const auto l = vmt_layout_for(2);
    EXPECT_EQ(l.self_ptr, -0x34);
    EXPECT_EQ(l.init_table, -0x30);
    EXPECT_EQ(l.type_info, -0x2C);
    EXPECT_EQ(l.field_table, -0x28);
    EXPECT_EQ(l.class_name, -0x1C);
    EXPECT_EQ(l.instance_size, -0x18);
    EXPECT_EQ(l.parent, -0x14);
    EXPECT_EQ(l.default_handler, -0x10);
    EXPECT_EQ(l.new_instance, -0xC);
    EXPECT_EQ(l.free_instance, -8);
    EXPECT_EQ(l.destroy, -4);
    EXPECT_EQ(l.intf_table, 0);
    EXPECT_EQ(l.auto_table, 0);
    EXPECT_EQ(l.safe_call, 0);
}

TEST(VmtLayout, delphi_3_adds_interface_and_safecall_fields) {
    const auto l = vmt_layout_for(3);
    EXPECT_EQ(l.self_ptr, -0x40);
    EXPECT_EQ(l.intf_table, -0x3C);
    EXPECT_EQ(l.auto_table, -0x38);
    EXPECT_EQ(l.init_table, -0x34);
    EXPECT_EQ(l.type_info, -0x30);
    EXPECT_EQ(l.class_name, -0x20);
    EXPECT_EQ(l.instance_size, -0x1C);
    EXPECT_EQ(l.safe_call, -0x14);
    EXPECT_EQ(l.default_handler, -0x10);
    EXPECT_EQ(l.destroy, -4);
    EXPECT_EQ(l.after_construction, 0);
    EXPECT_EQ(l.before_destruction, 0);
    EXPECT_EQ(l.dispatch, 0);
}

TEST(VmtLayout, delphi_4_through_2007_share_a_layout) {
    for (int v : {4, 5, 6, 7, 2005, 2006, 2007}) {
        const auto l = vmt_layout_for(v);
        EXPECT_EQ(l.self_ptr, -0x4C) << v;
        EXPECT_EQ(l.intf_table, -0x48) << v;
        EXPECT_EQ(l.auto_table, -0x44) << v;
        EXPECT_EQ(l.init_table, -0x40) << v;
        EXPECT_EQ(l.type_info, -0x3C) << v;
        EXPECT_EQ(l.class_name, -0x2C) << v;
        EXPECT_EQ(l.instance_size, -0x28) << v;
        EXPECT_EQ(l.after_construction, -0x1C) << v;
        EXPECT_EQ(l.dispatch, -0x14) << v;
        EXPECT_EQ(l.destroy, -4) << v;
    }
}

TEST(VmtLayout, 2009_and_2010_share_a_layout) {
    for (int v : {2009, 2010}) {
        const auto l = vmt_layout_for(v);
        EXPECT_EQ(l.self_ptr, -0x58) << v;
        EXPECT_EQ(l.instance_size, -0x34) << v;
        EXPECT_EQ(l.parent, -0x30) << v;
        EXPECT_EQ(l.safe_call, -0x20) << v;
        EXPECT_EQ(l.dispatch, -0x14) << v;
        EXPECT_EQ(l.destroy, -4) << v;
    }
}

TEST(VmtLayout, 2011_through_2014_share_the_2009_layout) {
    for (int v : {2011, 2012, 2013, 2014}) {
        const auto l = vmt_layout_for(v);
        EXPECT_EQ(l.self_ptr, vmt_layout_for(2009).self_ptr) << v;
        EXPECT_EQ(l.class_name, vmt_layout_for(2009).class_name) << v;
        EXPECT_EQ(l.destroy, -4) << v;
    }
}

TEST(VmtLayout, unknown_version_is_all_zero) {
    const auto l = vmt_layout_for(1234);
    EXPECT_EQ(l.self_ptr, 0);
    EXPECT_EQ(l.class_name, 0);
    EXPECT_EQ(l.destroy, 0);
}

// --- TargetProfile factory -------------------------------------------------

TEST(TargetProfile, of_pe32plus_reports_x64_and_8_byte_pointers) {
    const auto p = TargetProfile::of(Vendor::embarcadero, 2014, Arch::x64);
    EXPECT_EQ(p.vendor(), Vendor::embarcadero);
    EXPECT_EQ(p.version(), 2014);
    EXPECT_EQ(p.arch(), Arch::x64);
    EXPECT_EQ(p.pointer_size(), 8u);
    EXPECT_EQ(p.kb_file_name(), "kb2014.bin");
}

TEST(TargetProfile, of_pe32_reports_x86_and_4_byte_pointers) {
    const auto p = TargetProfile::of(Vendor::embarcadero, 7, Arch::x86);
    EXPECT_EQ(p.version(), 7);
    EXPECT_EQ(p.arch(), Arch::x86);
    EXPECT_EQ(p.pointer_size(), 4u);
    EXPECT_EQ(p.kb_file_name(), "kb7.bin");
    EXPECT_EQ(p.vmt().type_info, vmt_layout_for(7).type_info);
}

TEST(TargetProfile, of_carries_the_vendor) {
    EXPECT_EQ(TargetProfile::of(Vendor::fpc, 7, Arch::x86).vendor(), Vendor::fpc);
    EXPECT_EQ(TargetProfile::of(Vendor::unknown, 0, Arch::unknown).vendor(),
              Vendor::unknown);
}

TEST(TargetProfile, kb_file_name_formats_the_version) {
    EXPECT_EQ(TargetProfile::of(Vendor::embarcadero, 2, Arch::x86).kb_file_name(),
              "kb2.bin");
    EXPECT_EQ(TargetProfile::of(Vendor::embarcadero, 2005, Arch::x64).kb_file_name(),
              "kb2005.bin");
    EXPECT_EQ(TargetProfile::of(Vendor::embarcadero, 2014, Arch::x86).kb_file_name(),
              "kb2014.bin");
}

// --- Detection (GetDelphiVersion, Main.cpp:1525) ---------------------------

TEST(TargetDetect, plain_non_delphi_image_is_unsupported) {
    auto bytes = make_minimal_pe(Arch::x86);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto detected = TargetProfile::detect(pe.value(), no_kb_dir());
    ASSERT_FALSE(detected.has_value());
    EXPECT_EQ(detected.error(), ErrorCode::unsupported_version);
}

// Minor 2: a PE32+ image must not be probed with the 32-bit syskb ladder. Plant
// the >=2010 table so that, without the x86 gate, detection would confidently
// report 2010; instead the image must be rejected as unsupported.
TEST(TargetDetect, pe32plus_image_is_unsupported_not_a_wrong_version) {
    auto bytes = make_minimal_pe(Arch::x64, kDefaultImageBase);
    plant_extended_init_table(bytes, kDefaultImageBase);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    EXPECT_EQ(pe.value().arch(), Arch::x64);

    auto detected = TargetProfile::detect(pe.value(), no_kb_dir());
    ASSERT_FALSE(detected.has_value());
    EXPECT_EQ(detected.error(), ErrorCode::unsupported_version);
}

TEST(TargetDetect, extended_init_table_falls_back_to_2010) {
    auto bytes = make_minimal_pe(Arch::x86, kDefaultImageBase);
    plant_extended_init_table(bytes, kDefaultImageBase);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto detected = TargetProfile::detect(pe.value(), no_kb_dir());
    ASSERT_TRUE(detected.has_value()) << detected.message();
    EXPECT_EQ(detected.value().vendor(), Vendor::embarcadero);
    EXPECT_EQ(detected.value().version(), 2010);
    EXPECT_EQ(detected.value().arch(), Arch::x86);
    EXPECT_EQ(detected.value().pointer_size(), 4u);
    EXPECT_EQ(detected.value().kb_file_name(), "kb2010.bin");
    // The 2010 fallback with no KBs found must be reported as unprobed.
    EXPECT_FALSE(detected.value().kb_probed());
}

// Important 1: the valid-image range must cover inter-section gaps, exactly as
// legacy `[CodeBase, CodeBase + SizeOfImage)` does. A D2010+ table whose entry
// points into the gap must still be recognized (route to the >=2010 ladder),
// not fall through to the legacy branch.
TEST(TargetDetect, accepts_init_table_entry_in_inter_section_gap) {
    const uint32_t image_base = kDefaultImageBase;
    auto bytes = make_minimal_pe(Arch::x86, image_base);
    // .text is [0x1000, 0x2000); the new .data section is [0x3000, 0x4000), so
    // [0x2000, 0x3000) is an inter-section gap and [0x4000, 0x5000) is the
    // image tail past the last section's VirtualSize (both within SizeOfImage).
    add_empty_section(bytes, /*va=*/0x3000, /*vsize=*/0x1000, /*size_of_image=*/0x4000);

    const uint32_t gap_adr = image_base + 0x2500;
    const uint32_t tail_adr = image_base + 0x4500;
    plant_extended_init_table(bytes, image_base, /*at=*/0x10,
                              /*ini_addrs=*/{gap_adr, tail_adr});

    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    EXPECT_EQ(pe.value().size_of_image(), 0x4000u);

    auto detected = TargetProfile::detect(pe.value(), no_kb_dir());
    ASSERT_TRUE(detected.has_value())
        << "gap/tail pointer rejected: routed to the legacy branch";
    EXPECT_EQ(detected.value().version(), 2010);
    EXPECT_FALSE(detected.value().kb_probed());
}

// Important 2 / R9: with real syskb files present but no matching fingerprint,
// the 2010 fallback must be reported as probed.
TEST(TargetDetect, real_kb_dir_reports_probed_on_2010_fallback) {
    const fs::path sys_kb_dir = fs::path(IDR_REPO_ROOT);
    if (!fs::exists(sys_kb_dir / "syskb2014.bin")) {
        GTEST_SKIP() << "no syskb2014.bin fixture";
    }

    auto bytes = make_minimal_pe(Arch::x86, kDefaultImageBase);
    // Fill the code bytes with INT3 so no System fingerprint can match; only
    // the presence of the KBs should be reported.
    std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(kTextRawOffset), bytes.end(),
              std::byte{0xCC});
    plant_extended_init_table(bytes, kDefaultImageBase);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto detected = TargetProfile::detect(pe.value(), sys_kb_dir);
    ASSERT_TRUE(detected.has_value()) << detected.message();
    EXPECT_EQ(detected.value().version(), 2010);
    EXPECT_TRUE(detected.value().kb_probed());
}

TEST(TargetDetect, real_syskb2014_fingerprint_detects_2014) {
    const fs::path sys_kb_dir = fs::path(IDR_REPO_ROOT);
    const fs::path kb_file = sys_kb_dir / "syskb2014.bin";
    if (!fs::exists(kb_file)) {
        GTEST_SKIP() << "no syskb2014.bin fixture";
    }

    auto kb = KnowledgeBase::open(kb_file);
    ASSERT_TRUE(kb.has_value()) << kb.message();

    std::optional<uint16_t> sys_id;
    for (const auto& m : kb.value().data().modules) {
        if (m.name == "System") {
            sys_id = m.id;
            break;
        }
    }
    ASSERT_TRUE(sys_id.has_value()) << "no System module in syskb2014.bin";
    auto idx = kb.value().find_proc(*sys_id, "StringCopy");
    ASSERT_TRUE(idx.has_value()) << "no System.StringCopy in syskb2014.bin";
    const auto& dump = kb.value().data().procs[*idx].dump;
    ASSERT_FALSE(dump.empty());

    const uint32_t image_base = kDefaultImageBase;
    auto bytes = make_minimal_pe(Arch::x86, image_base);
    plant_extended_init_table(bytes, image_base);

    const size_t at = kTextRawOffset + 0x40;
    if (at + dump.size() > bytes.size()) {
        GTEST_SKIP() << "StringCopy fingerprint too large for the builder's .text";
    }
    std::copy(dump.begin(), dump.end(), bytes.begin() + at);

    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    auto detected = TargetProfile::detect(pe.value(), sys_kb_dir);
    ASSERT_TRUE(detected.has_value()) << detected.message();
    EXPECT_EQ(detected.value().version(), 2014);
    EXPECT_EQ(detected.value().arch(), Arch::x86);
    EXPECT_TRUE(detected.value().kb_probed());
}

TEST(TargetProfile, of_reports_unprobed) {
    EXPECT_FALSE(TargetProfile::of(Vendor::embarcadero, 2014, Arch::x86).kb_probed());
}
