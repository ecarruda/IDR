#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "idr/kb/knowledge_base.hpp"

namespace fs = std::filesystem;
using idr::kb::ArgRecord;
using idr::kb::ConstRecord;
using idr::kb::KnowledgeBase;
using idr::kb::KbData;
using idr::kb::ModuleRecord;
using idr::kb::ProcRecord;
using idr::kb::ResStringRecord;
using idr::kb::TypeRecord;
using idr::kb::VarRecord;

namespace {

KbData make_sample_kb() {
    KbData kb;
    kb.format_version = 3;
    kb.arch = idr::kb::Arch::x64;
    kb.vendor = "IDR Reborn";
    kb.vendor_code = 7;
    kb.compiler_version = 7;
    kb.compiler_id = "Delphi 7";
    kb.pointer_size = 4;

    ModuleRecord mod;
    mod.id = 1;
    mod.name = "System";
    mod.filename = "System.dcu";
    mod.uses_ids = {0xFFFF, 2};
    kb.modules.push_back(std::move(mod));

    ProcRecord proc;
    proc.module_id = 1;
    proc.name = "StringCopy";
    proc.embedded = false;
    proc.dump_type = 'C';
    proc.method_kind = 'F';
    proc.call_kind = 3;
    proc.vproc = 0;
    proc.result_type = "PChar";
    proc.dump = {std::byte{0x55}, std::byte{0x8B}, std::byte{0xEC},
                 std::byte{0xC2}, std::byte{0x08}, std::byte{0x00}};
    proc.relocs = {std::byte{0x00}, std::byte{0x00}, std::byte{0xFF},
                   std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    proc.fixups = {std::byte{0x04}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    ArgRecord a1;
    a1.tag = 0x22;
    a1.in_register = false;
    a1.reg_index = 8;
    a1.size = 4;
    a1.name = "Dest";
    a1.type = "PChar";
    proc.args.push_back(a1);

    ArgRecord a2;
    a2.tag = 0x21;
    a2.in_register = true;
    a2.reg_index = 0;
    a2.size = 4;
    a2.name = "Count";
    a2.type = "Integer";
    proc.args.push_back(a2);

    kb.procs.push_back(std::move(proc));

    TypeRecord type;
    type.module_id = 1;
    type.name = "TMyClass";
    type.kind = 'F';
    type.vmt_count = 1;
    type.decl = "TMyClass = class(TObject)";
    type.dump = {std::byte{0x01}, std::byte{0x02}};
    type.relocs = {std::byte{0x00}, std::byte{0x00}};
    type.fields = {std::byte{0x01}, std::byte{0x00}};
    type.props = {std::byte{0x00}, std::byte{0x00}};
    type.methods = {std::byte{0x01}, std::byte{0x00}};
    kb.types.push_back(std::move(type));

    return kb;
}

fs::path temp_path(const std::string& name) {
    return fs::temp_directory_path() / ("idr_kb_" + name + ".bin");
}

void write_bytes(const fs::path& path, const std::vector<std::byte>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

// A minimal 293-byte v2 header with kbVer == 2.
std::vector<std::byte> make_v2_header_bytes() {
    std::vector<std::byte> bytes(293, std::byte{0});
    const char* sig = "IDR Knowledge Base File";
    for (size_t i = 0; i < 23; ++i) {
        bytes[i] = static_cast<std::byte>(sig[i]);
    }
    // isMSIL(24)=0, delphiVer(25..28)=0, crc(29..32)=0, description(33..288)=0.
    bytes[289] = std::byte{2};  // kbVer (little-endian u32) = 2
    return bytes;
}

}  // namespace

TEST(KbV3, round_trips_dump_and_args_byte_exact) {
    KbData kb = make_sample_kb();
    auto path = temp_path("roundtrip");
    auto written = idr::kb::write_v3(path, kb);
    ASSERT_TRUE(written.has_value()) << written.message();

    auto opened = KnowledgeBase::open(path);
    ASSERT_TRUE(opened.has_value()) << opened.message();
    EXPECT_EQ(opened.value().format_version(), 3u);

    const auto& data = opened.value().data();
    // Header fields must round-trip, including the architecture/vendor bytes
    // that used to be written reserved and discarded on read (spec 6.1/6.2).
    EXPECT_EQ(data.arch, idr::kb::Arch::x64);
    EXPECT_EQ(data.vendor_code, 7u);
    EXPECT_EQ(data.vendor, "IDR Reborn");
    EXPECT_EQ(data.compiler_version, 7);
    EXPECT_EQ(data.compiler_id, "Delphi 7");
    ASSERT_EQ(data.procs.size(), 1u);
    const auto& proc = data.procs[0];
    EXPECT_EQ(proc.name, "StringCopy");
    EXPECT_EQ(proc.dump, kb.procs[0].dump);
    EXPECT_EQ(proc.relocs, kb.procs[0].relocs);
    EXPECT_EQ(proc.fixups, kb.procs[0].fixups);
    ASSERT_EQ(proc.args.size(), kb.procs[0].args.size());
    for (size_t i = 0; i < proc.args.size(); ++i) {
        EXPECT_EQ(proc.args[i].tag, kb.procs[0].args[i].tag);
        EXPECT_EQ(proc.args[i].in_register, kb.procs[0].args[i].in_register);
        EXPECT_EQ(proc.args[i].reg_index, kb.procs[0].args[i].reg_index);
        EXPECT_EQ(proc.args[i].size, kb.procs[0].args[i].size);
        EXPECT_EQ(proc.args[i].name, kb.procs[0].args[i].name);
        EXPECT_EQ(proc.args[i].type, kb.procs[0].args[i].type);
    }

    fs::remove(path);
}

TEST(KbV3, find_proc_resolves_by_name) {
    KbData kb = make_sample_kb();
    auto path = temp_path("findproc");
    ASSERT_TRUE(idr::kb::write_v3(path, kb).has_value());

    auto opened = KnowledgeBase::open(path);
    ASSERT_TRUE(opened.has_value());

    auto idx = opened.value().find_proc("StringCopy");
    ASSERT_TRUE(idx.has_value());
    EXPECT_EQ(opened.value().data().procs[*idx].name, "StringCopy");
    EXPECT_EQ(opened.value().find_proc("Missing"), std::nullopt);

    auto mod_idx = opened.value().find_proc(1, "StringCopy");
    ASSERT_TRUE(mod_idx.has_value());
    EXPECT_EQ(*mod_idx, *idx);
    EXPECT_EQ(opened.value().find_proc(2, "StringCopy"), std::nullopt);

    fs::remove(path);
}

TEST(KbV3, rejects_unknown_magic) {
    auto path = temp_path("badmagic");
    std::vector<std::byte> bytes(16, std::byte{'X'});
    write_bytes(path, bytes);

    auto opened = KnowledgeBase::open(path);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), idr::ErrorCode::bad_magic);

    fs::remove(path);
}

TEST(KbV3, rejects_unsupported_version) {
    auto path = temp_path("badversion");
    std::vector<std::byte> bytes;
    for (char c : std::string("IDRKB")) {
        bytes.push_back(static_cast<std::byte>(c));
    }
    // formatVersion = 99 (little-endian)
    for (unsigned int b : {99u, 0u, 0u, 0u}) {
        bytes.push_back(static_cast<std::byte>(b));
    }
    write_bytes(path, bytes);

    auto opened = KnowledgeBase::open(path);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), idr::ErrorCode::unsupported_version);

    fs::remove(path);
}

TEST(KbV3, zero_reserved_arch_reads_as_unknown) {
    // A v3 file whose architecture byte is the old reserved 0 must still read;
    // 0 maps to Arch::unknown rather than being rejected.
    KbData kb = make_sample_kb();
    kb.arch = idr::kb::Arch::unknown;
    kb.vendor_code = 0;
    auto path = temp_path("unknownarch");
    ASSERT_TRUE(idr::kb::write_v3(path, kb).has_value());

    auto opened = KnowledgeBase::open(path);
    ASSERT_TRUE(opened.has_value()) << opened.message();
    EXPECT_EQ(opened.value().data().arch, idr::kb::Arch::unknown);
    EXPECT_EQ(opened.value().data().vendor_code, 0u);

    fs::remove(path);
}

TEST(KbV3, checksum_mismatch_reports_unsupported_format) {
    KbData kb = make_sample_kb();
    auto path = temp_path("badchecksum");
    ASSERT_TRUE(idr::kb::write_v3(path, kb).has_value());

    // Corrupt a byte inside the checksummed (directory + section) region.
    std::vector<std::byte> bytes;
    {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        ASSERT_TRUE(in);
        const std::streamsize size = in.tellg();
        ASSERT_GT(size, 0);
        in.seekg(0, std::ios::beg);
        bytes.resize(static_cast<size_t>(size));
        in.read(reinterpret_cast<char*>(bytes.data()), size);
        ASSERT_TRUE(in);
    }
    bytes.back() ^= std::byte{0xFF};
    write_bytes(path, bytes);

    auto opened = KnowledgeBase::open(path);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), idr::ErrorCode::unsupported_format);

    fs::remove(path);
}

TEST(KbLegacyV2, opens_v2_kb_bin) {
    // Prefer the in-repo syskb2014.bin (a real v2 KB); fall back to kb2014.bin,
    // and skip only if neither is present.
    const fs::path sys_fixture = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    const fs::path kb_fixture = fs::path(IDR_REPO_ROOT) / "kb2014.bin";
    const fs::path fixture = fs::exists(sys_fixture) ? sys_fixture : kb_fixture;
    if (!fs::exists(fixture)) {
        GTEST_SKIP() << "no v2 KB fixture present";
    }

    auto opened = KnowledgeBase::open(fixture);
    ASSERT_TRUE(opened.has_value()) << opened.message();
    EXPECT_EQ(opened.value().format_version(), 2u);
    EXPECT_GT(opened.value().data().procs.size(), 1000u);

    // A known proc resolves, and its args map locflags -> in_register and
    // Ndx -> reg_index (the regression net for the v2 ARGINFO layout).
    auto idx = opened.value().find_proc("InterlockedExchange");
    ASSERT_TRUE(idx.has_value());
    const auto& proc = opened.value().data().procs[*idx];
    EXPECT_EQ(proc.name, "InterlockedExchange");
    EXPECT_EQ(proc.result_type, "System.Integer");
    ASSERT_EQ(proc.args.size(), 2u);
    EXPECT_EQ(proc.args[0].name, "Target");
    EXPECT_EQ(proc.args[1].name, "Value");
    EXPECT_EQ(proc.args[0].reg_index, 8);
    EXPECT_EQ(proc.args[1].reg_index, 12);
    EXPECT_FALSE(proc.args[0].in_register);
    EXPECT_FALSE(proc.args[1].in_register);

    // The register flag must actually be parsed (not left at its default):
    // the KB should contain at least one register-passed argument.
    bool saw_register_arg = false;
    for (const auto& p : opened.value().data().procs) {
        for (const auto& a : p.args) {
            if (a.in_register) {
                saw_register_arg = true;
                break;
            }
        }
        if (saw_register_arg) break;
    }
    EXPECT_TRUE(saw_register_arg);
}

TEST(KbLegacyV2, rejects_out_of_range_sections_offset) {
    auto bytes = make_v2_header_bytes();
    bytes.resize(300, std::byte{0});
    // Tail sections offset points past EOF (must be rejected, not read).
    bytes[296] = std::byte{0xFF};
    bytes[297] = std::byte{0xFF};
    bytes[298] = std::byte{0xFF};
    bytes[299] = std::byte{0xFF};

    auto path = temp_path("badoffset");
    write_bytes(path, bytes);

    auto opened = KnowledgeBase::open(path);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), idr::ErrorCode::truncated);

    fs::remove(path);
}

TEST(KbLegacyV2, rejects_huge_section_count_without_allocating) {
    // A crafted count must be rejected by the byte-bounded guard before it
    // drives reserve(); otherwise reserve(INT32_MAX * 16 bytes) would throw
    // std::length_error/bad_alloc across the open() boundary.
    auto bytes = make_v2_header_bytes();
    bytes.resize(320, std::byte{0});
    const uint32_t sections_offset = 300;  // points at the modules table header
    // count = INT32_MAX (positive), maxsize = 0.
    bytes[sections_offset + 0] = std::byte{0xFF};
    bytes[sections_offset + 1] = std::byte{0xFF};
    bytes[sections_offset + 2] = std::byte{0xFF};
    bytes[sections_offset + 3] = std::byte{0x7F};
    // Tail sections offset (last 4 bytes), little-endian.
    for (int i = 0; i < 4; ++i) {
        bytes[316 + i] =
            std::byte{static_cast<uint8_t>((sections_offset >> (8 * i)) & 0xFF)};
    }

    auto path = temp_path("hugecount");
    write_bytes(path, bytes);

    auto opened = KnowledgeBase::open(path);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), idr::ErrorCode::truncated);

    fs::remove(path);
}

// --- scan_code ------------------------------------------------------------

// Writes `data` as a v3 KB and reopens it, mirroring how a scanned probe
// arrives from a file. Returns nullopt when write/open failed.
std::optional<KnowledgeBase> open_kb(const KbData& data, const std::string& name) {
    const fs::path path = temp_path(name);
    if (!idr::kb::write_v3(path, data).has_value()) return std::nullopt;
    auto opened = KnowledgeBase::open(path);
    fs::remove(path);
    if (!opened.has_value()) return std::nullopt;
    return std::optional<KnowledgeBase>(opened.value());
}

// `push ebp; mov ebp, esp; ret` — a fingerprint with no relocated bytes.
const std::vector<std::byte> kPlainDump = {
    std::byte{0x55}, std::byte{0x8B}, std::byte{0xEC}, std::byte{0xC3}};

KbData make_proc_kb(std::string_view name, std::vector<std::byte> dump,
                    std::vector<std::byte> relocs) {
    KbData kb;
    kb.format_version = 3;
    kb.vendor = "IDR Reborn";
    kb.compiler_version = 7;
    kb.compiler_id = "Delphi 7";
    kb.pointer_size = 4;

    ProcRecord proc;
    proc.module_id = 1;
    proc.name = std::string(name);
    proc.dump_type = 'C';
    proc.method_kind = 'F';
    proc.call_kind = 3;
    proc.dump = std::move(dump);
    proc.relocs = std::move(relocs);
    kb.procs.push_back(std::move(proc));
    return kb;
}

TEST(KbScanCode, returns_image_address_of_the_first_match) {
    KbData data = make_proc_kb("RetTail", kPlainDump, {});
    auto kb = open_kb(data, "scan_found");
    ASSERT_TRUE(kb.has_value());

    std::vector<std::byte> code(0x40, std::byte{0x90});
    std::copy(kPlainDump.begin(), kPlainDump.end(), code.begin() + 0x20);
    const uint32_t code_base = 0x00401000u;

    const auto hit =
        kb.value().scan_code(code, code_base, kb.value().data().procs[0]);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, code_base + 0x20);
}

TEST(KbScanCode, no_match_returns_nullopt) {
    KbData data = make_proc_kb("RetTail", kPlainDump, {});
    auto kb = open_kb(data, "scan_miss");
    ASSERT_TRUE(kb.has_value());

    const std::vector<std::byte> code(0x40, std::byte{0x90});
    const auto hit =
        kb.value().scan_code(code, 0x00401000u, kb.value().data().procs[0]);
    EXPECT_EQ(hit, std::nullopt);
}

TEST(KbScanCode, empty_dump_returns_nullopt) {
    // An unguarded empty dump would match at offset 0 by definition.
    KbData data = make_proc_kb("NoDump", {}, {});
    auto kb = open_kb(data, "scan_emptydump");
    ASSERT_TRUE(kb.has_value());

    const auto hit =
        kb.value().scan_code(kPlainDump, 0x00401000u, kb.value().data().procs[0]);
    EXPECT_EQ(hit, std::nullopt);
}

TEST(KbScanCode, dump_larger_than_code_returns_nullopt) {
    // 8 dump bytes against a 4-byte code blob must be rejected up front
    // instead of reading past the end of `code`.
    KbData data = make_proc_kb("TooBig", std::vector<std::byte>(8, std::byte{0x90}),
                               {});
    auto kb = open_kb(data, "scan_toobig");
    ASSERT_TRUE(kb.has_value());

    const std::vector<std::byte> code(4, std::byte{0x90});
    const auto hit =
        kb.value().scan_code(code, 0x00401000u, kb.value().data().procs[0]);
    EXPECT_EQ(hit, std::nullopt);
}

TEST(KbScanCode, dump_spanning_all_the_code_matches_at_base) {
    KbData data = make_proc_kb("WholeCode", kPlainDump, {});
    auto kb = open_kb(data, "scan_exact");
    ASSERT_TRUE(kb.has_value());

    const auto hit =
        kb.value().scan_code(kPlainDump, 0x00405000u, kb.value().data().procs[0]);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, 0x00405000u);
}

TEST(KbScanCode, relocation_bytes_are_wildcards) {
    // `call rel32; ret` where the rel32 is relocated: 0xFF-flagged bytes are
    // skipped by the comparison, the fixed opcodes still have to match.
    const std::vector<std::byte> dump = {std::byte{0xE8}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0xC3}};
    const std::vector<std::byte> relocs = {std::byte{0x00}, std::byte{0xFF},
                                           std::byte{0xFF}, std::byte{0xFF},
                                           std::byte{0xFF}, std::byte{0x00}};
    KbData data = make_proc_kb("CallRet", dump, relocs);
    auto kb = open_kb(data, "scan_reloc");
    ASSERT_TRUE(kb.has_value());
    const ProcRecord& probe = kb.value().data().procs[0];

    std::vector<std::byte> code(0x30, std::byte{0x90});
    const uint32_t code_base = 0x00402000u;
    code[0x10 + 0] = std::byte{0xE8};
    code[0x10 + 1] = std::byte{0xDE};
    code[0x10 + 2] = std::byte{0xAD};
    code[0x10 + 3] = std::byte{0xBE};
    code[0x10 + 4] = std::byte{0xEF};
    code[0x10 + 5] = std::byte{0xC3};

    const auto hit = kb.value().scan_code(code, code_base, probe);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, code_base + 0x10);

    // Flipping a non-wildcard byte (and keeping the wildcards intact) breaks
    // the match.
    code[0x10 + 0] = std::byte{0xE9};
    EXPECT_EQ(kb.value().scan_code(code, code_base, probe), std::nullopt);
}

TEST(KbV3, round_trips_all_sections_and_raw_fields) {
    KbData kb;
    kb.arch = idr::kb::Arch::x86;
    kb.vendor = "embarcadero";
    kb.vendor_code = 1;
    kb.compiler_version = 2014;
    kb.compiler_id = "XE4";
    kb.pointer_size = 4;

    ModuleRecord m;
    m.id = 1; m.name = "System"; m.filename = "System.dcu";
    m.uses_ids = {0xFFFF, 2};
    m.uses_names = {"kernel32.dll", "System"};
    kb.modules.push_back(m);

    ConstRecord c;
    c.module_id = 1; c.name = "c1"; c.type = 'C';
    c.type_def = "Integer"; c.value = "1";
    c.dump = {std::byte{0xAA}}; c.relocs = {std::byte{0x00}};
    c.fixups = {std::byte{0x41}, std::byte{0x04}, std::byte{0x00}};
    kb.consts.push_back(c);

    TypeRecord t;
    t.module_id = 1; t.name = "T"; t.kind = 'F'; t.vmt_count = 2;
    t.decl = "T = class"; t.dump = {std::byte{0x01}}; t.relocs = {std::byte{0x00}};
    t.fixups = {std::byte{0x44}};
    t.fields = {std::byte{0x01}, std::byte{0x00}};
    t.props = {std::byte{0x00}, std::byte{0x00}};
    t.methods = {std::byte{0x01}, std::byte{0x00}};
    kb.types.push_back(t);

    VarRecord v;
    v.module_id = 1; v.name = "g"; v.type = 'V'; v.type_def = "Integer"; v.abs_name = "";
    kb.vars.push_back(v);

    ResStringRecord rs;
    rs.module_id = 1; rs.name = "s"; rs.type_def = "string"; rs.context = "System";
    kb.resstrings.push_back(rs);

    ProcRecord p;
    p.module_id = 1; p.name = "F"; p.dump_type = 'C'; p.method_kind = 'F'; p.call_kind = 3;
    p.result_type = "Integer";
    p.dump = {std::byte{0x55}}; p.relocs = {std::byte{0x00}};
    p.fixups = {std::byte{0x41}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    p.locals = {std::byte{0x00}, std::byte{0x00}};
    kb.procs.push_back(p);

    const auto path = temp_path("allroundtrip");
    ASSERT_TRUE(idr::kb::write_v3(path, kb).has_value());
    auto opened = KnowledgeBase::open(path);
    ASSERT_TRUE(opened.has_value()) << opened.message();

    KbData expected = kb;
    expected.format_version = 3;  // write_v3 always emits v3
    EXPECT_TRUE(idr::kb::kb_equal(expected, opened.value().data()));
    EXPECT_EQ(opened.value().data().vars.size(), 1u);
    EXPECT_EQ(opened.value().data().resstrings.size(), 1u);
    fs::remove(path);
}

TEST(KbV3, kb_equal_detects_a_field_difference) {
    KbData a;
    a.procs.push_back(ProcRecord{});
    a.procs[0].name = "A";
    KbData b = a;
    EXPECT_TRUE(idr::kb::kb_equal(a, b));
    b.procs[0].name = "B";
    EXPECT_FALSE(idr::kb::kb_equal(a, b));
}

TEST(KbLegacyV2, reads_all_sections_with_expected_counts) {
    const fs::path fixture = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    if (!fs::exists(fixture)) GTEST_SKIP() << "syskb2014.bin absent";

    auto opened = KnowledgeBase::open(fixture);
    ASSERT_TRUE(opened.has_value()) << opened.message();
    const auto& d = opened.value().data();

    EXPECT_EQ(d.modules.size(), 2u);
    EXPECT_EQ(d.consts.size(), 394u);
    EXPECT_EQ(d.types.size(), 451u);
    EXPECT_EQ(d.vars.size(), 82u);
    EXPECT_EQ(d.resstrings.size(), 0u);
    EXPECT_EQ(d.procs.size(), 1195u);

    // Header facts implied by a non-MSIL v2 file.
    EXPECT_EQ(d.arch, idr::kb::Arch::x86);
    EXPECT_EQ(d.vendor, "embarcadero");
    EXPECT_EQ(d.pointer_size, 4u);

    // Module use-names are materialized (previously dropped).
    ASSERT_FALSE(d.modules.empty());
    EXPECT_FALSE(d.modules[0].uses_names.empty());
    EXPECT_EQ(d.modules[0].uses_names.size(), d.modules[0].uses_ids.size());

    // A dumped record carries raw fixup bytes when the file records any.
    const bool saw_fixups = std::any_of(d.consts.begin(), d.consts.end(),
                                        [](const idr::kb::ConstRecord& c) {
                                            return !c.fixups.empty();
                                        });
    EXPECT_TRUE(saw_fixups);

    // Vars decode: at least one named var with a type.
    ASSERT_FALSE(d.vars.empty());
    EXPECT_FALSE(d.vars[0].name.empty());
}

TEST(KbLegacyV2, reads_proc_locals_when_present) {
    const fs::path fixture = fs::path(IDR_REPO_ROOT) / "syskb2.bin";
    if (!fs::exists(fixture)) GTEST_SKIP() << "syskb2.bin absent";

    auto opened = KnowledgeBase::open(fixture);
    ASSERT_TRUE(opened.has_value()) << opened.message();
    const auto& d = opened.value().data();

    const bool saw_locals = std::any_of(d.procs.begin(), d.procs.end(),
                                        [](const idr::kb::ProcRecord& p) {
                                            return !p.locals.empty();
                                        });
    EXPECT_TRUE(saw_locals);
}

TEST(KbV3, write_read_write_is_byte_identical) {
    KbData kb = make_sample_kb();
    const auto p1 = temp_path("det1");
    ASSERT_TRUE(idr::kb::write_v3(p1, kb).has_value());
    auto opened = KnowledgeBase::open(p1);
    ASSERT_TRUE(opened.has_value());
    const auto p2 = temp_path("det2");
    ASSERT_TRUE(idr::kb::write_v3(p2, opened.value().data()).has_value());

    auto read_all = [](const fs::path& p) {
        std::ifstream in(p, std::ios::binary | std::ios::ate);
        std::vector<std::byte> v(static_cast<size_t>(in.tellg()));
        in.seekg(0);
        in.read(reinterpret_cast<char*>(v.data()), static_cast<std::streamsize>(v.size()));
        return v;
    };
    EXPECT_EQ(read_all(p1), read_all(p2));
    fs::remove(p1); fs::remove(p2);
}
