#include "idr/target/target_profile.hpp"

#include "idr/kb/knowledge_base.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace idr::target {
namespace {

using kb::KnowledgeBase;

// The resource / base-relocation data-directory indices that identify the
// sections the legacy loader excludes from its flattened image
// (Main.cpp:8661-8690).
constexpr size_t kDirResource = 2;
constexpr size_t kDirBaseReloc = 5;

// Upper bound on the flattened image the legacy detection routines would build.
// It exists to keep a malformed SizeOfImage from driving an unbounded
// allocation (no exception may cross this boundary).
constexpr size_t kMaxFlatBytes = 64u << 20;

// A flattened image mirroring the legacy `Image` buffer: the eligible sections
// concatenated (resource / relocation sections and empty raw sections skipped),
// with each run recorded so language addresses can be mapped back.
struct FlatImage {
    struct Segment {
        uint32_t start_va = 0;  // image address of the segment's first byte
        uint32_t pos_begin = 0; // position of that byte within `bytes`
        uint32_t size = 0;
    };

    std::vector<std::byte> bytes;
    std::vector<Segment> segments;
    // Contiguous mapped-image extent [valid_lo, valid_hi), mirroring legacy
    // IsValidImageAdr's single `[CodeBase, CodeBase + ImageSize)` range
    // (Misc.cpp:284) so pointers into inter-section gaps are accepted.
    uint32_t valid_lo = 0;
    uint32_t valid_hi = 0;

    std::optional<uint32_t> u32_at(size_t pos) const {
        if (pos + 4 > bytes.size()) {
            return std::nullopt;
        }
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v |= static_cast<uint32_t>(static_cast<uint8_t>(bytes[pos + i])) << (8 * i);
        }
        return v;
    }

    // Pos2Adr (Misc.cpp:123): image address of a flattened position.
    std::optional<uint32_t> pos_to_adr(uint32_t pos) const {
        for (const auto& s : segments) {
            if (pos >= s.pos_begin && pos < s.pos_begin + s.size) {
                return s.start_va + (pos - s.pos_begin);
            }
        }
        return std::nullopt;
    }

    // Adr2Pos (Misc.cpp:105): flattened position of an image address.
    std::optional<uint32_t> adr_to_pos(uint32_t adr) const {
        for (const auto& s : segments) {
            if (adr >= s.start_va && adr < s.start_va + s.size) {
                return s.pos_begin + (adr - s.start_va);
            }
        }
        return std::nullopt;
    }

    // IsValidImageAdr (Misc.cpp:284): is `adr` inside the mapped image?
    bool valid_image_adr(uint32_t adr) const {
        return adr >= valid_lo && adr < valid_hi;
    }
};

FlatImage build_flat_image(const pe::PeFile& image) {
    FlatImage flat;
    const auto& secs = image.sections();

    const uint32_t rsrc_va =
        image.data_directory(kDirResource) ? image.data_directory(kDirResource)->rva : 0;
    const uint32_t reloc_va =
        image.data_directory(kDirBaseReloc) ? image.data_directory(kDirBaseReloc)->rva : 0;

    // The legacy valid-image range is the single extent
    // `[CodeBase, CodeBase + SizeOfImage)` (Misc.cpp:284): it deliberately
    // includes inter-section alignment gaps and the image tail beyond the last
    // section's VirtualSize. Reproduce that here so a genuine D2010+ binary is
    // not misrouted into the legacy branch.
    const uint32_t first_va = secs.empty() ? 0 : secs.front().virtual_address;
    const uint32_t code_base = static_cast<uint32_t>(image.image_base() + first_va);
    uint32_t image_end = 0;
    for (const auto& sec : secs) {
        const uint64_t end = image.image_base() + sec.virtual_address + sec.virtual_size;
        image_end = std::max(image_end, static_cast<uint32_t>(end));
    }
    flat.valid_lo = code_base;
    flat.valid_hi = std::max(code_base + image.size_of_image(), image_end);
    if (flat.valid_hi <= flat.valid_lo) {
        // Malformed or absent SizeOfImage with no usable sections.
        flat.valid_lo = static_cast<uint32_t>(image.image_base());
        flat.valid_hi = std::max(image_end, flat.valid_lo + 1);
    }

    for (size_t i = 0; i < secs.size(); ++i) {
        const auto& sec = secs[i];
        if (sec.virtual_address == rsrc_va || sec.virtual_address == reloc_va) {
            continue;
        }
        if (sec.raw_size == 0) {
            continue;
        }

        uint32_t size = sec.virtual_size;
        if (i + 1 < secs.size() && secs[i + 1].virtual_address > sec.virtual_address) {
            size = secs[i + 1].virtual_address - sec.virtual_address;
        }
        if (size == 0 || flat.bytes.size() + size > kMaxFlatBytes) {
            break;
        }

        FlatImage::Segment seg;
        seg.start_va = static_cast<uint32_t>(image.image_base() + sec.virtual_address);
        seg.pos_begin = static_cast<uint32_t>(flat.bytes.size());
        seg.size = size;
        flat.bytes.resize(flat.bytes.size() + size, std::byte{0});

        auto raw = image.at_rva(sec.virtual_address, sec.raw_size);
        if (raw.has_value()) {
            const size_t n = std::min<size_t>(size, raw.value().size());
            std::copy_n(raw.value().begin(), n, flat.bytes.begin() + seg.pos_begin);
        }
        flat.segments.push_back(seg);
    }
    return flat;
}

// One pass of IsExtendedInitTab (Main.cpp:2588): does a unit-initialization
// table start at flattened position `i`? `delta` is 4 for the pre-2010 table
// layout and 20 for the D2010+ layout.
bool units_table_at(const FlatImage& flat, size_t i, uint32_t delta) {
    auto init_table = flat.u32_at(i);
    if (!init_table.has_value()) {
        return false;
    }
    auto adr = flat.pos_to_adr(static_cast<uint32_t>(i));
    if (!adr.has_value() || *init_table != *adr + delta) {
        return false;
    }
    if (i < 4) {
        return false;
    }
    auto num_v = flat.u32_at(i - 4);
    if (!num_v.has_value()) {
        return false;
    }
    const int64_t num = static_cast<int32_t>(*num_v);
    if (num <= 0 || num > 10000) {
        return false;
    }

    uint64_t pos = static_cast<uint64_t>(i) + delta;
    for (int64_t n = 0; n < num; ++n, pos += 8) {
        auto ini = flat.u32_at(static_cast<size_t>(pos));
        if (!ini.has_value()) {
            return false;
        }
        if (*ini != 0 && !flat.valid_image_adr(*ini)) {
            return false;
        }
        auto fin = flat.u32_at(static_cast<size_t>(pos) + 4);
        if (!fin.has_value()) {
            return false;
        }
        if (*fin != 0 && !flat.valid_image_adr(*fin)) {
            return false;
        }
    }
    return true;
}

bool is_extended_init_tab(const FlatImage& flat) {
    const size_t n = flat.bytes.size();
    // The pre-2010 unit table, if present, means this is not the >=2010 layout.
    for (size_t i = 0; i + 4 <= n; i += 4) {
        if (units_table_at(flat, i, 4)) {
            return false;
        }
    }
    for (size_t i = 0; i + 20 <= n; i += 4) {
        if (units_table_at(flat, i, 20)) {
            return true;
        }
    }
    return false;
}

// The <2010 branch of GetDelphiVersion (Main.cpp:1628-1683): locate the
// TControl class VMT from its class-name shortstring and infer the version
// from the instance size stored before the VMT. Only the unambiguous
// instance-size probes are ported; 2006/2007 disambiguation and the KB ladder
// that follow in the legacy routine are Phase 2.
std::optional<int> detect_legacy_version(const FlatImage& flat) {
    auto read_before = [&flat](uint32_t pos, uint32_t delta) -> std::optional<uint32_t> {
        if (pos < delta) {
            return std::nullopt;
        }
        return flat.u32_at(pos - delta);
    };

    for (size_t n = 0; n + 14 <= flat.bytes.size(); n += 4) {
        const auto* p = flat.bytes.data() + n;
        if (p[0] != std::byte{7} || p[1] != std::byte{8} || p[2] != std::byte{'T'} ||
            p[3] != std::byte{'C'} || p[4] != std::byte{'o'} || p[5] != std::byte{'n'} ||
            p[6] != std::byte{'t'} || p[7] != std::byte{'r'} || p[8] != std::byte{'o'} ||
            p[9] != std::byte{'l'}) {
            continue;
        }
        auto vmt_adr = flat.u32_at(n + 10);
        if (!vmt_adr.has_value()) {
            break;
        }
        if (!flat.valid_image_adr(*vmt_adr)) {
            continue;
        }
        auto vpos = flat.adr_to_pos(*vmt_adr);
        if (!vpos.has_value()) {
            continue;
        }

        if (auto v = read_before(*vpos, 0x18); v.has_value() && *v == 0xA8) {
            return 2;
        }
        if (auto v = read_before(*vpos, 0x1C); v.has_value() && (*v == 0xB0 || *v == 0xB4)) {
            return 3;
        }
        const auto inst = read_before(*vpos, 0x28);
        if (inst.has_value()) {
            if (*inst == 0x114) {
                return 4;
            }
            if (*inst == 0x120) {
                return 5;
            }
            if (*inst == 0x15C) {
                // Delphi 6 or 7: disambiguate via the TForm instance size.
                for (size_t m = 0; m + 11 <= flat.bytes.size(); m += 4) {
                    const auto* q = flat.bytes.data() + m;
                    if (q[0] != std::byte{7} || q[1] != std::byte{5} ||
                        q[2] != std::byte{'T'} || q[3] != std::byte{'F'} ||
                        q[4] != std::byte{'o'} || q[5] != std::byte{'r'} ||
                        q[6] != std::byte{'m'}) {
                        continue;
                    }
                    auto form_vmt = flat.u32_at(m + 7);
                    if (!form_vmt.has_value() || !flat.valid_image_adr(*form_vmt)) {
                        continue;
                    }
                    auto fpos = flat.adr_to_pos(*form_vmt);
                    if (!fpos.has_value()) {
                        continue;
                    }
                    auto size = read_before(*fpos, 0x28);
                    if (size.has_value() && *size == 0x2F0) {
                        return 6;
                    }
                    if (size.has_value() && *size == 0x2F8) {
                        return 7;
                    }
                }
                return std::nullopt;
            }
            if (*inst == 0x164) {
                return 2005;
            }
            if (*inst == 0x190) {
                // Delphi 2006 vs 2007 (or later) is ambiguous without the KB
                // ladder; that is Phase 2.
                return std::nullopt;
            }
        }
        if (auto v = read_before(*vpos, 0x34); v.has_value() && *v == 0x1A4) {
            return 2009;
        }
    }
    return std::nullopt;
}

std::optional<uint16_t> module_id_of(const KnowledgeBase& kb, std::string_view name) {
    for (const auto& m : kb.data().modules) {
        if (m.name == name) {
            return m.id;
        }
    }
    return std::nullopt;
}

// The >=2010 ladder from GetDelphiVersion (Main.cpp:1537-1625): probe the
// System unit's fingerprint functions against the flattened image, newest KB
// first, falling back to 2010. `kb_probed` is set when a syskb file is
// successfully opened, so the caller can tell a real 2010 detection from the
// no-KB fallback.
int detect_extended(const FlatImage& flat,
                    const std::filesystem::path& sys_kb_dir, bool& kb_probed) {
    if (flat.segments.empty()) {
        return 2010;
    }
    const Bytes code(flat.bytes);
    const uint32_t code_base = flat.segments.front().start_va;

    struct Probe {
        int version;
        const char* kb_file;
        const char* proc;
    };
    static constexpr Probe kProbes[] = {
        {2014, "syskb2014.bin", "StringCopy"},
        {2013, "syskb2013.bin", "@FinalizeResStrings"},
        {2012, "syskb2012.bin", "@InitializeControlWord"},
        {2011, "syskb2011.bin", "ErrorAt"},
    };

    for (const auto& probe : kProbes) {
        auto kb = KnowledgeBase::open(sys_kb_dir / probe.kb_file);
        if (!kb.has_value()) {
            continue;
        }
        kb_probed = true;
        auto module = module_id_of(kb.value(), "System");
        if (!module.has_value()) {
            continue;
        }
        auto idx = kb.value().find_proc(*module, probe.proc);
        if (!idx.has_value()) {
            continue;
        }
        const auto& record = kb.value().data().procs[*idx];
        if (kb.value().scan_code(code, code_base, record).has_value()) {
            return probe.version;
        }
    }
    return 2010;
}

}  // namespace

VmtLayout vmt_layout_for(int version) {
    VmtLayout l;
    switch (version) {
        case 2:
            l.self_ptr = -0x34;
            l.init_table = -0x30;
            l.type_info = -0x2C;
            l.field_table = -0x28;
            l.method_table = -0x24;
            l.dynamic_table = -0x20;
            l.class_name = -0x1C;
            l.instance_size = -0x18;
            l.parent = -0x14;
            l.default_handler = -0x10;
            l.new_instance = -0xC;
            l.free_instance = -8;
            l.destroy = -4;
            break;
        case 3:
            l.self_ptr = -0x40;
            l.intf_table = -0x3C;
            l.auto_table = -0x38;
            l.init_table = -0x34;
            l.type_info = -0x30;
            l.field_table = -0x2C;
            l.method_table = -0x28;
            l.dynamic_table = -0x24;
            l.class_name = -0x20;
            l.instance_size = -0x1C;
            l.parent = -0x18;
            l.safe_call = -0x14;
            l.default_handler = -0x10;
            l.new_instance = -0xC;
            l.free_instance = -8;
            l.destroy = -4;
            break;
        case 4:
        case 5:
        case 6:
        case 7:
        case 2005:
        case 2006:
        case 2007:
            l.self_ptr = -0x4C;
            l.intf_table = -0x48;
            l.auto_table = -0x44;
            l.init_table = -0x40;
            l.type_info = -0x3C;
            l.field_table = -0x38;
            l.method_table = -0x34;
            l.dynamic_table = -0x30;
            l.class_name = -0x2C;
            l.instance_size = -0x28;
            l.parent = -0x24;
            l.safe_call = -0x20;
            l.after_construction = -0x1C;
            l.before_destruction = -0x18;
            l.dispatch = -0x14;
            l.default_handler = -0x10;
            l.new_instance = -0xC;
            l.free_instance = -8;
            l.destroy = -4;
            break;
        case 2009:
        case 2010:
        case 2011:
        case 2012:
        case 2013:
        case 2014:
            l.self_ptr = -0x58;
            l.intf_table = -0x54;
            l.auto_table = -0x50;
            l.init_table = -0x4C;
            l.type_info = -0x48;
            l.field_table = -0x44;
            l.method_table = -0x40;
            l.dynamic_table = -0x3C;
            l.class_name = -0x38;
            l.instance_size = -0x34;
            l.parent = -0x30;
            l.safe_call = -0x20;
            l.after_construction = -0x1C;
            l.before_destruction = -0x18;
            l.dispatch = -0x14;
            l.default_handler = -0x10;
            l.new_instance = -0xC;
            l.free_instance = -8;
            l.destroy = -4;
            break;
        default:
            break;
    }
    return l;
}

std::string TargetProfile::kb_file_name() const {
    return "kb" + std::to_string(version_) + ".bin";
}

TargetProfile TargetProfile::of(Vendor vendor, int version, pe::Arch arch) {
    TargetProfile profile;
    profile.vendor_ = vendor;
    profile.version_ = version;
    profile.arch_ = arch;
    profile.pointer_size_ = (arch == pe::Arch::x64) ? 8u : 4u;
    profile.vmt_ = vmt_layout_for(version);
    return profile;
}

Result<TargetProfile> TargetProfile::detect(const pe::PeFile& image,
                                            const std::filesystem::path& sys_kb_dir) {
    if (image.arch() == pe::Arch::unknown) {
        return Result<TargetProfile>::err(ErrorCode::unsupported_format,
                                          "unknown PE architecture");
    }
    if (image.arch() != pe::Arch::x86) {
        // The Phase 0 ladder probes 32-bit `syskb*.bin` dumps against a flattened
        // image that `build_flat_image` effectively treats as 32-bit; running it
        // on a PE32+ image could produce a confident but wrong version. Report
        // the architecture as unsupported instead of guessing.
        return Result<TargetProfile>::err(ErrorCode::unsupported_version,
                                          "x64 images are not supported by detection");
    }
    return detect_embarcadero(image, sys_kb_dir);
}

Result<TargetProfile> detect_embarcadero(const pe::PeFile& image,
                                         const std::filesystem::path& sys_kb_dir) {
    const FlatImage flat = build_flat_image(image);
    if (is_extended_init_tab(flat)) {
        bool kb_probed = false;
        const int version = detect_extended(flat, sys_kb_dir, kb_probed);
        TargetProfile profile =
            TargetProfile::of(Vendor::embarcadero, version, image.arch());
        profile.kb_probed_ = kb_probed;
        return Result<TargetProfile>::ok(profile);
    }
    if (auto version = detect_legacy_version(flat); version.has_value()) {
        return Result<TargetProfile>::ok(
            TargetProfile::of(Vendor::embarcadero, *version, image.arch()));
    }
    return Result<TargetProfile>::err(ErrorCode::unsupported_version,
                                      "could not determine the Delphi version");
}

}  // namespace idr::target
