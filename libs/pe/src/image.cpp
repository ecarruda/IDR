#include "idr/pe/image.hpp"

#include <algorithm>
#include <cstring>

namespace idr::pe {
namespace {

// Bounds-checked little-endian readers. Each returns ok(value) or
// err(ErrorCode::truncated) if the read would pass the end of the buffer.
Result<uint16_t> read_u16(Bytes b, size_t off) {
    if (off + 2 > b.size()) {
        return Result<uint16_t>::err(ErrorCode::truncated, "read_u16 past end of buffer");
    }
    uint16_t v = 0;
    for (int i = 0; i < 2; ++i) {
        v |= static_cast<uint16_t>(static_cast<uint8_t>(b[off + i])) << (8 * i);
    }
    return Result<uint16_t>::ok(v);
}

Result<uint32_t> read_u32(Bytes b, size_t off) {
    if (off + 4 > b.size()) {
        return Result<uint32_t>::err(ErrorCode::truncated, "read_u32 past end of buffer");
    }
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
        v |= static_cast<uint32_t>(static_cast<uint8_t>(b[off + i])) << (8 * i);
    }
    return Result<uint32_t>::ok(v);
}

Result<uint64_t> read_u64(Bytes b, size_t off) {
    if (off + 8 > b.size()) {
        return Result<uint64_t>::err(ErrorCode::truncated, "read_u64 past end of buffer");
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(static_cast<uint8_t>(b[off + i])) << (8 * i);
    }
    return Result<uint64_t>::ok(v);
}

constexpr uint16_t kDosMagic = 0x5A4D;   // 'MZ'
constexpr uint32_t kNtSignature = 0x00004550;  // 'PE\0\0'
constexpr uint16_t kOptMagic32 = 0x10B;  // PE32
constexpr uint16_t kOptMagic64 = 0x20B;  // PE32+
constexpr size_t kDosHeaderSize = 0x40;
constexpr size_t kFileHeaderSize = 20;
constexpr size_t kSectionHeaderSize = 40;
// Smallest optional header that still contains the fields we read:
// AddressOfEntryPoint (+0x10) and ImageBase (+0x1C PE32 / +0x18 PE32+).
constexpr size_t kMinOptionalHeaderSize = 0x20;

}  // namespace

Result<PeFile> PeFile::parse(Bytes bytes) {
    // DOS header: must be fully present before we can trust e_lfanew.
    if (bytes.size() < kDosHeaderSize) {
        return Result<PeFile>::err(ErrorCode::truncated, "buffer shorter than DOS header");
    }

    auto dos_magic = read_u16(bytes, 0x00);
    if (!dos_magic.has_value()) {
        return Result<PeFile>::err(dos_magic.error(), dos_magic.message());
    }
    if (dos_magic.value() != kDosMagic) {
        return Result<PeFile>::err(ErrorCode::bad_magic, "not an MZ image");
    }

    auto lfanew = read_u32(bytes, 0x3C);
    if (!lfanew.has_value()) {
        return Result<PeFile>::err(lfanew.error(), lfanew.message());
    }

    // NT signature ("PE\0\0"). A DOS header whose e_lfanew does not point at a
    // readable PE signature is a non-PE file, not a truncated PE.
    auto signature = read_u32(bytes, static_cast<size_t>(lfanew.value()));
    if (!signature.has_value() || signature.value() != kNtSignature) {
        return Result<PeFile>::err(ErrorCode::bad_magic, "missing PE signature");
    }

    // File header.
    const size_t coff = static_cast<size_t>(lfanew.value()) + 4;
    auto num_sections = read_u16(bytes, coff + 0x02);
    auto sizeof_opt = read_u16(bytes, coff + 0x10);
    if (!num_sections.has_value() || !sizeof_opt.has_value()) {
        return Result<PeFile>::err(ErrorCode::truncated, "truncated file header");
    }

    const size_t opt_off = coff + kFileHeaderSize;

    // Optional header: select 32 vs 64 by Magic.
    auto opt_magic = read_u16(bytes, opt_off + 0x00);
    if (!opt_magic.has_value()) {
        return Result<PeFile>::err(ErrorCode::truncated, "truncated optional header");
    }

    Arch arch;
    switch (opt_magic.value()) {
        case kOptMagic32:
            arch = Arch::x86;
            break;
        case kOptMagic64:
            arch = Arch::x64;
            break;
        default:
            return Result<PeFile>::err(ErrorCode::unsupported_format,
                                       "unrecognized optional header magic");
    }

    // The declared optional-header size must be large enough to contain the
    // fields read below, or a malformed PE would silently parse with garbage.
    if (sizeof_opt.value() < kMinOptionalHeaderSize) {
        return Result<PeFile>::err(ErrorCode::unsupported_format,
                                   "optional header smaller than minimum");
    }

    // The whole optional header (as declared by SizeOfOptionalHeader) must fit.
    if (opt_off + sizeof_opt.value() > bytes.size()) {
        return Result<PeFile>::err(ErrorCode::truncated, "truncated optional header");
    }

    auto entry_rva = read_u32(bytes, opt_off + 0x10);
    if (!entry_rva.has_value()) {
        return Result<PeFile>::err(entry_rva.error(), entry_rva.message());
    }

    uint64_t image_base = 0;
    if (arch == Arch::x86) {
        auto ib = read_u32(bytes, opt_off + 0x1C);
        if (!ib.has_value()) {
            return Result<PeFile>::err(ib.error(), ib.message());
        }
        image_base = ib.value();
    } else {
        auto ib = read_u64(bytes, opt_off + 0x18);
        if (!ib.has_value()) {
            return Result<PeFile>::err(ib.error(), ib.message());
        }
        image_base = ib.value();
    }

    // SizeOfImage (+0x38). Used by callers that need the mapped image extent.
    uint32_t size_of_image = 0;
    if (sizeof_opt.value() >= 0x38 + 4) {
        auto soi = read_u32(bytes, opt_off + 0x38);
        if (soi.has_value()) {
            size_of_image = soi.value();
        }
    }

    // Data directory array (index 0 = exports, 1 = imports, ...). Only entries
    // that fit within both the declared optional header and NumberOfRvaAndSizes
    // are read; the rest remain zeroed (absent).
    std::array<DataDirectory, 16> data_dirs{};
    const size_t dd_count_off = (arch == Arch::x86) ? 0x5C : 0x6C;
    const size_t dd_off = (arch == Arch::x86) ? 0x60 : 0x70;
    uint32_t num_rva_sizes = 0;
    if (sizeof_opt.value() >= dd_count_off + 4) {
        auto n = read_u32(bytes, opt_off + dd_count_off);
        if (n.has_value()) {
            num_rva_sizes = n.value();
        }
    }
    const size_t dd_avail = sizeof_opt.value() >= dd_off ? (sizeof_opt.value() - dd_off) / 8 : 0;
    const size_t dd_count = std::min<size_t>({dd_avail, num_rva_sizes, data_dirs.size()});
    for (size_t i = 0; i < dd_count; ++i) {
        const size_t o = opt_off + dd_off + i * 8;
        if (o + 8 > bytes.size()) {
            break;
        }
        auto rva = read_u32(bytes, o);
        auto size = read_u32(bytes, o + 4);
        if (!rva.has_value() || !size.has_value()) {
            break;
        }
        data_dirs[i] = DataDirectory{rva.value(), size.value()};
    }

    // Section table.
    const size_t sec_off = opt_off + sizeof_opt.value();
    const size_t max_sections = bytes.size() / kSectionHeaderSize + 1;
    std::vector<Section> sections;
    sections.reserve(std::min<size_t>(num_sections.value(), max_sections));

    for (uint16_t i = 0; i < num_sections.value(); ++i) {
        const size_t s = sec_off + static_cast<size_t>(i) * kSectionHeaderSize;
        if (s + kSectionHeaderSize > bytes.size()) {
            return Result<PeFile>::err(ErrorCode::truncated, "truncated section table");
        }

        Section sec;
        char name[8] = {};
        for (int k = 0; k < 8; ++k) {
            name[k] = static_cast<char>(static_cast<uint8_t>(bytes[s + k]));
        }
        sec.name.assign(name, 8);
        while (!sec.name.empty() && sec.name.back() == '\0') {
            sec.name.pop_back();
        }

        auto vsize = read_u32(bytes, s + 0x08);
        auto vaddr = read_u32(bytes, s + 0x0C);
        auto rsize = read_u32(bytes, s + 0x10);
        auto roff = read_u32(bytes, s + 0x14);
        auto chars = read_u32(bytes, s + 0x24);
        if (!vsize.has_value() || !vaddr.has_value() || !rsize.has_value() ||
            !roff.has_value() || !chars.has_value()) {
            return Result<PeFile>::err(ErrorCode::truncated, "truncated section header");
        }

        sec.virtual_size = vsize.value();
        sec.virtual_address = vaddr.value();
        sec.raw_size = rsize.value();
        sec.raw_offset = roff.value();
        sec.characteristics = chars.value();
        sections.push_back(std::move(sec));
    }

    PeFile pe;
    pe.arch_ = arch;
    pe.image_base_ = image_base;
    pe.entry_point_rva_ = entry_rva.value();
    pe.size_of_image_ = size_of_image;
    pe.sections_ = std::move(sections);
    pe.data_directories_ = data_dirs;
    pe.buffer_ = bytes;
    return Result<PeFile>::ok(std::move(pe));
}

std::optional<uint32_t> PeFile::rva_to_offset(uint32_t rva) const {
    for (const auto& sec : sections_) {
        const uint64_t begin = sec.virtual_address;
        const uint64_t end = begin + static_cast<uint64_t>(sec.virtual_size);
        if (rva >= begin && rva < end) {
            const uint64_t delta = rva - begin;
            if (delta < sec.raw_size) {
                return static_cast<uint32_t>(static_cast<uint64_t>(sec.raw_offset) + delta);
            }
            return std::nullopt;
        }
    }
    return std::nullopt;
}

Result<Bytes> PeFile::at_rva(uint32_t rva, size_t size) const {
    const auto offset = rva_to_offset(rva);
    if (!offset.has_value()) {
        return Result<Bytes>::err(ErrorCode::out_of_range, "RVA not mapped to a section");
    }
    if (static_cast<uint64_t>(offset.value()) + size > buffer_.size()) {
        return Result<Bytes>::err(ErrorCode::truncated, "RVA slice extends past end of file");
    }
    return Result<Bytes>::ok(buffer_.subspan(offset.value(), size));
}

std::optional<DataDirectory> PeFile::data_directory(size_t index) const {
    if (index >= data_directories_.size()) {
        return std::nullopt;
    }
    const auto& dd = data_directories_[index];
    if (dd.rva == 0 && dd.size == 0) {
        return std::nullopt;
    }
    return dd;
}

}  // namespace idr::pe
