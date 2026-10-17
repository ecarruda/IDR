#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "idr/pe/image.hpp"

namespace idr::pe::test_detail {

inline void put_u16(std::vector<std::byte>& v, size_t off, uint16_t x) {
    v[off] = static_cast<std::byte>(x & 0xFFu);
    v[off + 1] = static_cast<std::byte>((x >> 8) & 0xFFu);
}

inline void put_u32(std::vector<std::byte>& v, size_t off, uint32_t x) {
    for (int i = 0; i < 4; ++i) {
        v[off + i] = static_cast<std::byte>((x >> (8 * i)) & 0xFFu);
    }
}

inline void put_u64(std::vector<std::byte>& v, size_t off, uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        v[off + i] = static_cast<std::byte>((x >> (8 * i)) & 0xFFull);
    }
}

inline uint16_t get_u16(const std::vector<std::byte>& v, size_t off) {
    uint16_t x = 0;
    for (int i = 0; i < 2; ++i) {
        x |= static_cast<uint16_t>(static_cast<uint8_t>(v[off + i])) << (8 * i);
    }
    return x;
}

inline uint32_t get_u32(const std::vector<std::byte>& v, size_t off) {
    uint32_t x = 0;
    for (int i = 0; i < 4; ++i) {
        x |= static_cast<uint32_t>(static_cast<uint8_t>(v[off + i])) << (8 * i);
    }
    return x;
}

inline uint64_t get_u64(const std::vector<std::byte>& v, size_t off) {
    uint64_t x = 0;
    for (int i = 0; i < 8; ++i) {
        x |= static_cast<uint64_t>(static_cast<uint8_t>(v[off + i])) << (8 * i);
    }
    return x;
}

inline uint32_t align_up(uint32_t value, uint32_t alignment) {
    if (alignment == 0) {
        return value;
    }
    const uint32_t remainder = value % alignment;
    return remainder == 0 ? value : value + (alignment - remainder);
}

// Layout constants shared by make_minimal_pe and the directory builders.
constexpr uint32_t kTextVa = 0x1000;
constexpr uint32_t kTextRawOffset = 0x200;
constexpr uint32_t kDataVa = 0x2000;  // first RVA after `.text`
constexpr size_t kOptionalHeaderOffset = 0x58;  // DOS(0x40) + NT sig(4) + file header(20)

// File offset within the single `.text` section for a given RVA.
inline size_t text_file_offset(uint32_t rva) {
    return static_cast<size_t>(kTextRawOffset) + (rva - kTextVa);
}

inline bool pe_is_64(const std::vector<std::byte>& pe) {
    return get_u16(pe, kOptionalHeaderOffset) == 0x20B;
}

inline uint64_t pe_image_base(const std::vector<std::byte>& pe) {
    if (pe_is_64(pe)) {
        return get_u64(pe, kOptionalHeaderOffset + 0x18);
    }
    return get_u32(pe, kOptionalHeaderOffset + 0x1C);
}

inline void write_cstring(std::vector<std::byte>& pe, uint32_t rva, const std::string& s) {
    const size_t fo = text_file_offset(rva);
    for (size_t i = 0; i < s.size(); ++i) {
        pe[fo + i] = static_cast<std::byte>(s[i]);
    }
    pe[fo + s.size()] = std::byte{0};
}

inline void write_thunk(std::vector<std::byte>& pe, uint32_t rva, uint32_t value, size_t ptr) {
    const size_t fo = text_file_offset(rva);
    if (ptr == 8) {
        put_u64(pe, fo, value);
    } else {
        put_u32(pe, fo, value);
    }
}

inline void set_data_directory(std::vector<std::byte>& pe, size_t index, uint32_t rva,
                               uint32_t size) {
    const size_t dd_off = kOptionalHeaderOffset + (pe_is_64(pe) ? 0x70 : 0x60);
    put_u32(pe, dd_off + index * 8 + 0, rva);
    put_u32(pe, dd_off + index * 8 + 4, size);
}

}  // namespace idr::pe::test_detail

// Builds a syntactically valid PE image with a single `.text` section and zeroed
// data directories. Produces either PE32 or PE32+ depending on `arch`.
inline std::vector<std::byte> make_minimal_pe(idr::pe::Arch arch, uint64_t image_base = 0x400000) {
    using namespace idr::pe::test_detail;

    const bool is64 = (arch == idr::pe::Arch::x64);
    const size_t opt_size = is64 ? 240u : 224u;
    const size_t nt_off = 0x40;        // e_lfanew -> NT headers
    const size_t file_off = nt_off + 4;   // after "PE\0\0"
    const size_t opt_off = file_off + 20; // after IMAGE_FILE_HEADER
    const size_t sec_off = opt_off + opt_size;

    const uint32_t file_align = 0x200;
    const uint32_t section_align = 0x1000;
    const uint32_t headers_size = file_align;
    const uint32_t text_raw_offset = 0x200;
    const uint32_t text_raw_size = 0x200;
    const uint32_t text_va = 0x1000;
    const uint32_t text_vsize = 0x1000;

    std::vector<std::byte> b(headers_size + text_raw_size, std::byte{0});

    // DOS header: 'MZ' and e_lfanew.
    b[0] = std::byte{'M'};
    b[1] = std::byte{'Z'};
    put_u32(b, 0x3C, static_cast<uint32_t>(nt_off));

    // NT signature "PE\0\0".
    b[file_off - 4] = std::byte{'P'};
    b[file_off - 3] = std::byte{'E'};

    // IMAGE_FILE_HEADER.
    put_u16(b, file_off + 0x00, is64 ? 0x8664 : 0x014C);  // Machine
    put_u16(b, file_off + 0x02, 1);                        // NumberOfSections
    put_u16(b, file_off + 0x10, static_cast<uint16_t>(opt_size));  // SizeOfOptionalHeader
    put_u16(b, file_off + 0x12, 0x0022);                   // Characteristics

    // Optional header.
    put_u16(b, opt_off + 0x00, is64 ? 0x20B : 0x10B);      // Magic
    put_u32(b, opt_off + 0x10, text_va);                   // AddressOfEntryPoint
    if (is64) {
        put_u64(b, opt_off + 0x18, image_base);            // ImageBase
    } else {
        put_u32(b, opt_off + 0x1C, static_cast<uint32_t>(image_base));
    }
    put_u32(b, opt_off + 0x20, section_align);             // SectionAlignment
    put_u32(b, opt_off + 0x24, file_align);                // FileAlignment
    put_u32(b, opt_off + 0x38, 0x2000);                    // SizeOfImage
    put_u32(b, opt_off + 0x3C, headers_size);              // SizeOfHeaders
    if (is64) {
        put_u32(b, opt_off + 0x6C, 16);                    // NumberOfRvaAndSizes
    } else {
        put_u32(b, opt_off + 0x5C, 16);
    }

    // Single `.text` section header.
    const char name[] = ".text";
    std::memcpy(b.data() + sec_off, name, sizeof(name) - 1);
    put_u32(b, sec_off + 0x08, text_vsize);      // VirtualSize
    put_u32(b, sec_off + 0x0C, text_va);         // VirtualAddress
    put_u32(b, sec_off + 0x10, text_raw_size);   // SizeOfRawData
    put_u32(b, sec_off + 0x14, text_raw_offset); // PointerToRawData
    put_u32(b, sec_off + 0x24, 0x60000020);      // Characteristics (code/exec/read)

    return b;
}

// Appends a `.data` section carrying `data` verbatim to an image produced by
// make_minimal_pe and returns the enlarged image. `.text` keeps its original
// layout; `.data` takes the next section-aligned RVA (kDataVa) and the next
// file-aligned raw offset, and SizeOfImage is widened to cover it. The default
// image base matches make_minimal_pe's, so planted pointers can be written as
// `image_base + rva`.
//
// `virtual_size` overrides the section's VirtualSize (0 = the payload size),
// which leaves the tail of the raw payload present in the file but outside the
// mapped section.
inline std::vector<std::byte> make_pe_with_data(idr::pe::Arch arch,
                                                const std::vector<std::byte>& data,
                                                uint64_t image_base = 0x400000,
                                                uint32_t virtual_size = 0) {
    using namespace idr::pe::test_detail;

    std::vector<std::byte> pe = make_minimal_pe(arch, image_base);
    const bool is64 = pe_is_64(pe);
    const size_t opt_off = kOptionalHeaderOffset;
    const size_t sec_off = opt_off + (is64 ? 240u : 224u);

    const uint32_t data_raw_offset = align_up(static_cast<uint32_t>(pe.size()), 0x200);
    const uint32_t data_raw_size = align_up(static_cast<uint32_t>(data.size()), 0x200);
    const uint32_t data_virtual_size = virtual_size != 0 ? virtual_size
                                                         : static_cast<uint32_t>(data.size());

    // Grow the file to hold the raw section and copy the payload in.
    pe.resize(static_cast<size_t>(data_raw_offset) + data_raw_size, std::byte{0});
    std::copy(data.begin(), data.end(), pe.begin() + data_raw_offset);

    // Describe `.data` in the second section header slot (the header area is
    // large enough for the extra 40 bytes in both PE32 and PE32+).
    const size_t s1 = sec_off + 40;
    std::memcpy(pe.data() + s1, ".data", 5);
    put_u32(pe, s1 + 0x08, data_virtual_size);  // VirtualSize
    put_u32(pe, s1 + 0x0C, kDataVa);            // VirtualAddress
    put_u32(pe, s1 + 0x10, data_raw_size);      // SizeOfRawData
    put_u32(pe, s1 + 0x14, data_raw_offset);    // PointerToRawData
    put_u32(pe, s1 + 0x24, 0xC0000040);         // initialized data, read, write

    // NumberOfSections and SizeOfImage.
    put_u16(pe, 0x40 + 4 + 0x02, 2);
    put_u32(pe, opt_off + 0x38, align_up(kDataVa + data_virtual_size, 0x1000));

    return pe;
}

// Overrides the SizeOfOptionalHeader field (file-header offset +0x10) of an
// image produced by make_minimal_pe, for tests exercising malformed sizes.
inline void set_size_of_optional_header(std::vector<std::byte>& pe, uint16_t size) {
    using namespace idr::pe::test_detail;
    // DOS header (0x40) + NT signature (4) + file-header offset 0x10.
    put_u16(pe, 0x40 + 4 + 0x10, size);
}

// Appends an import descriptor for `module` importing `names` (by name) into the
// single `.text` section and points data directory index 1 at it. The image must
// have been produced by make_minimal_pe. The `.text` section only maps 0x200
// bytes of raw data, so total imported content must stay within that budget.
inline void add_import(std::vector<std::byte>& pe, const std::string& module,
                       std::vector<std::string> names) {
    using namespace idr::pe::test_detail;
    const bool is64 = pe_is_64(pe);
    const size_t ptr = is64 ? 8 : 4;

    uint32_t off = 0;
    const uint32_t desc_rva = kTextVa + off; off += 20;  // one descriptor
    off += 20;                                            // null terminator
    const uint32_t ilt_rva = kTextVa + off;
    off += static_cast<uint32_t>(ptr * (names.size() + 1));
    const uint32_t iat_rva = kTextVa + off;
    off += static_cast<uint32_t>(ptr * (names.size() + 1));
    const uint32_t module_rva = kTextVa + off;
    off += static_cast<uint32_t>(module.size() + 1);

    std::vector<uint32_t> ibn_rvas;
    ibn_rvas.reserve(names.size());
    for (const auto& n : names) {
        ibn_rvas.push_back(kTextVa + off);
        off += 2 + static_cast<uint32_t>(n.size() + 1);  // hint + name + null
    }

    put_u32(pe, text_file_offset(desc_rva) + 0x00, ilt_rva);    // OriginalFirstThunk
    put_u32(pe, text_file_offset(desc_rva) + 0x04, 0);          // TimeDateStamp
    put_u32(pe, text_file_offset(desc_rva) + 0x08, 0);          // ForwarderChain
    put_u32(pe, text_file_offset(desc_rva) + 0x0C, module_rva); // Name
    put_u32(pe, text_file_offset(desc_rva) + 0x10, iat_rva);    // FirstThunk

    write_cstring(pe, module_rva, module);
    for (size_t i = 0; i < names.size(); ++i) {
        put_u16(pe, text_file_offset(ibn_rvas[i]), 0);  // Hint
        write_cstring(pe, ibn_rvas[i] + 2, names[i]);
        write_thunk(pe, ilt_rva + static_cast<uint32_t>(i * ptr), ibn_rvas[i], ptr);
        write_thunk(pe, iat_rva + static_cast<uint32_t>(i * ptr), ibn_rvas[i], ptr);
    }

    set_data_directory(pe, 1, desc_rva, off);
}

// Appends an import descriptor for `module` importing by ordinal. Each thunk has
// its ordinal flag bit set (no import-by-name table is emitted).
inline void add_import_ordinal(std::vector<std::byte>& pe, const std::string& module,
                               std::vector<uint16_t> ordinals) {
    using namespace idr::pe::test_detail;
    const bool is64 = pe_is_64(pe);
    const size_t ptr = is64 ? 8 : 4;

    uint32_t off = 0;
    const uint32_t desc_rva = kTextVa + off; off += 20;
    off += 20;  // null terminator
    const uint32_t ilt_rva = kTextVa + off;
    off += static_cast<uint32_t>(ptr * (ordinals.size() + 1));
    const uint32_t iat_rva = kTextVa + off;
    off += static_cast<uint32_t>(ptr * (ordinals.size() + 1));
    const uint32_t module_rva = kTextVa + off;
    off += static_cast<uint32_t>(module.size() + 1);

    put_u32(pe, text_file_offset(desc_rva) + 0x00, ilt_rva);
    put_u32(pe, text_file_offset(desc_rva) + 0x04, 0);
    put_u32(pe, text_file_offset(desc_rva) + 0x08, 0);
    put_u32(pe, text_file_offset(desc_rva) + 0x0C, module_rva);
    put_u32(pe, text_file_offset(desc_rva) + 0x10, iat_rva);

    write_cstring(pe, module_rva, module);
    const uint64_t flag = is64 ? (1ull << 63) : (1ull << 31);
    for (size_t i = 0; i < ordinals.size(); ++i) {
        const uint64_t thunk = flag | ordinals[i];
        if (is64) {
            put_u64(pe, text_file_offset(ilt_rva + static_cast<uint32_t>(i * ptr)), thunk);
            put_u64(pe, text_file_offset(iat_rva + static_cast<uint32_t>(i * ptr)), thunk);
        } else {
            put_u32(pe, text_file_offset(ilt_rva + static_cast<uint32_t>(i * ptr)),
                    static_cast<uint32_t>(thunk));
            put_u32(pe, text_file_offset(iat_rva + static_cast<uint32_t>(i * ptr)),
                    static_cast<uint32_t>(thunk));
        }
    }

    set_data_directory(pe, 1, desc_rva, off);
}

// Appends an export directory exporting `names` (function RVAs are synthesized)
// and points data directory index 0 at it.
inline void add_export(std::vector<std::byte>& pe, std::vector<std::string> names) {
    using namespace idr::pe::test_detail;
    const uint32_t base = 1;

    uint32_t off = 0;
    const uint32_t dir_rva = kTextVa + off; off += 40;  // IMAGE_EXPORT_DIRECTORY
    const uint32_t funcs_rva = kTextVa + off;
    off += static_cast<uint32_t>(names.size() * 4);
    const uint32_t names_rva = kTextVa + off;
    off += static_cast<uint32_t>(names.size() * 4);
    const uint32_t ords_rva = kTextVa + off;
    off += static_cast<uint32_t>(names.size() * 2);

    std::vector<uint32_t> name_rvas;
    name_rvas.reserve(names.size());
    for (const auto& n : names) {
        name_rvas.push_back(kTextVa + off);
        off += static_cast<uint32_t>(n.size() + 1);
    }

    put_u32(pe, text_file_offset(dir_rva) + 0x10, base);
    put_u32(pe, text_file_offset(dir_rva) + 0x14, static_cast<uint32_t>(names.size()));
    put_u32(pe, text_file_offset(dir_rva) + 0x18, static_cast<uint32_t>(names.size()));
    put_u32(pe, text_file_offset(dir_rva) + 0x1C, funcs_rva);
    put_u32(pe, text_file_offset(dir_rva) + 0x20, names_rva);
    put_u32(pe, text_file_offset(dir_rva) + 0x24, ords_rva);

    for (size_t i = 0; i < names.size(); ++i) {
        put_u32(pe, text_file_offset(funcs_rva + static_cast<uint32_t>(i * 4)),
                kTextVa + 0x700 + static_cast<uint32_t>(i * 4));
        put_u32(pe, text_file_offset(names_rva + static_cast<uint32_t>(i * 4)), name_rvas[i]);
        put_u16(pe, text_file_offset(ords_rva + static_cast<uint32_t>(i * 2)),
                static_cast<uint16_t>(i));
        write_cstring(pe, name_rvas[i], names[i]);
    }

    set_data_directory(pe, 0, dir_rva, off);
}
