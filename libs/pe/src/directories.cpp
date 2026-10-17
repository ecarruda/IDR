#include "idr/pe/directories.hpp"

#include <cstdint>

namespace idr::pe {
namespace {

// Bounds-checked little-endian readers operating on the spans returned by
// PeFile::at_rva.
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

// Reads a NUL-terminated string at `rva`, one byte at a time with full bounds
// checking. Returns truncated if the string runs past the end of the image
// without a terminator.
Result<std::string> read_cstring(const PeFile& pe, uint32_t rva) {
    constexpr size_t kMaxNameLength = 1 << 16;
    std::string s;
    for (size_t i = 0; i < kMaxNameLength; ++i) {
        const uint64_t addr = static_cast<uint64_t>(rva) + i;
        if (addr > 0xFFFFFFFFull) {
            return Result<std::string>::err(ErrorCode::out_of_range, "string RVA overflow");
        }
        auto b = pe.at_rva(static_cast<uint32_t>(addr), 1);
        if (!b.has_value()) {
            return Result<std::string>::err(b.error(), b.message());
        }
        const char c = static_cast<char>(b.value()[0]);
        if (c == '\0') {
            return Result<std::string>::ok(std::move(s));
        }
        s.push_back(c);
    }
    return Result<std::string>::err(ErrorCode::truncated, "unterminated string");
}

// Bounds-checked read of a fixed-size little-endian field at `rva`, computing the
// effective address in 64-bit space to avoid wraparound on malformed RVAs.
Result<uint32_t> read_rva_u32(const PeFile& pe, uint32_t rva) {
    auto b = pe.at_rva(rva, 4);
    if (!b.has_value()) {
        return Result<uint32_t>::err(b.error(), b.message());
    }
    return read_u32(b.value(), 0);
}

constexpr size_t kImportDescriptorSize = 20;
constexpr size_t kExportDirectorySize = 40;

}  // namespace

Result<std::vector<Import>> parse_imports(const PeFile& pe) {
    const auto dd = pe.data_directory(1);  // imports
    if (!dd.has_value() || dd->rva == 0) {
        return Result<std::vector<Import>>::ok({});
    }

    const size_t ptr_size = pe.is_64() ? 8 : 4;
    const uint64_t ordinal_flag = pe.is_64() ? (1ull << 63) : (1ull << 31);
    std::vector<Import> imports;

    // Bound the walks by the declared import-directory size (when nonzero) so a
    // malformed directory cannot walk the whole mapped image. A zero size keeps
    // the legacy at_rva-only bound; an rva of 0 was handled above.
    const auto in_dir = [&dd](uint64_t addr, uint64_t len) {
        if (dd->size == 0) {
            return true;
        }
        const uint64_t lo = dd->rva;
        const uint64_t hi = lo + dd->size;
        return addr >= lo && addr <= hi && len <= hi - addr;
    };

    // Walk the NUL-terminated import descriptor array.
    for (size_t di = 0;; ++di) {
        const uint64_t desc_addr = static_cast<uint64_t>(dd->rva) + di * kImportDescriptorSize;
        if (desc_addr > 0xFFFFFFFFull) {
            return Result<std::vector<Import>>::err(ErrorCode::out_of_range,
                                                    "import descriptor RVA overflow");
        }
        if (!in_dir(desc_addr, kImportDescriptorSize)) {
            return Result<std::vector<Import>>::err(
                ErrorCode::truncated, "import descriptor past directory size");
        }
        auto desc = pe.at_rva(static_cast<uint32_t>(desc_addr), kImportDescriptorSize);
        if (!desc.has_value()) {
            return Result<std::vector<Import>>::err(desc.error(), desc.message());
        }
        auto orig_thunk = read_u32(desc.value(), 0x00);
        auto name_rva = read_u32(desc.value(), 0x0C);
        auto first_thunk = read_u32(desc.value(), 0x10);
        if (!orig_thunk.has_value() || !name_rva.has_value() || !first_thunk.has_value()) {
            return Result<std::vector<Import>>::err(ErrorCode::truncated,
                                                    "truncated import descriptor");
        }

        // An all-zero descriptor terminates the array.
        if (orig_thunk.value() == 0 && name_rva.value() == 0 && first_thunk.value() == 0) {
            break;
        }

        auto module = read_cstring(pe, name_rva.value());
        if (!module.has_value()) {
            return Result<std::vector<Import>>::err(module.error(), module.message());
        }

        // Prefer the ILT (OriginalFirstThunk); fall back to the IAT when a file
        // omits the ILT.
        const uint32_t thunk_rva =
            (orig_thunk.value() != 0) ? orig_thunk.value() : first_thunk.value();
        if (thunk_rva == 0) {
            continue;
        }

        for (size_t i = 0;; ++i) {
            const uint64_t thunk_addr = static_cast<uint64_t>(thunk_rva) + i * ptr_size;
            if (thunk_addr > 0xFFFFFFFFull) {
                return Result<std::vector<Import>>::err(ErrorCode::out_of_range,
                                                        "thunk RVA overflow");
            }
            if (!in_dir(thunk_addr, ptr_size)) {
                return Result<std::vector<Import>>::err(
                    ErrorCode::truncated, "import thunk past directory size");
            }
            auto thunk_bytes = pe.at_rva(static_cast<uint32_t>(thunk_addr), ptr_size);
            if (!thunk_bytes.has_value()) {
                return Result<std::vector<Import>>::err(thunk_bytes.error(),
                                                        thunk_bytes.message());
            }

            uint64_t thunk = 0;
            if (ptr_size == 8) {
                auto t = read_u64(thunk_bytes.value(), 0);
                if (!t.has_value()) {
                    return Result<std::vector<Import>>::err(t.error(), t.message());
                }
                thunk = t.value();
            } else {
                auto t = read_u32(thunk_bytes.value(), 0);
                if (!t.has_value()) {
                    return Result<std::vector<Import>>::err(t.error(), t.message());
                }
                thunk = t.value();
            }

            if (thunk == 0) {
                break;  // end of thunk array
            }

            Import imp;
            imp.module = module.value();
            imp.iat_va = pe.image_base() + static_cast<uint64_t>(first_thunk.value()) +
                         i * ptr_size;

            if (thunk & ordinal_flag) {
                imp.by_ordinal = true;
                imp.ordinal = static_cast<uint16_t>(thunk & 0xFFFFu);
            } else {
                // Thunk is the RVA of an IMAGE_IMPORT_BY_NAME entry; the name
                // follows the 2-byte hint.
                const uint32_t ibn_rva = static_cast<uint32_t>(thunk);
                auto name = read_cstring(pe, ibn_rva + 2);
                if (!name.has_value()) {
                    return Result<std::vector<Import>>::err(name.error(), name.message());
                }
                imp.name = std::move(name.value());
            }

            imports.push_back(std::move(imp));
        }
    }

    return Result<std::vector<Import>>::ok(std::move(imports));
}

Result<std::vector<Export>> parse_exports(const PeFile& pe) {
    const auto dd = pe.data_directory(0);  // exports
    if (!dd.has_value() || dd->rva == 0) {
        return Result<std::vector<Export>>::ok({});
    }

    auto dir = pe.at_rva(dd->rva, kExportDirectorySize);
    if (!dir.has_value()) {
        return Result<std::vector<Export>>::err(dir.error(), dir.message());
    }

    auto base = read_u32(dir.value(), 0x10);
    auto num_functions = read_u32(dir.value(), 0x14);
    auto num_names = read_u32(dir.value(), 0x18);
    auto addr_functions = read_u32(dir.value(), 0x1C);
    auto addr_names = read_u32(dir.value(), 0x20);
    auto addr_ordinals = read_u32(dir.value(), 0x24);
    if (!base.has_value() || !num_functions.has_value() || !num_names.has_value() ||
        !addr_functions.has_value() || !addr_names.has_value() ||
        !addr_ordinals.has_value()) {
        return Result<std::vector<Export>>::err(ErrorCode::truncated,
                                                "truncated export directory");
    }

    std::vector<Export> exports;

    // As with imports, cap the table walks by the declared export-directory size
    // (when nonzero) so a malformed directory cannot walk the whole mapped
    // image. A zero size keeps the legacy at_rva-only bound; an rva of 0 was
    // handled above.
    const auto in_dir = [&dd](uint64_t addr, uint64_t len) {
        if (dd->size == 0) {
            return true;
        }
        const uint64_t lo = dd->rva;
        const uint64_t hi = lo + dd->size;
        return addr >= lo && addr <= hi && len <= hi - addr;
    };

    for (uint32_t i = 0; i < num_names.value(); ++i) {
        const uint64_t name_slot =
            static_cast<uint64_t>(addr_names.value()) + static_cast<uint64_t>(i) * 4u;
        if (name_slot > 0xFFFFFFFFull) {
            return Result<std::vector<Export>>::err(ErrorCode::out_of_range,
                                                    "export name RVA overflow");
        }
        if (!in_dir(name_slot, 4)) {
            return Result<std::vector<Export>>::err(
                ErrorCode::truncated, "export name table past directory size");
        }
        auto name_rva = read_rva_u32(pe, static_cast<uint32_t>(name_slot));
        if (!name_rva.has_value()) {
            return Result<std::vector<Export>>::err(name_rva.error(), name_rva.message());
        }
        auto name = read_cstring(pe, name_rva.value());
        if (!name.has_value()) {
            return Result<std::vector<Export>>::err(name.error(), name.message());
        }

        const uint64_t ord_slot =
            static_cast<uint64_t>(addr_ordinals.value()) + static_cast<uint64_t>(i) * 2u;
        if (ord_slot > 0xFFFFFFFFull) {
            return Result<std::vector<Export>>::err(ErrorCode::out_of_range,
                                                    "export ordinal RVA overflow");
        }
        if (!in_dir(ord_slot, 2)) {
            return Result<std::vector<Export>>::err(
                ErrorCode::truncated, "export ordinal table past directory size");
        }
        auto ord_bytes = pe.at_rva(static_cast<uint32_t>(ord_slot), 2);
        if (!ord_bytes.has_value()) {
            return Result<std::vector<Export>>::err(ord_bytes.error(), ord_bytes.message());
        }
        auto ord_index = read_u16(ord_bytes.value(), 0);
        if (!ord_index.has_value()) {
            return Result<std::vector<Export>>::err(ord_index.error(), ord_index.message());
        }
        if (ord_index.value() >= num_functions.value()) {
            return Result<std::vector<Export>>::err(ErrorCode::out_of_range,
                                                    "export ordinal index out of range");
        }

        const uint64_t func_slot = static_cast<uint64_t>(addr_functions.value()) +
                                    static_cast<uint64_t>(ord_index.value()) * 4u;
        if (func_slot > 0xFFFFFFFFull) {
            return Result<std::vector<Export>>::err(ErrorCode::out_of_range,
                                                    "export function RVA overflow");
        }
        if (!in_dir(func_slot, 4)) {
            return Result<std::vector<Export>>::err(
                ErrorCode::truncated, "export function table past directory size");
        }
        auto func_rva = read_rva_u32(pe, static_cast<uint32_t>(func_slot));
        if (!func_rva.has_value()) {
            return Result<std::vector<Export>>::err(func_rva.error(), func_rva.message());
        }

        Export exp;
        exp.name = std::move(name.value());
        exp.rva = func_rva.value();
        exp.ordinal = static_cast<uint16_t>(base.value() + ord_index.value());
        exports.push_back(std::move(exp));
    }

    return Result<std::vector<Export>>::ok(std::move(exports));
}

}  // namespace idr::pe
