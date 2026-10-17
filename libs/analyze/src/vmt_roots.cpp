#include "idr/analyze/vmt_roots.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace idr::analyze {
namespace {

using idr::pe::PeFile;

// Byte range accepted as a class-name character. Delphi identifiers are ASCII,
// so anything outside the printable range rules a candidate out.
constexpr uint8_t kFirstPrintable = 0x20;
constexpr uint8_t kLastPrintable = 0x7E;
constexpr uint64_t kMaxRva = 0xFFFFFFFFull;

// Reads the pointer-width little-endian word at `rva`, or std::nullopt when it
// is not mapped (or does not fit in the file).
std::optional<uint64_t> read_pointer(const PeFile& image, uint32_t rva, std::size_t width) {
    auto bytes = image.at_rva(rva, width);
    if (!bytes.has_value()) {
        return std::nullopt;
    }
    uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value |= static_cast<uint64_t>(static_cast<uint8_t>(bytes.value()[i])) << (8 * i);
    }
    return value;
}

// Is a whole pointer-width word readable at `rva`? This is what makes `rva` a
// valid image address holding a word, which is the precondition for treating it
// as a VMT base.
bool readable_word(const PeFile& image, uint32_t rva, std::size_t width) {
    return image.at_rva(rva, width).has_value();
}

// Image RVA one past the last mapped byte, i.e. the wider of SizeOfImage and
// the end of the last section. 0 when the image has no extent at all.
uint32_t image_end_rva(const PeFile& image) {
    uint64_t end = image.size_of_image();
    for (const auto& section : image.sections()) {
        const uint64_t section_end =
            static_cast<uint64_t>(section.virtual_address) + section.virtual_size;
        end = std::max(end, section_end);
    }
    end = std::min(end, kMaxRva);
    return static_cast<uint32_t>(end);
}

// Is `address` an in-image address? Returns its RVA when it is.
std::optional<uint32_t> in_image_rva(const PeFile& image, uint64_t address, uint32_t image_end) {
    const uint64_t base = image.image_base();
    if (address < base) {
        return std::nullopt;
    }
    const uint64_t rva = address - base;
    if (rva >= image_end) {
        return std::nullopt;
    }
    return static_cast<uint32_t>(rva);
}

// Does a Delphi shortstring (length byte, then that many printable bytes) live
// at `rva`? The name is read as one bounds-checked span.
bool has_class_name(const PeFile& image, uint32_t rva) {
    auto length = image.at_rva(rva, 1);
    if (!length.has_value()) {
        return false;
    }
    const auto count = static_cast<std::size_t>(static_cast<uint8_t>(length.value()[0]));
    if (count < 1) {
        return false;  // 0, and only 0, is not a name
    }
    // Length byte plus the name bytes, read as a single span so a name running
    // past the section is rejected rather than partially read.
    auto text = image.at_rva(rva, count + 1);
    if (!text.has_value()) {
        return false;
    }
    for (std::size_t i = 1; i <= count; ++i) {
        const auto c = static_cast<uint8_t>(text.value()[i]);
        if (c < kFirstPrintable || c > kLastPrintable) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::vector<uint64_t> find_vmt_roots(const pe::PeFile& image,
                                     const target::TargetProfile& profile) {
    std::vector<uint64_t> roots;
    const auto& layout = profile.vmt();

    // Only a negative `class_name` offset is meaningful: 0 means the compiler
    // version has no ported layout, and a positive offset would read inside the
    // VMT rather than the name pointer in front of it.
    if (layout.class_name >= 0) {
        return roots;
    }
    const std::size_t width = profile.pointer_size();
    if (width < 1 || width > 8) {
        return roots;
    }
    // Distance from a candidate VMT base back to its class-name pointer. The
    // sign was already validated above, so this is a small positive offset.
    const uint64_t name_back = static_cast<uint64_t>(-profile.vmt().class_name);
    const uint32_t image_end = image_end_rva(image);

    // Sections in table order, so no RVA is visited twice and the results come
    // out in table order (ascending RVA for a well-formed image).
    for (const auto& section : image.sections()) {
        // `rva_to_offset` refuses an RVA at or past `raw_offset + raw_size`, and
        // a whole pointer has to fit, so the readable span is what matters.
        const uint64_t span = std::min<uint64_t>(section.virtual_size, section.raw_size);
        if (span < width) {
            continue;
        }
        uint64_t limit = static_cast<uint64_t>(section.virtual_address) + span;
        limit = std::min<uint64_t>(limit, image_end);

        // Pointer-aligned start within the section.
        uint64_t rva = section.virtual_address;
        if (rva % width != 0) {
            rva += width - (rva % width);
        }
        for (; rva + width <= limit; rva += width) {
            if (!readable_word(image, static_cast<uint32_t>(rva), width)) {
                continue;
            }
            // `name_field` is negative, so the name pointer sits before the
            // VMT; below RVA 0 there is nothing to read.
            if (rva < name_back) {
                continue;
            }
            const auto name_pointer =
                read_pointer(image, static_cast<uint32_t>(rva - name_back), width);
            if (!name_pointer.has_value()) {
                continue;
            }
            const auto name_rva = in_image_rva(image, *name_pointer, image_end);
            if (!name_rva.has_value()) {
                continue;
            }
            if (!has_class_name(image, *name_rva)) {
                continue;
            }
            roots.push_back(image.image_base() + rva);
        }
    }
    return roots;
}

}  // namespace idr::analyze
