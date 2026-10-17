#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "idr/common/error.hpp"
#include "idr/common/result.hpp"

namespace idr::pe {

enum class Arch { unknown, x86, x64 };

struct DataDirectory {
    uint32_t rva = 0;
    uint32_t size = 0;
};

struct Section {
    std::string name;
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
};

class PeFile {
public:
    static Result<PeFile> parse(Bytes bytes);

    Arch arch() const { return arch_; }
    bool is_64() const { return arch_ == Arch::x64; }
    uint64_t image_base() const { return image_base_; }
    uint32_t entry_point_rva() const { return entry_point_rva_; }
    // SizeOfImage from the optional header, or 0 when the header omits or
    // truncates the field.
    uint32_t size_of_image() const { return size_of_image_; }
    const std::vector<Section>& sections() const { return sections_; }

    std::optional<uint32_t> rva_to_offset(uint32_t rva) const;
    Result<Bytes> at_rva(uint32_t rva, size_t size) const;

    // Data directory entry by index, or std::nullopt when absent. The PE format
    // defines 16 standard entries; indices beyond that (or entries whose RVA and
    // size are both zero) are reported as absent.
    std::optional<DataDirectory> data_directory(size_t index) const;

private:
    Arch arch_ = Arch::unknown;
    uint64_t image_base_ = 0;
    uint32_t entry_point_rva_ = 0;
    uint32_t size_of_image_ = 0;
    std::vector<Section> sections_;
    std::array<DataDirectory, 16> data_directories_{};
    Bytes buffer_;
};

}  // namespace idr::pe
