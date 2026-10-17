#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>

#include "idr/common/result.hpp"
#include "idr/kb/records.hpp"

namespace idr::kb {

class KnowledgeBase {
public:
    static Result<KnowledgeBase> open(std::filesystem::path path);

    uint32_t format_version() const { return data_.format_version; }
    const KbData& data() const { return data_; }

    // Index of the first procedure whose name matches (case-sensitive), or
    // nullopt when absent.
    std::optional<size_t> find_proc(std::string_view name) const;

    // Index of the first procedure in the given module whose name matches.
    std::optional<size_t> find_proc(uint16_t module_id, std::string_view name) const;

    // Image address where `probe.dump` matches `code` (bytes flagged in
    // `probe.relocs` are wildcards), or nullopt when there is no such address.
    // Phase 0 only matches: relocation values are not applied.
    std::optional<uint32_t> scan_code(Bytes code, uint32_t code_base,
                                      const ProcRecord& probe) const;

private:
    KbData data_;
};

// Serialize `data` in the self-describing v3 format.
Result<void> write_v3(std::filesystem::path path, const KbData& data);

}  // namespace idr::kb
