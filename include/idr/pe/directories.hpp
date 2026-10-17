#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "idr/common/result.hpp"
#include "idr/pe/image.hpp"

namespace idr::pe {

struct Import {
    std::string module;
    std::string name;
    bool by_ordinal = false;
    uint16_t ordinal = 0;
    uint64_t iat_va = 0;
};

struct Export {
    std::string name;
    uint32_t rva = 0;
    uint16_t ordinal = 0;
};

// Parses the PE import directory (data directory index 1). Returns an empty
// vector when no import directory is present; returns an error when the
// directory data is malformed or truncated.
Result<std::vector<Import>> parse_imports(const PeFile& pe);

// Parses the PE export directory (data directory index 0). Returns an empty
// vector when no export directory is present; returns an error when the
// directory data is malformed or truncated.
Result<std::vector<Export>> parse_exports(const PeFile& pe);

}  // namespace idr::pe
