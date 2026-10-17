#pragma once

#include <cstddef>
#include <span>

namespace idr {

enum class ErrorCode {
    ok,
    truncated,
    bad_magic,
    unsupported_format,
    unsupported_version,
    out_of_range,
    io_error,
    not_found,
};

using Bytes = std::span<const std::byte>;

}  // namespace idr
