#pragma once

#include <filesystem>
#include <string>

#include "idr/common/result.hpp"

// Knowledge-base tooling shared by the `kbbuilder` CLI and its tests.

// Formats a fixed, line-per-field report describing the knowledge base at `kb`
// (either a v2 or a v3 file). The report always ends with a newline and never
// throws. When the file cannot be opened or is not a recognized KB, the report
// is a single diagnostic line beginning with "error: ".
std::string kb_info(const std::filesystem::path& kb);

// Reads the knowledge base at `in` (v2 or v3) and writes it to `out` in the v3
// format. Returns the underlying error when the input cannot be read or the
// output cannot be written.
idr::Result<void> kb_convert(const std::filesystem::path& in,
                             const std::filesystem::path& out);

// Round-trips `in` through the v3 serializer into a temporary file, re-opens
// it, and asserts content equality with the original (see `kb_equal`). Returns
// an error when any step fails; on a content mismatch the error is
// `ErrorCode::unsupported_format` with message "content differs". The
// temporary file is removed on every normal exit path.
idr::Result<void> kb_verify(const std::filesystem::path& in);
