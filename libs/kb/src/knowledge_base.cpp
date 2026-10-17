#include "idr/kb/knowledge_base.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace idr::kb {

// Implemented in v3_io.cpp and v2_read.cpp respectively.
Result<KbData> read_v3(std::span<const std::byte> buf);
Result<KbData> read_v2(std::span<const std::byte> buf);

namespace {

constexpr const char* kMagicV3 = "IDRKB";                // 5 bytes
constexpr const char* kSignatureV2 = "IDR Knowledge Base File";  // 23 chars + NUL
constexpr const char* kSignatureV1 = "IDD Knowledge Base File";

bool starts_with(std::span<const std::byte> buf, const char* s, size_t n) {
    if (buf.size() < n) return false;
    for (size_t i = 0; i < n; ++i) {
        if (static_cast<char>(buf[i]) != s[i]) return false;
    }
    return true;
}

}  // namespace

Result<KnowledgeBase> KnowledgeBase::open(std::filesystem::path path) {
    // No exception may cross this boundary. The file-sized buffer and the
    // parser's internal vectors can throw bad_alloc/length_error on a hostile
    // (e.g. absurdly large) input; translate those into an ErrorCode.
    try {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in) {
            return Result<KnowledgeBase>::err(ErrorCode::io_error, "cannot open file");
        }
        const std::streamsize size = in.tellg();
        if (size <= 0) {
            return Result<KnowledgeBase>::err(ErrorCode::truncated, "empty file");
        }
        in.seekg(0, std::ios::beg);
        std::vector<std::byte> buf(static_cast<size_t>(size));
        in.read(reinterpret_cast<char*>(buf.data()), size);
        if (!in) {
            return Result<KnowledgeBase>::err(ErrorCode::io_error, "read failed");
        }

        std::span<const std::byte> span(buf);

        Result<KbData> parsed = [&]() -> Result<KbData> {
            if (starts_with(span, kMagicV3, 5)) {
                return read_v3(span);
            }
            if (starts_with(span, kSignatureV2, 23)) {
                return read_v2(span);
            }
            if (starts_with(span, kSignatureV1, 23)) {
                // Legacy v1 ("IDD") is recognized but not supported.
                return Result<KbData>::err(ErrorCode::unsupported_version,
                                           "v1 KB files are not supported");
            }
            return Result<KbData>::err(ErrorCode::bad_magic, "unknown KB magic");
        }();

        if (!parsed.has_value()) {
            return Result<KnowledgeBase>::err(parsed.error(), parsed.message());
        }

        KnowledgeBase kb;
        kb.data_ = std::move(parsed.value());
        return Result<KnowledgeBase>::ok(std::move(kb));
    } catch (const std::bad_alloc&) {
        return Result<KnowledgeBase>::err(ErrorCode::io_error,
                                          "out of memory reading KB file");
    } catch (const std::length_error&) {
        return Result<KnowledgeBase>::err(ErrorCode::io_error,
                                          "KB file too large to load");
    }
}

std::optional<size_t> KnowledgeBase::find_proc(std::string_view name) const {
    for (size_t i = 0; i < data_.procs.size(); ++i) {
        if (data_.procs[i].name == name) {
            return i;
        }
    }
    return std::nullopt;
}

std::optional<size_t> KnowledgeBase::find_proc(uint16_t module_id,
                                               std::string_view name) const {
    for (size_t i = 0; i < data_.procs.size(); ++i) {
        if (data_.procs[i].module_id == module_id && data_.procs[i].name == name) {
            return i;
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> KnowledgeBase::scan_code(Bytes code, uint32_t code_base,
                                                 const ProcRecord& probe) const {
    // Ported from MKnowledgeBase::ScanCode (KnowledgeBase.cpp:1682). The legacy
    // walk compares the dump at every candidate offset, skipping the dump bytes
    // marked in Relocs; Phase 0 performs the match only and applies no
    // relocation arithmetic.
    const size_t dump_size = probe.dump.size();
    // An empty fingerprint matches everywhere, and one longer than the code
    // cannot match at all; both are rejected before any byte is read.
    if (dump_size == 0 || dump_size > code.size()) {
        return std::nullopt;
    }

    // A dump byte is a wildcard when its relocs entry is the 0xFF marker. An
    // entry beyond the end of relocs leaves the byte meaningful.
    const auto is_wildcard = [&probe](size_t i) {
        return i < probe.relocs.size() && probe.relocs[i] == std::byte{0xFF};
    };

    for (size_t offset = 0; offset + dump_size <= code.size(); ++offset) {
        bool matched = true;
        for (size_t i = 0; i < dump_size; ++i) {
            if (is_wildcard(i)) continue;
            if (probe.dump[i] != code[offset + i]) {
                matched = false;
                break;
            }
        }
        if (matched) {
            return code_base + static_cast<uint32_t>(offset);
        }
    }
    return std::nullopt;
}

}  // namespace idr::kb
