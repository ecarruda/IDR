#include "kb_tool.hpp"

#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>

#include "idr/common/error.hpp"
#include "idr/kb/knowledge_base.hpp"
#include "idr/kb/records.hpp"

namespace {

std::string arch_name(idr::kb::Arch arch) {
    switch (arch) {
        case idr::kb::Arch::x86:
            return "x86";
        case idr::kb::Arch::x64:
            return "x64";
        default:
            return "unknown";
    }
}

}  // namespace

std::string kb_info(const std::filesystem::path& kb) {
    auto opened = idr::kb::KnowledgeBase::open(kb);
    if (!opened.has_value()) {
        return "error: " + opened.message() + "\n";
    }

    const idr::kb::KbData& d = opened.value().data();
    std::ostringstream out;
    out << "format version: " << d.format_version << "\n";
    out << "arch: " << arch_name(d.arch) << "\n";
    out << "vendor: " << d.vendor << "\n";
    out << "compiler version: " << d.compiler_version << "\n";
    out << "compiler id: " << d.compiler_id << "\n";
    out << "pointer size: " << static_cast<int>(d.pointer_size) << "\n";
    out << "modules: " << d.modules.size() << "\n";
    out << "consts: " << d.consts.size() << "\n";
    out << "types: " << d.types.size() << "\n";
    out << "vars: " << d.vars.size() << "\n";
    out << "resstrings: " << d.resstrings.size() << "\n";
    out << "procs: " << d.procs.size() << "\n";
    return out.str();
}

idr::Result<void> kb_convert(const std::filesystem::path& in,
                             const std::filesystem::path& out) {
    auto opened = idr::kb::KnowledgeBase::open(in);
    if (!opened.has_value()) {
        return idr::Result<void>::err(opened.error(), opened.message());
    }
    return idr::kb::write_v3(out, opened.value().data());
}

idr::Result<void> kb_verify(const std::filesystem::path& in) {
    auto opened = idr::kb::KnowledgeBase::open(in);
    if (!opened.has_value()) {
        return idr::Result<void>::err(opened.error(), opened.message());
    }

    std::error_code ec;
    const std::filesystem::path temp_dir = std::filesystem::temp_directory_path(ec);
    if (ec) {
        return idr::Result<void>::err(idr::ErrorCode::io_error,
                                      "no temporary directory");
    }
    const std::filesystem::path tmp =
        temp_dir / (in.filename().string() + ".verify.v3.bin");

    auto written = idr::kb::write_v3(tmp, opened.value().data());
    if (!written.has_value()) {
        std::filesystem::remove(tmp, ec);
        return written;
    }

    auto reopened = idr::kb::KnowledgeBase::open(tmp);
    std::filesystem::remove(tmp, ec);
    if (!reopened.has_value()) {
        return idr::Result<void>::err(reopened.error(), reopened.message());
    }

    if (!idr::kb::kb_equal(opened.value().data(), reopened.value().data())) {
        return idr::Result<void>::err(idr::ErrorCode::unsupported_format,
                                      "content differs");
    }
    return idr::Result<void>::ok();
}
