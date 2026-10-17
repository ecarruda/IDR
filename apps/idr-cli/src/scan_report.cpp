#include "scan_report.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <vector>

#include "idr/analyze/vmt_roots.hpp"
#include "idr/disasm/disassembler.hpp"
#include "idr/kb/knowledge_base.hpp"
#include "idr/pe/directories.hpp"
#include "idr/pe/image.hpp"
#include "idr/target/target_profile.hpp"

namespace {

// Reads the whole file into memory. Returns false when it cannot be opened or
// read; never throws.
bool read_file(const std::filesystem::path& path, std::vector<std::byte>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff end = in.tellg();
    if (end < 0) {
        return false;
    }
    in.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(end));
    if (end > 0) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(end));
        if (!in) {
            return false;
        }
    }
    return true;
}

std::string arch_name(idr::pe::Arch arch) {
    switch (arch) {
        case idr::pe::Arch::x86:
            return "x86";
        case idr::pe::Arch::x64:
            return "x64";
        default:
            return "unknown";
    }
}

std::string vendor_name(idr::target::Vendor vendor) {
    switch (vendor) {
        case idr::target::Vendor::embarcadero:
            return "embarcadero";
        case idr::target::Vendor::fpc:
            return "fpc";
        default:
            return "unknown";
    }
}

// Appends up to `max_instructions` disassembled instructions at the entry point.
void append_entry_code(std::ostringstream& out, const idr::pe::PeFile& pe) {
    if (pe.arch() == idr::pe::Arch::unknown) {
        return;
    }
    auto code = pe.at_rva(pe.entry_point_rva(), 32);
    if (!code.has_value()) {
        return;
    }
    auto dis = idr::disasm::make_zydis(pe.arch());
    if (!dis) {
        return;
    }
    const idr::Bytes window = code.value();
    const uint64_t base = pe.image_base() + pe.entry_point_rva();
    size_t offset = 0;
    int shown = 0;
    while (offset < window.size() && shown < 4) {
        auto ins = dis->decode(base + offset, window.subspan(offset));
        if (!ins.has_value() || ins.value().length == 0) {
            break;
        }
        out << (shown == 0 ? "entry code: " : "            ") << ins.value().text << "\n";
        offset += ins.value().length;
        ++shown;
    }
}

}  // namespace

std::string scan_report(const std::filesystem::path& exe,
                        const std::filesystem::path& kb_dir,
                        const std::filesystem::path& sys_kb_dir) {
    std::ostringstream out;

    std::vector<std::byte> bytes;
    if (!read_file(exe, bytes)) {
        out << "not a PE: cannot read " << exe.string() << "\n";
        return out.str();
    }

    auto parsed = idr::pe::PeFile::parse(bytes);
    if (!parsed.has_value()) {
        out << "not a PE: " << exe.string() << "\n";
        return out.str();
    }
    const idr::pe::PeFile& pe = parsed.value();

    out << "file: " << exe.string() << "\n";
    out << "arch: " << arch_name(pe.arch()) << "\n";
    out << "sections: " << pe.sections().size() << "\n";

    size_t imports = 0;
    if (auto r = idr::pe::parse_imports(pe); r.has_value()) {
        imports = r.value().size();
    }
    out << "imports: " << imports << "\n";

    size_t exports = 0;
    if (auto r = idr::pe::parse_exports(pe); r.has_value()) {
        exports = r.value().size();
    }
    out << "exports: " << exports << "\n";

    out << "entry point: 0x" << std::hex << pe.entry_point_rva() << std::dec << "\n";

    // Detect the compiler target. On failure the report says "unknown" and the
    // VMT scan runs with a profile that has no layout criterion (so: no roots).
    idr::target::TargetProfile profile;
    auto detected = idr::target::TargetProfile::detect(pe, sys_kb_dir);
    if (detected.has_value()) {
        profile = detected.value();
        out << "delphi version: " << profile.version() << "\n";
        out << "vendor: " << vendor_name(profile.vendor()) << "\n";
        const std::filesystem::path kb_path = kb_dir / profile.kb_file_name();
        const bool loaded = idr::kb::KnowledgeBase::open(kb_path).has_value();
        out << "kb: " << profile.kb_file_name() << (loaded ? " (loaded)" : " (missing)")
            << "\n";
    } else {
        profile = idr::target::TargetProfile::of(idr::target::Vendor::unknown, 0, pe.arch());
        out << "delphi version: unknown\n";
        out << "vendor: unknown\n";
        out << "kb: none\n";
    }

    const auto roots = idr::analyze::find_vmt_roots(pe, profile);
    out << "vmt roots: " << roots.size() << "\n";

    append_entry_code(out, pe);

    return out.str();
}
