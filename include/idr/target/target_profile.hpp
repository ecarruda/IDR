#pragma once

#include <cstddef>
#include <filesystem>
#include <string>

#include "idr/common/result.hpp"
#include "idr/pe/image.hpp"

namespace idr::target {

// Compiler family a TargetProfile describes. FPC is reserved for Phase 2; only
// `embarcadero` is produced by the Phase 0 detection code.
enum class Vendor { unknown, embarcadero, fpc };

// Offsets of the fields that precede a Delphi class's VMT (the pointer stored
// at a class reference). Every offset is negative and relative to the VMT base.
// Values are ported verbatim from SetVmtConsts (Main.cpp:2004). Fields that do
// not exist for a version are 0.
struct VmtLayout {
    int self_ptr = 0;
    int intf_table = 0;
    int auto_table = 0;
    int init_table = 0;
    int type_info = 0;
    int field_table = 0;
    int method_table = 0;
    int dynamic_table = 0;
    int class_name = 0;
    int instance_size = 0;
    int parent = 0;
    int safe_call = 0;
    int after_construction = 0;
    int before_destruction = 0;
    int dispatch = 0;
    int default_handler = 0;
    int new_instance = 0;
    int free_instance = 0;
    int destroy = 0;
};

// VMT field offsets for a Delphi compiler version (2..7 and 2005..2014).
// Versions without a known layout yield an all-zero layout.
VmtLayout vmt_layout_for(int version);

// A detected compiler target: architecture, vendor, compiler version, pointer
// size and the matching VMT layout. Replaces the legacy global `int
// DelphiVersion`.
class TargetProfile {
public:
    TargetProfile() = default;

    Vendor vendor() const { return vendor_; }
    int version() const { return version_; }
    pe::Arch arch() const { return arch_; }
    std::size_t pointer_size() const { return pointer_size_; }
    const VmtLayout& vmt() const { return vmt_; }

    // True when detection actually opened and scanned at least one syskb*.bin
    // during the >=2010 ladder. It distinguishes a real 2010 detection from the
    // 2010 fallback taken because no KB could be opened (a mis-configured or
    // empty `sys_kb_dir`). Always false for `of()`.
    bool kb_probed() const { return kb_probed_; }

    // `"kb" + std::to_string(version()) + ".bin"`.
    std::string kb_file_name() const;

    // Builds a profile for a known compiler version without inspecting an image
    // or a KB (the VMT layout and pointer size follow from the arguments).
    static TargetProfile of(Vendor vendor, int version, pe::Arch arch);

    // Detects the architecture from `image` and the Embarcadero compiler version
    // by probing the `syskb*.bin` files in `sys_kb_dir`. Returns
    // ErrorCode::unsupported_version when no version can be determined.
    static Result<TargetProfile> detect(const pe::PeFile& image,
                                        const std::filesystem::path& sys_kb_dir);

    friend Result<TargetProfile> detect_embarcadero(
        const pe::PeFile& image, const std::filesystem::path& sys_kb_dir);

private:
    Vendor vendor_ = Vendor::unknown;
    int version_ = 0;
    pe::Arch arch_ = pe::Arch::unknown;
    std::size_t pointer_size_ = 4;
    bool kb_probed_ = false;
    VmtLayout vmt_{};
};

// Embarcadero-only detection, implementing GetDelphiVersion (Main.cpp:1525).
// Exposed separately so callers can force the Delphi ladder.
Result<TargetProfile> detect_embarcadero(const pe::PeFile& image,
                                         const std::filesystem::path& sys_kb_dir);

}  // namespace idr::target
