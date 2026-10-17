#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace idr::kb {

// A single procedure argument.
struct ArgRecord {
    uint8_t tag = 0;        // 0x21 "val", 0x22 "var" (legacy convention)
    bool in_register = false;
    int32_t reg_index = 0;  // register number / stack offset
    uint32_t size = 0;
    std::string name;
    std::string type;
};

struct ProcRecord {
    uint16_t module_id = 0;
    std::string name;
    bool embedded = false;
    char dump_type = 0;      // 'C' code, 'D' data
    char method_kind = 0;    // 'M','P','F','C','D'
    uint8_t call_kind = 0;   // 1 cdecl, 2 pascal, 3 stdcall, 4 safecall
    int32_t vproc = 0;
    std::string result_type;
    std::vector<std::byte> dump;
    std::vector<std::byte> relocs;
    std::vector<std::byte> fixups;
    std::vector<std::byte> locals;
    std::vector<ArgRecord> args;
};

struct ConstRecord {
    uint16_t module_id = 0;
    std::string name;
    char type = 0;           // 'C','P','V'
    std::string type_def;
    std::string value;
    std::vector<std::byte> dump;
    std::vector<std::byte> relocs;
    std::vector<std::byte> fixups;
};

struct TypeRecord {
    uint16_t module_id = 0;
    std::string name;
    uint8_t kind = 0;
    uint16_t vmt_count = 0;
    std::string decl;
    std::vector<std::byte> dump;
    std::vector<std::byte> relocs;
    std::vector<std::byte> fixups;
    std::vector<std::byte> fields;
    std::vector<std::byte> props;
    std::vector<std::byte> methods;
};

// A global/specialized/thread variable. `type` is 'V' (var), 'A' (absolute
// var), 'S' (specialized var), or 'T' (threadvar); `abs_name` is the target of
// an `absolute` declaration (empty otherwise).
struct VarRecord {
    uint16_t module_id = 0;
    std::string name;
    char type = 0;
    std::string type_def;
    std::string abs_name;
};

// A typed-constant / resource-string entry. `context` is the enclosing unit
// name; it is empty when the source record carries none.
struct ResStringRecord {
    uint16_t module_id = 0;
    std::string name;
    std::string type_def;
    std::string context;
};

struct ModuleRecord {
    uint16_t id = 0;
    std::string name;
    std::string filename;
    std::vector<uint16_t> uses_ids;
    std::vector<std::string> uses_names;
};

// Target architecture recorded in the v3 header. This mirrors `idr::pe::Arch`
// but is declared here so the KB layer stays independent of the PE layer. The
// wire value is the byte stored in the header; `unknown` (0) is also what a v3
// file written before this field was populated carries, so such files still
// read back (as unknown).
enum class Arch : uint8_t {
    unknown = 0,
    x86 = 1,
    x64 = 2,
};

struct KbData {
    uint32_t format_version = 0;
    Arch arch = Arch::unknown;  // v3 header: target architecture
    std::string vendor;
    uint8_t vendor_code = 0;  // v3 header: vendor discriminator
    int32_t compiler_version = 0;
    std::string compiler_id;
    uint8_t pointer_size = 0;
    std::vector<ModuleRecord> modules;
    std::vector<ConstRecord> consts;
    std::vector<TypeRecord> types;
    std::vector<VarRecord> vars;
    std::vector<ResStringRecord> resstrings;
    std::vector<ProcRecord> procs;
};

// Structural equality over the *content* of two knowledge bases: the shared
// header fields and every record field, including opaque blobs. It
// deliberately does NOT compare `format_version`, because a v2->v3 conversion
// legitimately changes the container version while preserving content.
bool kb_equal(const KbData& a, const KbData& b);

}  // namespace idr::kb
