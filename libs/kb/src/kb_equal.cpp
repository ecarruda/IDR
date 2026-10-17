#include <algorithm>
#include <cstddef>

#include "idr/kb/records.hpp"

namespace idr::kb {
namespace {

bool bytes_equal(const std::vector<std::byte>& a, const std::vector<std::byte>& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

bool arg_equal(const ArgRecord& a, const ArgRecord& b) {
    return a.tag == b.tag && a.in_register == b.in_register &&
           a.reg_index == b.reg_index && a.size == b.size && a.name == b.name &&
           a.type == b.type;
}

bool module_equal(const ModuleRecord& a, const ModuleRecord& b) {
    return a.id == b.id && a.name == b.name && a.filename == b.filename &&
           a.uses_ids == b.uses_ids && a.uses_names == b.uses_names;
}

bool const_equal(const ConstRecord& a, const ConstRecord& b) {
    return a.module_id == b.module_id && a.name == b.name && a.type == b.type &&
           a.type_def == b.type_def && a.value == b.value &&
           bytes_equal(a.dump, b.dump) && bytes_equal(a.relocs, b.relocs) &&
           bytes_equal(a.fixups, b.fixups);
}

bool type_equal(const TypeRecord& a, const TypeRecord& b) {
    return a.module_id == b.module_id && a.name == b.name && a.kind == b.kind &&
           a.vmt_count == b.vmt_count && a.decl == b.decl &&
           bytes_equal(a.dump, b.dump) && bytes_equal(a.relocs, b.relocs) &&
           bytes_equal(a.fixups, b.fixups) && bytes_equal(a.fields, b.fields) &&
           bytes_equal(a.props, b.props) && bytes_equal(a.methods, b.methods);
}

bool var_equal(const VarRecord& a, const VarRecord& b) {
    return a.module_id == b.module_id && a.name == b.name && a.type == b.type &&
           a.type_def == b.type_def && a.abs_name == b.abs_name;
}

bool resstring_equal(const ResStringRecord& a, const ResStringRecord& b) {
    return a.module_id == b.module_id && a.name == b.name &&
           a.type_def == b.type_def && a.context == b.context;
}

bool proc_equal(const ProcRecord& a, const ProcRecord& b) {
    return a.module_id == b.module_id && a.name == b.name &&
           a.embedded == b.embedded && a.dump_type == b.dump_type &&
           a.method_kind == b.method_kind && a.call_kind == b.call_kind &&
           a.vproc == b.vproc && a.result_type == b.result_type &&
           bytes_equal(a.dump, b.dump) && bytes_equal(a.relocs, b.relocs) &&
           bytes_equal(a.fixups, b.fixups) && bytes_equal(a.locals, b.locals) &&
           std::equal(a.args.begin(), a.args.end(), b.args.begin(), b.args.end(),
                      arg_equal);
}

template <class T, class Eq>
bool vectors_equal(const std::vector<T>& a, const std::vector<T>& b, Eq eq) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(), eq);
}

}  // namespace

bool kb_equal(const KbData& a, const KbData& b) {
    // format_version is intentionally not compared: a v2->v3 conversion
    // changes the container version while preserving content.
    if (a.arch != b.arch || a.vendor != b.vendor ||
        a.vendor_code != b.vendor_code ||
        a.compiler_version != b.compiler_version ||
        a.compiler_id != b.compiler_id || a.pointer_size != b.pointer_size) {
        return false;
    }
    return vectors_equal(a.modules, b.modules, module_equal) &&
           vectors_equal(a.consts, b.consts, const_equal) &&
           vectors_equal(a.types, b.types, type_equal) &&
           vectors_equal(a.vars, b.vars, var_equal) &&
           vectors_equal(a.resstrings, b.resstrings, resstring_equal) &&
           vectors_equal(a.procs, b.procs, proc_equal);
}

}  // namespace idr::kb
