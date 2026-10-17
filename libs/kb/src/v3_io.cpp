#include "idr/kb/knowledge_base.hpp"

#include <cstdint>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "binary.hpp"

namespace idr::kb {
namespace {

constexpr std::string_view kMagicV3 = "IDRKB";
constexpr uint32_t kFormatVersion3 = 3;

// Section identifiers (also used as the per-record tag byte).
constexpr uint32_t kSectionModules = 1;
constexpr uint32_t kSectionConsts = 2;
constexpr uint32_t kSectionTypes = 3;
constexpr uint32_t kSectionProcs = 4;
constexpr uint32_t kSectionVars = 5;
constexpr uint32_t kSectionResStrings = 6;
constexpr uint32_t kSectionCount = 6;

constexpr size_t kSectionDirEntrySize = 24;  // u32 id + u32 count + u64 off + u64 size

using detail::Reader;
using detail::Writer;

// ---- serialization -------------------------------------------------------

void write_arg(Writer& w, const ArgRecord& a) {
    w.u8(a.tag);
    w.u8(a.in_register ? 1 : 0);
    w.i32(a.reg_index);
    w.u32(a.size);
    w.string(a.name);
    w.string(a.type);
}

void write_module_body(Writer& w, const ModuleRecord& m) {
    w.u16(m.id);
    w.string(m.name);
    w.string(m.filename);
    w.u32(static_cast<uint32_t>(m.uses_ids.size()));
    for (uint16_t id : m.uses_ids) {
        w.u16(id);
    }
    w.u32(static_cast<uint32_t>(m.uses_names.size()));
    for (const std::string& name : m.uses_names) {
        w.string(name);
    }
}

void write_const_body(Writer& w, const ConstRecord& c) {
    w.u16(c.module_id);
    w.string(c.name);
    w.u8(static_cast<uint8_t>(c.type));
    w.string(c.type_def);
    w.string(c.value);
    w.u32(static_cast<uint32_t>(c.dump.size()));
    w.bytes(c.dump);
    w.u32(static_cast<uint32_t>(c.relocs.size()));
    w.bytes(c.relocs);
    w.u32(static_cast<uint32_t>(c.fixups.size()));
    w.bytes(c.fixups);
}

void write_type_body(Writer& w, const TypeRecord& t) {
    w.u16(t.module_id);
    w.string(t.name);
    w.u8(t.kind);
    w.u16(t.vmt_count);
    w.string(t.decl);
    w.u32(static_cast<uint32_t>(t.dump.size()));
    w.bytes(t.dump);
    w.u32(static_cast<uint32_t>(t.relocs.size()));
    w.bytes(t.relocs);
    w.u32(static_cast<uint32_t>(t.fixups.size()));
    w.bytes(t.fixups);
    w.u32(static_cast<uint32_t>(t.fields.size()));
    w.bytes(t.fields);
    w.u32(static_cast<uint32_t>(t.props.size()));
    w.bytes(t.props);
    w.u32(static_cast<uint32_t>(t.methods.size()));
    w.bytes(t.methods);
}

void write_var_body(Writer& w, const VarRecord& v) {
    w.u16(v.module_id);
    w.string(v.name);
    w.u8(static_cast<uint8_t>(v.type));
    w.string(v.type_def);
    w.string(v.abs_name);
}

void write_resstring_body(Writer& w, const ResStringRecord& r) {
    w.u16(r.module_id);
    w.string(r.name);
    w.string(r.type_def);
    w.string(r.context);
}

void write_proc_body(Writer& w, const ProcRecord& p) {
    w.u16(p.module_id);
    w.string(p.name);
    w.u8(p.embedded ? 1 : 0);
    w.u8(static_cast<uint8_t>(p.dump_type));
    w.u8(static_cast<uint8_t>(p.method_kind));
    w.u8(p.call_kind);
    w.i32(p.vproc);
    w.string(p.result_type);
    w.u32(static_cast<uint32_t>(p.dump.size()));
    w.bytes(p.dump);
    w.u32(static_cast<uint32_t>(p.relocs.size()));
    w.bytes(p.relocs);
    w.u32(static_cast<uint32_t>(p.fixups.size()));
    w.bytes(p.fixups);
    w.u32(static_cast<uint32_t>(p.locals.size()));
    w.bytes(p.locals);
    w.u32(static_cast<uint32_t>(p.args.size()));
    for (const ArgRecord& a : p.args) {
        write_arg(w, a);
    }
}

// Serialize one section into its own byte buffer.
std::vector<std::byte> serialize_section(uint32_t id, const KbData& data,
                                         size_t& count) {
    Writer w;
    switch (id) {
        case kSectionModules: {
            count = data.modules.size();
            for (const auto& m : data.modules) {
                Writer body;
                write_module_body(body, m);
                w.u32(static_cast<uint32_t>(1 + body.data().size()));
                w.u8(static_cast<uint8_t>(kSectionModules));
                w.bytes(body.data());
            }
            break;
        }
        case kSectionConsts: {
            count = data.consts.size();
            for (const auto& c : data.consts) {
                Writer body;
                write_const_body(body, c);
                w.u32(static_cast<uint32_t>(1 + body.data().size()));
                w.u8(static_cast<uint8_t>(kSectionConsts));
                w.bytes(body.data());
            }
            break;
        }
        case kSectionTypes: {
            count = data.types.size();
            for (const auto& t : data.types) {
                Writer body;
                write_type_body(body, t);
                w.u32(static_cast<uint32_t>(1 + body.data().size()));
                w.u8(static_cast<uint8_t>(kSectionTypes));
                w.bytes(body.data());
            }
            break;
        }
        case kSectionProcs: {
            count = data.procs.size();
            for (const auto& p : data.procs) {
                Writer body;
                write_proc_body(body, p);
                w.u32(static_cast<uint32_t>(1 + body.data().size()));
                w.u8(static_cast<uint8_t>(kSectionProcs));
                w.bytes(body.data());
            }
            break;
        }
        case kSectionVars: {
            count = data.vars.size();
            for (const auto& v : data.vars) {
                Writer body;
                write_var_body(body, v);
                w.u32(static_cast<uint32_t>(1 + body.data().size()));
                w.u8(static_cast<uint8_t>(kSectionVars));
                w.bytes(body.data());
            }
            break;
        }
        case kSectionResStrings: {
            count = data.resstrings.size();
            for (const auto& rs : data.resstrings) {
                Writer body;
                write_resstring_body(body, rs);
                w.u32(static_cast<uint32_t>(1 + body.data().size()));
                w.u8(static_cast<uint8_t>(kSectionResStrings));
                w.bytes(body.data());
            }
            break;
        }
        default:
            count = 0;
            break;
    }
    return w.data();
}

// ---- deserialization -----------------------------------------------------

Result<ArgRecord> read_arg(Reader& r) {
    ArgRecord a;
    auto tag = r.u8();
    if (!tag.has_value()) return Result<ArgRecord>::err(tag.error(), tag.message());
    auto reg = r.u8();
    if (!reg.has_value()) return Result<ArgRecord>::err(reg.error(), reg.message());
    auto ndx = r.i32();
    if (!ndx.has_value()) return Result<ArgRecord>::err(ndx.error(), ndx.message());
    auto size = r.u32();
    if (!size.has_value()) return Result<ArgRecord>::err(size.error(), size.message());
    auto name = r.string();
    if (!name.has_value()) return Result<ArgRecord>::err(name.error(), name.message());
    auto type = r.string();
    if (!type.has_value()) return Result<ArgRecord>::err(type.error(), type.message());

    a.tag = tag.value();
    a.in_register = reg.value() != 0;
    a.reg_index = ndx.value();
    a.size = size.value();
    a.name = std::move(name.value());
    a.type = std::move(type.value());
    return Result<ArgRecord>::ok(std::move(a));
}

Result<ModuleRecord> read_module(Reader& r) {
    ModuleRecord m;
    auto id = r.u16();
    if (!id.has_value()) return Result<ModuleRecord>::err(id.error(), id.message());
    auto name = r.string();
    if (!name.has_value()) return Result<ModuleRecord>::err(name.error(), name.message());
    auto filename = r.string();
    if (!filename.has_value()) return Result<ModuleRecord>::err(filename.error(), filename.message());
    auto n = r.u32();
    if (!n.has_value()) return Result<ModuleRecord>::err(n.error(), n.message());
    if (n.value() > r.remaining() / 2) {  // each use id is a u16
        return Result<ModuleRecord>::err(ErrorCode::truncated, "module uses count out of range");
    }

    m.id = id.value();
    m.name = std::move(name.value());
    m.filename = std::move(filename.value());
    m.uses_ids.reserve(n.value());
    for (uint32_t i = 0; i < n.value(); ++i) {
        auto use = r.u16();
        if (!use.has_value()) return Result<ModuleRecord>::err(use.error(), use.message());
        m.uses_ids.push_back(use.value());
    }

    auto nn = r.u32();
    if (!nn.has_value()) return Result<ModuleRecord>::err(nn.error(), nn.message());
    if (nn.value() > r.remaining() / 4) {  // each use name is at least a u32 length
        return Result<ModuleRecord>::err(ErrorCode::truncated, "module use name count out of range");
    }
    m.uses_names.reserve(nn.value());
    for (uint32_t i = 0; i < nn.value(); ++i) {
        auto uname = r.string();
        if (!uname.has_value()) return Result<ModuleRecord>::err(uname.error(), uname.message());
        m.uses_names.push_back(std::move(uname.value()));
    }
    return Result<ModuleRecord>::ok(std::move(m));
}

Result<ConstRecord> read_const(Reader& r) {
    ConstRecord c;
    auto mod = r.u16();
    if (!mod.has_value()) return Result<ConstRecord>::err(mod.error(), mod.message());
    auto name = r.string();
    if (!name.has_value()) return Result<ConstRecord>::err(name.error(), name.message());
    auto type = r.u8();
    if (!type.has_value()) return Result<ConstRecord>::err(type.error(), type.message());
    auto tdef = r.string();
    if (!tdef.has_value()) return Result<ConstRecord>::err(tdef.error(), tdef.message());
    auto value = r.string();
    if (!value.has_value()) return Result<ConstRecord>::err(value.error(), value.message());
    auto dsz = r.u32();
    if (!dsz.has_value()) return Result<ConstRecord>::err(dsz.error(), dsz.message());
    auto dump = r.bytes(dsz.value());
    if (!dump.has_value()) return Result<ConstRecord>::err(dump.error(), dump.message());
    auto rsz = r.u32();
    if (!rsz.has_value()) return Result<ConstRecord>::err(rsz.error(), rsz.message());
    auto relocs = r.bytes(rsz.value());
    if (!relocs.has_value()) return Result<ConstRecord>::err(relocs.error(), relocs.message());
    auto fsz = r.u32();
    if (!fsz.has_value()) return Result<ConstRecord>::err(fsz.error(), fsz.message());
    auto fixups = r.bytes(fsz.value());
    if (!fixups.has_value()) return Result<ConstRecord>::err(fixups.error(), fixups.message());

    c.module_id = mod.value();
    c.name = std::move(name.value());
    c.type = static_cast<char>(type.value());
    c.type_def = std::move(tdef.value());
    c.value = std::move(value.value());
    c.dump = std::move(dump.value());
    c.relocs = std::move(relocs.value());
    c.fixups = std::move(fixups.value());
    return Result<ConstRecord>::ok(std::move(c));
}

Result<TypeRecord> read_type(Reader& r) {
    TypeRecord t;
    auto mod = r.u16();
    if (!mod.has_value()) return Result<TypeRecord>::err(mod.error(), mod.message());
    auto name = r.string();
    if (!name.has_value()) return Result<TypeRecord>::err(name.error(), name.message());
    auto kind = r.u8();
    if (!kind.has_value()) return Result<TypeRecord>::err(kind.error(), kind.message());
    auto vmt = r.u16();
    if (!vmt.has_value()) return Result<TypeRecord>::err(vmt.error(), vmt.message());
    auto decl = r.string();
    if (!decl.has_value()) return Result<TypeRecord>::err(decl.error(), decl.message());

    auto dsz = r.u32();
    if (!dsz.has_value()) return Result<TypeRecord>::err(dsz.error(), dsz.message());
    auto dump = r.bytes(dsz.value());
    if (!dump.has_value()) return Result<TypeRecord>::err(dump.error(), dump.message());
    auto rsz = r.u32();
    if (!rsz.has_value()) return Result<TypeRecord>::err(rsz.error(), rsz.message());
    auto relocs = r.bytes(rsz.value());
    if (!relocs.has_value()) return Result<TypeRecord>::err(relocs.error(), relocs.message());
    auto xsz = r.u32();
    if (!xsz.has_value()) return Result<TypeRecord>::err(xsz.error(), xsz.message());
    auto fixups = r.bytes(xsz.value());
    if (!fixups.has_value()) return Result<TypeRecord>::err(fixups.error(), fixups.message());
    auto fsz = r.u32();
    if (!fsz.has_value()) return Result<TypeRecord>::err(fsz.error(), fsz.message());
    auto fields = r.bytes(fsz.value());
    if (!fields.has_value()) return Result<TypeRecord>::err(fields.error(), fields.message());
    auto psz = r.u32();
    if (!psz.has_value()) return Result<TypeRecord>::err(psz.error(), psz.message());
    auto props = r.bytes(psz.value());
    if (!props.has_value()) return Result<TypeRecord>::err(props.error(), props.message());
    auto msz = r.u32();
    if (!msz.has_value()) return Result<TypeRecord>::err(msz.error(), msz.message());
    auto methods = r.bytes(msz.value());
    if (!methods.has_value()) return Result<TypeRecord>::err(methods.error(), methods.message());

    t.module_id = mod.value();
    t.name = std::move(name.value());
    t.kind = kind.value();
    t.vmt_count = vmt.value();
    t.decl = std::move(decl.value());
    t.dump = std::move(dump.value());
    t.relocs = std::move(relocs.value());
    t.fixups = std::move(fixups.value());
    t.fields = std::move(fields.value());
    t.props = std::move(props.value());
    t.methods = std::move(methods.value());
    return Result<TypeRecord>::ok(std::move(t));
}

Result<VarRecord> read_var(Reader& r) {
    VarRecord v;
    auto mod = r.u16();
    if (!mod.has_value()) return Result<VarRecord>::err(mod.error(), mod.message());
    auto name = r.string();
    if (!name.has_value()) return Result<VarRecord>::err(name.error(), name.message());
    auto type = r.u8();
    if (!type.has_value()) return Result<VarRecord>::err(type.error(), type.message());
    auto tdef = r.string();
    if (!tdef.has_value()) return Result<VarRecord>::err(tdef.error(), tdef.message());
    auto abs = r.string();
    if (!abs.has_value()) return Result<VarRecord>::err(abs.error(), abs.message());

    v.module_id = mod.value();
    v.name = std::move(name.value());
    v.type = static_cast<char>(type.value());
    v.type_def = std::move(tdef.value());
    v.abs_name = std::move(abs.value());
    return Result<VarRecord>::ok(std::move(v));
}

Result<ResStringRecord> read_resstring(Reader& r) {
    ResStringRecord rs;
    auto mod = r.u16();
    if (!mod.has_value()) return Result<ResStringRecord>::err(mod.error(), mod.message());
    auto name = r.string();
    if (!name.has_value()) return Result<ResStringRecord>::err(name.error(), name.message());
    auto tdef = r.string();
    if (!tdef.has_value()) return Result<ResStringRecord>::err(tdef.error(), tdef.message());
    auto ctx = r.string();
    if (!ctx.has_value()) return Result<ResStringRecord>::err(ctx.error(), ctx.message());

    rs.module_id = mod.value();
    rs.name = std::move(name.value());
    rs.type_def = std::move(tdef.value());
    rs.context = std::move(ctx.value());
    return Result<ResStringRecord>::ok(std::move(rs));
}

Result<ProcRecord> read_proc(Reader& r) {
    ProcRecord p;
    auto mod = r.u16();
    if (!mod.has_value()) return Result<ProcRecord>::err(mod.error(), mod.message());
    auto name = r.string();
    if (!name.has_value()) return Result<ProcRecord>::err(name.error(), name.message());
    auto emb = r.u8();
    if (!emb.has_value()) return Result<ProcRecord>::err(emb.error(), emb.message());
    auto dt = r.u8();
    if (!dt.has_value()) return Result<ProcRecord>::err(dt.error(), dt.message());
    auto mk = r.u8();
    if (!mk.has_value()) return Result<ProcRecord>::err(mk.error(), mk.message());
    auto ck = r.u8();
    if (!ck.has_value()) return Result<ProcRecord>::err(ck.error(), ck.message());
    auto vproc = r.i32();
    if (!vproc.has_value()) return Result<ProcRecord>::err(vproc.error(), vproc.message());
    auto result = r.string();
    if (!result.has_value()) return Result<ProcRecord>::err(result.error(), result.message());

    auto dsz = r.u32();
    if (!dsz.has_value()) return Result<ProcRecord>::err(dsz.error(), dsz.message());
    auto dump = r.bytes(dsz.value());
    if (!dump.has_value()) return Result<ProcRecord>::err(dump.error(), dump.message());
    auto rsz = r.u32();
    if (!rsz.has_value()) return Result<ProcRecord>::err(rsz.error(), rsz.message());
    auto relocs = r.bytes(rsz.value());
    if (!relocs.has_value()) return Result<ProcRecord>::err(relocs.error(), relocs.message());
    auto fnum = r.u32();
    if (!fnum.has_value()) return Result<ProcRecord>::err(fnum.error(), fnum.message());
    auto fixups = r.bytes(fnum.value());
    if (!fixups.has_value()) return Result<ProcRecord>::err(fixups.error(), fixups.message());
    auto lnum = r.u32();
    if (!lnum.has_value()) return Result<ProcRecord>::err(lnum.error(), lnum.message());
    auto locals = r.bytes(lnum.value());
    if (!locals.has_value()) return Result<ProcRecord>::err(locals.error(), locals.message());
    auto anum = r.u32();
    if (!anum.has_value()) return Result<ProcRecord>::err(anum.error(), anum.message());
    // Smallest arg: tag(1) + in_register(1) + reg_index(4) + size(4)
    //              + name(4 for an empty string) + type(4) = 18 bytes.
    if (anum.value() > r.remaining() / 18) {
        return Result<ProcRecord>::err(ErrorCode::truncated, "proc arg count out of range");
    }
    p.args.reserve(anum.value());
    for (uint32_t i = 0; i < anum.value(); ++i) {
        auto a = read_arg(r);
        if (!a.has_value()) return Result<ProcRecord>::err(a.error(), a.message());
        p.args.push_back(std::move(a.value()));
    }

    p.module_id = mod.value();
    p.name = std::move(name.value());
    p.embedded = emb.value() != 0;
    p.dump_type = static_cast<char>(dt.value());
    p.method_kind = static_cast<char>(mk.value());
    p.call_kind = ck.value();
    p.vproc = vproc.value();
    p.result_type = std::move(result.value());
    p.dump = std::move(dump.value());
    p.relocs = std::move(relocs.value());
    p.fixups = std::move(fixups.value());
    p.locals = std::move(locals.value());
    return Result<ProcRecord>::ok(std::move(p));
}

}  // namespace

Result<void> write_v3(std::filesystem::path path, const KbData& data) {
    // Serialize sections first.
    size_t counts[kSectionCount] = {};
    std::vector<std::byte> sections[kSectionCount];
    sections[0] = serialize_section(kSectionModules, data, counts[0]);
    sections[1] = serialize_section(kSectionConsts, data, counts[1]);
    sections[2] = serialize_section(kSectionTypes, data, counts[2]);
    sections[3] = serialize_section(kSectionProcs, data, counts[3]);
    sections[4] = serialize_section(kSectionVars, data, counts[4]);
    sections[5] = serialize_section(kSectionResStrings, data, counts[5]);

    // Build the header (checksum placeholder).
    Writer header;
    for (char c : kMagicV3) {
        header.u8(static_cast<uint8_t>(c));
    }
    header.u32(kFormatVersion3);
    header.u8(static_cast<uint8_t>(data.arch));
    header.u8(data.vendor_code);
    header.i32(data.compiler_version);
    header.string(data.compiler_id);
    header.u8(data.pointer_size);
    header.string(data.vendor);  // vendor string carried in the description slot
    header.u32(kSectionCount);
    const size_t checksum_offset = header.data().size();
    header.u32(0);  // checksum placeholder

    // Section directory. Offsets are absolute positions within the final file.
    const size_t directory_offset = header.data().size();
    const size_t data_offset =
        directory_offset + kSectionCount * kSectionDirEntrySize;

    Writer directory;
    std::vector<std::byte> file = header.data();
    size_t cursor = data_offset;
    for (uint32_t i = 0; i < kSectionCount; ++i) {
        directory.u32(i + 1);
        directory.u32(static_cast<uint32_t>(counts[i]));
        directory.u64(static_cast<uint64_t>(cursor));
        directory.u64(static_cast<uint64_t>(sections[i].size()));
        cursor += sections[i].size();
    }

    // Assemble the full file: header + directory + sections.
    file.insert(file.end(), directory.data().begin(), directory.data().end());
    for (uint32_t i = 0; i < kSectionCount; ++i) {
        file.insert(file.end(), sections[i].begin(), sections[i].end());
    }

    // Checksum over the directory and section data.
    std::span<const std::byte> covered(file.data() + directory_offset,
                                       file.size() - directory_offset);
    const uint32_t checksum = detail::fnv1a(covered);

    // Patch the checksum into the header.
    for (int i = 0; i < 4; ++i) {
        file[checksum_offset + i] = static_cast<std::byte>((checksum >> (8 * i)) & 0xFF);
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return Result<void>::err(ErrorCode::io_error, "cannot open output file");
    }
    out.write(reinterpret_cast<const char*>(file.data()),
              static_cast<std::streamsize>(file.size()));
    if (!out) {
        return Result<void>::err(ErrorCode::io_error, "write failed");
    }
    return Result<void>::ok();
}

Result<KbData> read_v3(std::span<const std::byte> buf) {
    if (buf.size() < 5 || !(buf[0] == std::byte{'I'} && buf[1] == std::byte{'D'} &&
                            buf[2] == std::byte{'R'} && buf[3] == std::byte{'K'} &&
                            buf[4] == std::byte{'B'})) {
        return Result<KbData>::err(ErrorCode::bad_magic, "not an IDRKB file");
    }

    Reader r(buf);
    auto magic = r.bytes(5);
    (void)magic;
    auto version = r.u32();
    if (!version.has_value()) return Result<KbData>::err(version.error(), version.message());
    if (version.value() != kFormatVersion3) {
        return Result<KbData>::err(ErrorCode::unsupported_version,
                                   "unsupported format version");
    }

    auto arch = r.u8();          // target architecture
    auto vendor_code = r.u8();   // vendor discriminator
    auto compiler_version = r.i32();
    auto compiler_id = r.string();
    auto pointer_size = r.u8();
    auto description = r.string();
    auto section_count = r.u32();
    auto checksum = r.u32();
    if (!arch.has_value() || !vendor_code.has_value() ||
        !compiler_version.has_value() || !compiler_id.has_value() ||
        !pointer_size.has_value() || !description.has_value() ||
        !section_count.has_value() || !checksum.has_value()) {
        return Result<KbData>::err(ErrorCode::truncated, "short v3 header");
    }

    // Locate and verify the checksum over directory + sections.
    const size_t directory_offset = r.pos();
    const size_t covered_size = buf.size() - directory_offset;
    const uint32_t actual = detail::fnv1a(buf.subspan(directory_offset, covered_size));
    if (actual != checksum.value()) {
        // A bad checksum is a corrupt-format condition, not an I/O failure.
        return Result<KbData>::err(ErrorCode::unsupported_format, "v3 checksum mismatch");
    }

    // Read the section directory.
    struct DirEntry {
        uint32_t id;
        uint32_t count;
        uint64_t offset;
        uint64_t size;
    };
    // Each directory entry is 24 bytes; bound the count by the bytes remaining
    // after the header so a crafted huge count cannot drive reserve().
    const size_t remaining_after_header = buf.size() - r.pos();
    if (section_count.value() > remaining_after_header / kSectionDirEntrySize) {
        return Result<KbData>::err(ErrorCode::truncated, "section count out of range");
    }
    std::vector<DirEntry> dir;
    dir.reserve(section_count.value());
    for (uint32_t i = 0; i < section_count.value(); ++i) {
        auto id = r.u32();
        auto count = r.u32();
        auto offset = r.u64();
        auto size = r.u64();
        if (!id.has_value() || !count.has_value() || !offset.has_value() ||
            !size.has_value()) {
            return Result<KbData>::err(ErrorCode::truncated, "short section directory");
        }
        dir.push_back({id.value(), count.value(), offset.value(), size.value()});
    }

    KbData data;
    data.format_version = version.value();
    // A zero reserved byte predates the architecture field and reads as
    // unknown; values outside the enum also fall back to unknown.
    switch (arch.value()) {
        case static_cast<uint8_t>(Arch::x86):
            data.arch = Arch::x86;
            break;
        case static_cast<uint8_t>(Arch::x64):
            data.arch = Arch::x64;
            break;
        default:
            data.arch = Arch::unknown;
            break;
    }
    data.vendor_code = vendor_code.value();
    data.vendor = std::move(description.value());
    data.compiler_version = compiler_version.value();
    data.compiler_id = std::move(compiler_id.value());
    data.pointer_size = pointer_size.value();

    // Materialize each section. We re-read via a cursor positioned at the
    // section's data offset; each record is bounds-checked against its own
    // length prefix and the enclosing section size.
    auto materialize = [&](const DirEntry& e) -> Result<void> {
        if (e.offset > buf.size() || e.size > buf.size() - e.offset) {
            return Result<void>::err(ErrorCode::truncated, "section out of range");
        }
        Reader sr(buf.subspan(static_cast<size_t>(e.offset),
                              static_cast<size_t>(e.size)));
        for (uint32_t i = 0; i < e.count; ++i) {
            auto len = sr.u32();
            if (!len.has_value()) return Result<void>::err(len.error(), len.message());
            if (len.value() == 0) {
                return Result<void>::err(ErrorCode::truncated, "zero-length record");
            }
            auto tag = sr.u8();
            if (!tag.has_value()) return Result<void>::err(tag.error(), tag.message());
            auto body = sr.bytes(static_cast<size_t>(len.value()) - 1);
            if (!body.has_value()) return Result<void>::err(body.error(), body.message());

            Reader br(body.value());
            switch (e.id) {
                case kSectionModules: {
                    auto rec = read_module(br);
                    if (!rec.has_value()) return Result<void>::err(rec.error(), rec.message());
                    data.modules.push_back(std::move(rec.value()));
                    break;
                }
                case kSectionConsts: {
                    auto rec = read_const(br);
                    if (!rec.has_value()) return Result<void>::err(rec.error(), rec.message());
                    data.consts.push_back(std::move(rec.value()));
                    break;
                }
                case kSectionTypes: {
                    auto rec = read_type(br);
                    if (!rec.has_value()) return Result<void>::err(rec.error(), rec.message());
                    data.types.push_back(std::move(rec.value()));
                    break;
                }
                case kSectionProcs: {
                    auto rec = read_proc(br);
                    if (!rec.has_value()) return Result<void>::err(rec.error(), rec.message());
                    data.procs.push_back(std::move(rec.value()));
                    break;
                }
                case kSectionVars: {
                    auto rec = read_var(br);
                    if (!rec.has_value()) return Result<void>::err(rec.error(), rec.message());
                    data.vars.push_back(std::move(rec.value()));
                    break;
                }
                case kSectionResStrings: {
                    auto rec = read_resstring(br);
                    if (!rec.has_value()) return Result<void>::err(rec.error(), rec.message());
                    data.resstrings.push_back(std::move(rec.value()));
                    break;
                }
                default:
                    // Unknown section id: skip.
                    break;
            }
        }
        return Result<void>::ok();
    };

    for (const auto& e : dir) {
        auto res = materialize(e);
        if (!res.has_value()) {
            return Result<KbData>::err(res.error(), res.message());
        }
    }

    return Result<KbData>::ok(std::move(data));
}

}  // namespace idr::kb
