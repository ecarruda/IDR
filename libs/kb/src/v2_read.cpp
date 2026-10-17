#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "idr/kb/records.hpp"

#include "binary.hpp"

namespace idr::kb {
namespace {

constexpr const char* kSignatureV2 = "IDR Knowledge Base File";
constexpr size_t kHeaderSize = 24 + 1 + 4 + 4 + 256 + 4;  // 293 bytes

using detail::Reader;

// Legacy v2 stores strings as WORD length + characters + a trailing NUL.
Result<std::string> read_v2_string(Reader& r) {
    auto len = r.u16();
    if (!len.has_value()) return Result<std::string>::err(len.error(), len.message());
    auto chars = r.bytes(len.value());
    if (!chars.has_value()) return Result<std::string>::err(chars.error(), chars.message());
    auto nul = r.u8();
    if (!nul.has_value()) return Result<std::string>::err(nul.error(), nul.message());
    std::string s;
    s.reserve(chars.value().size());
    for (auto c : chars.value()) {
        s.push_back(static_cast<char>(static_cast<uint8_t>(c)));
    }
    return Result<std::string>::ok(std::move(s));
}

// Read the dump block described by DumpTotal, returning the dump bytes and
// storing the relocs and the raw fixup blob. DumpTotal covers DumpSize(4) +
// FixupNum(4) + dump + relocs + fixups, so the fixup region is
// dump_total - 8 - 2*dump_size bytes. The fixup bytes are captured verbatim;
// their internal layout is not interpreted here.
Result<std::vector<std::byte>> read_dump(Reader& r, uint32_t dump_total,
                                         std::vector<std::byte>& relocs,
                                         std::vector<std::byte>& fixups) {
    auto dump_sz = r.u32();
    if (!dump_sz.has_value()) {
        return Result<std::vector<std::byte>>::err(dump_sz.error(), dump_sz.message());
    }
    auto fixup_num = r.u32();
    if (!fixup_num.has_value()) {
        return Result<std::vector<std::byte>>::err(fixup_num.error(), fixup_num.message());
    }
    constexpr uint32_t header_sz = 8;
    if (dump_total < header_sz ||
        static_cast<uint64_t>(dump_total) < header_sz + 2ull * dump_sz.value()) {
        return Result<std::vector<std::byte>>::err(ErrorCode::truncated,
                                                   "bad DumpTotal");
    }
    auto dump = r.bytes(dump_sz.value());
    if (!dump.has_value()) return Result<std::vector<std::byte>>::err(dump.error(), dump.message());
    auto rel = r.bytes(dump_sz.value());
    if (!rel.has_value()) return Result<std::vector<std::byte>>::err(rel.error(), rel.message());
    relocs = std::move(rel.value());

    const uint32_t fixup_bytes = dump_total - header_sz - 2u * dump_sz.value();
    auto fx = r.bytes(fixup_bytes);
    if (!fx.has_value()) {
        return Result<std::vector<std::byte>>::err(fx.error(), fx.message());
    }
    fixups = std::move(fx.value());
    return dump;
}

}  // namespace

Result<KbData> read_v2(std::span<const std::byte> buf) {
    // Header layout (mirrors MKnowledgeBase::CheckKBFile):
    //   char signature[24]; bool isMSIL; int delphiVer; DWORD crc;
    //   char description[256]; DWORD kbVer;
    if (buf.size() < kHeaderSize + 4) {
        return Result<KbData>::err(ErrorCode::truncated, "v2 header too short");
    }
    for (size_t i = 0; i < 23; ++i) {
        if (static_cast<char>(buf[i]) != kSignatureV2[i]) {
            return Result<KbData>::err(ErrorCode::bad_magic, "not a v2 KB file");
        }
    }

    // isMSIL (1) at 24, delphiVer (i32) at 25, crc (u32) at 29.
    int32_t delphi_ver = 0;
    if (auto dv = detail::read_i32(buf, 25); dv.has_value()) {
        delphi_ver = dv.value();
    }
    // kbVer (u32) at 289.
    auto kb_ver = detail::read_u32(buf, 289);
    if (!kb_ver.has_value()) {
        return Result<KbData>::err(ErrorCode::truncated, "missing kbVer");
    }
    if (kb_ver.value() != 2) {
        return Result<KbData>::err(ErrorCode::unsupported_version, "unsupported KB version");
    }

    // The final 4 bytes hold the offset of the section table.
    auto sections_offset = detail::read_u32(buf, buf.size() - 4);
    if (!sections_offset.has_value()) {
        return Result<KbData>::err(ErrorCode::truncated, "missing sections offset");
    }
    if (sections_offset.value() > buf.size() - 4) {
        return Result<KbData>::err(ErrorCode::truncated, "sections offset out of range");
    }

    struct OffsetsInfo {
        uint32_t offset;
        uint32_t size;
        int32_t mod_id;
        int32_t nam_id;
    };

    // Read a {count, maxsize, count * OFFSETSINFO} section header.
    auto read_table = [&](Reader& r, std::vector<OffsetsInfo>& out) -> Result<int32_t> {
        auto count = r.i32();
        if (!count.has_value()) return Result<int32_t>::err(count.error(), count.message());
        auto max = r.i32();
        if (!max.has_value()) return Result<int32_t>::err(max.error(), max.message());
        if (count.value() < 0) {
            return Result<int32_t>::err(ErrorCode::truncated, "negative section count");
        }
        // Each OFFSETSINFO entry is 16 bytes; bound the count by the bytes
        // still available so a crafted huge count cannot drive reserve().
        if (static_cast<uint64_t>(count.value()) > r.remaining() / 16) {
            return Result<int32_t>::err(ErrorCode::truncated, "section count out of range");
        }
        out.clear();
        out.reserve(static_cast<size_t>(count.value()));
        for (int32_t i = 0; i < count.value(); ++i) {
            auto off = r.u32();
            auto sz = r.u32();
            auto mod = r.i32();
            auto nam = r.i32();
            if (!off.has_value() || !sz.has_value() || !mod.has_value() || !nam.has_value()) {
                return Result<int32_t>::err(ErrorCode::truncated, "short offsets table");
            }
            out.push_back({off.value(), sz.value(), mod.value(), nam.value()});
        }
        return Result<int32_t>::ok(count.value());
    };

    Reader table(buf.subspan(static_cast<size_t>(sections_offset.value())));

    std::vector<OffsetsInfo> modules, consts, types, procs;
    std::vector<OffsetsInfo> vars, resstr;
    auto mc = read_table(table, modules);
    if (!mc.has_value()) return Result<KbData>::err(mc.error(), mc.message());
    auto cc = read_table(table, consts);
    if (!cc.has_value()) return Result<KbData>::err(cc.error(), cc.message());
    auto tc = read_table(table, types);
    if (!tc.has_value()) return Result<KbData>::err(tc.error(), tc.message());
    auto vc = read_table(table, vars);
    if (!vc.has_value()) return Result<KbData>::err(vc.error(), vc.message());
    auto rc = read_table(table, resstr);
    if (!rc.has_value()) return Result<KbData>::err(rc.error(), rc.message());
    auto pc = read_table(table, procs);
    if (!pc.has_value()) return Result<KbData>::err(pc.error(), pc.message());

    // Read a record located at `info`, as its own bounds-checked sub-span.
    auto record_reader = [&](const OffsetsInfo& info) -> Result<Reader> {
        if (info.offset > buf.size() || info.size > buf.size() - info.offset) {
            return Result<Reader>::err(ErrorCode::truncated, "record out of range");
        }
        return Result<Reader>::ok(
            Reader(buf.subspan(static_cast<size_t>(info.offset),
                               static_cast<size_t>(info.size))));
    };

    KbData data;
    data.format_version = 2;
    // A v2 KB is always 32-bit Embarcadero; MSIL bytecode carries no native
    // arch. The isMSIL byte sits at offset 24.
    const bool is_msil = buf[24] != std::byte{0};
    data.arch = is_msil ? Arch::unknown : Arch::x86;
    data.vendor = "embarcadero";
    data.vendor_code = 1;
    data.compiler_version = delphi_ver;
    data.compiler_id.clear();
    data.pointer_size = 4;

    // Modules.
    for (const auto& info : modules) {
        auto rr = record_reader(info);
        if (!rr.has_value()) return Result<KbData>::err(rr.error(), rr.message());
        Reader r = rr.value();
        ModuleRecord m;
        auto id = r.u16();
        auto name = read_v2_string(r);
        auto filename = read_v2_string(r);
        auto uses_num = r.u16();
        if (!id.has_value() || !name.has_value() || !filename.has_value() ||
            !uses_num.has_value()) {
            return Result<KbData>::err(ErrorCode::truncated, "short module record");
        }
        m.id = id.value();
        m.name = std::move(name.value());
        m.filename = std::move(filename.value());
        for (uint16_t i = 0; i < uses_num.value(); ++i) {
            auto use = r.u16();
            if (!use.has_value()) {
                return Result<KbData>::err(ErrorCode::truncated, "short module uses");
            }
            m.uses_ids.push_back(use.value());
        }
        // uses_num trailing PSTR names follow the numeric uses ids.
        for (uint16_t i = 0; i < uses_num.value(); ++i) {
            auto use_name = read_v2_string(r);
            if (!use_name.has_value()) {
                return Result<KbData>::err(use_name.error(), use_name.message());
            }
            m.uses_names.push_back(std::move(use_name.value()));
        }
        data.modules.push_back(std::move(m));
    }

    // Consts.
    for (const auto& info : consts) {
        auto rr = record_reader(info);
        if (!rr.has_value()) return Result<KbData>::err(rr.error(), rr.message());
        Reader r = rr.value();
        ConstRecord c;
        auto mod = r.u16();
        auto name = read_v2_string(r);
        auto type = r.u8();
        auto tdef = read_v2_string(r);
        auto value = read_v2_string(r);
        auto dump_total = r.u32();
        if (!mod.has_value() || !name.has_value() || !type.has_value() ||
            !tdef.has_value() || !value.has_value() || !dump_total.has_value()) {
            return Result<KbData>::err(ErrorCode::truncated, "short const record");
        }
        std::vector<std::byte> relocs;
        std::vector<std::byte> fixups;
        auto dump = read_dump(r, dump_total.value(), relocs, fixups);
        if (!dump.has_value()) return Result<KbData>::err(dump.error(), dump.message());
        c.module_id = mod.value();
        c.name = std::move(name.value());
        c.type = static_cast<char>(type.value());
        c.type_def = std::move(tdef.value());
        c.value = std::move(value.value());
        c.dump = std::move(dump.value());
        c.relocs = std::move(relocs);
        c.fixups = std::move(fixups);
        data.consts.push_back(std::move(c));
    }

    // Types.
    for (const auto& info : types) {
        auto rr = record_reader(info);
        if (!rr.has_value()) return Result<KbData>::err(rr.error(), rr.message());
        Reader r = rr.value();
        TypeRecord t;
        auto size = r.u32();  // v2 stores the record size first; unused here
        auto mod = r.u16();
        auto name = read_v2_string(r);
        auto kind = r.u8();
        auto vmt = r.u16();
        auto decl = read_v2_string(r);
        auto dump_total = r.u32();
        if (!size.has_value() || !mod.has_value() || !name.has_value() ||
            !kind.has_value() || !vmt.has_value() || !decl.has_value() ||
            !dump_total.has_value()) {
            return Result<KbData>::err(ErrorCode::truncated, "short type record");
        }
        std::vector<std::byte> relocs;
        std::vector<std::byte> fixups;
        auto dump = read_dump(r, dump_total.value(), relocs, fixups);
        if (!dump.has_value()) return Result<KbData>::err(dump.error(), dump.message());

        // Opaque blocks: fields, props, methods (each is length-prefixed by a
        // DWORD total that includes its 2-byte count).
        auto fields_total = r.u32();
        auto fields = fields_total.has_value()
                          ? r.bytes(fields_total.value())
                          : Result<std::vector<std::byte>>::err(fields_total.error(),
                                                                fields_total.message());
        auto props_total = r.u32();
        auto props = props_total.has_value()
                         ? r.bytes(props_total.value())
                         : Result<std::vector<std::byte>>::err(props_total.error(),
                                                               props_total.message());
        auto methods_total = r.u32();
        auto methods = methods_total.has_value()
                           ? r.bytes(methods_total.value())
                           : Result<std::vector<std::byte>>::err(methods_total.error(),
                                                                 methods_total.message());
        if (!fields.has_value() || !props.has_value() || !methods.has_value()) {
            return Result<KbData>::err(ErrorCode::truncated, "short type blocks");
        }

        t.module_id = mod.value();
        t.name = std::move(name.value());
        t.kind = kind.value();
        t.vmt_count = vmt.value();
        t.decl = std::move(decl.value());
        t.dump = std::move(dump.value());
        t.relocs = std::move(relocs);
        t.fixups = std::move(fixups);
        t.fields = std::move(fields.value());
        t.props = std::move(props.value());
        t.methods = std::move(methods.value());
        data.types.push_back(std::move(t));
    }

    // Procs.
    for (const auto& info : procs) {
        auto rr = record_reader(info);
        if (!rr.has_value()) return Result<KbData>::err(rr.error(), rr.message());
        Reader r = rr.value();
        ProcRecord p;
        auto mod = r.u16();
        auto name = read_v2_string(r);
        auto embedded = r.u8();
        auto dump_type = r.u8();
        auto method_kind = r.u8();
        auto call_kind = r.u8();
        auto vproc = r.i32();
        auto result = read_v2_string(r);
        auto dump_total = r.u32();
        if (!mod.has_value() || !name.has_value() || !embedded.has_value() ||
            !dump_type.has_value() || !method_kind.has_value() ||
            !call_kind.has_value() || !vproc.has_value() || !result.has_value() ||
            !dump_total.has_value()) {
            return Result<KbData>::err(ErrorCode::truncated, "short proc record");
        }
        std::vector<std::byte> relocs;
        std::vector<std::byte> fixups;
        auto dump = read_dump(r, dump_total.value(), relocs, fixups);
        if (!dump.has_value()) return Result<KbData>::err(dump.error(), dump.message());

        // Args: DWORD ArgsTotal (includes the 2-byte count), WORD ArgsNum,
        // then ArgsNum * ARGINFO. Each ARGINFO (mirrors FillArgInfo, Misc.cpp):
        //   Tag u8, locflags i32, Ndx i32, Name, TypeDef.
        auto args_total = r.u32();
        auto args_num = r.u16();
        if (!args_total.has_value() || !args_num.has_value()) {
            return Result<KbData>::err(ErrorCode::truncated, "short proc args");
        }
        p.module_id = mod.value();
        p.name = std::move(name.value());
        p.embedded = embedded.value() != 0;
        p.dump_type = static_cast<char>(dump_type.value());
        p.method_kind = static_cast<char>(method_kind.value());
        p.call_kind = call_kind.value();
        p.vproc = vproc.value();
        p.result_type = std::move(result.value());
        p.dump = std::move(dump.value());
        p.relocs = std::move(relocs);
        p.fixups = std::move(fixups);
        for (uint16_t i = 0; i < args_num.value(); ++i) {
            ArgRecord a;
            auto tag = r.u8();
            auto locflags = r.u32();
            auto ndx = r.i32();
            auto aname = read_v2_string(r);
            auto atype = read_v2_string(r);
            if (!tag.has_value() || !locflags.has_value() || !ndx.has_value() ||
                !aname.has_value() || !atype.has_value()) {
                return Result<KbData>::err(ErrorCode::truncated, "short arg record");
            }
            a.tag = tag.value();
            if ((locflags.value() & 7u) == 1u) {
                a.tag = 0x23;  // 'const' override (mirrors FillArgInfo)
            }
            a.in_register = (locflags.value() & 8u) != 0;
            a.reg_index = ndx.value();
            a.size = 4;  // v2 does not store arg size; legacy assumes pointer width
            a.name = std::move(aname.value());
            a.type = std::move(atype.value());
            p.args.push_back(std::move(a));
        }

        // Only the oldest format (Delphi 2) appends a trailing Locals block:
        // DWORD LocalsTotal followed by exactly LocalsTotal bytes. When the
        // record has ended after the args block, `locals` stays empty.
        if (!r.eof()) {
            auto locals_total = r.u32();
            if (!locals_total.has_value()) {
                return Result<KbData>::err(ErrorCode::truncated, "short proc locals");
            }
            auto locals = r.bytes(locals_total.value());
            if (!locals.has_value()) {
                return Result<KbData>::err(locals.error(), locals.message());
            }
            p.locals = std::move(locals.value());
        }
        data.procs.push_back(std::move(p));
    }

    // Vars. Layout: u16 module_id, PSTR name, u8 type, PSTR type_def,
    // PSTR abs_name (always present, may be empty).
    for (const auto& info : vars) {
        auto rr = record_reader(info);
        if (!rr.has_value()) return Result<KbData>::err(rr.error(), rr.message());
        Reader r = rr.value();
        VarRecord v;
        auto mod = r.u16();
        auto name = read_v2_string(r);
        auto type = r.u8();
        auto tdef = read_v2_string(r);
        auto abs_name = read_v2_string(r);
        if (!mod.has_value() || !name.has_value() || !type.has_value() ||
            !tdef.has_value() || !abs_name.has_value()) {
            return Result<KbData>::err(ErrorCode::truncated, "short var record");
        }
        v.module_id = mod.value();
        v.name = std::move(name.value());
        v.type = static_cast<char>(type.value());
        v.type_def = std::move(tdef.value());
        v.abs_name = std::move(abs_name.value());
        data.vars.push_back(std::move(v));
    }

    // ResStrings. Layout: u16 module_id, PSTR name, PSTR type_def, PSTR context.
    for (const auto& info : resstr) {
        auto rr = record_reader(info);
        if (!rr.has_value()) return Result<KbData>::err(rr.error(), rr.message());
        Reader r = rr.value();
        ResStringRecord rs;
        auto mod = r.u16();
        auto name = read_v2_string(r);
        auto tdef = read_v2_string(r);
        auto ctx = read_v2_string(r);
        if (!mod.has_value() || !name.has_value() || !tdef.has_value() ||
            !ctx.has_value()) {
            return Result<KbData>::err(ErrorCode::truncated, "short resstring record");
        }
        rs.module_id = mod.value();
        rs.name = std::move(name.value());
        rs.type_def = std::move(tdef.value());
        rs.context = std::move(ctx.value());
        data.resstrings.push_back(std::move(rs));
    }

    return Result<KbData>::ok(std::move(data));
}

}  // namespace idr::kb
