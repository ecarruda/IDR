# IDR Reborn — Phase 1 (KB Builder: Lossless v2→v3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `idr_kb` v3 format a lossless representation of legacy v2 knowledge bases, and add a `kbbuilder` executable that converts v2→v3 and verifies the conversion.

**Architecture:** Extend the existing `idr_kb` model (`KbData`) with the tables and fields v2 carries but Phase 0 dropped (`Vars`, `ResStrings`, dump `Fixups`, proc `Locals`, module use-names), teach the v3 serializer/reader to carry them, complete the legacy v2 reader, and add a structural-equality helper `kb_equal` that defines KB equivalence. A thin `kbbuilder` app wraps `open`→`write_v3`→`kb_equal`.

**Tech Stack:** C++20, MSVC v143 (VS 2022), CMake ≥ 3.25, GoogleTest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-12-idr-reborn-phase1-kb-builder-design.md`

## Global Constraints

- **Language/toolchain:** C++20, MSVC v143 (VS 2022), CMake ≥ 3.25, Windows. `/W4 /permissive- /Zc:__cplusplus`.
- **Dependencies:** permissive only (Zydis, GoogleTest already fetched via `FetchContent`). Nothing added.
- **Error model (spec §8, Tier A):** readers operate on `std::span<const std::byte>` and are bounds-checked; parsing returns `idr::Result<T>`; **no exceptions cross module boundaries**.
- **Determinism:** `write_v3` is a pure function of the `KbData`; analysis/builder code is UI-free (spec §9).
- **Namespaces/targets:** extend `idr::kb`; new executable `kbbuilder`; no change to `idr_cli`/`idr_gui`.
- **v3 format:** keep magic `IDRKB` and `formatVersion = 3`; bodies gain fields (the format is pre-release — no v3 corpus exists).
- **Commits:** one commit per task, message prefix `feat:` / `test:` / `chore:`.
- **Fixture truth (measured):** `syskb2014.bin` holds modules=2, consts=394, types=451, vars=82, resstrings=0, procs=1195, `delphiVer=0`. `syskb2.bin` is the only committed fixture whose proc records carry a `Locals` block.

## Review Focus

Failure modes the spec implies but no single happy-path test catches; the owning task pins each:

1. **Derived length prefixes mis-sized** — `DumpTotal`, `ArgsTotal`, `FieldsTotal` and the type leading `Size` are *not* stored; the converter recomputes them. A wrong recompute corrupts every record downstream and can still "read" without error. *(Task 3 parity over a real 200 MB KB.)*
2. **The optional proc `Locals` block** — present in `syskb2.bin`, absent in every other fixture; a reader that assumes it exists desyncs the entire proc table. *(Task 2 `syskb2` test.)*
3. **PSTR edge cases** — `WORD len` + `len` bytes + a trailing NUL (consume `len + 3`); length can be 0 (empty trailing `AbsName`) and up to 65535. An off-by-one in the +3 desyncs the record. *(Task 2 reads real module/var records; Task 3 parity.)*
4. **Silently dropped tables** — `Vars`/`ResStrings` were parsed then discarded; if not materialized, a conversion loses data without error. *(Task 2 count assertions; Task 3 parity.)*
5. **Scale & determinism** — the converter must be reproducible and must not silently truncate a large KB. *(Task 1 determinism test; Task 3 opt-in 200 MB parity test.)*

---

### Task 1: Schema extension, v3 round-trip, and `kb_equal`

**Files:**
- Modify: `include/idr/kb/records.hpp`
- Modify: `libs/kb/src/v3_io.cpp`
- Create: `libs/kb/src/kb_equal.cpp`
- Modify: `libs/kb/CMakeLists.txt`
- Test: `libs/kb/tests/kb_test.cpp`

**Interfaces:**
- Consumes: existing `idr::kb::{KbData,ModuleRecord,ConstRecord,TypeRecord,ProcRecord,Arch}`, `idr::Result`.
- Produces (new/changed model):
  - `struct VarRecord { uint16_t module_id = 0; std::string name; char type = 0; std::string type_def; std::string abs_name; };`
  - `struct ResStringRecord { uint16_t module_id = 0; std::string name; std::string type_def; std::string context; };`
  - `ModuleRecord`: add `std::vector<std::string> uses_names;`
  - `ConstRecord`: add `std::vector<std::byte> fixups;`
  - `TypeRecord`: add `std::vector<std::byte> fixups;`
  - `ProcRecord`: **change** `std::vector<uint32_t> fixups` → `std::vector<std::byte> fixups;` and add `std::vector<std::byte> locals;`
  - `KbData`: add `std::vector<VarRecord> vars;` and `std::vector<ResStringRecord> resstrings;`
  - `bool kb_equal(const KbData& a, const KbData& b);` — **declared in `records.hpp`**, defined in `kb_equal.cpp`.
- Produces (wire): v3 gains sections `5 = Vars`, `6 = ResStrings`; `kSectionCount = 6`.

- [ ] **Step 1: Write the failing tests** — append to `libs/kb/tests/kb_test.cpp`:

```cpp
TEST(KbV3, round_trips_all_sections_and_raw_fields) {
    KbData kb;
    kb.arch = idr::kb::Arch::x86;
    kb.vendor = "embarcadero";
    kb.vendor_code = 1;
    kb.compiler_version = 2014;
    kb.compiler_id = "XE4";
    kb.pointer_size = 4;

    ModuleRecord m;
    m.id = 1; m.name = "System"; m.filename = "System.dcu";
    m.uses_ids = {0xFFFF, 2};
    m.uses_names = {"kernel32.dll", "System"};
    kb.modules.push_back(m);

    ConstRecord c;
    c.module_id = 1; c.name = "c1"; c.type = 'C';
    c.type_def = "Integer"; c.value = "1";
    c.dump = {std::byte{0xAA}}; c.relocs = {std::byte{0x00}};
    c.fixups = {std::byte{0x41}, std::byte{0x04}, std::byte{0x00}};
    kb.consts.push_back(c);

    TypeRecord t;
    t.module_id = 1; t.name = "T"; t.kind = 'F'; t.vmt_count = 2;
    t.decl = "T = class"; t.dump = {std::byte{0x01}}; t.relocs = {std::byte{0x00}};
    t.fixups = {std::byte{0x44}};
    t.fields = {std::byte{0x01}, std::byte{0x00}};
    t.props = {std::byte{0x00}, std::byte{0x00}};
    t.methods = {std::byte{0x01}, std::byte{0x00}};
    kb.types.push_back(t);

    VarRecord v;
    v.module_id = 1; v.name = "g"; v.type = 'V'; v.type_def = "Integer"; v.abs_name = "";
    kb.vars.push_back(v);

    ResStringRecord rs;
    rs.module_id = 1; rs.name = "s"; rs.type_def = "string"; rs.context = "System";
    kb.resstrings.push_back(rs);

    ProcRecord p;
    p.module_id = 1; p.name = "F"; p.dump_type = 'C'; p.method_kind = 'F'; p.call_kind = 3;
    p.result_type = "Integer";
    p.dump = {std::byte{0x55}}; p.relocs = {std::byte{0x00}};
    p.fixups = {std::byte{0x41}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    p.locals = {std::byte{0x00}, std::byte{0x00}};
    kb.procs.push_back(p);

    const auto path = temp_path("allroundtrip");
    ASSERT_TRUE(idr::kb::write_v3(path, kb).has_value());
    auto opened = KnowledgeBase::open(path);
    ASSERT_TRUE(opened.has_value()) << opened.message();

    KbData expected = kb;
    expected.format_version = 3;  // write_v3 always emits v3
    EXPECT_TRUE(idr::kb::kb_equal(expected, opened.value().data()));
    EXPECT_EQ(opened.value().data().vars.size(), 1u);
    EXPECT_EQ(opened.value().data().resstrings.size(), 1u);
    fs::remove(path);
}

TEST(KbV3, kb_equal_detects_a_field_difference) {
    KbData a;
    a.procs.push_back(ProcRecord{});
    a.procs[0].name = "A";
    KbData b = a;
    EXPECT_TRUE(idr::kb::kb_equal(a, b));
    b.procs[0].name = "B";
    EXPECT_FALSE(idr::kb::kb_equal(a, b));
}

TEST(KbV3, write_read_write_is_byte_identical) {
    KbData kb = make_sample_kb();
    const auto p1 = temp_path("det1");
    ASSERT_TRUE(idr::kb::write_v3(p1, kb).has_value());
    auto opened = KnowledgeBase::open(p1);
    ASSERT_TRUE(opened.has_value());
    const auto p2 = temp_path("det2");
    ASSERT_TRUE(idr::kb::write_v3(p2, opened.value().data()).has_value());

    auto read_all = [](const fs::path& p) {
        std::ifstream in(p, std::ios::binary | std::ios::ate);
        std::vector<std::byte> v(static_cast<size_t>(in.tellg()));
        in.seekg(0);
        in.read(reinterpret_cast<char*>(v.data()), static_cast<std::streamsize>(v.size()));
        return v;
    };
    EXPECT_EQ(read_all(p1), read_all(p2));
    fs::remove(p1); fs::remove(p2);
}
```

Also, in `make_sample_kb()` change `proc.fixups = {0x00000004, 0x00000008};` to raw bytes:
`proc.fixups = {std::byte{0x04}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};`
(The existing `EXPECT_EQ(proc.fixups, kb.procs[0].fixups)` at `kb_test.cpp:139` then compares `vector<byte>` on both sides and still compiles.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `ctest --preset windows-x64-debug -R idr_kb`
Expected: build error — `VarRecord`/`ResStringRecord`/`uses_names`/`fixups` (as bytes)/`locals`/`kb_equal` do not exist yet.

- [ ] **Step 3: Extend `records.hpp`** with the new structs and fields exactly as in the Interfaces block above.

- [ ] **Step 4: Extend `v3_io.cpp`.** Add `kSectionVars = 5`, `kSectionResStrings = 6`, set `kSectionCount = 6`; write/read bodies for the new record types; add `uses_names` to the module body, `fixups` to const/type bodies, and `fixups`(bytes)+`locals` to the proc body. Keep the existing tagged length-prefixed record framing. Bound any untrusted count before `reserve()` as the existing readers do.

- [ ] **Step 5: Implement `kb_equal` in `libs/kb/src/kb_equal.cpp`.** Compare `arch`, `vendor`, `vendor_code`, `compiler_version`, `compiler_id`, `pointer_size`, then each record vector element-by-element (all scalars and all blobs). **Do not** compare `format_version` (a v2→v3 conversion legitimately changes it; content is what parity means). Add `src/kb_equal.cpp` to `idr_kb` in `libs/kb/CMakeLists.txt`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `ctest --preset windows-x64-debug -R idr_kb`
Expected: all pass, no unexpected skips.

- [ ] **Step 7: Commit**

```bash
git add include/idr/kb/records.hpp libs/kb
git commit -m "feat(kb): lossless v3 schema (vars, resstrings, fixups, locals)"
```

---

### Task 2: Complete the v2 reader

**Files:**
- Modify: `libs/kb/src/v2_read.cpp`
- Test: `libs/kb/tests/kb_test.cpp`

**Interfaces:**
- Consumes: the Task 1 model (`VarRecord`, `ResStringRecord`, `uses_names`, raw `fixups`, `locals`).
- Produces: `read_v2` fills every model field. Record layouts (pinned against `KnowledgeBase.cpp` / `KnowledgeBase.h`):
  - **String (`PSTR`):** `u16 len` → `len` bytes → **1 NUL** (consume `len + 3`).
  - **Modules:** `u16 id`, `PSTR name`, `PSTR filename`, `u16 uses_num`, `uses_num × u16 ids`, `uses_num × PSTR use_names`.
  - **Consts/Types/Procs dump block:** `u32 dump_total`, `u32 dump_size`, `u32 fixup_num`, `dump_size` bytes dump, `dump_size` bytes relocs, `dump_total - 8 - 2*dump_size` raw fixup bytes.
  - **Types:** after the dump block, three raw blocks: `u32 total` then `total` bytes (the bytes include the block's own `u16` count) for `fields`, `props`, `methods`.
  - **Procs:** after the dump block, `u32 args_total` + `args_total` bytes (contains `u16 args_num` + `args_num × ARGINFO`); then, **only if bytes remain in the record**, `u32 locals_total` + `locals_total` bytes → `locals`; otherwise `locals` stays empty.
  - **Vars:** `u16 module_id`, `PSTR name`, `u8 type`, `PSTR type_def`, `PSTR abs_name` (always present, may be empty).
  - **ResStrings:** `u16 module_id`, `PSTR name`, `PSTR type_def`, `PSTR context`.
  - Header facts for a v2 file: `arch = Arch::x86` (or `unknown` if `isMSIL` at offset 24 is non-zero), `vendor = "embarcadero"`, `vendor_code = 1`, `pointer_size = 4`, `compiler_version = delphiVer`.

- [ ] **Step 1: Write the failing tests** — append to `libs/kb/tests/kb_test.cpp`:

```cpp
TEST(KbLegacyV2, reads_all_sections_with_expected_counts) {
    const fs::path fixture = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    if (!fs::exists(fixture)) GTEST_SKIP() << "syskb2014.bin absent";

    auto opened = KnowledgeBase::open(fixture);
    ASSERT_TRUE(opened.has_value()) << opened.message();
    const auto& d = opened.value().data();

    EXPECT_EQ(d.modules.size(), 2u);
    EXPECT_EQ(d.consts.size(), 394u);
    EXPECT_EQ(d.types.size(), 451u);
    EXPECT_EQ(d.vars.size(), 82u);
    EXPECT_EQ(d.resstrings.size(), 0u);
    EXPECT_EQ(d.procs.size(), 1195u);

    // Header facts implied by a non-MSIL v2 file.
    EXPECT_EQ(d.arch, idr::kb::Arch::x86);
    EXPECT_EQ(d.vendor, "embarcadero");
    EXPECT_EQ(d.pointer_size, 4u);

    // Module use-names are materialized (previously dropped).
    ASSERT_FALSE(d.modules.empty());
    EXPECT_FALSE(d.modules[0].uses_names.empty());
    EXPECT_EQ(d.modules[0].uses_names.size(), d.modules[0].uses_ids.size());

    // A dumped record carries raw fixup bytes when the file records any.
    const bool saw_fixups = std::any_of(d.consts.begin(), d.consts.end(),
                                        [](const idr::kb::ConstRecord& c) {
                                            return !c.fixups.empty();
                                        });
    EXPECT_TRUE(saw_fixups);

    // Vars decode: at least one named var with a type.
    ASSERT_FALSE(d.vars.empty());
    EXPECT_FALSE(d.vars[0].name.empty());
}

TEST(KbLegacyV2, reads_proc_locals_when_present) {
    const fs::path fixture = fs::path(IDR_REPO_ROOT) / "syskb2.bin";
    if (!fs::exists(fixture)) GTEST_SKIP() << "syskb2.bin absent";

    auto opened = KnowledgeBase::open(fixture);
    ASSERT_TRUE(opened.has_value()) << opened.message();
    const auto& d = opened.value().data();

    const bool saw_locals = std::any_of(d.procs.begin(), d.procs.end(),
                                        [](const idr::kb::ProcRecord& p) {
                                            return !p.locals.empty();
                                        });
    EXPECT_TRUE(saw_locals);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ctest --preset windows-x64-debug -R idr_kb`
Expected: FAIL — `vars.size()` is 0 (not read), `uses_names` empty, `fixups`/`locals` empty.

- [ ] **Step 3: Complete `v2_read.cpp`.**
  - Replace `read_dump_and_skip_fixups` with `read_dump(r, dump, relocs, fixups)` capturing the raw fixup blob (`fixup_bytes = dump_total - 8 - 2*dump_size`); bound-check `dump_total >= 8 + 2*dump_size`.
  - Modules: also read `uses_num` trailing `PSTR` use-names into `uses_names`.
  - Types: keep the three raw blocks (already read) — no change beyond `fixups`.
  - Procs: capture raw `locals` only when the record has bytes remaining after the args block.
  - Add Vars and ResStrings loops over the already-parsed offset tables; set the header facts (`arch`, `vendor`, `vendor_code`, `pointer_size`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `ctest --preset windows-x64-debug -R idr_kb`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add libs/kb
git commit -m "feat(kb): complete legacy v2 reader (vars, resstrings, fixups, locals)"
```

---

### Task 3: Parity harness over real KBs

**Files:**
- Create: `libs/kb/tests/parity_test.cpp`
- Modify: `libs/kb/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `KnowledgeBase::open`, `write_v3`, `kb_equal`.
- Produces: the phase gate — the assertion `kb_equal(read_v2(f), read_v3(write_v3(read_v2(f))))`.

- [ ] **Step 1: Write the failing test** — `libs/kb/tests/parity_test.cpp`:

```cpp
#include <gtest/gtest.h>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "idr/kb/knowledge_base.hpp"

namespace fs = std::filesystem;

namespace {

// Reads `fixture` (v2), converts to v3, reads it back, and asserts content
// equality. Returns false only when a step failed (so callers can ASSERT).
// Content equality ignores the container format_version (see kb_equal), so a
// v2->v3 conversion is expected to compare equal.
testing::AssertionResult v2_v3_round_trip_is_lossless(const fs::path& fixture) {
    auto v2 = idr::kb::KnowledgeBase::open(fixture);
    if (!v2.has_value()) return testing::AssertionFailure() << v2.message();

    const fs::path out = fs::temp_directory_path() / "idr_parity.v3.bin";
    if (!idr::kb::write_v3(out, v2.value().data()).has_value()) {
        return testing::AssertionFailure() << "write_v3 failed";
    }
    auto v3 = idr::kb::KnowledgeBase::open(out);
    fs::remove(out);
    if (!v3.has_value()) return testing::AssertionFailure() << v3.message();

    if (!idr::kb::kb_equal(v2.value().data(), v3.value().data())) {
        return testing::AssertionFailure() << "content differs after v2->v3";
    }
    return testing::AssertionSuccess();
}

}  // namespace

TEST(KbParity, syskb2014_round_trips_losslessly) {
    const fs::path f = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    if (!fs::exists(f)) GTEST_SKIP() << "syskb2014.bin absent";
    EXPECT_TRUE(v2_v3_round_trip_is_lossless(f));
}

TEST(KbParity, syskb2_locals_round_trip_losslessly) {
    const fs::path f = fs::path(IDR_REPO_ROOT) / "syskb2.bin";
    if (!fs::exists(f)) GTEST_SKIP() << "syskb2.bin absent";
    EXPECT_TRUE(v2_v3_round_trip_is_lossless(f));
}

TEST(KbParity, scale_fixture_round_trips_when_env_set) {
    const char* env = std::getenv("IDR_KB_SCALE_FIXTURE");
    if (env == nullptr || *env == '\0') {
        GTEST_SKIP() << "set IDR_KB_SCALE_FIXTURE to a full kb*.bin to run";
    }
    const fs::path f = env;
    if (!fs::exists(f)) GTEST_SKIP() << "scale fixture absent: " << f.string();
    EXPECT_TRUE(v2_v3_round_trip_is_lossless(f));
}
```

- [ ] **Step 2: Register the test file and verify it fails**

Modify `libs/kb/tests/CMakeLists.txt`:
`add_executable(idr_kb_tests kb_test.cpp parity_test.cpp)`

Run: `ctest --preset windows-x64-debug -R idr_kb`
Expected: FAIL (content differs) if Tasks 1–2 are incomplete; with them done, PASS.

- [ ] **Step 3: Run the opt-in scale parity** (manual verification of the exit criterion)

Extract a full KB once with 7-Zip, then run:
```powershell
& "C:\Program Files\7-Zip\7z.exe" x -y -o"$env:TEMP\idrkb" kb2014.7z
$env:IDR_KB_SCALE_FIXTURE = "$env:TEMP\idrkb\kb2014.bin"
ctest --preset windows-x64-debug -R KbParity
```
Expected: `syskb2014` and `syskb2` pass; the scale test passes on the 200 MB `kb2014.bin`.

- [ ] **Step 4: Commit**

```bash
git add libs/kb/tests
git commit -m "test(kb): v2->v3 lossless parity harness over real KBs"
```

---

### Task 4: `kbbuilder` executable

**Files:**
- Create: `apps/kbbuilder/CMakeLists.txt`
- Create: `apps/kbbuilder/src/kb_tool.hpp`, `apps/kbbuilder/src/kb_tool.cpp`, `apps/kbbuilder/src/main.cpp`
- Create: `apps/kbbuilder/tests/CMakeLists.txt`, `apps/kbbuilder/tests/kb_tool_test.cpp`
- Modify: `CMakeLists.txt` (add `add_subdirectory(apps/kbbuilder)`)

**Interfaces:**
- Consumes: `idr::kb::KnowledgeBase::open`, `idr::kb::write_v3`, `idr::kb::kb_equal`, `idr::Result`.
- Produces:
  - `std::string kb_info(const std::filesystem::path& kb);`
  - `idr::Result<void> kb_convert(const std::filesystem::path& in, const std::filesystem::path& out);`
  - `idr::Result<void> kb_verify(const std::filesystem::path& in);`
  - CLI: `kbbuilder info <kb>` · `kbbuilder convert <v2-in> <v3-out>` · `kbbuilder verify <v2-in>`; exit codes 0 success, 1 operation failure, 2 usage error.

- [ ] **Step 1: Write the failing test** — `apps/kbbuilder/tests/kb_tool_test.cpp`:

```cpp
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "kb_tool.hpp"

namespace fs = std::filesystem;

TEST(KbTool, info_reports_sections_of_a_real_v2_kb) {
    const fs::path f = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    if (!fs::exists(f)) GTEST_SKIP() << "syskb2014.bin absent";

    const std::string info = kb_info(f);
    EXPECT_NE(info.find("arch: x86"), std::string::npos);
    EXPECT_NE(info.find("procs: 1195"), std::string::npos);
    EXPECT_NE(info.find("vars: 82"), std::string::npos);
}

TEST(KbTool, convert_then_verify_a_real_v2_kb) {
    const fs::path in = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    if (!fs::exists(in)) GTEST_SKIP() << "syskb2014.bin absent";

    const fs::path out = fs::temp_directory_path() / "kbbuilder_out.v3.bin";
    auto converted = kb_convert(in, out);
    ASSERT_TRUE(converted.has_value()) << converted.message();
    ASSERT_TRUE(fs::exists(out));

    auto verified = kb_verify(in);
    EXPECT_TRUE(verified.has_value()) << verified.message();

    fs::remove(out);
}

TEST(KbTool, convert_reports_error_on_non_kb_input) {
    const fs::path bad = fs::temp_directory_path() / "kbbuilder_bad.bin";
    { std::ofstream(bad, std::ios::binary) << "not a kb"; }
    const fs::path out = fs::temp_directory_path() / "kbbuilder_bad.v3.bin";
    EXPECT_FALSE(kb_convert(bad, out).has_value());
    fs::remove(bad);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ctest --preset windows-x64-debug -R kbbuilder`
Expected: FAIL — target/`kb_tool.hpp` do not exist.

- [ ] **Step 3: Implement `kb_tool.cpp`.**
  - `kb_info`: `open` then format a fixed line-per-field report:
    `format version: N`, `arch: <x86|x64|unknown>`, `vendor: <...>`, `compiler version: N`,
    `compiler id: <...>`, `pointer size: N`, `modules: N`, `consts: N`, `types: N`, `vars: N`,
    `resstrings: N`, `procs: N`.
  - `kb_convert`: `open(in)` → `write_v3(out, data)`.
  - `kb_verify`: temp path = `in`'s filename + `.verify.v3.bin` in `temp_directory_path()`;
    `open(in)` → `write_v3(tmp)` → `open(tmp)` → `kb_equal`; remove `tmp`; `err(ErrorCode::unsupported_format, "content differs")` on mismatch.

- [ ] **Step 4: Implement `main.cpp`** mirroring `apps/idr-cli/src/main.cpp`: subcommand dispatch, an MSVC SEH guard around the operation, usage error → exit 2, operation failure → exit 1 (message to `stderr`), success → exit 0.

- [ ] **Step 5: Wire the build.** `apps/kbbuilder/CMakeLists.txt`:
```cmake
add_library(kbbuilder_core STATIC src/kb_tool.cpp)
target_link_libraries(kbbuilder_core PUBLIC idr_common idr_kb)
target_include_directories(kbbuilder_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(kbbuilder src/main.cpp)
target_link_libraries(kbbuilder PRIVATE kbbuilder_core)

add_subdirectory(tests)
```
`apps/kbbuilder/tests/CMakeLists.txt`:
```cmake
add_executable(kbbuilder_tests kb_tool_test.cpp)
target_link_libraries(kbbuilder_tests PRIVATE kbbuilder_core GTest::gtest_main)
target_compile_definitions(kbbuilder_tests PRIVATE IDR_REPO_ROOT="${CMAKE_SOURCE_DIR}")
include(GoogleTest)
gtest_discover_tests(kbbuilder_tests TEST_PREFIX "kbbuilder.")
```
Append `add_subdirectory(apps/kbbuilder)` to the top-level `CMakeLists.txt`.

- [ ] **Step 6: Run the full suite**

Run: `cmake --preset windows-x64-debug`, `cmake --build --preset windows-x64-debug`, `ctest --preset windows-x64-debug`
Expected: all tests pass; no new warnings.

- [ ] **Step 7: Commit**

```bash
git add apps/kbbuilder CMakeLists.txt
git commit -m "feat(kbbuilder): v2->v3 convert/verify/info CLI"
```

---

## Phase 1 exit criteria

- `ctest --preset windows-x64-debug` builds clean and all tests pass (including `KbParity`).
- `kb_equal(read_v2(f), read_v3(write_v3(read_v2(f))))` on `syskb2014.bin`, `syskb2.bin`, and (opt-in) the 200 MB `kb2014.bin`.
- `kbbuilder convert <v2> <v3>` produces a v3 file that `kbbuilder verify` accepts, and `kbbuilder info` reports the
  section counts of both v2 and v3 inputs.
- v3 carries vars, resstrings, fixups, locals, and module use-names byte-exact.