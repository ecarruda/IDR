# IDR Reborn — Phase 0 (Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the portable IDR Reborn core and a headless `idr-cli` that loads a Delphi PE, detects architecture/vendor/version, disassembles, and reports sections/imports/RTTI roots.

**Architecture:** A CMake/MSVC C++20 workspace of small static libraries (`idr_common`, `idr_pe`, `idr_disasm`, `idr_kb`, `idr_target`) consumed by thin executables (`idr_cli`). All binary readers are bounds-checked and return `Result<T>`; no exceptions cross module boundaries. The disassembler wraps Zydis behind `IDisassembler`. `TargetProfile` replaces the legacy global `int DelphiVersion`.

**Tech Stack:** C++20, MSVC v143 (Visual Studio 2022), CMake ≥ 3.25, GoogleTest (tests), Zydis (disassembly). Dependencies fetched via CMake `FetchContent` (no external package manager required).

**Spec:** `docs/superpowers/specs/2026-10-10-idr-reborn-design.md`

## Global Constraints

- **Language/toolchain:** C++20, MSVC v143 (VS 2022), CMake ≥ 3.25, Windows. `/W4 /permissive- /Zc:__cplusplus`.
- **Dependencies:** permissive licenses only — Zydis (MIT), GoogleTest (BSD-3). Acquired via `FetchContent`; nothing else added without a spec change.
- **Error model (spec §8, Tier A):** binary readers operate on `std::span<const std::byte>` and are bounds-checked; parsing returns `idr::Result<T>`; **no exceptions cross module boundaries**.
- **Determinism:** analysis code is UI-free and deterministic (spec §9). No prompts, no global mutable version state.
- **Namespaces/targets:** `idr::common`, `idr::pe`, `idr::disasm`, `idr::kb`, `idr::target`; library targets `idr_common`, `idr_pe`, `idr_disasm`, `idr_kb`, `idr_target`; executables `idr_cli` (and later `idr_gui`, `kbbuilder`).
- **Deferred:** decompiler, GUI, and FPC support are **out of Phase 0**. `idr-kb` must still read legacy v2 `kb*.bin`.
- **Commits:** one commit per task, message prefix `feat:` / `test:` / `chore:`.

## Review Focus

Failure modes the spec implies but no single task's happy-path tests catch; the owning task's tests pin each:

1. **Truncated PE** — a file shorter than the DOS+NT headers must return `ErrorCode::truncated`, never read past the buffer. *(Task 2)*
2. **Section table / raw data beyond file end** — `rva_to_offset` and `at_rva` must bound-check and return no-value / error rather than compute an out-of-range offset. *(Task 2)*
3. **PE32+ mistaken for PE32** — 64-bit images are identified by `Magic == 0x20B`, not `0x10B`; a PE32+ must report `Arch::x64` and 8-byte pointers. *(Task 2)*
4. **Unknown/newer KB format** — bad magic or `formatVersion` not in {2, 3} must fail cleanly instead of misparsing. *(Task 5)*
5. **Empty/oversized KB dump during scan** — a zero-length or larger-than-code dump must return "no match", not divide by zero or read OOB. *(Task 6)*

Plus: non-PE / non-Delphi input must yield a clean "unknown" report from the CLI, not a crash. *(Task 9)*

---

### Task 1: Project skeleton, `idr_common`, and the test harness

**Files:**
- Create: `CMakeLists.txt`
- Create: `cmake/Dependencies.cmake`
- Create: `CMakePresets.json`
- Create: `include/idr/common/error.hpp`
- Create: `include/idr/common/result.hpp`
- Create: `libs/common/CMakeLists.txt`
- Create: `libs/common/tests/result_test.cpp`
- Create: `libs/common/tests/CMakeLists.txt`
- Modify: `.gitignore` (add `build/`)
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `namespace idr { enum class ErrorCode { ok, truncated, bad_magic, unsupported_format, unsupported_version, out_of_range, io_error, not_found }; using Bytes = std::span<const std::byte>; }`
  - `namespace idr { template <class T> class Result; }` with `static Result ok(T)`, `static Result err(ErrorCode, std::string = "")`, `bool has_value() const`, `T& value()`, `const T& value() const`, `ErrorCode error() const`, `const std::string& message() const`.

- [ ] **Step 1: Write the failing tests** — `libs/common/tests/result_test.cpp`

```cpp
#include <gtest/gtest.h>
#include "idr/common/result.hpp"

TEST(Result, ok_holds_value) {
    auto r = idr::Result<int>::ok(42);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r.value(), 42);
}

TEST(Result, err_reports_code_and_message) {
    auto r = idr::Result<int>::err(idr::ErrorCode::truncated, "short buffer");
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), idr::ErrorCode::truncated);
    EXPECT_EQ(r.message(), "short buffer");
}
```

- [ ] **Step 2: Write the build files** — `CMakeLists.txt`, `cmake/Dependencies.cmake`, `libs/common/CMakeLists.txt`, `libs/common/tests/CMakeLists.txt`, `CMakePresets.json`.

Top-level `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.25)
project(idr_reborn LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if (MSVC)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus)
endif()
include(cmake/Dependencies.cmake)
enable_testing()
add_subdirectory(libs/common)
```

`cmake/Dependencies.cmake`:

```cmake
include(FetchContent)
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.15.2)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG v4.1.0)
FetchContent_MakeAvailable(zydis)
```

`libs/common/CMakeLists.txt`:

```cmake
add_library(idr_common INTERFACE)
target_include_directories(idr_common INTERFACE ${CMAKE_SOURCE_DIR}/include)
add_subdirectory(tests)
```

`libs/common/tests/CMakeLists.txt`:

```cmake
add_executable(idr_common_tests result_test.cpp)
target_link_libraries(idr_common_tests PRIVATE idr_common GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(idr_common_tests)
```

`CMakePresets.json` (configure + build + test presets for `windows-x64-debug`/`release`, generator `Visual Studio 17 2022`, `architecture: x64`, binary dir `build/${presetName}`).

- [ ] **Step 3: Implement `error.hpp` and `result.hpp`.**

`error.hpp` defines `ErrorCode` and `Bytes` (via `std::span`). `result.hpp` defines `template <class T> class Result` storing `std::optional<T>` plus `ErrorCode` and `std::string`. Use `T& value()` returning `*opt` (precondition: `has_value()`).

- [ ] **Step 4: Configure, build, and run tests.**

Run: `cmake --preset windows-x64-debug` then `cmake --build --preset windows-x64-debug` then `ctest --preset windows-x64-debug`
Expected: 2 tests pass. If `FetchContent` cannot reach the network, record that and stop — the build must not silently skip the tests.

- [ ] **Step 5: Add `.github/workflows/ci.yml` and `.gitignore`.** CI: Windows runner, checkout, configure/build/test via the debug preset. Add `build/` to `.gitignore`.

- [ ] **Step 6: Commit.**

```bash
git add CMakeLists.txt cmake CMakePresets.json include libs .github .gitignore
git commit -m "chore: phase-0 project skeleton, idr_common, and test harness"
```

---

### Task 2: `idr_pe` — headers, sections, and RVA mapping

**Files:**
- Create: `include/idr/pe/image.hpp`
- Create: `libs/pe/CMakeLists.txt`, `libs/pe/src/image.cpp`
- Create: `libs/pe/tests/CMakeLists.txt`, `libs/pe/tests/image_test.cpp`, `libs/pe/tests/pe_builder.hpp`
- Modify: `CMakeLists.txt` (add `add_subdirectory(libs/pe)`)

**Interfaces:**
- Consumes: `idr::Result`, `idr::ErrorCode`, `idr::Bytes`.
- Produces:
  - `namespace idr::pe { enum class Arch { unknown, x86, x64 }; }`
  - `struct Section { std::string name; uint32_t virtual_address; uint32_t virtual_size; uint32_t raw_offset; uint32_t raw_size; uint32_t characteristics; };`
  - `class PeFile` with: `static Result<PeFile> parse(Bytes)`; `Arch arch() const`; `bool is_64() const`; `uint64_t image_base() const`; `uint32_t entry_point_rva() const`; `const std::vector<Section>& sections() const`; `std::optional<uint32_t> rva_to_offset(uint32_t) const`; `Result<Bytes> at_rva(uint32_t, size_t) const`.
  - Test helper `libs/pe/tests/pe_builder.hpp`: `std::vector<std::byte> make_minimal_pe(Arch, uint64_t image_base = 0x400000)`, producing a syntactically valid image with one `.text` section and zeroed data directories.
  - An `idr_test_support` INTERFACE target with `libs/pe/tests` on its include path, so later tasks (Task 9) can build synthetic images with `pe_builder.hpp`.

- [ ] **Step 1: Write the failing tests** — `image_test.cpp`

```cpp
#include <gtest/gtest.h>
#include "idr/pe/image.hpp"
#include "pe_builder.hpp"

TEST(PeFile, parses_pe32_arch_and_entry) {
    auto bytes = make_minimal_pe(idr::pe::Arch::x86);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    EXPECT_EQ(pe.value().arch(), idr::pe::Arch::x86);
    EXPECT_FALSE(pe.value().is_64());
    EXPECT_NE(pe.value().entry_point_rva(), 0u);
}

TEST(PeFile, parses_pe32plus_as_x64) {
    auto bytes = make_minimal_pe(idr::pe::Arch::x64, 0x140000000ull);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    EXPECT_EQ(pe.value().arch(), idr::pe::Arch::x64);
    EXPECT_TRUE(pe.value().is_64());
    EXPECT_EQ(pe.value().image_base(), 0x140000000ull);
}

TEST(PeFile, truncated_buffer_is_rejected) {
    std::vector<std::byte> bytes(16, std::byte{0});
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_FALSE(pe.has_value());
    EXPECT_EQ(pe.error(), idr::ErrorCode::truncated);
}

TEST(PeFile, rva_to_offset_maps_section_and_bounds_checks) {
    auto bytes = make_minimal_pe(idr::pe::Arch::x86);
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    ASSERT_EQ(pe.value().sections().size(), 1u);
    const uint32_t rva = pe.value().sections()[0].virtual_address;
    ASSERT_TRUE(pe.value().rva_to_offset(rva).has_value());
    EXPECT_FALSE(pe.value().at_rva(0xFFFFFF00u, 16).has_value());
}

TEST(PeFile, non_pe_is_rejected) {
    std::vector<std::byte> bytes(64, std::byte{'X'});
    bytes[0] = std::byte{'M'}; bytes[1] = std::byte{'Z'};
    auto pe = idr::pe::PeFile::parse(bytes);
    ASSERT_FALSE(pe.has_value());
    EXPECT_EQ(pe.error(), idr::ErrorCode::bad_magic);
}
```

- [ ] **Step 2: Run tests to verify they fail to build/link** (no `image.hpp` yet).

- [ ] **Step 3: Implement `image.cpp`.** Parse DOS header (`e_magic == 'MZ'`, `e_lfanew`), NT signature (`PE\0\0`), file header, optional header; select 32 vs 64 by `Magic` (`0x10B`=PE32, `0x20B`=PE32+). Read `NumberOfSections`, `AddressOfEntryPoint`, `ImageBase`. For each section header, read the 8-byte name (trim NULs), virtual/raw sizes and offsets. `rva_to_offset` finds the containing section (`VA <= rva < VA+VirtualSize`) and checks `rva - VA < RawSize`; `at_rva` checks the slice against the file buffer. Every read goes through a local bounds-checked reader that returns `ErrorCode::truncated`. Also create `libs/pe/CMakeLists.txt`: `add_library(idr_pe STATIC src/image.cpp)` linking `idr_common`, plus `add_library(idr_test_support INTERFACE)` with `target_include_directories(idr_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/tests)` and `add_subdirectory(tests)`.

- [ ] **Step 4: Run tests.** Run: `ctest --preset windows-x64-debug -R idr_pe`. Expected: all pass.

- [ ] **Step 5: Commit.**

```bash
git add include/idr/pe libs/pe CMakeLists.txt
git commit -m "feat(pe): PE32/PE32+ header, section, and RVA-mapping parser"
```

---

### Task 3: `idr_pe` — imports and exports

**Files:**
- Create: `include/idr/pe/directories.hpp`
- Create: `libs/pe/src/directories.cpp`
- Modify: `libs/pe/tests/image_test.cpp` (or add `directories_test.cpp`)

**Interfaces:**
- Consumes: `idr::pe::PeFile`.
- Produces:
  - `struct Import { std::string module; std::string name; bool by_ordinal; uint16_t ordinal; uint64_t iat_va; };`
  - `struct Export { std::string name; uint32_t rva; uint16_t ordinal; };`
  - `Result<std::vector<Import>> parse_imports(const PeFile&);`
  - `Result<std::vector<Export>> parse_exports(const PeFile&);`

- [ ] **Step 1: Write failing tests** — extend `pe_builder.hpp` with `add_import(module, {names...})` and `add_export(names...)` helpers; test that a PE built with one import of `KERNEL32.dll!GetProcAddress` yields one `Import` with that module/name, and that a PE with no import directory yields an empty vector (not an error).

- [ ] **Step 2: Run tests to verify they fail.**

- [ ] **Step 3: Implement `directories.cpp`.** Locate the data-directory array (offset `0x60` PE32 / `0x70` PE32+ relative to the optional header), index `1` (imports) and `0` (exports). Walk the import descriptors (null-terminated), then the ILT/IAT thunks: compute `iat_va = image_base + FirstThunk + i*ptr_size`; resolve names via the import-by-name table; detect ordinal imports (high bit set). For exports, walk the export directory's name/ordinal/function arrays. All reads bounds-checked via `PeFile::at_rva`; a missing directory returns an empty vector.

- [ ] **Step 4: Run tests.** Run: `ctest --preset windows-x64-debug -R idr_pe`. Expected: all pass.

- [ ] **Step 5: Commit.**

```bash
git add include/idr/pe/directories.hpp libs/pe
git commit -m "feat(pe): import and export directory parsing"
```

---

### Task 4: `idr_disasm` — `IDisassembler` over Zydis

**Files:**
- Create: `include/idr/disasm/disassembler.hpp`
- Create: `libs/disasm/CMakeLists.txt`, `libs/disasm/src/zydis_disassembler.cpp`
- Create: `libs/disasm/tests/CMakeLists.txt`, `libs/disasm/tests/disasm_test.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `idr::pe::Arch`, `idr::Result`.
- Produces:
  - `struct Instruction { uint64_t address; uint8_t length; std::string mnemonic; std::string text; bool is_call; bool is_jump; bool is_conditional; bool is_ret; bool is_relative; std::optional<uint64_t> branch_target; };`
  - `class IDisassembler { public: virtual ~IDisassembler() = default; virtual Result<Instruction> decode(uint64_t address, Bytes code) const = 0; virtual size_t pointer_size() const = 0; };`
  - `std::unique_ptr<IDisassembler> make_zydis(pe::Arch arch);`

- [ ] **Step 1: Write the failing tests** — `disasm_test.cpp`

```cpp
#include <gtest/gtest.h>
#include "idr/disasm/disassembler.hpp"

static std::vector<std::byte> bytes(std::initializer_list<int> xs) {
    std::vector<std::byte> v;
    for (int x : xs) v.push_back(static_cast<std::byte>(x));
    return v;
}

TEST(Zydis, decodes_mov_x64) {
    auto d = idr::disasm::make_zydis(idr::pe::Arch::x64);
    auto ins = d->decode(0x1000, bytes({0x48, 0x89, 0xE5}));
    ASSERT_TRUE(ins.has_value());
    EXPECT_EQ(ins.value().mnemonic, "mov");
    EXPECT_EQ(ins.value().length, 3);
}

TEST(Zydis, flags_ret_and_call) {
    auto d = idr::disasm::make_zydis(idr::pe::Arch::x86);
    auto ret = d->decode(0x1000, bytes({0xC3}));
    ASSERT_TRUE(ret.has_value());
    EXPECT_TRUE(ret.value().is_ret);
    auto call = d->decode(0x1000, bytes({0xE8, 0x00, 0x00, 0x00, 0x00}));
    ASSERT_TRUE(call.has_value());
    EXPECT_TRUE(call.value().is_call);
    EXPECT_TRUE(call.value().is_relative);
}

TEST(Zydis, truncated_instruction_errors) {
    auto d = idr::disasm::make_zydis(idr::pe::Arch::x64);
    auto ins = d->decode(0x1000, bytes({0x48, 0x89}));
    ASSERT_FALSE(ins.has_value());
    EXPECT_EQ(ins.error(), idr::ErrorCode::truncated);
}
```

- [ ] **Step 2: Run tests to verify they fail.**

- [ ] **Step 3: Implement `zydis_disassembler.cpp`.** Select `ZYDIS_MACHINE_MODE_LONG_64` or `LEGACY_32` and the matching `ZYDIS_STACK_WIDTH`. Call `ZydisDecoderDecodeFull`; on `ZYDIS_STATUS_NO_MORE_DATA`/insufficient length return `ErrorCode::truncated`; on other failures return `ErrorCode::unsupported_format`. Format with `ZydisFormatter` into `text`; set `mnemonic` lowercased; set flags from `ZydisDecodedInstruction.meta.category` and operand types; compute `branch_target` for rel8/rel32 from `address + length + disp`. Link `Zydis::Zydis`.

- [ ] **Step 4: Run tests.** Run: `ctest --preset windows-x64-debug -R idr_disasm`. Expected: all pass.

- [ ] **Step 5: Commit.**

```bash
git add include/idr/disasm libs/disasm CMakeLists.txt
git commit -m "feat(disasm): Zydis-backed IDisassembler for x86 and x64"
```

---

### Task 5: `idr_kb` — format v3 (write/read) and legacy v2 read

**Files:**
- Create: `include/idr/kb/records.hpp`, `include/idr/kb/knowledge_base.hpp`
- Create: `libs/kb/CMakeLists.txt`, `libs/kb/src/knowledge_base.cpp`, `libs/kb/src/v3_io.cpp`, `libs/kb/src/v2_read.cpp`
- Create: `libs/kb/tests/CMakeLists.txt`, `libs/kb/tests/kb_test.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `idr::Result`.
- Produces (spec §6):
  - `struct ArgRecord { uint8_t tag; bool in_register; int32_t reg_index; uint32_t size; std::string name; std::string type; };`
  - `struct ProcRecord { uint16_t module_id; std::string name; bool embedded; char dump_type; char method_kind; uint8_t call_kind; int32_t vproc; std::string result_type; std::vector<std::byte> dump; std::vector<std::byte> relocs; std::vector<uint32_t> fixups; std::vector<ArgRecord> args; };`
  - `struct ConstRecord { uint16_t module_id; std::string name; char type; std::string type_def; std::string value; std::vector<std::byte> dump; std::vector<std::byte> relocs; };`
  - `struct TypeRecord { uint16_t module_id; std::string name; uint8_t kind; uint16_t vmt_count; std::string decl; std::vector<std::byte> dump; std::vector<std::byte> relocs; std::vector<std::byte> fields; std::vector<std::byte> props; std::vector<std::byte> methods; };`
  - `struct ModuleRecord { uint16_t id; std::string name; std::string filename; std::vector<uint16_t> uses_ids; };`
  - `struct KbData { uint32_t format_version; std::string vendor; int32_t compiler_version; std::string compiler_id; uint8_t pointer_size; std::vector<ModuleRecord> modules; std::vector<ConstRecord> consts; std::vector<TypeRecord> types; std::vector<ProcRecord> procs; };`
  - `class KnowledgeBase { public: static Result<KnowledgeBase> open(std::filesystem::path); uint32_t format_version() const; const KbData& data() const; std::optional<size_t> find_proc(std::string_view name) const; std::optional<size_t> find_proc(uint16_t module_id, std::string_view name) const; };`
  - `Result<void> write_v3(std::filesystem::path, const KbData&);`

- [ ] **Step 1: Write the failing tests** — `kb_test.cpp`: build a `KbData` with one module, one proc (name `"StringCopy"`, a small `dump`), one type; `write_v3` to a temp path; `open` it back; assert `format_version() == 3`, that `find_proc("StringCopy")` resolves, that the round-tripped `dump` bytes and `args` are byte-identical. Add a test that `open` on a file with magic `"XXXX"` returns `ErrorCode::bad_magic`, and on a v3 header with `formatVersion == 99` returns `ErrorCode::unsupported_version`. Add a test that `open` on the repository's `kb2014.bin` (path passed via a test data dir, skipped if absent) returns `format_version() == 2` and a non-empty proc table.

- [ ] **Step 2: Run tests to verify they fail.**

- [ ] **Step 3: Implement.**
  - `v3_io.cpp`: header = magic `IDRKB`, `uint32_t formatVersion = 3`, `uint8_t arch`, `uint8_t vendor`, `int32_t compilerVersion`, length-prefixed `compilerId`, `uint8_t pointerSize`, length-prefixed `description`, `uint32_t sectionCount`, `uint32_t checksum`. Then a section directory `{uint32_t id, uint32_t count, uint64_t offset, uint64_t size}` per section, then sections with length-prefixed, little-endian, tagged records (per the structs above). All writes/reads bounds-checked on read.
  - `v2_read.cpp`: read magic + version, the `int kbVer` at the tail (mirror `MKnowledgeBase::Open`/`CheckKBFile` in `KnowledgeBase.cpp`), the `OFFSETSINFO`-style offset tables, and materialize `KbData`. v1 (`"IDD"`) may return `ErrorCode::unsupported_version` for now.

- [ ] **Step 4: Run tests.** Run: `ctest --preset windows-x64-debug -R idr_kb`. Expected: all pass (the `kb2014.bin` test runs when the fixture is present).

- [ ] **Step 5: Commit.**

```bash
git add include/idr/kb libs/kb CMakeLists.txt
git commit -m "feat(kb): KB format v3 read/write and legacy v2 reader"
```

---

### Task 6: `idr_kb` — dump fingerprint scan

**Files:**
- Modify: `include/idr/kb/knowledge_base.hpp` (add method)
- Modify: `libs/kb/src/knowledge_base.cpp`
- Modify: `libs/kb/tests/kb_test.cpp`

**Interfaces:**
- Consumes: `ProcRecord`, `Bytes`.
- Produces: `std::optional<uint32_t> scan_code(Bytes code, uint32_t code_base, const ProcRecord& probe) const;` — returns the image address where `probe.dump` matches `code` (applying `probe.relocs` as wildcards), or no value.

- [ ] **Step 1: Write the failing tests.** Build a `KbData` whose proc `dump = {0x55, 0x8B, 0xEC, 0xC3}` with empty relocs; assert `scan_code` over a code blob containing that sequence at offset 0x20 returns `code_base + 0x20`; assert a non-matching blob returns no value; assert a proc with an **empty** `dump` returns no value; assert a proc whose `dump` is **larger than the code** returns no value.

- [ ] **Step 2: Run tests to verify they fail.**

- [ ] **Step 3: Implement `scan_code`.** Port the byte-match loop from `MKnowledgeBase::ScanCode` (`KnowledgeBase.cpp:1682`): walk the code, at each candidate compare `dump` against code, skipping bytes flagged in `relocs`. Guard `dump.empty()` and `dump.size() > code.size()` up front. No relocation arithmetic is applied in Phase 0 (matching only).

- [ ] **Step 4: Run tests.** Run: `ctest --preset windows-x64-debug -R idr_kb`. Expected: all pass.

- [ ] **Step 5: Commit.**

```bash
git add include/idr/kb libs/kb
git commit -m "feat(kb): dump fingerprint scan with relocation wildcards"
```

---

### Task 7: `idr_target` — `TargetProfile`, VMT layouts, and detection

**Files:**
- Create: `include/idr/target/target_profile.hpp`
- Create: `libs/target/CMakeLists.txt`, `libs/target/src/target_profile.cpp`
- Create: `libs/target/tests/CMakeLists.txt`, `libs/target/tests/target_test.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `idr::pe::PeFile`, `idr::kb::KnowledgeBase`.
- Produces:
  - `enum class Vendor { unknown, embarcadero, fpc };`
  - `struct VmtLayout { int self_ptr, intf_table, auto_table, init_table, type_info, field_table, method_table, dynamic_table, class_name, instance_size, parent, safe_call, after_construction, before_destruction, dispatch, default_handler, new_instance, free_instance, destroy; };`
  - `VmtLayout vmt_layout_for(int version);` (values ported verbatim from `SetVmtConsts`, `Main.cpp:2004`).
  - `class TargetProfile { public: Vendor vendor() const; int version() const; pe::Arch arch() const; size_t pointer_size() const; const VmtLayout& vmt() const; std::string kb_file_name() const; static Result<TargetProfile> detect(const pe::PeFile&, const kb::KnowledgeBase& sys_kb); };`
  - `Result<TargetProfile> detect_embarcadero(const pe::PeFile&, const kb::KnowledgeBase& sys_kb);` implementing the `GetDelphiVersion` probe logic (`Main.cpp:1525`).

- [ ] **Step 1: Write the failing tests** — assert exact VMT constants ported from `SetVmtConsts`: `vmt_layout_for(7).type_info == -0x3C`, `vmt_layout_for(2009).type_info == -0x48`, `vmt_layout_for(2009).class_name == -0x38`, `vmt_layout_for(2010).self_ptr == -0x58`. Assert `TargetProfile` for a PE32+ reports `arch() == Arch::x64` and `pointer_size() == 8`, and `kb_file_name()` for version 2014 equals `"kb2014.bin"`.

- [ ] **Step 2: Run tests to verify they fail.**

- [ ] **Step 3: Implement.** Port the VMT constants from `SetVmtConsts`. Implement `detect`: arch from the PE; then `detect_embarcadero` — if the image has the extended init table (`IsExtendedInitTab` equivalent), scan `System`-module probe functions (`StringCopy`, `@FinalizeResStrings`, `@InitializeControlWord`, `ErrorAt`) against the code using `KnowledgeBase::scan_code`, returning 2014/2013/2012/2011 in order and 2010 as the fallback, mirroring `GetDelphiVersion` (`Main.cpp:1537-1625`). Legacy (<2010) heuristics: port the `TControl` instance-size check; if unresolved, return `ErrorCode::unsupported_version` (full legacy detection is Phase 2). `kb_file_name()` returns `"kb" + std::to_string(version) + ".bin"`.

- [ ] **Step 4: Run tests.** Run: `ctest --preset windows-x64-debug -R idr_target`. Expected: all pass.

- [ ] **Step 5: Commit.**

```bash
git add include/idr/target libs/target CMakeLists.txt
git commit -m "feat(target): TargetProfile, VMT layouts, and Delphi version detection"
```

---

### Task 8: `idr_analyze` — VMT/RTTI root candidates

**Files:**
- Create: `include/idr/analyze/vmt_roots.hpp`
- Create: `libs/analyze/CMakeLists.txt`, `libs/analyze/src/vmt_roots.cpp`
- Create: `libs/analyze/tests/CMakeLists.txt`, `libs/analyze/tests/vmt_roots_test.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `idr::pe::PeFile`, `idr::target::TargetProfile`, `idr::target::VmtLayout`.
- Produces: `namespace idr::analyze { std::vector<uint64_t> find_vmt_roots(const pe::PeFile&, const target::TargetProfile&); }` — returns the image addresses of pointer-aligned words that look like Delphi class VMTs.

- [ ] **Step 1: Write the failing tests.** Extend the PE test builder with `make_pe_with_data(Arch, const std::vector<std::byte>& data)` that appends a `.data` section. Build an image where a class-name shortstring (length byte `8`, then `"TControl"`) is placed, and a pointer word `w` is planted such that the word at `w + layout.class_name` points at that name and `w` is in-image; assert `find_vmt_roots` returns a vector containing `w`. Assert an image whose `.data` is all zeros returns an empty vector.

- [ ] **Step 2: Run tests to verify they fail.**

- [ ] **Step 3: Implement `vmt_roots.cpp`.** Iterate pointer-aligned words across the image; for each word `w` that is a valid in-image address, compute `name_ptr` by reading the word at `w + layout.class_name`; if `name_ptr` is in-image, read its 1-byte length `n` and the following `n` bytes; require `1 <= n <= 255` and all bytes printable ASCII, then record `w`. Use `PeFile::at_rva`/`rva_to_offset` for every read; skip silently on out-of-range. Link `idr_pe` and `idr_target`.

- [ ] **Step 4: Run tests.** Run: `ctest --preset windows-x64-debug -R idr_analyze`. Expected: pass.

- [ ] **Step 5: Commit.**

```bash
git add include/idr/analyze libs/analyze CMakeLists.txt
git commit -m "feat(analyze): VMT/RTTI root candidate detection"
```

---

### Task 9: `idr_cli` — scan report and end-to-end test

**Files:**
- Create: `apps/idr-cli/CMakeLists.txt`, `apps/idr-cli/src/main.cpp`
- Create: `apps/idr-cli/tests/CMakeLists.txt`, `apps/idr-cli/tests/cli_test.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: all prior libraries (`idr_pe`, `idr_disasm`, `idr_kb`, `idr_target`, `idr_analyze`).
- Produces: `idr_cli <path-to-exe> [--kb-dir <dir>] [--sys-kb-dir <dir>]`, printing a scan report; and a testable library function `std::string scan_report(const std::filesystem::path& exe, const std::filesystem::path& kb_dir, const std::filesystem::path& sys_kb_dir);` returning the report text.

- [ ] **Step 1: Write the failing test** — `cli_test.cpp` (link `idr_test_support` for the PE builder):
  - Given a minimal **non-PE** temp file: `scan_report` returns text containing `"not a PE"` and does **not** throw.
  - Given a minimal synthetic PE32 with a planted VMT root (from the shared test builder): the report contains `"arch: x86"`, a `sections:` line, an `imports:` line, and a `"vmt roots:"` line with a non-zero count.
  - Conditional (skipped if absent): run `scan_report` on `../bin/Idr.exe` with `sys_kb_dir = ".."` and `kb_dir = ".."`; assert the report contains `"arch: x86"` and either a detected version line or `"delphi version: unknown"`.

- [ ] **Step 2: Run tests to verify they fail.**

- [ ] **Step 3: Implement.** `main.cpp` parses args, calls `scan_report`, prints, and installs a top-level per-sample guard (spec §8 Tier B) so an unexpected exception yields `"analysis aborted"` and a non-zero exit rather than a crash. `scan_report` composes: `PeFile::parse` → `parse_imports`/`parse_exports` → open the `System` system-KB and `detect` → optionally `make_zydis` to disassemble the entry point window. Section/ARCH/import lines use the exact strings the test asserts.

- [ ] **Step 4: Run the full suite.** Run: `ctest --preset windows-x64-debug`. Expected: all libraries' tests plus the CLI test pass.

- [ ] **Step 5: Commit.**

```bash
git add apps/idr-cli CMakeLists.txt
git commit -m "feat(cli): headless scan report with arch/vendor/version detection"
```

---

## Phase 0 exit criteria

- `cmake --preset windows-x64-debug && cmake --build --preset windows-x64-debug && ctest --preset windows-x64-debug` builds clean and all tests pass on Windows/MSVC.
- `idr_cli <exe>` prints arch (x86/x64), sections, imports, VMT/RTTI root count, and a detected Delphi version or `unknown`, without crashing on non-PE input.
- `idr_kb` reads legacy v2 `kb*.bin` and round-trips the v3 format.
- `TargetProfile` + VMT tables exist and are unit-tested; no global `int DelphiVersion` anywhere.
