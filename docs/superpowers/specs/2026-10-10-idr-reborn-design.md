# IDR Reborn — Architecture & Design

- **Date:** 2026-10-10
- **Status:** Draft for review
- **Scope:** Overall system architecture and phased delivery plan for a modern, multi-architecture, multi-vendor Delphi/FPC static analyzer built on the salvageable parts of IDR and KBBUILDER.

---

## 1. Context

IDR (Interactive Delphi Reconstructor) is a Windows 32-bit static analyzer and decompiler for Delphi
EXE/DLL files. The existing implementation is a **Borland C++Builder 6** (2002) VCL application
(~65k lines of C++ across ~30 units) and is the de facto reference for Delphi symbol recovery.

A companion project, **KBBUILDER**, produces the "knowledge bases" IDR consumes. Its parsing engine is
**DCU32INT** (by Alexei Hmelnov), a Delphi `.dcu` parser that already supports up to Delphi 10.2
Tokyo including Win64.

### 1.1 How the existing system works

- **Knowledge Base (KB):** a per-compiler binary file (`kb2.bin` … `kb2014.bin`) containing
  pre-extracted metadata and compiled code dumps of a Delphi version's runtime/system units.
  Sections: Modules, Consts, Types, Vars, ResStrings, Procs. Each proc/type/const entry carries a
  binary `Dump` (compiled bytes) plus `Relocs`/`Fixups`, used for byte-pattern fingerprinting.
  Format is identified by magic (`"IDR Knowledge Base File"`, version 2) and read by raw
  `fopen`/`fread` + manual pointer walking (`OFRESTSINFO` offset tables + `GetKBCachePtr`).
- **KB generation (offline):** copy `.dcu` files into `KBBUILDER/BUILDER/` → run `BuildKb.exe <name>`
  → the KB is produced by parsing each DCU (DCU32INT) and serializing RTTI/code. There is also a
  `TestKb.exe` verifier.
- **Analysis (runtime):** load PE (`IMAGE_NT_HEADERS`, 32-bit only) → detect Delphi version →
  load `kb<version>.bin` → fingerprint code against KB dumps → recover proc prototypes, types,
  RTTI, fields, properties → reconstruct Pascal source via `TDecompiler` (x86-32 register/FPU
  simulation only) → optionally export IDA `.idc` scripts.

### 1.2 Why it cannot simply be patched

1. **x86-32 is load-bearing** in the PE layer, the hand-rolled disassembler (`MDisasm`), the
   decompiler (`TDecompiler`), and the KB scanning/analysis code.
2. **Compiler version logic is hard-coded**: a global `int DelphiVersion` with scattered
   `if (DelphiVersion >= 2010)` branches throughout `TypeInfo.cpp`, `Threads.cpp`, `Main.cpp`.
3. **The toolchain is dead**: C++Builder 6 + TntUnicode, IDE-bound `.bpr`/`.dfm`, no tests, no CI,
   no CLI, global analysis state coupled to the GUI (13k-line `Main.cpp`).
4. **Prior in-place modernization was reverted**: the upstream repository carries a
   `cbuilder-10.2` branch and a `revert-30-cbuilder-10.2` branch.

### 1.3 What is genuinely valuable (must be preserved)

The domain knowledge is the asset, not the C++Builder plumbing:

- **KB fingerprint scanning** (`MKnowledgeBase::ScanCode`) — matching target code against known
  runtime dumps using relocations.
- **Delphi RTTI reconstruction** (`TypeInfo.cpp`) — rebuilding type/vtable/field/property metadata.
- **Decompiler heuristics** (`Decompiler.cpp`) — x86 code-pattern recognition and Pascal synthesis
  (deferred to a later phase).

---

## 2. Problem statement

Build a stable, modern tool that (a) recovers Delphi symbols/RTTI for **both 32-bit and 64-bit**
binaries and (b) is **scalable to new Delphi versions and new vendors (FPC/Lazarus)** without
rearchitecting, while (c) preserving IDR's existing analysis quality and (d) serving both automated
(anti-virus triage) and interactive (source recovery) use.

## 3. Goals / Non-goals

### Goals

- Portable C++20 core, buildable with **MSVC + CMake** on Windows.
- **x86-32 and x86-64** analysis and symbol/RTTI recovery.
- Preserve existing 32-bit Delphi coverage (Delphi 2 … XE4) via existing KBs and the KB builder.
- Vendor/version behavior expressed through a **`TargetProfile`** abstraction, not scattered globals.
- A **versioned, self-describing KB format (v3)** shared by the KB builder and the analyzer.
- First-class **headless CLI** for batch/AV use; separate interactive GUI later.
- Deterministic, UI-free analysis usable by any front-end.

### Non-goals (for now)

- .NET / MSIL (Delphi 8) support.
- Full fuzz-hardening as a delivery gate (fuzzing is optional hardening, Tier D).
- The interactive GUI before core recovery works (Phase 4).
- The decompiler before recovery works (Phase 5, deferred and conditional).
- C++Builder/MFC output; only Pascal source reconstruction is in scope.

## 4. Key decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **New MSVC C++20 + CMake workspace**; salvage domain logic, rebuild the skeleton | The 32-bit ceiling and dead toolchain make in-place patching a dead end; the domain algorithms are worth keeping |
| D2 | **Separate executables** (`idr-cli`, `idr-gui`, `kbbuilder`) linked against shared static core libraries | Keeps AV/headless deployment free of GUI deps; lets GUI evolve independently; avoids conditional-dependency complexity |
| D3 | **Zydis** as the disassembly backend behind an `IDisassembler` interface | Battle-tested multi-arch (x86/x86-64) decode; removes the hand-rolled 32-bit decoder as a maintenance burden |
| D4 | **`TargetProfile` object** (arch × vendor × version × conventions × RTTI/VMT layout) | Replaces `int DelphiVersion`; adding a vendor/version becomes adding a profile |
| D5 | **KB format v3** — versioned, self-describing, checksummed; reader also loads legacy v2 | Shared contract between `kbbuilder` and `idr-kb`; safe parsing of untrusted data |
| D6 | **Separate `kbbuilder.exe`** reusing a ported DCU32INT parser | KB generation is offline build-time work and needs the DCU toolchain, not the analyzer |
| D7 | **Tiered robustness** (bounds-checked readers + per-sample guard + optional process isolation); no "malware" toggle | The real AV requirement is "one bad sample does not kill the batch", achieved by isolation, not by assuming input safety |
| D8 | **Decompiler deferred** to after GUI, conditional on earlier phases succeeding | Highest-effort, lowest-certainty component; recovery is the core value |

## 5. Architecture

### 5.1 Component tree

```
offline (build-time)
  kbbuilder.exe
    dcu-parser   ported DCU32INT (Delphi 2–XE4 + x64; extensible per version)
    kb-writer    serializes KB format v3
        │ produces
        ▼
  kb-<vendor><version>-<arch>.bin   (KB v3; legacy v2 also readable)

runtime (analysis)
  idr-core (static libs)
    idr-pe        PE32 / PE32+ loader (sections, imports, exports, relocs, TLS)
    idr-disasm    IDisassembler over Zydis
    idr-target    TargetProfile: arch × vendor × version × conventions × RTTI/VMT layout
    idr-kb        KB v3 reader (typed access to modules/consts/types/vars/resstr/procs) + v2 compat
    idr-rtti      Delphi RTTI / TypeInfo model + reconstruction
    idr-analyze   unit discovery, KB fingerprint scan, xrefs, function identification
    idr-decompile decompiler engine (ported heuristics), arch-parameterized  [Phase 5]
  idr-cli         headless batch tool (scan / symbols / IDC export)
  idr-gui         interactive front-end (source recovery)                     [Phase 4]
```

### 5.2 Responsibilities and interfaces

- **`idr-pe`** — parse PE32 and PE32+, expose sections, imports, exports, relocations, TLS, entry
  point, and a flat image view. Returns `Result`-style errors; no exceptions across the boundary.
- **`idr-disasm`** — `IDisassembler` interface: `decode(address) -> Instruction{tokens, operands,
  length, control-flow flags}`. Implemented over Zydis. IDR-specific operand/flag semantics are
  derived on top, so no custom ISA decoder is maintained.
- **`idr-target`** — `TargetProfile` with: architecture, pointer size, vendor, compiler version,
  string id, supported calling conventions (`cdecl/pascal/stdcall/safecall` + x64 variants), VMT
  layout rule, RTTI layout rule, and system-unit name mapping. Provides `detect(image)` and
  `kbFileName()`.
- **`idr-kb`** — reads v3 (and legacy v2) KBs into typed records; provides lookups by name/module and
  the byte-pattern scan used for fingerprinting.
- **`idr-rtti`** — models Delphi RTTI records independently of encoding version; reconstructs
  type/vtable/field/property info using the KB and the target image.
- **`idr-analyze`** — orchestrates: unit discovery, KB fingerprint scan, xref building, function
  identification; produces an `AnalysisResult` (below).
- **`idr-decompile`** — per-procedure Pascal synthesis from the analysis; parameterized by arch.

### 5.3 Runtime data flow

```
target.exe
  → idr-pe.load()
  → idr-target.detect()            # arch, vendor, version
  → idr-kb.open(kb<profile>.bin)   # v3 or legacy v2
  → idr-analyze.run()              # fingerprint scan + RTTI + xrefs
  → AnalysisResult
        → idr-cli: scan report / symbol dump / IDC export
        → idr-gui: browse units, RTTI, decompile
```

## 6. KB format v3

### 6.1 Principles

- **Self-describing:** an explicit header and section directory; no reliance on the reader knowing
  record offsets a priori.
- **Versioned and negotiable:** `formatVersion` in the header; readers accept known versions and
  fail cleanly on unknown ones.
- **Explicit encoding:** fixed little-endian integers of declared width; length-prefixed strings;
  no compiler-ABI-dependent struct layouts.
- **Safe:** every read is bounds-checked against a validated section directory.
- **Lossless for existing data:** v3 can represent everything v2 holds, plus architecture/ABI fields.

### 6.2 Logical layout

- **Header:** magic (`IDRKB`), `formatVersion` (=3), target architecture, vendor, compiler version,
  compiler string id (e.g. `"XE4"`, `"10.2"`, `"FPC-3.2"`), pointer size, description, creating-tool
  version, section-count, and a content checksum.
- **Section directory:** for each section, `{id, recordCount, offset, size}`.
- **Sections (records):** `Modules`, `Consts`, `Types`, `Vars`, `ResStrings`, `Procs`. Each record
  uses a tagged, length-prefixed field layout. A Proc record carries name, module, kind, calling
  kind, result type, argument list, and the code `Dump` + `Relocs` + `Fixups`. A Type record carries
  kind, declaration, RTTI dump + relocs/fixups, and field/property/method tables.
- **Indexes:** by-name and by-module lookup tables may be included for binary search, mirroring the
  performance intent of v2's `OFRESTSINFO` tables.

### 6.3 Compatibility

- The reader transparently loads legacy v2 (`"IDR Knowledge Base File"`, and the older `"IDD"` v1)
  so all existing `kb*.bin` files remain usable without regeneration.
- `kbbuilder` writes v3. A v2→v3 conversion/normalization path is a Phase-1 test vehicle
  (read v2 → write v3 → read → compare semantics).

## 7. TargetProfile model

A profile is a value object plus behavior. It replaces the global `int DelphiVersion`.

- **Data:** architecture (`x86`, `x64`), pointer size, vendor (`embarcadero`, `fpc`), compiler
  version (numeric), compiler string id, RTTI layout version, VMT layout version, calling-convention
  set, system-unit mapping.
- **Behavior:** `detect(image) -> optional<TargetProfile>`; `kbFileName()`; RTTI/VMT interpretation
  hooks consumed by `idr-rtti` and `idr-analyze`.
- **Extensibility:** a new Delphi version is a new profile value; a new vendor (FPC) is a new
  profile implementation with its own RTTI/encoding rules. Call sites never branch on version again.

## 8. Robustness & error handling

Tiered, in increasing cost. Tiers A and B are always on; C and D are optional.

- **Tier A (always):** all binary readers (`idr-pe`, `idr-kb`, `dcu-parser`) are length-aware and
  bounds-checked, operating on validated buffers rather than raw pointer walking. Parsing functions
  return `Result`/error values; no exceptions cross module boundaries. Debug assertions only.
- **Tier B (always):** a top-level per-sample guard in `idr-cli` translates an access violation or
  unexpected exception into "analysis aborted for this file"; the run continues.
- **Tier C (optional):** worker-process isolation so a hard crash cannot terminate a large scan.
- **Tier D (optional):** coverage-guided fuzzing of PE/KB/DCU parsers as ongoing hardening.

Rationale: for AV triage the requirement is that **one bad sample does not kill the batch**, achieved
by isolation and contained errors — not by assuming inputs are benign. A user-supplied "is this
malware?" flag is therefore unnecessary; `--paranoid` may exist for extra checks.

## 9. Diagnostics & AnalysisResult

- Analysis is **deterministic and UI-free**. It produces an `AnalysisResult` containing: image
  facts, detected `TargetProfile`, KB reference, recovered units/functions/types/RTTI, xrefs, and a
  list of **structured diagnostics** (e.g. `unsupported-compiler-version`,
  `incomplete-prototype`, `aborted-due-to-guard`).
- Front-ends render diagnostics; the core never shows modal dialogs.

## 10. Testing strategy

- **Unit tests** (GoogleTest or Catch2) per library.
- **Golden corpus:** a set of Delphi EXEs/DLLs (32-bit and 64-bit, several compiler versions) with
  expected recovered symbols; current IDR output seeds the 32-bit expectations.
- **KB round-trip:** read v2 → write v3 → read → compare semantics (Phase 1 gate).
- **Cross-validation:** fingerprint a routine from a KB, then re-find it in a real binary.
- **Fuzzing (optional):** PE/KB/DCU parsers as Tier D hardening, not a gate.
- **CI:** GitHub Actions on a Windows runner building with MSVC + CMake and running unit/golden tests.

## 11. Phasing & deliverables

Each phase is its own spec → plan → implementation cycle.

| Phase | Sub-project | Deliverable / exit criterion |
|---|---|---|
| **0** | **Foundation** — repo/CMake layout, `idr-pe` (PE32/64), `idr-disasm` (Zydis), `idr-target` skeleton, KB v3 schema + reader, `idr-cli` skeleton | CLI loads a Delphi exe, detects arch/vendor/version, disassembles, lists sections/imports/RTTI roots; unit tests green |
| **1** | **KB builder** — DCU32INT port → `dcu-parser`; `kb-writer` emits v3 | `kbbuilder.exe` builds a KB for an old version; v2→v3 round-trip parity passes |
| **2** | **32-bit analyzer parity** — KB scan, unit discovery, xrefs, RTTI | `idr-cli` recovers symbols/RTTI for 32-bit Delphi exes matching current IDR output on the golden corpus |
| **3** | **x64 recovery** — PE32+ analysis path, x64 decode/analysis, x64 KB generation | `idr-cli` recovers symbols/RTTI for x64 Delphi exes |
| **4** | **GUI** — source-recovery front-end | interactive browsing/decompilation on the shared core |
| **5** | **Decompiler** *(deferred/optional)* — port `TDecompiler`, dual-arch | `idr-decompile` emits Pascal for x86-32 and x64 |
| **6** | **FPC/Lazarus** *(later)* — generator + profile | KB + analysis for FPC binaries |

**Phases 0–3 are the core value** (AV triage + symbol recovery, 32- and 64-bit). GUI, decompiler, and
FPC follow and are conditional.

## 12. Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Newer Delphi DCU formats (10.3+/11/12) beyond DCU32INT's 10.2 support | Blocks KB generation for new versions | Phase 1 isolates DCU parsing behind `dcu-parser`; extend per version; DCU format is documented in DCU32INT sources |
| Obtaining `.dcu` files / licensing of derived KBs | Legal/redistribution risk for new versions | Confirm licensing; keep KB generation as a user-run local step; do not redistribute vendor-derived KBs without a clear basis |
| Decompiler port effort is large | Schedule/certainty risk | Deferred to Phase 5, conditional; recovery (the core deliverable) does not depend on it |
| FPC/Lazarus uses `.ppu`/`.o`, not DCU | A separate generator/model | Isolated as Phase 6; not on the critical path |
| 32-bit parity drift vs original IDR | Regression in coverage | Golden corpus seeded from current IDR output; parity is the Phase-2 exit criterion |

## 13. Decisions deferred

- GUI toolkit (Qt / Dear ImGui / Win32) — Phase 4.
- Whether `idr-kb` indexes are precomputed in the KB or built at load time.
- Exact DCU32INT integration form (vendored source vs a maintained fork).
- FPC RTTI encoding details — Phase 6.

## 14. References

- Existing analyzer: `README.md`, `KnowledgeBase.*`, `Disasm.*`, `Decompiler.*`, `TypeInfo.cpp`,
  `Main.cpp` (this repository).
- KB builder and DCU32INT notes: `crypto2011/KBBUILDER` (BUILDER: `BuildKb.exe`, `DCUClasses.*`;
  root: `DCU32.pas`, `DCURecs.pas`, `DasmX86.pas`).
- DCU32INT upstream: `http://hmelnov.icc.ru/DCU/` (support through Delphi 10.2 Tokyo + Win64).
