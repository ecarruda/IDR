# IDR Reborn — Phase 1 (KB Builder: Lossless v2→v3) — Design

- **Date:** 2026-10-12
- **Status:** Draft for review
- **Parent spec:** `docs/superpowers/specs/2026-10-10-idr-reborn-design.md` (§6 KB format v3, §11 phasing)
- **Scope:** A `kbbuilder` executable that converts legacy v2 knowledge bases to the v3 format, plus the `idr_kb`
  schema and reader extensions that make v3 a *lossless* representation of v2. DCU-based generation is out of scope
  (see §10).

---

## 1. Context

Phase 0 delivered the portable core, including `idr_kb`: a self-describing v3 writer/reader and a legacy v2 reader,
plus the headless `idr-cli`. The parent spec's Phase 1 is described as *"DCU32INT port → `dcu-parser`; `kb-writer`
emits v3 … v2→v3 round-trip parity passes."*

That description bundles two very different jobs:

1. **A v2→v3 converter with a parity harness** — derivable entirely from artifacts already in the repository.
2. **DCU-based KB generation** — requires porting DCU32INT (a large Delphi Pascal codebase) and a supply of
   version-accurate `.dcu` files.

Investigation of the repository found:

- **No DCU32INT/KBBUILDER source and no `.dcu` files are present.** They would have to be acquired from
  `crypto2011/KBBUILDER` and ported.
- **No Delphi/FPC compiler is installed**, and the free Delphi Community Edition ships only the *latest* compiler,
  whose DCU format is beyond DCU32INT's support boundary — so it cannot produce the old-version DCUs that generation
  needs.
- **Real v2 KBs are available now**: `syskb2014.bin` is committed (578 KB), and the full KBs ship as `kb*.7z`
  (`kb2014.7z` → a 200 MB `kb2014.bin`). A 7-Zip installation is present to extract them.

**Decision:** split Phase 1. This phase delivers the converter and the parity gate — the half that the repository can
fully support and validate today, and the half that freezes the v3 format before any generator is written. DCU-based
generation becomes a follow-on spec (§10).

## 2. Scope

**In scope**

- Extend the v3 schema so a v3 file is a *lossless* representation of the data a v2 KB holds — including the
  sections and fields currently dropped (`Vars`, `ResStrings`, dump `Fixups`, type `Fields`/`Props`/`Methods`,
  proc `Locals`, module `Uses`).
- Complete the legacy v2 reader to materialize everything the schema carries.
- A structural-equality helper `kb_equal` for parity assertions.
- A `kbbuilder` executable with `info`, `convert`, and `verify` operations.
- A parity test suite over real v2 KBs (a committed fixture and an opt-in scale fixture).

**Out of scope**

- DCU parsing / `dcu-parser`, and generation of KBs for any Delphi version (follow-on spec).
- Streaming / low-memory serialization (the offline builder may hold a KB in memory).
- x64 KBs, the GUI, and the decompiler.
- Structured decoding of the opaque blobs (`fixups`, `fields`, `props`, `methods`, `locals`) — those are captured
  byte-exact and interpreted later by `idr-rtti` / `idr-analyze` (Phase 2).

## 3. Success criteria (phase exit)

1. **Container losslessness:** for a real v2 KB `f`, `kb_equal(read_v2(f), read_v3(write_v3(read_v2(f))))` holds.
   Verified on `syskb2014.bin` (committed; CI) and, opt-in, on the 200 MB `kb2014.bin`.
2. **Coverage:** the v3 model represents modules, consts, types, **vars**, **resstrings**, and procs — with
   byte-exact `dump`, `relocs`, `fixups`, `fields`, `props`, `methods`, and `locals` payloads.
3. **Determinism:** `write_v3(data)` is a pure function of `data`; `write→read→write` is byte-identical.
4. **Robustness:** truncated/corrupt v2 and v3 inputs fail cleanly with an `ErrorCode`; no exceptions cross module
   boundaries.
5. **Quality:** full suite green on Windows/MSVC `/W4 /permissive-`, no new warnings.

## 4. Schema changes

All changes are in `include/idr/kb/records.hpp` and the v3 serializer/reader (`libs/kb/src/v3_io.cpp`).

**New record types**

- `VarRecord { uint16_t module_id; std::string name; char type; std::string type_def; std::string abs_name; }`
  — `type` is `'V'` (var), `'A'` (absolute var), `'S'` (specialized var), or `'T'` (threadvar); `abs_name` is the
  target of an `absolute` declaration.
- `ResStringRecord { uint16_t module_id; std::string name; std::string type_def; }`
  — if the v2 record carries a `Context` field (it is present in the file-table description but commented out of
  `MResStrInfo`), it is captured as `std::string context`; whether it exists is pinned during implementation
  against `KnowledgeBase.cpp` (§6).

**Extended record types**

- `ConstRecord` — add `std::vector<std::byte> fixups` (raw).
- `TypeRecord` — add `std::vector<std::byte> fixups` (raw); `fields`/`props`/`methods` remain raw byte blobs.
- `ProcRecord` — **change** `fixups` from `std::vector<uint32_t>` to `std::vector<std::byte>` (raw); add
  `std::vector<std::byte> locals` (raw). `dump`, `relocs`, and `args` are unchanged.
- `ModuleRecord` — v2 additionally stores module *use names* alongside the use ids; these are captured as
  `std::vector<std::string> uses_names` when present (layout pinned against `GetModuleInfo`). If they are not
  present in the file, the vector stays empty and parity is unaffected.

**Aggregate**

- `KbData` — add `std::vector<VarRecord> vars;` and `std::vector<ResStringRecord> resstrings;`.

**Losslessness definition.** "Lossless" is defined over the `KbData` model: every *informational* field v2 carries is
captured. Purely derived length prefixes (`DumpTotal`, `ArgsTotal`, the leading per-type `Size`, and the per-table
count headers) are recomputed on write and not stored. Opaque blobs are captured byte-exact.

## 5. v3 section directory

Two sections are added; the directory remains self-describing and readers skip unknown section ids:

| id | Section |
|----|---------|
| 1 | Modules |
| 2 | Consts |
| 3 | Types |
| 4 | Procs |
| **5** | **Vars** |
| **6** | **ResStrings** |

Each record keeps the existing tagged, length-prefixed body encoding; the new fields are appended to their bodies
(all integers little-endian; strings and blobs length-prefixed).

## 6. v2 reader completion

`libs/kb/src/v2_read.cpp` currently drops several tables and fields. It is completed to:

- **Capture dump fixups** rather than skip them: `read_dump_and_skip_fixups` becomes a `read_dump` that returns the
  raw fixup bytes (the existing `DumpTotal` accounting already locates them:
  `fixup_bytes = DumpTotal - 8 - 2 * DumpSize`).
- **Materialize `vars` and `resstr`** from their offset tables (already parsed, then discarded) into `VarRecord`
  and `ResStringRecord`.
- **Capture proc `locals`** from the `LocalsTotal`/`LocalsNum` block as raw bytes.
- **Capture module uses names** if the record carries them.
- **Populate header facts a v2 file implies:** `arch = x86` (or `unknown` when `isMSIL`), `vendor = "embarcadero"`,
  the corresponding `vendor_code`, and `pointer_size = 4`.

The exact v2 record layouts for fixups, locals, resstr, and module-use names are pinned in the implementation plan
against the legacy accessors (`MKnowledgeBase::GetConstInfo`, `GetTypeInfo`, `GetProcInfo`, `GetVarInfo`,
`GetResStrInfo`, `GetModuleInfo`) in `KnowledgeBase.cpp` and the structs in `KnowledgeBase.h`.

## 7. `kb_equal`

A new free function in `idr_kb`:

```cpp
bool kb_equal(const KbData& a, const KbData& b);
```

It compares `format_version`, the shared header fields (`arch`, `vendor`, `vendor_code`, `compiler_version`,
`compiler_id`, `pointer_size`), and the record vectors (`modules`, `consts`, `types`, `vars`, `resstrings`, `procs`)
element-by-element, including all blobs. It is the single reusable definition of KB equivalence used by the parity
tests, `kbbuilder verify`, and future round-trip checks.

## 8. `kbbuilder` executable

A new `apps/kbbuilder/` target, kept deliberately thin (no DCU logic) and linked only against `idr_kb`:

- `kbbuilder info <kb>` — print header facts and per-section record counts (works on v2 and v3 inputs).
- `kbbuilder convert <v2-in> <v3-out>` — `read_v2` → `write_v3`; report record counts and the output size.
- `kbbuilder verify <v2-in>` — `read_v2` → `write_v3` (temp) → `read_v3` → `kb_equal`; exit non-zero on mismatch.

It follows the `idr-cli` conventions: deterministic output, a top-level per-sample guard (spec parent §8, Tier B) so
an unexpected fault becomes a clean non-zero exit, and no exceptions crossing module boundaries.

## 9. Testing & fixtures

- **Unit tests** (`libs/kb/tests/`): v3 write→read round-trip per record type including the new
  vars/resstrings/fixups/locals fields; a large-value and an empty-collection case; truncated-body and bad-magic
  negative cases; determinism (`write→read→write` byte-identical).
- **Parity test** (the phase gate): `kb_equal(read_v2(f), read_v3(write_v3(read_v2(f))))` on `syskb2014.bin`, located
  via the existing `IDR_REPO_ROOT` compile definition; skipped only if the fixture is absent.
- **Scale parity test (opt-in):** the same assertion on a full `kb2014.bin`, located via an environment variable
  (e.g. `IDR_KB_SCALE_FIXTURE`); `GTEST_SKIP()` when unset, so CI stays fast and the 200 MB file is never committed.
- **CLI test** (`apps/kbbuilder/tests/`): `convert` a fixture to a temp file, then `verify` it; assert exit codes and
  that `info` reports the expected sections.
- GoogleTest; `/W4 /permissive-`; the full suite must pass.

## 10. Deviation from the parent spec (Phase 1 split)

The parent spec §11 defines Phase 1 as DCU-parser port **plus** v2→v3 parity. This document delivers the converter and
parity half. The remaining half — porting DCU32INT behind `dcu-parser` and generating KBs, including any decision to
install a Delphi toolchain — is deferred to a **Phase 1b (KB generation)** spec. This is recorded here because it is a
deliberate deviation from the parent plan, chosen to freeze the v3 format and produce a v3 corpus from real data
before any generator exists.

## 11. Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Exact v2 layout of `fixups`/`locals`/`resstr`/module-uses differs from the struct comments | Converter misreads records → parity falsely passes/fails | Pin each layout in the plan against the legacy `Get*Info` parse code; parity over a real 200 MB KB exercises every path |
| A 200 MB `KbData` held wholly in memory | High peak memory in `kbbuilder`/tests | Acceptable for offline batch work; streaming is deferred (§2) |
| Keeping `formatVersion = 3` while bodies gain fields | A hypothetical earlier v3 file is not readable | No v3 corpus exists (format is pre-release); the reader is bounds-checked and fails cleanly, never misparses |
| `delphiVer`/`compiler_id` unset in some v2 KBs | Header parity nuance | Both sides derive these from the same v2 read; `kb_equal` compares what the model holds |

## 12. Deferred / follow-on

- **Phase 1b — KB generation:** `dcu-parser` (ported DCU32INT) + `kb-writer` integration; real KBs for a chosen
  version; any Delphi-toolchain decision.
- Structured decoding of the opaque blobs (belongs to Phase 2 RTTI work).
- Streaming/kbbuilder scale optimization.
- x64 KB generation.