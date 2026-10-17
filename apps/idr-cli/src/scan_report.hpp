#pragma once

#include <filesystem>
#include <string>

// Composes a headless scan report for `exe` using the version-independent KB in
// `kb_dir` (kb<version>.bin) and the system KBs in `sys_kb_dir` (syskb*.bin).
//
// Returns the report text. Never throws: a missing or malformed input produces a
// "not a PE" report instead of an exception. Deterministic and UI-free.
std::string scan_report(const std::filesystem::path& exe,
                        const std::filesystem::path& kb_dir,
                        const std::filesystem::path& sys_kb_dir);
