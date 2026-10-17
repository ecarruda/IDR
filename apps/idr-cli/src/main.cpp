#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

#include "scan_report.hpp"

#ifdef _MSC_VER
#include <windows.h>
#endif

namespace {

struct Options {
    std::filesystem::path exe;
    std::filesystem::path kb_dir = ".";
    std::filesystem::path sys_kb_dir = ".";
};

void print_usage() {
    std::cerr << "usage: idr_cli <path-to-exe> [--kb-dir <dir>] [--sys-kb-dir <dir>]\n";
}

// Parses argv into `opt`. Returns true on success; false on a malformed or
// missing argument list. Never throws.
bool parse_args(int argc, char** argv, Options& opt) {
    bool have_exe = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--kb-dir") {
            if (i + 1 >= argc) {
                return false;
            }
            opt.kb_dir = argv[++i];
        } else if (arg == "--sys-kb-dir") {
            if (i + 1 >= argc) {
                return false;
            }
            opt.sys_kb_dir = argv[++i];
        } else if (arg.rfind("--", 0) == 0) {
            return false;
        } else if (!have_exe) {
            opt.exe = arg;
            have_exe = true;
        } else {
            return false;
        }
    }
    return have_exe;
}

// The analysis call itself. Kept in its own function so the SEH guard below has
// no local objects that require C++ unwinding (MSVC C2712).
void do_scan(const Options& opt, std::string& out) {
    out = scan_report(opt.exe, opt.kb_dir, opt.sys_kb_dir);
}

#ifdef _MSC_VER
// Tier B per-sample guard (spec §8): a structured/Access-Violation exception
// during analysis is translated into a failed run instead of a crash.
__declspec(noinline) bool guarded_scan(const Options& opt, std::string& out) {
    __try {
        do_scan(opt, out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}
#else
bool guarded_scan(const Options& opt, std::string& out) {
    do_scan(opt, out);
    return true;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        print_usage();
        return 2;
    }

    std::string report;
    bool guarded = false;
    // Defense in depth: under MSVC the SEH `__except` in `guarded_scan` matches
    // C++ exceptions first, so these catch blocks are normally unreachable
    // there. They are kept as a portable fallback for non-SEH builds (and
    // document that no exception may escape `main`), not as dead code.
    try {
        guarded = guarded_scan(opt, report);
    } catch (const std::exception& e) {
        std::cerr << "analysis aborted: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "analysis aborted\n";
        return 1;
    }

    if (!guarded) {
        std::cerr << "analysis aborted\n";
        return 1;
    }

    std::cout << report;
    return 0;
}
