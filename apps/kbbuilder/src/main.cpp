#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <utility>

#include "kb_tool.hpp"

#ifdef _MSC_VER
#include <windows.h>
#endif

namespace {

struct Options {
    enum class Command { info, convert, verify };
    Command cmd = Command::info;
    std::filesystem::path in;
    std::filesystem::path out;
};

void print_usage() {
    std::cerr << "usage: kbbuilder info <kb>\n"
                 "       kbbuilder convert <v2-in> <v3-out>\n"
                 "       kbbuilder verify <v2-in>\n";
}

// Parses argv into `opt`. Returns true on success; false on an unknown
// subcommand or a malformed argument list. Never throws.
bool parse_args(int argc, char** argv, Options& opt) {
    if (argc < 3) {
        return false;
    }
    const std::string cmd = argv[1];
    if (cmd == "info" && argc == 3) {
        opt.cmd = Options::Command::info;
        opt.in = argv[2];
        return true;
    }
    if (cmd == "convert" && argc == 4) {
        opt.cmd = Options::Command::convert;
        opt.in = argv[2];
        opt.out = argv[3];
        return true;
    }
    if (cmd == "verify" && argc == 3) {
        opt.cmd = Options::Command::verify;
        opt.in = argv[2];
        return true;
    }
    return false;
}

// The operation itself. Kept in its own function so the SEH guard below has no
// local objects that require C++ unwinding (MSVC C2712). On success stores any
// report text in `out`; on failure stores a single-line diagnostic in `message`.
bool run_operation(const Options& opt, std::string& out, std::string& message) {
    switch (opt.cmd) {
        case Options::Command::info: {
            std::string report = kb_info(opt.in);
            // kb_info reports its own failures as a single "error: " line.
            if (report.rfind("error: ", 0) == 0) {
                message = report.substr(7);
                while (!message.empty() &&
                       (message.back() == '\n' || message.back() == '\r')) {
                    message.pop_back();
                }
                return false;
            }
            out = std::move(report);
            return true;
        }
        case Options::Command::convert: {
            auto converted = kb_convert(opt.in, opt.out);
            if (!converted.has_value()) {
                message = converted.message();
                return false;
            }
            return true;
        }
        case Options::Command::verify: {
            auto verified = kb_verify(opt.in);
            if (!verified.has_value()) {
                message = verified.message();
                return false;
            }
            return true;
        }
    }
    return false;
}

#ifdef _MSC_VER
// Tier B per-sample guard: a structured/Access-Violation exception during the
// operation is translated into a failed run instead of a crash.
__declspec(noinline) bool guarded_run(const Options& opt, std::string& out,
                                      std::string& message) {
    bool ok = false;
    __try {
        ok = run_operation(opt, out, message);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return ok;
}
#else
bool guarded_run(const Options& opt, std::string& out, std::string& message) {
    return run_operation(opt, out, message);
}
#endif

}  // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        print_usage();
        return 2;
    }

    std::string out;
    std::string message;
    bool ok = false;
    // Defense in depth: under MSVC's default `/EHsc`, the SEH guard in
    // `guarded_run` (`__except(EXCEPTION_EXECUTE_HANDLER)`) does NOT catch C++
    // exceptions; it only handles structured/Access-Violation faults. These
    // catch blocks are therefore the C++-exception backstop (and document that
    // no exception may escape `main`); they remain the only such backstop on
    // non-SEH builds.
    try {
        ok = guarded_run(opt, out, message);
    } catch (const std::exception& e) {
        std::cerr << "operation aborted: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "operation aborted\n";
        return 1;
    }

    if (!ok) {
        std::cerr << (message.empty() ? "operation aborted" : message) << "\n";
        return 1;
    }

    if (!out.empty()) {
        std::cout << out;
    }
    return 0;
}
