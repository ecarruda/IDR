#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "idr/common/result.hpp"
#include "idr/pe/image.hpp"

namespace idr::disasm {

struct Instruction {
    uint64_t address;
    uint8_t length;
    std::string mnemonic;
    std::string text;
    bool is_call;
    bool is_jump;
    bool is_conditional;
    bool is_ret;
    bool is_relative;
    std::optional<uint64_t> branch_target;
};

class IDisassembler {
public:
    virtual ~IDisassembler() = default;
    virtual Result<Instruction> decode(uint64_t address, Bytes code) const = 0;
    virtual size_t pointer_size() const = 0;
};

std::unique_ptr<IDisassembler> make_zydis(pe::Arch arch);

}  // namespace idr::disasm
