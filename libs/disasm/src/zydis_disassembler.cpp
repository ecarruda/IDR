#include "idr/disasm/disassembler.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>

namespace idr::disasm {

namespace {

class ZydisDisassembler final : public IDisassembler {
public:
    ZydisDisassembler(ZydisMachineMode machine_mode, ZydisStackWidth stack_width,
                      size_t pointer_size)
        : pointer_size_(pointer_size) {
        ZydisDecoderInit(&decoder_, machine_mode, stack_width);
        ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
    }

    Result<Instruction> decode(uint64_t address, Bytes code) const override {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

        const ZyanStatus status = ZydisDecoderDecodeFull(&decoder_, code.data(), code.size(),
                                                         &insn, operands);
        if (ZYAN_FAILED(status)) {
            if (status == ZYDIS_STATUS_NO_MORE_DATA) {
                return Result<Instruction>::err(ErrorCode::truncated);
            }
            return Result<Instruction>::err(ErrorCode::unsupported_format);
        }

        Instruction out{};
        out.address = address;
        out.length = insn.length;

        const char* mnemonic = ZydisMnemonicGetString(insn.mnemonic);
        if (mnemonic != nullptr) {
            out.mnemonic = mnemonic;
            std::transform(out.mnemonic.begin(), out.mnemonic.end(), out.mnemonic.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        }

        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter_, &insn, operands,
                                        insn.operand_count_visible, buffer, sizeof(buffer),
                                        address, nullptr);
        out.text = buffer;

        out.is_call = insn.meta.category == ZYDIS_CATEGORY_CALL;
        out.is_jump = insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                      insn.meta.category == ZYDIS_CATEGORY_COND_BR;
        out.is_conditional = insn.meta.category == ZYDIS_CATEGORY_COND_BR;
        out.is_ret = insn.meta.category == ZYDIS_CATEGORY_RET;
        out.is_relative = (insn.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;

        if (out.is_relative) {
            for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
                const ZydisDecodedOperand& operand = operands[i];
                if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative) {
                    out.branch_target =
                        address + insn.length + static_cast<uint64_t>(operand.imm.value.s);
                    break;
                }
            }
        }

        return Result<Instruction>::ok(std::move(out));
    }

    size_t pointer_size() const override { return pointer_size_; }

private:
    ZydisDecoder decoder_{};
    ZydisFormatter formatter_{};
    size_t pointer_size_;
};

}  // namespace

std::unique_ptr<IDisassembler> make_zydis(pe::Arch arch) {
    switch (arch) {
        case pe::Arch::x64:
            return std::make_unique<ZydisDisassembler>(ZYDIS_MACHINE_MODE_LONG_64,
                                                       ZYDIS_STACK_WIDTH_64, 8);
        case pe::Arch::x86:
            return std::make_unique<ZydisDisassembler>(ZYDIS_MACHINE_MODE_LEGACY_32,
                                                       ZYDIS_STACK_WIDTH_32, 4);
        case pe::Arch::unknown:
            return nullptr;
    }
    return nullptr;
}

}  // namespace idr::disasm
