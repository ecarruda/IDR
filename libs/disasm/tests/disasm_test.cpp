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
