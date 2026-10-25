/// @file        adapter_primitives_test.cpp
/// @brief       adapter 原语：寄存器域读写、批量重编号与 payload 构造。
#include <initializer_list>
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

namespace {

std::vector<ca::u8> codeUnits(std::initializer_list<ca::u16> units)
{
    std::vector<ca::u8> bytes;
    bytes.reserve(units.size() * 2);
    for (const ca::u16 unit : units) {
        bytes.push_back(static_cast<ca::u8>(unit & 0xFFu));
        bytes.push_back(static_cast<ca::u8>(unit >> 8));
    }
    return bytes;
}

ByteSlice viewOf(const std::vector<ca::u8>& bytes)
{
    return ByteSlice{bytes.data(), bytes.size()};
}

/// 解码一段混合格式的指令流（同 DecodesOperandFormats 的样本）。
std::vector<Insn> decodeMixed()
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x000e,                                  //  0: return-void
        0x8112,                                  //  1: const/4 v1, #-8
        0x0122, 0x0010,                          //  2: new-instance v1, type@0x0010
        0x21d0, 0xfffe,                          //  4: add-int/lit16 v1, v2, #-2
        0x206e, 0x0005, 0x0021,                  //  6: invoke-virtual {v1, v2}, method@5
        0x0374, 0x0006, 0x0003,                  //  9: invoke-virtual/range {v3..v5}, method@6
        0x11fa, 0x0007, 0x0000, 0x0008,          // 12: invoke-polymorphic {v0}, method@7, proto@8
        0x0018, 0x7788, 0x5566, 0x3344, 0x1122,  // 16: const-wide v0
        0x0003, 0x0001, 0x0002,                  // 21: move/16 v1, v2
    });
    auto decoded = decodeInsns(viewOf(bytes));
    if (decoded.is_err()) {
        return {};
    }
    return std::move(decoded).unwrap();
}

}   // namespace

TEST(DexInsnAdapter, ReadsAndWritesRegistersAcrossLayouts)
{
    std::vector<Insn> insns = decodeMixed();
    ASSERT_EQ(insns.size(), 9u);

    // const/4 v1：List，1 槽，4 位。
    const Insn& const4 = insns[1];
    EXPECT_EQ(insnRegisterLayout(const4), RegisterLayout::List);
    EXPECT_EQ(insnRegisterTotal(const4), 1u);
    EXPECT_EQ(insnRegisterAt(const4, 0), 1u);

    // invoke-virtual {v1, v2}：List，2 槽，各 4 位。
    const Insn& invoke = insns[4];
    EXPECT_EQ(insnRegisterLayout(invoke), RegisterLayout::List);
    EXPECT_EQ(insnRegisterTotal(invoke), 2u);
    EXPECT_EQ(insnRegisterAt(invoke, 0), 1u);
    EXPECT_EQ(insnRegisterAt(invoke, 1), 2u);

    // invoke-virtual/range {v3..v5}：Range。
    const Insn& range = insns[5];
    EXPECT_EQ(insnRegisterLayout(range), RegisterLayout::Range);
    EXPECT_EQ(insnRegisterTotal(range), 3u);
    EXPECT_EQ(insnRegisterAt(range, 0), 3u);
    EXPECT_EQ(insnRegisterAt(range, 2), 5u);

    // return-void：None。
    EXPECT_EQ(insnRegisterLayout(insns[0]), RegisterLayout::None);
    EXPECT_EQ(insnRegisterTotal(insns[0]), 0u);

    // 槽位域宽：4 位槽写 15 通过、16 拒绝；8 位槽写 255 通过、256 拒绝。
    Insn edited = invoke;
    EXPECT_TRUE(setInsnRegister(edited, 0, 15).is_ok());
    EXPECT_EQ(setInsnRegister(edited, 0, 16).unwrap_err(), InsnEncodeError::OperandOverflow);
    Insn wide = insns[7];  // const-wide v0：8 位槽
    EXPECT_TRUE(setInsnRegister(wide, 0, 255).is_ok());
    EXPECT_EQ(setInsnRegister(wide, 0, 256).unwrap_err(), InsnEncodeError::OperandOverflow);

    // 越界槽位与布局不符。
    Insn rangeCopy = range;
    EXPECT_EQ(setInsnRegister(edited, 2, 0).unwrap_err(), InsnEncodeError::BadFormat);
    EXPECT_EQ(setInsnRegister(rangeCopy, 0, 0).unwrap_err(), InsnEncodeError::BadFormat);

    // range 槽位写入：count 超 8 位拒绝。
    Insn rangeEdit = range;
    EXPECT_TRUE(setInsnRegisterRange(rangeEdit, 10, 5).is_ok());
    EXPECT_EQ(rangeEdit.startRegister, 10u);
    EXPECT_EQ(rangeEdit.registerCount, 5u);
    EXPECT_EQ(setInsnRegisterRange(rangeEdit, 10, 0x100).unwrap_err(),
              InsnEncodeError::OperandOverflow);
    EXPECT_EQ(setInsnRegisterRange(edited, 10, 5).unwrap_err(), InsnEncodeError::BadFormat);
}

TEST(DexInsnAdapter, ComputesCeilingAndShifts)
{
    std::vector<Insn> insns = decodeMixed();
    ASSERT_EQ(insns.size(), 9u);
    // 最高寄存器是 range 的 v5。
    EXPECT_EQ(insnRegisterCeiling(insns), 6u);

    ASSERT_TRUE(shiftInsnRegisters(insns, 10).is_ok());
    EXPECT_EQ(insnRegisterCeiling(insns), 16u);
    // 编码再解码，寄存器平移往返无损。
    auto encoded = encodeInsns(insns);
    ASSERT_TRUE(encoded.is_ok()) << to_string(encoded.unwrap_err());
    auto decoded = decodeInsns(viewOf(encoded.unwrap()));
    ASSERT_TRUE(decoded.is_ok());
    EXPECT_EQ(insnRegisterAt(decoded.unwrap()[5], 2), 15u);

    // 平移出 0..65535 或槽位域宽（4 位槽装不下 16+）即拒绝。
    std::vector<Insn> small = decodeMixed();
    EXPECT_EQ(shiftInsnRegisters(small, -2).unwrap_err(), InsnEncodeError::OperandOverflow);
    std::vector<Insn> fourBit = decodeMixed();
    EXPECT_EQ(shiftInsnRegisters(fourBit, 15).unwrap_err(), InsnEncodeError::OperandOverflow);
}

TEST(DexInsnAdapter, RemapsRegisters)
{
    // v1 与 v2 互换，其余平移不变；range {v3..v5} 上映射是恒等平移。
    const std::vector<ca::u16> swapped = {0, 2, 1, 3, 4, 5};
    std::vector<Insn> insns = decodeMixed();
    ASSERT_TRUE(remapInsnRegisters(insns, swapped).is_ok());
    EXPECT_EQ(insnRegisterAt(insns[4], 0), 2u);
    EXPECT_EQ(insnRegisterAt(insns[4], 1), 1u);
    EXPECT_EQ(insnRegisterAt(insns[5], 0), 3u);

    // range 区间上映射不是平移：3→3、4→5 断裂。
    const std::vector<ca::u16> torn = {0, 1, 2, 3, 5, 6};
    std::vector<Insn> tornStream = decodeMixed();
    EXPECT_EQ(remapInsnRegisters(tornStream, torn).unwrap_err(), InsnEncodeError::BadFormat);

    // 旧编号超出映射表。
    const std::vector<ca::u16> tiny = {0, 1};
    std::vector<Insn> shortTable = decodeMixed();
    EXPECT_EQ(remapInsnRegisters(shortTable, tiny).unwrap_err(),
              InsnEncodeError::OperandOverflow);
}

TEST(DexInsnAdapter, BuildsPayloadsAndRoundTrips)
{
    auto packed = makePackedSwitchPayload(10, {-2, 3, 8});
    ASSERT_TRUE(packed.is_ok()) << to_string(packed.unwrap_err());
    auto sparse = makeSparseSwitchPayload({5, 9, 100}, {-2, 4, 1});
    ASSERT_TRUE(sparse.is_ok());
    auto fill = makeFillArrayDataPayload(2, {0x78, 0x56, 0x34, 0x12});
    ASSERT_TRUE(fill.is_ok());

    // 移动取出：payloadData 指向各自 storage 内部，storage 存活到编码完成。
    PayloadInsn packedPayload = std::move(packed).unwrap();
    PayloadInsn sparsePayload = std::move(sparse).unwrap();
    PayloadInsn fillPayload = std::move(fill).unwrap();

    // 拼流：switch/fill 是 31t（宽 3），payload 需要偶地址，插 nop 对齐。
    std::vector<Insn> stream;
    Insn packedSwitch;
    packedSwitch.opcode = 0x2b;
    packedSwitch.format = InsnFormat::F31t;
    packedSwitch.registerCount = 1;
    Insn sparseSwitch = packedSwitch;
    sparseSwitch.opcode = 0x2c;
    Insn fillCall = packedSwitch;
    fillCall.opcode = 0x26;
    Insn nop;
    nop.opcode = 0x00;
    nop.format = InsnFormat::F10x;

    stream.push_back(packedSwitch);
    stream.push_back(nop);
    stream.push_back(packedPayload.insn);  // @4，宽 4+2*3=10
    stream.push_back(sparseSwitch);        // @14，宽 3
    stream.push_back(nop);                 // @17，对齐到偶地址
    stream.push_back(sparsePayload.insn);  // @18，宽 2+4*3=14
    stream.push_back(fillCall);            // @32，宽 3
    stream.push_back(nop);
    stream.push_back(fillPayload.insn);

    const auto recomputed = recomputeInsnAddresses(stream);
    ASSERT_TRUE(recomputed.is_ok()) << to_string(recomputed.unwrap_err());
    ASSERT_TRUE(setInsnBranchTarget(stream[0], stream[2].address).is_ok());
    ASSERT_TRUE(setInsnBranchTarget(stream[3], stream[5].address).is_ok());
    ASSERT_TRUE(setInsnBranchTarget(stream[6], stream[8].address).is_ok());

    auto encoded = encodeInsns(stream);
    ASSERT_TRUE(encoded.is_ok()) << to_string(encoded.unwrap_err());
    const std::vector<ca::u8> bytes = std::move(encoded).unwrap();
    // 规范标识在产物字节里。
    EXPECT_EQ(bytes[8], 0x01);
    EXPECT_EQ(bytes[9], 0x01);

    auto decoded = decodeInsns(viewOf(bytes));
    ASSERT_TRUE(decoded.is_ok()) << to_string(decoded.unwrap_err());
    const std::vector<Insn>& back = decoded.unwrap();
    ASSERT_EQ(back.size(), 9u);
    EXPECT_EQ(back[2].payloadKind, PayloadKind::PackedSwitch);
    ASSERT_EQ(back[2].payloadCount, 3u);
    EXPECT_EQ(back[2].payloadFirstKey, 10);
    EXPECT_EQ(back[2].packedSwitchTarget(0), -2);
    EXPECT_EQ(back[2].packedSwitchTarget(2), 8);
    EXPECT_EQ(back[5].payloadKind, PayloadKind::SparseSwitch);
    EXPECT_EQ(back[5].sparseSwitchKey(1), 9);
    EXPECT_EQ(back[5].sparseSwitchTarget(2), 1);
    EXPECT_EQ(back[8].payloadKind, PayloadKind::FillArrayData);
    ASSERT_EQ(back[8].payloadCount, 2u);
    ASSERT_EQ(back[8].payloadElementWidth, 2u);
    ASSERT_EQ(back[8].payloadData.size(), 4u);
    EXPECT_EQ(back[8].payloadData.data()[0], 0x78);

    auto again = encodeInsns(back);
    ASSERT_TRUE(again.is_ok());
    EXPECT_EQ(again.unwrap(), bytes);

    // 31t 宽 3：紧跟的 payload 落在奇地址，整流编码拒绝且不自动插 nop。
    std::vector<Insn> misaligned;
    misaligned.push_back(packedSwitch);
    misaligned.push_back(packedPayload.insn);
    ASSERT_TRUE(recomputeInsnAddresses(misaligned).is_ok());
    EXPECT_EQ(encodeInsns(misaligned).unwrap_err(), InsnEncodeError::MisalignedPayload);
}

TEST(DexInsnAdapter, RejectsBadPayloadBuilders)
{
    EXPECT_EQ(makeSparseSwitchPayload({9, 5}, {1, 2}).unwrap_err(),
              InsnEncodeError::BadPayload);  // key 递减
    EXPECT_EQ(makeSparseSwitchPayload({5, 5}, {1, 2}).unwrap_err(),
              InsnEncodeError::BadPayload);  // key 重复
    EXPECT_EQ(makeSparseSwitchPayload({5}, {1, 2}).unwrap_err(),
              InsnEncodeError::BadPayload);  // 个数不等
    EXPECT_EQ(makeFillArrayDataPayload(0, {1}).unwrap_err(), InsnEncodeError::BadPayload);
    EXPECT_EQ(makeFillArrayDataPayload(3, {1, 2, 3, 4}).unwrap_err(),
              InsnEncodeError::BadPayload);  // 字节数不是宽度倍数

    // 宽度 4+2n ≤ 65535 → n ≤ 32765。
    const std::vector<ca::i32> tooMany(32766, 0);
    EXPECT_EQ(makePackedSwitchPayload(0, tooMany).unwrap_err(),
              InsnEncodeError::OperandOverflow);
}
