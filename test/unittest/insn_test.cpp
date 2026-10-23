/// @file        insn_test.cpp
/// @brief       指令解码：操作码表、全格式操作数、payload 与错误路径。
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

}   // namespace

TEST(DexInsn, OpcodeMetadata)
{
    EXPECT_STREQ(opcodeInfo(0x00).name, "nop");
    EXPECT_EQ(opcodeInfo(0x00).format, InsnFormat::F10x);
    EXPECT_EQ(opcodeInfo(0x22).format, InsnFormat::F21c);
    EXPECT_EQ(opcodeInfo(0x22).indexKind, IndexKind::Type);
    EXPECT_EQ(opcodeInfo(0x6e).format, InsnFormat::F35c);
    EXPECT_EQ(opcodeInfo(0x6e).indexKind, IndexKind::Method);
    EXPECT_EQ(opcodeInfo(0xfa).format, InsnFormat::F45cc);
    EXPECT_EQ(opcodeInfo(0xfc).indexKind, IndexKind::CallSite);
    EXPECT_EQ(opcodeInfo(0xff).indexKind, IndexKind::Proto);

    const ca::u8 unused[] = {0x3e, 0x43, 0x73, 0x79, 0x7a, 0xe3, 0xf9};
    for (const ca::u8 opcode : unused) {
        EXPECT_FALSE(opcodeInfo(opcode).isDefined()) << "opcode 0x" << std::hex << +opcode;
    }

    ca::u32 defined = 0;
    for (ca::u32 opcode = 0; opcode < 256; ++opcode) {
        if (opcodeInfo(static_cast<ca::u8>(opcode)).isDefined()) {
            ++defined;
        }
    }
    EXPECT_EQ(defined, 224u);

    EXPECT_EQ(insnWidth(InsnFormat::F10x), 1u);
    EXPECT_EQ(insnWidth(InsnFormat::F22c), 2u);
    EXPECT_EQ(insnWidth(InsnFormat::F35c), 3u);
    EXPECT_EQ(insnWidth(InsnFormat::F45cc), 4u);
    EXPECT_EQ(insnWidth(InsnFormat::F51l), 5u);
    EXPECT_EQ(insnWidth(InsnFormat::Payload), 0u);
}

TEST(DexInsn, DecodesOperandFormats)
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x000e,                                  //  0: return-void
        0x8112,                                  //  1: const/4 v1, #-8
        0x001a, 0x1234,                          //  2: const-string v0, string@0x1234
        0x0122, 0x0010,                          //  4: new-instance v1, type@0x0010
        0x0023, 0x0011,                          //  6: new-array v0, v0, type@0x0011
        0x2132, 0x0004,                          //  8: if-eq v1, v2, +4
        0x0038, 0xfffa,                          // 10: if-eqz v0, -6
        0x21d0, 0xfffe,                          // 12: add-int/lit16 v1, v2, #-2
        0x01d8, 0xff02,                          // 14: add-int/lit8 v1, v2, #-1
        0x206e, 0x0005, 0x0021,                  // 16: invoke-virtual {v1, v2}, method@5
        0x0374, 0x0006, 0x0003,                  // 19: invoke-virtual/range {v3..v5}, method@6
        0x11fa, 0x0007, 0x0000, 0x0008,          // 22: invoke-polymorphic {v0}, method@7, proto@8
        0x0015, 0x1234,                          // 26: const/high16 v0, #0x1234
        0x0019, 0x1234,                          // 28: const-wide/high16 v0, #0x1234
        0x0018, 0x7788, 0x5566, 0x3344, 0x1122,  // 30: const-wide v0, #0x1122334455667788
        0x0500,                                  // 35: nop（高字节非零，按 ART 宽容度接受）
        0x0031, 0x0201,                          // 36: cmp-long v0, v1, v2
        0x0003, 0x0001, 0x0002,                  // 38: move/16 v1, v2
        0x001b, 0x2345, 0x0001,                  // 41: const-string/jumbo v0, string@0x12345
    });

    const auto decoded = decodeInsns(viewOf(bytes));
    ASSERT_TRUE(decoded.is_ok()) << to_string(decoded.unwrap_err());
    const std::vector<Insn>& insns = decoded.unwrap();

    ASSERT_EQ(insns.size(), 19u);
    ca::u32 sum = 0;
    for (const Insn& insn : insns) {
        sum += insn.width;
    }
    EXPECT_EQ(sum, 44u);

    EXPECT_EQ(insns[0].address, 0u);
    EXPECT_EQ(insns[0].format, InsnFormat::F10x);

    EXPECT_EQ(insns[1].format, InsnFormat::F11n);
    EXPECT_EQ(insns[1].registers[0], 1u);
    EXPECT_EQ(insns[1].literal, -8);

    EXPECT_EQ(insns[2].address, 2u);
    EXPECT_EQ(insns[2].indexKind, IndexKind::String);
    EXPECT_EQ(insns[2].index, 0x1234u);
    EXPECT_EQ(insns[2].registers[0], 0u);

    EXPECT_EQ(insns[3].address, 4u);
    EXPECT_EQ(insns[3].format, InsnFormat::F21c);
    EXPECT_EQ(insns[3].indexKind, IndexKind::Type);
    EXPECT_EQ(insns[3].index, 0x0010u);

    EXPECT_EQ(insns[4].format, InsnFormat::F22c);
    EXPECT_EQ(insns[4].registers[0], 0u);
    EXPECT_EQ(insns[4].registers[1], 0u);
    EXPECT_EQ(insns[4].index, 0x0011u);

    EXPECT_EQ(insns[5].format, InsnFormat::F22t);
    EXPECT_EQ(insns[5].registers[0], 1u);
    EXPECT_EQ(insns[5].registers[1], 2u);
    EXPECT_EQ(insns[5].branchOffset, 4);

    EXPECT_EQ(insns[6].format, InsnFormat::F21t);
    EXPECT_EQ(insns[6].branchOffset, -6);

    EXPECT_EQ(insns[7].format, InsnFormat::F22s);
    EXPECT_EQ(insns[7].registers[0], 1u);
    EXPECT_EQ(insns[7].registers[1], 2u);
    EXPECT_EQ(insns[7].literal, -2);

    EXPECT_EQ(insns[8].format, InsnFormat::F22b);
    EXPECT_EQ(insns[8].registers[0], 1u);
    EXPECT_EQ(insns[8].registers[1], 2u);
    EXPECT_EQ(insns[8].literal, -1);

    EXPECT_EQ(insns[9].address, 16u);
    EXPECT_EQ(insns[9].format, InsnFormat::F35c);
    EXPECT_EQ(insns[9].registerCount, 2u);
    EXPECT_EQ(insns[9].registers[0], 1u);
    EXPECT_EQ(insns[9].registers[1], 2u);
    EXPECT_EQ(insns[9].index, 5u);
    EXPECT_FALSE(insns[9].hasProtoIndex);

    EXPECT_EQ(insns[10].format, InsnFormat::F3rc);
    EXPECT_EQ(insns[10].registerCount, 3u);
    EXPECT_EQ(insns[10].startRegister, 3u);
    EXPECT_EQ(insns[10].index, 6u);

    EXPECT_EQ(insns[11].format, InsnFormat::F45cc);
    EXPECT_EQ(insns[11].registerCount, 1u);
    EXPECT_EQ(insns[11].registers[0], 0u);
    EXPECT_EQ(insns[11].index, 7u);
    EXPECT_TRUE(insns[11].hasProtoIndex);
    EXPECT_EQ(insns[11].protoIndex, 8u);

    EXPECT_EQ(insns[12].format, InsnFormat::F21h);
    EXPECT_EQ(insns[12].literal, 0x12340000);

    EXPECT_EQ(insns[13].literal, static_cast<ca::i64>(0x1234) * 0x0001000000000000LL);

    EXPECT_EQ(insns[14].format, InsnFormat::F51l);
    EXPECT_EQ(insns[14].literal, 0x1122334455667788LL);

    EXPECT_EQ(insns[15].address, 35u);
    EXPECT_EQ(insns[15].opcode, 0u);
    EXPECT_EQ(insns[15].width, 1u);

    EXPECT_EQ(insns[16].format, InsnFormat::F23x);
    EXPECT_EQ(insns[16].registers[0], 0u);
    EXPECT_EQ(insns[16].registers[1], 1u);
    EXPECT_EQ(insns[16].registers[2], 2u);

    EXPECT_EQ(insns[17].format, InsnFormat::F32x);
    EXPECT_EQ(insns[17].registers[0], 1u);
    EXPECT_EQ(insns[17].registers[1], 2u);

    EXPECT_EQ(insns[18].format, InsnFormat::F31c);
    EXPECT_EQ(insns[18].index, 0x00012345u);

    const auto encoded = encodeInsns(insns);
    ASSERT_TRUE(encoded.is_ok()) << to_string(encoded.unwrap_err());
    EXPECT_EQ(encoded.unwrap(), bytes);
}

TEST(DexInsn, SignExtendsImmediates)
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x0013, 0xfff0,          // 0: const/16 v0, #-16
        0x0015, 0xffff,          // 2: const/high16 v0, #-1
        0x0019, 0xffff,          // 4: const-wide/high16 v0, #-1
        0x0014, 0x0000, 0x8000,  // 6: const v0, #-2147483648
    });

    const auto decoded = decodeInsns(viewOf(bytes));
    ASSERT_TRUE(decoded.is_ok()) << to_string(decoded.unwrap_err());
    const std::vector<Insn>& insns = decoded.unwrap();

    ASSERT_EQ(insns.size(), 4u);
    EXPECT_EQ(insns[0].literal, -16);
    EXPECT_EQ(insns[1].literal, -65536);
    EXPECT_EQ(insns[2].literal, -static_cast<ca::i64>(0x0001000000000000LL));
    EXPECT_EQ(insns[3].literal, -2147483648LL);
}

TEST(DexInsn, DecodesPackedSwitchPayload)
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x002b, 0x0004, 0x0000,  // 0: packed-switch v0, +4
        0x0000,                  // 3: nop（保证 payload 落在偶数地址）
        0x0100, 0x0002,          // 4: packed-switch-payload, size=2
        0x000a, 0x0000,          // 6: first_key=10
        0xfffe, 0xffff,          // 8: target 0 = -2
        0x0003, 0x0000,          // 10: target 1 = +3
    });

    const auto decoded = decodeInsns(viewOf(bytes));
    ASSERT_TRUE(decoded.is_ok()) << to_string(decoded.unwrap_err());
    const std::vector<Insn>& insns = decoded.unwrap();

    ASSERT_EQ(insns.size(), 3u);
    EXPECT_EQ(insns[0].opcode, 0x2b);
    EXPECT_EQ(insns[0].branchOffset, 4);

    const Insn& payload = insns[2];
    EXPECT_EQ(payload.address, 4u);
    EXPECT_EQ(payload.width, 8u);
    EXPECT_TRUE(payload.isPayload());
    EXPECT_EQ(payload.payloadKind, PayloadKind::PackedSwitch);
    ASSERT_EQ(payload.payloadCount, 2u);
    EXPECT_EQ(payload.payloadFirstKey, 10);
    EXPECT_EQ(payload.packedSwitchTarget(0), -2);
    EXPECT_EQ(payload.packedSwitchTarget(1), 3);

    const auto encoded = encodeInsns(insns);
    ASSERT_TRUE(encoded.is_ok()) << to_string(encoded.unwrap_err());
    EXPECT_EQ(encoded.unwrap(), bytes);
}

TEST(DexInsn, DecodesSparseSwitchPayload)
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x002c, 0x0004, 0x0000,  // 0: sparse-switch v0, +4
        0x0000,                  // 3: nop
        0x0200, 0x0002,          // 4: sparse-switch-payload, size=2
        0x0005, 0x0000,          // 6: key 0 = 5
        0x0009, 0x0000,          // 8: key 1 = 9
        0xfffe, 0xffff,          // 10: target 0 = -2
        0x0004, 0x0000,          // 12: target 1 = +4
    });

    const auto decoded = decodeInsns(viewOf(bytes));
    ASSERT_TRUE(decoded.is_ok()) << to_string(decoded.unwrap_err());
    const std::vector<Insn>& insns = decoded.unwrap();

    ASSERT_EQ(insns.size(), 3u);
    const Insn& payload = insns[2];
    EXPECT_EQ(payload.address, 4u);
    EXPECT_EQ(payload.width, 10u);
    EXPECT_EQ(payload.payloadKind, PayloadKind::SparseSwitch);
    ASSERT_EQ(payload.payloadCount, 2u);
    EXPECT_EQ(payload.sparseSwitchKey(0), 5);
    EXPECT_EQ(payload.sparseSwitchKey(1), 9);
    EXPECT_EQ(payload.sparseSwitchTarget(0), -2);
    EXPECT_EQ(payload.sparseSwitchTarget(1), 4);

    const auto encoded = encodeInsns(insns);
    ASSERT_TRUE(encoded.is_ok()) << to_string(encoded.unwrap_err());
    EXPECT_EQ(encoded.unwrap(), bytes);
}

TEST(DexInsn, DecodesFillArrayDataPayload)
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x0026, 0x0004, 0x0000,  // 0: fill-array-data v0, +4
        0x0000,                  // 3: nop
        0x0300, 0x0002,          // 4: fill-array-data-payload, element_width=2
        0x0003, 0x0000,          // 6: size=3
        0x1122, 0x3344, 0x5566,  // 8: data（6 字节，占 3 个 code unit）
    });

    const auto decoded = decodeInsns(viewOf(bytes));
    ASSERT_TRUE(decoded.is_ok()) << to_string(decoded.unwrap_err());
    const std::vector<Insn>& insns = decoded.unwrap();

    ASSERT_EQ(insns.size(), 3u);
    const Insn& payload = insns[2];
    EXPECT_EQ(payload.address, 4u);
    EXPECT_EQ(payload.width, 7u);
    EXPECT_EQ(payload.payloadKind, PayloadKind::FillArrayData);
    EXPECT_EQ(payload.payloadElementWidth, 2u);
    ASSERT_EQ(payload.payloadCount, 3u);
    ASSERT_EQ(payload.payloadData.size(), 6u);
    EXPECT_EQ(payload.payloadData.data()[0], 0x22u);
    EXPECT_EQ(payload.payloadData.data()[5], 0x55u);

    const auto encoded = encodeInsns(insns);
    ASSERT_TRUE(encoded.is_ok()) << to_string(encoded.unwrap_err());
    EXPECT_EQ(encoded.unwrap(), bytes);
}

TEST(DexInsn, RejectsUnknownOpcode)
{
    const std::vector<ca::u8> reserved = codeUnits({0x003e});
    const auto reservedResult = decodeInsns(viewOf(reserved));
    ASSERT_TRUE(reservedResult.is_err());
    EXPECT_EQ(reservedResult.unwrap_err(), InsnError::UnknownOpcode);

    const std::vector<ca::u8> unused = codeUnits({0x0073});
    const auto unusedResult = decodeInsns(viewOf(unused));
    ASSERT_TRUE(unusedResult.is_err());
    EXPECT_EQ(unusedResult.unwrap_err(), InsnError::UnknownOpcode);
}

TEST(DexInsn, RejectsTruncatedInstruction)
{
    const std::vector<ca::u8> bytes = codeUnits({0x0014, 0x1234});  // const 需要 3 个 unit
    const auto result = decodeInsns(viewOf(bytes));
    ASSERT_TRUE(result.is_err());
    EXPECT_EQ(result.unwrap_err(), InsnError::Truncated);

    const ca::u8 oddBytes[] = {0x0e, 0x00, 0x00};  // 3 字节无法构成整数个 code unit
    const auto oddResult = decodeInsns(ByteSlice{oddBytes, sizeof(oddBytes)});
    ASSERT_TRUE(oddResult.is_err());
    EXPECT_EQ(oddResult.unwrap_err(), InsnError::Truncated);
}

TEST(DexInsn, RejectsBadPayload)
{
    const std::vector<ca::u8> misaligned = codeUnits({
        0x0000,  // 0: nop
        0x0100,  // 1: payload 标识落在奇地址
    });
    const auto misalignedResult = decodeInsns(viewOf(misaligned));
    ASSERT_TRUE(misalignedResult.is_err());
    EXPECT_EQ(misalignedResult.unwrap_err(), InsnError::BadPayload);

    const std::vector<ca::u8> truncated = codeUnits({
        0x0100, 0x0002,  // size=2，但后面没有 target
    });
    const auto truncatedResult = decodeInsns(viewOf(truncated));
    ASSERT_TRUE(truncatedResult.is_err());
    EXPECT_EQ(truncatedResult.unwrap_err(), InsnError::Truncated);

    const std::vector<ca::u8> zeroWidth = codeUnits({
        0x0300, 0x0000,  // element_width=0
        0x0001, 0x0000,  // size=1
    });
    const auto zeroWidthResult = decodeInsns(viewOf(zeroWidth));
    ASSERT_TRUE(zeroWidthResult.is_err());
    EXPECT_EQ(zeroWidthResult.unwrap_err(), InsnError::BadPayload);
}

TEST(DexInsn, EmptyStreamDecodesToNothing)
{
    const auto result = decodeInsns(ByteSlice{});
    ASSERT_TRUE(result.is_ok());
    EXPECT_TRUE(result.unwrap().empty());
}

TEST(DexInsn, PreservesRawCodeUnits)
{
    // 第二个 unit 是高字节非零的 nop 变体：语义上仍是 nop，原始字节必须保留。
    const std::vector<ca::u8> bytes = codeUnits({0x0000, 0xAB00, 0x000E});
    const auto decoded = decodeInsns(viewOf(bytes));
    ASSERT_TRUE(decoded.is_ok());
    ASSERT_EQ(decoded.unwrap().size(), 3u);

    EXPECT_EQ(decoded.unwrap()[0].raw.size(), 2u);
    EXPECT_EQ(decoded.unwrap()[0].raw[1], 0x00);
    EXPECT_EQ(decoded.unwrap()[1].raw.size(), 2u);
    EXPECT_EQ(decoded.unwrap()[1].raw[0], 0x00);
    EXPECT_EQ(decoded.unwrap()[1].raw[1], 0xAB);
    EXPECT_EQ(decoded.unwrap()[2].raw.size(), 2u);
    EXPECT_EQ(decoded.unwrap()[2].raw[0], 0x0E);
}

TEST(DexInsn, RejectsUnencodableInsns)
{
    std::vector<ca::u8> out;

    Insn regOverflow;
    regOverflow.opcode = 0x01;  // move (12x)
    regOverflow.format = InsnFormat::F12x;
    regOverflow.registers[0] = 16;
    EXPECT_EQ(encodeInsn(regOverflow, out).unwrap_err(),
              InsnEncodeError::OperandOverflow);
    EXPECT_TRUE(out.empty());

    Insn indexOverflow;
    indexOverflow.opcode = 0x1a;  // const-string
    indexOverflow.format = InsnFormat::F21c;
    indexOverflow.index = 0x10000;
    out.clear();
    EXPECT_EQ(encodeInsn(indexOverflow, out).unwrap_err(),
              InsnEncodeError::OperandOverflow);
    EXPECT_TRUE(out.empty());

    Insn high16;
    high16.opcode = 0x15;  // const/high16
    high16.format = InsnFormat::F21h;
    high16.literal = 1;
    out.clear();
    EXPECT_EQ(encodeInsn(high16, out).unwrap_err(), InsnEncodeError::OperandOverflow);

    Insn callCount;
    callCount.opcode = 0x6e;  // invoke-virtual
    callCount.format = InsnFormat::F35c;
    callCount.registerCount = 16;
    out.clear();
    EXPECT_EQ(encodeInsn(callCount, out).unwrap_err(), InsnEncodeError::OperandOverflow);

    Insn badFormat;
    badFormat.opcode = 0x12;
    badFormat.format = InsnFormat::F10x;
    out.clear();
    EXPECT_EQ(encodeInsn(badFormat, out).unwrap_err(), InsnEncodeError::BadFormat);

    Insn unknownOpcode;
    unknownOpcode.opcode = 0x3e;
    unknownOpcode.format = InsnFormat::F10x;
    out.clear();
    EXPECT_EQ(encodeInsn(unknownOpcode, out).unwrap_err(), InsnEncodeError::BadFormat);

    Insn returnVoid;
    returnVoid.opcode = 0x0e;
    returnVoid.format = InsnFormat::F10x;
    Insn payload;
    payload.format = InsnFormat::Payload;
    payload.payloadKind = PayloadKind::PackedSwitch;
    const auto misaligned = encodeInsns({returnVoid, payload});
    ASSERT_TRUE(misaligned.is_err());
    EXPECT_EQ(misaligned.unwrap_err(), InsnEncodeError::MisalignedPayload);
}

TEST(DexInsn, DecodesFixtureCodeItem)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

    const auto classDataResult = file->classData(0);
    ASSERT_TRUE(classDataResult.is_ok());
    const ClassData* classData = classDataResult.unwrap();
    ASSERT_NE(classData, nullptr);
    ASSERT_FALSE(classData->directMethods.empty());

    const auto codeResult = file->codeItem(classData->directMethods[0].codeOff);
    ASSERT_TRUE(codeResult.is_ok());
    const CodeItem* code = codeResult.unwrap();
    ASSERT_NE(code, nullptr);

    const ByteSlice insnsBytes = subOrEmpty(file->source(), code->insns.offset, code->insns.length);
    const auto decoded = decodeInsns(insnsBytes);
    ASSERT_TRUE(decoded.is_ok()) << to_string(decoded.unwrap_err());
    const std::vector<Insn>& insns = decoded.unwrap();
    ASSERT_EQ(insns.size(), 1u);
    EXPECT_EQ(insns[0].opcode, 0x0e);
    EXPECT_EQ(insns[0].format, InsnFormat::F10x);
    EXPECT_EQ(insns[0].width, code->insnsSize);
}
