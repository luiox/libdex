/// @file        debug_info_test.cpp
/// @brief       debug_info 状态机的全操作码解码、重编码与错误边界。
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

namespace {

std::vector<ca::u8> bytesOf(std::initializer_list<ca::u8> bytes)
{
    return std::vector<ca::u8>(bytes);
}

ByteSlice viewOf(const std::vector<ca::u8>& bytes)
{
    return ByteSlice{bytes.data(), bytes.size()};
}

/// line_start=0x10, 两个参数名，覆盖全部状态机操作码一次。
std::vector<ca::u8> makeDebugInfo()
{
    return bytesOf({
        0x10,                    // line_start 16
        0x02, 0x05, 0x07,        // parameters_size 2, names {5, 7}
        0x01, 0x03,              // ADVANCE_PC +3
        0x02, 0x7E,              // ADVANCE_LINE -2
        0x03, 0x01, 0x09, 0x04,  // START_LOCAL r1 name9 type4
        0x04, 0x02, 0x0A, 0x06, 0x0B,  // START_LOCAL_EXTENDED r2 name10 type6 sig11
        0x05, 0x01,              // END_LOCAL r1
        0x06, 0x01,              // RESTART_LOCAL r1
        0x07,                    // SET_PROLOGUE_END
        0x08,                    // SET_EPILOGUE_BEGIN
        0x09, 0x0C,              // SET_FILE name12
        0x1D,                    // special：addressDiff 1, lineDiff 0
        0x00,                    // END_SEQUENCE
    });
}

}   // namespace

TEST(DexDebugInfo, DecodesAllOpcodes)
{
    const std::vector<ca::u8> bytes = makeDebugInfo();
    const auto info = readDebugInfo(viewOf(bytes), 0);
    ASSERT_TRUE(info.is_ok()) << to_string(info.unwrap_err());

    EXPECT_EQ(info.unwrap().raw.offset, 0u);
    EXPECT_EQ(info.unwrap().raw.length, bytes.size());
    EXPECT_EQ(info.unwrap().lineStart, 0x10u);
    EXPECT_EQ(info.unwrap().parameterNames, (std::vector<ca::u32>{5, 7}));

    const std::vector<DebugOp>& ops = info.unwrap().ops;
    ASSERT_EQ(ops.size(), 10u);
    EXPECT_EQ(ops[0].opcode, kDbgAdvancePc);
    EXPECT_EQ(ops[0].addressDiff, 3u);
    EXPECT_EQ(ops[1].opcode, kDbgAdvanceLine);
    EXPECT_EQ(ops[1].lineDiff, -2);
    EXPECT_EQ(ops[2].opcode, kDbgStartLocal);
    EXPECT_EQ(ops[2].reg, 1u);
    EXPECT_EQ(ops[2].nameIdx, 9u);
    EXPECT_EQ(ops[2].typeIdx, 4u);
    EXPECT_EQ(ops[3].opcode, kDbgStartLocalExtended);
    EXPECT_EQ(ops[3].reg, 2u);
    EXPECT_EQ(ops[3].sigIdx, 11u);
    EXPECT_EQ(ops[4].opcode, kDbgEndLocal);
    EXPECT_EQ(ops[4].reg, 1u);
    EXPECT_EQ(ops[5].opcode, kDbgRestartLocal);
    EXPECT_EQ(ops[6].opcode, kDbgSetPrologueEnd);
    EXPECT_EQ(ops[7].opcode, kDbgSetEpilogueBegin);
    EXPECT_EQ(ops[8].opcode, kDbgSetFile);
    EXPECT_EQ(ops[8].nameIdx, 12u);
    EXPECT_EQ(ops[9].opcode, 0x1D);
    EXPECT_TRUE(ops[9].isSpecial());
    EXPECT_EQ(ops[9].addressDiff, 1u);
    EXPECT_EQ(ops[9].lineDiff, 0);
}

TEST(DexDebugInfo, ReencodesExactly)
{
    const std::vector<ca::u8> bytes = makeDebugInfo();
    const auto info = readDebugInfo(viewOf(bytes), 0);
    ASSERT_TRUE(info.is_ok());

    const auto encoded = writeDebugInfo(info.unwrap());
    ASSERT_TRUE(encoded.is_ok()) << to_string(encoded.unwrap_err());
    EXPECT_EQ(encoded.unwrap(), bytes);
}

TEST(DexDebugInfo, RejectsMalformedInput)
{
    {
        const std::vector<ca::u8> bytes = bytesOf({0x00, 0x05});
        EXPECT_EQ(readDebugInfo(viewOf(bytes), 0).unwrap_err(), ReadError::Truncated);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({0x00, 0x00, 0x01});
        EXPECT_EQ(readDebugInfo(viewOf(bytes), 0).unwrap_err(), ReadError::Truncated);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({0x00, 0x00});
        EXPECT_EQ(readDebugInfo(viewOf(bytes), 0).unwrap_err(), ReadError::Truncated);
    }
    {
        DebugInfo info;
        DebugOp op;
        op.opcode = 0x1D;
        op.addressDiff = 0;
        op.lineDiff = 0;
        info.ops.push_back(op);
        EXPECT_EQ(writeDebugInfo(info).unwrap_err(), WriteError::Unencodable);
    }
    {
        DebugInfo info;
        DebugOp op;
        op.opcode = kDbgEndSequence;
        info.ops.push_back(op);
        EXPECT_EQ(writeDebugInfo(info).unwrap_err(), WriteError::Unencodable);
    }
}

TEST(DexDebugInfo, PreservesNonMinimalOperandEncodings)
{
    const std::vector<ca::u8> bytes = bytesOf({
        0x80, 0x00,        // line_start 0（非最小 ULEB）
        0x00,              // parameters_size 0
        0x01, 0x83, 0x00,  // ADVANCE_PC +3（非最小 ULEB）
        0x02, 0xFF, 0x7F,  // ADVANCE_LINE -1（非最小 SLEB）
        0x00,              // END_SEQUENCE
    });
    const auto info = readDebugInfo(viewOf(bytes), 0);
    ASSERT_TRUE(info.is_ok());
    EXPECT_EQ(info.unwrap().lineStart, 0u);
    ASSERT_EQ(info.unwrap().ops.size(), 2u);
    EXPECT_EQ(info.unwrap().ops[0].addressDiff, 3u);
    EXPECT_EQ(info.unwrap().ops[1].lineDiff, -1);

    const auto encoded = writeDebugInfo(info.unwrap());
    ASSERT_TRUE(encoded.is_ok());
    EXPECT_EQ(encoded.unwrap(), bytes);
}

TEST(DexDebugInfo, DexFileLazyAccessor)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(viewOf(bytes));
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

    const auto data = file->classData(0);
    ASSERT_TRUE(data.is_ok());
    const EncodedMethod& method = data.unwrap()->directMethods[0];
    const auto code = file->codeItem(method.codeOff);
    ASSERT_TRUE(code.is_ok());
    ASSERT_NE(code.unwrap(), nullptr);
    ASSERT_NE(code.unwrap()->debugInfoOff, 0u);

    const auto info = file->debugInfo(code.unwrap()->debugInfoOff);
    ASSERT_TRUE(info.is_ok());
    ASSERT_NE(info.unwrap(), nullptr);
    EXPECT_EQ(info.unwrap()->lineStart, 0u);
    EXPECT_TRUE(info.unwrap()->parameterNames.empty());
    EXPECT_TRUE(info.unwrap()->ops.empty());

    const auto encoded = writeDebugInfo(*info.unwrap());
    ASSERT_TRUE(encoded.is_ok());
    const ByteSlice raw = subOrEmpty(file->source(), info.unwrap()->raw.offset,
                                     info.unwrap()->raw.length);
    ASSERT_EQ(encoded.unwrap().size(), raw.size());
    EXPECT_EQ(std::memcmp(encoded.unwrap().data(), raw.data(), raw.size()), 0);
}
