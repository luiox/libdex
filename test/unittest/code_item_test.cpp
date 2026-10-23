/// @file        code_item_test.cpp
/// @brief       code_item 的 try_item 与 encoded_catch_handler 解析。
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"

using namespace dex::core;

namespace {

void putU16(std::vector<ca::u8>& out, ca::u16 value)
{
    out.push_back(static_cast<ca::u8>(value & 0xFFu));
    out.push_back(static_cast<ca::u8>(value >> 8));
}

void putU32(std::vector<ca::u8>& out, ca::u32 value)
{
    out.push_back(static_cast<ca::u8>(value & 0xFFu));
    out.push_back(static_cast<ca::u8>((value >> 8) & 0xFFu));
    out.push_back(static_cast<ca::u8>((value >> 16) & 0xFFu));
    out.push_back(static_cast<ca::u8>((value >> 24) & 0xFFu));
}

// 头部（2 insns、1 try）+ try_item + 调用方给的 handler 表。
std::vector<ca::u8> makeTryCodeItem(ca::u32 start, ca::u16 count, ca::u16 handlerOff,
                                    const std::vector<ca::u8>& handlerList)
{
    std::vector<ca::u8> bytes;
    putU16(bytes, 2);  // registers_size
    putU16(bytes, 0);  // ins_size
    putU16(bytes, 0);  // outs_size
    putU16(bytes, 1);  // tries_size
    putU32(bytes, 0);  // debug_info_off
    putU32(bytes, 2);  // insns_size
    putU16(bytes, 0x000e);
    putU16(bytes, 0x0000);
    putU32(bytes, start);
    putU16(bytes, count);
    putU16(bytes, handlerOff);
    bytes.insert(bytes.end(), handlerList.begin(), handlerList.end());
    return bytes;
}

// count=1，size=-2（两条 typed + catch-all）。
std::vector<ca::u8> handlerWithCatchAll()
{
    return {0x01, 0x7e, 0x00, 0x00, 0x01, 0x01, 0x00};
}

// count=1，size=2（两条 typed，无 catch-all）。
std::vector<ca::u8> handlerWithoutCatchAll()
{
    return {0x01, 0x02, 0x00, 0x00, 0x01, 0x01};
}

ByteSlice viewOf(const std::vector<ca::u8>& bytes)
{
    return ByteSlice{bytes.data(), bytes.size()};
}

}   // namespace

TEST(DexCodeItem, ParsesTypedAndCatchAllHandlers)
{
    const std::vector<ca::u8> bytes = makeTryCodeItem(0, 2, 1, handlerWithCatchAll());
    const auto parsed = parseCodeItem(viewOf(bytes), 0, 2, nullptr);
    ASSERT_TRUE(parsed.is_ok()) << to_string(parsed.unwrap_err());

    const CodeItem& item = parsed.unwrap();
    EXPECT_EQ(item.registersSize, 2u);
    EXPECT_EQ(item.insnsSize, 2u);
    EXPECT_EQ(item.insns.offset, 16u);
    EXPECT_EQ(item.insns.length, 4u);
    EXPECT_EQ(item.raw.offset, 0u);
    EXPECT_EQ(item.raw.length, 28u);
    EXPECT_EQ(item.handlers.offset, 28u);
    EXPECT_EQ(item.handlers.length, 7u);

    ASSERT_EQ(item.tryBlocks.size(), 1u);
    EXPECT_EQ(item.tryBlocks[0].startAddress, 0u);
    EXPECT_EQ(item.tryBlocks[0].insnCount, 2u);
    EXPECT_EQ(item.tryBlocks[0].handlerOff, 1u);  // 相对 handler 表起点，首个 handler 在计数之后
    EXPECT_EQ(item.tryBlocks[0].handlerIndex, 0u);

    ASSERT_EQ(item.catchHandlers.size(), 1u);
    const CatchHandler& handler = item.catchHandlers[0];
    ASSERT_EQ(handler.typed.size(), 2u);
    EXPECT_EQ(handler.typed[0].typeIdx, 0u);
    EXPECT_EQ(handler.typed[0].address, 0u);
    EXPECT_EQ(handler.typed[1].typeIdx, 1u);
    EXPECT_EQ(handler.typed[1].address, 1u);
    EXPECT_TRUE(handler.hasCatchAll);
    EXPECT_EQ(handler.catchAllAddress, 0u);
}

TEST(DexCodeItem, ParsesHandlerWithoutCatchAll)
{
    const std::vector<ca::u8> bytes = makeTryCodeItem(0, 2, 1, handlerWithoutCatchAll());
    const auto parsed = parseCodeItem(viewOf(bytes), 0, 2, nullptr);
    ASSERT_TRUE(parsed.is_ok()) << to_string(parsed.unwrap_err());

    const CodeItem& item = parsed.unwrap();
    ASSERT_EQ(item.catchHandlers.size(), 1u);
    EXPECT_EQ(item.catchHandlers[0].typed.size(), 2u);
    EXPECT_FALSE(item.catchHandlers[0].hasCatchAll);
    EXPECT_EQ(item.handlers.length, 6u);
}

TEST(DexCodeItem, WarnsOnDanglingTypeAndBadTryRange)
{
    {
        Diagnostics diagnostics;
        const std::vector<ca::u8> bytes = makeTryCodeItem(0, 2, 1, handlerWithCatchAll());
        const auto parsed = parseCodeItem(viewOf(bytes), 0, 1, &diagnostics);
        ASSERT_TRUE(parsed.is_ok());
        EXPECT_TRUE(diagnostics.contains(ReadError::BadIndex));
    }
    {
        Diagnostics diagnostics;
        const std::vector<ca::u8> bytes = makeTryCodeItem(1, 2, 1, handlerWithCatchAll());
        const auto parsed = parseCodeItem(viewOf(bytes), 0, 2, &diagnostics);
        ASSERT_TRUE(parsed.is_ok());
        EXPECT_TRUE(diagnostics.contains(ReadError::BadCodeItem));
    }
}

TEST(DexCodeItem, RejectsMalformedHandlerTables)
{
    {
        const std::vector<ca::u8> bytes = makeTryCodeItem(0, 2, 5, handlerWithCatchAll());
        const auto parsed = parseCodeItem(viewOf(bytes), 0, 2, nullptr);
        ASSERT_TRUE(parsed.is_err());
        EXPECT_EQ(parsed.unwrap_err(), ReadError::BadCodeItem);
    }
    {
        const std::vector<ca::u8> bytes = makeTryCodeItem(0, 2, 1, {0x02, 0x00});
        const auto parsed = parseCodeItem(viewOf(bytes), 0, 2, nullptr);
        ASSERT_TRUE(parsed.is_err());
        EXPECT_EQ(parsed.unwrap_err(), ReadError::BadCodeItem);
    }
    {
        const std::vector<ca::u8> bytes = makeTryCodeItem(0, 2, 1, {0x01, 0x02});
        const auto parsed = parseCodeItem(viewOf(bytes), 0, 2, nullptr);
        ASSERT_TRUE(parsed.is_err());
        EXPECT_EQ(parsed.unwrap_err(), ReadError::BadCodeItem);
    }
    {
        const ca::u8 header[] = {0x02, 0x00, 0x00, 0x00};
        const auto parsed = parseCodeItem(ByteSlice{header, sizeof(header)}, 0, 0, nullptr);
        ASSERT_TRUE(parsed.is_err());
        EXPECT_EQ(parsed.unwrap_err(), ReadError::BadCodeItem);
    }
    {
        const std::vector<ca::u8> bytes = makeTryCodeItem(0, 2, 1, handlerWithCatchAll());
        const auto parsed = parseCodeItem(viewOf(bytes), 4096, 2, nullptr);
        ASSERT_TRUE(parsed.is_err());
        EXPECT_EQ(parsed.unwrap_err(), ReadError::BadCodeItem);
    }
}
