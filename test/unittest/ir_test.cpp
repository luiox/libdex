/// @file        ir_test.cpp
/// @brief       CodeDom：指令、分支/switch label 与 try 区域。
#include <initializer_list>
#include <memory>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;
using namespace dex::ir;

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

CodeItem itemFor(const std::vector<ca::u8>& bytes)
{
    CodeItem item;
    item.insns = ByteSpan{0, static_cast<ca::u32>(bytes.size())};
    item.insnsSize = static_cast<ca::u32>(bytes.size() / 2);
    return item;
}

ca::core::Bytes sourceFor(const std::vector<ca::u8>& bytes)
{
    return ca::core::Bytes::from_static(bytes.data(), bytes.size());
}

}   // namespace

TEST(DexIr, BuildsFromFixtureCodeItem)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

    const auto classDataResult = file->classData(0);
    ASSERT_TRUE(classDataResult.is_ok());
    ASSERT_NE(classDataResult.unwrap(), nullptr);

    const ca::u32 codeOff = classDataResult.unwrap()->directMethods[0].codeOff;
    auto domResult = buildCodeDom(*file, codeOff);
    ASSERT_TRUE(domResult.is_ok()) << to_string(domResult.unwrap_err());

    const CodeDom& dom = std::move(domResult).unwrap();
    ASSERT_EQ(dom.insns().size(), 1u);
    EXPECT_EQ(dom.insns()[0].opcode, 0x0e);
    EXPECT_EQ(dom.insnsSize(), 1u);
    EXPECT_TRUE(dom.labels().empty());
    EXPECT_TRUE(dom.tryRegions().empty());
    EXPECT_TRUE(dom.issues().empty());
    EXPECT_EQ(dom.source().len(), file->source().size());
    EXPECT_FALSE(dom.hasLabel(0));
}

TEST(DexIr, CollectsBranchLabels)
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x0038, 0x0002,  // 0: if-eqz v0, +2
        0x000e,          // 2: return-void
        0x000e,          // 3: return-void
    });
    const CodeItem item = itemFor(bytes);

    auto domResult = buildCodeDom(sourceFor(bytes), item);
    ASSERT_TRUE(domResult.is_ok()) << to_string(domResult.unwrap_err());
    const CodeDom& dom = std::move(domResult).unwrap();

    ASSERT_EQ(dom.insns().size(), 3u);
    ASSERT_EQ(dom.labels().size(), 1u);
    EXPECT_EQ(dom.labels()[0], 2u);
    EXPECT_TRUE(dom.hasLabel(2));
    EXPECT_TRUE(dom.issues().empty());
}

TEST(DexIr, CollectsSwitchPayloadAndCaseLabels)
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x002b, 0x0004, 0x0000,  // 0: packed-switch v0, +4
        0x0000,                  // 3: nop
        0x0100, 0x0001,          // 4: payload, size=1
        0x000a, 0x0000,          // 6: first_key=10
        0x000a, 0x0000,          // 8: target +10（相对 switch）
        0x000e,                  // 10: return-void
    });
    const CodeItem item = itemFor(bytes);

    auto domResult = buildCodeDom(sourceFor(bytes), item);
    ASSERT_TRUE(domResult.is_ok()) << to_string(domResult.unwrap_err());
    const CodeDom& dom = std::move(domResult).unwrap();

    ASSERT_EQ(dom.insns().size(), 4u);
    ASSERT_EQ(dom.labels().size(), 2u);
    EXPECT_EQ(dom.labels()[0], 4u);
    EXPECT_EQ(dom.labels()[1], 10u);
    EXPECT_TRUE(dom.issues().empty());
}

TEST(DexIr, FlattensTryRegions)
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x000e,  // 0: return-void
        0x000e,  // 1: return-void
    });
    CodeItem item = itemFor(bytes);

    TryBlock block;
    block.startAddress = 0;
    block.insnCount = 1;
    block.handlerOff = 0;
    block.handlerIndex = 0;
    item.tryBlocks.push_back(block);

    CatchHandler handler;
    handler.typed.push_back(TypedCatch{5, 1});
    handler.hasCatchAll = true;
    handler.catchAllAddress = 0;
    item.catchHandlers.push_back(handler);

    auto domResult = buildCodeDom(sourceFor(bytes), item);
    ASSERT_TRUE(domResult.is_ok()) << to_string(domResult.unwrap_err());
    const CodeDom& dom = std::move(domResult).unwrap();

    ASSERT_EQ(dom.tryRegions().size(), 2u);
    EXPECT_EQ(dom.tryRegions()[0].startAddress, 0u);
    EXPECT_EQ(dom.tryRegions()[0].endAddress, 1u);
    EXPECT_EQ(dom.tryRegions()[0].handlerAddress, 1u);
    EXPECT_EQ(dom.tryRegions()[0].typeIndex, 5);
    EXPECT_FALSE(dom.tryRegions()[0].isCatchAll());

    EXPECT_EQ(dom.tryRegions()[1].handlerAddress, 0u);
    EXPECT_TRUE(dom.tryRegions()[1].isCatchAll());

    ASSERT_EQ(dom.labels().size(), 2u);
    EXPECT_EQ(dom.labels()[0], 0u);
    EXPECT_EQ(dom.labels()[1], 1u);
    EXPECT_TRUE(dom.issues().empty());
}

TEST(DexIr, ReportsOutOfRangeBranch)
{
    const std::vector<ca::u8> bytes = codeUnits({
        0x0038, 0x0064,  // 0: if-eqz v0, +100
        0x000e,          // 2: return-void
    });
    const CodeItem item = itemFor(bytes);

    auto domResult = buildCodeDom(sourceFor(bytes), item);
    ASSERT_TRUE(domResult.is_ok()) << to_string(domResult.unwrap_err());
    const CodeDom& dom = std::move(domResult).unwrap();

    ASSERT_EQ(dom.issues().size(), 1u);
    EXPECT_EQ(dom.issues()[0].kind, CodeIssueKind::BranchTargetOutOfRange);
    EXPECT_EQ(dom.issues()[0].address, 100);
    EXPECT_EQ(dom.issues()[0].sourceAddress, 0u);
    EXPECT_TRUE(dom.labels().empty());
}

TEST(DexIr, PropagatesInstructionDecodeErrors)
{
    const std::vector<ca::u8> bytes = codeUnits({0x003e});
    const CodeItem item = itemFor(bytes);

    const auto domResult = buildCodeDom(sourceFor(bytes), item);
    ASSERT_TRUE(domResult.is_err());
    EXPECT_EQ(domResult.unwrap_err(), CodeError::UnknownOpcode);
}
