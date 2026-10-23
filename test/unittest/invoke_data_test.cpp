/// @file        invoke_data_test.cpp
/// @brief       call_site_id / method_handle 定长表的读取与保真字段。
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

TEST(DexTables, ReadsCallSitesAndMethodHandles)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(ByteSlice{bytes.data(), bytes.size()});
    ASSERT_TRUE(parsed.is_ok()) << to_string(parsed.unwrap_err());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

    ASSERT_NE(file->findMapItem(MapType::CallSiteIdItem), nullptr);
    ASSERT_NE(file->findMapItem(MapType::MethodHandleItem), nullptr);
    ASSERT_EQ(file->callSiteCount(), 1u);
    ASSERT_EQ(file->methodHandleCount(), 1u);

    EXPECT_EQ(file->callSites[0].callSiteOff, file->classDefs[0].staticValuesOff);

    const MethodHandle& handle = file->methodHandles[0];
    EXPECT_EQ(handle.handleType, 4u);   // invoke-static
    EXPECT_EQ(handle.unused1, 0xBEEFu);
    EXPECT_EQ(handle.targetIdx, 0u);
    EXPECT_EQ(handle.unused2, 0xCAFEu);

    const auto values = file->callSiteValues(0);
    ASSERT_TRUE(values.is_ok());
    ASSERT_NE(values.unwrap(), nullptr);
    EXPECT_TRUE(values.unwrap()->values.empty());
    EXPECT_EQ(values.unwrap()->raw.length, 1u);

    EXPECT_EQ(file->callSiteValues(1).unwrap_err(), ReadError::BadIndex);
}

TEST(DexTables, PreservesUnknownMapSection)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(ByteSlice{bytes.data(), bytes.size()});
    ASSERT_TRUE(parsed.is_ok()) << to_string(parsed.unwrap_err());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

    const MapItem* unknown = file->findMapItem(static_cast<MapType>(0x7F00));
    ASSERT_NE(unknown, nullptr);
    ASSERT_EQ(file->rawSections.size(), 1u);

    const RawSection& section = file->rawSections[0];
    EXPECT_EQ(section.type, 0x7F00u);
    EXPECT_EQ(section.size, 1u);
    EXPECT_EQ(section.span.offset, unknown->offset);
    ASSERT_GE(section.span.length, 4u);

    const ByteSlice raw =
        subOrEmpty(file->source(), section.span.offset, section.span.length);
    ASSERT_EQ(raw.size(), section.span.length);
    EXPECT_EQ(raw[0], 0xDEu);
    EXPECT_EQ(raw[1], 0xADu);
    EXPECT_EQ(raw[2], 0xBEu);
    EXPECT_EQ(raw[3], 0xEFu);
}
