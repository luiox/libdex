/// @file        writer_items_test.cpp
/// @brief       class_data_item / code_item 的整条目重编码。
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

TEST(DexWrite, ReencodesFixtureClassData)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(ByteSlice{bytes.data(), bytes.size()});
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

    const auto data = file->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);

    const auto encoded = writeClassData(*data.unwrap());
    ASSERT_TRUE(encoded.is_ok()) << to_string(encoded.unwrap_err());

    const ByteSlice raw =
        subOrEmpty(file->source(), data.unwrap()->raw.offset, data.unwrap()->raw.length);
    ASSERT_EQ(encoded.unwrap().size(), raw.size());
    EXPECT_EQ(std::memcmp(encoded.unwrap().data(), raw.data(), raw.size()), 0);
}

TEST(DexWrite, ReencodesFixtureCodeItem)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(ByteSlice{bytes.data(), bytes.size()});
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

    const auto data = file->classData(0);
    ASSERT_TRUE(data.is_ok());
    const EncodedMethod& method = data.unwrap()->directMethods[0];
    const auto code = file->codeItem(method.codeOff);
    ASSERT_TRUE(code.is_ok());
    ASSERT_NE(code.unwrap(), nullptr);

    const ByteSlice insns =
        subOrEmpty(file->source(), code.unwrap()->insns.offset, code.unwrap()->insns.length);
    const auto decoded = decodeInsns(insns);
    ASSERT_TRUE(decoded.is_ok());
    const auto encodedInsns = encodeInsns(decoded.unwrap());
    ASSERT_TRUE(encodedInsns.is_ok());

    const auto encoded = writeCodeItem(*code.unwrap(), ByteSlice{encodedInsns.unwrap().data(),
                                                                 encodedInsns.unwrap().size()});
    ASSERT_TRUE(encoded.is_ok()) << to_string(encoded.unwrap_err());

    const ca::u32 end = code.unwrap()->handlersOff != 0
                            ? code.unwrap()->handlers.offset + code.unwrap()->handlers.length
                            : code.unwrap()->raw.offset + code.unwrap()->raw.length;
    const ByteSlice raw =
        subOrEmpty(file->source(), code.unwrap()->offset, end - code.unwrap()->offset);
    ASSERT_EQ(encoded.unwrap().size(), raw.size());
    EXPECT_EQ(std::memcmp(encoded.unwrap().data(), raw.data(), raw.size()), 0);
}
