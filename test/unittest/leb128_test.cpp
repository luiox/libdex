/// @file        leb128_test.cpp
/// @brief       ULEB128 读取边界：规范编码、冗余填充容忍、溢出与截断。
#include <gtest/gtest.h>

#include <utility>

#include "dex/dex.hpp"

using namespace dex::core;

namespace {

Reader readerFor(const ca::u8* data, ca::usize size)
{
    const ca::core::Bytes source = ca::core::Bytes::from_static(data, size);
    return std::move(Reader::at(source, 0)).unwrap();
}

}   // namespace

TEST(DexLeb128, ReadsCanonicalEncoding)
{
    const ca::u8 bytes[] = {0xE5, 0x8E, 0x26};  // 624485
    Reader cur = readerFor(bytes, sizeof(bytes));

    const auto value = readUleb128(cur);
    ASSERT_TRUE(value.is_ok());
    EXPECT_EQ(value.unwrap(), 624485u);
    EXPECT_EQ(cur.pos(), 3u);
}

TEST(DexLeb128, AcceptsRedundantPadding)
{
    // libca 的 get_var_u32 把 [80 00] 判为 MalformedVarint；DEX 读取面
    // 按 ART 的宽容度接受非最小编码，避免混淆产物被误拒。
    const ca::u8 bytes[] = {0x80, 0x00};
    Reader cur = readerFor(bytes, sizeof(bytes));

    const auto value = readUleb128(cur);
    ASSERT_TRUE(value.is_ok());
    EXPECT_EQ(value.unwrap(), 0u);
    EXPECT_EQ(cur.pos(), 2u);
}

TEST(DexLeb128, ReadsU32Maximum)
{
    const ca::u8 bytes[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x0F};
    Reader cur = readerFor(bytes, sizeof(bytes));

    const auto value = readUleb128(cur);
    ASSERT_TRUE(value.is_ok());
    EXPECT_EQ(value.unwrap(), 0xFFFFFFFFu);
    EXPECT_EQ(cur.pos(), 5u);
}

TEST(DexLeb128, RejectsOverflow)
{
    const ca::u8 bytes[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x1F};
    Reader cur = readerFor(bytes, sizeof(bytes));

    const auto value = readUleb128(cur);
    ASSERT_TRUE(value.is_err());
    EXPECT_EQ(value.unwrap_err(), ReadError::BadLeb128);
}

TEST(DexLeb128, RejectsTruncated)
{
    const ca::u8 bytes[] = {0x80};
    Reader cur = readerFor(bytes, sizeof(bytes));

    const auto value = readUleb128(cur);
    ASSERT_TRUE(value.is_err());
    EXPECT_EQ(value.unwrap_err(), ReadError::Truncated);
}

TEST(DexLeb128, ReadsSignedValues)
{
    const ca::u8 negativeOne[] = {0x7F};
    Reader cur = readerFor(negativeOne, sizeof(negativeOne));
    const auto minusOne = readSleb128(cur);
    ASSERT_TRUE(minusOne.is_ok());
    EXPECT_EQ(minusOne.unwrap(), -1);

    const ca::u8 negativeBig[] = {0x9B, 0xF1, 0x59};
    Reader cur2 = readerFor(negativeBig, sizeof(negativeBig));
    const auto minus = readSleb128(cur2);
    ASSERT_TRUE(minus.is_ok());
    EXPECT_EQ(minus.unwrap(), -624485);

    const ca::u8 minInt[] = {0x80, 0x80, 0x80, 0x80, 0x78};
    Reader cur3 = readerFor(minInt, sizeof(minInt));
    const auto minimum = readSleb128(cur3);
    ASSERT_TRUE(minimum.is_ok());
    EXPECT_EQ(minimum.unwrap(), -2147483647 - 1);
}

TEST(DexLeb128, AcceptsRedundantSignExtension)
{
    const ca::u8 bytes[] = {0xFF, 0x7F};
    Reader cur = readerFor(bytes, sizeof(bytes));

    const auto value = readSleb128(cur);
    ASSERT_TRUE(value.is_ok());
    EXPECT_EQ(value.unwrap(), -1);
}

TEST(DexLeb128, RejectsSignedOverflowAndTruncation)
{
    const ca::u8 overflow[] = {0x80, 0x80, 0x80, 0x80, 0x80};
    Reader cur = readerFor(overflow, sizeof(overflow));
    const auto bad = readSleb128(cur);
    ASSERT_TRUE(bad.is_err());
    EXPECT_EQ(bad.unwrap_err(), ReadError::BadLeb128);

    const ca::u8 truncated[] = {0x80};
    Reader cur2 = readerFor(truncated, sizeof(truncated));
    const auto missing = readSleb128(cur2);
    ASSERT_TRUE(missing.is_err());
    EXPECT_EQ(missing.unwrap_err(), ReadError::Truncated);
}
