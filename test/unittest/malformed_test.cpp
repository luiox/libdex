/// @file        malformed_test.cpp
/// @brief       结构损坏 fail-closed 与语义降级（Recovered）测试。
#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

TEST(DexMalformed, RejectsStructuralDamage)
{
    EXPECT_TRUE(readDex(ByteSlice{}).is_err());

    {
        std::vector<ca::u8> bytes = dex_test::makeHelloDex();
        bytes[0] = 'X';
        const auto r = readDex(dex_test::asSlice(bytes));
        ASSERT_TRUE(r.is_err());
        EXPECT_EQ(r.unwrap_err(), ReadError::BadMagic);
    }
    {
        std::vector<ca::u8> bytes = dex_test::makeHelloDex();
        bytes[4] = '0';
        bytes[5] = '9';
        bytes[6] = '9';
        const auto r = readDex(dex_test::asSlice(bytes));
        ASSERT_TRUE(r.is_err());
        EXPECT_EQ(r.unwrap_err(), ReadError::UnsupportedVersion);
    }
    {
        std::vector<ca::u8> bytes = dex_test::makeHelloDex();
        bytes.resize(0x40);
        const auto r = readDex(dex_test::asSlice(bytes));
        ASSERT_TRUE(r.is_err());
        EXPECT_EQ(r.unwrap_err(), ReadError::Truncated);
    }
    {
        std::vector<ca::u8> bytes = dex_test::makeHelloDex();
        dex_test::patchU32(bytes, dex_test::kHeaderEndianTagField, 0x78563412u);
        const auto r = readDex(dex_test::asSlice(bytes));
        ASSERT_TRUE(r.is_err());
        EXPECT_EQ(r.unwrap_err(), ReadError::BadEndianTag);
    }
    {
        std::vector<ca::u8> bytes = dex_test::makeHelloDex();
        dex_test::patchU32(bytes, dex_test::kHeaderSizeField, 0x60u);
        const auto r = readDex(dex_test::asSlice(bytes));
        ASSERT_TRUE(r.is_err());
        EXPECT_EQ(r.unwrap_err(), ReadError::BadHeaderSize);
    }
    {
        std::vector<ca::u8> bytes = dex_test::makeHelloDex();
        dex_test::patchU32(bytes, dex_test::kHeaderStringIdsOffField, 0xFFFFFF00u);
        const auto r = readDex(dex_test::asSlice(bytes));
        ASSERT_TRUE(r.is_err());
        EXPECT_EQ(r.unwrap_err(), ReadError::BadTableSpan);
    }
}

TEST(DexMalformed, ChecksumMismatchIsRecovered)
{
    std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    dex_test::patchU32(bytes, dex_test::kHeaderChecksumField,
                       dex_test::readU32(bytes, dex_test::kHeaderChecksumField) ^ 1u);

    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_EQ(file->state(), ParseState::Recovered);
    EXPECT_TRUE(file->diagnostics().contains(ReadError::BadChecksum));
    EXPECT_FALSE(file->diagnostics().contains(ReadError::BadSignature));

    const auto name = file->classDescriptor(0);
    ASSERT_TRUE(name.is_ok());
    EXPECT_EQ(name.unwrap().as_std_view(), "LHello;");
}

TEST(DexMalformed, SignatureMismatchIsRecovered)
{
    std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    bytes[dex_test::kHeaderSignatureField] ^= 0xFFu;

    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_EQ(file->state(), ParseState::Recovered);
    EXPECT_TRUE(file->diagnostics().contains(ReadError::BadSignature));
    EXPECT_TRUE(file->diagnostics().contains(ReadError::BadChecksum));
}

TEST(DexMalformed, IntegrityCheckCanBeDisabled)
{
    std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    dex_test::patchU32(bytes, dex_test::kHeaderChecksumField,
                       dex_test::readU32(bytes, dex_test::kHeaderChecksumField) ^ 1u);

    ReadOptions opt;
    opt.verifyIntegrity = false;

    auto result = readDex(dex_test::asSlice(bytes), opt);
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();
    EXPECT_EQ(file->state(), ParseState::Validated);
    EXPECT_TRUE(file->diagnostics().empty());
}

TEST(DexMalformed, DanglingStringOffsetIsRecoveredButUndecodable)
{
    std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    dex_test::patchU32(bytes, dex_test::kStringIdsTableOff, 0xFFFFFF00u);

    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_EQ(file->state(), ParseState::Recovered);
    EXPECT_TRUE(file->diagnostics().contains(ReadError::BadIndex));
    EXPECT_TRUE(file->string(0).is_err());
}

TEST(DexMalformed, DanglingClassDataOffsetIsRecoveredButUndecodable)
{
    std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    dex_test::patchU32(bytes, dex_test::kClassDefClassDataField, 0xFFFFFF00u);

    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_EQ(file->state(), ParseState::Recovered);
    EXPECT_TRUE(file->diagnostics().contains(ReadError::BadIndex));
    EXPECT_TRUE(file->classData(0).is_err());
}

TEST(DexMalformed, BadMapOffsetIsRecovered)
{
    std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    dex_test::patchU32(bytes, dex_test::kHeaderMapOffField, 0xFFFFFF00u);

    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_EQ(file->state(), ParseState::Recovered);
    EXPECT_TRUE(file->diagnostics().contains(ReadError::BadMapList));
    EXPECT_TRUE(file->mapItems.empty());

    // 头部表仍然可读——map 是目录，不是唯一寻址路径。
    const auto name = file->classDescriptor(0);
    ASSERT_TRUE(name.is_ok());
    EXPECT_EQ(name.unwrap().as_std_view(), "LHello;");
}

TEST(DexMalformed, BadClassDataPayloadFailsClosed)
{
    std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    dex_test::patchU32(bytes, dex_test::kClassDefClassDataField, 1u);

    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_TRUE(file->classData(0).is_err());
}
