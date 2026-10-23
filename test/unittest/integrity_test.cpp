/// @file        integrity_test.cpp
/// @brief       adler32 / SHA-1 已知向量与头部核对测试。
#include <algorithm>
#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

TEST(DexIntegrity, Adler32KnownVector)
{
    const char* text = "123456789";
    const ByteSlice view{reinterpret_cast<const ca::u8*>(text), 9};
    EXPECT_EQ(adler32(view), 0x091E01DEu);
    EXPECT_EQ(adler32(ByteSlice{}), 1u);
}

TEST(DexIntegrity, Sha1KnownVector)
{
    const char* text = "abc";
    const std::array<ca::u8, 20> digest =
        sha1Digest(ByteSlice{reinterpret_cast<const ca::u8*>(text), 3});

    const std::array<ca::u8, 20> expected = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    };
    EXPECT_TRUE(std::equal(digest.begin(), digest.end(), expected.begin()));
}

TEST(DexIntegrity, FixtureHasValidChecksumAndSignature)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();

    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    const Integrity integrity =
        verifyIntegrity(dex_test::asSlice(bytes), file->header.checksum, file->header.signature);
    EXPECT_TRUE(integrity.checksumOk);
    EXPECT_TRUE(integrity.signatureOk);
    EXPECT_TRUE(integrity.ok());
}

TEST(DexIntegrity, DetectsSingleByteCorruption)
{
    std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    const ca::u32 checksum = dex_test::readU32(bytes, dex_test::kHeaderChecksumField);
    const std::array<ca::u8, 20> signature = [&bytes]() {
        std::array<ca::u8, 20> out{};
        std::copy_n(bytes.begin() + dex_test::kHeaderSignatureField, 20, out.begin());
        return out;
    }();

    // 正文任意一字节同时落在 checksum 与 signature 的覆盖区内。
    bytes[dex_test::kStringIdsTableOff] ^= 0x01u;

    const Integrity integrity = verifyIntegrity(dex_test::asSlice(bytes), checksum, signature);
    EXPECT_FALSE(integrity.checksumOk);
    EXPECT_FALSE(integrity.signatureOk);
}
