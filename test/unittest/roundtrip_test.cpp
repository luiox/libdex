/// @file        roundtrip_test.cpp
/// @brief       未修改字节级往返门禁。
#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

TEST(DexRoundtrip, UnmodifiedBytesAreIdentical)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();

    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    const auto written = writeDex(*file);
    ASSERT_TRUE(written.is_ok()) << to_string(written.unwrap_err());
    EXPECT_EQ(written.unwrap(), bytes);
}

TEST(DexRoundtrip, ReReadsOwnOutput)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();

    auto first = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(first.is_ok());
    std::unique_ptr<DexFile> firstFile = std::move(first).unwrap();
    const auto written = writeDex(*firstFile);
    ASSERT_TRUE(written.is_ok());
    const std::vector<ca::u8> again = written.unwrap();

    auto second = readDex(dex_test::asSlice(again));
    ASSERT_TRUE(second.is_ok());
    std::unique_ptr<DexFile> secondFile = std::move(second).unwrap();

    EXPECT_EQ(secondFile->state(), ParseState::Validated);
    EXPECT_EQ(secondFile->header.version, firstFile->header.version);
    EXPECT_EQ(secondFile->stringCount(), firstFile->stringCount());
    EXPECT_EQ(secondFile->classCount(), firstFile->classCount());

    const auto name = secondFile->classDescriptor(0);
    ASSERT_TRUE(name.is_ok());
    EXPECT_EQ(name.unwrap().as_std_view(), "LHello;");
}

TEST(DexRoundtrip, MissingSourceIsRejected)
{
    DexFile empty;
    const auto written = writeDex(empty);
    ASSERT_TRUE(written.is_err());
    EXPECT_EQ(written.unwrap_err(), WriteError::MissingSource);
}
