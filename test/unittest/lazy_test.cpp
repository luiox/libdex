/// @file        lazy_test.cpp
/// @brief       eager 骨架 / lazy 数据与 peek 语义测试。
#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

TEST(DexLazy, PeekDoesNotDecode)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_EQ(file->peekString(0), nullptr);
    EXPECT_EQ(file->peekClassData(0), nullptr);
    EXPECT_EQ(file->peekString(999), nullptr);
    EXPECT_EQ(file->peekClassData(999), nullptr);

    const auto name = file->string(0);
    ASSERT_TRUE(name.is_ok());
    EXPECT_EQ(name.unwrap().as_std_view(), "Hello.java");
    ASSERT_NE(file->peekString(0), nullptr);
    EXPECT_EQ(file->peekString(0)->as_std_view(), "Hello.java");

    const auto dataResult = file->classData(0);
    ASSERT_TRUE(dataResult.is_ok());
    const ClassData* data = dataResult.unwrap();
    ASSERT_NE(data, nullptr);
    ASSERT_NE(file->peekClassData(0), nullptr);
    EXPECT_EQ(file->peekClassData(0), data);

    const ca::u32 codeOff = data->directMethods[0].codeOff;
    EXPECT_EQ(file->peekCodeItem(codeOff), nullptr);

    const auto codeResult = file->codeItem(codeOff);
    ASSERT_TRUE(codeResult.is_ok());
    const CodeItem* code = codeResult.unwrap();
    ASSERT_NE(code, nullptr);
    EXPECT_EQ(file->peekCodeItem(codeOff), code);
}

TEST(DexLazy, CachesDecodedResults)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    const auto first = file->string(2);
    ASSERT_TRUE(first.is_ok());
    const auto second = file->string(2);
    ASSERT_TRUE(second.is_ok());
    EXPECT_EQ(first.unwrap().data(), second.unwrap().data());
    EXPECT_EQ(first.unwrap().size(), second.unwrap().size());

    const auto dataFirst = file->classData(0);
    const auto dataSecond = file->classData(0);
    ASSERT_TRUE(dataFirst.is_ok());
    ASSERT_TRUE(dataSecond.is_ok());
    EXPECT_EQ(dataFirst.unwrap(), dataSecond.unwrap());

    const ca::u32 codeOff = dataFirst.unwrap()->directMethods[0].codeOff;
    const auto codeFirst = file->codeItem(codeOff);
    const auto codeSecond = file->codeItem(codeOff);
    ASSERT_TRUE(codeFirst.is_ok());
    ASSERT_TRUE(codeSecond.is_ok());
    EXPECT_EQ(codeFirst.unwrap(), codeSecond.unwrap());
}

TEST(DexLazy, InternsAndDedupesStrings)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();
    const ca::u32 before = file->stringCount();

    const auto first = file->internUtf8("Hello2.java");
    ASSERT_TRUE(first.is_ok());
    EXPECT_EQ(first.unwrap(), before);

    const auto again = file->internUtf8("Hello2.java");
    ASSERT_TRUE(again.is_ok());
    EXPECT_EQ(again.unwrap(), first.unwrap());
    EXPECT_EQ(file->stringCount(), before + 1);

    const auto text = file->string(first.unwrap());
    ASSERT_TRUE(text.is_ok());
    EXPECT_EQ(text.unwrap().as_std_view(), "Hello2.java");

    const auto item = file->stringData(first.unwrap());
    ASSERT_TRUE(item.is_ok());
    ASSERT_GE(item.unwrap().size(), 2u);
    EXPECT_EQ(item.unwrap().front(), 11u);  // UTF-16 code unit 数
    EXPECT_EQ(item.unwrap().back(), 0u);

    const auto name = file->internUtf8("\xE5\x90\x8D\xE5\xAD\x97");  // "名字"
    ASSERT_TRUE(name.is_ok());
    const auto nameItem = file->stringData(name.unwrap());
    ASSERT_TRUE(nameItem.is_ok());
    EXPECT_EQ(nameItem.unwrap().front(), 2u);

    const auto emoji = file->internUtf8("\xF0\x9F\x98\x80");  // U+1F600，代理对
    ASSERT_TRUE(emoji.is_ok());
    const auto emojiItem = file->stringData(emoji.unwrap());
    ASSERT_TRUE(emojiItem.is_ok());
    EXPECT_EQ(emojiItem.unwrap().front(), 2u);

    const ca::u8 bad[] = {0x80};
    const auto invalid =
        file->internString(jstr::MUtf8StringRef(reinterpret_cast<const char*>(bad), 1));
    ASSERT_TRUE(invalid.is_err());
    EXPECT_EQ(invalid.unwrap_err(), ReadError::BadStringData);
}

TEST(DexLazy, BorrowedSourceStaysUsable)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();

    ReadOptions opt;
    opt.preserveSourceBytes = false;

    auto result = readDex(dex_test::asSlice(bytes), opt);
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_TRUE(file->hasSource());
    const auto name = file->classDescriptor(0);
    ASSERT_TRUE(name.is_ok());
    EXPECT_EQ(name.unwrap().as_std_view(), "LHello;");

    const auto written = writeDex(*file);
    ASSERT_TRUE(written.is_ok());
    EXPECT_EQ(written.unwrap(), bytes);
}
