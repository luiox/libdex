/// @file        smali_test.cpp
/// @brief       libsmali 反汇编冒烟与（汇编器就位后的）文本往返。
#include "smali/disassemble.hpp"
#include "smali/opcodes.hpp"

#include <string>
#include <vector>

#include "dex/reader.hpp"

#include <gtest/gtest.h>

#include "dex_fixture.hpp"

namespace {

using namespace dex::core;
using namespace dex::smali;
using dex_test::asSlice;

}   // namespace

TEST(DexSmali, DisassemblesFixtureClass)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    Result<std::unique_ptr<DexFile>, ReadError> parsed = readDex(asSlice(bytes));
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

    const Result<std::string, SmaliError> text = disassembleClass(*file, 0);
    ASSERT_TRUE(text.is_ok());

    const std::string& s = text.unwrap();
    EXPECT_NE(s.find(".class public LHello;"), std::string::npos);
    EXPECT_NE(s.find(".super Ljava/lang/Object;"), std::string::npos);
    EXPECT_NE(s.find(".field"), std::string::npos);
    EXPECT_NE(s.find(".method"), std::string::npos);
    EXPECT_NE(s.find("return-void"), std::string::npos);
    EXPECT_NE(s.find(".end method"), std::string::npos);
}

TEST(DexSmali, DisassemblyIsDeterministic)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    Result<std::unique_ptr<DexFile>, ReadError> a = readDex(asSlice(bytes));
    Result<std::unique_ptr<DexFile>, ReadError> b = readDex(asSlice(bytes));
    ASSERT_TRUE(a.is_ok() && b.is_ok());
    std::unique_ptr<DexFile> fa = std::move(a).unwrap();
    std::unique_ptr<DexFile> fb = std::move(b).unwrap();
    const Result<std::string, SmaliError> ta = disassembleClass(*fa, 0);
    const Result<std::string, SmaliError> tb = disassembleClass(*fb, 0);
    ASSERT_TRUE(ta.is_ok() && tb.is_ok());
    EXPECT_EQ(ta.unwrap(), tb.unwrap());
}
