// vacuum 闭包测试：未引用表项被剔除、引用点全部重写、二次重建固定。
#include "dex/builder.hpp"
#include "dex/reader.hpp"
#include "dex/vacuum.hpp"
#include "smali/assemble.hpp"
#include "smali/disassemble.hpp"
#include "dex_fixture.hpp"
#include <gtest/gtest.h>

namespace {

using dex::core::BuildOptions;
using dex::core::DexFile;
using dex::core::WriteError;

struct Assembled
{
    std::unique_ptr<DexFile> dex;
    dex::core::BuildOptions options;  // 汇编器累积的成员注入
};

/// @brief 汇编一个引用 "used" 字符串的类，并额外 intern 一个无引用字符串。
Assembled makeDexWithOrphanString()
{
    Assembled out;
    out.dex = dex::core::DexFile::createEmpty(35);
    EXPECT_TRUE(out.dex != nullptr);
    const char* kSrc =
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".source \"Use.java\"\n"
        ".method public static hello()Ljava/lang/String;\n"
        "    .registers 1\n"
        "    const-string v0 \"used\"\n"
        "    return-object v0\n"
        ".end method\n";
    dex::smali::SmaliAssembler assembler(*out.dex);
    auto r = assembler.assembleClass(kSrc);
    EXPECT_TRUE(r.is_ok());
    const auto orphan = out.dex->internUtf8("totally-unused-string");
    EXPECT_TRUE(orphan.is_ok());
    out.options = assembler.options();
    out.options.keepUnknownSections = false;
    out.options.vacuumIds = true;
    return out;
}

}   // namespace

TEST(DexVacuum, DropsOrphanStringAndKeepsReferenced)
{
    Assembled a = makeDexWithOrphanString();
    ASSERT_NE(a.dex, nullptr);
    const ca::u32 before = a.dex->stringCount();

    auto built = dex::core::buildDex(*a.dex, a.options);
    ASSERT_TRUE(built.is_ok()) << dex::core::to_string(built.unwrap_err());

    auto reparsed = dex::core::readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok()) << dex::core::to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> out = std::move(reparsed).unwrap();

    EXPECT_LT(out->stringCount(), before);  // 孤儿被剔除
    // 引用字符串仍在：反汇编文本包含 const-string "used"。
    auto text = dex::smali::disassembleClass(*out, 0);
    ASSERT_TRUE(text.is_ok());
    EXPECT_NE(text.unwrap().find("const-string v0 \"used\""), std::string::npos);
    EXPECT_EQ(text.unwrap().find("totally-unused-string"), std::string::npos);
}

TEST(DexVacuum, VacuumIsIdempotent)
{
    Assembled a = makeDexWithOrphanString();
    ASSERT_NE(a.dex, nullptr);

    auto first = dex::core::buildDex(*a.dex, a.options);
    ASSERT_TRUE(first.is_ok());

    auto reparsed = dex::core::readDex(dex_test::asSlice(first.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> out = std::move(reparsed).unwrap();
    // 成员注入已被第一次构建消费（编入 class_data），第二次用干净选项。
    BuildOptions again;
    again.keepUnknownSections = false;
    again.vacuumIds = true;
    auto second = dex::core::buildDex(*out, again);
    ASSERT_TRUE(second.is_ok()) << dex::core::to_string(second.unwrap_err());
    EXPECT_EQ(second.unwrap(), first.unwrap());
}

/// @brief 仅被 .catch 引用的类型也是闭包成员：漏标会让 vacuum 把它剔除，
///        重映射后 handler 悄悄改捕另一个类。
TEST(DexVacuum, KeepsCatchHandlerType)
{
    Assembled out;
    out.dex = dex::core::DexFile::createEmpty(35);
    ASSERT_NE(out.dex, nullptr);
    const char* kSrc =
        ".class public LTryer;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static boom()V\n"
        "    .registers 2\n"
        ":try_start_0\n"
        "    invoke-static {}, LOnlyHere;->thrower()V\n"
        ":try_end_0\n"
        "    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0\n"
        "    return-void\n"
        "    :catch_0\n"
        "    move-exception v0\n"
        "    return-void\n"
        ".end method\n";
    dex::smali::SmaliAssembler assembler(*out.dex);
    auto r = assembler.assembleClass(kSrc);
    ASSERT_TRUE(r.is_ok());
    out.options = assembler.options();
    out.options.keepUnknownSections = false;
    out.options.vacuumIds = true;

    auto built = dex::core::buildDex(*out.dex, out.options);
    ASSERT_TRUE(built.is_ok()) << dex::core::to_string(built.unwrap_err());

    auto reparsed = dex::core::readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> file = std::move(reparsed).unwrap();

    // catch 类型必须仍在 type_ids 且被 handler 引用；反汇编文本可校验。
    auto text = dex::smali::disassembleClass(*file, 0);
    ASSERT_TRUE(text.is_ok());
    EXPECT_NE(text.unwrap().find(".catch Ljava/lang/IllegalStateException;"),
              std::string::npos);
}

TEST(DexVacuum, ClosureKeepsEverythingOnTightCorpus)
{
    auto parsed = dex::core::readDex(dex_test::asSlice(dex_test::makeHelloDex()));
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> dex = std::move(parsed).unwrap();
    ASSERT_NE(dex, nullptr);

    // d8 产物引用紧凑，但 type/proto 冗余仍可能存在；闭包只需自洽：
    // vacuum 后的文件必须可读、可反汇编、类数不变。
    BuildOptions options;
    options.keepUnknownSections = false;
    options.vacuumIds = true;
    auto built = dex::core::buildDex(*dex, options);
    ASSERT_TRUE(built.is_ok()) << dex::core::to_string(built.unwrap_err());

    auto reparsed = dex::core::readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> out = std::move(reparsed).unwrap();
    auto text = dex::smali::disassembleAll(*out);
    ASSERT_TRUE(text.is_ok());
    EXPECT_EQ(text.unwrap().size(), dex->classCount());
}
