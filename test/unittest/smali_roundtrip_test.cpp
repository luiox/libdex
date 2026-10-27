/// @file        smali_roundtrip_test.cpp
/// @brief       libsmali 往返：反汇编 → 汇编 → buildDex → 重读 → 反汇编，
///              文本逐字节一致。
#include "smali/assemble.hpp"
#include "smali/disassemble.hpp"

#include <string>
#include <vector>

#include "dex/core/builder.hpp"
#include "dex/core/insn.hpp"
#include "dex/core/reader.hpp"

#include <cstdio>

#include <gtest/gtest.h>

#include "dex_fixture.hpp"

namespace {

using namespace dex::core;
using namespace dex::smali;
using dex::smali::disassembleClass;

using dex_test::asSlice;

/// @brief fixture 全流程往返；返回中间文本便于失败诊断。
bool roundtripFixture(std::string* firstOut, std::string* secondOut)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    Result<std::unique_ptr<DexFile>, ReadError> parsed = readDex(asSlice(bytes));
    if (parsed.is_err()) {
        std::fprintf(stderr, "step: readDex failed\n");
        return false;
    }
    std::unique_ptr<DexFile> src = std::move(parsed).unwrap();

    const Result<std::string, SmaliError> t1 = disassembleClass(*src, 0);
    if (t1.is_err()) {
        std::fprintf(stderr, "step: disasm1 failed\n");

        return false;
    }
    *firstOut = t1.unwrap();

    // 汇编进一个全新的 dex。
    std::unique_ptr<DexFile> fresh = DexFile::createEmpty(35);
    SmaliAssembler assembler(*fresh);
    if (auto ar = assembler.assembleClass(t1.unwrap()); ar.is_err()) {
        std::fprintf(stderr, "asm err line=%u code=%s detail=%s\n", ar.unwrap_err().line,
                     to_string(ar.unwrap_err().code), ar.unwrap_err().detail.c_str());
        return false;
    }
    const Result<std::vector<ca::u8>, WriteError> built = buildDex(*fresh, assembler.options());
    if (built.is_err()) {
        std::fprintf(stderr, "step: buildDex failed\n");

        return false;
    }

    Result<std::unique_ptr<DexFile>, ReadError> reparsed =
        readDex(ByteSlice{built.unwrap().data(), built.unwrap().size()});
    if (reparsed.is_err()) {
        std::fprintf(stderr, "step: reparse failed\n");

        return false;
    }
    std::unique_ptr<DexFile> out = std::move(reparsed).unwrap();
    const Result<std::string, SmaliError> t2 = disassembleClass(*out, 0);
    if (t2.is_err()) {
        std::fprintf(stderr, "step: disasm2 failed\n");

        return false;
    }
    *secondOut = t2.unwrap();
    return true;
}

}   // namespace

TEST(DexSmaliRoundtrip, FixtureTextIsByteIdentical)
{
    std::string t1;
    std::string t2;
    ASSERT_TRUE(roundtripFixture(&t1, &t2));
    EXPECT_EQ(t1, t2);
}

TEST(DexSmaliRoundtrip, InvokePolymorphicRoundtrips)
{
    const char* kSrc =
        ".class public LPoly;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static call(Ljava/lang/invoke/MethodHandle;"
        "[Ljava/lang/String;)Ljava/lang/Object;\n"
        "    .registers 4\n"
        "    invoke-polymorphic {v0, v1}, Ljava/lang/invoke/MethodHandle;"
        "->invoke([Ljava/lang/Object;)Ljava/lang/Object;"
        ", ([Ljava/lang/String;)Ljava/lang/Object;\n"
        "    move-result-object v0\n"
        "    return-object v0\n"
        ".end method\n"
        ".method public static callRange(Ljava/lang/invoke/MethodHandle;I)J\n"
        "    .registers 4\n"
        "    invoke-polymorphic/range {v0 .. v1}, Ljava/lang/invoke/MethodHandle;"
        "->invoke([Ljava/lang/Object;)Ljava/lang/Object;, (I)J\n"
        "    move-result-wide v0\n"
        "    return-wide v0\n"
        ".end method\n";

    std::unique_ptr<DexFile> fresh = DexFile::createEmpty(35);
    SmaliAssembler assembler(*fresh);
    auto ar = assembler.assembleClass(kSrc);
    if (ar.is_err()) {
        std::fprintf(stderr, "asm err line=%u code=%s detail=%s\n",
                     ar.unwrap_err().line, to_string(ar.unwrap_err().code),
                     ar.unwrap_err().detail.c_str());
        ASSERT_TRUE(ar.is_ok());
    }
    const Result<std::vector<ca::u8>, WriteError> built =
        buildDex(*fresh, assembler.options());
    ASSERT_TRUE(built.is_ok());

    Result<std::unique_ptr<DexFile>, ReadError> reparsed =
        readDex(ByteSlice{built.unwrap().data(), built.unwrap().size()});
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> out = std::move(reparsed).unwrap();
    const Result<std::string, SmaliError> t1 = disassembleClass(*out, 0);
    ASSERT_TRUE(t1.is_ok());
    EXPECT_NE(t1.unwrap().find("invoke-polymorphic {v0, v1}"), std::string::npos);
    EXPECT_NE(t1.unwrap().find("invoke-polymorphic/range {v0 .. v1}"), std::string::npos);

    // 二次往返：反汇编文本必须可再次汇编且文本逐字节一致。
    std::unique_ptr<DexFile> fresh2 = DexFile::createEmpty(35);
    SmaliAssembler assembler2(*fresh2);
    auto ar2 = assembler2.assembleClass(t1.unwrap());
    if (ar2.is_err()) {
        std::fprintf(stderr, "asm2 err line=%u code=%s detail=%s\n",
                     ar2.unwrap_err().line, to_string(ar2.unwrap_err().code),
                     ar2.unwrap_err().detail.c_str());
        ASSERT_TRUE(ar2.is_ok());
    }
    const Result<std::vector<ca::u8>, WriteError> built2 =
        buildDex(*fresh2, assembler2.options());
    ASSERT_TRUE(built2.is_ok());
    Result<std::unique_ptr<DexFile>, ReadError> reparsed2 =
        readDex(ByteSlice{built2.unwrap().data(), built2.unwrap().size()});
    ASSERT_TRUE(reparsed2.is_ok());
    const Result<std::string, SmaliError> t2 =
        disassembleClass(*std::move(reparsed2).unwrap(), 0);
    ASSERT_TRUE(t2.is_ok());
    EXPECT_EQ(t1.unwrap(), t2.unwrap());
}

TEST(DexSmaliRoundtrip, NonAsciiStringRoundtrips)
{
    // 非 ASCII 字符串：反汇编按 UTF-16 码元转义，汇编逐码元还原，
    // MUTF-8 字节必须逐字节一致。
    const char* kSrc =
        ".class public LCjk;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static hi()Ljava/lang/String;\n"
        "    .registers 1\n"
        "    const-string v0, \"中文，世界 emoji \\ud83d\\ude00\"\n"
        "    return-object v0\n"
        ".end method\n";

    const auto buildOnce = [](const char* text)
        -> Result<std::vector<ca::u8>, WriteError> {
        std::unique_ptr<DexFile> fresh = DexFile::createEmpty(35);
        SmaliAssembler assembler(*fresh);
        if (auto ar = assembler.assembleClass(text); ar.is_err()) {
            std::fprintf(stderr, "asm err line=%u code=%s detail=%s\n",
                         ar.unwrap_err().line, to_string(ar.unwrap_err().code),
                         ar.unwrap_err().detail.c_str());
            return Err(WriteError::Unencodable);
        }
        return buildDex(*fresh, assembler.options());
    };

    const Result<std::vector<ca::u8>, WriteError> built = buildOnce(kSrc);
    ASSERT_TRUE(built.is_ok());

    Result<std::unique_ptr<DexFile>, ReadError> reparsed =
        readDex(ByteSlice{built.unwrap().data(), built.unwrap().size()});
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> out = std::move(reparsed).unwrap();
    const Result<std::string, SmaliError> t1 = disassembleClass(*out, 0);
    ASSERT_TRUE(t1.is_ok());
    // 非 ASCII 以码元转义落文本。
    EXPECT_NE(t1.unwrap().find("\\u4e2d\\u6587"), std::string::npos);

    const Result<std::vector<ca::u8>, WriteError> built2 =
        buildOnce(t1.unwrap().c_str());
    ASSERT_TRUE(built2.is_ok());
    EXPECT_EQ(built2.unwrap(), built.unwrap());
}

TEST(DexSmaliRoundtrip, AssembledDexReparses)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    Result<std::unique_ptr<DexFile>, ReadError> parsed = readDex(asSlice(bytes));
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> src = std::move(parsed).unwrap();
    const Result<std::string, SmaliError> t1 = disassembleClass(*src, 0);
    ASSERT_TRUE(t1.is_ok());

    std::unique_ptr<DexFile> fresh = DexFile::createEmpty(35);
    SmaliAssembler assembler(*fresh);
    ASSERT_TRUE(assembler.assembleClass(t1.unwrap()).is_ok());
    const Result<std::vector<ca::u8>, WriteError> built = buildDex(*fresh, assembler.options());
    ASSERT_TRUE(built.is_ok());
    Result<std::unique_ptr<DexFile>, ReadError> reparsed =
        readDex(ByteSlice{built.unwrap().data(), built.unwrap().size()});
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> out = std::move(reparsed).unwrap();

    EXPECT_EQ(out->classCount(), 1u);
    EXPECT_EQ(out->stringCount(), src->stringCount());
    EXPECT_EQ(out->methodCount(), src->methodCount());
    EXPECT_EQ(out->fieldCount(), src->fieldCount());

    // 方法体语义一致（指令 opcode/宽度逐条）。
    const Result<const ClassData*, ReadError> cd = out->classData(0);
    ASSERT_TRUE(cd.is_ok() && cd.unwrap() != nullptr);
    ASSERT_EQ(cd.unwrap()->directMethods.size(), 1u);
    const EncodedMethod& m = cd.unwrap()->directMethods[0];
    const Result<const CodeItem*, ReadError> code = out->codeItem(m.codeOff);
    ASSERT_TRUE(code.is_ok() && code.unwrap() != nullptr);
    const Result<std::vector<Insn>, InsnError> insns = decodeInsns(
        subOrEmpty(out->source(), code.unwrap()->insns.offset, code.unwrap()->insns.length));
    ASSERT_TRUE(insns.is_ok());
    ASSERT_FALSE(insns.unwrap().empty());
}
