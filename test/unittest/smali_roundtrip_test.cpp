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

namespace {

/// @brief 汇编 → buildDex → 重读；失败时打印汇编诊断并返回 nullptr。
std::unique_ptr<DexFile> buildFrom(const char* text)
{
    std::unique_ptr<DexFile> fresh = DexFile::createEmpty(35);
    SmaliAssembler assembler(*fresh);
    if (auto ar = assembler.assembleClass(text); ar.is_err()) {
        std::fprintf(stderr, "asm err line=%u code=%s detail=%s\n", ar.unwrap_err().line,
                     to_string(ar.unwrap_err().code), ar.unwrap_err().detail.c_str());
        return nullptr;
    }
    const Result<std::vector<ca::u8>, WriteError> built =
        buildDex(*fresh, assembler.options());
    if (built.is_err()) {
        std::fprintf(stderr, "step: buildDex failed\n");
        return nullptr;
    }
    Result<std::unique_ptr<DexFile>, ReadError> reparsed =
        readDex(ByteSlice{built.unwrap().data(), built.unwrap().size()});
    if (reparsed.is_err()) {
        std::fprintf(stderr, "step: reparse failed\n");
        return nullptr;
    }
    return std::move(reparsed).unwrap();
}

/// @brief 反汇编 → 再汇编 → 再反汇编：文本逐字节一致即往返成立。
::testing::AssertionResult textRoundtrips(const char* src)
{
    std::unique_ptr<DexFile> once = buildFrom(src);
    if (once == nullptr) {
        return ::testing::AssertionFailure() << "first assemble failed";
    }
    const Result<std::string, SmaliError> t1 = disassembleClass(*once, 0);
    if (t1.is_err()) {
        return ::testing::AssertionFailure() << "first disasm failed";
    }
    std::unique_ptr<DexFile> twice = buildFrom(t1.unwrap().c_str());
    if (twice == nullptr) {
        return ::testing::AssertionFailure() << "re-assemble failed:\n" << t1.unwrap();
    }
    const Result<std::string, SmaliError> t2 = disassembleClass(*twice, 0);
    if (t2.is_err()) {
        return ::testing::AssertionFailure() << "second disasm failed";
    }
    if (t1.unwrap() != t2.unwrap()) {
        return ::testing::AssertionFailure()
               << "text mismatch:\n--- first ---\n" << t1.unwrap()
               << "--- second ---\n" << t2.unwrap();
    }
    return ::testing::AssertionSuccess();
}

}   // namespace

TEST(DexSmaliRoundtrip, F22xSecondRegisterSurvives)
{
    // F22x/F32x 第二寄存器在 registers[1]（List 布局）：汇编端曾写进
    // startRegister（Range 专用），编码器读 registers[1] → 恒编成 v0。
    const char* kSrc =
        ".class public LWide2;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static pick([III)I\n"
        "    .registers 6\n"
        "    move/from16 v5, v3\n"
        "    return v5\n"
        ".end method\n";
    std::unique_ptr<DexFile> dex = buildFrom(kSrc);
    ASSERT_NE(dex, nullptr);
    const auto data = dex->classData(0);
    ASSERT_TRUE(data.is_ok() && data.unwrap() != nullptr);
    ASSERT_FALSE(data.unwrap()->directMethods.empty());
    const Result<const CodeItem*, ReadError> code =
        dex->codeItem(data.unwrap()->directMethods[0].codeOff);
    ASSERT_TRUE(code.is_ok() && code.unwrap() != nullptr);
    const Result<std::vector<Insn>, InsnError> insns = decodeInsns(
        subOrEmpty(dex->source(), code.unwrap()->insns.offset, code.unwrap()->insns.length));
    ASSERT_TRUE(insns.is_ok());
    ASSERT_FALSE(insns.unwrap().empty());
    EXPECT_EQ(insns.unwrap().front().opcode, 0x02);  // move/from16
    EXPECT_EQ(insns.unwrap().front().registers[1], 3u)
        << "second register must encode v3, not v0";

    EXPECT_TRUE(textRoundtrips(kSrc));
}

TEST(DexSmaliRoundtrip, DebugLocalEventsRoundtrip)
{
    // .end local / .restart local 曾是汇编器死分支（t0 按空白切分后恒为
    // ".end"），自家反汇编输出无法回编。
    const char* kSrc =
        ".class public LLocals;\n"
        ".super Ljava/lang/Object;\n"
        ".method public foo()V\n"
        "    .registers 2\n"
        "    .local v0, \"x\":I\n"
        "    const/4 v0, 1\n"
        "    .end local v0\n"
        "    .restart local v0\n"
        "    return-void\n"
        ".end method\n";
    std::unique_ptr<DexFile> dex = buildFrom(kSrc);
    ASSERT_NE(dex, nullptr);
    const Result<std::string, SmaliError> t1 = disassembleClass(*dex, 0);
    ASSERT_TRUE(t1.is_ok());
    EXPECT_NE(t1.unwrap().find(".end local"), std::string::npos);
    EXPECT_NE(t1.unwrap().find(".restart local"), std::string::npos);
    EXPECT_TRUE(textRoundtrips(kSrc));
}

TEST(DexSmaliRoundtrip, NegativeHigh16Roundtrip)
{
    // F21h 负值按位模式渲染会溢出 i64，汇编端 strtoll 钳位后整类回编失败：
    // 反汇编端负值必须带符号前缀，汇编端 0x 前缀按补码回卷。
    const char* kSrc =
        ".class public LHigh16;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static neg()I\n"
        "    .registers 2\n"
        "    const/high16 v0, 0xffff0000\n"
        "    return v0\n"
        ".end method\n"
        ".method public static dneg()D\n"
        "    .registers 4\n"
        "    const-wide/high16 v0, 0xbff0000000000000\n"
        "    return-wide v0\n"
        ".end method\n";
    std::unique_ptr<DexFile> dex = buildFrom(kSrc);
    ASSERT_NE(dex, nullptr);
    const auto data = dex->classData(0);
    ASSERT_TRUE(data.is_ok() && data.unwrap() != nullptr);
    const std::vector<EncodedMethod>& methods = data.unwrap()->directMethods;
    ASSERT_EQ(methods.size(), 2u);
    for (const EncodedMethod& m : methods) {
        const Result<const CodeItem*, ReadError> code = dex->codeItem(m.codeOff);
        ASSERT_TRUE(code.is_ok() && code.unwrap() != nullptr);
        const Result<std::vector<Insn>, InsnError> insns = decodeInsns(
            subOrEmpty(dex->source(), code.unwrap()->insns.offset,
                       code.unwrap()->insns.length));
        ASSERT_TRUE(insns.is_ok());
        const ca::u8 op = insns.unwrap().front().opcode;
        ASSERT_TRUE(op == 0x15 || op == 0x19) << "unexpected opcode " << static_cast<int>(op);
        // const/high16 → -65536；const-wide/high16 → double 位模式 -1.0。
        EXPECT_EQ(insns.unwrap().front().literal,
                  op == 0x15 ? static_cast<ca::i64>(-65536)
                             : static_cast<ca::i64>(0xbff0000000000000ULL));
    }
    EXPECT_TRUE(textRoundtrips(kSrc));
}

TEST(DexSmaliRoundtrip, FieldAnnotationKeepsFollowingField)
{
    // 单行 .annotation 后的 ++i 曾无条件吃掉下一行：第二个字段静默丢失。
    const char* kSrc =
        ".class public LAnn;\n"
        ".super Ljava/lang/Object;\n"
        ".field public static a:I\n"
        "    .annotation runtime Lann/Mark; count = 7 .end annotation\n"
        ".field public static b:I\n"
        "    .annotation runtime Lann/Mark; count = 9 .end annotation\n"
        ".method public constructor <init>()V\n"
        "    .registers 1\n"
        "    invoke-direct {v0}, Ljava/lang/Object;-><init>()V\n"
        "    return-void\n"
        ".end method\n";
    std::unique_ptr<DexFile> dex = buildFrom(kSrc);
    ASSERT_NE(dex, nullptr);
    const auto data = dex->classData(0);
    ASSERT_TRUE(data.is_ok() && data.unwrap() != nullptr);
    EXPECT_EQ(data.unwrap()->staticFields.size(), 2u)
        << "both annotated static fields must survive";
    EXPECT_TRUE(textRoundtrips(kSrc));
}

TEST(DexSmaliRoundtrip, ParameterAnnotationRoundtrip)
{
    // 反汇编端不生成 .end parameter-annotation：汇编端按「下一行不再是
    // .annotation」收敛，否则会吞掉整个方法体。
    const char* kSrc =
        ".class public LParamAnn;\n"
        ".super Ljava/lang/Object;\n"
        ".method public foo(I)V\n"
        "    .registers 2\n"
        "    return-void\n"
        "    .parameter-annotation 0\n"
        "    .annotation runtime Lann/Mark; count = 3 .end annotation\n"
        ".end method\n";
    std::unique_ptr<DexFile> dex = buildFrom(kSrc);
    ASSERT_NE(dex, nullptr);
    const auto data = dex->classData(0);
    ASSERT_TRUE(data.is_ok() && data.unwrap() != nullptr);
    // foo 是非静态方法 → virtualMethods。
    ASSERT_EQ(data.unwrap()->virtualMethods.size(), 1u);
    const Result<std::string, SmaliError> t1 = disassembleClass(*dex, 0);
    ASSERT_TRUE(t1.is_ok());
    EXPECT_NE(t1.unwrap().find(".parameter-annotation"), std::string::npos);
    EXPECT_TRUE(textRoundtrips(kSrc));
}
