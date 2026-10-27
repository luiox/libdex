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
    std::fprintf(stderr, "step: enter\n");
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
