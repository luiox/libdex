/// @file        method_editor_test.cpp
/// @brief       MethodEditor 门面与从零构建 dex（createEmpty → buildDex）。
#include "dex/method_editor.hpp"

#include <vector>

#include "dex/builder.hpp"
#include "dex/reader.hpp"
#include "dex/writer.hpp"

#include <gtest/gtest.h>

namespace {

using namespace dex::core;

/// @brief const/4 vA, lit（11n）。
Insn const4(ca::u8 reg, ca::i8 lit)
{
    Insn i;
    i.opcode = 0x12;
    i.format = InsnFormat::F11n;
    i.width = 1;
    i.registerCount = 1;
    i.registers[0] = reg;
    i.literal = lit;
    return i;
}

Insn returnVoid()
{
    Insn i;
    i.opcode = 0x0e;
    i.format = InsnFormat::F10x;
    i.width = 1;
    return i;
}

}   // namespace

TEST(DexMethodEditor, CommitProducesInjectableBody)
{
    MethodEditor editor(1, 0, 0);
    editor.unit().append(const4(0, 3));
    editor.unit().append(returnVoid());
    const Result<MethodBody, CodeDomError> body = editor.commit();
    ASSERT_TRUE(body.is_ok());
    EXPECT_EQ(body.unwrap().item.insnsSize, 2u);
    EXPECT_EQ(body.unwrap().insns.size(), 4u);
    EXPECT_EQ(body.unwrap().item.registersSize, 1u);

    // commit 可重复调用（lower 幂等）。
    const Result<MethodBody, CodeDomError> again = editor.commit();
    ASSERT_TRUE(again.is_ok());
    EXPECT_EQ(again.unwrap().insns, body.unwrap().insns);
}

TEST(DexMethodEditor, CommitFailsCleanlyOnDanglingLabel)
{
    MethodEditor editor(1, 0, 0);
    const InsnId br = editor.unit().append(Insn{});  // 占位，后面绑分支
    Insn gotoInsn;
    gotoInsn.opcode = 0x28;
    gotoInsn.format = InsnFormat::F10t;
    gotoInsn.width = 1;
    editor.unit().get(br) = gotoInsn;
    const LabelId never = editor.unit().newLabel();
    ASSERT_TRUE(editor.unit().bindBranch(br, never).is_ok());
    EXPECT_EQ(editor.commit().unwrap_err(), CodeDomError::DanglingLabel);
    // 编辑器内容保持原样：补绑后可成功。
    ASSERT_TRUE(editor.unit().bindLabel(never, editor.unit().end()).is_ok());
    const Result<MethodBody, CodeDomError> body = editor.commit();
    ASSERT_TRUE(body.is_ok());
}

TEST(DexFromScratch, BuildsClassWithMethodAndReparses)
{
    std::unique_ptr<DexFile> dexPtr = DexFile::createEmpty(35);
    DexFile& dex = *dexPtr;

    const Result<ca::u32, ReadError> cls = dex.addType("LFoo;");
    const Result<ca::u32, ReadError> super = dex.addType("Ljava/lang/Object;");
    const Result<ca::u32, ReadError> voidType = dex.addType("V");
    ASSERT_TRUE(cls.is_ok() && super.is_ok() && voidType.is_ok());

    const Result<ca::u32, ReadError> proto =
        dex.addProtoWithParams(voidType.unwrap(), {});
    ASSERT_TRUE(proto.is_ok());
    const Result<ca::u32, ReadError> name = dex.internUtf8("foo");
    ASSERT_TRUE(name.is_ok());
    const Result<ca::u32, ReadError> methodIdx =
        dex.addMethod(cls.unwrap(), proto.unwrap(), name.unwrap());
    ASSERT_TRUE(methodIdx.is_ok());

    MethodEditor editor(1, 0, 0);
    editor.unit().append(const4(0, 1));
    editor.unit().append(returnVoid());
    const Result<MethodBody, CodeDomError> body = editor.commit();
    ASSERT_TRUE(body.is_ok());

    ClassDef def;
    def.classIdx = cls.unwrap();
    def.accessFlags = 0x1;  // ACC_PUBLIC
    def.superclassIdx = super.unwrap();
    def.sourceFileIdx = DexFile::kNoIndex;
    dex.classDefs.push_back(def);

    BuildOptions options;
    MethodAddition add;
    add.classDefIdx = 0;
    add.methodIdx = methodIdx.unwrap();
    add.accessFlags = 0x9;  // ACC_PUBLIC | ACC_STATIC
    add.item = std::move(body.unwrap().item);
    add.insns = std::move(body.unwrap().insns);
    options.methodAdditions.push_back(std::move(add));

    const Result<std::vector<ca::u8>, WriteError> built = buildDex(dex, options);
    ASSERT_TRUE(built.is_ok());

    // 产物重读：1 类 1 方法，方法体语义一致，字符串/类型表就位。
    Result<std::unique_ptr<DexFile>, ReadError> reparsed =
        readDex(ByteSlice{built.unwrap().data(), built.unwrap().size()});
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> out = std::move(reparsed).unwrap();
    EXPECT_EQ(out->classCount(), 1u);
    EXPECT_EQ(out->methodCount(), 1u);
    const Result<const ClassData*, ReadError> data = out->classData(0);
    ASSERT_TRUE(data.is_ok() && data.unwrap() != nullptr);
    ASSERT_EQ(data.unwrap()->directMethods.size(), 1u);
    const EncodedMethod& m = data.unwrap()->directMethods[0];
    EXPECT_EQ(m.methodIndex, methodIdx.unwrap());
    EXPECT_EQ(m.accessFlags, 0x9u);
    const Result<const CodeItem*, ReadError> code = out->codeItem(m.codeOff);
    ASSERT_TRUE(code.is_ok() && code.unwrap() != nullptr);
    EXPECT_EQ(code.unwrap()->insnsSize, 2u);
    const Result<jstr::MUtf8StringRef, ReadError> desc = out->classDescriptor(0);
    ASSERT_TRUE(desc.is_ok());
    EXPECT_EQ(desc.unwrap().as_std_view(), "LFoo;");
}

TEST(DexFromScratch, TwoRebuildsAreByteStable)
{
    std::unique_ptr<DexFile> dexPtr = DexFile::createEmpty(35);
    DexFile& dex = *dexPtr;
    const Result<ca::u32, ReadError> cls = dex.addType("LBar;");
    ASSERT_TRUE(cls.is_ok());
    const Result<ca::u32, ReadError> super = dex.addType("Ljava/lang/Object;");
    ASSERT_TRUE(super.is_ok());
    ClassDef def;
    def.classIdx = cls.unwrap();
    def.superclassIdx = super.unwrap();
    def.sourceFileIdx = DexFile::kNoIndex;
    dex.classDefs.push_back(def);

    const Result<std::vector<ca::u8>, WriteError> first = buildDex(dex);
    ASSERT_TRUE(first.is_ok());
    Result<std::unique_ptr<DexFile>, ReadError> reparsed =
        readDex(ByteSlice{first.unwrap().data(), first.unwrap().size()});
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> out = std::move(reparsed).unwrap();
    const Result<std::vector<ca::u8>, WriteError> second = buildDex(*out);
    ASSERT_TRUE(second.is_ok());
    EXPECT_EQ(second.unwrap(), first.unwrap());
}
