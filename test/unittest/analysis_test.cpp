// 分析层测试：格合并、CFG 形状、到达帧（分支合流/冲突/宽配对/move-result/
// 异常 handler/monitor），真实语料全方法可解析，畸形分支目标不崩溃。
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "dex/analysis.hpp"
#include "dex/builder.hpp"
#include "dex/reader.hpp"
#include "dex_fixture.hpp"
#include "smali/assemble.hpp"
#include "smali/disassemble.hpp"

namespace {

using dex::core::CfgBlock;
using dex::core::CodeItem;
using dex::core::DexFile;
using dex::core::EncodedMethod;
using dex::core::FrameDiagnostic;
using dex::core::Insn;
using dex::core::MethodAnalysis;
using dex::core::RegKind;
using dex::core::RegType;

/// @brief 汇编 → 构建 → 重解析；分析只作用于落盘字节。
struct Built
{
    std::unique_ptr<DexFile> dex;
};

Built assemble(const char* src)
{
    Built out;
    auto file = DexFile::createEmpty(35);
    EXPECT_NE(file, nullptr);
    if (file == nullptr) {
        return out;
    }
    dex::smali::SmaliAssembler assembler(*file);
    auto r = assembler.assembleClass(src);
    EXPECT_TRUE(r.is_ok());
    if (r.is_err()) {
        EXPECT_TRUE(false) << "assemble failed @" << r.unwrap_err().line << ": "
                           << r.unwrap_err().detail;
        return out;
    }
    auto options = assembler.options();
    options.keepUnknownSections = false;
    auto built = dex::core::buildDex(*file, options);
    EXPECT_TRUE(built.is_ok());
    if (built.is_err()) {
        return out;
    }
    auto reparsed = dex::core::readDex(dex_test::asSlice(built.unwrap()));
    EXPECT_TRUE(reparsed.is_ok());
    if (reparsed.is_err()) {
        return out;
    }
    out.dex = std::move(reparsed).unwrap();
    return out;
}

/// @brief 在类 0 的类数据里按方法名找方法（测试样本都是单类）。
std::optional<EncodedMethod> findMethod(const Built& b, const std::string& name)
{
    const auto data = b.dex->classData(0);
    if (data.is_err() || data.unwrap() == nullptr) {
        return std::nullopt;
    }
    for (const EncodedMethod& m : data.unwrap()->directMethods) {
        auto n = b.dex->methodName(m.methodIndex);
        if (n.is_ok() && n.unwrap().as_std_view() == name) {
            return m;
        }
    }
    for (const EncodedMethod& m : data.unwrap()->virtualMethods) {
        auto n = b.dex->methodName(m.methodIndex);
        if (n.is_ok() && n.unwrap().as_std_view() == name) {
            return m;
        }
    }
    return std::nullopt;
}

/// @brief 分析一个方法；失败返回 nullopt（断言由调用方做）。
std::optional<MethodAnalysis> analyze(const Built& b, const EncodedMethod& m, bool strict)
{
    const auto code = b.dex->codeItem(m.codeOff);
    if (code.is_err() || code.unwrap() == nullptr) {
        return std::nullopt;
    }
    auto r = dex::core::analyzeFrames(*b.dex, *code.unwrap(), m.methodIndex,
                                      (m.accessFlags & 0x8u) != 0, strict);
    if (r.is_err()) {
        return std::nullopt;
    }
    return std::move(r).unwrap();
}

/// @brief 方法体的解码指令流（与 entryFrames 一一同位）。
std::vector<Insn> decode(const Built& b, const EncodedMethod& m)
{
    const auto code = b.dex->codeItem(m.codeOff);
    if (code.is_err() || code.unwrap() == nullptr) {
        return {};
    }
    auto r = dex::core::decodeInsns(dex::core::subOrEmpty(
        b.dex->source(), code.unwrap()->insns.offset, code.unwrap()->insns.length));
    if (r.is_err()) {
        return {};
    }
    return std::move(r).unwrap();
}

bool hasDiag(const MethodAnalysis& a, FrameDiagnostic::Code code)
{
    for (const FrameDiagnostic& d : a.diagnostics) {
        if (d.code == code) {
            return true;
        }
    }
    return false;
}

/// @brief 诊断清单（断言消息用）。
std::string diagText(const MethodAnalysis& a)
{
    std::string out;
    for (const FrameDiagnostic& d : a.diagnostics) {
        out += " [@" + std::to_string(d.address) + " code=" +
               std::to_string(static_cast<int>(d.code)) + "]";
    }
    return out;
}

Insn makeInsn(ca::u32 addr, ca::u8 opcode, dex::core::InsnFormat format, ca::i32 branch = 0)
{
    Insn i;
    i.address = addr;
    i.width = 1;
    i.opcode = opcode;
    i.format = format;
    i.branchOffset = branch;
    return i;
}

}   // namespace

TEST(DexAnalysis, MergeLattice)
{
    const RegType i1 = RegType::ofKind(RegKind::IntLike);
    const RegType f = RegType::ofKind(RegKind::Float);
    const RegType l = RegType::ofKind(RegKind::Long);
    const RegType d = RegType::ofKind(RegKind::Double);
    const RegType nullT = RegType::ofKind(RegKind::Null);
    const RegType str = RegType::ref(7);
    const RegType obj = RegType::ref(9);
    const RegType refTop = RegType::ref(DexFile::kNoIndex);

    EXPECT_TRUE(dex::core::mergeRegTypes(i1, i1).sameAs(i1));
    EXPECT_TRUE(dex::core::mergeRegTypes(i1, f).kind == RegKind::Conflicted);  // 异类冲突
    EXPECT_TRUE(dex::core::mergeRegTypes(str, obj).sameAs(refTop));            // 引用顶
    EXPECT_TRUE(dex::core::mergeRegTypes(nullT, str).sameAs(str));             // null 吸收
    // 字面量零语义：const 0 与 int/float 相遇并入对方（ART Constant(0)）。
    EXPECT_TRUE(dex::core::mergeRegTypes(nullT, i1).sameAs(i1));
    EXPECT_TRUE(dex::core::mergeRegTypes(nullT, f).sameAs(f));
    EXPECT_TRUE(dex::core::mergeRegTypes(l, d).kind == RegKind::Conflicted);   // 宽冲突
    EXPECT_TRUE(dex::core::mergeRegTypes(i1, str).kind == RegKind::Conflicted);
    EXPECT_TRUE(dex::core::mergeRegTypes(i1, RegType::top()).sameAs(RegType::top()));
    EXPECT_TRUE(dex::core::mergeRegTypes(l, l).sameAs(l));
}

TEST(DexAnalysis, CfgSyntheticBlocks)
{
    // 0: goto 3 | 1: nop | 2: return-void | 3: return
    std::vector<Insn> insns;
    insns.push_back(makeInsn(0, 0x28, dex::core::InsnFormat::F10t, 3));
    insns.push_back(makeInsn(1, 0x00, dex::core::InsnFormat::F10x));
    insns.push_back(makeInsn(2, 0x0e, dex::core::InsnFormat::F10x));
    insns.push_back(makeInsn(3, 0x0f, dex::core::InsnFormat::F11x));
    const std::vector<CfgBlock> blocks = dex::core::buildCfg(insns, {}, {});
    ASSERT_EQ(blocks.size(), 3u);
    EXPECT_EQ(blocks[0].startAddress, 0u);
    ASSERT_EQ(blocks[0].successors.size(), 1u);
    EXPECT_EQ(blocks[0].successors[0], 2u);  // goto 的目标块
    EXPECT_FALSE(blocks[0].isExitReachable);
    EXPECT_TRUE(blocks[1].isExitReachable);  // return-void 结尾
    EXPECT_TRUE(blocks[2].isExitReachable);
    // 悬垂目标：不崩溃、不产生假边。
    insns[0].branchOffset = 100;
    const std::vector<CfgBlock> dangling = dex::core::buildCfg(insns, {}, {});
    ASSERT_EQ(dangling.size(), 3u);
    EXPECT_TRUE(dangling[0].successors.empty());
}

TEST(DexAnalysis, BranchMergeSameTypeIsClean)
{
    Built b = assemble(
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static pick(I)I\n"
        "    .registers 3\n"
        "    if-eqz v2 :cond_z\n"
        "    const/4 v0 1\n"
        "    goto :goto_m\n"
        "    :cond_z\n"
        "    const/4 v0 2\n"
        "    :goto_m\n"
        "    return v0\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);
    auto m = findMethod(b, "pick");
    ASSERT_TRUE(m.has_value());

    auto strict = analyze(b, *m, true);
    ASSERT_TRUE(strict.has_value());
    EXPECT_TRUE(strict->strictClean) << diagText(*strict);
    EXPECT_TRUE(strict->diagnostics.empty()) << diagText(*strict);
    ASSERT_FALSE(strict->blocks.empty());

    auto decoded = decode(b, *m);
    ASSERT_FALSE(decoded.empty());
    ASSERT_EQ(strict->entryFrames.size(), decoded.size());
    // 合流点（return v0，最后一条）：两路都是 IntLike。
    EXPECT_EQ(strict->entryFrames.back()[0].kind, RegKind::IntLike);
    // 参数槽：v2 = p0 是 IntLike。
    EXPECT_EQ(strict->entryFrames.front()[2].kind, RegKind::IntLike);
    // CFG：条件分支切块。
    EXPECT_GE(strict->blocks.size(), 3u);
}

TEST(DexAnalysis, BranchMergeConflictDiagnosedInStrict)
{
    const char* kSrc =
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static pick(I)Ljava/lang/Object;\n"
        "    .registers 3\n"
        "    if-eqz v2 :cond_z\n"
        "    const/4 v0 1\n"
        "    goto :goto_m\n"
        "    :cond_z\n"
        "    const-string v0 \"x\"\n"
        "    :goto_m\n"
        "    return-object v0\n"
        ".end method\n";
    Built b = assemble(kSrc);
    ASSERT_NE(b.dex, nullptr);
    auto m = findMethod(b, "pick");
    ASSERT_TRUE(m.has_value());

    auto strict = analyze(b, *m, true);
    ASSERT_TRUE(strict.has_value());
    // IntLike 与 Reference 在合流点冲突（const 0 零语义不适用于本例）。
    EXPECT_TRUE(hasDiag(*strict, FrameDiagnostic::Code::TypeConflict));
    EXPECT_FALSE(strict->strictClean);

    auto lenient = analyze(b, *m, false);
    ASSERT_TRUE(lenient.has_value());
    EXPECT_TRUE(lenient->diagnostics.empty());  // best-effort 不报错
}

TEST(DexAnalysis, ConstZeroMergeIsClean)
{
    // d8 惯用：const/4 0 既可作 null 也可作 int 字面量，合流不得误报。
    Built b = assemble(
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static zero(I)Ljava/lang/Object;\n"
        "    .registers 3\n"
        "    if-eqz v2 :cond_z\n"
        "    const/4 v0 0\n"
        "    goto :goto_m\n"
        "    :cond_z\n"
        "    const-string v0 \"x\"\n"
        "    :goto_m\n"
        "    return-object v0\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);
    auto m = findMethod(b, "zero");
    ASSERT_TRUE(m.has_value());
    auto strict = analyze(b, *m, true);
    ASSERT_TRUE(strict.has_value());
    EXPECT_TRUE(strict->diagnostics.empty()) << diagText(*strict);
}

TEST(DexAnalysis, WidePairingViolation)
{
    Built b = assemble(
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static bad()V\n"
        "    .registers 3\n"
        "    const-wide v0 3\n"
        "    const/4 v1 7\n"
        "    return-void\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);
    auto m = findMethod(b, "bad");
    ASSERT_TRUE(m.has_value());

    auto strict = analyze(b, *m, true);
    ASSERT_TRUE(strict.has_value());
    EXPECT_TRUE(hasDiag(*strict, FrameDiagnostic::Code::WidePairing));

    auto lenient = analyze(b, *m, false);
    ASSERT_TRUE(lenient.has_value());
    EXPECT_TRUE(lenient->diagnostics.empty());

    // return-void 入口帧：v0 仍是 Long，v1 被 cat1 写占位为 IntLike。
    auto decoded = decode(b, *m);
    ASSERT_EQ(strict->entryFrames.size(), decoded.size());
    const std::vector<RegType>& tail = strict->entryFrames.back();
    ASSERT_GE(tail.size(), 2u);
    EXPECT_EQ(tail[0].kind, RegKind::Long);
    EXPECT_EQ(tail[1].kind, RegKind::IntLike);
}

TEST(DexAnalysis, WideBinop23xSourcesAreClean)
{
    // add-long/add-double（23x）的源与目标同族同宽：strict 不得把合法宽
    // 源误报成 WidePairing（回归：binop 3reg 曾按 unop 的 long-/double-
    // 前缀判源宽，add-long 走进了 cat1 检查分支）。
    Built b = assemble(
        ".class public LWideBinop;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static calc(JJ)J\n"
        "    .registers 6\n"
        "    add-long v0, v2, v4\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static fmul(DD)D\n"
        "    .registers 6\n"
        "    mul-double v0, v2, v4\n"
        "    return-wide v0\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);

    auto addLong = findMethod(b, "calc");
    ASSERT_TRUE(addLong.has_value());
    auto strictAdd = analyze(b, *addLong, true);
    ASSERT_TRUE(strictAdd.has_value());
    EXPECT_TRUE(strictAdd->diagnostics.empty())
        << diagText(*strictAdd);
    // 目标寄存器落在宽格上。
    auto decodedAdd = decode(b, *addLong);
    ASSERT_GE(decodedAdd.size(), 2u);
    ASSERT_EQ(strictAdd->entryFrames.size(), decodedAdd.size());
    const std::vector<RegType>& afterAdd = strictAdd->entryFrames[1];
    ASSERT_GE(afterAdd.size(), 2u);
    EXPECT_EQ(afterAdd[0].kind, RegKind::Long);
    EXPECT_EQ(afterAdd[1].kind, RegKind::Long);

    auto mulDouble = findMethod(b, "fmul");
    ASSERT_TRUE(mulDouble.has_value());
    auto strictMul = analyze(b, *mulDouble, true);
    ASSERT_TRUE(strictMul.has_value());
    EXPECT_TRUE(strictMul->diagnostics.empty())
        << diagText(*strictMul);
}

TEST(DexAnalysis, MoveResultPairing)
{
    Built b = assemble(
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static good()J\n"
        "    .registers 2\n"
        "    invoke-static {} Ljava/lang/System;->currentTimeMillis()J\n"
        "    move-result-wide v0\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static bad()V\n"
        "    .registers 1\n"
        "    move-result v0\n"
        "    return-void\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);

    auto good = findMethod(b, "good");
    ASSERT_TRUE(good.has_value());
    auto strictGood = analyze(b, *good, true);
    ASSERT_TRUE(strictGood.has_value());
    EXPECT_TRUE(strictGood->diagnostics.empty()) << diagText(*strictGood);
    // 前驱 invoke 的返回描述符 J → move-result-wide 目标是 Long 宽对。
    const std::vector<RegType>& retFrame = strictGood->entryFrames.back();
    ASSERT_GE(retFrame.size(), 2u);
    EXPECT_EQ(retFrame[0].kind, RegKind::Long);
    EXPECT_EQ(retFrame[1].kind, RegKind::Long);

    auto bad = findMethod(b, "bad");
    ASSERT_TRUE(bad.has_value());
    auto strictBad = analyze(b, *bad, true);
    ASSERT_TRUE(strictBad.has_value());
    EXPECT_TRUE(hasDiag(*strictBad, FrameDiagnostic::Code::MoveResultPair));
}

TEST(DexAnalysis, ExceptionHandlerFrame)
{
    Built b = assemble(
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static guarded()V\n"
        "    .registers 2\n"
        "    :try_s\n"
        "    const/4 v0 1\n"
        "    :try_e\n"
        "    .catch Ljava/lang/Exception; { :try_s .. :try_e } :h\n"
        "    return-void\n"
        "    :h\n"
        "    move-exception v1\n"
        "    return-void\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);
    auto m = findMethod(b, "guarded");
    ASSERT_TRUE(m.has_value());

    auto strict = analyze(b, *m, true);
    ASSERT_TRUE(strict.has_value());
    EXPECT_TRUE(strict->diagnostics.empty()) << "clean 程序不得有 strict 诊断";

    // handler 入口帧：v0 全清（Unknown），v1 是 catch 类型引用。
    auto decoded = decode(b, *m);
    ASSERT_EQ(strict->entryFrames.size(), decoded.size());
    std::size_t handlerIdx = decoded.size();
    for (std::size_t k = 0; k < decoded.size(); ++k) {
        if (decoded[k].opcode == 0x0d) {  // move-exception
            handlerIdx = k;
        }
    }
    if (handlerIdx == decoded.size()) {
        auto text = dex::smali::disassembleClass(*b.dex, 0);
        ADD_FAILURE() << "move-exception 缺失；asm="
                      << (text.is_ok() ? text.unwrap() : "<dis fail>");
        return;
    }
    ASSERT_LT(handlerIdx, decoded.size());
    const std::vector<RegType>& h = strict->entryFrames[handlerIdx];
    ASSERT_GE(h.size(), 2u);
    // 异常边语义：handler 入口帧寄存器全清（Unknown），类型由 move-exception
    // 在帧内写入、流入后继。
    EXPECT_EQ(h[0].kind, RegKind::Unknown);
    EXPECT_EQ(h[1].kind, RegKind::Unknown);

    // CFG：try 块有异常边到 handler 入口块。
    bool handlerEdge = false;
    for (const CfgBlock& blk : strict->blocks) {
        if (!blk.handlers.empty()) {
            handlerEdge = true;
        }
    }
    EXPECT_TRUE(handlerEdge);
}

TEST(DexAnalysis, MonitorBalance)
{
    Built b = assemble(
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static locked(Ljava/lang/Object;)V\n"
        "    .registers 2\n"
        "    monitor-enter v1\n"
        "    monitor-exit v1\n"
        "    monitor-enter v1\n"
        "    return-void\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);
    auto m = findMethod(b, "locked");
    ASSERT_TRUE(m.has_value());

    auto strict = analyze(b, *m, true);
    ASSERT_TRUE(strict.has_value());
    EXPECT_TRUE(hasDiag(*strict, FrameDiagnostic::Code::MonitorBalance));

    auto lenient = analyze(b, *m, false);
    ASSERT_TRUE(lenient.has_value());
    EXPECT_TRUE(lenient->diagnostics.empty());
}

TEST(DexAnalysis, NewInstanceUninitFlow)
{
    // new-instance → invoke-direct <init> → 引用初始化；strict 干净。
    Built b = assemble(
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static make()Ljava/lang/Object;\n"
        "    .registers 2\n"
        "    new-instance v0 Ljava/lang/Object;\n"
        "    invoke-direct {v0} Ljava/lang/Object;-><init>()V\n"
        "    return-object v0\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);
    auto m = findMethod(b, "make");
    ASSERT_TRUE(m.has_value());

    auto strict = analyze(b, *m, true);
    ASSERT_TRUE(strict.has_value());
    EXPECT_TRUE(strict->diagnostics.empty()) << "make: " << diagText(*strict);

    // return-object 入口帧：v0 已从 UninitRef 变为已初始化引用。
    const std::vector<RegType>& tail = strict->entryFrames.back();
    ASSERT_FALSE(tail.empty());
    EXPECT_EQ(tail[0].kind, RegKind::Reference);
}

TEST(DexRealCorpus, FramesParseEveryMethod)
{
    const char* env = std::getenv("LIBDEX_REAL_DEX_DIR");
    if (env == nullptr || *env == '\0') {
        GTEST_SKIP() << "LIBDEX_REAL_DEX_DIR is not set";
    }
    std::error_code ec;
    std::filesystem::directory_iterator it(env, ec);
    ASSERT_FALSE(ec) << env;

    ca::u32 methodTotal = 0;
    for (const std::filesystem::directory_entry& entry : it) {
        std::error_code fileEc;
        if (!entry.is_regular_file(fileEc) || entry.path().extension() != ".dex") {
            continue;
        }
        std::ifstream in(entry.path(), std::ios::binary);
        std::vector<char> raw((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
        ASSERT_FALSE(raw.empty()) << entry.path().string();

        auto parsed = dex::core::readDex(dex_test::asSlice(
            std::vector<ca::u8>(raw.begin(), raw.end())));
        ASSERT_TRUE(parsed.is_ok())
            << entry.path().string() << ": " << dex::core::to_string(parsed.unwrap_err());
        std::unique_ptr<DexFile> dex = std::move(parsed).unwrap();

        for (ca::u32 c = 0; c < dex->classCount(); ++c) {
            const auto data = dex->classData(c);
            ASSERT_TRUE(data.is_ok()) << entry.path().string();
            if (data.unwrap() == nullptr) {
                continue;
            }
            for (const bool virtualSide : {false, true}) {
                const std::vector<EncodedMethod>& methods =
                    virtualSide ? data.unwrap()->virtualMethods
                                : data.unwrap()->directMethods;
                for (const EncodedMethod& m : methods) {
                    if (m.codeOff == 0) {
                        continue;  // abstract/native 无方法体
                    }
                    const auto code = dex->codeItem(m.codeOff);
                    ASSERT_TRUE(code.is_ok() && code.unwrap() != nullptr)
                        << entry.path().string();
                    const bool isStatic = (m.accessFlags & 0x8u) != 0;
                    auto lenient = dex::core::analyzeFrames(*dex, *code.unwrap(),
                                                            m.methodIndex, isStatic, false);
                    ASSERT_TRUE(lenient.is_ok())
                        << entry.path().string() << " method " << m.methodIndex << ": "
                        << dex::core::to_string(lenient.unwrap_err());
                    EXPECT_TRUE(lenient.unwrap().diagnostics.empty())
                        << entry.path().string() << " method " << m.methodIndex
                        << ": best-effort 不得产出诊断";
                    auto strict = dex::core::analyzeFrames(*dex, *code.unwrap(),
                                                           m.methodIndex, isStatic, true);
                    ASSERT_TRUE(strict.is_ok())
                        << entry.path().string() << " method " << m.methodIndex << ": "
                        << dex::core::to_string(strict.unwrap_err());
                    ++methodTotal;
                }
            }
        }
    }
    EXPECT_GT(methodTotal, 0u);
}

TEST(DexAnalysis, WideUnopShapesAreClean)
{
    // unop 的源宽不能按名字前缀判定：neg-long/not-long/neg-double 的源是
    // cat2，long-to-int 等转换的源同样是 cat2；合法帧不得误报 WidePairing。
    Built b = assemble(
        ".class public LWideUnop;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static neg()J\n"
        "    .registers 6\n"
        "    const-wide v2, 1\n"
        "    neg-long v0, v2\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static notl()J\n"
        "    .registers 6\n"
        "    const-wide v2, 1\n"
        "    not-long v0, v2\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static dneg()D\n"
        "    .registers 6\n"
        "    const-wide v2, 1\n"
        "    neg-double v0, v2\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static widen()J\n"
        "    .registers 4\n"
        "    const/4 v2, 1\n"
        "    int-to-long v0, v2\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static narrow()I\n"
        "    .registers 4\n"
        "    const-wide v2, 1\n"
        "    long-to-int v0, v2\n"
        "    return v0\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);
    for (const char* n : {"neg", "notl", "dneg", "widen", "narrow"}) {
        auto m = findMethod(b, n);
        ASSERT_TRUE(m.has_value()) << n;
        auto a = analyze(b, *m, true);
        ASSERT_TRUE(a.has_value()) << n;
        EXPECT_TRUE(a->diagnostics.empty()) << n << ": " << diagText(*a);
    }
}

TEST(DexAnalysis, WideShiftShapesAreClean)
{
    // long 移位与 2addr 移位的第二源是 cat1：23x 的 C、2addr 的 B 不能按
    // 目标族套 checkWide。
    Built b = assemble(
        ".class public LWideShift;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static shl()J\n"
        "    .registers 6\n"
        "    const-wide v2, 1\n"
        "    const/4 v4, 1\n"
        "    shl-long v0, v2, v4\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static shr()J\n"
        "    .registers 6\n"
        "    const-wide v2, 1\n"
        "    const/4 v4, 1\n"
        "    shr-long v0, v2, v4\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static ushr()J\n"
        "    .registers 6\n"
        "    const-wide v2, 1\n"
        "    const/4 v4, 1\n"
        "    ushr-long v0, v2, v4\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static shl2()J\n"
        "    .registers 6\n"
        "    const-wide v0, 1\n"
        "    const/4 v2, 1\n"
        "    shl-long/2addr v0, v2\n"
        "    return-wide v0\n"
        ".end method\n"
        ".method public static ushr2()J\n"
        "    .registers 6\n"
        "    const-wide v0, 1\n"
        "    const/4 v2, 1\n"
        "    ushr-long/2addr v0, v2\n"
        "    return-wide v0\n"
        ".end method\n");
    ASSERT_NE(b.dex, nullptr);
    for (const char* n : {"shl", "shr", "ushr", "shl2", "ushr2"}) {
        auto m = findMethod(b, n);
        ASSERT_TRUE(m.has_value()) << n;
        auto a = analyze(b, *m, true);
        ASSERT_TRUE(a.has_value()) << n;
        EXPECT_TRUE(a->diagnostics.empty()) << n << ": " << diagText(*a);
    }
}
