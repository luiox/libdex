/// @file        main.cpp
/// @brief       ASan 泄漏门：真实 dex 读 → 全解码 → 重建 → 重读，零报告。
///
/// 独立于 gtest（MSVC 下 /fsanitize=address 改 STL ABI，不能与预编译 gtest
/// 同链），plain main + Result API。用法：
///
///   libdex_leak_check <dex> [<dex>...]
///   LIBDEX_ASAN_SELFTEST=1 同上   # 故意泄漏一块内存，自证插桩生效
///
/// 退出码 0 = 全部文件走查通过（ASan 无报告时才可能是 0）。
#include <cstdio>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "dex/core/analysis.hpp"
#include "dex/core/builder.hpp"
#include "dex/core/dex_file.hpp"
#include "dex/core/error.hpp"
#include "dex/core/insn.hpp"
#include "dex/core/reader.hpp"
#include "dex/core/writer.hpp"
#include "dex/type/descriptor.hpp"
#include "smali/disassemble.hpp"
#include "smali/opcodes.hpp"

using namespace dex::core;

namespace {

int fail(const char* what, const std::string& name)
{
    std::fprintf(stderr, "leak_check: %s: %s\n", what, name.c_str());
    return 1;
}

/// @brief 逐条比对助记符表，找反汇编器渲染不了的指令。
void SmaliProbeInsnCheck(DexFile& dex, const EncodedMethod& m)
{
    const Result<const CodeItem*, ReadError> code = dex.codeItem(m.codeOff);
    if (code.is_err() || code.unwrap() == nullptr) {
        return;
    }
    const CodeItem* ci = code.unwrap();
    const Result<std::vector<Insn>, InsnError> decoded =
        decodeInsns(subOrEmpty(dex.source(), ci->insns.offset, ci->insns.length));
    if (decoded.is_err()) {
        return;
    }
    for (const Insn& i : decoded.unwrap()) {
        const std::optional<dex::smali::Mnemonic> mm = dex::smali::mnemonicOf(i.opcode);
        if (!mm || mm->format != i.format) {
            std::printf("smali probe: unmapped insn op=0x%02x fmt=%d at %u\n",
                        i.opcode, static_cast<int>(i.format), i.address);
        }
    }
}

/// @brief 帧分析走查（M4 路径进 ASan 门）。
void AnalyzeFramesProbe(DexFile& dex, const EncodedMethod& m)
{
    if (m.codeOff == 0) {
        return;
    }
    const Result<const CodeItem*, ReadError> code = dex.codeItem(m.codeOff);
    if (code.is_err() || code.unwrap() == nullptr) {
        return;
    }
    const bool isStatic = (m.accessFlags & 0x8u) != 0;
    for (const bool strict : {false, true}) {
        const Result<MethodAnalysis, ReadError> a =
            analyzeFrames(dex, *code.unwrap(), m.methodIndex, isStatic, strict);
        if (a.is_err()) {
            std::printf("analysis probe: method %u failed: %s\n", m.methodIndex,
                        to_string(a.unwrap_err()));
            return;
        }
        if (!strict || a.unwrap().diagnostics.empty()) {
            continue;
        }
        std::printf("analysis probe: method %u diags:", m.methodIndex);
        for (const FrameDiagnostic& d : a.unwrap().diagnostics) {
            std::printf(" @%u/c%d", d.address, static_cast<int>(d.code));
        }
        std::printf("\n");
        if (std::getenv("LIBDEX_ANALYSIS_DUMP") == nullptr) {
            continue;
        }
        {
            const Result<std::vector<Insn>, InsnError> decoded = decodeInsns(
                subOrEmpty(dex.source(), code.unwrap()->insns.offset,
                           code.unwrap()->insns.length));
            if (decoded.is_ok()) {
                for (const Insn& i : decoded.unwrap()) {
                    std::printf("  insn @%u op=0x%02x w=%u\n", i.address, i.opcode,
                                i.width);
                }
            }
            std::printf("  regs=%u ins=%u\n", code.unwrap()->registersSize,
                        code.unwrap()->insSize);
        }
        for (ca::u32 c = 0; c < dex.classCount(); ++c) {
            const Result<const ClassData*, ReadError> data = dex.classData(c);
            if (data.is_err() || data.unwrap() == nullptr) {
                continue;
            }
            bool owns = false;
            for (const EncodedMethod& mm : data.unwrap()->directMethods) {
                owns = owns || mm.methodIndex == m.methodIndex;
            }
            for (const EncodedMethod& mm : data.unwrap()->virtualMethods) {
                owns = owns || mm.methodIndex == m.methodIndex;
            }
            if (!owns) {
                continue;
            }
            const Result<std::string, dex::smali::SmaliError> text =
                dex::smali::disassembleClass(dex, c);
            if (text.is_ok()) {
                std::printf("---- class %u ----\n%s", c, text.unwrap().c_str());
            }
            break;
        }
    }
}

void walkEverything(DexFile& dex)
{
    for (ca::u32 i = 0; i < dex.stringCount(); ++i) {
        (void)dex.stringData(i);
        (void)dex.string(i);
    }
    for (ca::u32 i = 0; i < dex.typeCount(); ++i) {
        (void)dex.typeDescriptor(i);
    }
    for (ca::u32 i = 0; i < dex.protoCount(); ++i) {
        (void)dex.protoParameters(i);
    }
    for (ca::u32 i = 0; i < dex.fieldCount(); ++i) {
        (void)dex.fieldClassDescriptor(i);
        (void)dex.fieldTypeDescriptor(i);
        (void)dex.fieldName(i);
    }
    for (ca::u32 i = 0; i < dex.methodCount(); ++i) {
        (void)dex.methodClassDescriptor(i);
        (void)dex.methodName(i);
    }
    for (ca::u32 i = 0; i < dex.classCount(); ++i) {
        (void)dex.classDescriptor(i);
        (void)dex.superclassDescriptor(i);
        (void)dex.sourceFile(i);
        (void)dex.interfaces(i);
        (void)dex.classAnnotations(i);
        (void)dex.staticValues(i);
        const Result<const ClassData*, ReadError> data = dex.classData(i);
        if (data.is_err() || data.unwrap() == nullptr) {
            continue;
        }
        const ClassData* cd = data.unwrap();
        for (const EncodedMethod& m : cd->directMethods) {
            (void)dex.methodName(m.methodIndex);
            const Result<const CodeItem*, ReadError> code = dex.codeItem(m.codeOff);
            if (code.is_err() || code.unwrap() == nullptr) {
                continue;
            }
            const CodeItem* ci = code.unwrap();
            (void)decodeInsns(subOrEmpty(dex.source(), ci->insns.offset, ci->insns.length));
            if (ci->debugInfoOff != 0) {
                (void)dex.debugInfo(ci->debugInfoOff);
            }
            AnalyzeFramesProbe(dex, m);
        }
        for (const EncodedMethod& m : cd->virtualMethods) {
            (void)dex.methodName(m.methodIndex);
            const Result<const CodeItem*, ReadError> code = dex.codeItem(m.codeOff);
            if (code.is_err() || code.unwrap() == nullptr) {
                continue;
            }
            const CodeItem* ci = code.unwrap();
            (void)decodeInsns(subOrEmpty(dex.source(), ci->insns.offset, ci->insns.length));
            if (ci->debugInfoOff != 0) {
                (void)dex.debugInfo(ci->debugInfoOff);
            }
            AnalyzeFramesProbe(dex, m);
        }
    }
    for (ca::u32 i = 0; i < dex.callSiteCount(); ++i) {
        (void)dex.callSiteValues(i);
    }
}

bool processOne(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return fail("cannot open", path) == 0;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string bytes = ss.str();

    Result<std::unique_ptr<DexFile>, ReadError> parsed =
        readDex(ByteSlice{reinterpret_cast<const ca::u8*>(bytes.data()), bytes.size()});
    if (parsed.is_err()) {
        return fail("readDex failed", path) == 0;
    }
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();
    DexFile& dex = *file;
    walkEverything(dex);

    Result<std::vector<ca::u8>, WriteError> rebuilt = buildDex(dex);
    if (rebuilt.is_err()) {
        return fail("buildDex failed", path) == 0;
    }

    // 重建产物重读 + 再走查 + 二次重建固定点。
    const std::vector<ca::u8>& out = rebuilt.unwrap();
    Result<std::unique_ptr<DexFile>, ReadError> reparsed =
        readDex(ByteSlice{out.data(), out.size()});
    if (reparsed.is_err()) {
        return fail("rebuilt dex unreadable", path) == 0;
    }
    std::unique_ptr<DexFile> file2 = std::move(reparsed).unwrap();
    DexFile& dex2 = *file2;
    walkEverything(dex2);
    Result<std::vector<ca::u8>, WriteError> rebuilt2 = buildDex(dex2);
    if (rebuilt2.is_err()) {
        return fail("second buildDex failed", path) == 0;
    }
    if (rebuilt2.unwrap() != out) {
        return fail("second buildDex not byte-stable", path) == 0;
    }

    if (std::getenv("LIBDEX_SMALI_PROBE") != nullptr) {
        for (ca::u32 c = 0; c < dex.classCount(); ++c) {
            const Result<std::string, dex::smali::SmaliError> text =
                dex::smali::disassembleClass(dex, c);
            if (text.is_err()) {
                std::printf("smali probe: class %u FAILED: %s\n", c,
                            dex::smali::to_string(text.unwrap_err()));
                // 定位渲染不了的指令：逐条比对助记符表。
                const Result<const ClassData*, ReadError> data = dex.classData(c);
                if (data.is_ok() && data.unwrap() != nullptr) {
                    const ClassData* cd = data.unwrap();
                    for (const EncodedMethod& m : cd->directMethods) {
                        SmaliProbeInsnCheck(dex, m);
                    }
                    for (const EncodedMethod& m : cd->virtualMethods) {
                        SmaliProbeInsnCheck(dex, m);
                    }
                }
                break;
            }
        }
        std::printf("smali probe: %u classes disassembled\n", dex.classCount());
    }

    std::printf("leak_check: ok %s (%u classes)\n", path.c_str(), dex.classCount());
    return true;
}

}   // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::fprintf(stderr, "usage: libdex_leak_check <dex> [<dex>...]\n");
        return 2;
    }
    if (std::getenv("LIBDEX_ASAN_SELFTEST") != nullptr) {
        // 自检：故意 use-after-free。MSVC 的 ASan 不启用 LSan，漏内存不报，
        // 但 UAF 是确定性报告——插桩生效时进程带 ERROR: AddressSanitizer
        // 退出，外层脚本据此断言"门是通的"；没生效时这里静默 0。
        auto* probe = new char[64];
        std::snprintf(probe, 64, "asan probe");
        delete[] probe;
        volatile char touched = probe[0];
        (void)touched;
        return 0;
    }
    for (int i = 1; i < argc; ++i) {
        if (!processOne(argv[i])) {
            return 1;
        }
    }
    return 0;
}
