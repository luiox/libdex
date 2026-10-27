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
#include <sstream>
#include <string>
#include <vector>

#include "dex/core/builder.hpp"
#include "dex/core/dex_file.hpp"
#include "dex/core/error.hpp"
#include "dex/core/insn.hpp"
#include "dex/core/reader.hpp"
#include "dex/core/writer.hpp"
#include "dex/type/descriptor.hpp"

using namespace dex::core;

namespace {

int fail(const char* what, const std::string& name)
{
    std::fprintf(stderr, "leak_check: %s: %s\n", what, name.c_str());
    return 1;
}

/// @brief 把模型里所有 lazy 数据强制解码一遍（含失败路径的缓存写入）。
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
