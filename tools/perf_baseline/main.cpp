/// @file        main.cpp
/// @brief       大文件性能基线：合成 10 万方法级 dex，计时 解析/走查/重建。
///
/// 只防回归不激进优化；换机器或换编译器后重跑本工具，
/// 与上次输出对比判断回归。
///
/// DEX 格式 method_ids 上限 65536（u16），单文件不可能超——基线按 64K
/// 方法近满表 + 大字符串池（近似真实大文件体量）计时。
///
/// 用法：dexperf [类数] [每类方法数] [附加字符串数]
///   （默认 800 × 80 = 6.4 万方法 + 20 万字符串）
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "dex/builder.hpp"
#include "dex/dex_file.hpp"
#include "dex/reader.hpp"
#include "dex/writer.hpp"

using namespace dex::core;

namespace {

double msSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double, std::milli>(
               std::chrono::steady_clock::now() - t0)
        .count();
}

}   // namespace

int main(int argc, char** argv)
{
    const ca::u32 classCount =
        argc > 1 ? static_cast<ca::u32>(std::atoi(argv[1])) : 800u;
    const ca::u32 methodsPerClass =
        argc > 2 ? static_cast<ca::u32>(std::atoi(argv[2])) : 80u;
    const ca::u32 extraStrings =
        argc > 3 ? static_cast<ca::u32>(std::atoi(argv[3])) : 200000u;

    // ---- 合成：类 + 方法 ID + 方法体注入 ----
    auto t0 = std::chrono::steady_clock::now();
    auto file = DexFile::createEmpty(35);
    if (file == nullptr) {
        std::fprintf(stderr, "dexperf: createEmpty failed\n");
        return 1;
    }
    const auto objType = file->addType("Ljava/lang/Object;");
    const auto voidType = file->addType("V");
    if (objType.is_err() || voidType.is_err()) {
        std::fprintf(stderr, "dexperf: addType failed\n");
        return 1;
    }
    const auto voidProto = file->addProtoWithParams(voidType.unwrap(), {});
    if (voidProto.is_err()) {
        std::fprintf(stderr, "dexperf: addProto failed\n");
        return 1;
    }

    // 大字符串池：近似真实大文件的 string_ids 体量。
    for (ca::u32 s2 = 0; s2 < extraStrings; ++s2) {
        char text[64];
        std::snprintf(text, sizeof(text),
                      "Lcom/example/perf/Item%08d;#annotationValue%08d",
                      static_cast<int>(s2), static_cast<int>(s2));
        if (file->internUtf8(text).is_err()) {
            std::fprintf(stderr, "dexperf: internUtf8 failed\n");
            return 1;
        }
    }

    BuildOptions options;
    options.keepUnknownSections = false;
    CodeItem item;
    item.registersSize = 1;
    item.insSize = 0;
    item.outsSize = 0;
    item.insnsSize = 1;
    const std::vector<ca::u8> insns{0x0e, 0x00};  // return-void

    for (ca::u32 c = 0; c < classCount; ++c) {
        char name[32];
        std::snprintf(name, sizeof(name), "LPerf%06d;", static_cast<int>(c));
        const auto type = file->addType(name);
        if (type.is_err()) {
            std::fprintf(stderr, "dexperf: addType %s failed\n", name);
            return 1;
        }
        ClassDef def;
        def.classIdx = type.unwrap();
        def.accessFlags = 0x1;  // public
        def.superclassIdx = objType.unwrap();
        file->classDefs.push_back(def);

        for (ca::u32 m = 0; m < methodsPerClass; ++m) {
            char mName[32];
            std::snprintf(mName, sizeof(mName), "m%06d", static_cast<int>(m));
            auto nameStr = file->internUtf8(mName);
            if (nameStr.is_err()) {
                std::fprintf(stderr, "dexperf: internUtf8 failed\n");
                return 1;
            }
            auto method = file->addMethod(type.unwrap(), voidProto.unwrap(), nameStr.unwrap());
            if (method.is_err()) {
                std::fprintf(stderr, "dexperf: addMethod failed: %s\n",
                             to_string(method.unwrap_err()));
                return 1;
            }
            MethodAddition add;
            add.classDefIdx = c;
            add.methodIdx = method.unwrap();
            add.accessFlags = 0x9;  // public static
            add.item = item;
            add.insns = insns;
            options.methodAdditions.push_back(std::move(add));
        }
    }
    const double genMs = msSince(t0);

    // ---- canonical 重建（含方法体注入）----
    t0 = std::chrono::steady_clock::now();
    auto built = buildDex(*file, options);
    if (built.is_err()) {
        std::fprintf(stderr, "dexperf: buildDex failed: %s\n",
                     to_string(built.unwrap_err()));
        return 1;
    }
    const double buildMs = msSince(t0);
    std::vector<ca::u8> bytes = std::move(built).unwrap();
    const double mib = static_cast<double>(bytes.size()) / (1024.0 * 1024.0);

    // ---- 解析 ----
    t0 = std::chrono::steady_clock::now();
    auto parsed = readDex(ByteSlice{bytes.data(), bytes.size()});
    if (parsed.is_err()) {
        std::fprintf(stderr, "dexperf: readDex failed: %s\n",
                     to_string(parsed.unwrap_err()));
        return 1;
    }
    const double parseMs = msSince(t0);
    std::unique_ptr<DexFile> dex = std::move(parsed).unwrap();

    // ---- 全方法走查（code_item 解码）----
    t0 = std::chrono::steady_clock::now();
    ca::u64 walked = 0;
    for (ca::u32 c = 0; c < dex->classCount(); ++c) {
        const auto data = dex->classData(c);
        if (data.is_err() || data.unwrap() == nullptr) {
            continue;
        }
        for (const EncodedMethod& m : data.unwrap()->directMethods) {
            const auto code = dex->codeItem(m.codeOff);
            if (code.is_ok() && code.unwrap() != nullptr) {
                walked += code.unwrap()->insnsSize;
            }
        }
        for (const EncodedMethod& m : data.unwrap()->virtualMethods) {
            const auto code = dex->codeItem(m.codeOff);
            if (code.is_ok() && code.unwrap() != nullptr) {
                walked += code.unwrap()->insnsSize;
            }
        }
    }
    const double walkMs = msSince(t0);

    // ---- 再重建（canonical 固定路径）----
    t0 = std::chrono::steady_clock::now();
    auto rebuilt = buildDex(*dex);
    if (rebuilt.is_err()) {
        std::fprintf(stderr, "dexperf: rebuild failed: %s\n",
                     to_string(rebuilt.unwrap_err()));
        return 1;
    }
    const double rebuildMs = msSince(t0);

    std::printf("dexperf: classes=%u methods=%u size=%.1f MiB insns=%llu\n",
                classCount, classCount * methodsPerClass, mib,
                static_cast<unsigned long long>(walked));
    std::printf("dexperf: generate=%.0fms build=%.0fms parse=%.0fms "
                "walk=%.0fms rebuild=%.0fms\n",
                genMs, buildMs, parseMs, walkMs, rebuildMs);
    std::printf("dexperf: per-10k-methods build=%.1fms parse=%.1fms "
                "rebuild=%.1fms\n",
                buildMs * 10000.0 / (classCount * methodsPerClass),
                parseMs * 10000.0 / (classCount * methodsPerClass),
                rebuildMs * 10000.0 / (classCount * methodsPerClass));
    return 0;
}
