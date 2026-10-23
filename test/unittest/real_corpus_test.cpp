/// @file        real_corpus_test.cpp
/// @brief       真实 dex 语料门控测试（LIBDEX_REAL_DEX_DIR）。
///
/// 语料不在仓内：环境变量指向一个目录时，逐个 .dex 做解析 + 未修改往返 +
/// 摘要 + 全方法体指令解码；变量缺席或目录为空时 skip，而不是硬失败（与
/// libjbc 真实语料政策同型）。
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"

namespace {

std::vector<ca::u8> readFile(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return std::vector<ca::u8>(raw.begin(), raw.end());
}

std::vector<std::filesystem::path> corpusFiles()
{
    const char* env = std::getenv("LIBDEX_REAL_DEX_DIR");
    if (env == nullptr || *env == '\0') {
        return {};
    }

    std::error_code ec;
    std::filesystem::directory_iterator it(env, ec);
    if (ec) {
        return {};
    }

    std::vector<std::filesystem::path> files;
    for (const std::filesystem::directory_entry& entry : it) {
        std::error_code entryEc;
        if (!entry.is_regular_file(entryEc)) {
            continue;
        }
        if (entry.path().extension() == ".dex") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}

}   // namespace

TEST(DexRealCorpus, ParseRoundtripSummary)
{
    const std::vector<std::filesystem::path> files = corpusFiles();
    if (files.empty()) {
        GTEST_SKIP() << "LIBDEX_REAL_DEX_DIR is not set or has no .dex files";
    }

    for (const std::filesystem::path& path : files) {
        const std::vector<ca::u8> bytes = readFile(path);
        ASSERT_FALSE(bytes.empty()) << path.string();

        auto result = dex::core::readDex(dex::core::ByteSlice{bytes.data(), bytes.size()});
        ASSERT_TRUE(result.is_ok())
            << path.string() << ": " << dex::core::to_string(result.unwrap_err());

        std::unique_ptr<dex::core::DexFile> file = std::move(result).unwrap();
        EXPECT_FALSE(file->diagnostics().hasError()) << path.string();

        // 现实语料常见「checksum 已更新、签名过期」的被改产物；完整性诊断
        // 属预期降级，其余诊断（结构/索引）一律视为失败。
        for (const dex::core::Diagnostic& diagnostic : file->diagnostics().items()) {
            const bool integrityOnly = diagnostic.code == dex::core::ReadError::BadChecksum ||
                                       diagnostic.code == dex::core::ReadError::BadSignature;
            EXPECT_TRUE(integrityOnly)
                << path.string() << ": " << dex::core::to_string(diagnostic.code)
                << " @" << diagnostic.offset;
        }

        const auto written = dex::core::writeDex(*file);
        ASSERT_TRUE(written.is_ok()) << path.string();
        EXPECT_EQ(written.unwrap(), bytes) << path.string();
    }
}

TEST(DexRealCorpus, DecodeAllMethodInsns)
{
    const std::vector<std::filesystem::path> files = corpusFiles();
    if (files.empty()) {
        GTEST_SKIP() << "LIBDEX_REAL_DEX_DIR is not set or has no .dex files";
    }

    for (const std::filesystem::path& path : files) {
        const std::vector<ca::u8> bytes = readFile(path);
        ASSERT_FALSE(bytes.empty()) << path.string();

        auto parsed = dex::core::readDex(dex::core::ByteSlice{bytes.data(), bytes.size()});
        ASSERT_TRUE(parsed.is_ok())
            << path.string() << ": " << dex::core::to_string(parsed.unwrap_err());
        std::unique_ptr<dex::core::DexFile> file = std::move(parsed).unwrap();

        for (ca::u32 classIdx = 0; classIdx < file->classCount(); ++classIdx) {
            const auto dataResult = file->classData(classIdx);
            ASSERT_TRUE(dataResult.is_ok())
                << path.string() << " class " << classIdx << ": "
                << dex::core::to_string(dataResult.unwrap_err());
            const dex::core::ClassData* data = dataResult.unwrap();
            if (data == nullptr) {
                continue;
            }

            const std::vector<dex::core::EncodedMethod>* methodLists[2] = {
                &data->directMethods,
                &data->virtualMethods,
            };
            for (const std::vector<dex::core::EncodedMethod>* methods : methodLists) {
                for (const dex::core::EncodedMethod& method : *methods) {
                    if (method.codeOff == 0) {
                        continue;
                    }

                    const auto codeResult = file->codeItem(method.codeOff);
                    ASSERT_TRUE(codeResult.is_ok())
                        << path.string() << " code_item@" << method.codeOff << ": "
                        << dex::core::to_string(codeResult.unwrap_err());
                    const dex::core::CodeItem* code = codeResult.unwrap();
                    ASSERT_NE(code, nullptr);

                    const dex::core::ByteSlice insnsBytes = dex::core::subOrEmpty(
                        file->source(), code->insns.offset, code->insns.length);
                    ASSERT_EQ(insnsBytes.size(), static_cast<ca::usize>(code->insnsSize) * 2u);

                    const auto decodedResult = dex::core::decodeInsns(insnsBytes);
                    ASSERT_TRUE(decodedResult.is_ok())
                        << path.string() << " code_item@" << code->offset << ": "
                        << dex::core::to_string(decodedResult.unwrap_err());
                    const std::vector<dex::core::Insn>& insns = decodedResult.unwrap();

                    auto domResult = dex::ir::buildCodeDom(*file, method.codeOff);
                    ASSERT_TRUE(domResult.is_ok())
                        << path.string() << " code_item@" << code->offset << ": "
                        << dex::ir::to_string(domResult.unwrap_err());
                    const dex::ir::CodeDom& dom = std::move(domResult).unwrap();
                    EXPECT_TRUE(dom.issues().empty())
                        << path.string() << " code_item@" << code->offset << " issues="
                        << dom.issues().size();

                    std::unordered_map<ca::u32, ca::usize> indexByAddress;
                    indexByAddress.reserve(insns.size());
                    ca::u32 widthSum = 0;
                    for (ca::usize i = 0; i < insns.size(); ++i) {
                        widthSum += insns[i].width;
                        indexByAddress.emplace(insns[i].address, i);
                    }
                    EXPECT_EQ(widthSum, code->insnsSize)
                        << path.string() << " code_item@" << code->offset;

                    for (const dex::core::Insn& insn : insns) {
                        if (insn.opcode == 0x26 || insn.opcode == 0x2b || insn.opcode == 0x2c) {
                            ASSERT_EQ(insn.format, dex::core::InsnFormat::F31t);
                            const ca::i64 target =
                                static_cast<ca::i64>(insn.address) + insn.branchOffset;
                            ASSERT_GE(target, 0);
                            ASSERT_LT(target, code->insnsSize);
                            const auto found = indexByAddress.find(static_cast<ca::u32>(target));
                            ASSERT_NE(found, indexByAddress.end());
                            const dex::core::Insn& payload = insns[found->second];
                            ASSERT_TRUE(payload.isPayload());

                            const dex::core::PayloadKind expected =
                                insn.opcode == 0x26 ? dex::core::PayloadKind::FillArrayData
                                : insn.opcode == 0x2b
                                    ? dex::core::PayloadKind::PackedSwitch
                                    : dex::core::PayloadKind::SparseSwitch;
                            EXPECT_EQ(payload.payloadKind, expected);

                            if (expected == dex::core::PayloadKind::PackedSwitch ||
                                expected == dex::core::PayloadKind::SparseSwitch) {
                                for (ca::u32 k = 0; k < payload.payloadCount; ++k) {
                                    const ca::i32 offset =
                                        expected == dex::core::PayloadKind::PackedSwitch
                                            ? payload.packedSwitchTarget(k)
                                            : payload.sparseSwitchTarget(k);
                                    const ca::i64 caseTarget =
                                        static_cast<ca::i64>(insn.address) + offset;
                                    EXPECT_GE(caseTarget, 0);
                                    EXPECT_LT(caseTarget, code->insnsSize);
                                    if (caseTarget >= 0 &&
                                        caseTarget < code->insnsSize) {
                                        EXPECT_EQ(indexByAddress.count(
                                                      static_cast<ca::u32>(caseTarget)),
                                                  1u);
                                    }
                                }
                            }
                        } else if (insn.isBranch()) {
                            const ca::i64 target =
                                static_cast<ca::i64>(insn.address) + insn.branchOffset;
                            EXPECT_GE(target, 0);
                            EXPECT_LE(target, code->insnsSize);
                            if (target >= 0 && target < code->insnsSize) {
                                EXPECT_EQ(indexByAddress.count(static_cast<ca::u32>(target)), 1u);
                            }
                        }
                    }
                }
            }
        }
    }
}
