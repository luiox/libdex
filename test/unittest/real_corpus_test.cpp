/// @file        real_corpus_test.cpp
/// @brief       真实 dex 语料门控测试（LIBDEX_REAL_DEX_DIR）。
///
/// 语料不在仓内：环境变量指向一个目录时，逐个 .dex 做解析 + 未修改往返 +
/// 摘要 + 全方法体指令解码；变量缺席或目录为空时 skip，而不是硬失败。
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <unordered_map>
#include <unordered_set>
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

/// @brief 与索引无关的方法摘要：名称+签名、标志、code_item 形状与 opcode 序列。
///
/// canonical 重建会重排 ID 表，方法索引与指令里的索引操作数都会变；
/// 比较语义摘要而不是字节，逐字节等价由 baksmali 对拍负责。
std::string summarizeMethod(dex::core::DexFile& dex,
                            const dex::core::EncodedMethod& method)
{
    std::string out;
    const auto name = dex.methodName(method.methodIndex);
    if (name.is_ok()) {
        out.append(name.unwrap().data(), name.unwrap().size());
    }
    out.push_back('(');
    const dex::core::ProtoId& proto = dex.protoIds[dex.methodIds[method.methodIndex].protoIdx];
    const auto returnType = dex.typeDescriptor(proto.returnTypeIdx);
    if (returnType.is_ok()) {
        out.append(returnType.unwrap().data(), returnType.unwrap().size());
    }
    if (proto.parametersOff != 0) {
        const auto params = dex.typeList(proto.parametersOff);
        if (params.is_ok()) {
            for (ca::u32 i = 0; i < params.unwrap().size; ++i) {
                const auto param = dex.typeDescriptor(params.unwrap().at(i));
                if (param.is_ok()) {
                    out.append(param.unwrap().data(), param.unwrap().size());
                }
            }
        }
    }
    out.push_back(')');
    out.append(" flags=");
    out.append(std::to_string(method.accessFlags));

    if (method.codeOff == 0) {
        out.append(" nocode");
        return out;
    }
    const auto code = dex.codeItem(method.codeOff);
    if (code.is_err() || code.unwrap() == nullptr) {
        out.append(" badcode");
        return out;
    }
    out.append(" regs=");
    out.append(std::to_string(code.unwrap()->registersSize));
    out.append(" ins=");
    out.append(std::to_string(code.unwrap()->insSize));
    out.append(" outs=");
    out.append(std::to_string(code.unwrap()->outsSize));
    out.append(" tries=");
    out.append(std::to_string(code.unwrap()->triesSize));
    out.append(" dbg=");
    out.append(code.unwrap()->debugInfoOff == 0 ? "0" : "1");

    const dex::core::ByteSlice insns = dex::core::subOrEmpty(
        dex.source(), code.unwrap()->insns.offset, code.unwrap()->insns.length);
    const auto decoded = dex::core::decodeInsns(insns);
    if (decoded.is_err()) {
        out.append(" badinsns");
        return out;
    }
    out.append(" [");
    for (const dex::core::Insn& insn : decoded.unwrap()) {
        out.append(std::to_string(insn.opcode));
        out.push_back(',');
    }
    out.push_back(']');
    return out;
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

TEST(DexRealCorpus, DecodeClassValuesAndAnnotations)
{
    const std::vector<std::filesystem::path> files = corpusFiles();
    if (files.empty()) {
        GTEST_SKIP() << "LIBDEX_REAL_DEX_DIR is not set or has no .dex files";
    }

    ca::u32 totalArrays = 0;
    ca::u32 totalValues = 0;
    ca::u32 totalAnnotationItems = 0;

    for (const std::filesystem::path& path : files) {
        const std::vector<ca::u8> bytes = readFile(path);
        ASSERT_FALSE(bytes.empty()) << path.string();

        auto parsed = dex::core::readDex(dex::core::ByteSlice{bytes.data(), bytes.size()});
        ASSERT_TRUE(parsed.is_ok())
            << path.string() << ": " << dex::core::to_string(parsed.unwrap_err());
        std::unique_ptr<dex::core::DexFile> file = std::move(parsed).unwrap();

        for (ca::u32 classIdx = 0; classIdx < file->classCount(); ++classIdx) {
            const auto values = file->staticValues(classIdx);
            ASSERT_TRUE(values.is_ok())
                << path.string() << " class " << classIdx << ": "
                << dex::core::to_string(values.unwrap_err());
            if (const dex::core::EncodedArrayItem* array = values.unwrap()) {
                ++totalArrays;
                totalValues += static_cast<ca::u32>(array->values.size());

                // 解码 → 重编码必须逐字节还原 encoded_array_item 的源区间。
                const auto encoded = dex::core::writeEncodedArray(array->values);
                ASSERT_TRUE(encoded.is_ok())
                    << path.string() << " static_values@" << array->raw.offset << ": "
                    << dex::core::to_string(encoded.unwrap_err());
                const dex::core::ByteSlice raw = dex::core::subOrEmpty(
                    file->source(), array->raw.offset, array->raw.length);
                ASSERT_EQ(encoded.unwrap().size(), raw.size())
                    << path.string() << " static_values@" << array->raw.offset;
                EXPECT_EQ(std::memcmp(encoded.unwrap().data(), raw.data(), raw.size()), 0)
                    << path.string() << " static_values@" << array->raw.offset;
            }

            const auto annotations = file->classAnnotations(classIdx);
            ASSERT_TRUE(annotations.is_ok())
                << path.string() << " class " << classIdx << ": "
                << dex::core::to_string(annotations.unwrap_err());
            const dex::core::AnnotationsDirectory* directory = annotations.unwrap();
            if (directory == nullptr) {
                continue;
            }

            const auto directoryBytes = dex::core::writeAnnotationsDirectory(*directory);
            ASSERT_TRUE(directoryBytes.is_ok())
                << path.string() << " annotations_directory@" << directory->raw.offset << ": "
                << dex::core::to_string(directoryBytes.unwrap_err());
            const dex::core::ByteSlice directoryRaw = dex::core::subOrEmpty(
                file->source(), directory->raw.offset, directory->raw.length);
            ASSERT_EQ(directoryBytes.unwrap().size(), directoryRaw.size());
            EXPECT_EQ(std::memcmp(directoryBytes.unwrap().data(), directoryRaw.data(),
                                  directoryRaw.size()),
                      0)
                << path.string() << " annotations_directory@" << directory->raw.offset;

            const auto readSet = [&](ca::u32 setOff) {
                if (setOff == 0) {
                    return;
                }
                const auto set = file->annotationSet(setOff);
                ASSERT_TRUE(set.is_ok())
                    << path.string() << " annotation_set@" << setOff << ": "
                    << dex::core::to_string(set.unwrap_err());
                if (set.unwrap() == nullptr) {
                    return;
                }

                const auto setBytes = dex::core::writeAnnotationSet(*set.unwrap());
                ASSERT_TRUE(setBytes.is_ok());
                const dex::core::ByteSlice setRaw = dex::core::subOrEmpty(
                    file->source(), set.unwrap()->raw.offset, set.unwrap()->raw.length);
                ASSERT_EQ(setBytes.unwrap().size(), setRaw.size());
                EXPECT_EQ(std::memcmp(setBytes.unwrap().data(), setRaw.data(), setRaw.size()),
                          0)
                    << path.string() << " annotation_set@" << setOff;

                for (ca::u32 itemOff : set.unwrap()->annotationOffs) {
                    const auto item = file->annotationItem(itemOff);
                    ASSERT_TRUE(item.is_ok())
                        << path.string() << " annotation_item@" << itemOff << ": "
                        << dex::core::to_string(item.unwrap_err());
                    ASSERT_NE(item.unwrap(), nullptr);
                    ++totalAnnotationItems;

                    // 注解体解码 → 重编码必须逐字节还原（visibility 字节除外）。
                    const dex::core::AnnotationItem* annotation = item.unwrap();
                    const auto encoded =
                        dex::core::writeEncodedAnnotation(annotation->annotation);
                    ASSERT_TRUE(encoded.is_ok())
                        << path.string() << " annotation_item@" << itemOff << ": "
                        << dex::core::to_string(encoded.unwrap_err());
                    ASSERT_GE(annotation->raw.length, 1u);
                    const dex::core::ByteSlice raw = dex::core::subOrEmpty(
                        file->source(), annotation->raw.offset + 1,
                        annotation->raw.length - 1);
                    ASSERT_EQ(encoded.unwrap().size(), raw.size())
                        << path.string() << " annotation_item@" << itemOff;
                    EXPECT_EQ(std::memcmp(encoded.unwrap().data(), raw.data(), raw.size()), 0)
                        << path.string() << " annotation_item@" << itemOff;
                }
            };

            readSet(directory->classAnnotationsOff);
            for (const dex::core::AnnotationsDirectoryEntry& entry :
                 directory->fieldAnnotations) {
                readSet(entry.annotationsOff);
            }
            for (const dex::core::AnnotationsDirectoryEntry& entry :
                 directory->methodAnnotations) {
                readSet(entry.annotationsOff);
            }
            for (const dex::core::AnnotationsDirectoryEntry& entry :
                 directory->parameterAnnotations) {
                const auto refs = file->annotationSetRefList(entry.annotationsOff);
                ASSERT_TRUE(refs.is_ok())
                    << path.string() << " annotation_set_ref_list@" << entry.annotationsOff
                    << ": " << dex::core::to_string(refs.unwrap_err());
                if (refs.unwrap() == nullptr) {
                    continue;
                }

                const auto refsBytes = dex::core::writeAnnotationSetRefList(*refs.unwrap());
                ASSERT_TRUE(refsBytes.is_ok());
                const dex::core::ByteSlice refsRaw = dex::core::subOrEmpty(
                    file->source(), refs.unwrap()->raw.offset, refs.unwrap()->raw.length);
                ASSERT_EQ(refsBytes.unwrap().size(), refsRaw.size());
                EXPECT_EQ(std::memcmp(refsBytes.unwrap().data(), refsRaw.data(),
                                      refsRaw.size()),
                          0)
                    << path.string() << " annotation_set_ref_list@" << entry.annotationsOff;

                for (ca::u32 setOff : refs.unwrap()->annotationSetOffs) {
                    readSet(setOff);
                }
            }
        }
    }

    EXPECT_GT(totalArrays, 0u);
    EXPECT_GT(totalValues, 0u);
    EXPECT_GT(totalAnnotationItems, 0u);
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

        for (ca::u32 i = 0; i < file->callSiteCount(); ++i) {
            const auto values = file->callSiteValues(i);
            ASSERT_TRUE(values.is_ok())
                << path.string() << " call_site " << i << ": "
                << dex::core::to_string(values.unwrap_err());
        }

        for (ca::u32 classIdx = 0; classIdx < file->classCount(); ++classIdx) {
            const auto dataResult = file->classData(classIdx);
            ASSERT_TRUE(dataResult.is_ok())
                << path.string() << " class " << classIdx << ": "
                << dex::core::to_string(dataResult.unwrap_err());
            const dex::core::ClassData* data = dataResult.unwrap();
            if (data == nullptr) {
                continue;
            }

            const auto dataBytes = dex::core::writeClassData(*data);
            ASSERT_TRUE(dataBytes.is_ok())
                << path.string() << " class_data@" << data->raw.offset << ": "
                << dex::core::to_string(dataBytes.unwrap_err());
            const dex::core::ByteSlice dataRaw = dex::core::subOrEmpty(
                file->source(), data->raw.offset, data->raw.length);
            ASSERT_EQ(dataBytes.unwrap().size(), dataRaw.size());
            EXPECT_EQ(std::memcmp(dataBytes.unwrap().data(), dataRaw.data(), dataRaw.size()), 0)
                << path.string() << " class_data@" << data->raw.offset;

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

                    if (code->debugInfoOff != 0) {
                        const auto info = file->debugInfo(code->debugInfoOff);
                        ASSERT_TRUE(info.is_ok())
                            << path.string() << " debug_info@" << code->debugInfoOff << ": "
                            << dex::core::to_string(info.unwrap_err());
                        ASSERT_NE(info.unwrap(), nullptr);

                        const auto encoded = dex::core::writeDebugInfo(*info.unwrap());
                        ASSERT_TRUE(encoded.is_ok())
                            << path.string() << " debug_info@" << code->debugInfoOff << ": "
                            << dex::core::to_string(encoded.unwrap_err());
                        const dex::core::ByteSlice raw = dex::core::subOrEmpty(
                            file->source(), info.unwrap()->raw.offset,
                            info.unwrap()->raw.length);
                        ASSERT_EQ(encoded.unwrap().size(), raw.size())
                            << path.string() << " debug_info@" << code->debugInfoOff;
                        EXPECT_EQ(std::memcmp(encoded.unwrap().data(), raw.data(),
                                              raw.size()),
                                  0)
                            << path.string() << " debug_info@" << code->debugInfoOff;
                    }

                    const dex::core::ByteSlice insnsBytes = dex::core::subOrEmpty(
                        file->source(), code->insns.offset, code->insns.length);
                    ASSERT_EQ(insnsBytes.size(), static_cast<ca::usize>(code->insnsSize) * 2u);

                    const auto decodedResult = dex::core::decodeInsns(insnsBytes);
                    ASSERT_TRUE(decodedResult.is_ok())
                        << path.string() << " code_item@" << code->offset << ": "
                        << dex::core::to_string(decodedResult.unwrap_err());
                    const std::vector<dex::core::Insn>& insns = decodedResult.unwrap();

                    // 低层编码器必须逐字节还原源指令流：不合并 const 形态，
                    // 不重排 payload，nop 变体的未用高位也原样保留。
                    const auto encodedResult = dex::core::encodeInsns(insns);
                    ASSERT_TRUE(encodedResult.is_ok())
                        << path.string() << " code_item@" << code->offset << ": "
                        << dex::core::to_string(encodedResult.unwrap_err());
                    const std::vector<ca::u8>& encoded = encodedResult.unwrap();
                    ASSERT_EQ(encoded.size(), insnsBytes.size())
                        << path.string() << " code_item@" << code->offset;
                    EXPECT_EQ(std::memcmp(encoded.data(), insnsBytes.data(),
                                          insnsBytes.size()),
                              0)
                        << path.string() << " code_item@" << code->offset;

                    const auto itemBytes = dex::core::writeCodeItem(
                        *code, dex::core::ByteSlice{encoded.data(), encoded.size()});
                    ASSERT_TRUE(itemBytes.is_ok())
                        << path.string() << " code_item@" << code->offset << ": "
                        << dex::core::to_string(itemBytes.unwrap_err());
                    const ca::u32 itemEnd =
                        code->handlersOff != 0
                            ? code->handlers.offset + code->handlers.length
                            : code->raw.offset + code->raw.length;
                    const dex::core::ByteSlice itemRaw = dex::core::subOrEmpty(
                        file->source(), code->offset, itemEnd - code->offset);
                    ASSERT_EQ(itemBytes.unwrap().size(), itemRaw.size())
                        << path.string() << " code_item@" << code->offset;
                    EXPECT_EQ(std::memcmp(itemBytes.unwrap().data(), itemRaw.data(),
                                          itemRaw.size()),
                              0)
                        << path.string() << " code_item@" << code->offset;

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

TEST(DexRealCorpus, RebuildsCanonical)
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

        auto built = dex::core::buildDex(*file);
        ASSERT_TRUE(built.is_ok())
            << path.string() << ": " << dex::core::to_string(built.unwrap_err());
        const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

        auto reparsed = dex::core::readDex(
            dex::core::ByteSlice{rebuilt.data(), rebuilt.size()});
        ASSERT_TRUE(reparsed.is_ok())
            << path.string() << ": " << dex::core::to_string(reparsed.unwrap_err());
        std::unique_ptr<dex::core::DexFile> second = std::move(reparsed).unwrap();

        ASSERT_EQ(second->state(), dex::core::ParseState::Validated) << path.string();
        const dex::core::Integrity integrity = dex::core::verifyIntegrity(
            second->source(), second->header.checksum, second->header.signature);
        EXPECT_TRUE(integrity.checksumOk) << path.string();
        EXPECT_TRUE(integrity.signatureOk) << path.string();

        EXPECT_EQ(second->stringCount(), file->stringCount()) << path.string();
        EXPECT_EQ(second->typeCount(), file->typeCount()) << path.string();
        EXPECT_EQ(second->protoCount(), file->protoCount()) << path.string();
        EXPECT_EQ(second->fieldCount(), file->fieldCount()) << path.string();
        EXPECT_EQ(second->methodCount(), file->methodCount()) << path.string();
        EXPECT_EQ(second->classCount(), file->classCount()) << path.string();

        // class_defs 会按 class_idx 重排，比较时以描述符对齐新旧类。
        std::unordered_map<std::string, ca::u32> firstClassByDescriptor;
        for (ca::u32 classIdx = 0; classIdx < file->classCount(); ++classIdx) {
            const auto descriptor = file->classDescriptor(classIdx);
            ASSERT_TRUE(descriptor.is_ok()) << path.string() << " class " << classIdx;
            firstClassByDescriptor.emplace(
                std::string(descriptor.unwrap().as_std_view()), classIdx);
        }

        for (ca::u32 secondIdx = 0; secondIdx < second->classCount(); ++secondIdx) {
            const auto descriptor = second->classDescriptor(secondIdx);
            ASSERT_TRUE(descriptor.is_ok()) << path.string() << " class " << secondIdx;
            const auto mapped =
                firstClassByDescriptor.find(std::string(descriptor.unwrap().as_std_view()));
            ASSERT_NE(mapped, firstClassByDescriptor.end())
                << path.string() << " class " << secondIdx;
            const ca::u32 classIdx = mapped->second;
            const auto firstData = file->classData(classIdx);
            const auto secondData = second->classData(secondIdx);
            ASSERT_TRUE(firstData.is_ok()) << path.string() << " class " << classIdx;
            ASSERT_TRUE(secondData.is_ok()) << path.string() << " class " << classIdx;
            if (firstData.unwrap() == nullptr) {
                EXPECT_EQ(secondData.unwrap(), nullptr)
                    << path.string() << " class " << classIdx;
                continue;
            }
            ASSERT_NE(secondData.unwrap(), nullptr) << path.string() << " class " << classIdx;

            const std::vector<dex::core::EncodedMethod>* firstLists[2] = {
                &firstData.unwrap()->directMethods,
                &firstData.unwrap()->virtualMethods,
            };
            const std::vector<dex::core::EncodedMethod>* secondLists[2] = {
                &secondData.unwrap()->directMethods,
                &secondData.unwrap()->virtualMethods,
            };
            const auto summarize = [](dex::core::DexFile& source,
                                      const std::vector<dex::core::EncodedMethod>& methods) {
                std::vector<std::string> out;
                out.reserve(methods.size());
                for (const dex::core::EncodedMethod& method : methods) {
                    out.push_back(summarizeMethod(source, method));
                }
                std::sort(out.begin(), out.end());
                return out;
            };
            for (ca::u32 listIdx = 0; listIdx < 2; ++listIdx) {
                const std::vector<std::string> expected =
                    summarize(*file, *firstLists[listIdx]);
                const std::vector<std::string> actual =
                    summarize(*second, *secondLists[listIdx]);
                EXPECT_EQ(actual, expected) << path.string() << " class " << classIdx;
            }
        }

        // 注解族与静态初值的偏移在新布局中必须仍然可解。
        for (ca::u32 classIdx = 0; classIdx < second->classCount(); ++classIdx) {
            const auto values = second->staticValues(classIdx);
            ASSERT_TRUE(values.is_ok()) << path.string() << " class " << classIdx;
            const auto annotations = second->classAnnotations(classIdx);
            ASSERT_TRUE(annotations.is_ok()) << path.string() << " class " << classIdx;
            const dex::core::AnnotationsDirectory* directory = annotations.unwrap();
            if (directory == nullptr) {
                continue;
            }

            const auto checkSet = [&](ca::u32 setOff) {
                if (setOff == 0) {
                    return;
                }
                const auto set = second->annotationSet(setOff);
                ASSERT_TRUE(set.is_ok())
                    << path.string() << " annotation_set@" << setOff << ": "
                    << dex::core::to_string(set.unwrap_err());
                ASSERT_NE(set.unwrap(), nullptr) << path.string() << " annotation_set@" << setOff;
                for (ca::u32 itemOff : set.unwrap()->annotationOffs) {
                    const auto item = second->annotationItem(itemOff);
                    ASSERT_TRUE(item.is_ok())
                        << path.string() << " annotation_item@" << itemOff << ": "
                        << dex::core::to_string(item.unwrap_err());
                    ASSERT_NE(item.unwrap(), nullptr)
                        << path.string() << " annotation_item@" << itemOff;
                }
            };

            checkSet(directory->classAnnotationsOff);
            for (const dex::core::AnnotationsDirectoryEntry& entry :
                 directory->fieldAnnotations) {
                checkSet(entry.annotationsOff);
            }
            for (const dex::core::AnnotationsDirectoryEntry& entry :
                 directory->methodAnnotations) {
                checkSet(entry.annotationsOff);
            }
            for (const dex::core::AnnotationsDirectoryEntry& entry :
                 directory->parameterAnnotations) {
                if (entry.annotationsOff == 0) {
                    continue;
                }
                const auto refs = second->annotationSetRefList(entry.annotationsOff);
                ASSERT_TRUE(refs.is_ok())
                    << path.string() << " annotation_set_ref_list@" << entry.annotationsOff
                    << ": " << dex::core::to_string(refs.unwrap_err());
                ASSERT_NE(refs.unwrap(), nullptr);
                for (ca::u32 setOff : refs.unwrap()->annotationSetOffs) {
                    checkSet(setOff);
                }
            }
        }
        for (ca::u32 i = 0; i < second->callSiteCount(); ++i) {
            const auto values = second->callSiteValues(i);
            ASSERT_TRUE(values.is_ok()) << path.string() << " call_site " << i;
        }
        for (ca::u32 i = 0; i < second->methodHandleCount(); ++i) {
            const dex::core::MethodHandle& handle = second->methodHandles[i];
            ASSERT_LE(handle.handleType, 8u);
            const ca::u32 limit =
                handle.handleType <= 3 ? second->fieldCount() : second->methodCount();
            EXPECT_LT(handle.targetIdx, limit);
        }

        auto builtAgain = dex::core::buildDex(*second);
        ASSERT_TRUE(builtAgain.is_ok())
            << path.string() << ": " << dex::core::to_string(builtAgain.unwrap_err());
        EXPECT_EQ(builtAgain.unwrap(), rebuilt) << path.string();
    }
}

/// @brief 逐类摘要清单（类描述符 + 排序后的方法摘要），布局无关。
std::vector<std::string> summarizeClasses(dex::core::DexFile& dex)
{
    std::vector<std::string> out;
    out.reserve(dex.classCount());
    for (ca::u32 classIdx = 0; classIdx < dex.classCount(); ++classIdx) {
        const auto descriptor = dex.classDescriptor(classIdx);
        if (descriptor.is_err()) {
            out.push_back("<bad>");
            continue;
        }
        std::string entry(descriptor.unwrap().as_std_view());
        const auto data = dex.classData(classIdx);
        if (data.is_err() || data.unwrap() == nullptr) {
            out.push_back(std::move(entry));
            continue;
        }
        const std::vector<dex::core::EncodedMethod>* lists[2] = {
            &data.unwrap()->directMethods, &data.unwrap()->virtualMethods};
        for (const std::vector<dex::core::EncodedMethod>* list : lists) {
            std::vector<std::string> methods;
            methods.reserve(list->size());
            for (const dex::core::EncodedMethod& method : *list) {
                methods.push_back(summarizeMethod(dex, method));
            }
            std::sort(methods.begin(), methods.end());
            for (const std::string& method : methods) {
                entry.push_back('|');
                entry.append(method);
            }
        }
        out.push_back(std::move(entry));
    }
    std::sort(out.begin(), out.end());
    return out;
}

TEST(DexRealCorpus, IncrementalRebuildReproducesAndAgrees)
{
    const std::vector<std::filesystem::path> files = corpusFiles();
    if (files.empty()) {
        GTEST_SKIP() << "LIBDEX_REAL_DEX_DIR is not set or has .dex files";
    }

    for (const std::filesystem::path& path : files) {
        const std::vector<ca::u8> bytes = readFile(path);
        ASSERT_FALSE(bytes.empty()) << path.string();

        // 无编辑增量：全部条目未触碰，输出必须与源逐字节一致。
        {
            auto parsed =
                dex::core::readDex(dex::core::ByteSlice{bytes.data(), bytes.size()});
            ASSERT_TRUE(parsed.is_ok()) << path.string();
            std::unique_ptr<dex::core::DexFile> file = std::move(parsed).unwrap();
            dex::core::BuildOptions options;
            options.incremental = true;
            auto built = dex::core::buildDex(*file, options);
            ASSERT_TRUE(built.is_ok())
                << path.string() << ": " << dex::core::to_string(built.unwrap_err());
            EXPECT_EQ(built.unwrap(), bytes) << path.string();
        }

        // 条目级编辑（剥离 debug）：增量产物 Validated、可二次稳定，且与
        // canonical 同编辑产物逐类语义一致。
        auto parse = [&]() {
            auto parsed =
                dex::core::readDex(dex::core::ByteSlice{bytes.data(), bytes.size()});
            return parsed;
        };
        auto canonical = parse();
        ASSERT_TRUE(canonical.is_ok()) << path.string();
        std::unique_ptr<dex::core::DexFile> canonicalFile = std::move(canonical).unwrap();
        dex::core::BuildOptions canonicalOptions;
        canonicalOptions.stripDebugInfo = true;
        auto canonicalBuilt = dex::core::buildDex(*canonicalFile, canonicalOptions);
        ASSERT_TRUE(canonicalBuilt.is_ok())
            << path.string() << ": " << dex::core::to_string(canonicalBuilt.unwrap_err());

        auto incremental = parse();
        ASSERT_TRUE(incremental.is_ok()) << path.string();
        std::unique_ptr<dex::core::DexFile> incrementalFile = std::move(incremental).unwrap();
        dex::core::BuildOptions incrementalOptions;
        incrementalOptions.incremental = true;
        incrementalOptions.stripDebugInfo = true;
        auto incrementalBuilt = dex::core::buildDex(*incrementalFile, incrementalOptions);
        ASSERT_TRUE(incrementalBuilt.is_ok())
            << path.string() << ": " << dex::core::to_string(incrementalBuilt.unwrap_err());
        const std::vector<ca::u8> incrementalBytes = std::move(incrementalBuilt).unwrap();

        auto readBack = [&](const std::vector<ca::u8>& data) {
            auto parsed = dex::core::readDex(dex::core::ByteSlice{data.data(), data.size()});
            return parsed;
        };
        auto canonicalSecond = readBack(canonicalBuilt.unwrap());
        ASSERT_TRUE(canonicalSecond.is_ok()) << path.string();
        auto incrementalSecond = readBack(incrementalBytes);
        ASSERT_TRUE(incrementalSecond.is_ok()) << path.string();
        std::unique_ptr<dex::core::DexFile> canonicalModel = std::move(canonicalSecond).unwrap();
        std::unique_ptr<dex::core::DexFile> incrementalModel =
            std::move(incrementalSecond).unwrap();
        ASSERT_EQ(incrementalModel->state(), dex::core::ParseState::Validated)
            << path.string();
        const dex::core::Integrity integrity = dex::core::verifyIntegrity(
            incrementalModel->source(), incrementalModel->header.checksum,
            incrementalModel->header.signature);
        EXPECT_TRUE(integrity.checksumOk) << path.string();
        EXPECT_TRUE(integrity.signatureOk) << path.string();
        EXPECT_EQ(incrementalModel->classCount(), canonicalModel->classCount())
            << path.string();
        EXPECT_EQ(summarizeClasses(*incrementalModel), summarizeClasses(*canonicalModel))
            << path.string();
        // debug 条目应整体消失。
        EXPECT_EQ(incrementalModel->findMapItem(dex::core::MapType::DebugInfoItem), nullptr)
            << path.string();

        // 无新编辑的二次增量：逐字节稳定。
        dex::core::BuildOptions stable;
        stable.incremental = true;
        auto rebuilt = dex::core::buildDex(*incrementalModel, stable);
        ASSERT_TRUE(rebuilt.is_ok())
            << path.string() << ": " << dex::core::to_string(rebuilt.unwrap_err());
        EXPECT_EQ(rebuilt.unwrap(), incrementalBytes) << path.string();
    }
}

TEST(DexRealCorpus, RebuildsAfterMethodAndFieldRenames)
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

        std::unordered_map<std::string, ca::u32> renamedMethodsPerClass;
        std::unordered_map<std::string, ca::u32> renamedFieldsPerClass;
        std::unordered_set<ca::u32> seenMethods;
        std::unordered_set<ca::u32> seenFields;
        std::unordered_set<std::string> renamedMethodNames;
        std::unordered_set<std::string> renamedFieldNames;

        for (ca::u32 classIdx = 0; classIdx < file->classCount(); ++classIdx) {
            const auto data = file->classData(classIdx);
            ASSERT_TRUE(data.is_ok()) << path.string() << " class " << classIdx;
            if (data.unwrap() == nullptr) {
                continue;
            }

            const auto descriptor = file->classDescriptor(classIdx);
            ASSERT_TRUE(descriptor.is_ok()) << path.string() << " class " << classIdx;
            const std::string classKey(descriptor.unwrap().as_std_view());

            const std::vector<dex::core::EncodedMethod>* methodLists[2] = {
                &data.unwrap()->directMethods,
                &data.unwrap()->virtualMethods,
            };
            for (const std::vector<dex::core::EncodedMethod>* list : methodLists) {
                for (ca::usize i = list->size() / 2; i < list->size(); ++i) {
                    const ca::u32 methodIdx = (*list)[i].methodIndex;
                    if (!seenMethods.insert(methodIdx).second) {
                        continue;
                    }
                    const auto oldName = file->methodName(methodIdx);
                    ASSERT_TRUE(oldName.is_ok()) << path.string() << " method " << methodIdx;
                    std::string newName = "!renamed!";
                    newName.append(oldName.unwrap().data(), oldName.unwrap().size());
                    const auto interned = file->internUtf8(newName);
                    ASSERT_TRUE(interned.is_ok()) << path.string() << " method " << methodIdx;
                    file->methodIds[methodIdx].nameIdx = interned.unwrap();
                    renamedMethodNames.insert(newName);
                    ++renamedMethodsPerClass[classKey];
                }
            }

            const std::vector<dex::core::EncodedField>* fieldLists[2] = {
                &data.unwrap()->staticFields,
                &data.unwrap()->instanceFields,
            };
            for (const std::vector<dex::core::EncodedField>* list : fieldLists) {
                for (ca::usize i = list->size() / 2; i < list->size(); ++i) {
                    const ca::u32 fieldIdx = (*list)[i].fieldIndex;
                    if (!seenFields.insert(fieldIdx).second) {
                        continue;
                    }
                    const auto oldName = file->fieldName(fieldIdx);
                    ASSERT_TRUE(oldName.is_ok()) << path.string() << " field " << fieldIdx;
                    std::string newName = "!renamed!";
                    newName.append(oldName.unwrap().data(), oldName.unwrap().size());
                    const auto interned = file->internUtf8(newName);
                    ASSERT_TRUE(interned.is_ok()) << path.string() << " field " << fieldIdx;
                    file->fieldIds[fieldIdx].nameIdx = interned.unwrap();
                    renamedFieldNames.insert(newName);
                    ++renamedFieldsPerClass[classKey];
                }
            }
        }

        dex::core::BuildOptions options;
        options.keepUnknownSections = false;
        auto built = dex::core::buildDex(*file, options);
        ASSERT_TRUE(built.is_ok())
            << path.string() << ": " << dex::core::to_string(built.unwrap_err());
        const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

        auto reparsed = dex::core::readDex(
            dex::core::ByteSlice{rebuilt.data(), rebuilt.size()});
        ASSERT_TRUE(reparsed.is_ok())
            << path.string() << ": " << dex::core::to_string(reparsed.unwrap_err());
        std::unique_ptr<dex::core::DexFile> second = std::move(reparsed).unwrap();

        EXPECT_EQ(second->state(), dex::core::ParseState::Validated) << path.string();
        const dex::core::Integrity integrity = dex::core::verifyIntegrity(
            second->source(), second->header.checksum, second->header.signature);
        EXPECT_TRUE(integrity.checksumOk) << path.string();
        EXPECT_TRUE(integrity.signatureOk) << path.string();
        EXPECT_EQ(second->typeCount(), file->typeCount()) << path.string();
        EXPECT_EQ(second->protoCount(), file->protoCount()) << path.string();
        EXPECT_EQ(second->fieldCount(), file->fieldCount()) << path.string();
        EXPECT_EQ(second->methodCount(), file->methodCount()) << path.string();
        EXPECT_EQ(second->classCount(), file->classCount()) << path.string();
        EXPECT_GE(second->stringCount(), file->stringCount()) << path.string();

        for (ca::u32 classIdx = 0; classIdx < second->classCount(); ++classIdx) {
            const auto descriptor = second->classDescriptor(classIdx);
            ASSERT_TRUE(descriptor.is_ok()) << path.string() << " class " << classIdx;
            const std::string classKey(descriptor.unwrap().as_std_view());
            const ca::u32 expectedMethods = renamedMethodsPerClass.count(classKey) != 0
                                                ? renamedMethodsPerClass.at(classKey)
                                                : 0u;
            const ca::u32 expectedFields = renamedFieldsPerClass.count(classKey) != 0
                                               ? renamedFieldsPerClass.at(classKey)
                                               : 0u;

            const auto data = second->classData(classIdx);
            ASSERT_TRUE(data.is_ok()) << path.string() << " class " << classIdx;
            if (data.unwrap() == nullptr) {
                EXPECT_EQ(expectedMethods, 0u);
                EXPECT_EQ(expectedFields, 0u);
                continue;
            }

            ca::u32 methodHits = 0;
            const std::vector<dex::core::EncodedMethod>* methodLists[2] = {
                &data.unwrap()->directMethods,
                &data.unwrap()->virtualMethods,
            };
            for (const std::vector<dex::core::EncodedMethod>* list : methodLists) {
                for (const dex::core::EncodedMethod& method : *list) {
                    ASSERT_LT(method.methodIndex, second->methodCount());
                    const auto name = second->methodName(method.methodIndex);
                    ASSERT_TRUE(name.is_ok());
                    if (renamedMethodNames.count(std::string(name.unwrap().as_std_view())) != 0) {
                        ++methodHits;
                    }
                    if (method.codeOff == 0) {
                        continue;
                    }
                    const auto code = second->codeItem(method.codeOff);
                    ASSERT_TRUE(code.is_ok());
                    ASSERT_NE(code.unwrap(), nullptr);
                    const dex::core::ByteSlice insns = dex::core::subOrEmpty(
                        second->source(), code.unwrap()->insns.offset,
                        code.unwrap()->insns.length);
                    const auto decoded = dex::core::decodeInsns(insns);
                    ASSERT_TRUE(decoded.is_ok())
                        << path.string() << " method " << method.methodIndex;
                    for (const dex::core::Insn& insn : decoded.unwrap()) {
                        switch (insn.indexKind) {
                            case dex::core::IndexKind::String:
                                EXPECT_LT(insn.index, second->stringCount());
                                break;
                            case dex::core::IndexKind::Type:
                                EXPECT_LT(insn.index, second->typeCount());
                                break;
                            case dex::core::IndexKind::Field:
                                EXPECT_LT(insn.index, second->fieldCount());
                                break;
                            case dex::core::IndexKind::Method:
                                EXPECT_LT(insn.index, second->methodCount());
                                break;
                            case dex::core::IndexKind::Proto:
                                EXPECT_LT(insn.index, second->protoCount());
                                break;
                            default:
                                break;
                        }
                    }
                }
            }
            EXPECT_EQ(methodHits, expectedMethods)
                << path.string() << " class " << classIdx;

            ca::u32 fieldHits = 0;
            const std::vector<dex::core::EncodedField>* fieldLists[2] = {
                &data.unwrap()->staticFields,
                &data.unwrap()->instanceFields,
            };
            for (const std::vector<dex::core::EncodedField>* list : fieldLists) {
                for (const dex::core::EncodedField& field : *list) {
                    ASSERT_LT(field.fieldIndex, second->fieldCount());
                    const auto name = second->fieldName(field.fieldIndex);
                    ASSERT_TRUE(name.is_ok());
                    if (renamedFieldNames.count(std::string(name.unwrap().as_std_view())) != 0) {
                        ++fieldHits;
                    }
                }
            }
            EXPECT_EQ(fieldHits, expectedFields)
                << path.string() << " class " << classIdx;
        }

        auto builtAgain = dex::core::buildDex(*second, options);
        ASSERT_TRUE(builtAgain.is_ok())
            << path.string() << ": " << dex::core::to_string(builtAgain.unwrap_err());
        EXPECT_EQ(builtAgain.unwrap(), rebuilt) << path.string();
    }
}

TEST(DexRealCorpus, StripsMetadata)
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

        dex::core::BuildOptions options;
        options.keepUnknownSections = false;
        options.stripDebugInfo = true;
        options.stripAnnotations = true;

        auto built = dex::core::buildDex(*file, options);
        ASSERT_TRUE(built.is_ok())
            << path.string() << ": " << dex::core::to_string(built.unwrap_err());
        const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

        auto reparsed = dex::core::readDex(
            dex::core::ByteSlice{rebuilt.data(), rebuilt.size()});
        ASSERT_TRUE(reparsed.is_ok())
            << path.string() << ": " << dex::core::to_string(reparsed.unwrap_err());
        std::unique_ptr<dex::core::DexFile> second = std::move(reparsed).unwrap();

        EXPECT_EQ(second->state(), dex::core::ParseState::Validated) << path.string();
        const dex::core::Integrity integrity = dex::core::verifyIntegrity(
            second->source(), second->header.checksum, second->header.signature);
        EXPECT_TRUE(integrity.checksumOk) << path.string();
        EXPECT_TRUE(integrity.signatureOk) << path.string();

        EXPECT_EQ(second->findMapItem(dex::core::MapType::DebugInfoItem), nullptr)
            << path.string();
        EXPECT_EQ(second->findMapItem(dex::core::MapType::AnnotationItem), nullptr)
            << path.string();
        EXPECT_EQ(second->findMapItem(dex::core::MapType::AnnotationSetItem), nullptr)
            << path.string();
        EXPECT_EQ(second->findMapItem(dex::core::MapType::AnnotationSetRefList), nullptr)
            << path.string();
        EXPECT_EQ(second->findMapItem(dex::core::MapType::AnnotationsDirectoryItem), nullptr)
            << path.string();

        for (ca::u32 classIdx = 0; classIdx < second->classCount(); ++classIdx) {
            const auto annotations = second->classAnnotations(classIdx);
            ASSERT_TRUE(annotations.is_ok()) << path.string() << " class " << classIdx;
            EXPECT_EQ(annotations.unwrap(), nullptr) << path.string();
            const auto data = second->classData(classIdx);
            ASSERT_TRUE(data.is_ok()) << path.string() << " class " << classIdx;
            if (data.unwrap() == nullptr) {
                continue;
            }
            const std::vector<dex::core::EncodedMethod>* lists[2] = {
                &data.unwrap()->directMethods,
                &data.unwrap()->virtualMethods,
            };
            for (const std::vector<dex::core::EncodedMethod>* list : lists) {
                for (const dex::core::EncodedMethod& method : *list) {
                    if (method.codeOff == 0) {
                        continue;
                    }
                    const auto code = second->codeItem(method.codeOff);
                    ASSERT_TRUE(code.is_ok()) << path.string();
                    ASSERT_NE(code.unwrap(), nullptr) << path.string();
                    EXPECT_EQ(code.unwrap()->debugInfoOff, 0u) << path.string();
                }
            }
        }

        dex::core::BuildOptions plain;
        plain.keepUnknownSections = false;
        auto builtAgain = dex::core::buildDex(*second, plain);
        ASSERT_TRUE(builtAgain.is_ok())
            << path.string() << ": " << dex::core::to_string(builtAgain.unwrap_err());
        EXPECT_EQ(builtAgain.unwrap(), rebuilt) << path.string();
    }
}

TEST(DexRealCorpus, RebuildsAfterRemovingMembers)
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

        ca::u32 target = dex::core::DexFile::kNoIndex;
        ca::u32 removedMethod = dex::core::DexFile::kNoIndex;
        ca::u32 removedField = dex::core::DexFile::kNoIndex;
        for (ca::u32 classIdx = 0; classIdx < file->classCount(); ++classIdx) {
            const auto data = file->classData(classIdx);
            ASSERT_TRUE(data.is_ok()) << path.string() << " class " << classIdx;
            if (data.unwrap() == nullptr) {
                continue;
            }
            const std::vector<dex::core::EncodedMethod>* methodLists[2] = {
                &data.unwrap()->directMethods,
                &data.unwrap()->virtualMethods,
            };
            for (const std::vector<dex::core::EncodedMethod>* list : methodLists) {
                for (const dex::core::EncodedMethod& method : *list) {
                    if (method.codeOff != 0) {
                        target = classIdx;
                        removedMethod = method.methodIndex;
                        break;
                    }
                }
                if (target != dex::core::DexFile::kNoIndex) {
                    break;
                }
            }
            if (target != dex::core::DexFile::kNoIndex) {
                break;
            }
        }
        if (target == dex::core::DexFile::kNoIndex) {
            continue;
        }

        const auto data = file->classData(target);
        ASSERT_TRUE(data.is_ok());
        if (!data.unwrap()->staticFields.empty()) {
            removedField = data.unwrap()->staticFields.front().fieldIndex;
        } else if (!data.unwrap()->instanceFields.empty()) {
            removedField = data.unwrap()->instanceFields.front().fieldIndex;
        }
        const auto targetDescriptor = file->classDescriptor(target);
        ASSERT_TRUE(targetDescriptor.is_ok()) << path.string();
        const std::string targetName(targetDescriptor.unwrap().as_std_view());

        dex::core::BuildOptions options;
        options.keepUnknownSections = false;
        options.removedMethods.push_back(removedMethod);
        if (removedField != dex::core::DexFile::kNoIndex) {
            options.removedFields.push_back(removedField);
        }

        auto built = dex::core::buildDex(*file, options);
        ASSERT_TRUE(built.is_ok())
            << path.string() << ": " << dex::core::to_string(built.unwrap_err());
        const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

        auto reparsed = dex::core::readDex(
            dex::core::ByteSlice{rebuilt.data(), rebuilt.size()});
        ASSERT_TRUE(reparsed.is_ok())
            << path.string() << ": " << dex::core::to_string(reparsed.unwrap_err());
        std::unique_ptr<dex::core::DexFile> second = std::move(reparsed).unwrap();

        EXPECT_EQ(second->state(), dex::core::ParseState::Validated) << path.string();
        const dex::core::Integrity integrity = dex::core::verifyIntegrity(
            second->source(), second->header.checksum, second->header.signature);
        EXPECT_TRUE(integrity.checksumOk) << path.string();
        EXPECT_TRUE(integrity.signatureOk) << path.string();
        EXPECT_EQ(second->fieldCount(), file->fieldCount()) << path.string();
        EXPECT_EQ(second->methodCount(), file->methodCount()) << path.string();
        EXPECT_EQ(second->classCount(), file->classCount()) << path.string();

        ca::u32 secondTarget = dex::core::DexFile::kNoIndex;
        for (ca::u32 classIdx = 0; classIdx < second->classCount(); ++classIdx) {
            const auto descriptor = second->classDescriptor(classIdx);
            ASSERT_TRUE(descriptor.is_ok());
            if (descriptor.unwrap().as_std_view() == targetName) {
                secondTarget = classIdx;
                break;
            }
        }
        ASSERT_NE(secondTarget, dex::core::DexFile::kNoIndex) << path.string();

        const auto secondData = second->classData(secondTarget);
        ASSERT_TRUE(secondData.is_ok());
        ASSERT_NE(secondData.unwrap(), nullptr) << path.string();

        const std::vector<dex::core::EncodedMethod>* methodLists[2] = {
            &secondData.unwrap()->directMethods,
            &secondData.unwrap()->virtualMethods,
        };
        for (const std::vector<dex::core::EncodedMethod>* list : methodLists) {
            for (const dex::core::EncodedMethod& method : *list) {
                EXPECT_NE(method.methodIndex, removedMethod) << path.string();
            }
        }
        if (removedField != dex::core::DexFile::kNoIndex) {
            const std::vector<dex::core::EncodedField>* fieldLists[2] = {
                &secondData.unwrap()->staticFields,
                &secondData.unwrap()->instanceFields,
            };
            for (const std::vector<dex::core::EncodedField>* list : fieldLists) {
                for (const dex::core::EncodedField& field : *list) {
                    EXPECT_NE(field.fieldIndex, removedField) << path.string();
                }
            }
        }

        // static_values 与 static_fields 必须保持同长。
        const auto values = second->staticValues(secondTarget);
        ASSERT_TRUE(values.is_ok()) << path.string();
        if (values.unwrap() != nullptr) {
            EXPECT_EQ(values.unwrap()->values.size(),
                      secondData.unwrap()->staticFields.size())
                << path.string();
        }

        dex::core::BuildOptions plain;
        plain.keepUnknownSections = false;
        auto builtAgain = dex::core::buildDex(*second, plain);
        ASSERT_TRUE(builtAgain.is_ok())
            << path.string() << ": " << dex::core::to_string(builtAgain.unwrap_err());
        EXPECT_EQ(builtAgain.unwrap(), rebuilt) << path.string();
    }
}

TEST(DexRealCorpus, RebuildsAfterAddingMembers)
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

        ca::u32 target = dex::core::DexFile::kNoIndex;
        for (ca::u32 classIdx = 0; classIdx < file->classCount(); ++classIdx) {
            const auto data = file->classData(classIdx);
            ASSERT_TRUE(data.is_ok()) << path.string() << " class " << classIdx;
            if (data.unwrap() != nullptr) {
                target = classIdx;
                break;
            }
        }
        if (target == dex::core::DexFile::kNoIndex) {
            continue;
        }

        ca::u32 voidType = dex::core::DexFile::kNoIndex;
        for (ca::u32 typeIdx = 0; typeIdx < file->typeCount(); ++typeIdx) {
            const auto descriptor = file->typeDescriptor(typeIdx);
            ASSERT_TRUE(descriptor.is_ok());
            if (descriptor.unwrap().as_std_view() == "V") {
                voidType = typeIdx;
                break;
            }
        }
        ASSERT_NE(voidType, dex::core::DexFile::kNoIndex) << path.string();

        ca::u32 voidProto = dex::core::DexFile::kNoIndex;
        for (ca::u32 protoIdx = 0; protoIdx < file->protoCount(); ++protoIdx) {
            if (file->protoIds[protoIdx].returnTypeIdx == voidType &&
                file->protoIds[protoIdx].parametersOff == 0) {
                voidProto = protoIdx;
                break;
            }
        }
        if (voidProto == dex::core::DexFile::kNoIndex) {
            const auto addedProto = file->addProto(file->typeIds[voidType].descriptorIdx,
                                                   voidType, 0);
            ASSERT_TRUE(addedProto.is_ok()) << path.string();
            voidProto = addedProto.unwrap();
        }

        const ca::u32 classType = file->classDefs[target].classIdx;
        const auto fieldName = file->internUtf8("!addedField!");
        ASSERT_TRUE(fieldName.is_ok()) << path.string();
        const auto methodName = file->internUtf8("!addedMethod!");
        ASSERT_TRUE(methodName.is_ok()) << path.string();

        const auto fieldIdx = file->addField(classType, classType, fieldName.unwrap());
        ASSERT_TRUE(fieldIdx.is_ok()) << path.string();
        const auto methodIdx = file->addMethod(classType, voidProto, methodName.unwrap());
        ASSERT_TRUE(methodIdx.is_ok()) << path.string();

        dex::core::FieldAddition field;
        field.classDefIdx = target;
        field.fieldIdx = fieldIdx.unwrap();
        field.accessFlags = 0x1;  // public instance，避免动 static_values 槽位

        dex::core::MethodAddition method;
        method.classDefIdx = target;
        method.methodIdx = methodIdx.unwrap();
        method.accessFlags = 0x9;  // public static
        method.item.insnsSize = 1;
        method.insns = {0x0e, 0x00};  // return-void

        dex::core::BuildOptions options;
        options.keepUnknownSections = false;
        options.fieldAdditions.push_back(field);
        options.methodAdditions.push_back(method);

        auto built = dex::core::buildDex(*file, options);
        ASSERT_TRUE(built.is_ok())
            << path.string() << ": " << dex::core::to_string(built.unwrap_err());
        const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

        auto reparsed = dex::core::readDex(
            dex::core::ByteSlice{rebuilt.data(), rebuilt.size()});
        ASSERT_TRUE(reparsed.is_ok())
            << path.string() << ": " << dex::core::to_string(reparsed.unwrap_err());
        std::unique_ptr<dex::core::DexFile> second = std::move(reparsed).unwrap();

        EXPECT_EQ(second->state(), dex::core::ParseState::Validated) << path.string();
        const dex::core::Integrity integrity = dex::core::verifyIntegrity(
            second->source(), second->header.checksum, second->header.signature);
        EXPECT_TRUE(integrity.checksumOk) << path.string();
        EXPECT_TRUE(integrity.signatureOk) << path.string();
        EXPECT_EQ(second->classCount(), file->classCount()) << path.string();
        EXPECT_EQ(second->fieldCount(), file->fieldCount()) << path.string();
        EXPECT_EQ(second->methodCount(), file->methodCount()) << path.string();

        const auto targetDescriptor = file->classDescriptor(target);
        ASSERT_TRUE(targetDescriptor.is_ok()) << path.string();
        const std::string targetName(targetDescriptor.unwrap().as_std_view());
        ca::u32 secondTarget = dex::core::DexFile::kNoIndex;
        for (ca::u32 classIdx = 0; classIdx < second->classCount(); ++classIdx) {
            const auto descriptor = second->classDescriptor(classIdx);
            ASSERT_TRUE(descriptor.is_ok());
            if (descriptor.unwrap().as_std_view() == targetName) {
                secondTarget = classIdx;
                break;
            }
        }
        ASSERT_NE(secondTarget, dex::core::DexFile::kNoIndex) << path.string();

        const auto data = second->classData(secondTarget);
        ASSERT_TRUE(data.is_ok()) << path.string();
        ASSERT_NE(data.unwrap(), nullptr) << path.string();

        ca::u32 methodHits = 0;
        const std::vector<dex::core::EncodedMethod>* methodLists[2] = {
            &data.unwrap()->directMethods,
            &data.unwrap()->virtualMethods,
        };
        for (const std::vector<dex::core::EncodedMethod>* list : methodLists) {
            for (const dex::core::EncodedMethod& item : *list) {
                const auto name = second->methodName(item.methodIndex);
                ASSERT_TRUE(name.is_ok());
                if (name.unwrap().as_std_view() != "!addedMethod!") {
                    continue;
                }
                ++methodHits;
                const auto code = second->codeItem(item.codeOff);
                ASSERT_TRUE(code.is_ok());
                ASSERT_NE(code.unwrap(), nullptr);
                const dex::core::ByteSlice insns = dex::core::subOrEmpty(
                    second->source(), code.unwrap()->insns.offset,
                    code.unwrap()->insns.length);
                const auto decoded = dex::core::decodeInsns(insns);
                ASSERT_TRUE(decoded.is_ok());
                ASSERT_EQ(decoded.unwrap().size(), 1u);
                EXPECT_EQ(decoded.unwrap()[0].opcode, 0x0e);
            }
        }
        EXPECT_EQ(methodHits, 1u) << path.string();

        ca::u32 fieldHits = 0;
        const std::vector<dex::core::EncodedField>* fieldLists[2] = {
            &data.unwrap()->staticFields,
            &data.unwrap()->instanceFields,
        };
        for (const std::vector<dex::core::EncodedField>* list : fieldLists) {
            for (const dex::core::EncodedField& item : *list) {
                const auto name = second->fieldName(item.fieldIndex);
                ASSERT_TRUE(name.is_ok());
                if (name.unwrap().as_std_view() == "!addedField!") {
                    ++fieldHits;
                }
            }
        }
        EXPECT_EQ(fieldHits, 1u) << path.string();

        dex::core::BuildOptions plain;
        plain.keepUnknownSections = false;
        auto builtAgain = dex::core::buildDex(*second, plain);
        ASSERT_TRUE(builtAgain.is_ok())
            << path.string() << ": " << dex::core::to_string(builtAgain.unwrap_err());
        EXPECT_EQ(builtAgain.unwrap(), rebuilt) << path.string();
    }
}

TEST(DexRealCorpus, RebuildsAfterTypeRenames)
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

        // 全表改名：type/proto/field/method/class_defs 与指令、调试信息、
        // 注解、静态初值里的 type 索引都要跟着重排。
        for (ca::u32 typeIdx = 0; typeIdx < file->typeCount(); ++typeIdx) {
            std::string descriptor = "L!retyped!";
            descriptor.append(std::to_string(typeIdx));
            descriptor.push_back(';');
            const auto interned = file->internUtf8(descriptor);
            ASSERT_TRUE(interned.is_ok())
                << path.string() << " type " << typeIdx << ": "
                << dex::core::to_string(interned.unwrap_err());
            file->typeIds[typeIdx].descriptorIdx = interned.unwrap();
        }

        dex::core::BuildOptions options;
        options.keepUnknownSections = false;
        auto built = dex::core::buildDex(*file, options);
        ASSERT_TRUE(built.is_ok())
            << path.string() << ": " << dex::core::to_string(built.unwrap_err());
        const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

        auto reparsed = dex::core::readDex(
            dex::core::ByteSlice{rebuilt.data(), rebuilt.size()});
        ASSERT_TRUE(reparsed.is_ok())
            << path.string() << ": " << dex::core::to_string(reparsed.unwrap_err());
        std::unique_ptr<dex::core::DexFile> second = std::move(reparsed).unwrap();

        EXPECT_EQ(second->state(), dex::core::ParseState::Validated) << path.string();
        const dex::core::Integrity integrity = dex::core::verifyIntegrity(
            second->source(), second->header.checksum, second->header.signature);
        EXPECT_TRUE(integrity.checksumOk) << path.string();
        EXPECT_TRUE(integrity.signatureOk) << path.string();
        EXPECT_EQ(second->typeCount(), file->typeCount()) << path.string();
        EXPECT_EQ(second->protoCount(), file->protoCount()) << path.string();
        EXPECT_EQ(second->fieldCount(), file->fieldCount()) << path.string();
        EXPECT_EQ(second->methodCount(), file->methodCount()) << path.string();
        EXPECT_EQ(second->classCount(), file->classCount()) << path.string();

        std::unordered_set<std::string> seenTypes;
        for (ca::u32 typeIdx = 0; typeIdx < second->typeCount(); ++typeIdx) {
            const auto descriptor = second->typeDescriptor(typeIdx);
            ASSERT_TRUE(descriptor.is_ok()) << path.string() << " type " << typeIdx;
            const std::string name(descriptor.unwrap().as_std_view());
            EXPECT_EQ(name.rfind("L!retyped!", 0), 0u) << path.string() << " type " << typeIdx;
            EXPECT_TRUE(seenTypes.insert(name).second) << path.string() << " type " << typeIdx;
        }
        EXPECT_EQ(seenTypes.size(), second->typeCount()) << path.string();

        for (ca::u32 classIdx = 0; classIdx < second->classCount(); ++classIdx) {
            const auto descriptor = second->classDescriptor(classIdx);
            ASSERT_TRUE(descriptor.is_ok()) << path.string() << " class " << classIdx;
            EXPECT_EQ(std::string(descriptor.unwrap().as_std_view()).rfind("L!retyped!", 0), 0u)
                << path.string() << " class " << classIdx;
            const ca::u32 superIdx = second->classDefs[classIdx].superclassIdx;
            if (superIdx != dex::core::DexFile::kNoIndex) {
                EXPECT_LT(superIdx, second->typeCount()) << path.string();
            }
        }

        for (ca::u32 classIdx = 0; classIdx < second->classCount(); ++classIdx) {
            const auto data = second->classData(classIdx);
            ASSERT_TRUE(data.is_ok()) << path.string() << " class " << classIdx;
            if (data.unwrap() == nullptr) {
                continue;
            }

            const std::vector<dex::core::EncodedMethod>* methodLists[2] = {
                &data.unwrap()->directMethods,
                &data.unwrap()->virtualMethods,
            };
            for (const std::vector<dex::core::EncodedMethod>* list : methodLists) {
                for (const dex::core::EncodedMethod& method : *list) {
                    if (method.codeOff == 0) {
                        continue;
                    }
                    const auto code = second->codeItem(method.codeOff);
                    ASSERT_TRUE(code.is_ok()) << path.string() << " method " << method.methodIndex;
                    ASSERT_NE(code.unwrap(), nullptr);

                    for (const dex::core::TryBlock& block : code.unwrap()->tryBlocks) {
                        ASSERT_LT(block.handlerIndex, code.unwrap()->catchHandlers.size())
                            << path.string() << " method " << method.methodIndex;
                    }
                    for (const dex::core::CatchHandler& handler :
                         code.unwrap()->catchHandlers) {
                        for (const dex::core::TypedCatch& typed : handler.typed) {
                            EXPECT_LT(typed.typeIdx, second->typeCount())
                                << path.string() << " method " << method.methodIndex;
                        }
                    }

                    const dex::core::ByteSlice insns = dex::core::subOrEmpty(
                        second->source(), code.unwrap()->insns.offset,
                        code.unwrap()->insns.length);
                    const auto decoded = dex::core::decodeInsns(insns);
                    ASSERT_TRUE(decoded.is_ok()) << path.string() << " method "
                                                 << method.methodIndex;
                    for (const dex::core::Insn& insn : decoded.unwrap()) {
                        if (insn.indexKind == dex::core::IndexKind::Type) {
                            EXPECT_LT(insn.index, second->typeCount())
                                << path.string() << " method " << method.methodIndex;
                        }
                    }
                }
            }
        }

        auto builtAgain = dex::core::buildDex(*second, options);
        ASSERT_TRUE(builtAgain.is_ok())
            << path.string() << ": " << dex::core::to_string(builtAgain.unwrap_err());
        EXPECT_EQ(builtAgain.unwrap(), rebuilt) << path.string();
    }
}
