/// @file        builder_test.cpp
/// @brief       整文件 canonical 重建：布局固定点、透传区段、方法体替换与错误面。
#include <cstring>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "jstr/conversion.hpp"

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

namespace {

std::unique_ptr<DexFile> readFixture(const std::vector<ca::u8>& bytes)
{
    auto parsed = readDex(dex_test::asSlice(bytes));
    EXPECT_TRUE(parsed.is_ok());
    return std::move(parsed).unwrap();
}

ByteSlice insnsOf(DexFile& file, ca::u32 classIdx, ca::usize methodSlot)
{
    const auto data = file.classData(classIdx);
    if (data.is_err() || data.unwrap() == nullptr) {
        return ByteSlice{};
    }
    const EncodedMethod& method = data.unwrap()->directMethods[methodSlot];
    const auto code = file.codeItem(method.codeOff);
    if (code.is_err() || code.unwrap() == nullptr) {
        return ByteSlice{};
    }
    return subOrEmpty(file.source(), code.unwrap()->insns.offset,
                      code.unwrap()->insns.length);
}

}   // namespace

TEST(DexBuilder, RebuildsFixtureAsFixedPoint)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    std::unique_ptr<DexFile> file = readFixture(bytes);
    ASSERT_NE(file, nullptr);

    const ByteSlice originalInsns = insnsOf(*file, 0, 0);
    ASSERT_FALSE(originalInsns.empty());

    auto built = buildDex(*file);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    EXPECT_EQ(second->state(), ParseState::Validated);
    EXPECT_TRUE(second->diagnostics().empty());
    EXPECT_EQ(second->header.version, 35);
    EXPECT_EQ(second->stringCount(), 7u);
    EXPECT_EQ(second->typeCount(), 4u);
    EXPECT_EQ(second->protoCount(), 2u);
    EXPECT_EQ(second->fieldCount(), 1u);
    EXPECT_EQ(second->methodCount(), 1u);
    EXPECT_EQ(second->classCount(), 1u);
    EXPECT_EQ(second->callSiteCount(), 1u);
    EXPECT_EQ(second->methodHandleCount(), 1u);
    EXPECT_EQ(second->header.dataOff + second->header.dataSize, second->header.fileSize);

    const MapItem* stringData = second->findMapItem(MapType::StringDataItem);
    ASSERT_NE(stringData, nullptr);
    EXPECT_EQ(second->header.dataOff, stringData->offset);

    const Integrity integrity = verifyIntegrity(
        second->source(), second->header.checksum, second->header.signature);
    EXPECT_TRUE(integrity.checksumOk);
    EXPECT_TRUE(integrity.signatureOk);

    const ByteSlice rebuiltInsns = insnsOf(*second, 0, 0);
    ASSERT_EQ(rebuiltInsns.size(), originalInsns.size());
    EXPECT_EQ(std::memcmp(rebuiltInsns.data(), originalInsns.data(), originalInsns.size()), 0);

    const auto descriptor = second->classDescriptor(0);
    ASSERT_TRUE(descriptor.is_ok());
    EXPECT_EQ(descriptor.unwrap().as_std_view(), "LHello;");

    // 重建产物再重建必须逐字节稳定。
    auto builtAgain = buildDex(*second);
    ASSERT_TRUE(builtAgain.is_ok()) << to_string(builtAgain.unwrap_err());
    EXPECT_EQ(builtAgain.unwrap(), rebuilt);
}

TEST(DexBuilder, MapOffsetsAreAscending)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    std::unique_ptr<DexFile> file = readFixture(bytes);
    ASSERT_NE(file, nullptr);

    auto built = buildDex(*file);
    ASSERT_TRUE(built.is_ok());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    ASSERT_FALSE(second->mapItems.empty());
    EXPECT_EQ(second->mapItems.front().type, MapType::HeaderItem);
    EXPECT_EQ(second->mapItems.front().offset, 0u);
    EXPECT_EQ(second->mapItems.back().type, MapType::MapList);
    EXPECT_EQ(second->mapItems.back().offset, second->header.mapOff);

    for (ca::usize i = 1; i < second->mapItems.size(); ++i) {
        EXPECT_LT(second->mapItems[i - 1].offset, second->mapItems[i].offset);
    }
    for (const MapItem& item : second->mapItems) {
        EXPECT_LE(item.offset, second->header.fileSize);
    }
}

TEST(DexBuilder, PreservesUnknownSections)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    std::unique_ptr<DexFile> file = readFixture(bytes);
    ASSERT_NE(file, nullptr);

    auto built = buildDex(*file);
    ASSERT_TRUE(built.is_ok());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    const MapItem* raw = second->findMapItem(static_cast<MapType>(0x7F00));
    ASSERT_NE(raw, nullptr);
    ASSERT_EQ(second->rawSections.size(), 1u);
    EXPECT_EQ(second->rawSections[0].type, 0x7F00);
    EXPECT_EQ(second->rawSections[0].size, 1u);

    const ByteSlice span = subOrEmpty(second->source(), second->rawSections[0].span.offset,
                                      second->rawSections[0].span.length);
    ASSERT_GE(span.size(), 4u);
    EXPECT_EQ(span[0], 0xDE);
    EXPECT_EQ(span[1], 0xAD);
    EXPECT_EQ(span[2], 0xBE);
    EXPECT_EQ(span[3], 0xEF);

    BuildOptions options;
    options.keepUnknownSections = false;
    auto dropped = buildDex(*file, options);
    ASSERT_TRUE(dropped.is_ok());
    auto droppedParsed = readDex(dex_test::asSlice(dropped.unwrap()));
    ASSERT_TRUE(droppedParsed.is_ok());
    std::unique_ptr<DexFile> third = std::move(droppedParsed).unwrap();

    EXPECT_EQ(third->findMapItem(static_cast<MapType>(0x7F00)), nullptr);
    EXPECT_TRUE(third->rawSections.empty());
    EXPECT_EQ(third->stringCount(), 7u);
}

TEST(DexBuilder, ReplacesMethodBody)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    std::unique_ptr<DexFile> file = readFixture(bytes);
    ASSERT_NE(file, nullptr);

    const auto data = file->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    const EncodedMethod& method = data.unwrap()->directMethods[0];
    const auto code = file->codeItem(method.codeOff);
    ASSERT_TRUE(code.is_ok());
    ASSERT_NE(code.unwrap(), nullptr);
    const ca::u32 oldDebugOff = code.unwrap()->debugInfoOff;
    ASSERT_NE(oldDebugOff, 0u);

    BuildOptions options;
    CodeReplacement replacement;
    replacement.methodIdx = method.methodIndex;
    replacement.item = *code.unwrap();
    replacement.item.insnsSize = 2;
    replacement.item.triesSize = 0;
    replacement.item.tryBlocks.clear();
    replacement.item.catchHandlers.clear();
    replacement.item.debugInfoOff = oldDebugOff;  // 源文件偏移，重建时重映射
    replacement.insns = {0x12, 0x10, 0x0e, 0x00};  // const/4 v0,#1; return-void
    options.codeReplacements.push_back(replacement);

    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    EXPECT_EQ(second->state(), ParseState::Validated);

    const auto newData = second->classData(0);
    ASSERT_TRUE(newData.is_ok());
    ASSERT_NE(newData.unwrap(), nullptr);
    const EncodedMethod& newMethod = newData.unwrap()->directMethods[0];
    EXPECT_EQ(newMethod.methodIndex, method.methodIndex);
    EXPECT_EQ(newMethod.accessFlags, method.accessFlags);
    ASSERT_NE(newMethod.codeOff, 0u);

    const auto newCode = second->codeItem(newMethod.codeOff);
    ASSERT_TRUE(newCode.is_ok());
    ASSERT_NE(newCode.unwrap(), nullptr);
    EXPECT_EQ(newCode.unwrap()->insnsSize, 2u);
    EXPECT_NE(newCode.unwrap()->debugInfoOff, 0u);

    const ByteSlice insns = subOrEmpty(second->source(), newCode.unwrap()->insns.offset,
                                       newCode.unwrap()->insns.length);
    ASSERT_EQ(insns.size(), 4u);
    EXPECT_EQ(std::memcmp(insns.data(), replacement.insns.data(), 4), 0);

    const auto decoded = decodeInsns(insns);
    ASSERT_TRUE(decoded.is_ok());
    ASSERT_EQ(decoded.unwrap().size(), 2u);
    EXPECT_EQ(decoded.unwrap()[0].opcode, 0x12);
    EXPECT_EQ(decoded.unwrap()[0].registers[0], 0u);
    EXPECT_EQ(decoded.unwrap()[0].literal, 1);
    EXPECT_EQ(decoded.unwrap()[1].opcode, 0x0e);

    const auto debug = second->debugInfo(newCode.unwrap()->debugInfoOff);
    ASSERT_TRUE(debug.is_ok());
    EXPECT_NE(debug.unwrap(), nullptr);
}

TEST(DexBuilder, RejectsUnknownOrDuplicateReplacement)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    std::unique_ptr<DexFile> file = readFixture(bytes);
    ASSERT_NE(file, nullptr);

    BuildOptions unknown;
    CodeReplacement replacement;
    replacement.methodIdx = 99;
    replacement.item.insnsSize = 1;
    replacement.insns = {0x0e, 0x00};
    unknown.codeReplacements.push_back(replacement);
    const auto unknownResult = buildDex(*file, unknown);
    ASSERT_TRUE(unknownResult.is_err());
    EXPECT_EQ(unknownResult.unwrap_err(), WriteError::InvalidModel);

    BuildOptions duplicated;
    replacement.methodIdx = 0;
    duplicated.codeReplacements.push_back(replacement);
    duplicated.codeReplacements.push_back(replacement);
    const auto duplicatedResult = buildDex(*file, duplicated);
    ASSERT_TRUE(duplicatedResult.is_err());
    EXPECT_EQ(duplicatedResult.unwrap_err(), WriteError::InvalidModel);

    BuildOptions wrongSize;
    replacement.item.insnsSize = 2;
    wrongSize.codeReplacements.push_back(replacement);
    const auto wrongSizeResult = buildDex(*file, wrongSize);
    ASSERT_TRUE(wrongSizeResult.is_err());
    EXPECT_EQ(wrongSizeResult.unwrap_err(), WriteError::Unencodable);
}

TEST(DexBuilder, RejectsUnfrozenStructures)
{
    DexFile empty;
    const auto noSource = buildDex(empty);
    ASSERT_TRUE(noSource.is_err());
    EXPECT_EQ(noSource.unwrap_err(), WriteError::MissingSource);

    std::vector<ca::u8> v41 = dex_test::makeHelloDex();
    v41[4] = '0';
    v41[5] = '4';
    v41[6] = '1';
    auto parsed41 = readDex(dex_test::asSlice(v41));
    ASSERT_TRUE(parsed41.is_ok());
    std::unique_ptr<DexFile> file41 = std::move(parsed41).unwrap();
    const auto built41 = buildDex(*file41);
    ASSERT_TRUE(built41.is_err());
    EXPECT_EQ(built41.unwrap_err(), WriteError::NotModeled);

    std::vector<ca::u8> linked = dex_test::makeHelloDex();
    dex_test::patchU32(linked, 44, 4);  // link_size
    auto parsedLink = readDex(dex_test::asSlice(linked));
    ASSERT_TRUE(parsedLink.is_ok());
    std::unique_ptr<DexFile> fileLink = std::move(parsedLink).unwrap();
    const auto builtLink = buildDex(*fileLink);
    ASSERT_TRUE(builtLink.is_err());
    EXPECT_EQ(builtLink.unwrap_err(), WriteError::NotModeled);
}

TEST(DexBuilder, RebuildsSortedStringPoolAfterIntern)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    const auto added = file->internUtf8("Hello2.java");
    ASSERT_TRUE(added.is_ok());
    file->classDefs[0].sourceFileIdx = added.unwrap();

    BuildOptions options;
    options.keepUnknownSections = false;
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    EXPECT_EQ(second->stringCount(), 8u);
    const auto sourceFile = second->sourceFile(0);
    ASSERT_TRUE(sourceFile.is_ok());
    EXPECT_EQ(sourceFile.unwrap().as_std_view(), "Hello2.java");

    for (ca::u32 i = 1; i < second->stringCount(); ++i) {
        const auto previous = second->string(i - 1);
        const auto current = second->string(i);
        ASSERT_TRUE(previous.is_ok());
        ASSERT_TRUE(current.is_ok());
        const auto previousUtf16 = jstr::mutf8_to_utf16(previous.unwrap());
        const auto currentUtf16 = jstr::mutf8_to_utf16(current.unwrap());
        ASSERT_TRUE(previousUtf16.is_ok());
        ASSERT_TRUE(currentUtf16.is_ok());
        EXPECT_LT(previousUtf16.unwrap(), currentUtf16.unwrap());
    }

    const auto descriptor = second->classDescriptor(0);
    ASSERT_TRUE(descriptor.is_ok());
    EXPECT_EQ(descriptor.unwrap().as_std_view(), "LHello;");
    const auto methodName = second->methodName(0);
    ASSERT_TRUE(methodName.is_ok());
    EXPECT_EQ(methodName.unwrap().as_std_view(), "foo");

    auto again = buildDex(*second, options);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, RemapsStringIndexInReplacementInsns)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);
    const auto added = file->internUtf8("Hello2.java");
    ASSERT_TRUE(added.is_ok());

    const auto data = file->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    const EncodedMethod& method = data.unwrap()->directMethods[0];
    const auto code = file->codeItem(method.codeOff);
    ASSERT_TRUE(code.is_ok());
    ASSERT_NE(code.unwrap(), nullptr);

    CodeReplacement replacement;
    replacement.methodIdx = method.methodIndex;
    replacement.item = *code.unwrap();
    replacement.item.registersSize = 1;
    replacement.item.insnsSize = 3;
    replacement.item.debugInfoOff = 0;
    replacement.item.triesSize = 0;
    replacement.item.tryBlocks.clear();
    replacement.item.catchHandlers.clear();
    // const-string v0, string@<new index> ; return-void
    replacement.insns = {0x1a, 0x00,
                         static_cast<ca::u8>(added.unwrap() & 0xFFu),
                         static_cast<ca::u8>(added.unwrap() >> 8), 0x0e, 0x00};

    BuildOptions options;
    options.keepUnknownSections = false;
    options.codeReplacements.push_back(replacement);

    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    const auto newData = second->classData(0);
    ASSERT_TRUE(newData.is_ok());
    ASSERT_NE(newData.unwrap(), nullptr);
    const EncodedMethod& newMethod = newData.unwrap()->directMethods[0];
    const auto newCode = second->codeItem(newMethod.codeOff);
    ASSERT_TRUE(newCode.is_ok());
    ASSERT_NE(newCode.unwrap(), nullptr);

    const ByteSlice insns = subOrEmpty(second->source(), newCode.unwrap()->insns.offset,
                                       newCode.unwrap()->insns.length);
    auto decoded = decodeInsns(insns);
    ASSERT_TRUE(decoded.is_ok());
    const std::vector<Insn> list = std::move(decoded).unwrap();
    ASSERT_EQ(list.size(), 2u);
    const Insn& load = list[0];
    EXPECT_EQ(load.opcode, 0x1a);
    EXPECT_EQ(load.indexKind, IndexKind::String);
    EXPECT_EQ(load.index, 1u);  // "Hello2.java" 排到 "I" 之前

    const auto text = second->string(load.index);
    ASSERT_TRUE(text.is_ok());
    EXPECT_EQ(text.unwrap().as_std_view(), "Hello2.java");
}

TEST(DexBuilder, ReordersMethodTableAfterRename)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    const auto zzz = file->internUtf8("zzz");
    ASSERT_TRUE(zzz.is_ok());
    file->methodIds.push_back(
        MethodId{file->methodIds[0].classIdx, file->methodIds[0].protoIdx, zzz.unwrap()});

    const auto data = file->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    const EncodedMethod& original = data.unwrap()->directMethods[0];
    const auto code = file->codeItem(original.codeOff);
    ASSERT_TRUE(code.is_ok());
    ASSERT_NE(code.unwrap(), nullptr);

    CodeReplacement replacement;
    replacement.methodIdx = original.methodIndex;
    replacement.item = *code.unwrap();
    replacement.item.insnsSize = 4;
    replacement.item.debugInfoOff = 0;
    replacement.item.triesSize = 0;
    replacement.item.tryBlocks.clear();
    replacement.item.catchHandlers.clear();
    // invoke-static {}, method@0 ; return-void
    replacement.insns = {0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00};

    const auto aaa = file->internUtf8("aaa");
    ASSERT_TRUE(aaa.is_ok());
    file->methodIds[1].nameIdx = aaa.unwrap();

    BuildOptions options;
    options.keepUnknownSections = false;
    options.codeReplacements.push_back(replacement);
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    const auto firstName = second->methodName(0);
    const auto secondName = second->methodName(1);
    ASSERT_TRUE(firstName.is_ok());
    ASSERT_TRUE(secondName.is_ok());
    EXPECT_EQ(firstName.unwrap().as_std_view(), "aaa");
    EXPECT_EQ(secondName.unwrap().as_std_view(), "foo");

    const auto newData = second->classData(0);
    ASSERT_TRUE(newData.is_ok());
    ASSERT_NE(newData.unwrap(), nullptr);
    const EncodedMethod& newMethod = newData.unwrap()->directMethods[0];
    EXPECT_EQ(newMethod.methodIndex, 1u);  // 旧 foo 排到 aaa 之后
    ASSERT_NE(newMethod.codeOff, 0u);

    const auto newCode = second->codeItem(newMethod.codeOff);
    ASSERT_TRUE(newCode.is_ok());
    ASSERT_NE(newCode.unwrap(), nullptr);
    const ByteSlice insns = subOrEmpty(second->source(), newCode.unwrap()->insns.offset,
                                       newCode.unwrap()->insns.length);
    auto decoded = decodeInsns(insns);
    ASSERT_TRUE(decoded.is_ok());
    const std::vector<Insn> list = std::move(decoded).unwrap();
    ASSERT_EQ(list.size(), 2u);
    EXPECT_EQ(list[0].opcode, 0x71);
    EXPECT_EQ(list[0].indexKind, IndexKind::Method);
    EXPECT_EQ(list[0].index, 1u);

    ASSERT_EQ(second->methodHandles.size(), 1u);
    EXPECT_EQ(second->methodHandles[0].targetIdx, 1u);
}

TEST(DexBuilder, ReordersFieldTableAndRemapsReferences)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    const auto zzz = file->internUtf8("zzz");
    ASSERT_TRUE(zzz.is_ok());
    FieldId extra = file->fieldIds[0];
    extra.nameIdx = zzz.unwrap();
    file->fieldIds.push_back(extra);

    const auto data = file->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    const EncodedMethod& original = data.unwrap()->directMethods[0];
    const auto code = file->codeItem(original.codeOff);
    ASSERT_TRUE(code.is_ok());
    ASSERT_NE(code.unwrap(), nullptr);

    CodeReplacement replacement;
    replacement.methodIdx = original.methodIndex;
    replacement.item = *code.unwrap();
    replacement.item.registersSize = 1;
    replacement.item.insnsSize = 3;
    replacement.item.debugInfoOff = 0;
    replacement.item.triesSize = 0;
    replacement.item.tryBlocks.clear();
    replacement.item.catchHandlers.clear();
    // sget-object v0, field@0 ; return-void
    replacement.insns = {0x62, 0x00, 0x00, 0x00, 0x0e, 0x00};

    const auto aaa = file->internUtf8("aaa");
    ASSERT_TRUE(aaa.is_ok());
    file->fieldIds[1].nameIdx = aaa.unwrap();

    BuildOptions options;
    options.keepUnknownSections = false;
    options.codeReplacements.push_back(replacement);
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    const auto firstName = second->fieldName(0);
    const auto secondName = second->fieldName(1);
    ASSERT_TRUE(firstName.is_ok());
    ASSERT_TRUE(secondName.is_ok());
    EXPECT_EQ(firstName.unwrap().as_std_view(), "aaa");
    EXPECT_EQ(secondName.unwrap().as_std_view(), "bar");

    const auto newData = second->classData(0);
    ASSERT_TRUE(newData.is_ok());
    ASSERT_NE(newData.unwrap(), nullptr);
    ASSERT_EQ(newData.unwrap()->instanceFields.size(), 1u);
    EXPECT_EQ(newData.unwrap()->instanceFields[0].fieldIndex, 1u);

    const EncodedMethod& newMethod = newData.unwrap()->directMethods[0];
    const auto newCode = second->codeItem(newMethod.codeOff);
    ASSERT_TRUE(newCode.is_ok());
    ASSERT_NE(newCode.unwrap(), nullptr);
    const ByteSlice insns = subOrEmpty(second->source(), newCode.unwrap()->insns.offset,
                                       newCode.unwrap()->insns.length);
    auto decoded = decodeInsns(insns);
    ASSERT_TRUE(decoded.is_ok());
    const std::vector<Insn> list = std::move(decoded).unwrap();
    ASSERT_EQ(list.size(), 2u);
    EXPECT_EQ(list[0].opcode, 0x62);
    EXPECT_EQ(list[0].indexKind, IndexKind::Field);
    EXPECT_EQ(list[0].index, 1u);
}

TEST(DexBuilder, ReordersTypeProtoAndClassTablesAfterDescriptorRename)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    // 把 I 改名为 Z：type_ids 重排，proto 返回类型顺序随之翻转，
    // field 的类型、class_def 的 class/superclass 索引全部要跟着改写。
    const auto zed = file->internUtf8("Z");
    ASSERT_TRUE(zed.is_ok());
    file->typeIds[0].descriptorIdx = zed.unwrap();

    BuildOptions options;
    options.keepUnknownSections = false;
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    EXPECT_EQ(second->state(), ParseState::Validated);

    const char* expectedTypes[] = {"LHello;", "Ljava/lang/Object;", "V", "Z"};
    ASSERT_EQ(second->typeCount(), 4u);
    for (ca::u32 i = 0; i < 4; ++i) {
        const auto descriptor = second->typeDescriptor(i);
        ASSERT_TRUE(descriptor.is_ok());
        EXPECT_EQ(descriptor.unwrap().as_std_view(), expectedTypes[i]);
    }

    ASSERT_EQ(second->protoCount(), 2u);
    EXPECT_EQ(second->protoIds[0].returnTypeIdx, 2u);  // ()V 排到前面
    EXPECT_EQ(second->protoIds[1].returnTypeIdx, 3u);  // ()Z
    ASSERT_EQ(second->methodCount(), 1u);
    EXPECT_EQ(second->methodIds[0].protoIdx, 0u);

    ASSERT_EQ(second->fieldCount(), 1u);
    EXPECT_EQ(second->fieldIds[0].classIdx, 0u);
    EXPECT_EQ(second->fieldIds[0].typeIdx, 3u);

    ASSERT_EQ(second->classCount(), 1u);
    EXPECT_EQ(second->classDefs[0].classIdx, 0u);
    EXPECT_EQ(second->classDefs[0].superclassIdx, 1u);

    // 表重排后的布局必须是固定点。
    auto again = buildDex(*second, options);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, RemapsTypeIndicesInInsnsAndCatchHandlers)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    const auto zed = file->internUtf8("Z");
    ASSERT_TRUE(zed.is_ok());
    file->typeIds[0].descriptorIdx = zed.unwrap();

    // const-class v0, type 1（LHello;）+ return-void；catch 也指向 LHello;。
    CodeReplacement replacement;
    replacement.methodIdx = 0;
    replacement.item.registersSize = 1;
    replacement.item.triesSize = 1;
    replacement.item.insnsSize = 3;
    replacement.item.tryBlocks.push_back(TryBlock{0, 2, 0, 0});
    CatchHandler handler;
    handler.typed.push_back(TypedCatch{1, 2});
    replacement.item.catchHandlers.push_back(std::move(handler));
    replacement.insns = {0x1c, 0x00, 0x01, 0x00, 0x0e, 0x00};

    BuildOptions options;
    options.keepUnknownSections = false;
    options.codeReplacements.push_back(std::move(replacement));
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());

    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    const auto data = second->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    ASSERT_EQ(data.unwrap()->directMethods.size(), 1u);
    const auto code = second->codeItem(data.unwrap()->directMethods[0].codeOff);
    ASSERT_TRUE(code.is_ok());
    ASSERT_NE(code.unwrap(), nullptr);

    const ByteSlice insns = subOrEmpty(second->source(), code.unwrap()->insns.offset,
                                       code.unwrap()->insns.length);
    auto decoded = decodeInsns(insns);
    ASSERT_TRUE(decoded.is_ok());
    const std::vector<Insn> list = std::move(decoded).unwrap();
    ASSERT_EQ(list.size(), 2u);
    EXPECT_EQ(list[0].opcode, 0x1c);
    EXPECT_EQ(list[0].indexKind, IndexKind::Type);
    EXPECT_EQ(list[0].index, 0u);  // LHello; 的新 type 索引
    EXPECT_EQ(list[1].opcode, 0x0e);

    ASSERT_EQ(code.unwrap()->catchHandlers.size(), 1u);
    ASSERT_EQ(code.unwrap()->catchHandlers[0].typed.size(), 1u);
    EXPECT_EQ(code.unwrap()->catchHandlers[0].typed[0].typeIdx, 0u);
}

TEST(DexBuilder, RejectsDuplicateTypeDescriptors)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    // type 0 改成与 type 3 相同的 V，type_ids 无法形成严格排序。
    file->typeIds[0].descriptorIdx = 4;

    BuildOptions options;
    options.keepUnknownSections = false;
    const auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_err());
    EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
}

TEST(DexBuilder, AddsAndReusesIdTableEntries)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    const auto sameType = file->addType("I");
    ASSERT_TRUE(sameType.is_ok());
    EXPECT_EQ(sameType.unwrap(), 0u);

    const auto stringType = file->addType("Ljava/lang/String;");
    ASSERT_TRUE(stringType.is_ok());
    EXPECT_EQ(stringType.unwrap(), 4u);
    const auto stringTypeAgain = file->addType("Ljava/lang/String;");
    ASSERT_TRUE(stringTypeAgain.is_ok());
    EXPECT_EQ(stringTypeAgain.unwrap(), stringType.unwrap());

    const auto sameProto = file->addProto(1, 0, 0);  // ()I
    ASSERT_TRUE(sameProto.is_ok());
    EXPECT_EQ(sameProto.unwrap(), 0u);
    const auto objectShorty = file->internUtf8("L");
    ASSERT_TRUE(objectShorty.is_ok());
    const auto stringProto = file->addProto(objectShorty.unwrap(), stringType.unwrap(), 0);
    ASSERT_TRUE(stringProto.is_ok());
    EXPECT_EQ(stringProto.unwrap(), 2u);

    const auto name = file->internUtf8("baz");
    ASSERT_TRUE(name.is_ok());
    const auto field = file->addField(stringType.unwrap(), stringType.unwrap(), name.unwrap());
    ASSERT_TRUE(field.is_ok());
    EXPECT_EQ(field.unwrap(), 1u);
    const auto fieldAgain =
        file->addField(stringType.unwrap(), stringType.unwrap(), name.unwrap());
    ASSERT_TRUE(fieldAgain.is_ok());
    EXPECT_EQ(fieldAgain.unwrap(), field.unwrap());

    const auto method = file->addMethod(stringType.unwrap(), stringProto.unwrap(), name.unwrap());
    ASSERT_TRUE(method.is_ok());
    EXPECT_EQ(method.unwrap(), 1u);

    BuildOptions options;
    options.keepUnknownSections = false;
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    EXPECT_EQ(second->typeCount(), 5u);
    EXPECT_EQ(second->protoCount(), 3u);
    EXPECT_EQ(second->fieldCount(), 2u);
    EXPECT_EQ(second->methodCount(), 2u);

    const auto newType = second->typeDescriptor(3);
    ASSERT_TRUE(newType.is_ok());
    EXPECT_EQ(newType.unwrap().as_std_view(), "Ljava/lang/String;");
    EXPECT_EQ(second->protoIds[1].returnTypeIdx, 3u);

    ASSERT_EQ(second->fieldCount(), 2u);
    EXPECT_EQ(second->fieldName(1).unwrap().as_std_view(), "baz");
    EXPECT_EQ(second->fieldClassDescriptor(1).unwrap().as_std_view(),
              "Ljava/lang/String;");
    EXPECT_EQ(second->fieldTypeDescriptor(1).unwrap().as_std_view(),
              "Ljava/lang/String;");

    ASSERT_EQ(second->methodCount(), 2u);
    EXPECT_EQ(second->methodName(1).unwrap().as_std_view(), "baz");
    EXPECT_EQ(second->methodClassDescriptor(1).unwrap().as_std_view(),
              "Ljava/lang/String;");
    EXPECT_EQ(second->methodIds[1].protoIdx, 1u);

    auto again = buildDex(*second, options);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, RejectsDanglingIdTableAdds)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    const auto badProtoShorty = file->addProto(99, 0, 0);
    ASSERT_TRUE(badProtoShorty.is_err());
    EXPECT_EQ(badProtoShorty.unwrap_err(), ReadError::BadIndex);

    const auto badProtoReturn = file->addProto(1, 99, 0);
    ASSERT_TRUE(badProtoReturn.is_err());
    EXPECT_EQ(badProtoReturn.unwrap_err(), ReadError::BadIndex);

    const auto badTypeList = file->addProto(1, 0, 0xFFFFFFF0u);
    ASSERT_TRUE(badTypeList.is_err());
    EXPECT_EQ(badTypeList.unwrap_err(), ReadError::BadTableSpan);

    const auto badFieldClass = file->addField(99, 0, 5);
    ASSERT_TRUE(badFieldClass.is_err());
    EXPECT_EQ(badFieldClass.unwrap_err(), ReadError::BadIndex);

    const auto badFieldName = file->addField(0, 0, 99);
    ASSERT_TRUE(badFieldName.is_err());
    EXPECT_EQ(badFieldName.unwrap_err(), ReadError::BadIndex);

    const auto badMethodProto = file->addMethod(0, 99, 5);
    ASSERT_TRUE(badMethodProto.is_err());
    EXPECT_EQ(badMethodProto.unwrap_err(), ReadError::BadIndex);
}

TEST(DexBuilder, RejectsIdTableAddsAtCapacity)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    file->fieldIds.resize(DexFile::kIdTableLimit);
    const auto added = file->addField(1, 1, 1);
    ASSERT_TRUE(added.is_err());
    EXPECT_EQ(added.unwrap_err(), ReadError::IdTableFull);
}

TEST(DexBuilder, AddsClassMembersAndCodeItems)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    const auto name = file->internUtf8("gen");
    ASSERT_TRUE(name.is_ok());
    const auto stringType = file->addType("Ljava/lang/String;");
    ASSERT_TRUE(stringType.is_ok());
    const auto fieldIdx = file->addField(1, stringType.unwrap(), name.unwrap());
    ASSERT_TRUE(fieldIdx.is_ok());
    const auto methodIdx = file->addMethod(1, 1, name.unwrap());
    ASSERT_TRUE(methodIdx.is_ok());

    FieldAddition field;
    field.classDefIdx = 0;
    field.fieldIdx = fieldIdx.unwrap();
    field.accessFlags = 0x1;  // public instance

    MethodAddition method;
    method.classDefIdx = 0;
    method.methodIdx = methodIdx.unwrap();
    method.accessFlags = 0x9;  // public static -> direct
    method.item.registersSize = 1;
    method.item.insnsSize = 3;
    // const-class v0, Ljava/lang/String; + return-void
    method.insns = {0x1c, 0x00, static_cast<ca::u8>(stringType.unwrap() & 0xFFu),
                    static_cast<ca::u8>(stringType.unwrap() >> 8), 0x0e, 0x00};

    BuildOptions options;
    options.keepUnknownSections = false;
    options.fieldAdditions.push_back(field);
    options.methodAdditions.push_back(method);

    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    EXPECT_EQ(second->state(), ParseState::Validated);

    const auto data = second->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    EXPECT_EQ(data.unwrap()->staticFields.size(), 0u);
    ASSERT_EQ(data.unwrap()->instanceFields.size(), 2u);
    ASSERT_EQ(data.unwrap()->directMethods.size(), 2u);
    EXPECT_EQ(data.unwrap()->virtualMethods.size(), 0u);

    ca::u32 fieldHits = 0;
    for (const EncodedField& addedField : data.unwrap()->instanceFields) {
        const auto addedName = second->fieldName(addedField.fieldIndex);
        ASSERT_TRUE(addedName.is_ok());
        if (addedName.unwrap().as_std_view() != "gen") {
            continue;
        }
        ++fieldHits;
        EXPECT_EQ(second->fieldTypeDescriptor(addedField.fieldIndex).unwrap().as_std_view(),
                  "Ljava/lang/String;");
        EXPECT_EQ(addedField.accessFlags, 0x1u);
    }
    EXPECT_EQ(fieldHits, 1u);

    ca::u32 found = 0;
    for (const EncodedMethod& added : data.unwrap()->directMethods) {
        const auto addedName = second->methodName(added.methodIndex);
        ASSERT_TRUE(addedName.is_ok());
        if (addedName.unwrap().as_std_view() == "gen") {
            ++found;
            EXPECT_EQ(added.accessFlags, 0x9u);
            const auto code = second->codeItem(added.codeOff);
            ASSERT_TRUE(code.is_ok());
            ASSERT_NE(code.unwrap(), nullptr);
            EXPECT_EQ(code.unwrap()->registersSize, 1u);
            const ByteSlice insns = subOrEmpty(second->source(), code.unwrap()->insns.offset,
                                               code.unwrap()->insns.length);
            auto decoded = decodeInsns(insns);
            ASSERT_TRUE(decoded.is_ok());
            const std::vector<Insn> list = std::move(decoded).unwrap();
            ASSERT_EQ(list.size(), 2u);
            EXPECT_EQ(list[0].opcode, 0x1c);
            EXPECT_EQ(list[0].indexKind, IndexKind::Type);
            const auto referenced = second->typeDescriptor(list[0].index);
            ASSERT_TRUE(referenced.is_ok());
            EXPECT_EQ(referenced.unwrap().as_std_view(), "Ljava/lang/String;");
            EXPECT_EQ(list[1].opcode, 0x0e);
        }
    }
    EXPECT_EQ(found, 1u);

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, AddsMembersToClassWithoutClassData)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);
    file->classDefs[0].classDataOff = 0;
    file->classDefs[0].staticValuesOff = 0;

    const auto name = file->internUtf8("gen");
    ASSERT_TRUE(name.is_ok());
    const auto fieldIdx = file->addField(1, 0, name.unwrap());
    ASSERT_TRUE(fieldIdx.is_ok());
    const auto methodIdx = file->addMethod(1, 1, name.unwrap());
    ASSERT_TRUE(methodIdx.is_ok());

    FieldAddition field;
    field.classDefIdx = 0;
    field.fieldIdx = fieldIdx.unwrap();
    field.accessFlags = 0x9;  // public static
    field.isStatic = true;
    MethodAddition method;
    method.classDefIdx = 0;
    method.methodIdx = methodIdx.unwrap();
    method.accessFlags = 0x1;  // public -> virtual
    method.item.registersSize = 0;
    method.item.insnsSize = 1;
    method.insns = {0x0e, 0x00};  // return-void

    BuildOptions options;
    options.keepUnknownSections = false;
    options.fieldAdditions.push_back(field);
    options.methodAdditions.push_back(method);

    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    const auto data = second->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    ASSERT_EQ(data.unwrap()->staticFields.size(), 1u);
    EXPECT_EQ(data.unwrap()->staticFields[0].fieldIndex, fieldIdx.unwrap());
    EXPECT_EQ(data.unwrap()->instanceFields.size(), 0u);
    EXPECT_EQ(data.unwrap()->directMethods.size(), 0u);
    ASSERT_EQ(data.unwrap()->virtualMethods.size(), 1u);
    EXPECT_EQ(data.unwrap()->virtualMethods[0].methodIndex, methodIdx.unwrap());

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, AddsClassDefWithMembers)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    const auto newType = file->addType("LNew;");
    ASSERT_TRUE(newType.is_ok());
    ClassDef def;
    def.classIdx = newType.unwrap();
    def.accessFlags = 0x1;  // public
    def.superclassIdx = 2;  // Ljava/lang/Object;
    file->classDefs.push_back(def);

    const auto name = file->internUtf8("run");
    ASSERT_TRUE(name.is_ok());
    const auto methodIdx = file->addMethod(newType.unwrap(), 1, name.unwrap());
    ASSERT_TRUE(methodIdx.is_ok());

    MethodAddition method;
    method.classDefIdx = 1;  // 新追加的 class_def
    method.methodIdx = methodIdx.unwrap();
    method.accessFlags = 0x9;  // public static
    method.item.insnsSize = 1;
    method.insns = {0x0e, 0x00};

    BuildOptions options;
    options.keepUnknownSections = false;
    options.methodAdditions.push_back(method);

    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    ASSERT_EQ(second->classCount(), 2u);
    ca::u32 newClassIdx = DexFile::kNoIndex;
    for (ca::u32 classIdx = 0; classIdx < second->classCount(); ++classIdx) {
        const auto descriptor = second->classDescriptor(classIdx);
        ASSERT_TRUE(descriptor.is_ok());
        if (descriptor.unwrap().as_std_view() == "LNew;") {
            newClassIdx = classIdx;
        }
    }
    ASSERT_NE(newClassIdx, DexFile::kNoIndex);
    EXPECT_EQ(second->superclassDescriptor(newClassIdx).unwrap().as_std_view(),
              "Ljava/lang/Object;");

    const auto data = second->classData(newClassIdx);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    ASSERT_EQ(data.unwrap()->directMethods.size(), 1u);
    const EncodedMethod& added = data.unwrap()->directMethods[0];
    EXPECT_EQ(second->methodName(added.methodIndex).unwrap().as_std_view(), "run");
    const auto code = second->codeItem(added.codeOff);
    ASSERT_TRUE(code.is_ok());
    ASSERT_NE(code.unwrap(), nullptr);

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, AddsStaticFieldAndExtendsStaticValues)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);
    ASSERT_NE(file->classDefs[0].staticValuesOff, 0u);

    const auto name = file->internUtf8("gen");
    ASSERT_TRUE(name.is_ok());
    const auto fieldIdx = file->addField(1, 0, name.unwrap());
    ASSERT_TRUE(fieldIdx.is_ok());

    FieldAddition add;
    add.classDefIdx = 0;
    add.fieldIdx = fieldIdx.unwrap();
    add.accessFlags = 0x9;  // public static
    add.isStatic = true;

    BuildOptions options;
    options.keepUnknownSections = false;
    options.fieldAdditions.push_back(add);

    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    const auto data = second->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    ASSERT_EQ(data.unwrap()->staticFields.size(), 1u);
    EXPECT_EQ(data.unwrap()->staticFields[0].fieldIndex, fieldIdx.unwrap());

    const auto values = second->staticValues(0);
    ASSERT_TRUE(values.is_ok());
    ASSERT_NE(values.unwrap(), nullptr);
    ASSERT_EQ(values.unwrap()->values.size(), 1u);
    EXPECT_EQ(values.unwrap()->values[0].type, EncodedValueType::Int);
    EXPECT_EQ(values.unwrap()->values[0].integer, 0);

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, RejectsInvalidMemberAdditions)
{
    const auto expectInvalid = [](std::unique_ptr<DexFile> file, BuildOptions options) {
        const auto built = buildDex(*file, options);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
    };

    {
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        FieldAddition add;
        add.classDefIdx = 0;
        add.fieldIdx = 0;  // 已由现有 class_data 定义
        BuildOptions options;
        options.keepUnknownSections = false;
        options.fieldAdditions.push_back(add);
        expectInvalid(std::move(file), std::move(options));
    }
    {
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        FieldAddition add;
        add.classDefIdx = 99;
        add.fieldIdx = 0;
        BuildOptions options;
        options.keepUnknownSections = false;
        options.fieldAdditions.push_back(add);
        expectInvalid(std::move(file), std::move(options));
    }
    {
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        MethodAddition first;
        first.classDefIdx = 0;
        first.methodIdx = 0;  // 已有定义
        first.item.insnsSize = 1;
        first.insns = {0x0e, 0x00};
        BuildOptions options;
        options.keepUnknownSections = false;
        options.methodAdditions.push_back(first);
        expectInvalid(std::move(file), std::move(options));
    }
    {
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        const auto name = file->internUtf8("gen");
        ASSERT_TRUE(name.is_ok());
        const auto methodIdx = file->addMethod(1, 1, name.unwrap());
        ASSERT_TRUE(methodIdx.is_ok());

        MethodAddition add;
        add.classDefIdx = 0;
        add.methodIdx = methodIdx.unwrap();
        add.item.insnsSize = 1;
        add.insns = {0x0e, 0x00};

        CodeReplacement replacement;
        replacement.methodIdx = methodIdx.unwrap();  // 新增方法不能同时替换
        replacement.item.insnsSize = 1;
        replacement.insns = {0x0e, 0x00};

        BuildOptions options;
        options.keepUnknownSections = false;
        options.methodAdditions.push_back(add);
        options.codeReplacements.push_back(replacement);
        expectInvalid(std::move(file), std::move(options));
    }
}

TEST(DexBuilder, RemovesMembersButKeepsIdTables)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    BuildOptions options;
    options.keepUnknownSections = false;
    options.removedFields = {0};
    options.removedMethods = {0};

    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    EXPECT_EQ(second->fieldCount(), 1u);
    EXPECT_EQ(second->methodCount(), 1u);
    ASSERT_EQ(second->classCount(), 1u);
    const auto data = second->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    EXPECT_TRUE(data.unwrap()->staticFields.empty());
    EXPECT_TRUE(data.unwrap()->instanceFields.empty());
    EXPECT_TRUE(data.unwrap()->directMethods.empty());
    EXPECT_TRUE(data.unwrap()->virtualMethods.empty());
    EXPECT_EQ(second->findMapItem(MapType::CodeItem), nullptr);
    EXPECT_EQ(second->findMapItem(MapType::DebugInfoItem), nullptr);

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, RemovesClassDef)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);
    file->classDefs.clear();

    BuildOptions options;
    options.keepUnknownSections = false;
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    EXPECT_EQ(second->classCount(), 0u);
    EXPECT_EQ(second->methodCount(), 1u);  // ID 表条目保留
    EXPECT_EQ(second->findMapItem(MapType::ClassDataItem), nullptr);
    EXPECT_EQ(second->findMapItem(MapType::CodeItem), nullptr);

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, RejectsRemovingReplacedMethod)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    BuildOptions options;
    options.keepUnknownSections = false;
    options.removedMethods = {0};
    CodeReplacement replacement;
    replacement.methodIdx = 0;
    replacement.item.insnsSize = 1;
    replacement.insns = {0x0e, 0x00};
    options.codeReplacements.push_back(replacement);

    const auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_err());
    EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
}

TEST(DexBuilder, OverridesMemberAccessFlags)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    BuildOptions options;
    options.keepUnknownSections = false;
    options.fieldAccessFlags.push_back(AccessFlagEdit{0, 0x1});   // public
    options.methodAccessFlags.push_back(AccessFlagEdit{0, 0x1});  // public，转虚方法

    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    const auto data = second->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    EXPECT_EQ(data.unwrap()->staticFields.size(), 0u);
    ASSERT_EQ(data.unwrap()->instanceFields.size(), 1u);
    EXPECT_EQ(data.unwrap()->instanceFields[0].accessFlags, 0x1u);
    EXPECT_EQ(data.unwrap()->directMethods.size(), 0u);
    ASSERT_EQ(data.unwrap()->virtualMethods.size(), 1u);
    EXPECT_EQ(data.unwrap()->virtualMethods[0].accessFlags, 0x1u);
    EXPECT_NE(data.unwrap()->virtualMethods[0].codeOff, 0u);

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, RejectsInvalidAccessFlagEdits)
{
    const auto expectInvalid = [](std::unique_ptr<DexFile> file, BuildOptions options) {
        const auto built = buildDex(*file, options);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
    };

    {
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        BuildOptions options;
        options.fieldAccessFlags.push_back(AccessFlagEdit{99, 0x1});
        expectInvalid(std::move(file), std::move(options));
    }
    {
        // 不能借 access_flags 把实例字段改成静态字段。
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        BuildOptions options;
        options.fieldAccessFlags.push_back(AccessFlagEdit{0, 0xA});
        expectInvalid(std::move(file), std::move(options));
    }
    {
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        BuildOptions options;
        options.methodAccessFlags.push_back(AccessFlagEdit{99, 0x1});
        expectInvalid(std::move(file), std::move(options));
    }
    {
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        BuildOptions options;
        options.methodAccessFlags.push_back(AccessFlagEdit{0, 0x1});
        options.methodAccessFlags.push_back(AccessFlagEdit{0, 0x1});
        expectInvalid(std::move(file), std::move(options));
    }
    {
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        BuildOptions options;
        options.removedFields = {0};
        options.fieldAccessFlags.push_back(AccessFlagEdit{0, 0x1});
        expectInvalid(std::move(file), std::move(options));
    }
}

TEST(DexBuilder, StripsDebugInfo)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    BuildOptions options;
    options.keepUnknownSections = false;
    options.stripDebugInfo = true;

    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    EXPECT_EQ(second->findMapItem(MapType::DebugInfoItem), nullptr);
    const auto data = second->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_NE(data.unwrap(), nullptr);
    ASSERT_EQ(data.unwrap()->directMethods.size(), 1u);
    const auto code = second->codeItem(data.unwrap()->directMethods[0].codeOff);
    ASSERT_TRUE(code.is_ok());
    ASSERT_NE(code.unwrap(), nullptr);
    EXPECT_EQ(code.unwrap()->debugInfoOff, 0u);

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexBuilder, RejectsRemapWithOpaqueRawSections)
{
    std::unique_ptr<DexFile> shifted = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(shifted, nullptr);
    ASSERT_TRUE(shifted->internUtf8("Hello2.java").is_ok());
    const auto rejected = buildDex(*shifted);
    ASSERT_TRUE(rejected.is_err());
    EXPECT_EQ(rejected.unwrap_err(), WriteError::UnmappedRawSection);

    // 新字符串排在末尾时旧索引不动，未知 section 可以原样保留。
    std::unique_ptr<DexFile> appended = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(appended, nullptr);
    ASSERT_TRUE(appended->internUtf8("zzz").is_ok());
    const auto accepted = buildDex(*appended);
    ASSERT_TRUE(accepted.is_ok()) << to_string(accepted.unwrap_err());
}

TEST(DexBuilder, RejectsDanglingIdTables)
{
    const auto expectInvalid = [](auto&& mutate) {
        std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
        mutate(*file);
        const auto built = buildDex(*file);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
    };

    expectInvalid([](DexFile& file) {
        file.typeIds[0].descriptorIdx = file.stringCount();
    });
    expectInvalid([](DexFile& file) {
        file.protoIds[0].returnTypeIdx = file.typeCount();
    });
    expectInvalid([](DexFile& file) {
        file.fieldIds[0].classIdx = static_cast<ca::u16>(file.typeCount());
    });
    expectInvalid([](DexFile& file) {
        file.methodIds[0].protoIdx = static_cast<ca::u16>(file.protoCount());
    });
    expectInvalid([](DexFile& file) {
        file.classDefs[0].superclassIdx = file.typeCount();
    });
    expectInvalid([](DexFile& file) {
        file.classDefs[0].sourceFileIdx = file.stringCount();
    });
    expectInvalid([](DexFile& file) {
        file.methodHandles[0].handleType = 9;
    });
    expectInvalid([](DexFile& file) {
        file.callSites[0].callSiteOff = 0;
    });
    expectInvalid([](DexFile& file) {
        file.typeIds.resize(0x10001);
    });
}
