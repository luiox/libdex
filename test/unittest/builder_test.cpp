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

TEST(DexBuilder, RejectsRenamesThatBreakTableOrder)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    ASSERT_NE(file, nullptr);

    const auto zzz = file->internUtf8("zzz");
    ASSERT_TRUE(zzz.is_ok());
    file->methodIds.push_back(
        MethodId{file->methodIds[0].classIdx, file->methodIds[0].protoIdx, zzz.unwrap()});

    BuildOptions options;
    options.keepUnknownSections = false;
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());

    const auto aaa = file->internUtf8("aaa");
    ASSERT_TRUE(aaa.is_ok());
    file->methodIds[1].nameIdx = aaa.unwrap();

    const auto broken = buildDex(*file, options);
    ASSERT_TRUE(broken.is_err());
    EXPECT_EQ(broken.unwrap_err(), WriteError::UnsortedTables);
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
