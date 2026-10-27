/// @file        incremental_test.cpp
/// @brief       buildDex 增量布局路径：字节级固定点、透传保真与条目级编辑。
#include <cstring>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

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

BuildOptions incrementalOptions()
{
    BuildOptions options;
    options.incremental = true;
    return options;
}

const EncodedMethod& onlyMethod(DexFile& file)
{
    const auto data = file.classData(0);
    return data.unwrap()->directMethods.front();
}

CodeReplacement nopReturnReplacement(ca::u32 methodIdx)
{
    CodeReplacement repl;
    repl.methodIdx = methodIdx;
    repl.item.registersSize = 1;
    repl.item.insSize = 0;
    repl.item.outsSize = 0;
    repl.item.insnsSize = 1;
    repl.insns = {0x0e, 0x00};  // return-void
    return repl;
}

}   // namespace

TEST(DexIncremental, NoEditReproducesSourceBytes)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    std::unique_ptr<DexFile> file = readFixture(bytes);

    auto built = buildDex(*file, incrementalOptions());
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    EXPECT_EQ(built.unwrap(), bytes);  // 未触碰条目零平移，输出与源逐字节一致
}

TEST(DexIncremental, ReplacedBodyKeepsLayoutAndUnknownSection)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    std::unique_ptr<DexFile> file = readFixture(bytes);
    const ca::u32 codeOff = onlyMethod(*file).codeOff;

    BuildOptions options = incrementalOptions();
    options.codeReplacements.push_back(nopReturnReplacement(0));
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    ASSERT_EQ(second->state(), ParseState::Validated);
    EXPECT_TRUE(second->diagnostics().empty());

    // 未建模 section 原字节保留（copy-through 的直接证据）；span 覆盖到
    // 下一 map 条目，平移后长度可变，只断言头部字节。
    ASSERT_NE(second->rawSections.size(), 0u);
    const ByteSlice raw = subOrEmpty(second->source(), second->rawSections.front().span.offset,
                                     second->rawSections.front().span.length);
    ASSERT_GE(raw.size(), 4u);
    EXPECT_EQ(raw[0], 0xDEu);
    EXPECT_EQ(raw[1], 0xADu);
    EXPECT_EQ(raw[2], 0xBEu);
    EXPECT_EQ(raw[3], 0xEFu);

    // 替换体生效：新指令字节在产物的 code 区起点。
    const ca::u32 newCodeOff = onlyMethod(*second).codeOff;
    EXPECT_EQ(rebuilt[newCodeOff + 16u], 0x0Eu);
    EXPECT_EQ(rebuilt[newCodeOff + 17u], 0x00u);
    // 替换体与原方法体等长：替换点之前的布局保持。checksum/signature/
    // fileSize/mapOff/dataSize 按定义随编辑变化；class_defs 表内的
    // annotations/class_data/static_values 偏移也会随下游布局合法回填。
    // 稳定区只有：magic、五张表的 (size, off)（透传不变）、ID 表区与
    // data 区里 code 之前的字符串数据。
    ASSERT_EQ(newCodeOff, codeOff);
    EXPECT_EQ(std::memcmp(rebuilt.data(), bytes.data(), 8), 0);
    EXPECT_EQ(std::memcmp(rebuilt.data() + 56, bytes.data() + 56, 104 - 56), 0);
    EXPECT_EQ(std::memcmp(rebuilt.data() + 108, bytes.data() + 108,
                          dex_test::kClassDefsTableOff - 108),
              0);
    EXPECT_EQ(std::memcmp(rebuilt.data() + dex_test::kDataOffset, bytes.data() + dex_test::kDataOffset,
                          codeOff - dex_test::kDataOffset),
              0);

    const Integrity integrity =
        verifyIntegrity(second->source(), second->header.checksum, second->header.signature);
    EXPECT_TRUE(integrity.checksumOk);
    EXPECT_TRUE(integrity.signatureOk);
}

TEST(DexIncremental, ReplacedBodyIsByteStableOnSecondPass)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    BuildOptions options = incrementalOptions();
    options.codeReplacements.push_back(nopReturnReplacement(0));
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok());
    const std::vector<ca::u8> first = std::move(built).unwrap();

    // 产物再走一次无编辑增量：全部条目未触碰，输出逐字节稳定。
    std::unique_ptr<DexFile> second = readFixture(first);
    auto rebuilt = buildDex(*second, incrementalOptions());
    ASSERT_TRUE(rebuilt.is_ok()) << to_string(rebuilt.unwrap_err());
    EXPECT_EQ(rebuilt.unwrap(), first);
}

TEST(DexIncremental, StripsDebugInfoAndDropsSection)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());

    BuildOptions options = incrementalOptions();
    options.stripDebugInfo = true;
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    ASSERT_EQ(second->state(), ParseState::Validated);

    // debug section 从 map 消失，code_item 的 debug_info_off 归零。
    EXPECT_EQ(second->findMapItem(MapType::DebugInfoItem), nullptr);
    const auto code = second->codeItem(onlyMethod(*second).codeOff);
    ASSERT_TRUE(code.is_ok());
    EXPECT_EQ(code.unwrap()->debugInfoOff, 0u);
}

TEST(DexIncremental, RemovedMethodDropsItsCodeItem)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    const ca::u32 codeItems = file->findMapItem(MapType::CodeItem)->size;

    BuildOptions options = incrementalOptions();
    options.removedMethods.push_back(0);
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    ASSERT_EQ(second->state(), ParseState::Validated);

    // ID 表条目保留，class_data 不再定义该方法，code 条目不再发射。
    EXPECT_EQ(second->methodCount(), file->methodCount());
    const auto data = second->classData(0);
    ASSERT_TRUE(data.is_ok());
    EXPECT_EQ(data.unwrap()->directMethods.size(), 0u);
    const MapItem* codeMap = second->findMapItem(MapType::CodeItem);
    if (codeItems > 1u) {
        ASSERT_NE(codeMap, nullptr);
        EXPECT_EQ(codeMap->size, codeItems - 1u);
    } else {
        EXPECT_EQ(codeMap, nullptr);  // 唯一 code 条目也被删，section 消失
    }
}

TEST(DexIncremental, RemovesClassDef)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());

    file->classDefs.erase(file->classDefs.begin());
    auto built = buildDex(*file, incrementalOptions());
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    ASSERT_EQ(second->state(), ParseState::Validated);
    EXPECT_EQ(second->classCount(), 0u);
    EXPECT_EQ(second->header.classDefsSize, 0u);
    // 类删除后 class_data / code / debug / static_values 都不再被引用。
    EXPECT_EQ(second->findMapItem(MapType::ClassDataItem), nullptr);
    EXPECT_EQ(second->findMapItem(MapType::CodeItem), nullptr);
}

TEST(DexIncremental, OverridesMethodAccessFlags)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    const ca::u32 original = onlyMethod(*file).accessFlags;

    BuildOptions options = incrementalOptions();
    options.methodAccessFlags.push_back(AccessFlagEdit{0, original | 0x10u});  // +final
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    EXPECT_EQ(onlyMethod(*second).accessFlags, original | 0x10u);
}

TEST(DexIncremental, RejectsTableLevelEdits)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());
    auto interned = file->internUtf8("extra");
    ASSERT_TRUE(interned.is_ok());

    // intern 追加了 string_ids：增量前提破坏，调用方应改走 canonical。
    auto built = buildDex(*file, incrementalOptions());
    ASSERT_TRUE(built.is_err());
    EXPECT_EQ(built.unwrap_err(), WriteError::NotIncremental);
}

TEST(DexIncremental, RejectsDroppedUnknownSections)
{
    std::unique_ptr<DexFile> file = readFixture(dex_test::makeHelloDex());

    BuildOptions options = incrementalOptions();
    options.keepUnknownSections = false;
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    EXPECT_EQ(second->rawSections.size(), 0u);
}

TEST(DexIncremental, CanonicalAndIncrementalAgreeSemantically)
{
    // 同一编辑分别走 canonical 与增量：readDex 后关键 DOM 必须一致。
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();

    std::unique_ptr<DexFile> forCanonical = readFixture(bytes);
    BuildOptions plain;
    plain.codeReplacements.push_back(nopReturnReplacement(0));
    plain.methodAccessFlags.push_back(AccessFlagEdit{0, 0x9u | 0x10u});
    auto canonical = buildDex(*forCanonical, plain);
    ASSERT_TRUE(canonical.is_ok()) << to_string(canonical.unwrap_err());

    std::unique_ptr<DexFile> forIncremental = readFixture(bytes);
    BuildOptions inc = incrementalOptions();
    inc.codeReplacements = plain.codeReplacements;
    inc.methodAccessFlags = plain.methodAccessFlags;
    auto incremental = buildDex(*forIncremental, inc);
    ASSERT_TRUE(incremental.is_ok()) << to_string(incremental.unwrap_err());

    std::unique_ptr<DexFile> left = readFixture(canonical.unwrap());
    std::unique_ptr<DexFile> right = readFixture(incremental.unwrap());
    ASSERT_NE(left, nullptr);
    ASSERT_NE(right, nullptr);
    ASSERT_EQ(left->classCount(), right->classCount());
    ASSERT_EQ(left->stringCount(), right->stringCount());
    ASSERT_EQ(left->methodCount(), right->methodCount());
    const auto leftData = left->classData(0);
    const auto rightData = right->classData(0);
    ASSERT_TRUE(leftData.is_ok() && rightData.is_ok());
    ASSERT_EQ(leftData.unwrap()->directMethods.size(), 1u);
    const EncodedMethod& lm = leftData.unwrap()->directMethods.front();
    const EncodedMethod& rm = rightData.unwrap()->directMethods.front();
    EXPECT_EQ(lm.methodIndex, rm.methodIndex);
    EXPECT_EQ(lm.accessFlags, rm.accessFlags);
    const auto lc = left->codeItem(lm.codeOff);
    const auto rc = right->codeItem(rm.codeOff);
    ASSERT_TRUE(lc.is_ok() && rc.is_ok());
    ASSERT_EQ(lc.unwrap()->insnsSize, rc.unwrap()->insnsSize);
    EXPECT_EQ(std::memcmp(bytes.data() + 0, canonical.unwrap().data(), 0), 0);
}
