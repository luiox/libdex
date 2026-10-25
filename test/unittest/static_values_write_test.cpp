/// @file        static_values_write_test.cpp
/// @brief       静态初值显式赋值：既有/新增字段、引用与布尔值、物化与拒绝面。
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

namespace {

std::unique_ptr<DexFile> readFixture()
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(dex_test::asSlice(bytes));
    if (parsed.is_err()) {
        return nullptr;
    }
    return std::move(parsed).unwrap();
}

BuildOptions plainOptions()
{
    BuildOptions options;
    options.keepUnknownSections = false;
    return options;
}

/// 注入一个静态字段并返回其字段索引（构建前调用）。
ca::u32 injectStaticField(DexFile& file, const char* name, ca::u32 typeIdx)
{
    const auto interned = file.internUtf8(name);
    if (interned.is_err()) {
        return DexFile::kNoIndex;
    }
    const auto fieldIdx = file.addField(1, typeIdx, interned.unwrap());
    return fieldIdx.is_ok() ? fieldIdx.unwrap() : DexFile::kNoIndex;
}

FieldAddition staticAddition(ca::u32 fieldIdx)
{
    FieldAddition add;
    add.classDefIdx = 0;
    add.fieldIdx = fieldIdx;
    add.accessFlags = 0x9;  // public static
    add.isStatic = true;
    return add;
}

/// 解析重建产物；失败返回 nullptr。
std::unique_ptr<DexFile> reparse(const std::vector<ca::u8>& bytes)
{
    auto parsed = readDex(dex_test::asSlice(bytes));
    if (parsed.is_err()) {
        return nullptr;
    }
    return std::move(parsed).unwrap();
}

}   // namespace

TEST(DexStaticValuesWrite, SetsExplicitStaticFieldValue)
{
    // 注入静态字段 gen:I，重建后再把初值从默认 0 改成 42，最后覆盖成 -7。
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);
    const ca::u32 gen = injectStaticField(*file, "gen", 0 /* I */);
    ASSERT_NE(gen, DexFile::kNoIndex);

    BuildOptions options = plainOptions();
    options.fieldAdditions.push_back(staticAddition(gen));
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    std::unique_ptr<DexFile> second = reparse(built.unwrap());
    ASSERT_NE(second, nullptr);
    const auto data = second->classData(0);
    ASSERT_TRUE(data.is_ok());
    ASSERT_EQ(data.unwrap()->staticFields.size(), 1u);
    const ca::u32 genIdx = data.unwrap()->staticFields[0].fieldIndex;

    EncodedValue value;
    value.type = EncodedValueType::Int;
    value.integer = 42;
    ASSERT_TRUE(second->setStaticFieldValue(0, genIdx, value).is_ok());

    BuildOptions editOptions = plainOptions();  // 字段已定义，不能再带注入

    auto rebuilt = buildDex(*second, editOptions);
    ASSERT_TRUE(rebuilt.is_ok()) << to_string(rebuilt.unwrap_err());
    std::unique_ptr<DexFile> third = reparse(rebuilt.unwrap());
    ASSERT_NE(third, nullptr);
    const auto values = third->staticValues(0);
    ASSERT_TRUE(values.is_ok());
    ASSERT_NE(values.unwrap(), nullptr);
    ASSERT_EQ(values.unwrap()->values.size(), 1u);
    EXPECT_EQ(values.unwrap()->values[0].type, EncodedValueType::Int);
    EXPECT_EQ(values.unwrap()->values[0].integer, 42);

    // 覆盖旧值，顺带验证负数最小宽度往返。
    value.integer = -7;
    ASSERT_TRUE(third->setStaticFieldValue(0, genIdx, value).is_ok());
    auto rebuilt2 = buildDex(*third, editOptions);
    ASSERT_TRUE(rebuilt2.is_ok()) << to_string(rebuilt2.unwrap_err());
    std::unique_ptr<DexFile> fourth = reparse(rebuilt2.unwrap());
    ASSERT_NE(fourth, nullptr);
    const auto values2 = fourth->staticValues(0);
    ASSERT_TRUE(values2.is_ok());
    EXPECT_EQ(values2.unwrap()->values[0].integer, -7);

    auto again = buildDex(*fourth, editOptions);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt2.unwrap());
}

TEST(DexStaticValuesWrite, SetsValueOnInjectedFieldInSameBuild)
{
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);
    const auto longType = file->addType("J");
    ASSERT_TRUE(longType.is_ok());
    const ca::u32 gen = injectStaticField(*file, "gen", longType.unwrap());
    ASSERT_NE(gen, DexFile::kNoIndex);

    EncodedValue value;
    value.type = EncodedValueType::Long;
    value.integer = 0x100000000ll;  // 需要 5 字节，验证宽度归一
    ASSERT_TRUE(file->setStaticFieldValue(0, gen, value).is_ok());

    BuildOptions options = plainOptions();
    options.fieldAdditions.push_back(staticAddition(gen));
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    std::unique_ptr<DexFile> second = reparse(built.unwrap());
    ASSERT_NE(second, nullptr);
    const auto values = second->staticValues(0);
    ASSERT_TRUE(values.is_ok());
    ASSERT_EQ(values.unwrap()->values[0].type, EncodedValueType::Long);
    EXPECT_EQ(values.unwrap()->values[0].integer, 0x100000000ll);

    auto again = buildDex(*second, plainOptions());
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), built.unwrap());
}

TEST(DexStaticValuesWrite, SetsReferenceAndBooleanStaticValues)
{
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);
    const auto boolType = file->addType("Z");
    const auto stringType = file->addType("Ljava/lang/String;");
    ASSERT_TRUE(boolType.is_ok());
    ASSERT_TRUE(stringType.is_ok());
    const auto flag = injectStaticField(*file, "flag", boolType.unwrap());
    const auto name = injectStaticField(*file, "name", stringType.unwrap());
    ASSERT_NE(flag, DexFile::kNoIndex);
    ASSERT_NE(name, DexFile::kNoIndex);

    EncodedValue boolean;
    boolean.type = EncodedValueType::Boolean;
    boolean.boolean = true;
    ASSERT_TRUE(file->setStaticFieldValue(0, flag, boolean).is_ok());

    const auto text = file->internUtf8("hello");
    ASSERT_TRUE(text.is_ok());
    EncodedValue reference;
    reference.type = EncodedValueType::String;
    reference.index = text.unwrap();
    ASSERT_TRUE(file->setStaticFieldValue(0, name, reference).is_ok());

    BuildOptions options = plainOptions();
    options.fieldAdditions.push_back(staticAddition(flag));
    options.fieldAdditions.push_back(staticAddition(name));
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    std::unique_ptr<DexFile> second = reparse(built.unwrap());
    ASSERT_NE(second, nullptr);

    // 字段按 (class, name) 排序：flag 在前，name 在后。
    const auto values = second->staticValues(0);
    ASSERT_TRUE(values.is_ok());
    ASSERT_EQ(values.unwrap()->values.size(), 2u);
    EXPECT_EQ(values.unwrap()->values[0].type, EncodedValueType::Boolean);
    EXPECT_TRUE(values.unwrap()->values[0].boolean);
    EXPECT_EQ(values.unwrap()->values[1].type, EncodedValueType::String);
    const auto resolved = second->string(values.unwrap()->values[1].index);
    ASSERT_TRUE(resolved.is_ok());
    EXPECT_EQ(resolved.unwrap().as_std_view(), "hello");

    auto again = buildDex(*second, plainOptions());
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), built.unwrap());
}

TEST(DexStaticValuesWrite, MaterializesValuesWithoutSourceArray)
{
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);
    const ca::u32 gen = injectStaticField(*file, "gen", 0 /* I */);
    ASSERT_NE(gen, DexFile::kNoIndex);

    EncodedValue value;
    value.type = EncodedValueType::Int;
    value.integer = 9;
    ASSERT_TRUE(file->setStaticFieldValue(0, gen, value).is_ok());

    // 模拟「无源数组」的类：static_values_off 置 0，编辑仍应物化出数组。
    file->classDefs[0].staticValuesOff = 0;

    BuildOptions options = plainOptions();
    options.fieldAdditions.push_back(staticAddition(gen));
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    std::unique_ptr<DexFile> second = reparse(built.unwrap());
    ASSERT_NE(second, nullptr);
    const auto values = second->staticValues(0);
    ASSERT_TRUE(values.is_ok());
    ASSERT_NE(values.unwrap(), nullptr);
    ASSERT_EQ(values.unwrap()->values.size(), 1u);
    EXPECT_EQ(values.unwrap()->values[0].integer, 9);
}

TEST(DexStaticValuesWrite, RejectsInvalidStaticValueEdits)
{
    // 值类别与字段类型不匹配。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const auto boolType = file->addType("Z");
        ASSERT_TRUE(boolType.is_ok());
        const ca::u32 flag = injectStaticField(*file, "flag", boolType.unwrap());
        ASSERT_NE(flag, DexFile::kNoIndex);

        EncodedValue value;
        value.type = EncodedValueType::Int;
        value.integer = 1;
        const auto rejected = file->setStaticFieldValue(0, flag, value);
        ASSERT_TRUE(rejected.is_err());
        EXPECT_EQ(rejected.unwrap_err(), ReadError::BadIndex);
    }
    // 原始类型字段不接受引用值。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const ca::u32 gen = injectStaticField(*file, "gen", 0 /* I */);
        EncodedValue value;
        value.type = EncodedValueType::String;
        value.index = 0;
        const auto rejected = file->setStaticFieldValue(0, gen, value);
        ASSERT_TRUE(rejected.is_err());
        EXPECT_EQ(rejected.unwrap_err(), ReadError::BadIndex);
    }
    // 值里索引悬垂。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const auto stringType = file->addType("Ljava/lang/String;");
        ASSERT_TRUE(stringType.is_ok());
        const ca::u32 name = injectStaticField(*file, "name", stringType.unwrap());
        EncodedValue value;
        value.type = EncodedValueType::String;
        value.index = file->stringCount();
        const auto rejected = file->setStaticFieldValue(0, name, value);
        ASSERT_TRUE(rejected.is_err());
        EXPECT_EQ(rejected.unwrap_err(), ReadError::BadIndex);
    }
    // 目标是实例字段：API 层通过（索引与类别都合法），重建时拒绝。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        EncodedValue value;
        value.type = EncodedValueType::Int;
        value.integer = 1;
        // fixture 的字段 0（bar:I）是实例字段。
        ASSERT_TRUE(file->setStaticFieldValue(0, 0, value).is_ok());
        BuildOptions options = plainOptions();
        const auto built = buildDex(*file, options);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
    }
    // 目标是已删除的静态字段：构建期拒绝。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const ca::u32 gen = injectStaticField(*file, "gen", 0);
        EncodedValue value;
        value.type = EncodedValueType::Int;
        value.integer = 1;
        ASSERT_TRUE(file->setStaticFieldValue(0, gen, value).is_ok());
        BuildOptions options = plainOptions();
        options.removedFields.push_back(gen);
        const auto built = buildDex(*file, options);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
    }
    // 宽度归一后仍放不下：Byte 放大数由重编码拒绝。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const auto byteType = file->addType("B");
        ASSERT_TRUE(byteType.is_ok());
        const ca::u32 tiny = injectStaticField(*file, "tiny", byteType.unwrap());
        EncodedValue value;
        value.type = EncodedValueType::Byte;
        value.integer = 0x12345;  // 超出 1 字节
        ASSERT_TRUE(file->setStaticFieldValue(0, tiny, value).is_ok());
        BuildOptions options = plainOptions();
        options.fieldAdditions.push_back(staticAddition(tiny));
        const auto built = buildDex(*file, options);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::Unencodable);
    }
}
