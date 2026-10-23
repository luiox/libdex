/// @file        reader_test.cpp
/// @brief       骨架解析与访问面测试（合成 035 样本）。
#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

TEST(DexReader, ParsesSkeleton)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();

    Result<std::unique_ptr<DexFile>, ReadError> result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok()) << to_string(result.unwrap_err());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_EQ(file->header.version, 35);
    EXPECT_EQ(file->header.endianTag, 0x12345678u);
    EXPECT_EQ(file->header.headerSize, dex_test::kHeaderSize);
    EXPECT_EQ(file->header.fileSize, static_cast<ca::u32>(bytes.size()));
    EXPECT_EQ(file->state(), ParseState::Validated);
    EXPECT_TRUE(file->diagnostics().empty());

    EXPECT_EQ(file->stringCount(), 7u);
    EXPECT_EQ(file->typeCount(), 4u);
    EXPECT_EQ(file->protoCount(), 2u);
    EXPECT_EQ(file->fieldCount(), 1u);
    EXPECT_EQ(file->methodCount(), 1u);
    EXPECT_EQ(file->classCount(), 1u);

    ASSERT_NE(file->findMapItem(MapType::StringDataItem), nullptr);
    EXPECT_EQ(file->findMapItem(MapType::StringDataItem)->size, 7u);
    ASSERT_NE(file->findMapItem(MapType::CodeItem), nullptr);
    EXPECT_EQ(file->findMapItem(MapType::CodeItem)->size, 1u);
    ASSERT_NE(file->findMapItem(MapType::ClassDataItem), nullptr);
}

TEST(DexReader, ResolvesDescriptors)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    const auto type0 = file->typeDescriptor(0);
    ASSERT_TRUE(type0.is_ok());
    EXPECT_EQ(type0.unwrap().as_std_view(), "I");

    const auto type3 = file->typeDescriptor(3);
    ASSERT_TRUE(type3.is_ok());
    EXPECT_EQ(type3.unwrap().as_std_view(), "V");

    const auto cls = file->classDescriptor(0);
    ASSERT_TRUE(cls.is_ok());
    EXPECT_EQ(cls.unwrap().as_std_view(), "LHello;");

    const auto super = file->superclassDescriptor(0);
    ASSERT_TRUE(super.is_ok());
    EXPECT_EQ(super.unwrap().as_std_view(), "Ljava/lang/Object;");

    const auto source = file->sourceFile(0);
    ASSERT_TRUE(source.is_ok());
    EXPECT_EQ(source.unwrap().as_std_view(), "Hello.java");

    const auto fieldOwner = file->fieldClassDescriptor(0);
    ASSERT_TRUE(fieldOwner.is_ok());
    EXPECT_EQ(fieldOwner.unwrap().as_std_view(), "LHello;");

    const auto fieldType = file->fieldTypeDescriptor(0);
    ASSERT_TRUE(fieldType.is_ok());
    EXPECT_EQ(fieldType.unwrap().as_std_view(), "I");

    const auto fieldName = file->fieldName(0);
    ASSERT_TRUE(fieldName.is_ok());
    EXPECT_EQ(fieldName.unwrap().as_std_view(), "bar");

    const auto methodOwner = file->methodClassDescriptor(0);
    ASSERT_TRUE(methodOwner.is_ok());
    EXPECT_EQ(methodOwner.unwrap().as_std_view(), "LHello;");

    const auto methodName = file->methodName(0);
    ASSERT_TRUE(methodName.is_ok());
    EXPECT_EQ(methodName.unwrap().as_std_view(), "foo");

    const auto proto0Params = file->protoParameters(0);
    ASSERT_TRUE(proto0Params.is_ok());
    EXPECT_TRUE(proto0Params.unwrap().empty());

    const auto classInterfaces = file->interfaces(0);
    ASSERT_TRUE(classInterfaces.is_ok());
    EXPECT_TRUE(classInterfaces.unwrap().empty());
}

TEST(DexReader, DecodesClassDataAndCodeItem)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    const auto dataResult = file->classData(0);
    ASSERT_TRUE(dataResult.is_ok()) << to_string(dataResult.unwrap_err());
    const ClassData* data = dataResult.unwrap();
    ASSERT_NE(data, nullptr);

    EXPECT_TRUE(data->staticFields.empty());
    ASSERT_EQ(data->instanceFields.size(), 1u);
    EXPECT_EQ(data->instanceFields[0].fieldIndex, 0u);
    EXPECT_EQ(data->instanceFields[0].accessFlags, 0x2u);
    ASSERT_EQ(data->directMethods.size(), 1u);
    EXPECT_EQ(data->directMethods[0].methodIndex, 0u);
    EXPECT_EQ(data->directMethods[0].accessFlags, 0x9u);
    EXPECT_TRUE(data->virtualMethods.empty());
    EXPECT_FALSE(data->raw.empty());

    const ca::u32 codeOff = data->directMethods[0].codeOff;
    ASSERT_NE(codeOff, 0u);

    const auto codeResult = file->codeItem(codeOff);
    ASSERT_TRUE(codeResult.is_ok()) << to_string(codeResult.unwrap_err());
    const CodeItem* code = codeResult.unwrap();
    ASSERT_NE(code, nullptr);

    EXPECT_EQ(code->registersSize, 0u);
    EXPECT_EQ(code->insSize, 0u);
    EXPECT_EQ(code->outsSize, 0u);
    EXPECT_EQ(code->triesSize, 0u);
    EXPECT_EQ(code->insnsSize, 1u);
    EXPECT_EQ(code->insns.length, 2u);
    EXPECT_EQ(code->raw.length, 18u);
    EXPECT_EQ(code->handlersOff, 0u);
    ASSERT_EQ(code->insns.offset + 1u < bytes.size(), true);
    EXPECT_EQ(file->source()[code->insns.offset], 0x0eu);
    EXPECT_EQ(file->source()[code->insns.offset + 1u], 0x00u);
}

TEST(DexReader, RejectsOutOfRangeIndexes)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto result = readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(result.is_ok());
    std::unique_ptr<DexFile> file = std::move(result).unwrap();

    EXPECT_TRUE(file->string(7).is_err());
    EXPECT_TRUE(file->typeDescriptor(4).is_err());
    EXPECT_TRUE(file->classDescriptor(1).is_err());
    EXPECT_TRUE(file->fieldName(1).is_err());
    EXPECT_TRUE(file->methodName(1).is_err());
    EXPECT_TRUE(file->classData(1).is_err());
    EXPECT_TRUE(file->interfaces(1).is_err());
    EXPECT_TRUE(file->protoParameters(2).is_err());

    const auto noCode = file->codeItem(0);
    ASSERT_TRUE(noCode.is_ok());
    EXPECT_EQ(noCode.unwrap(), nullptr);
}
