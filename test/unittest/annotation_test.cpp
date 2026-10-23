/// @file        annotation_test.cpp
/// @brief       注解族条目与静态初值数组的结构解码、raw 区间与错误边界。
#include <cstdint>
#include <initializer_list>
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

namespace {

std::vector<ca::u8> bytesOf(std::initializer_list<ca::u8> bytes)
{
    return std::vector<ca::u8>(bytes);
}

ByteSlice viewOf(const std::vector<ca::u8>& bytes)
{
    return ByteSlice{bytes.data(), bytes.size()};
}

/// 布局：annotation_item[0,8) / annotation_set[8,20) / ref_list[20,28) /
/// directory[28,68) / encoded_array[68,75)。
std::vector<ca::u8> makeItems()
{
    return bytesOf({
        // annotation_item：runtime、type 5、{name 0: int 7, name 1: null}
        0x01, 0x05, 0x02, 0x00, 0x04, 0x07, 0x01, 0x1E,
        // annotation_set：两个条目
        0x02, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00,
        // annotation_set_ref_list：一个 set
        0x01, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        // annotations_directory：class 0x30，字段/方法/参数各一条
        0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
        // encoded_array：[1, null, string 300]
        0x03, 0x04, 0x01, 0x1E, 0x37, 0x2C, 0x01,
    });
}

}   // namespace

TEST(DexAnnotation, ReadsAnnotationItem)
{
    const std::vector<ca::u8> bytes = makeItems();
    const auto item = readAnnotationItem(viewOf(bytes), 0);
    ASSERT_TRUE(item.is_ok());

    EXPECT_EQ(item.unwrap().raw.offset, 0u);
    EXPECT_EQ(item.unwrap().raw.length, 8u);
    EXPECT_EQ(item.unwrap().visibility, 1u);
    EXPECT_EQ(item.unwrap().annotation.typeIdx, 5u);
    ASSERT_EQ(item.unwrap().annotation.elements.size(), 2u);
    EXPECT_EQ(item.unwrap().annotation.elements[0].nameIdx, 0u);
    EXPECT_EQ(item.unwrap().annotation.elements[0].value.type, EncodedValueType::Int);
    EXPECT_EQ(item.unwrap().annotation.elements[0].value.integer, 7);
    EXPECT_EQ(item.unwrap().annotation.elements[1].nameIdx, 1u);
    EXPECT_EQ(item.unwrap().annotation.elements[1].value.type, EncodedValueType::Null);
}

TEST(DexAnnotation, ReadsSetsAndRefLists)
{
    const std::vector<ca::u8> bytes = makeItems();

    const auto set = readAnnotationSet(viewOf(bytes), 8);
    ASSERT_TRUE(set.is_ok());
    EXPECT_EQ(set.unwrap().raw.length, 12u);
    EXPECT_EQ(set.unwrap().annotationOffs,
              (std::vector<ca::u32>{0x10, 0x20}));

    const auto refs = readAnnotationSetRefList(viewOf(bytes), 20);
    ASSERT_TRUE(refs.is_ok());
    EXPECT_EQ(refs.unwrap().raw.length, 8u);
    EXPECT_EQ(refs.unwrap().annotationSetOffs, (std::vector<ca::u32>{8}));
}

TEST(DexAnnotation, ReadsDirectory)
{
    const std::vector<ca::u8> bytes = makeItems();
    const auto directory = readAnnotationsDirectory(viewOf(bytes), 28);
    ASSERT_TRUE(directory.is_ok());

    EXPECT_EQ(directory.unwrap().raw.length, 40u);
    EXPECT_EQ(directory.unwrap().classAnnotationsOff, 0x30u);
    ASSERT_EQ(directory.unwrap().fieldAnnotations.size(), 1u);
    EXPECT_EQ(directory.unwrap().fieldAnnotations[0].memberIdx, 1u);
    EXPECT_EQ(directory.unwrap().fieldAnnotations[0].annotationsOff, 0x40u);
    ASSERT_EQ(directory.unwrap().methodAnnotations.size(), 1u);
    EXPECT_EQ(directory.unwrap().methodAnnotations[0].memberIdx, 2u);
    EXPECT_EQ(directory.unwrap().methodAnnotations[0].annotationsOff, 0x50u);
    ASSERT_EQ(directory.unwrap().parameterAnnotations.size(), 1u);
    EXPECT_EQ(directory.unwrap().parameterAnnotations[0].memberIdx, 3u);
    EXPECT_EQ(directory.unwrap().parameterAnnotations[0].annotationsOff, 0x60u);
}

TEST(DexAnnotation, ReadsEncodedArray)
{
    const std::vector<ca::u8> bytes = makeItems();
    const auto array = readEncodedArrayItem(viewOf(bytes), 68);
    ASSERT_TRUE(array.is_ok());

    EXPECT_EQ(array.unwrap().raw.offset, 68u);
    EXPECT_EQ(array.unwrap().raw.length, 7u);
    ASSERT_EQ(array.unwrap().values.size(), 3u);
    EXPECT_EQ(array.unwrap().values[0].integer, 1);
    EXPECT_EQ(array.unwrap().values[1].type, EncodedValueType::Null);
    EXPECT_EQ(array.unwrap().values[2].type, EncodedValueType::String);
    EXPECT_EQ(array.unwrap().values[2].valueArg, 1u);
    EXPECT_EQ(array.unwrap().values[2].index, 300u);
}

TEST(DexAnnotation, RejectsMalformedCounts)
{
    {
        const std::vector<ca::u8> bytes = bytesOf({0x02, 0x00, 0x00, 0x00});
        EXPECT_EQ(readAnnotationSet(viewOf(bytes), 0).unwrap_err(), ReadError::Truncated);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({
            0x00, 0x00, 0x00, 0x00,  // class off
            0x02, 0x00, 0x00, 0x00,  // field count 2
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        });
        EXPECT_EQ(readAnnotationsDirectory(viewOf(bytes), 0).unwrap_err(),
                  ReadError::Truncated);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({0x05, 0x04});
        EXPECT_EQ(readEncodedArrayItem(viewOf(bytes), 0).unwrap_err(),
                  ReadError::Truncated);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({0x01});
        EXPECT_EQ(readAnnotationItem(viewOf(bytes), 0).unwrap_err(), ReadError::Truncated);
    }
}

TEST(DexAnnotation, ReencodesItemsExactly)
{
    const std::vector<ca::u8> bytes = makeItems();
    const auto slice = [&bytes](ca::u32 begin, ca::u32 end) {
        return std::vector<ca::u8>(bytes.begin() + begin, bytes.begin() + end);
    };

    const auto item = readAnnotationItem(viewOf(bytes), 0);
    ASSERT_TRUE(item.is_ok());
    const auto itemBytes = writeAnnotationItem(item.unwrap());
    ASSERT_TRUE(itemBytes.is_ok());
    EXPECT_EQ(itemBytes.unwrap(), slice(0, 8));

    const auto set = readAnnotationSet(viewOf(bytes), 8);
    ASSERT_TRUE(set.is_ok());
    const auto setBytes = writeAnnotationSet(set.unwrap());
    ASSERT_TRUE(setBytes.is_ok());
    EXPECT_EQ(setBytes.unwrap(), slice(8, 20));

    const auto refs = readAnnotationSetRefList(viewOf(bytes), 20);
    ASSERT_TRUE(refs.is_ok());
    const auto refsBytes = writeAnnotationSetRefList(refs.unwrap());
    ASSERT_TRUE(refsBytes.is_ok());
    EXPECT_EQ(refsBytes.unwrap(), slice(20, 28));

    const auto directory = readAnnotationsDirectory(viewOf(bytes), 28);
    ASSERT_TRUE(directory.is_ok());
    const auto directoryBytes = writeAnnotationsDirectory(directory.unwrap());
    ASSERT_TRUE(directoryBytes.is_ok());
    EXPECT_EQ(directoryBytes.unwrap(), slice(28, 68));

    const auto array = readEncodedArrayItem(viewOf(bytes), 68);
    ASSERT_TRUE(array.is_ok());
    const auto arrayBytes = writeEncodedArrayItem(array.unwrap());
    ASSERT_TRUE(arrayBytes.is_ok());
    EXPECT_EQ(arrayBytes.unwrap(), slice(68, 75));
}

TEST(DexAnnotation, DexFileLazyAccessors)
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(viewOf(bytes));
    ASSERT_TRUE(parsed.is_ok());
    std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

    const auto values = file->staticValues(0);
    ASSERT_TRUE(values.is_ok());
    ASSERT_NE(values.unwrap(), nullptr);
    EXPECT_TRUE(values.unwrap()->values.empty());
    EXPECT_EQ(values.unwrap()->raw.length, 1u);

    const auto annotations = file->classAnnotations(0);
    ASSERT_TRUE(annotations.is_ok());
    EXPECT_EQ(annotations.unwrap(), nullptr);

    const auto set = file->annotationSet(0);
    ASSERT_TRUE(set.is_ok());
    EXPECT_EQ(set.unwrap(), nullptr);

    EXPECT_EQ(file->staticValues(99).unwrap_err(), ReadError::BadIndex);
}
