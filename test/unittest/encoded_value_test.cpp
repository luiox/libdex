/// @file        encoded_value_test.cpp
/// @brief       encoded_value/encoded_annotation 的类型、嵌套与错误边界。
#include <cstdint>
#include <initializer_list>
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"

using namespace dex::core;

namespace {

std::vector<ca::u8> bytesOf(std::initializer_list<ca::u8> bytes)
{
    return std::vector<ca::u8>(bytes);
}

Reader readerFor(const std::vector<ca::u8>& bytes)
{
    const ca::core::Bytes source = ca::core::Bytes::from_static(bytes.data(), bytes.size());
    return std::move(Reader::at(source, 0)).unwrap();
}

}   // namespace

TEST(DexEncodedValue, ReadsScalarValues)
{
    const std::vector<ca::u8> bytes = bytesOf({
        0x00, 0xFF,                          // byte -1
        0x22, 0xFE, 0xFF,                    // short -2
        0x64, 0x78, 0x56, 0x34, 0x12,        // int 0x12345678
        0xE6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // long -1
        0x03, 0x41,                          // char 'A'
    });
    Reader cur = readerFor(bytes);

    const auto byte = readEncodedValue(cur);
    ASSERT_TRUE(byte.is_ok());
    EXPECT_EQ(byte.unwrap().type, EncodedValueType::Byte);
    EXPECT_EQ(byte.unwrap().integer, -1);

    const auto shortValue = readEncodedValue(cur);
    ASSERT_TRUE(shortValue.is_ok());
    EXPECT_EQ(shortValue.unwrap().type, EncodedValueType::Short);
    EXPECT_EQ(shortValue.unwrap().integer, -2);

    const auto intValue = readEncodedValue(cur);
    ASSERT_TRUE(intValue.is_ok());
    EXPECT_EQ(intValue.unwrap().type, EncodedValueType::Int);
    EXPECT_EQ(intValue.unwrap().integer, 0x12345678);

    const auto longValue = readEncodedValue(cur);
    ASSERT_TRUE(longValue.is_ok());
    EXPECT_EQ(longValue.unwrap().type, EncodedValueType::Long);
    EXPECT_EQ(longValue.unwrap().integer, -1);

    const auto charValue = readEncodedValue(cur);
    ASSERT_TRUE(charValue.is_ok());
    EXPECT_EQ(charValue.unwrap().type, EncodedValueType::Char);
    EXPECT_EQ(charValue.unwrap().bits, 0x41u);
}

TEST(DexEncodedValue, ReadsFloatDoubleAndReferences)
{
    const std::vector<ca::u8> bytes = bytesOf({
        0x70, 0x00, 0x00, 0x80, 0x3F,  // float 1.0
        0xF1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F,  // double 1.0
        0x37, 0x2C, 0x01,              // string index 300（value_arg=1，两字节零扩展）
        0x18, 0x05,                    // type index 5
    });
    Reader cur = readerFor(bytes);

    const auto floatValue = readEncodedValue(cur);
    ASSERT_TRUE(floatValue.is_ok());
    EXPECT_EQ(floatValue.unwrap().type, EncodedValueType::Float);
    EXPECT_EQ(floatValue.unwrap().bits, 0x3F800000u);

    const auto doubleValue = readEncodedValue(cur);
    ASSERT_TRUE(doubleValue.is_ok());
    EXPECT_EQ(doubleValue.unwrap().type, EncodedValueType::Double);
    EXPECT_EQ(doubleValue.unwrap().bits, 0x3FF0000000000000ull);

    const auto stringValue = readEncodedValue(cur);
    ASSERT_TRUE(stringValue.is_ok());
    EXPECT_EQ(stringValue.unwrap().type, EncodedValueType::String);
    EXPECT_EQ(stringValue.unwrap().valueArg, 1u);
    EXPECT_EQ(stringValue.unwrap().header(), 0x37u);
    EXPECT_EQ(stringValue.unwrap().index, 300u);

    const auto typeValue = readEncodedValue(cur);
    ASSERT_TRUE(typeValue.is_ok());
    EXPECT_EQ(typeValue.unwrap().type, EncodedValueType::Type);
    EXPECT_EQ(typeValue.unwrap().valueArg, 0u);
    EXPECT_EQ(typeValue.unwrap().index, 5u);
}

TEST(DexEncodedValue, ReencodesDecodedBytesExactly)
{
    const std::vector<ca::u8> bytes = bytesOf({
        0x00, 0xFF,                          // byte -1
        0x22, 0xFE, 0xFF,                    // short -2
        0x64, 0x78, 0x56, 0x34, 0x12,        // int 0x12345678
        0xE6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // long -1
        0x03, 0x41,                          // char 'A'
        0x70, 0x00, 0x00, 0x80, 0x3F,        // float 1.0
        0xF1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F,  // double 1.0
        0x37, 0x2C, 0x01,                    // string 300（非最小宽度）
        0x77, 0x2C, 0x01, 0x00, 0x00,        // string 300（4 字节宽度）
        0x24, 0x01, 0x00,                    // int 1（非最小宽度）
        0x3F,                                // true
        0x1E,                                // null
        0x1C, 0x02, 0x04, 0x01, 0x04, 0xFF,  // [1, -1]
        0x1D, 0x02, 0x01, 0x00, 0x37, 0x2C, 0x01,  // 注解 {string 300}
    });
    Reader cur = readerFor(bytes);

    ca::usize consumed = 0;
    while (consumed < bytes.size()) {
        const auto value = readEncodedValue(cur);
        ASSERT_TRUE(value.is_ok());
        const auto encoded = writeEncodedValue(value.unwrap());
        ASSERT_TRUE(encoded.is_ok()) << dex::core::to_string(encoded.unwrap_err());
        const ca::usize end = cur.pos();
        const std::vector<ca::u8> expected(bytes.begin() + consumed, bytes.begin() + end);
        EXPECT_EQ(encoded.unwrap(), expected);
        consumed = end;
    }
}

TEST(DexEncodedValue, RejectsUnencodableValues)
{
    {
        EncodedValue value;
        value.type = EncodedValueType::String;
        value.index = 0x100;
        const auto encoded = writeEncodedValue(value);
        ASSERT_TRUE(encoded.is_err());
        EXPECT_EQ(encoded.unwrap_err(), WriteError::Unencodable);
    }
    {
        EncodedValue value;
        value.type = EncodedValueType::Boolean;
        value.valueArg = 1;
        value.boolean = false;
        EXPECT_EQ(writeEncodedValue(value).unwrap_err(), WriteError::Unencodable);
    }
    {
        EncodedValue value;
        value.type = EncodedValueType::Float;
        value.bits = 0x3F800000u;
        EXPECT_EQ(writeEncodedValue(value).unwrap_err(), WriteError::Unencodable);
    }
}

TEST(DexEncodedValue, ReadsBooleanNullAndArray)
{
    const std::vector<ca::u8> bytes = bytesOf({
        0x1E,                    // null
        0x3F,                    // true
        0x1F,                    // false
        0x1C, 0x02, 0x04, 0x01, 0x04, 0xFF,  // [1, -1]
    });
    Reader cur = readerFor(bytes);

    const auto nullValue = readEncodedValue(cur);
    ASSERT_TRUE(nullValue.is_ok());
    EXPECT_EQ(nullValue.unwrap().type, EncodedValueType::Null);

    const auto trueValue = readEncodedValue(cur);
    ASSERT_TRUE(trueValue.is_ok());
    EXPECT_EQ(trueValue.unwrap().type, EncodedValueType::Boolean);
    EXPECT_TRUE(trueValue.unwrap().boolean);

    const auto falseValue = readEncodedValue(cur);
    ASSERT_TRUE(falseValue.is_ok());
    EXPECT_FALSE(falseValue.unwrap().boolean);

    const auto arrayValue = readEncodedValue(cur);
    ASSERT_TRUE(arrayValue.is_ok());
    EXPECT_TRUE(arrayValue.unwrap().isArray());
    ASSERT_EQ(arrayValue.unwrap().array.size(), 2u);
    EXPECT_EQ(arrayValue.unwrap().array[0].integer, 1);
    EXPECT_EQ(arrayValue.unwrap().array[1].integer, -1);
}

TEST(DexEncodedValue, ReadsAnnotation)
{
    const std::vector<ca::u8> bytes = bytesOf({
        0x1D,        // annotation
        0x02,        // type_idx
        0x01,        // one element
        0x00,        // name_idx
        0x17, 0x07,  // string index 7
    });
    Reader cur = readerFor(bytes);

    const auto value = readEncodedValue(cur);
    ASSERT_TRUE(value.is_ok());
    ASSERT_TRUE(value.unwrap().isAnnotation());
    ASSERT_NE(value.unwrap().annotation, nullptr);
    EXPECT_EQ(value.unwrap().annotation->typeIdx, 2u);
    ASSERT_EQ(value.unwrap().annotation->elements.size(), 1u);
    EXPECT_EQ(value.unwrap().annotation->elements[0].nameIdx, 0u);
    EXPECT_EQ(value.unwrap().annotation->elements[0].value.type, EncodedValueType::String);
    EXPECT_EQ(value.unwrap().annotation->elements[0].value.index, 7u);
}

TEST(DexEncodedValue, ReadsEmptyAnnotation)
{
    const std::vector<ca::u8> bytes = bytesOf({0x1D, 0x03, 0x00});
    Reader cur = readerFor(bytes);

    const auto value = readEncodedValue(cur);
    ASSERT_TRUE(value.is_ok());
    ASSERT_NE(value.unwrap().annotation, nullptr);
    EXPECT_EQ(value.unwrap().annotation->typeIdx, 3u);
    EXPECT_TRUE(value.unwrap().annotation->elements.empty());
}

TEST(DexEncodedValue, RejectsMalformedValues)
{
    {
        const std::vector<ca::u8> bytes = bytesOf({0x01});
        Reader cur = readerFor(bytes);
        const auto value = readEncodedValue(cur);
        ASSERT_TRUE(value.is_err());
        EXPECT_EQ(value.unwrap_err(), ReadError::BadEncodedValue);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({0x20, 0x00});  // byte 带 value_arg
        Reader cur = readerFor(bytes);
        const auto value = readEncodedValue(cur);
        ASSERT_TRUE(value.is_err());
        EXPECT_EQ(value.unwrap_err(), ReadError::BadEncodedValue);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({0x5F});  // boolean value_arg=2
        Reader cur = readerFor(bytes);
        const auto value = readEncodedValue(cur);
        ASSERT_TRUE(value.is_err());
        EXPECT_EQ(value.unwrap_err(), ReadError::BadEncodedValue);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({0x64, 0x01, 0x02});  // int 只有 2 字节
        Reader cur = readerFor(bytes);
        const auto value = readEncodedValue(cur);
        ASSERT_TRUE(value.is_err());
        EXPECT_EQ(value.unwrap_err(), ReadError::Truncated);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({0x1C, 0x03, 0x1E});  // 声明 3 个只有 1 个
        Reader cur = readerFor(bytes);
        const auto value = readEncodedValue(cur);
        ASSERT_TRUE(value.is_err());
        EXPECT_EQ(value.unwrap_err(), ReadError::Truncated);
    }
    {
        const std::vector<ca::u8> bytes = bytesOf({0x1D, 0x00, 0x02, 0x00});  // 注解元素不足
        Reader cur = readerFor(bytes);
        const auto value = readEncodedValue(cur);
        ASSERT_TRUE(value.is_err());
        EXPECT_EQ(value.unwrap_err(), ReadError::Truncated);
    }
}

TEST(DexEncodedValue, RejectsDeepNesting)
{
    std::vector<ca::u8> deep;
    for (ca::u32 i = 0; i < 300; ++i) {
        deep.push_back(0x1C);  // array
        deep.push_back(0x01);  // size 1
    }
    deep.push_back(0x1E);  // null

    Reader cur = readerFor(deep);
    const auto value = readEncodedValue(cur);
    ASSERT_TRUE(value.is_err());
    EXPECT_EQ(value.unwrap_err(), ReadError::BadEncodedValue);
}

TEST(DexEncodedValue, AnnotationDepthIsBounded)
{
    // 顶层读取 256 层注解应被拒绝。
    std::vector<ca::u8> deep;
    for (ca::u32 i = 0; i < 260; ++i) {
        deep.push_back(0x1D);  // annotation
        deep.push_back(0x00);  // type 0
        deep.push_back(0x01);  // one element
        deep.push_back(0x00);  // name 0
    }
    deep.push_back(0x1E);  // null at the bottom

    Reader cur = readerFor(deep);
    const auto value = readEncodedValue(cur);
    ASSERT_TRUE(value.is_err());
    EXPECT_EQ(value.unwrap_err(), ReadError::BadEncodedValue);
}
