/// @file        descriptor_test.cpp
/// @brief       DEX 类型/方法描述符解析边界。
#include <string>
#include <string_view>

#include <gtest/gtest.h>

#include "dex/dex.hpp"

using namespace dex::type;

TEST(DexType, ParsesFieldDescriptors)
{
    const auto intType = parseFieldType("I");
    ASSERT_TRUE(intType.is_ok());
    EXPECT_EQ(intType.unwrap().kind, TypeDesc::Kind::Primitive);
    EXPECT_EQ(intType.unwrap().primitive, BaseType::Int);
    EXPECT_EQ(intType.unwrap().array_dims, 0u);
    EXPECT_FALSE(intType.unwrap().isArray());

    const auto longArray = parseFieldType("[J");
    ASSERT_TRUE(longArray.is_ok());
    EXPECT_EQ(longArray.unwrap().primitive, BaseType::Long);
    EXPECT_EQ(longArray.unwrap().array_dims, 1u);

    const auto objectArray = parseFieldType("[[Ljava/lang/String;");
    ASSERT_TRUE(objectArray.is_ok());
    EXPECT_EQ(objectArray.unwrap().kind, TypeDesc::Kind::Class);
    EXPECT_EQ(objectArray.unwrap().array_dims, 2u);
    EXPECT_EQ(objectArray.unwrap().class_name, "java/lang/String");

    const auto nested = parseFieldType("Lfoo/Outer$Inner;");
    ASSERT_TRUE(nested.is_ok());
    EXPECT_EQ(nested.unwrap().class_name, "foo/Outer$Inner");
}

TEST(DexType, RejectsBadFieldDescriptors)
{
    EXPECT_EQ(parseFieldType("").unwrap_err(), DescError::Empty);
    EXPECT_EQ(parseFieldType("V").unwrap_err(), DescError::BadBaseType);
    EXPECT_EQ(parseFieldType("L;").unwrap_err(), DescError::BadClassName);
    EXPECT_EQ(parseFieldType("Lfoo.bar;").unwrap_err(), DescError::BadClassName);
    EXPECT_EQ(parseFieldType("Lfoo").unwrap_err(), DescError::Truncated);
    EXPECT_EQ(parseFieldType("[Ix").unwrap_err(), DescError::TrailingChars);
    EXPECT_EQ(parseFieldType("[V").unwrap_err(), DescError::BadBaseType);
    EXPECT_EQ(parseFieldType("(").unwrap_err(), DescError::BadBaseType);

    std::string deep(256, '[');
    deep.push_back('I');
    EXPECT_EQ(parseFieldType(deep).unwrap_err(), DescError::NestingTooDeep);

    EXPECT_TRUE(isValidFieldType("Ljava/lang/Object;"));
    EXPECT_FALSE(isValidFieldType("V"));
}

TEST(DexType, ParsesMethodDescriptors)
{
    const auto voidNoArgs = parseMethodDescriptor("()V");
    ASSERT_TRUE(voidNoArgs.is_ok());
    EXPECT_TRUE(voidNoArgs.unwrap().ret_void);
    EXPECT_TRUE(voidNoArgs.unwrap().params.empty());

    const auto mixed = parseMethodDescriptor("(I[Ljava/lang/String;J)D");
    ASSERT_TRUE(mixed.is_ok());
    ASSERT_EQ(mixed.unwrap().params.size(), 3u);
    EXPECT_EQ(mixed.unwrap().params[0].primitive, BaseType::Int);
    EXPECT_EQ(mixed.unwrap().params[1].class_name, "java/lang/String");
    EXPECT_EQ(mixed.unwrap().params[1].array_dims, 1u);
    EXPECT_EQ(mixed.unwrap().params[2].primitive, BaseType::Long);
    EXPECT_FALSE(mixed.unwrap().ret_void);
    EXPECT_EQ(mixed.unwrap().ret.primitive, BaseType::Double);

    const auto objectReturn = parseMethodDescriptor("(Ljava/util/List;)Ljava/lang/Object;");
    ASSERT_TRUE(objectReturn.is_ok());
    EXPECT_EQ(objectReturn.unwrap().ret.class_name, "java/lang/Object");
}

TEST(DexType, RejectsBadMethodDescriptors)
{
    EXPECT_EQ(parseMethodDescriptor("").unwrap_err(), DescError::Empty);
    EXPECT_EQ(parseMethodDescriptor("I").unwrap_err(), DescError::BadMethodShape);
    EXPECT_EQ(parseMethodDescriptor("(V)V").unwrap_err(), DescError::BadBaseType);
    EXPECT_EQ(parseMethodDescriptor("()").unwrap_err(), DescError::Truncated);
    EXPECT_EQ(parseMethodDescriptor("(I").unwrap_err(), DescError::Truncated);
    EXPECT_EQ(parseMethodDescriptor("(I)Vx").unwrap_err(), DescError::TrailingChars);
    EXPECT_EQ(parseMethodDescriptor("([I)[Jx").unwrap_err(), DescError::TrailingChars);
}
