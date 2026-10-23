/// @file        descriptor.hpp
/// @brief       DEX 类型描述符与方法描述符解析。
///
/// DEX 的类型系统直接用描述符字符串表达：字段/参数/返回值是
/// `Z B S C I J F D Lname; [T`，方法是 `(参数)返回`。本模块把描述符定型为
/// 零拷贝解析结果（类名与字段名共用输入串的字节），只做语法事实，不查表、
/// 不解析泛型签名。语法真源是 DEX 格式规范与 JVMS 4.3 的同形子集。
#pragma once

#include <string_view>
#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

namespace dex::type {

using ca::core::Err;
using ca::core::Ok;
using ca::core::Result;

/// @brief 描述符解析失败原因。
enum class DescError {
    Ok = 0,
    Empty,          ///< 输入为空
    Truncated,      ///< 结构在闭合前结束（缺 ';' 或 ')'）
    TrailingChars,  ///< 结构结束后仍有字符
    BadBaseType,    ///< 未知基类型字符，或 V 出现在非返回位置
    BadClassName,   ///< L';' 之间为空或含 '.' '[' ';'
    BadMethodShape, ///< 方法描述符不以 '(' 开头
    NestingTooDeep, ///< 数组维数超过 255
};

/// @brief 错误码的可读文本。
const char* to_string(DescError e) noexcept;

/// @brief 基类型原子。
enum class BaseType : ca::u8 {
    Byte,
    Char,
    Double,
    Float,
    Int,
    Long,
    Short,
    Boolean,
};

/// @brief 一个字段/参数/返回类型（数组扁平表示：叶子 + 维数）。
///
/// @ref class_name 指向输入串；输入失效即视图失效。`[[I` 解析为
/// kind=Primitive、primitive=Int、array_dims=2。
struct TypeDesc
{
    enum class Kind : ca::u8 { Primitive, Class };

    Kind kind = Kind::Primitive;
    BaseType primitive = BaseType::Int;  ///< kind==Primitive 时有效
    std::string_view class_name;         ///< kind==Class：内部名，不含 L/;
    ca::u32 array_dims = 0;

    bool isArray() const noexcept { return array_dims != 0; }
    bool isClass() const noexcept { return kind == Kind::Class; }
};

/// @brief 解析字段类型描述符（不接受 V）。
Result<TypeDesc, DescError> parseFieldType(std::string_view descriptor) noexcept;

/// @brief 方法描述符：参数顺序保持，返回类型单独表达 void。
struct MethodDesc
{
    std::vector<TypeDesc> params;
    bool ret_void = false;
    TypeDesc ret;  ///< ret_void==false 时有效
};

/// @brief 解析方法描述符 `(参数)返回`。
Result<MethodDesc, DescError> parseMethodDescriptor(std::string_view descriptor);

/// @brief 是否是一个完整的字段类型描述符（不接受 V）。
bool isValidFieldType(std::string_view descriptor) noexcept;

}   // namespace dex::type
