/// @file        encoded_value.hpp
/// @brief       encoded_value / encoded_annotation 的递归 DOM 与读取。
///
/// 注解、静态字段初值、注解默认值都走这套编码。值的类型与载荷长度由首字节
/// 的 type/value_arg 决定；数组与注解递归。解析按值拥有内容，不借用源字节。
#pragma once

#include <memory>
#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/core/bytes.hpp"
#include "dex/core/error.hpp"

namespace dex::core {

/// @brief encoded_value 的类型码（首字节低 5 位）。
enum class EncodedValueType : ca::u8 {
    Byte = 0x00,
    Short = 0x02,
    Char = 0x03,
    Int = 0x04,
    Long = 0x06,
    Float = 0x10,
    Double = 0x11,
    MethodType = 0x15,
    MethodHandle = 0x16,
    String = 0x17,
    Type = 0x18,
    Field = 0x19,
    Method = 0x1A,
    Enum = 0x1B,
    Array = 0x1C,
    Annotation = 0x1D,
    Null = 0x1E,
    Boolean = 0x1F,
};

/// @brief 类型码的可读文本。
const char* to_string(EncodedValueType type) noexcept;

struct EncodedAnnotation;

/// @brief 单个编码值；按 @ref type 解释相应载荷。
///
/// @ref valueArg 保留原始首字节的高 3 位。解码不按最小值归一化：DEX 允许
/// 非最小宽度，重编码按原宽度写出才能保证字节一致。新建值应通过
/// @ref writeEncodedValue 的域宽检查，超宽返回 Unencodable 而不是静默截断。
struct EncodedValue
{
    EncodedValueType type = EncodedValueType::Null;
    ca::u8 valueArg = 0;  ///< 原始首字节高 3 位（载荷宽度 - 1）

    ca::i64 integer = 0;  ///< Byte/Short/Int/Long（符号扩展后）
    ca::u64 bits = 0;     ///< Char 零扩展值，或 Float/Double 的位模式
    ca::u32 index = 0;    ///< String/Type/Field/Method/Enum/MethodType/MethodHandle
    bool boolean = false;

    std::vector<EncodedValue> array;
    std::unique_ptr<EncodedAnnotation> annotation;

    EncodedValue() noexcept = default;
    EncodedValue(const EncodedValue& other);             ///< 深拷贝注解子树
    EncodedValue& operator=(const EncodedValue& other);  ///< 深拷贝注解子树
    EncodedValue(EncodedValue&&) noexcept;
    EncodedValue& operator=(EncodedValue&&) noexcept;
    ~EncodedValue();

    bool isArray() const noexcept { return type == EncodedValueType::Array; }
    bool isAnnotation() const noexcept { return type == EncodedValueType::Annotation; }

    /// @brief 原始首字节：低 5 位类型码，高 3 位 value_arg。
    ca::u8 header() const noexcept
    {
        return static_cast<ca::u8>(static_cast<ca::u8>(type) | (valueArg << 5));
    }
};

/// @brief encoded_annotation 的一个元素：名字 string 索引 + 值。
struct AnnotationElement
{
    ca::u32 nameIdx = 0;
    EncodedValue value;
};

/// @brief encoded_annotation：类型索引 + 元素列表。
struct EncodedAnnotation
{
    ca::u32 typeIdx = 0;
    std::vector<AnnotationElement> elements;
};

/// @brief 数组/注解允许的最大嵌套层数。
inline constexpr ca::u32 kMaxValueDepth = 256;

/// @brief 读取一个 encoded_value；depth 是当前嵌套层数。
Result<EncodedValue, ReadError> readEncodedValue(Reader& cur, ca::u32 depth = 0) noexcept;

/// @brief 读取一个 encoded_annotation；depth 含义同 @ref readEncodedValue。
Result<EncodedAnnotation, ReadError> readEncodedAnnotation(Reader& cur,
                                                           ca::u32 depth = 0) noexcept;

/// @brief 按 @ref EncodedValue::valueArg 记录的宽度重编码一个值。
///
/// 载荷超出所记宽度、布尔与 value_arg 不一致、或类型码未定义时返回
/// Err(WriteError::Unencodable)，不静默截断。解码后原样调用本函数必须
/// 逐字节还原源编码（包括非最小宽度）。
Result<std::vector<ca::u8>, WriteError> writeEncodedValue(const EncodedValue& value);

/// @brief 编码一个 encoded_array_item 的主体（uleb 计数 + 各值）。
///
/// 解码后原样调用必须逐字节还原源编码；静态初值与 call_site 都走这一形态。
Result<std::vector<ca::u8>, WriteError> writeEncodedArray(
    const std::vector<EncodedValue>& values);

/// @brief 编码一个 encoded_annotation（不含量值字节 visibility）。
Result<std::vector<ca::u8>, WriteError> writeEncodedAnnotation(
    const EncodedAnnotation& annotation);

}   // namespace dex::core
