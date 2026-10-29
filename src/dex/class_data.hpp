/// @file        class_data.hpp
/// @brief       class_data_item 的结构解码与精确重编码。
///
/// 解码只到目录层：字段/方法列表展开为绝对索引，方法体与 debug_info 保持
/// lazy，由 DexFile 按 code_off 继续解码。写回按四处列表顺序重编码并重新
/// 计算索引差分，不改变各组的相对顺序。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/bytes.hpp"
#include "dex/error.hpp"

namespace dex::core {

/// @brief class_data_item 的字段条目（索引已从差分展开为绝对值）。
struct EncodedField
{
    ca::u32 fieldIndex = 0;
    ca::u32 accessFlags = 0;
};

/// @brief class_data_item 的方法条目（code_off 保留为文件偏移）。
struct EncodedMethod
{
    ca::u32 methodIndex = 0;
    ca::u32 accessFlags = 0;
    ca::u32 codeOff = 0;  ///< 0 表示抽象/本地方法，无 code_item
};

/// @brief 单类的 class_data_item：字段与方法目录。
///
/// 解码只到目录层：方法体、debug_info、注解内容都保持 lazy。
struct ClassData
{
    ByteSpan raw;  ///< 源字节中的完整编码区间
    std::vector<EncodedField> staticFields;
    std::vector<EncodedField> instanceFields;
    std::vector<EncodedMethod> directMethods;
    std::vector<EncodedMethod> virtualMethods;
};

/// @brief 解析一个 class_data_item，不依赖 DexFile（按偏移发现用）。
///
/// @param source 整个 dex 的源字节；offset 是 class_data_item 起始。
/// @param fieldLimit/methodLimit 对成员索引做 BadClassData 上界闸门的表长。
Result<ClassData, ReadError> parseClassData(ByteSlice source, ca::u32 offset,
                                            ca::u32 fieldLimit, ca::u32 methodLimit);

/// @brief 精确重编码 class_data_item；字段/方法的索引差分由本函数计算。
///
/// 各组索引必须严格递增；否则返回 Err(WriteError::Unencodable)。写回顺序
/// 与模型中的四处列表一致（static/instance fields、direct/virtual methods）。
Result<std::vector<ca::u8>, WriteError> writeClassData(const ClassData& data);

}   // namespace dex::core
