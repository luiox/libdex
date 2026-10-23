/// @file        annotation.hpp
/// @brief       注解族数据条目：annotation_item / annotation_set_item /
///              annotation_set_ref_list / annotations_directory_item /
///              encoded_array_item。
///
/// 每个条目保留自己在源字节中的完整区间 @ref ByteSpan raw，与 libjbc 的
/// 属性槽同族：未修改时写回可以 copy 这段字节，保真不依赖重编码器正确。
/// 条目内部只解到结构层，值树由 @ref EncodedValue 承载；目录里的 set 偏移
/// 与 set 里的 annotation 偏移都原样保留，供调用方按需继续解码。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/core/bytes.hpp"
#include "dex/core/encoded_value.hpp"

namespace dex::core {

/// @brief annotation_item.visibility（dex-format 中 0/1/2）。
///
/// 解码不拒绝未知取值：模型保存原始 u8，枚举只给已定义值命名。
enum class AnnotationVisibility : ca::u8 {
    Build = 0,
    Runtime = 1,
    System = 2,
};

/// @brief 可见性取值的可读文本；未知值返回 "unknown"。
const char* to_string(AnnotationVisibility visibility) noexcept;

/// @brief annotation_item：可见性 + 一个 encoded_annotation。
struct AnnotationItem
{
    ByteSpan raw;            ///< 可见性字节到注解体末尾
    ca::u8 visibility = 0;   ///< 原始 visibility，不做拒绝
    EncodedAnnotation annotation;
};

/// @brief annotation_set_item：一组 annotation_item 的文件偏移。
struct AnnotationSetItem
{
    ByteSpan raw;
    std::vector<ca::u32> annotationOffs;
};

/// @brief annotation_set_ref_list：参数维的一组 annotation_set 偏移。
struct AnnotationSetRefList
{
    ByteSpan raw;
    std::vector<ca::u32> annotationSetOffs;
};

/// @brief annotations_directory_item 的一行：成员索引 + 注解集偏移。
struct AnnotationsDirectoryEntry
{
    ca::u32 memberIdx = 0;      ///< field_idx 或 method_idx
    ca::u32 annotationsOff = 0; ///< annotation_set_item 偏移
};

/// @brief annotations_directory_item：类、字段、方法、参数四级注解入口。
struct AnnotationsDirectory
{
    ByteSpan raw;
    ca::u32 classAnnotationsOff = 0;
    std::vector<AnnotationsDirectoryEntry> fieldAnnotations;
    std::vector<AnnotationsDirectoryEntry> methodAnnotations;
    std::vector<AnnotationsDirectoryEntry> parameterAnnotations;
};

/// @brief encoded_array_item：静态字段初值等场景的编码数组。
struct EncodedArrayItem
{
    ByteSpan raw;
    std::vector<EncodedValue> values;
};

/// @brief 读取 annotation_item；offset 是条目起始。
Result<AnnotationItem, ReadError> readAnnotationItem(ByteSlice source, ca::u32 offset);

/// @brief 读取 annotation_set_item；只解偏移表，不递归条目。
Result<AnnotationSetItem, ReadError> readAnnotationSet(ByteSlice source, ca::u32 offset);

/// @brief 读取 annotation_set_ref_list；只解偏移表。
Result<AnnotationSetRefList, ReadError> readAnnotationSetRefList(ByteSlice source,
                                                                 ca::u32 offset);

/// @brief 读取 annotations_directory_item；只解目录，不递归 set。
Result<AnnotationsDirectory, ReadError> readAnnotationsDirectory(ByteSlice source,
                                                                ca::u32 offset);

/// @brief 读取 encoded_array_item；元素按 encoded_value 全量解码。
Result<EncodedArrayItem, ReadError> readEncodedArrayItem(ByteSlice source, ca::u32 offset);

/// @brief 按条目字段精确重编码一个 annotation_item。
Result<std::vector<ca::u8>, WriteError> writeAnnotationItem(const AnnotationItem& item);

/// @brief 按条目字段精确重编码一个 annotation_set_item。
Result<std::vector<ca::u8>, WriteError> writeAnnotationSet(const AnnotationSetItem& item);

/// @brief 按条目字段精确重编码一个 annotation_set_ref_list。
Result<std::vector<ca::u8>, WriteError> writeAnnotationSetRefList(
    const AnnotationSetRefList& item);

/// @brief 按条目字段精确重编码一个 annotations_directory_item。
Result<std::vector<ca::u8>, WriteError> writeAnnotationsDirectory(
    const AnnotationsDirectory& item);

/// @brief 按条目字段精确重编码一个 encoded_array_item。
Result<std::vector<ca::u8>, WriteError> writeEncodedArrayItem(const EncodedArrayItem& item);

}   // namespace dex::core
