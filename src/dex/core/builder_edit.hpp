/// @file        builder_edit.hpp
/// @brief       buildDex 的编辑应用层：canonical 与增量布局共享的编辑校验与合成。
///
/// @ref buildDex 的两条布局路径对「编辑是什么」必须给出同一答案：成员增删与
/// 标志覆盖构成的有效 class_data、静态初值的合成、注解覆盖与源目录的合并。
/// 本头把这些与布局无关的编辑语义集中在一处，canonical 路径与
/// @ref BuildOptions::incremental 路径共用，保证两条产物语义一致。
#pragma once

#include <map>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/core/annotation.hpp"
#include "dex/core/builder.hpp"
#include "dex/core/dex_file.hpp"
#include "dex/core/encoded_value.hpp"
#include "dex/core/error.hpp"

namespace dex::core {

/// @brief 注解合成键的基址：源偏移与合成键以 0x60000000 为界。
/// @{

/// @brief 布局路径的合成键分配规则（见 @ref AnnotationPlan）。
inline constexpr ca::u32 kOwnedItemKeyBase = 0x50000000u;
inline constexpr ca::u32 kOwnedSetKeyBase = 0x60000000u;
inline constexpr ca::u32 kOwnedRefListKeyBase = 0x70000000u;
inline constexpr ca::u32 kOwnedDirectoryKeyBase = 0x78000000u;
/// @}

/// @brief 成员编辑的校验结果与规范化集合。
///
/// `classDataEdits` 只覆盖被注入新成员的类：内容是源 class_data 的副本加新
/// 成员（新方法 code_off 为占位 1，布局后回填）；未被编辑的类不在 map 中，
/// 发射时直接用源 class_data。
struct MemberEditSet
{
    std::unordered_map<ca::u32, const CodeReplacement*> replacements;
    std::unordered_set<ca::u32> removedFields;
    std::unordered_set<ca::u32> removedMethods;
    std::unordered_map<ca::u32, std::vector<const FieldAddition*>> fieldsByClass;
    std::unordered_map<ca::u32, std::vector<const MethodAddition*>> methodsByClass;
    std::unordered_map<ca::u32, ca::u32> fieldFlagEdits;
    std::unordered_map<ca::u32, ca::u32> methodFlagEdits;
    std::unordered_set<ca::u32> definedFields;    ///< 源 class_data 定义的字段
    std::unordered_set<ca::u32> definedMethods;   ///< 源 class_data 定义的方法
    std::unordered_set<ca::u32> methodsWithCode;  ///< 有非零 code_off 的方法
    std::map<ca::u32, ClassData> classDataEdits;  ///< 注入成员后的逐类 class_data
};

/// @brief 解码全部源 class_data，按旧偏移去重（多个 class_def 可共享）。
Result<std::map<ca::u32, const ClassData*>, WriteError> collectSourceClassData(DexFile& dex);

/// @brief 校验 BuildOptions 中的成员编辑并构建逐类注入后的 class_data。
///
/// @p classDataByOff 来自 @ref collectSourceClassData。重复定义、索引越界、
/// 替换与删除冲突、标志编辑指向未定义成员等都返回 `InvalidModel`。
Result<MemberEditSet, WriteError> collectMemberEdits(
    const DexFile& dex, const BuildOptions& options,
    const std::map<ca::u32, const ClassData*>& classDataByOff);

/// @brief 应用移除与标志覆盖（含方法 direct/virtual 分组搬移）。
///
/// 只改成员列表内容：不重排索引、不回填 code_off，排序与索引映射归调用方
/// 的布局路径。字段改 static 位返回 `InvalidModel`。
Result<void, WriteError> applyMemberEdits(ClassData& data, const MemberEditSet& edits);

/// @brief 计算一个类编辑后的静态初值数组。
///
/// 返回 nullopt 表示该类无需重建（无新增静态字段、无删除、无显式赋值），
/// 布局路径透传源数组。槽位顺序按 @p fieldRemap 给出的键排序（null = 源
/// 索引序）；新增字段与被省略的尾部槽位填类型默认值，显式赋值优先于源值。
Result<std::optional<EncodedArrayItem>, WriteError> synthesizeStaticValues(
    DexFile& dex, ca::u32 classDefIdx, const ClassData* original,
    const std::vector<ca::u32>& addedStatic, const MemberEditSet& edits,
    const std::vector<ca::u32>* fieldRemap);

/// @brief 注解合并的结果：逐类生效目录与自有 set/ref_list 的键分配。
struct EffectiveDirectory
{
    bool overridden = false;       ///< 有自有覆盖，目录按合成键发射
    bool effectivelyEmpty = true;  ///< 覆盖后无任何内容（不发射目录）
    AnnotationsDirectory content;
};

/// @brief 注解族的编辑计划（布局无关）。
struct AnnotationPlan
{
    std::vector<EffectiveDirectory> dirs;  ///< 按 classDefIdx
    /// 合成 set 键 → 注解项池下标列表；键空间由布局路径定义。
    std::map<ca::u32, const std::vector<ca::u32>*> ownedSetItems;
    /// 合成 ref_list 键 → 每参数一个 set 键（0 表示该参数无注解）。
    std::map<ca::u32, std::vector<ca::u32>> ownedRefListSets;
    std::map<ca::u32, const AnnotationsDirectory*> directories;  ///< 源目录按偏移
};

/// @brief 合并源注解目录与 @ref DexFile 的覆盖表，产出逐类生效目录。
///
/// 校验覆盖目标在生效 class_data（含注入成员、扣除删除）中有定义、参数
/// 注解个数与 proto 一致；与 `stripAnnotations` 同时使用返回 `InvalidModel`。
Result<AnnotationPlan, WriteError> planAnnotations(DexFile& dex,
                                                   const BuildOptions& options,
                                                   const MemberEditSet& memberEdits,
                                                   const std::map<ca::u32,
                                                                  const ClassData*>&
                                                       classDataByOff);

}   // namespace dex::core
