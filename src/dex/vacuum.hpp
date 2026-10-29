/// @file        vacuum.hpp
/// @brief       ID 表引用闭包：计算 vacuum 重写需要保留的条目集合。
///
/// vacuum 语义：以 class_defs（全部保留）为根，沿类定义、注解、静态初值、
/// 方法体指令、debug 信息、method_handle/call_site 展开引用闭包；未被闭包
/// 覆盖的 string_ids/type_ids/proto_ids/field_ids/method_ids 条目在 canonical
/// 重建中被剔除，全部引用点按新索引重写。与 BuildOptions::vacuumIds 配合。
#pragma once

#include <vector>

#include "dex/dex_file.hpp"

namespace dex::core {

struct MemberEditSet;

/// @brief 五张 ID 表的保留标记；class_defs 不参与（全保留）。
struct VacuumKeep
{
    std::vector<bool> strings;
    std::vector<bool> types;
    std::vector<bool> protos;
    std::vector<bool> fields;
    std::vector<bool> methods;
};

/// @brief 计算引用闭包。@p edits 非空时同时铺开编辑层根（新增方法体/字段、
/// 代码替换、自有注解与静态初值覆盖）。失败返回 SourceUnreadable（源条目
/// 解码失败）或 InvalidModel（索引悬垂）。
Result<VacuumKeep, WriteError> computeVacuumClosure(DexFile& dex,
                                                    const MemberEditSet* edits = nullptr);

}   // namespace dex::core
