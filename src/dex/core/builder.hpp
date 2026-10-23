/// @file        builder.hpp
/// @brief       整文件 canonical 重建：布局、偏移回填、map_list 与校验字段。
///
/// 与 @ref writeDex 的分工：`writeDex` 是未修改透传（源字节原样交回），
/// `buildDex` 是把 DOM 重新排布成一份新 dex。后者的输入必须是可完整解码的
/// 文件；重建只输出从 class_defs 可达的条目，不可达的建模条目被丢弃。
///
/// 重建保持的保真项：string_data 与 type_list 原字节复制（含非最小 ULEB、
/// 共享 type_list）、encoded_value 的 value_arg 宽度、debug_info 的原始
/// 操作编码、handler 共享、method_handle 的 unused 字段，以及未建模 section
/// 的原始字节（可由 @ref BuildOptions::keepUnknownSections 关闭）。
///
/// 重建不做的事：不校验 ID 表的排序约定，不校验 MUTF-8 码点，不推断未知
/// section 内部是否含文件偏移。unknown section 的偏移按原字节透传，若其中
/// 含指向其他 section 的绝对偏移，重建后不会回填。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/core/dex_file.hpp"
#include "dex/core/error.hpp"

namespace dex::core {

/// @brief 一个方法体的替换内容。
///
/// @ref methodIdx 指向 method_ids；该方法必须在某个 class_data 中有非零
/// code_off。@ref item 的 tries/catchHandlers 按 @ref writeCodeItem 的约定
/// 使用，@ref DebugInfo 的 `debugInfoOff` 解释为**源文件中的偏移**，重建时
/// 重映射到新位置；置 0 表示替换后的方法没有 debug_info。
struct CodeReplacement
{
    ca::u32 methodIdx = 0;
    CodeItem item;
    std::vector<ca::u8> insns;  ///< 已编码指令区，长度必须是 item.insnsSize * 2
};

/// @brief 整文件重建选项。
struct BuildOptions
{
    std::vector<CodeReplacement> codeReplacements;
    bool keepUnknownSections = true;  ///< 保留未建模 map section 的原始字节
};

/// @brief 把 DOM 重建为一份 canonical 布局的 .dex 字节。
///
/// 输出布局：header、五张 ID 表、class_defs、call_site_ids、method_handles、
/// 然后是 string_data、type_list、encoded_array、annotation_item、
/// annotation_set、annotation_set_ref_list、annotations_directory、debug_info、
/// code_item、class_data、unknown sections、map_list。所有模型内偏移按新布局
/// 回填，checksum/signature 重算。
///
/// 失败原因见 @ref WriteError：版本 041（container 语义未冻结）或非空 link
/// 区返回 `NotModeled`；重建期间再次解码源条目失败返回 `SourceUnreadable`；
/// 替换项指向不存在或无可替换方法体的方法返回 `InvalidModel`；条目超出编码
/// 域宽返回 `Unencodable`。返回 Err 时输出字节一律作废。
///
/// 重建会按需解码 string_data/class_data/code_item/注解等条目并填充
/// @ref DexFile 的 lazy 缓存，因此入参是非 const 引用；语义上不修改文件内容。
Result<std::vector<ca::u8>, WriteError> buildDex(DexFile& dex,
                                                 const BuildOptions& options = {});

}   // namespace dex::core
