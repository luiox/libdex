/// @file        opcodes.hpp
/// @brief       libsmali 共享表：opcode ↔ 助记符、格式与 access flags。
///
/// 表覆盖 libdex 指令层的全部定义操作码（26 格式 + 3 payload）。助记符是
/// baksmali 同名拼写；libsmali 的文法以反汇编器自产文本为准做往返封闭，
/// 与 baksmali 的输出在个别方言点（payload 指令、注解元素名）有意不同。
#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "libca/core/datatype.hpp"

#include "dex/core/opcode.hpp"

namespace dex::smali {

/// @brief 一条助记符记录：字节 → 拼写与格式。
struct Mnemonic
{
    ca::u8 opcode;
    const char* name;
    core::InsnFormat format;
};

/// @brief 按 opcode 查表；未定义返回 nullopt。
std::optional<Mnemonic> mnemonicOf(ca::u8 opcode) noexcept;

/// @brief 按助记符查表（精确匹配）；未定义返回 nullopt。
std::optional<Mnemonic> opcodeOf(std::string_view name) noexcept;

// ---- access flags（smali 拼写 ↔ 位）----

/// @brief 按 smali 关键字查类/字段/方法共用位表；未知返回 nullopt。
std::optional<ca::u32> accessFlagOf(std::string_view keyword) noexcept;

/// @brief 位的 smali 拼写；未知名返回空串。
std::string_view accessFlagName(ca::u32 bit) noexcept;

/// @brief 把 access flags 渲染成空格分隔的关键字序列（按固定顺序）。
std::string renderAccessFlags(ca::u32 flags);

}   // namespace dex::smali
