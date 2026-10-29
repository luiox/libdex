/// @file        disassemble.hpp
/// @brief       libsmali 反汇编器：DexFile → smali 文本。
///
/// 文法是 baksmali 的可读子集加少量本库方言（有意偏离处均以确定性往返为
/// 目标，见 doc/design.md「分层」）：
///   - payload 用 `.packed-switch/.sparse-switch/.fill-array-data` 指令块，
///     就地渲染在指令流里 payload 所在的位置；
///   - 注解块 `.annotation <visibility> <type>`，元素 `name = value`；
///   - 参数注解 `.parameter-annotation <index> <visibility>` 块；
///   - debug 投影：.line/.local/.end local/.restart local/.prologue/
///     .epilogue/.file/.params；浮点字面量按位模式 `0x<bits>F/D`。
///
/// 每个类一段文本（一个 .smali 文件）；label 名由地址决定（`:l<addr>`），
/// 反汇编→汇编→反汇编的文本是逐字节确定的。
#pragma once

#include <string>
#include <utility>
#include <vector>

#include "libca/core/result.hpp"

#include "dex/dex_file.hpp"

namespace dex::smali {

using core::Result;

/// @brief 文本层失败原因。
enum class SmaliError {
    Ok = 0,
    BadIndex,     ///< 引用了不存在的表条目（模型被外部改动）
    SourceUnreadable, ///< lazy 条目解码失败
    Unencodable,  ///< 渲染不了的结构（如超宽寄存器）
};

/// @brief 错误码的可读文本。
const char* to_string(SmaliError e) noexcept;

/// @brief 反汇编一个类。输出即一个 .smali 文件的全部内容（UTF-8）。
///        入参非 const：反汇编按需填充 lazy 缓存（同 buildDex 的约定）。
Result<std::string, SmaliError> disassembleClass(core::DexFile& dex,
                                                 ca::u32 classDefIdx);

/// @brief 反汇编整份 dex 的全部类；返回 (文件名, 内容) 列表，文件名取
///        `<描述符去掉 L;>/smali` 形态（`Ljava/lang/Object;` →
///        `java/lang/Object.smali`）。
Result<std::vector<std::pair<std::string, std::string>>, SmaliError> disassembleAll(
    core::DexFile& dex);

}   // namespace dex::smali
