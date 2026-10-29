/// @file        opcode.hpp
/// @brief       DEX 操作码与指令格式的静态元数据。
///
/// 元数据只描述编码形状：操作码名字、占用 code unit 数、索引类别。指令语义
/// （算术、调用分派、类型检查）不属于本库；上层需要的只是稳定的形状表。
///
/// 未被 dex-format 定义的操作码（0x3e–0x43、0x73、0x79–0x7a、0xe3–0xf9）
/// 保留为 format=Unknown 的条目，查询不抛异常、不返回空指针。
#pragma once

#include "libca/core/datatype.hpp"

namespace dex::core {

/// @brief instruction formats 全表（dex-format §instruction-formats）。
enum class InsnFormat : ca::u8 {
    Unknown = 0,
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F30t,
    F32x,
    F31i,
    F31t,
    F31c,
    F35c,
    F3rc,
    F45cc,
    F4rcc,
    F51l,
    /// @brief 伪指令（packed-switch / sparse-switch / fill-array-data payload）。
    Payload,
};

/// @brief 指令中的索引操作数指向哪张全局表。
enum class IndexKind : ca::u8 {
    None = 0,
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
};

/// @brief 单个操作码的静态描述。
struct OpcodeInfo
{
    const char* name = "unused";
    InsnFormat format = InsnFormat::Unknown;
    IndexKind indexKind = IndexKind::None;

    bool isDefined() const noexcept { return format != InsnFormat::Unknown; }
};

/// @brief 定长格式占用的 code unit 数；Unknown 与 Payload 返回 0（宽度由内容决定）。
ca::u32 insnWidth(InsnFormat format) noexcept;

/// @brief 查询操作码元数据；未定义操作码返回 name="unused" 的条目。
const OpcodeInfo& opcodeInfo(ca::u8 opcode) noexcept;

/// @brief 格式名（诊断与测试输出用）。
const char* to_string(InsnFormat format) noexcept;

}   // namespace dex::core
