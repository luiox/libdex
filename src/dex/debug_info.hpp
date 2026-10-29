/// @file        debug_info.hpp
/// @brief       debug_info_item 的结构解码与精确重编码。
///
/// debug_info 是寄存器/行号状态机的字节码。模型保留每条状态机操作码的原始
/// 字节（special 区间不归一化），操作数以解码值保存；`raw` 覆盖从
/// line_start 到 END_SEQUENCE 的完整源区间。写回时按 opcode 重写操作数并
/// 自动补 END_SEQUENCE，不合并 special 形态。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/bytes.hpp"

namespace dex::core {

inline constexpr ca::u8 kDbgEndSequence = 0x00;
inline constexpr ca::u8 kDbgAdvancePc = 0x01;
inline constexpr ca::u8 kDbgAdvanceLine = 0x02;
inline constexpr ca::u8 kDbgStartLocal = 0x03;
inline constexpr ca::u8 kDbgStartLocalExtended = 0x04;
inline constexpr ca::u8 kDbgEndLocal = 0x05;
inline constexpr ca::u8 kDbgRestartLocal = 0x06;
inline constexpr ca::u8 kDbgSetPrologueEnd = 0x07;
inline constexpr ca::u8 kDbgSetEpilogueBegin = 0x08;
inline constexpr ca::u8 kDbgSetFile = 0x09;
inline constexpr ca::u8 kDbgFirstSpecial = 0x0A;
inline constexpr ca::i32 kDbgLineBase = -4;
inline constexpr ca::u32 kDbgLineRange = 15;

/// @brief special 操作码携带的地址增量。
inline ca::u32 debugSpecialAddressDiff(ca::u8 opcode) noexcept
{
    return static_cast<ca::u32>(opcode - kDbgFirstSpecial) / kDbgLineRange;
}

/// @brief special 操作码携带的行号增量。
inline ca::i32 debugSpecialLineDiff(ca::u8 opcode) noexcept
{
    return kDbgLineBase +
           static_cast<ca::i32>(static_cast<ca::u32>(opcode - kDbgFirstSpecial) %
                                kDbgLineRange);
}

/// @brief 一条状态机操作；字段按 @ref opcode 解释。
struct DebugOp
{
    ByteSlice raw{};          ///< 该操作在源字节中的原始编码；空表示按字段重编码
    ca::u8 opcode = 0;        ///< 原始操作码（0x0A..0xFF 为 special）
    ca::u32 addressDiff = 0;  ///< ADVANCE_PC / special
    ca::i32 lineDiff = 0;     ///< ADVANCE_LINE / special
    ca::u32 reg = 0;          ///< START_LOCAL / END_LOCAL / RESTART_LOCAL
    ca::u32 nameIdx = 0;      ///< START_LOCAL / START_LOCAL_EXTENDED / SET_FILE
    ca::u32 typeIdx = 0;      ///< START_LOCAL / START_LOCAL_EXTENDED
    ca::u32 sigIdx = 0;       ///< START_LOCAL_EXTENDED

    bool isSpecial() const noexcept { return opcode >= kDbgFirstSpecial; }
};

/// @brief 单个 debug_info_item。
///
/// @ref headerRaw 与 @ref DebugOp::raw 借用源字节，生命周期随 DexFile 或
/// 解码入参 `ByteSlice`；它们非空时写回原样 copy，清空后按字段重编码。
struct DebugInfo
{
    ByteSpan raw;           ///< line_start 到 END_SEQUENCE（含）
    ByteSlice headerRaw{};  ///< line_start + 参数名的原始编码；空表示按字段重编码
    ca::u32 lineStart = 0;
    std::vector<ca::u32> parameterNames;
    std::vector<DebugOp> ops;  ///< 不含 END_SEQUENCE；写回时自动补 0x00
};

/// @brief 读取 debug_info_item；offset 是条目起始。
Result<DebugInfo, ReadError> readDebugInfo(ByteSlice source, ca::u32 offset);

/// @brief 精确重编码 debug_info_item（含末尾 END_SEQUENCE）。
///
/// 解码产生的条目保留 header 与每条操作的原始字节；这些 raw 视图非空时
/// 原样写回（包括非最小 ULEB/SLEB），否则按字段重编码。要修改一条已解码
/// 操作，先清空它的 `raw`；要修改 header，先清空 `headerRaw`。
/// special 操作码在按字段重编码时要求 addressDiff/lineDiff 与 opcode 自洽；
/// ops 中出现 END_SEQUENCE 视为模型错误，返回 Err(WriteError::Unencodable)。
Result<std::vector<ca::u8>, WriteError> writeDebugInfo(const DebugInfo& info);

}   // namespace dex::core
