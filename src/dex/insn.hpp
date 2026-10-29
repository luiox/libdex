/// @file        insn.hpp
/// @brief       code_item.insns 的指令 DOM：逐条解码为定长结构。
///
/// 解码只做边界与形状：每条指令的地址、宽度、寄存器操作数、索引、立即数与
/// 分支偏移；控制流、栈帧与类型推导留给上层。payload 伪指令不展开成 target
/// 数组，而是保留指向源字节的零拷贝视图，调用方按索引取值。
///
/// 与 @ref DexFile 的 lazy 视图不同，本接口不持有源字节：传入的 ByteSlice 必须
/// 在 @ref Insn 使用期内有效（通常就是 DexFile 的 source()）。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"

#include "dex/bytes.hpp"
#include "dex/opcode.hpp"

namespace dex::core {

/// @brief 指令流解码失败原因。
enum class InsnError {
    Ok = 0,
    Truncated,       ///< 指令区在一条指令中间结束
    UnknownOpcode,   ///< dex-format 未定义的操作码
    BadPayload,      ///< payload 落在奇地址，或元素宽度/大小自相矛盾
};

/// @brief 错误码的可读文本。
const char* to_string(InsnError e) noexcept;

/// @brief 指令编码失败原因。
///
/// 编码只做「按该 opcode 的定长格式逐位写入」，不做形态提升或合并：
/// `const/4` 不会自动改成 `const/16`，`const-string` 不会自动改成 jumbo。
/// 形态选择是调用方（adapter）的职责。
enum class InsnEncodeError {
    Ok = 0,
    BadFormat,          ///< 未定义操作码，或 format 字段与 opcode 的格式不符
    OperandOverflow,    ///< 寄存器、索引、立即数或分支偏移超出该格式的域宽
    BadPayload,         ///< payload 的计数与载荷数据长度不一致
    MisalignedPayload,  ///< payload 落在奇 code unit 地址
};

/// @brief 错误码的可读文本。
const char* to_string(InsnEncodeError e) noexcept;

/// @brief 单条 DEX 指令（含 payload 伪指令）。
///
/// 寄存器操作数统一放在 @ref registers，@ref registerCount 表示有效个数：
///   - 普通格式按格式文档的 A/B/C 顺序填入（最多 3 个）；
///   - 35c/45cc 按调用参数顺序填 C、D、E、F、G，最多 5 个；
///   - 3rc/4rcc 不使用该数组，改用 @ref startRegister 与 @ref registerCount。
struct Insn
{
    ca::u32 address = 0;  ///< 相对 insns 起点的 code unit 地址
    ca::u32 width = 0;    ///< 占用 code unit 数（payload 为实际长度）
    ca::u8 opcode = 0;
    InsnFormat format = InsnFormat::Unknown;
    IndexKind indexKind = IndexKind::None;
    PayloadKind payloadKind = PayloadKind::None;

    ca::u8 registerCount = 0;
    ca::u16 registers[5] = {0, 0, 0, 0, 0};
    ca::u16 startRegister = 0;

    ca::u32 index = 0;           ///< 按 @ref indexKind 解释的全局表索引
    ca::u32 protoIndex = 0;      ///< 仅 45cc/4rcc 使用
    bool hasProtoIndex = false;

    /// @brief 立即数；21h 已按 opcode 左移 16 或 48 位。
    ca::i64 literal = 0;

    /// @brief 分支偏移（code unit，相对本指令地址）；31t 指向 payload。
    ca::i32 branchOffset = 0;

    ca::u32 payloadCount = 0;        ///< switch 条目数 / 数组元素数
    ca::i32 payloadFirstKey = 0;     ///< 仅 packed-switch
    ca::u16 payloadElementWidth = 0; ///< 仅 fill-array-data
    ByteSlice payloadData{};         ///< packed/sparse 的条目区；fill 的原始数据

    /// @brief 本条指令的原始 code unit 字节（width*2），借用入参。
    ///
    /// 保留原字节而不是只留语义字段：ART 接受高字节非零的 nop 变体，
    /// 只按语义重编码会丢掉这些字节；后续编码器据此判断可否原样写回。
    ByteSlice raw{};

    bool isPayload() const noexcept { return format == InsnFormat::Payload; }

    /// @brief 是否为带分支偏移的指令（含 31t 的三类）。
    bool isBranch() const noexcept
    {
        switch (format) {
        case InsnFormat::F10t:
        case InsnFormat::F20t:
        case InsnFormat::F30t:
        case InsnFormat::F21t:
        case InsnFormat::F22t:
        case InsnFormat::F31t:
            return true;
        default:
            return false;
        }
    }

    /// @brief packed-switch 第 i 个 target（相对 switch 指令的偏移）。
    ///        调用方保证 payloadKind == PackedSwitch 且 i < payloadCount。
    ca::i32 packedSwitchTarget(ca::u32 i) const noexcept;

    /// @brief sparse-switch 第 i 个 case key。调用方保证边界同 packedSwitchTarget。
    ca::i32 sparseSwitchKey(ca::u32 i) const noexcept;

    /// @brief sparse-switch 第 i 个 target（相对 switch 指令的偏移）。
    ca::i32 sparseSwitchTarget(ca::u32 i) const noexcept;
};

/// @brief 解码整个 insns 区。
///
/// 规范标识 0x0100/0x0200/0x0300 的偶数地址 code unit 识别为 payload；
/// 低字节为 0、高字节非 payload 标识的 code unit 按 ART 的宽容度当作 nop
/// （宽度 1）。
Result<std::vector<Insn>, InsnError> decodeInsns(ByteSlice insns);

/// @brief 按 opcode 的定长格式精确编码一条指令，追加到 @p out。
///
/// 只写该操作码对应的格式，不做形态选择。10x/20t/30t/32x 的未用高位在
/// @ref Insn::raw 与当前 opcode 一致时原样沿用，保证 nop 变体等源字节可还原；
/// payload 由 @ref Insn::payloadData 与计数字段重写。
///
/// @warning 单条编码不知道流位置，payload 的偶数地址约束由
///          @ref encodeInsns 检查；直接调用本函数时由调用方保证。
Result<void, InsnEncodeError> encodeInsn(const Insn& insn, std::vector<ca::u8>& out);

/// @brief 按给定顺序精确编码整条指令流（含 payload）。
///
/// payload 必须落在偶数 code unit 地址（@p out 的字节偏移为 4 的倍数），
/// 否则返回 Err(MisalignedPayload)，不自动插入 nop 填充。
Result<std::vector<ca::u8>, InsnEncodeError> encodeInsns(const std::vector<Insn>& insns);

}   // namespace dex::core
