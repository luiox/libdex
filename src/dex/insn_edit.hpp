/// @file        insn_edit.hpp
/// @brief       指令编辑原语：分支目标、寄存器域、地址重算与 payload 构造。
///
/// 这是 adapter 层的原语面：按调用方给定的形态与域宽精确改写指令字段，
/// 不做形态提升或合并（design「指令」）。只需要解码/编码指令流的代码
/// include @ref insn.hpp 即可，不必见到这一层；analysis 就不依赖本文件。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"

#include "dex/bytes.hpp"
#include "dex/insn.hpp"

namespace dex::core {

/// @brief const 系列指令的编码形态。
enum class ConstForm : ca::u8 {
    Const4,
    Const16,
    Const,
    ConstHigh16,
    ConstWide16,
    ConstWide32,
    ConstWideHigh16,
    ConstWide,
};

/// @brief 有符号立即数能否用该形态精确表示。
///
/// 32 位形态按 `ca::i32` 解释；浮点常量先把位模式重解释为同宽有符号数再传入。
bool constFormFits(ConstForm form, ca::i64 value) noexcept;

/// @brief 该格式索引操作数的最大值；没有索引返回 0。
ca::u32 insnIndexLimit(InsnFormat format) noexcept;

/// @brief 分支目标地址（code unit）：`address + branchOffset`。
ca::i64 insnBranchTarget(const Insn& insn) noexcept;

/// @brief 让分支指令指向 @p target，按格式检查偏移域宽。
///
/// 非分支格式返回 BadFormat；target 与当前 address 的差超出该格式范围返回
/// OperandOverflow。31t 的 payload 对齐不在此检查。
Result<void, InsnEncodeError> setInsnBranchTarget(Insn& insn, ca::i64 target) noexcept;

/// @brief 按指令顺序重算 address。
///
/// 非 payload 的 width 按 opcode 的定长格式重设，payload 保留调用方给的 width。
/// 不修改 branchOffset：编辑指令后先记录目标下标，重算地址，再用
/// @ref setInsnBranchTarget 逐条恢复。总长度超出 u32 返回 OperandOverflow。
Result<void, InsnEncodeError> recomputeInsnAddresses(std::vector<Insn>& insns);

/// @brief 指令的寄存器布局形态。
enum class RegisterLayout : ca::u8 {
    None,   ///< 不含寄存器（分支、payload 等）
    List,   ///< @ref Insn::registers 前 registerCount 个逐个给出
    Range,  ///< @ref Insn::startRegister 起连续 registerCount 个
};

/// @brief 指令的寄存器布局；按格式静态决定，不依赖解码出的值。
RegisterLayout insnRegisterLayout(const Insn& insn) noexcept;

/// @brief 布局内的寄存器个数（None 为 0）。
ca::u32 insnRegisterTotal(const Insn& insn) noexcept;

/// @brief 第 i 个寄存器编号（i < @ref insnRegisterTotal；Range 返回 startRegister+i）。
ca::u16 insnRegisterAt(const Insn& insn, ca::u32 i) noexcept;

/// @brief 改 List 布局的第 i 个寄存器，按格式域宽校验。
///
/// 非 List 布局或 i 越界返回 BadFormat；reg 超出该槽的 4/8/16 位域宽返回
/// OperandOverflow。
Result<void, InsnEncodeError> setInsnRegister(Insn& insn, ca::u32 i, ca::u16 reg) noexcept;

/// @brief 改 Range 布局（3rc/4rcc）的寄存器区间。
///
/// start 占 16 位；count 占 8 位，超出返回 OperandOverflow。非 Range 布局
/// 返回 BadFormat。
Result<void, InsnEncodeError> setInsnRegisterRange(Insn& insn, ca::u16 start,
                                                   ca::u16 count) noexcept;

/// @brief 指令流占用的最大寄存器编号 +1；不含寄存器返回 0。
///
/// 改小 code_item.registers_size 前用它检查下界；不含对寄存器宽表
/// （payload 等）的语义校验。
ca::u32 insnRegisterCeiling(const std::vector<Insn>& insns) noexcept;

/// @brief 全部寄存器编号加 delta（插入/删除低位寄存器时平移）。
///
/// 结果越出 0..65535 或所在槽的格式域宽返回 OperandOverflow，流保持已改到
/// 出错处的状态。registers_size 不在此改，归调用方。
Result<void, InsnEncodeError> shiftInsnRegisters(std::vector<Insn>& insns,
                                                 ca::i32 delta) noexcept;

/// @brief 按 mapping[旧编号] = 新编号 重排全部寄存器。
///
/// List 布局逐槽查表；Range 布局要求映射在区间上是平移（mapping[start+k]
/// == mapping[start]+k），否则返回 BadFormat——不平移的重排需要改成 35c
/// 形态，归 adapter。旧编号超出 mapping 长度返回 OperandOverflow。
Result<void, InsnEncodeError> remapInsnRegisters(
    std::vector<Insn>& insns, const std::vector<ca::u16>& mapping) noexcept;

/// @brief 自包含的 payload 伪指令：storage 持有条目字节，insn.payloadData 指向其内部。
///
/// 把 insn 拼进指令流后须保持 storage 存活到编码完成；移动本结构不失效
/// （vector 移动保持分配）。
struct PayloadInsn
{
    std::vector<ca::u8> storage;
    Insn insn;
};

/// @brief 构造 packed-switch payload；targets 相对 switch 指令的 code unit 偏移。
///
/// 条目数超过 size 域宽（宽度 4+2n 个 unit ≤ 65535）返回 OperandOverflow。
Result<PayloadInsn, InsnEncodeError> makePackedSwitchPayload(
    ca::i32 firstKey, const std::vector<ca::i32>& targets);

/// @brief 构造 sparse-switch payload；keys 须严格递增（ART 按二分查找解释）。
///
/// keys 与 targets 个数不等返回 BadPayload，不递增返回 BadPayload，超宽返回
/// OperandOverflow。
Result<PayloadInsn, InsnEncodeError> makeSparseSwitchPayload(
    const std::vector<ca::i32>& keys, const std::vector<ca::i32>& targets);

/// @brief 构造 fill-array-data payload；data 长度必须是 elementWidth 的倍数。
///
/// elementWidth 为 0 且 data 非空返回 BadPayload；总宽度超出 size 域宽返回
/// OperandOverflow。
Result<PayloadInsn, InsnEncodeError> makeFillArrayDataPayload(
    ca::u16 elementWidth, std::vector<ca::u8> data);
}   // namespace dex::core
