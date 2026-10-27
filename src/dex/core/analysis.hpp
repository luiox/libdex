/// @file        analysis.hpp
/// @brief       分析层：CFG 构建（从解码指令流）+ 逐指令到达帧。
///
/// 帧域是寄存器类型/宽度的格：cat1（IntLike/Float/Null）与 cat2（Long/
/// Double）按半寄存器配对，引用带 type_idx（不同引用相遇归并为引用顶）。
/// 宽类型的低半与高半 slot 都存 Long/Double（高半不可被 cat1 指令独立读
/// 写，违例即 WidePairing）。Strict 档给出诊断（配对违例、move-result 配
/// 对、monitor 平衡）；best-effort 档同一引擎，未知即退化、不报错。异常
/// 边：handler 入口帧按规范语义寄存器全清（Unknown）合并。
///
/// 不做全程序视图（跨类归上层，同基线裁决）；类型层级不解析继承——不同
/// 引用类型合并为引用顶，不做公共父类搜索。
#pragma once

#include <vector>

#include "dex/core/code_item.hpp"
#include "dex/core/dex_file.hpp"
#include "dex/core/insn.hpp"

namespace dex::core {

/// @brief 寄存器类型格的种类。
enum class RegKind : ca::u8 {
    Unknown,     ///< 顶（未初始化帧、异常清理、best-effort 不可判定）
    IntLike,     ///< 32 位整型族（Z/B/S/C/I），cat1
    Float,       ///< cat1
    Long,        ///< cat2（低半承载语义，高半为配对占位）
    Double,      ///< cat2（同上）
    Null,        ///< 空引用/字面量零（const 0）：并入引用或 cat1 同族
    Reference,   ///< typeIdx == kNoIndex 表示引用顶
    UninitRef,   ///< new-instance 后未执行 <init>，addr 记 new 地址
    UninitThis,  ///< <init> 内 this
    Conflicted,  ///< 不可合并（strict 报诊断）
};

/// @brief 单个（半）寄存器的类型。
struct RegType
{
    RegKind kind = RegKind::Unknown;
    ca::u32 typeIdx = 0;   ///< Reference 的类型；kNoIndex = 引用顶
    ca::u32 addr = 0;      ///< UninitRef 的 new-instance 地址

    static RegType top() noexcept { return RegType{}; }
    static RegType ofKind(RegKind kind) noexcept { return RegType{kind, 0, 0}; }
    static RegType ref(ca::u32 typeIdx) noexcept { return RegType{RegKind::Reference, typeIdx, 0}; }
    static RegType uninit(ca::u32 addr) noexcept { return RegType{RegKind::UninitRef, 0, addr}; }

    bool isWideLow() const noexcept
    {
        return kind == RegKind::Long || kind == RegKind::Double;
    }
    bool sameAs(const RegType& o) const noexcept
    {
        return kind == o.kind && typeIdx == o.typeIdx && addr == o.addr;
    }
};

/// @brief 合并；不可合并返回 Conflicted。
RegType mergeRegTypes(const RegType& a, const RegType& b) noexcept;

/// @brief 基本块：[startAddress, endAddress) 内指令线性连续。
struct CfgBlock
{
    ca::u32 startAddress = 0;
    ca::u32 endAddress = 0;              ///< 流末哨兵 = 最后一条指令地址 + 宽度
    std::vector<ca::u32> successors;     ///< 流内边（块下标）
    std::vector<ca::u32> predecessors;
    std::vector<ca::u32> handlers;       ///< 异常边（handler 入口所在块下标）
    bool isExitReachable = false;        ///< 块以 return/throw 结尾或流出流末
};

/// @brief 单条诊断（strict 档产出）。
struct FrameDiagnostic
{
    ca::u32 address = 0;
    enum class Code : ca::u8 {
        WidePairing,     ///< cat2 半寄存器被独立读写
        MoveResultPair,  ///< move-result 未紧跟 invoke/filled-new-array
        MonitorBalance,  ///< 方法出口 monitor 深度非零 / monitor-exit 无配对
        TypeConflict,    ///< 冲突合流的寄存器被读取（strict 视为不可验证）
        BadOperand,      ///< 寄存器越界 / 引用种类不符
    };
    Code code = Code::TypeConflict;
};

/// @brief 分析产物：CFG + 逐指令入口帧 + 诊断。
struct MethodAnalysis
{
    std::vector<CfgBlock> blocks;
    /// 每条解码指令一份入口帧（按解码序，与 insns 等长；payload 位保持
    /// 入流帧）。宽类型低半与高半 slot 均存 Long/Double。
    std::vector<std::vector<RegType>> entryFrames;
    std::vector<FrameDiagnostic> diagnostics;
    ca::u32 registersSize = 0;
    bool strictClean = true;  ///< 无诊断
};

/// @brief 从解码指令流 + try 表构建 CFG。块在 try 边界与控制流目标处切分，
/// 不跨 handler 集合变化点。@p handlers 解析 handler 入口地址。
std::vector<CfgBlock> buildCfg(const std::vector<Insn>& insns,
                               const std::vector<TryBlock>& tries,
                               const std::vector<CatchHandler>& handlers);

/// @brief 帧分析。@p dex 用于字段/方法/proto 的描述符 → 寄存器种类解析；
/// @p methodIdx 提供入口帧的参数类型；@p isStatic 决定槽 0 是否 UninitThis。
/// 指令流解码自 @p code。best-effort（strict=false）不产出诊断。
Result<MethodAnalysis, ReadError> analyzeFrames(DexFile& dex, const CodeItem& code,
                                                ca::u32 methodIdx, bool isStatic,
                                                bool strict);

}   // namespace dex::core
