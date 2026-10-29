/// @file        code_dom.hpp
/// @brief       方法体的结构编辑模型：CodeUnit + label + 值句柄。
///
/// CodeUnit 是 @ref Insn 流之上的编辑层：指令住在稳定的槽表（deque，只追加，
/// 引用不失效），程序序在 @c order_ 里；插入/删除只改 order_，已有槽位与
/// 句柄不失效。分支、switch payload、try 区间与 handler 一律引用 label，
/// lower 时一次算定地址与偏移——编辑者永远不碰字节偏移。
///
/// @ref InsnId{owner, slot, gen} 三元句柄：gen 在槽被 erase 时自增防 ABA；
/// 跨 owner 或过期句柄结构性拒绝。不引入 visitor。
///
/// 保真边界：promote 保留语义字段，丢弃 @ref Insn::raw 原始字节（nop 变体、
/// 非规范高字节不保留）——CodeDom 面向编辑后的方法体，未编辑方法体走
/// dex_file 的透传路径，不经过这里。
#pragma once

#include <deque>
#include <unordered_map>
#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/bytes.hpp"
#include "dex/code_item.hpp"
#include "dex/error.hpp"
#include "dex/insn.hpp"

namespace dex::core {

/// @brief CodeDom 操作失败原因。
enum class CodeDomError {
    Ok = 0,
    StaleHandle,       ///< InsnId 的 owner/slot/gen 与本单元不符（含 ABA）
    UnknownLabel,      ///< label id 未由本单元签发
    StillUsed,         ///< erase(Fail)：槽上仍有 label 绑定
    DanglingLabel,     /// 被 branch/switch/try/handler 引用的 label 从未绑定
    Unencodable,       ///< 指令编码失败（域宽溢出等），见 lower 的诊断
    MisalignedPayload, ///< 关闭自动对齐时 payload 落在奇地址
    BadTryRegion,      ///< try 区间为空/交叠/乱序，或 handler 下标悬垂
    BadShape,          ///< 操作与指令形状不符（非分支用 branchTo 等）
};

/// @brief 错误码的可读文本。
const char* to_string(CodeDomError e) noexcept;

/// @brief erase 的两种语义。
enum class ErasePolicy : ca::u8 {
    Fail,  ///< 槽上有 label 绑定即 Err(StillUsed)，单元不动
    Force, ///< 绑定在该槽的 label 重锚到后继指令（无后继则悬空，lower 报错）
};

/// @brief 指令句柄：owner 进程内唯一、slot 槽位、gen 防 ABA。
struct InsnId
{
    const void* owner = nullptr;  ///< 签发本句柄的 CodeUnit
    ca::u32 slot = 0;
    ca::u32 gen = 0;

    bool operator==(const InsnId& o) const noexcept
    {
        return owner == o.owner && slot == o.slot && gen == o.gen;
    }
};

/// @brief end() 哨兵槽位与「label 绑在指令流末尾」的内部标记。
inline constexpr ca::u32 kEndSlot = 0xFFFFFFFFu;

/// @brief label id；由 CodeUnit 签发的稠密 u32。
using LabelId = ca::u32;
inline constexpr LabelId kNoLabel = 0xFFFFFFFFu;

/// @brief try 区间：[start, end) 两个 label，handlerIndex 指向 handlers()。
struct TryDom
{
    LabelId start = kNoLabel;
    LabelId end = kNoLabel;  ///< 排他边界
    ca::u32 handlerIndex = 0;
};

/// @brief 一个 handler 的 DOM 形态：typed 目标与 catch-all 都是 label。
struct HandlerDom
{
    struct Typed
    {
        ca::u32 typeIdx = 0;
        LabelId handler = kNoLabel;
    };
    std::vector<Typed> typed;
    bool hasCatchAll = false;
    LabelId catchAll = kNoLabel;
};

/// @brief lower 的产物：指令区字节 + 已回填偏移的 code_item 模型。
struct LoweredCode
{
    std::vector<ca::u8> insns;
    CodeItem item;  ///< tries/handlers 已重组，可直送 writeCodeItem
};

/// @brief 方法体编辑单元。
class CodeUnit
{
public:
    /// @brief 从解码后的 code_item 提升：指令流、try 与 handler 全部转入
    ///        label 域。共享的 handler 保持共享（按源 handler 下标去重）。
    /// @param item 头部计数与 try/handler 模型。
    /// @param insns 指令区字节（item.insns 视图）；须在调用期内有效。
    static Result<CodeUnit, CodeDomError> promote(const CodeItem& item, ByteSlice insns);

    /// @brief 落回字节与 code_item 模型。
    ///
    /// 流程：定址（按 order_ 累加宽度）→ label 解析 → 分支/switch 偏移回填
    /// → payload 重编码 → 编码指令区 → 重组 try/handler 表。payload 落在
    /// 奇地址时按 @p autoAlign 在其前插入 nop 槽（可见地修改本单元）再定址；
    /// 关闭则返回 Err(MisalignedPayload)。
    /// 被引用而未绑定的 label 返回 Err(DanglingLabel)；try 区间交叠/乱序
    /// 返回 Err(BadTryRegion)。
    Result<LoweredCode, CodeDomError> lower(bool autoAlign = true);

    // ---- 单元状态 ----

    ca::u32 insnCount() const noexcept { return static_cast<ca::u32>(order_.size()); }
    ca::u32 labelCount() const noexcept { return nextLabel_; }
    const std::vector<TryDom>& tries() const noexcept { return tries_; }
    const std::vector<HandlerDom>& handlers() const noexcept { return handlers_; }
    ca::u16 registersSize() const noexcept { return registersSize_; }
    ca::u16 insSize() const noexcept { return insSize_; }
    ca::u16 outsSize() const noexcept { return outsSize_; }
    ca::u32 debugInfoOff() const noexcept { return debugInfoOff_; }
    void setRegistersSize(ca::u16 v) noexcept { registersSize_ = v; }
    void setInsSize(ca::u16 v) noexcept { insSize_ = v; }
    void setOutsSize(ca::u16 v) noexcept { outsSize_ = v; }
    void setDebugInfoOff(ca::u32 v) noexcept { debugInfoOff_ = v; }

    // ---- 遍历 ----

    /// @brief 程序序首条；空体返回失效句柄。
    InsnId first() const noexcept;
    /// @brief 流末哨兵（next 的终点；label 可绑定在此 = 方法体末地址）。
    InsnId end() const noexcept { return InsnId{this, kEndSlot, 0}; }
    /// @brief 程序序中的下一条；末条返回 end()。
    InsnId next(InsnId id) const;
    /// @brief 句柄是否仍有效（owner/slot/gen 三对）。
    bool valid(InsnId id) const noexcept;

    // ---- 句柄取值 ----

    const Insn& get(InsnId id) const;
    Insn& get(InsnId id);

    /// @brief 槽的当前 code unit 地址（按 order_ 定址）。
    Result<ca::u32, CodeDomError> addressOf(InsnId id) const;

    // ---- 编辑 ----

    /// @brief 追加到程序序末尾。payload 指令同时给出自持载荷字节。
    InsnId append(Insn insn, std::vector<ca::u8> payloadStorage = std::vector<ca::u8>{});

    /// @brief 插到 @p before 之前（程序序）。
    Result<InsnId, CodeDomError> insertBefore(InsnId before, Insn insn,
                                              std::vector<ca::u8> payloadStorage =
                                                  std::vector<ca::u8>{});

    /// @brief 删除一条指令。policy 语义见 @ref ErasePolicy。
    Result<void, CodeDomError> erase(InsnId id, ErasePolicy policy);

    // ---- label ----

    LabelId newLabel();
    /// @brief 把 label 绑到某槽（地址 = 该槽起始）；@p at 为 end() 时绑在
    ///        指令流末尾（分支到方法体末、try 区间排他边界都落在这里）。
    Result<void, CodeDomError> bindLabel(LabelId label, InsnId at);
    /// @brief label 当前绑定的槽；绑在流末尾返回 end()，未绑定返回失效句柄。
    InsnId labelAt(LabelId label) const;
    /// @brief 解除绑定（label 仍可重绑）。
    Result<void, CodeDomError> unbindLabel(LabelId label);

    // ---- 控制流 ----

    /// @brief 让分支指令指向 label（10t/20t/21t/22t/30t/31t）。
    Result<void, CodeDomError> bindBranch(InsnId branch, LabelId target);

    /// @brief 绑定 31t switch 与其 payload：payload 槽必须是 payload 指令，
    ///        targets 逐项对应 packed/sparse 条目（顺序即条目序），地址相对
    ///        switch 指令在 lower 时回填。fill-array-data 无目标，传空。
    Result<void, CodeDomError> bindPayload(InsnId switchInsn, InsnId payload,
                                           std::vector<LabelId> targets);

    /// @brief 新增 try 区间与 handler。区间 [start, end) 由 label 定界，
    ///        handler 挂在 @p handlerIndex；typed/catchAll 的 label 为
    ///        kNoLabel 表示该目标暂缺（lower 报 DanglingLabel）。
    Result<void, CodeDomError> addTry(LabelId start, LabelId end, ca::u32 handlerIndex);
    ca::u32 addHandler(HandlerDom handler);

private:
    struct Slot
    {
        Insn insn;
        std::vector<ca::u8> payloadStorage;  ///< 仅 payload 槽使用
        ca::u32 gen = 0;
    };

    const Slot& slotOf(InsnId id) const;
    Slot& slotOf(InsnId id);
    /// @brief order_ 下标 → code unit 地址（全量重算）。
    std::vector<ca::u32> computeAddresses() const;
    InsnId handleForSlot(ca::u32 slot) const noexcept;
    /// @brief 槽在 order_ 中的位置；不在返回 npos。
    ca::usize orderPos(ca::u32 slot) const noexcept;

    std::deque<Slot> slots_;
    std::vector<ca::u32> order_;  ///< 程序序的槽下标
    std::unordered_map<LabelId, ca::u32> labelSlot_;      ///< label → 槽
    std::unordered_map<ca::u32, LabelId> branchLabel_;    ///< 槽 → 分支目标 label
    std::unordered_map<ca::u32, std::vector<LabelId>> switchTarget_;  ///< switch 槽 → 目标
    std::unordered_map<ca::u32, ca::u32> payloadOwner_;   ///< payload 槽 → switch 槽
    std::vector<TryDom> tries_;
    std::vector<HandlerDom> handlers_;
    ca::u32 nextLabel_ = 0;
    ca::u16 registersSize_ = 0;
    ca::u16 insSize_ = 0;
    ca::u16 outsSize_ = 0;
    ca::u32 debugInfoOff_ = 0;
};

}   // namespace dex::core
