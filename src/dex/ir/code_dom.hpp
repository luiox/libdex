/// @file        code_dom.hpp
/// @brief       方法体的只读 CodeDom：指令序列、label 边界与 try 区域。
///
/// core 层给出 code_item 与逐条指令；本层把它们组织成方法级视图：
///   - 指令按地址升序排列，payload 保持为伪指令节点；
///   - label 是所有分支、switch case、payload 与 try 边界用到的 code unit 地址；
///   - try 区域按「try 范围 + 单个 handler」展平，catch-all 的 type 索引为 -1。
///
/// CodeDom 持有源字节的共享所有权（libca Bytes 是引用计数容器），因此
/// payload 视图在 DexFile 析构后仍然有效。结构性问题（越界目标、目标不是
/// 指令边界、payload 类型不匹配）记入 @ref issues，不阻断构建。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/core/bytes.hpp"
#include "dex/core/dex_file.hpp"
#include "dex/core/insn.hpp"

namespace dex::ir {

using ca::core::Err;
using ca::core::Ok;
using ca::core::Result;

/// @brief CodeDom 构建失败原因。
enum class CodeError {
    Ok = 0,
    BadCodeItem,    ///< code_item 缺失、区间不符或指令区大小不一致
    Truncated,      ///< 指令流在一条指令中间结束
    UnknownOpcode,  ///< 指令流含未定义操作码
    BadPayload,     ///< payload 地址或尺寸非法
};

/// @brief 错误码的可读文本。
const char* to_string(CodeError e) noexcept;

/// @brief CodeDom 发现的结构问题种类。
enum class CodeIssueKind : ca::u8 {
    BranchTargetOutOfRange,    ///< 分支目标不在 [0, insns_size]
    BranchTargetNotInstruction,///< 分支目标不是指令边界或指向 payload
    PayloadTargetMissing,      ///< 31t 引用的地址没有 payload
    PayloadKindMismatch,       ///< 31t 引用到了错误种类的 payload
    TryRangeOutOfRange,        ///< try 的 [start, end) 越出方法体
    TryBoundaryNotInstruction, ///< try 的 start/end 不是指令边界
    HandlerTargetNotInstruction, ///< handler 地址越界或不是指令边界
    MissingCatchHandler,       ///< try_item 的 handler 下标无效
};

/// @brief 问题种类文本。
const char* to_string(CodeIssueKind kind) noexcept;

/// @brief 单条结构问题；sourceAddress 是触发问题的指令/try 起始地址。
struct CodeIssue
{
    CodeIssueKind kind = CodeIssueKind::BranchTargetOutOfRange;
    ca::i64 address = 0;        ///< 目标地址；负值是非法分支偏移的结果
    ca::u32 sourceAddress = 0;  ///< 触发问题的指令/try 起始地址
};

/// @brief 展平后的 try 区域：一个 try 对应一条 typed catch 或 catch-all。
struct TryRegion
{
    ca::u32 startAddress = 0;  ///< 含
    ca::u32 endAddress = 0;    ///< 不含
    ca::u32 handlerAddress = 0;
    ca::i32 typeIndex = -1;    ///< -1 表示 catch-all

    bool isCatchAll() const noexcept { return typeIndex < 0; }
};

/// @brief 单个方法体的只读视图。
class CodeDom
{
public:
    CodeDom() = default;
    CodeDom(const CodeDom&) = delete;
    CodeDom& operator=(const CodeDom&) = delete;
    CodeDom(CodeDom&&) noexcept = default;
    CodeDom& operator=(CodeDom&&) noexcept = default;

    bool empty() const noexcept { return insns_.empty(); }

    ca::u32 codeOffset() const noexcept { return item_.offset; }
    ca::u32 insnsSize() const noexcept { return item_.insnsSize; }
    ca::u16 registersSize() const noexcept { return item_.registersSize; }
    ca::u16 insSize() const noexcept { return item_.insSize; }
    ca::u16 outsSize() const noexcept { return item_.outsSize; }

    const std::vector<core::Insn>& insns() const noexcept { return insns_; }
    const std::vector<ca::u32>& labels() const noexcept { return labels_; }
    const std::vector<TryRegion>& tryRegions() const noexcept { return tryRegions_; }
    const std::vector<CodeIssue>& issues() const noexcept { return issues_; }
    const core::CodeItem& codeItem() const noexcept { return item_; }
    const ca::core::Bytes& source() const noexcept { return source_; }

    /// @brief address 是否在 label 集合中（二分查找）。
    bool hasLabel(ca::u32 address) const noexcept;

private:
    friend Result<CodeDom, CodeError> buildCodeDom(ca::core::Bytes source,
                                                   const core::CodeItem& item);

    ca::core::Bytes source_;
    core::CodeItem item_;
    std::vector<core::Insn> insns_;
    std::vector<ca::u32> labels_;
    std::vector<TryRegion> tryRegions_;
    std::vector<CodeIssue> issues_;
};

/// @brief 由源字节与已解析的 code_item 构建 CodeDom；source 取共享所有权。
Result<CodeDom, CodeError> buildCodeDom(ca::core::Bytes source, const core::CodeItem& item);

/// @brief 按 codeOff 从 DexFile 取 code_item 并构建 CodeDom。
Result<CodeDom, CodeError> buildCodeDom(core::DexFile& file, ca::u32 codeOff);

}   // namespace dex::ir
