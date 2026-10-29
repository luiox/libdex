/// @file        method_editor.cpp
/// @brief       方法体构建门面实现：lower + debug 事件降级。
#include "dex/method_editor.hpp"

#include <algorithm>

#include "dex/debug_info.hpp"

namespace dex::core {
namespace {

/// @brief debug 事件锚点解析：kEndSlot 锚 = 尚无前驱指令 → 地址 0；
///        其余锚 = 该槽地址 + 槽宽（事件落在槽之后）。
Result<ca::u32, CodeDomError> anchorAddress(const CodeUnit& unit, const InsnId& after)
{
    if (after.slot == kEndSlot) {
        return Ok(static_cast<ca::u32>(0));
    }
    const Result<ca::u32, CodeDomError> a = unit.addressOf(after);
    if (a.is_err()) {
        return Err(a.unwrap_err());
    }
    return Ok(a.unwrap() + unit.get(after).width);
}

}   // namespace

InsnId MethodEditor::append(Insn insn, std::vector<ca::u8> payloadStorage)
{
    const InsnId id = unit_.append(std::move(insn), std::move(payloadStorage));
    lastAppended_ = id;
    return id;
}

void MethodEditor::debugLine(ca::i32 line)
{
    DbgEvent e;
    e.kind = DbgKind::Line;
    e.line = line;
    e.after = lastAppended_;
    debug_.push_back(e);
}

void MethodEditor::debugStartLocal(ca::u32 reg, ca::u32 nameIdx, ca::u32 typeIdx, ca::u32 sigIdx)
{
    DbgEvent e;
    e.kind = sigIdx == kNoIndex ? DbgKind::StartLocal : DbgKind::StartLocalExtended;
    e.reg = reg;
    e.nameIdx = nameIdx;
    e.typeIdx = typeIdx;
    e.sigIdx = sigIdx;
    e.after = lastAppended_;
    debug_.push_back(e);
}

void MethodEditor::debugEndLocal(ca::u32 reg)
{
    DbgEvent e;
    e.kind = DbgKind::EndLocal;
    e.reg = reg;
    e.after = lastAppended_;
    debug_.push_back(e);
}

void MethodEditor::debugRestartLocal(ca::u32 reg)
{
    DbgEvent e;
    e.kind = DbgKind::RestartLocal;
    e.reg = reg;
    e.after = lastAppended_;
    debug_.push_back(e);
}

void MethodEditor::debugPrologueEnd()
{
    DbgEvent e;
    e.kind = DbgKind::PrologueEnd;
    e.after = lastAppended_;
    debug_.push_back(e);
}

void MethodEditor::debugEpilogueBegin()
{
    DbgEvent e;
    e.kind = DbgKind::EpilogueBegin;
    e.after = lastAppended_;
    debug_.push_back(e);
}

void MethodEditor::setDebugParamNames(std::vector<ca::u32> nameIdx)
{
    paramNames_ = std::move(nameIdx);
}

Result<MethodBody, CodeDomError> MethodEditor::commit()
{
    Result<LoweredCode, CodeDomError> lowered = unit_.lower(true);
    if (lowered.is_err()) {
        return Err(lowered.unwrap_err());
    }
    LoweredCode code = std::move(lowered).unwrap();

    MethodBody body;
    body.item = std::move(code.item);
    body.insns = std::move(code.insns);

    if (debug_.empty() && paramNames_.empty()) {
        return Ok(std::move(body));
    }

    // 事件按 lower 后地址定锚，同址保持记录序。
    struct Resolved
    {
        ca::u32 addr = 0;
        DbgEvent e;
    };
    std::vector<Resolved> resolved;
    resolved.reserve(debug_.size());
    for (const DbgEvent& e : debug_) {
        Result<ca::u32, CodeDomError> a = anchorAddress(unit_, e.after);
        if (a.is_err()) {
            return Err(a.unwrap_err());
        }
        resolved.push_back(Resolved{a.unwrap(), e});
    }
    std::stable_sort(resolved.begin(), resolved.end(),
                     [](const Resolved& x, const Resolved& y) { return x.addr < y.addr; });

    DebugInfo info;
    info.parameterNames = paramNames_;

    ca::u32 lastAddr = 0;
    ca::i32 lastLine = 0;
    bool haveLine = false;
    for (const Resolved& r : resolved) {
        const DbgEvent& e = r.e;
        if (e.kind == DbgKind::Line) {
            if (haveLine && r.addr == lastAddr && e.line == lastLine) {
                continue;
            }
            if (!haveLine) {
                info.lineStart = static_cast<ca::u32>(e.line);
                lastAddr = r.addr;
                lastLine = e.line;
                haveLine = true;
                continue;
            }
            // 地址差 + 行差 → special / AdvancePC+AdvanceLine。
            const ca::u32 addrDiff = r.addr - lastAddr;
            const ca::i32 lineDiff = e.line - lastLine;
            if (addrDiff == 0) {
                DebugOp op;
                op.opcode = kDbgAdvanceLine;
                op.lineDiff = lineDiff;
                info.ops.push_back(op);
            } else {
                const ca::u32 step = addrDiff > 16 ? 16 : addrDiff;
                const ca::i32 adj = static_cast<ca::i32>(step * 15 + (lineDiff + 4));
                if (lineDiff >= -4 && lineDiff <= 10 && adj >= 0 && adj <= 245) {
                    DebugOp op;
                    op.opcode = static_cast<ca::u8>(kDbgFirstSpecial + adj);
                    // special opcode 的语义字段必须与编码自洽（writeDebugInfo 校验）。
                    op.addressDiff = debugSpecialAddressDiff(op.opcode);
                    op.lineDiff = debugSpecialLineDiff(op.opcode);
                    info.ops.push_back(op);
                } else {
                    DebugOp pc;
                    pc.opcode = kDbgAdvancePc;
                    pc.addressDiff = addrDiff;
                    info.ops.push_back(pc);
                    DebugOp ln;
                    ln.opcode = kDbgAdvanceLine;
                    ln.lineDiff = lineDiff;
                    info.ops.push_back(ln);
                }
            }
            lastAddr = r.addr;
            lastLine = e.line;
            continue;
        }
        DebugOp op;
        switch (e.kind) {
        case DbgKind::StartLocal:
        case DbgKind::StartLocalExtended:
            op.opcode = e.kind == DbgKind::StartLocal ? kDbgStartLocal : kDbgStartLocalExtended;
            op.reg = e.reg;
            op.nameIdx = e.nameIdx;
            op.typeIdx = e.typeIdx;
            op.sigIdx = e.sigIdx;
            break;
        case DbgKind::EndLocal:
            op.opcode = kDbgEndLocal;
            op.reg = e.reg;
            break;
        case DbgKind::RestartLocal:
            op.opcode = kDbgRestartLocal;
            op.reg = e.reg;
            break;
        case DbgKind::PrologueEnd:
            op.opcode = kDbgSetPrologueEnd;
            break;
        case DbgKind::EpilogueBegin:
            op.opcode = kDbgSetEpilogueBegin;
            break;
        case DbgKind::Line:
            break;  // 不可达：上面已 continue
        }
        info.ops.push_back(op);
        lastAddr = r.addr;
    }

    Result<std::vector<ca::u8>, WriteError> bytes = writeDebugInfo(info);
    if (bytes.is_err()) {
        return Err(CodeDomError::BadDebugInfo);
    }
    body.debugBytes = std::move(bytes).unwrap();
    return Ok(std::move(body));
}

}   // namespace dex::core
