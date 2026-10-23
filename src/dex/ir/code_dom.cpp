/// @file        code_dom.cpp
/// @brief       CodeDom 构建：指令、label 与 try 区域。
#include "dex/ir/code_dom.hpp"

#include <algorithm>
#include <unordered_map>

namespace dex::ir {

namespace {

CodeError mapInsnError(core::InsnError error) noexcept
{
    switch (error) {
    case core::InsnError::Ok:
        return CodeError::Ok;
    case core::InsnError::Truncated:
        return CodeError::Truncated;
    case core::InsnError::UnknownOpcode:
        return CodeError::UnknownOpcode;
    case core::InsnError::BadPayload:
        return CodeError::BadPayload;
    }
    return CodeError::BadCodeItem;
}

void addIssue(std::vector<CodeIssue>& issues, CodeIssueKind kind, ca::i64 address,
              ca::u32 sourceAddress)
{
    issues.push_back(CodeIssue{kind, address, sourceAddress});
}

}   // namespace

Result<CodeDom, CodeError> buildCodeDom(ca::core::Bytes source, const core::CodeItem& item)
{
    const core::ByteSlice sourceView{source.as_ptr(), source.len()};
    const core::ByteSlice insnsBytes =
        core::subOrEmpty(sourceView, item.insns.offset, item.insns.length);
    if (insnsBytes.size() != static_cast<ca::usize>(item.insnsSize) * 2u) {
        return Err(CodeError::BadCodeItem);
    }

    const auto decoded = core::decodeInsns(insnsBytes);
    if (decoded.is_err()) {
        return Err(mapInsnError(decoded.unwrap_err()));
    }

    CodeDom dom;
    dom.source_ = std::move(source);
    dom.item_ = item;
    dom.insns_ = decoded.unwrap();

    std::unordered_map<ca::u32, ca::usize> indexByAddress;
    indexByAddress.reserve(dom.insns_.size());
    for (ca::usize i = 0; i < dom.insns_.size(); ++i) {
        indexByAddress.emplace(dom.insns_[i].address, i);
    }

    const auto hasInstructionAt = [&dom, &indexByAddress](ca::u32 address) -> bool {
        const auto it = indexByAddress.find(address);
        return it != indexByAddress.end() && !dom.insns_[it->second].isPayload();
    };
    const auto addLabel = [&dom](ca::u32 address) { dom.labels_.push_back(address); };

    const auto checkBranchTarget = [&](ca::i64 target, ca::u32 origin) -> bool {
        if (target < 0 || target >= dom.item_.insnsSize) {
            addIssue(dom.issues_, CodeIssueKind::BranchTargetOutOfRange, target, origin);
            return false;
        }
        if (!hasInstructionAt(static_cast<ca::u32>(target))) {
            addIssue(dom.issues_, CodeIssueKind::BranchTargetNotInstruction, target, origin);
            return false;
        }
        return true;
    };

    for (const core::Insn& insn : dom.insns_) {
        if (insn.opcode == 0x26 || insn.opcode == 0x2b || insn.opcode == 0x2c) {
            const core::PayloadKind expected =
                insn.opcode == 0x26 ? core::PayloadKind::FillArrayData
                : insn.opcode == 0x2b ? core::PayloadKind::PackedSwitch
                                      : core::PayloadKind::SparseSwitch;

            const ca::i64 target = static_cast<ca::i64>(insn.address) + insn.branchOffset;
            const core::Insn* payload = nullptr;
            if (target < 0 || target >= dom.item_.insnsSize) {
                addIssue(dom.issues_, CodeIssueKind::PayloadTargetMissing, target, insn.address);
            } else {
                const auto found = indexByAddress.find(static_cast<ca::u32>(target));
                if (found == indexByAddress.end()) {
                    addIssue(dom.issues_, CodeIssueKind::PayloadTargetMissing, target, insn.address);
                } else {
                    payload = &dom.insns_[found->second];
                    if (!payload->isPayload()) {
                        addIssue(dom.issues_, CodeIssueKind::PayloadKindMismatch, target,
                                 insn.address);
                    } else if (payload->payloadKind != expected) {
                        addIssue(dom.issues_, CodeIssueKind::PayloadKindMismatch, target,
                                 insn.address);
                    } else {
                        addLabel(payload->address);
                    }
                }
            }

            if (payload == nullptr || payload->payloadKind != expected) {
                continue;
            }
            if (expected == core::PayloadKind::FillArrayData) {
                continue;
            }
            for (ca::u32 k = 0; k < payload->payloadCount; ++k) {
                const ca::i32 offset = expected == core::PayloadKind::PackedSwitch
                                           ? payload->packedSwitchTarget(k)
                                           : payload->sparseSwitchTarget(k);
                const ca::i64 caseTarget = static_cast<ca::i64>(insn.address) + offset;
                if (checkBranchTarget(caseTarget, insn.address)) {
                    addLabel(static_cast<ca::u32>(caseTarget));
                }
            }
            continue;
        }

        if (insn.isBranch()) {
            const ca::i64 target = static_cast<ca::i64>(insn.address) + insn.branchOffset;
            if (checkBranchTarget(target, insn.address)) {
                addLabel(static_cast<ca::u32>(target));
            }
        }
    }

    for (const core::TryBlock& block : dom.item_.tryBlocks) {
        const ca::i64 end64 = static_cast<ca::i64>(block.startAddress) + block.insnCount;
        const ca::u32 end = end64 > dom.item_.insnsSize
                                ? dom.item_.insnsSize
                                : static_cast<ca::u32>(end64);
        if (end64 > dom.item_.insnsSize) {
            addIssue(dom.issues_, CodeIssueKind::TryRangeOutOfRange, end64, block.startAddress);
        }

        if (block.startAddress < dom.item_.insnsSize &&
            hasInstructionAt(block.startAddress)) {
            addLabel(block.startAddress);
        } else {
            addIssue(dom.issues_, CodeIssueKind::TryBoundaryNotInstruction,
                     block.startAddress, block.startAddress);
        }

        if (end == dom.item_.insnsSize || hasInstructionAt(end)) {
            addLabel(end);
        } else {
            addIssue(dom.issues_, CodeIssueKind::TryBoundaryNotInstruction, end,
                     block.startAddress);
        }

        if (block.handlerIndex >= dom.item_.catchHandlers.size()) {
            addIssue(dom.issues_, CodeIssueKind::MissingCatchHandler, block.handlerOff,
                     block.startAddress);
            continue;
        }
        const core::CatchHandler& handler = dom.item_.catchHandlers[block.handlerIndex];

        const auto recordHandler = [&](ca::u32 address, ca::i32 typeIndex) {
            dom.tryRegions_.push_back(
                TryRegion{block.startAddress, end, address, typeIndex});
            if (address < dom.item_.insnsSize && hasInstructionAt(address)) {
                addLabel(address);
            } else {
                addIssue(dom.issues_, CodeIssueKind::HandlerTargetNotInstruction, address,
                         block.startAddress);
            }
        };

        for (const core::TypedCatch& typed : handler.typed) {
            recordHandler(typed.address, static_cast<ca::i32>(typed.typeIdx));
        }
        if (handler.hasCatchAll) {
            recordHandler(handler.catchAllAddress, -1);
        }
    }

    std::sort(dom.labels_.begin(), dom.labels_.end());
    dom.labels_.erase(std::unique(dom.labels_.begin(), dom.labels_.end()), dom.labels_.end());

    return Ok(std::move(dom));
}

Result<CodeDom, CodeError> buildCodeDom(core::DexFile& file, ca::u32 codeOff)
{
    if (codeOff == 0) {
        return Err(CodeError::BadCodeItem);
    }
    const auto codeResult = file.codeItem(codeOff);
    if (codeResult.is_err()) {
        return Err(CodeError::BadCodeItem);
    }
    const core::CodeItem* item = codeResult.unwrap();
    if (item == nullptr) {
        return Err(CodeError::BadCodeItem);
    }
    return buildCodeDom(file.sourceBytes(), *item);
}

bool CodeDom::hasLabel(ca::u32 address) const noexcept
{
    return std::binary_search(labels_.begin(), labels_.end(), address);
}

const char* to_string(CodeError e) noexcept
{
    switch (e) {
    case CodeError::Ok:
        return "Ok";
    case CodeError::BadCodeItem:
        return "BadCodeItem";
    case CodeError::Truncated:
        return "Truncated";
    case CodeError::UnknownOpcode:
        return "UnknownOpcode";
    case CodeError::BadPayload:
        return "BadPayload";
    }
    return "Unknown";
}

const char* to_string(CodeIssueKind kind) noexcept
{
    switch (kind) {
    case CodeIssueKind::BranchTargetOutOfRange:
        return "BranchTargetOutOfRange";
    case CodeIssueKind::BranchTargetNotInstruction:
        return "BranchTargetNotInstruction";
    case CodeIssueKind::PayloadTargetMissing:
        return "PayloadTargetMissing";
    case CodeIssueKind::PayloadKindMismatch:
        return "PayloadKindMismatch";
    case CodeIssueKind::TryRangeOutOfRange:
        return "TryRangeOutOfRange";
    case CodeIssueKind::TryBoundaryNotInstruction:
        return "TryBoundaryNotInstruction";
    case CodeIssueKind::HandlerTargetNotInstruction:
        return "HandlerTargetNotInstruction";
    case CodeIssueKind::MissingCatchHandler:
        return "MissingCatchHandler";
    }
    return "Unknown";
}

}   // namespace dex::ir
