/// @file        code_dom.cpp
/// @brief       CodeUnit 的 promote/lower 与编辑实现。
#include "dex/code_dom.hpp"

#include "dex/insn_edit.hpp"

#include <algorithm>
#include <cstddef>
#include <functional>
#include <utility>

namespace dex::core {

namespace {

Insn makeNop()
{
    Insn nop;
    nop.opcode = 0x00;
    nop.format = InsnFormat::F10x;
    nop.width = 1;
    return nop;
}

/// @brief 地址 → 起始槽下标的反查表。
std::unordered_map<ca::u32, ca::u32> addressIndex(const std::vector<Insn>& insns)
{
    std::unordered_map<ca::u32, ca::u32> byAddr;
    byAddr.reserve(insns.size());
    for (ca::u32 i = 0; i < insns.size(); ++i) {
        byAddr.emplace(insns[i].address, i);
    }
    return byAddr;
}

}   // namespace

const char* to_string(CodeDomError e) noexcept
{
    switch (e) {
    case CodeDomError::Ok: return "ok";
    case CodeDomError::StaleHandle: return "stale handle";
    case CodeDomError::UnknownLabel: return "unknown label";
    case CodeDomError::StillUsed: return "slot still referenced by a label";
    case CodeDomError::DanglingLabel: return "referenced label is unbound";
    case CodeDomError::Unencodable: return "instruction not encodable";
    case CodeDomError::MisalignedPayload: return "payload on odd address";
    case CodeDomError::BadTryRegion: return "try region invalid";
    case CodeDomError::BadShape: return "operation does not fit instruction shape";
    }
    return "unknown";
}

// ---- 句柄与遍历 ----

bool CodeUnit::valid(InsnId id) const noexcept
{
    return id.owner == static_cast<const void*>(this) && id.slot != kEndSlot &&
           id.slot < slots_.size() && slots_[id.slot].gen == id.gen;
}

InsnId CodeUnit::first() const noexcept
{
    if (order_.empty()) {
        return InsnId{};
    }
    return handleForSlot(order_[0]);
}

InsnId CodeUnit::next(InsnId id) const
{
    if (!valid(id)) {
        return InsnId{};
    }
    const ca::usize pos = orderPos(id.slot);
    if (pos + 1 >= order_.size()) {
        return end();
    }
    return handleForSlot(order_[pos + 1]);
}

const CodeUnit::Slot& CodeUnit::slotOf(InsnId id) const
{
    // end()、已擦除句柄与跨单元句柄都回落哑槽：owner/gen/slot 任一不符都不能
    // 读到别的槽。取值入口按约定应先 valid()，这里只做内存安全兜底。
    static const Slot dummy{};
    if (!valid(id)) {
        return dummy;
    }
    return slots_[id.slot];
}

CodeUnit::Slot& CodeUnit::slotOf(InsnId id)
{
    static Slot dummy{};
    if (!valid(id)) {
        return dummy;
    }
    return slots_[id.slot];
}

const Insn& CodeUnit::get(InsnId id) const
{
    return slotOf(id).insn;
}

Insn& CodeUnit::get(InsnId id)
{
    return slotOf(id).insn;
}

InsnId CodeUnit::handleForSlot(ca::u32 slot) const noexcept
{
    return InsnId{this, slot, slots_[slot].gen};
}

ca::usize CodeUnit::orderPos(ca::u32 slot) const noexcept
{
    for (ca::usize i = 0; i < order_.size(); ++i) {
        if (order_[i] == slot) {
            return i;
        }
    }
    return static_cast<ca::usize>(-1);
}

std::vector<ca::u32> CodeUnit::computeAddresses() const
{
    std::vector<ca::u32> addrs;
    addrs.reserve(order_.size());
    ca::u32 addr = 0;
    for (ca::u32 slot : order_) {
        addrs.push_back(addr);
        addr += slots_[slot].insn.width;
    }
    return addrs;
}

Result<ca::u32, CodeDomError> CodeUnit::addressOf(InsnId id) const
{
    if (!valid(id)) {
        return Err(CodeDomError::StaleHandle);
    }
    const std::vector<ca::u32> addrs = computeAddresses();
    const ca::usize pos = orderPos(id.slot);
    return Ok(addrs[pos]);
}

// ---- 编辑 ----

InsnId CodeUnit::append(Insn insn, std::vector<ca::u8> payloadStorage)
{
    const ca::u32 slot = static_cast<ca::u32>(slots_.size());
    if (!payloadStorage.empty()) {
        insn.payloadData = ByteSlice{payloadStorage.data(), payloadStorage.size()};
    }
    slots_.push_back(Slot{std::move(insn), std::move(payloadStorage), 0});
    order_.push_back(slot);
    return handleForSlot(slot);
}

Result<InsnId, CodeDomError> CodeUnit::insertBefore(InsnId before, Insn insn,
                                                    std::vector<ca::u8> payloadStorage)
{
    if (!valid(before)) {
        return Err(CodeDomError::StaleHandle);
    }
    const ca::u32 slot = static_cast<ca::u32>(slots_.size());
    if (!payloadStorage.empty()) {
        insn.payloadData = ByteSlice{payloadStorage.data(), payloadStorage.size()};
    }
    slots_.push_back(Slot{std::move(insn), std::move(payloadStorage), 0});
    const ca::usize pos = orderPos(before.slot);
    order_.insert(order_.begin() + static_cast<std::ptrdiff_t>(pos), slot);
    return Ok(handleForSlot(slot));
}

Result<void, CodeDomError> CodeUnit::erase(InsnId id, ErasePolicy policy)
{
    if (!valid(id)) {
        return Err(CodeDomError::StaleHandle);
    }
    const ca::usize pos = orderPos(id.slot);

    // 绑定在该槽的 label：Fail 拒绝，Force 重锚到后继（无后继则挂流末）。
    std::vector<LabelId> bound;
    for (const auto& entry : labelSlot_) {
        if (entry.second == id.slot) {
            bound.push_back(entry.first);
        }
    }
    if (!bound.empty() && policy == ErasePolicy::Fail) {
        return Err(CodeDomError::StillUsed);
    }
    const bool hasSuccessor = pos + 1 < order_.size();
    const ca::u32 successor = hasSuccessor ? order_[pos + 1] : kEndSlot;
    for (LabelId label : bound) {
        labelSlot_[label] = successor;
    }

    order_.erase(order_.begin() + static_cast<std::ptrdiff_t>(pos));
    branchLabel_.erase(id.slot);
    switchTarget_.erase(id.slot);
    // 本槽是 switch：解除其 payload 的反向引用，payload 退化为普通 payload 槽。
    for (auto it = payloadOwner_.begin(); it != payloadOwner_.end();) {
        if (it->second == id.slot) {
            it = payloadOwner_.erase(it);
        } else {
            ++it;
        }
    }
    // 本槽是某 switch 的 payload：switch 的分支/目标绑定一并清。
    for (const auto& entry : payloadOwner_) {
        if (entry.first == id.slot) {
            branchLabel_.erase(entry.second);
            switchTarget_.erase(entry.second);
        }
    }
    payloadOwner_.erase(id.slot);
    slots_[id.slot].gen += 1;
    return Ok();
}

// ---- label ----

LabelId CodeUnit::newLabel()
{
    return nextLabel_++;
}

Result<void, CodeDomError> CodeUnit::bindLabel(LabelId label, InsnId at)
{
    if (label >= nextLabel_) {
        return Err(CodeDomError::UnknownLabel);
    }
    if (at.owner == static_cast<const void*>(this) && at.slot == kEndSlot) {
        labelSlot_[label] = kEndSlot;
        return Ok();
    }
    if (!valid(at)) {
        return Err(CodeDomError::StaleHandle);
    }
    labelSlot_[label] = at.slot;
    return Ok();
}

InsnId CodeUnit::labelAt(LabelId label) const
{
    if (label >= nextLabel_) {
        return InsnId{};
    }
    const auto found = labelSlot_.find(label);
    if (found == labelSlot_.end()) {
        return InsnId{};
    }
    if (found->second == kEndSlot) {
        return end();
    }
    return handleForSlot(found->second);
}

Result<void, CodeDomError> CodeUnit::unbindLabel(LabelId label)
{
    if (label >= nextLabel_) {
        return Err(CodeDomError::UnknownLabel);
    }
    labelSlot_.erase(label);
    return Ok();
}

// ---- 控制流 ----

Result<void, CodeDomError> CodeUnit::bindBranch(InsnId branch, LabelId target)
{
    if (!valid(branch)) {
        return Err(CodeDomError::StaleHandle);
    }
    if (target >= nextLabel_) {
        return Err(CodeDomError::UnknownLabel);
    }
    if (!get(branch).isBranch()) {
        return Err(CodeDomError::BadShape);
    }
    if (get(branch).format == InsnFormat::F31t) {
        // 31t 的目标是 payload，走 bindPayload；bindBranch 会让 lower 把
        // 偏移指向普通指令，产出 ART 拒收的方法体。
        return Err(CodeDomError::BadShape);
    }
    branchLabel_[branch.slot] = target;
    return Ok();
}

ca::u32 CodeUnit::addHandler(HandlerDom handler)
{
    handlers_.push_back(std::move(handler));
    return static_cast<ca::u32>(handlers_.size() - 1);
}

Result<void, CodeDomError> CodeUnit::bindPayload(InsnId switchInsn, InsnId payload,
                                                 std::vector<LabelId> targets)
{
    if (!valid(switchInsn) || !valid(payload)) {
        return Err(CodeDomError::StaleHandle);
    }
    const Insn& sw = get(switchInsn);
    const Insn& pl = get(payload);
    if (sw.format != InsnFormat::F31t || !pl.isPayload()) {
        return Err(CodeDomError::BadShape);
    }
    const auto existingOwner = payloadOwner_.find(payload.slot);
    if (existingOwner != payloadOwner_.end() && existingOwner->second != switchInsn.slot) {
        // 两个 switch 共享一个 payload：1:1 owner 表无法表达，明确拒绝。
        return Err(CodeDomError::BadShape);
    }
    const PayloadKind kind = switchKindOf(sw.opcode);
    if (kind != pl.payloadKind) {
        // 种类错配（如 packed-switch 绑 sparse payload）：lower 按 opcode
        // 种类读 payload 字段会静默错码——在这里拒绝。
        return Err(CodeDomError::BadShape);
    }
    if (kind == PayloadKind::PackedSwitch || kind == PayloadKind::SparseSwitch) {
        if (targets.size() != pl.payloadCount) {
            return Err(CodeDomError::BadShape);
        }
    } else if (kind == PayloadKind::FillArrayData) {
        if (!targets.empty()) {
            return Err(CodeDomError::BadShape);
        }
    } else {
        return Err(CodeDomError::BadShape);
    }

    // payload 的锚点 label 自动签发并绑定；重复 bindPayload 会留下旧 label
    // 的绑定（无害：不被引用的 label 不参与 lower）。
    const LabelId anchor = newLabel();
    if (Result<void, CodeDomError> b = bindLabel(anchor, payload); b.is_err()) {
        return Err(b.unwrap_err());
    }
    branchLabel_[switchInsn.slot] = anchor;
    switchTarget_[switchInsn.slot] = std::move(targets);
    payloadOwner_[payload.slot] = switchInsn.slot;
    return Ok();
}

Result<void, CodeDomError> CodeUnit::addTry(LabelId start, LabelId end, ca::u32 handlerIndex)
{
    if (start >= nextLabel_ || end >= nextLabel_) {
        return Err(CodeDomError::UnknownLabel);
    }
    if (handlerIndex >= handlers_.size()) {
        return Err(CodeDomError::BadTryRegion);
    }
    tries_.push_back(TryDom{start, end, handlerIndex});
    return Ok();
}

// ---- promote ----

Result<CodeUnit, CodeDomError> CodeUnit::promote(const CodeItem& item, ByteSlice insns)
{
    Result<std::vector<Insn>, InsnError> decoded = decodeInsns(insns);
    if (decoded.is_err()) {
        return Err(CodeDomError::Unencodable);
    }
    std::vector<Insn> list = std::move(decoded).unwrap();
    const std::unordered_map<ca::u32, ca::u32> byAddr = addressIndex(list);
    const ca::u32 totalEnd = [&] {
        ca::u32 a = 0;
        for (const Insn& i : list) {
            a += i.width;
        }
        return a;
    }();

    CodeUnit unit;
    unit.registersSize_ = item.registersSize;
    unit.insSize_ = item.insSize;
    unit.outsSize_ = item.outsSize;
    unit.debugInfoOff_ = item.debugInfoOff;

    // 地址 → label（同地址复用同一 label；流末地址绑定到 kEndSlot）。
    std::unordered_map<ca::u32, LabelId> labelByAddr;
    const auto internAt = [&](ca::u32 address) -> Result<LabelId, CodeDomError> {
        const auto found = labelByAddr.find(address);
        if (found != labelByAddr.end()) {
            return Ok(found->second);
        }
        LabelId label = unit.newLabel();
        if (address == totalEnd) {
            unit.labelSlot_[label] = kEndSlot;
        } else {
            const auto slot = byAddr.find(address);
            if (slot == byAddr.end()) {
                return Err(CodeDomError::Unencodable);  // 目标落在指令中间或流外
            }
            unit.labelSlot_[label] = slot->second;
        }
        labelByAddr.emplace(address, label);
        return Ok(label);
    };

    // 先落槽（label 需要槽存在才能绑定）。
    std::vector<InsnId> handles;
    handles.reserve(list.size());
    for (Insn& insn : list) {
        std::vector<ca::u8> storage;
        if (insn.isPayload() && !insn.payloadData.empty()) {
            storage.assign(insn.payloadData.data(),
                           insn.payloadData.data() + insn.payloadData.size());
        }
        insn.raw = ByteSlice{};  // DOM 重编码为规范形态，不保留 nop 变体
        handles.push_back(unit.append(std::move(insn), std::move(storage)));
    }

    // 分支与 switch。
    for (ca::u32 i = 0; i < handles.size(); ++i) {
        Insn& insn = unit.get(handles[i]);
        if (insn.format == InsnFormat::F31t) {
            const ca::u32 switchAddr = list[i].address;
            const ca::i64 payloadAddr = insnBranchTarget(insn);
            if (payloadAddr < 0 || payloadAddr >= static_cast<ca::i64>(totalEnd)) {
                return Err(CodeDomError::Unencodable);
            }
            const Result<LabelId, CodeDomError> label =
                internAt(static_cast<ca::u32>(payloadAddr));
            if (label.is_err()) {
                return Err(label.unwrap_err());
            }
            const InsnId payloadHandle = unit.labelAt(label.unwrap());
            if (payloadHandle.slot == kEndSlot) {
                return Err(CodeDomError::Unencodable);
            }
            const Insn& payload = unit.get(payloadHandle);
            const PayloadKind kind = switchKindOf(insn.opcode);
            if (payloadHandle.slot == handles[i].slot || !payload.isPayload() ||
                payload.payloadKind != kind) {
                // 31t 指向普通指令/异种 payload：lower 会把目标槽无条件改
                // 写成重建的 payload，当场拒绝而不是静默破坏指令流。
                return Err(CodeDomError::Unencodable);
            }
            const auto existingOwner = unit.payloadOwner_.find(payloadHandle.slot);
            if (existingOwner != unit.payloadOwner_.end() &&
                existingOwner->second != handles[i].slot) {
                // 两个 switch 共享一个 payload：lower 的 1:1 owner 表无法表
                // 达，当场拒绝而不是静默孤儿化前者。
                return Err(CodeDomError::BadShape);
            }
            unit.payloadOwner_[payloadHandle.slot] = handles[i].slot;
            // bindPayload 同形：31t 的 branchLabel 指向 payload 锚点，
            // lower 靠它解析 payload 地址。
            unit.branchLabel_[handles[i].slot] = label.unwrap();

            std::vector<LabelId> targets;
            if (kind == PayloadKind::PackedSwitch || kind == PayloadKind::SparseSwitch) {
                // size/target 表在 payload 伪指令上（decode 只填它）；
                // target 值相对 switch 指令地址（DEX 规范）。
                const Insn& pl = payload;
                targets.reserve(pl.payloadCount);
                for (ca::u32 t = 0; t < pl.payloadCount; ++t) {
                    const ca::i32 rel =
                        kind == PayloadKind::PackedSwitch ? pl.packedSwitchTarget(t)
                                                          : pl.sparseSwitchTarget(t);
                    const ca::i64 abs =
                        static_cast<ca::i64>(switchAddr) + static_cast<ca::i64>(rel);
                    if (abs < 0 || abs > static_cast<ca::i64>(totalEnd)) {
                        return Err(CodeDomError::Unencodable);
                    }
                    const Result<LabelId, CodeDomError> tl =
                        internAt(static_cast<ca::u32>(abs));
                    if (tl.is_err()) {
                        return Err(tl.unwrap_err());
                    }
                    targets.push_back(tl.unwrap());
                }
            }
            unit.switchTarget_[handles[i].slot] = std::move(targets);
        } else if (insn.isBranch()) {
            const ca::i64 target = insnBranchTarget(insn);
            if (target < 0 || target > static_cast<ca::i64>(totalEnd)) {
                return Err(CodeDomError::Unencodable);
            }
            const Result<LabelId, CodeDomError> label =
                internAt(static_cast<ca::u32>(target));
            if (label.is_err()) {
                return Err(label.unwrap_err());
            }
            unit.branchLabel_[handles[i].slot] = label.unwrap();
        }
    }

    // try 与 handler：源 handler 下标去重保持共享。
    std::unordered_map<ca::u32, ca::u32> handlerBySource;
    std::vector<TryDom> localTries;
    localTries.reserve(item.tryBlocks.size());
    for (const TryBlock& block : item.tryBlocks) {
        if (block.handlerIndex >= item.catchHandlers.size()) {
            return Err(CodeDomError::BadTryRegion);
        }
        auto found = handlerBySource.find(block.handlerIndex);
        if (found == handlerBySource.end()) {
            const CatchHandler& src = item.catchHandlers[block.handlerIndex];
            HandlerDom dom;
            dom.typed.reserve(src.typed.size());
            for (const TypedCatch& tc : src.typed) {
                if (tc.address > totalEnd) {
                    return Err(CodeDomError::Unencodable);
                }
                const Result<LabelId, CodeDomError> label = internAt(tc.address);
                if (label.is_err()) {
                    return Err(label.unwrap_err());
                }
                dom.typed.push_back(HandlerDom::Typed{tc.typeIdx, label.unwrap()});
            }
            if (src.hasCatchAll) {
                if (src.catchAllAddress > totalEnd) {
                    return Err(CodeDomError::Unencodable);
                }
                const Result<LabelId, CodeDomError> label = internAt(src.catchAllAddress);
                if (label.is_err()) {
                    return Err(label.unwrap_err());
                }
                dom.hasCatchAll = true;
                dom.catchAll = label.unwrap();
            }
            found = handlerBySource
                        .emplace(block.handlerIndex, unit.addHandler(std::move(dom)))
                        .first;
        }
        if (block.startAddress > totalEnd) {
            return Err(CodeDomError::BadTryRegion);
        }
        const Result<LabelId, CodeDomError> start = internAt(block.startAddress);
        if (start.is_err()) {
            return Err(start.unwrap_err());
        }
        const ca::i64 endAddr = static_cast<ca::i64>(block.startAddress) + block.insnCount;
        if (endAddr < 0 || endAddr > static_cast<ca::i64>(totalEnd)) {
            return Err(CodeDomError::BadTryRegion);
        }
        const Result<LabelId, CodeDomError> end = internAt(static_cast<ca::u32>(endAddr));
        if (end.is_err()) {
            return Err(end.unwrap_err());
        }
        localTries.push_back(TryDom{start.unwrap(), end.unwrap(), found->second});
    }
    unit.tries_ = std::move(localTries);

    return Ok(std::move(unit));
}

// ---- lower ----

Result<LoweredCode, CodeDomError> CodeUnit::lower(bool autoAlign)
{
    // 给定一份地址快照的 label 解析（流末绑定的 label 地址 = 快照总长）。
    const auto labelAddressIn = [&](const std::vector<ca::u32>& a)
        -> std::function<Result<ca::u32, CodeDomError>(LabelId)> {
        return [this, &a](LabelId label) -> Result<ca::u32, CodeDomError> {
            if (label >= nextLabel_) {
                return Err(CodeDomError::UnknownLabel);
            }
            const auto found = labelSlot_.find(label);
            if (found == labelSlot_.end()) {
                return Err(CodeDomError::DanglingLabel);
            }
            const ca::u32 endAddr =
                a.empty() ? 0 : a.back() + slots_[order_.back()].insn.width;
            if (found->second == kEndSlot) {
                return Ok(endAddr);
            }
            const ca::usize pos = orderPos(found->second);
            if (pos >= a.size()) {
                return Err(CodeDomError::DanglingLabel);
            }
            return Ok(a[pos]);
        };
    };

    // 定宽 → 对齐 → 终算：payload 重建会改宽度（目标数被编辑过时），先按
    // 当前地址重建一次把宽度定下来，再插对齐 nop，最后用终态地址重算全部
    // 偏移。重建对固定宽度是幂等的。
    // 手工构造的 Insn 容易忘填 width；地址/偏移全建立在 width 上，而编码按
    // 格式规范宽度写——先对不上就当场报错，免得静默错位。
    for (const ca::u32 slot : order_) {
        const Insn& s = slots_[slot].insn;
        if (!s.isPayload() && s.width != insnWidth(s.format)) {
            return Err(CodeDomError::Unencodable);
        }
    }
    const auto rebuildAndFill = [&](bool fillBranches) -> Result<void, CodeDomError> {
        const std::vector<ca::u32> addrs = computeAddresses();
        for (ca::usize pos = 0; pos < order_.size(); ++pos) {
            slots_[order_[pos]].insn.address = addrs[pos];
        }

        for (ca::usize pos = 0; pos < order_.size(); ++pos) {
            const ca::u32 slot = order_[pos];
            Slot& slotRef = slots_[slot];
            Insn& cur = slotRef.insn;

            const auto sw = switchTarget_.find(slot);
            if (sw != switchTarget_.end()) {
                // 本槽是 switch 指令：找它的 payload 槽。
                ca::u32 payloadSlot = kEndSlot;
                for (const auto& entry : payloadOwner_) {
                    if (entry.second == slot) {
                        payloadSlot = entry.first;
                        break;
                    }
                }
                if (payloadSlot == kEndSlot) {
                    return Err(CodeDomError::DanglingLabel);
                }
                Slot& payloadRef = slots_[payloadSlot];

                const auto anchor = branchLabel_.find(slot);
                if (anchor == branchLabel_.end()) {
                    return Err(CodeDomError::DanglingLabel);
                }
                const Result<ca::u32, CodeDomError> payloadAddr =
                    labelAddressIn(addrs)(anchor->second);
                if (payloadAddr.is_err()) {
                    return Err(payloadAddr.unwrap_err());
                }

                const PayloadKind kind = switchKindOf(cur.opcode);
                if (kind == PayloadKind::PackedSwitch || kind == PayloadKind::SparseSwitch) {
                    // payload 数据（size/firstKey/keys）在 payload 伪指令上，
                    // decode 只填它；31t 自身只有寄存器与分支偏移。
                    const Insn& pl = payloadRef.insn;
                    std::vector<ca::i32> keys;
                    if (kind == PayloadKind::SparseSwitch) {
                        keys.reserve(pl.payloadCount);
                        for (ca::u32 k = 0; k < pl.payloadCount; ++k) {
                            keys.push_back(pl.sparseSwitchKey(k));
                        }
                    }
                    std::vector<ca::i32> targets;
                    targets.reserve(sw->second.size());
                    for (LabelId l : sw->second) {
                        const Result<ca::u32, CodeDomError> addr =
                            labelAddressIn(addrs)(l);
                        if (addr.is_err()) {
                            return Err(addr.unwrap_err());
                        }
                        const ca::i64 rel = static_cast<ca::i64>(addr.unwrap()) -
                                            static_cast<ca::i64>(cur.address);
                        if (rel < -0x80000000LL || rel > 0x7FFFFFFFLL) {
                            return Err(CodeDomError::Unencodable);
                        }
                        targets.push_back(static_cast<ca::i32>(rel));
                    }
                    Result<PayloadInsn, InsnEncodeError> p =
                        kind == PayloadKind::PackedSwitch
                            ? makePackedSwitchPayload(pl.payloadFirstKey, targets)
                            : makeSparseSwitchPayload(keys, targets);
                    if (p.is_err()) {
                        return Err(CodeDomError::Unencodable);
                    }
                    PayloadInsn built = std::move(p).unwrap();
                    payloadRef.payloadStorage = std::move(built.storage);
                    payloadRef.insn = built.insn;
                    payloadRef.insn.address = addrs[orderPos(payloadSlot)];
                    payloadRef.insn.payloadData = ByteSlice{payloadRef.payloadStorage.data(),
                                                            payloadRef.payloadStorage.size()};
                }
                if (fillBranches) {
                    if (Result<void, InsnEncodeError> r = setInsnBranchTarget(
                            cur, static_cast<ca::i64>(payloadAddr.unwrap()));
                        r.is_err()) {
                        return Err(CodeDomError::Unencodable);
                    }
                }
            } else if (cur.isBranch() && fillBranches) {
                const auto owner = branchLabel_.find(slot);
                if (owner == branchLabel_.end()) {
                    return Err(CodeDomError::DanglingLabel);
                }
                const Result<ca::u32, CodeDomError> target =
                    labelAddressIn(addrs)(owner->second);
                if (target.is_err()) {
                    return Err(target.unwrap_err());
                }
                if (Result<void, InsnEncodeError> r =
                        setInsnBranchTarget(cur, static_cast<ca::i64>(target.unwrap()));
                    r.is_err()) {
                    return Err(CodeDomError::Unencodable);
                }
            }
        }
        return Ok();
    };

    if (Result<void, CodeDomError> r = rebuildAndFill(false); r.is_err()) {
        return Err(r.unwrap_err());
    }

    // payload 对齐：奇地址前插 nop 槽，直到全部 payload 落偶。
    if (autoAlign) {
        for (;;) {
            const std::vector<ca::u32> alignAddrs = computeAddresses();
            bool aligned = true;
            for (ca::usize pos = 0; pos < order_.size(); ++pos) {
                if (slots_[order_[pos]].insn.isPayload() && (alignAddrs[pos] & 1u) != 0) {
                    const Result<InsnId, CodeDomError> nop =
                        insertBefore(handleForSlot(order_[pos]), makeNop());
                    if (nop.is_err()) {
                        return Err(nop.unwrap_err());
                    }
                    aligned = false;
                    break;
                }
            }
            if (aligned) {
                break;
            }
        }
    }

    if (Result<void, CodeDomError> r = rebuildAndFill(true); r.is_err()) {
        return Err(r.unwrap_err());
    }

    const std::vector<ca::u32> addrs = computeAddresses();
    const ca::u32 totalEnd =
        addrs.empty() ? 0 : addrs.back() + slots_[order_.back()].insn.width;

    const auto labelAddress = [&](LabelId label) -> Result<ca::u32, CodeDomError> {
        if (label >= nextLabel_) {
            return Err(CodeDomError::UnknownLabel);
        }
        const auto found = labelSlot_.find(label);
        if (found == labelSlot_.end()) {
            return Err(CodeDomError::DanglingLabel);
        }
        if (found->second == kEndSlot) {
            return Ok(totalEnd);
        }
        const ca::usize pos = orderPos(found->second);
        if (pos >= addrs.size()) {
            return Err(CodeDomError::DanglingLabel);
        }
        return Ok(addrs[pos]);
    };

    // 被引用的 label 必须可解析（先校验，不产生半成品）。
    {
        std::vector<LabelId> referenced;
        for (const auto& entry : branchLabel_) {
            referenced.push_back(entry.second);
        }
        for (const auto& entry : switchTarget_) {
            if (switchKindOf(slots_[entry.first].insn.opcode) !=
                PayloadKind::FillArrayData) {
                referenced.insert(referenced.end(), entry.second.begin(),
                                  entry.second.end());
            }
        }
        std::vector<ca::u32> usedHandlers;
        for (const TryDom& t : tries_) {
            referenced.push_back(t.start);
            referenced.push_back(t.end);
            usedHandlers.push_back(t.handlerIndex);
        }
        std::sort(usedHandlers.begin(), usedHandlers.end());
        usedHandlers.erase(std::unique(usedHandlers.begin(), usedHandlers.end()),
                           usedHandlers.end());
        for (ca::u32 hi : usedHandlers) {
            if (hi >= handlers_.size()) {
                return Err(CodeDomError::BadTryRegion);
            }
            for (const HandlerDom::Typed& tc : handlers_[hi].typed) {
                referenced.push_back(tc.handler);
            }
            if (handlers_[hi].hasCatchAll) {
                referenced.push_back(handlers_[hi].catchAll);
            }
        }
        for (LabelId l : referenced) {
            const Result<ca::u32, CodeDomError> a = labelAddress(l);
            if (a.is_err()) {
                return Err(a.unwrap_err());
            }
        }
    }

    std::vector<Insn> stream;
    stream.reserve(order_.size());
    for (ca::u32 slot : order_) {
        stream.push_back(slots_[slot].insn);
    }
    Result<std::vector<ca::u8>, InsnEncodeError> encoded = encodeInsns(stream);
    if (encoded.is_err()) {
        return Err(encoded.unwrap_err() == InsnEncodeError::MisalignedPayload
                       ? CodeDomError::MisalignedPayload
                       : CodeDomError::Unencodable);
    }

    // try/handler 重组（writeCodeItem 重算 handler_off 并保持共享）。
    std::vector<TryBlock> blocks;
    blocks.reserve(tries_.size());
    for (const TryDom& t : tries_) {
        const Result<ca::u32, CodeDomError> start = labelAddress(t.start);
        if (start.is_err()) {
            return Err(start.unwrap_err());
        }
        const Result<ca::u32, CodeDomError> end = labelAddress(t.end);
        if (end.is_err()) {
            return Err(end.unwrap_err());
        }
        if (end.unwrap() <= start.unwrap()) {
            return Err(CodeDomError::BadTryRegion);
        }
        const ca::u64 span = static_cast<ca::u64>(end.unwrap()) - start.unwrap();
        if (span > 0xFFFFu) {
            return Err(CodeDomError::Unencodable);  // try_item.insn_count 是 u16
        }
        TryBlock b;
        b.startAddress = start.unwrap();
        b.insnCount = static_cast<ca::u16>(span);
        b.handlerIndex = t.handlerIndex;
        blocks.push_back(b);
    }
    std::sort(blocks.begin(), blocks.end(), [](const TryBlock& a, const TryBlock& b) {
        return a.startAddress < b.startAddress;
    });
    // 规范要求 try 条目不交叠，但 d8 实发完全相同的区间（同一范围挂多个
    // handler），ART 接受——按现实放宽：只要求按起始地址排序。
    (void)0;

    std::vector<CatchHandler> handlers;
    handlers.reserve(handlers_.size());
    for (const HandlerDom& dom : handlers_) {
        CatchHandler h;
        h.typed.reserve(dom.typed.size());
        for (const HandlerDom::Typed& tc : dom.typed) {
            const Result<ca::u32, CodeDomError> addr = labelAddress(tc.handler);
            if (addr.is_err()) {
                return Err(addr.unwrap_err());
            }
            h.typed.push_back(TypedCatch{tc.typeIdx, addr.unwrap()});
        }
        if (dom.hasCatchAll) {
            const Result<ca::u32, CodeDomError> addr = labelAddress(dom.catchAll);
            if (addr.is_err()) {
                return Err(addr.unwrap_err());
            }
            h.hasCatchAll = true;
            h.catchAllAddress = addr.unwrap();
        }
        handlers.push_back(std::move(h));
    }

    LoweredCode out;
    out.insns = std::move(encoded).unwrap();
    out.item.registersSize = registersSize_;
    out.item.insSize = insSize_;
    out.item.outsSize = outsSize_;
    out.item.triesSize = static_cast<ca::u16>(blocks.size());
    out.item.insnsSize = totalEnd;
    out.item.debugInfoOff = debugInfoOff_;
    out.item.tryBlocks = std::move(blocks);
    out.item.catchHandlers = std::move(handlers);
    return Ok(std::move(out));
}

}   // namespace dex::core
