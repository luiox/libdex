/// @file        analysis.cpp
/// @brief       CFG 构建 + 逐指令到达帧实现。
#include "dex/core/analysis.hpp"

#include <algorithm>
#include <set>
#include <unordered_map>

#include "dex/core/bytes.hpp"
#include "dex/core/insn.hpp"

namespace dex::core {
namespace {

// ---- 描述符 → 寄存器种类 -------------------------------------------------

RegType regTypeOfTypeIdx(DexFile& dex, ca::u32 typeIdx)
{
    if (typeIdx == DexFile::kNoIndex) {
        return RegType::ref(DexFile::kNoIndex);
    }
    const Result<jstr::MUtf8StringRef, ReadError> d = dex.typeDescriptor(typeIdx);
    if (d.is_err()) {
        return RegType::top();
    }
    const std::string_view v = d.unwrap().as_std_view();
    if (!v.empty() && v[0] == '[') {
        return RegType::ref(typeIdx);  // 数组类型本身就是引用
    }
    switch (v.empty() ? '\0' : v[0]) {
    case 'Z':
    case 'B':
    case 'S':
    case 'C':
    case 'I':
        return RegType::ofKind(RegKind::IntLike);
    case 'J':
        return RegType::ofKind(RegKind::Long);
    case 'F':
        return RegType::ofKind(RegKind::Float);
    case 'D':
        return RegType::ofKind(RegKind::Double);
    default:
        return RegType::ref(typeIdx);
    }
}

/// @brief 数组引用描述符的元素种类（用于 aget 族）。
RegType elemTypeOfArrayDesc(DexFile& dex, const RegType& arrayRef)
{
    if (arrayRef.kind != RegKind::Reference || arrayRef.typeIdx == DexFile::kNoIndex) {
        return RegType::top();
    }
    const Result<jstr::MUtf8StringRef, ReadError> d = dex.typeDescriptor(arrayRef.typeIdx);
    if (d.is_err()) {
        return RegType::top();
    }
    const std::string_view v = d.unwrap().as_std_view();
    std::size_t pos = 0;
    while (pos < v.size() && v[pos] == '[') {
        ++pos;
    }
    if (pos == 0 || pos >= v.size()) {
        return RegType::top();
    }
    switch (v[pos]) {
    case 'J':
        return RegType::ofKind(RegKind::Long);
    case 'D':
        return RegType::ofKind(RegKind::Double);
    case 'F':
        return RegType::ofKind(RegKind::Float);
    case 'L':
    case '[':
        return RegType::ref(DexFile::kNoIndex);
    default:
        return RegType::ofKind(RegKind::IntLike);
    }
}

// ---- 格合并 ---------------------------------------------------------------

RegType mergeKinds(const RegType& a, const RegType& b) noexcept
{
    if (a.sameAs(b)) {
        return a;
    }
    if (a.kind == RegKind::Unknown || b.kind == RegKind::Unknown) {
        return RegType::top();
    }
    if (a.kind == RegKind::Conflicted || b.kind == RegKind::Conflicted) {
        return RegType::ofKind(RegKind::Conflicted);
    }
    const bool aRefish = a.kind == RegKind::Reference || a.kind == RegKind::Null;
    const bool bRefish = b.kind == RegKind::Reference || b.kind == RegKind::Null;
    // Null（含 const 0 的字面量零）与 cat1 同族相遇并入对方——ART 的
    // Constant(0) 语义：既是合法 int 也是合法 null。
    if (a.kind == RegKind::Null && (b.kind == RegKind::IntLike || b.kind == RegKind::Float)) {
        return b;
    }
    if (b.kind == RegKind::Null && (a.kind == RegKind::IntLike || a.kind == RegKind::Float)) {
        return a;
    }
    if (aRefish && bRefish) {
        if (a.kind == RegKind::Null) {
            return b;
        }
        if (b.kind == RegKind::Null) {
            return a;
        }
        return RegType::ref(DexFile::kNoIndex);  // 不同引用类型 → 引用顶
    }
    // 未初始化引用与已初始化引用合并：保守留未初始化。
    if (a.kind == RegKind::UninitRef || a.kind == RegKind::UninitThis ||
        b.kind == RegKind::UninitRef || b.kind == RegKind::UninitThis) {
        if (a.kind == b.kind && a.addr == b.addr) {
            return a;
        }
        if ((a.kind == RegKind::UninitRef || a.kind == RegKind::UninitThis) && bRefish) {
            return a;
        }
        if ((b.kind == RegKind::UninitRef || b.kind == RegKind::UninitThis) && aRefish) {
            return b;
        }
        return RegType::ofKind(RegKind::Conflicted);
    }
    if (a.isWideLow() && b.isWideLow()) {
        return a.kind == b.kind ? a : RegType::ofKind(RegKind::Conflicted);
    }
    if (a.kind == b.kind) {
        return a;
    }
    return RegType::ofKind(RegKind::Conflicted);
}

struct Frame
{
    std::vector<RegType> regs;
    ca::u32 monitorDepth = 0;

    /// @brief 就地向 @p src 合并；返回是否变化。
    bool mergeFrom(const Frame& src)
    {
        bool changed = false;
        const std::size_t n = std::min(regs.size(), src.regs.size());
        for (std::size_t i = 0; i < n; ++i) {
            const RegType merged = mergeKinds(regs[i], src.regs[i]);
            if (!merged.sameAs(regs[i])) {
                regs[i] = merged;
                changed = true;
            }
        }
        if (src.monitorDepth < monitorDepth) {
            monitorDepth = src.monitorDepth;
            changed = true;
        }
        return changed;
    }
};

std::unordered_map<ca::u32, ca::u32> addrIndex(const std::vector<Insn>& insns)
{
    std::unordered_map<ca::u32, ca::u32> m;
    m.reserve(insns.size() * 2u);
    for (ca::u32 i = 0; i < insns.size(); ++i) {
        m.emplace(insns[i].address, i);
    }
    return m;
}

}   // namespace

RegType mergeRegTypes(const RegType& a, const RegType& b) noexcept
{
    return mergeKinds(a, b);
}

// ---- CFG ------------------------------------------------------------------

std::vector<CfgBlock> buildCfg(const std::vector<Insn>& insns,
                               const std::vector<TryBlock>& tries,
                               const std::vector<CatchHandler>& handlers)
{
    if (insns.empty()) {
        return {};
    }
    const std::unordered_map<ca::u32, ca::u32> insIdx = addrIndex(insns);

    std::unordered_map<ca::u32, const Insn*> payloadByAddr;
    for (const Insn& i : insns) {
        if (i.isPayload()) {
            payloadByAddr.emplace(i.address, &i);
        }
    }

    // ---- leaders：分支/switch 目标、try 边界、handler 入口、转移后继 ----
    std::set<ca::u32> leaders;
    leaders.insert(insns.front().address);
    const auto addAddr = [&leaders, &insIdx](ca::u32 addr) {
        if (insIdx.count(addr) != 0) {
            leaders.insert(addr);
        }
    };
    for (const Insn& i : insns) {
        if (i.isPayload()) {
            leaders.insert(i.address);  // payload 自成块（无流出）
            continue;
        }
        if (i.isBranch()) {
            if (i.format == InsnFormat::F31t) {
                addAddr(static_cast<ca::u32>(static_cast<ca::i64>(i.address) + i.branchOffset));
                auto pit = payloadByAddr.find(
                    static_cast<ca::u32>(static_cast<ca::i64>(i.address) + i.branchOffset));
                if (pit != payloadByAddr.end()) {
                    const Insn& p = *pit->second;
                    // 目标偏移相对 switch 指令地址，不是 payload 地址。
                    if (p.payloadKind == PayloadKind::PackedSwitch) {
                        for (ca::u32 t = 0; t < p.payloadCount; ++t) {
                            addAddr(static_cast<ca::u32>(
                                static_cast<ca::i64>(i.address) + p.packedSwitchTarget(t)));
                        }
                    } else if (p.payloadKind == PayloadKind::SparseSwitch) {
                        for (ca::u32 t = 0; t < p.payloadCount; ++t) {
                            addAddr(static_cast<ca::u32>(
                                static_cast<ca::i64>(i.address) + p.sparseSwitchTarget(t)));
                        }
                    }
                }
                addAddr(i.address + i.width);  // switch 不线性流入 payload
                continue;
            }
            addAddr(static_cast<ca::u32>(static_cast<ca::i64>(i.address) + i.branchOffset));
        }
        if (i.opcode == 0x27 /*throw*/ || (i.opcode >= 0x0e && i.opcode <= 0x11) /*return*/ ||
            (i.opcode >= 0x28 && i.opcode <= 0x2c) /*goto/switch*/ ||
            (i.opcode >= 0x32 && i.opcode <= 0x37) /*条件分支：落点自成块*/) {
            addAddr(i.address + i.width);  // 转移后的下一条自成块
        }
    }
    for (const TryBlock& tb : tries) {
        addAddr(tb.startAddress);
        addAddr(static_cast<ca::u32>(tb.startAddress) + tb.insnCount);
        if (tb.handlerIndex >= handlers.size()) {
            continue;
        }
        const CatchHandler& h = handlers[tb.handlerIndex];
        for (const TypedCatch& tc : h.typed) {
            addAddr(tc.address);
        }
        if (h.hasCatchAll) {
            addAddr(h.catchAllAddress);
        }
    }

    // ---- 切块 ----
    std::vector<CfgBlock> blocks;
    std::unordered_map<ca::u32, ca::u32> blockStartIdx;
    {
        CfgBlock cur;
        bool open = false;
        for (const Insn& i : insns) {
            if (leaders.count(i.address) != 0 && open) {
                blockStartIdx.emplace(cur.startAddress, static_cast<ca::u32>(blocks.size()));
                blocks.push_back(cur);
                cur = CfgBlock{};
                open = false;
            }
            if (!open) {
                cur.startAddress = i.address;
                open = true;
            }
            cur.endAddress = i.address + (i.width == 0 ? 1u : i.width);
        }
        if (open) {
            blockStartIdx.emplace(cur.startAddress, static_cast<ca::u32>(blocks.size()));
            blocks.push_back(cur);
        }
    }

    const auto blockAt = [&blockStartIdx](ca::u32 addr) -> ca::u32 {
        auto it = blockStartIdx.find(addr);
        return it == blockStartIdx.end() ? 0xFFFFFFFFu : it->second;
    };

    // ---- 边 ----
    for (ca::u32 b = 0; b < blocks.size(); ++b) {
        CfgBlock& blk = blocks[b];
        const Insn* last = nullptr;
        for (const Insn& i : insns) {
            if (i.address >= blk.startAddress && i.address < blk.endAddress &&
                !i.isPayload()) {
                last = &i;
            }
        }
        if (last == nullptr) {
            continue;
        }
        const ca::u32 branchIdx = blockAt(
            static_cast<ca::u32>(static_cast<ca::i64>(last->address) + last->branchOffset));
        const ca::u32 nextIdx = blockAt(last->address + last->width);
        if (last->opcode >= 0x28 && last->opcode <= 0x2a) {
            if (branchIdx != 0xFFFFFFFFu) {
                blk.successors.push_back(branchIdx);
            }
        } else if (last->opcode == 0x2b || last->opcode == 0x2c) {
            auto pit = payloadByAddr.find(
                static_cast<ca::u32>(static_cast<ca::i64>(last->address) + last->branchOffset));
            if (pit != payloadByAddr.end()) {
                const Insn& p = *pit->second;
                // 目标偏移相对 switch 指令地址；default 分支线性落入下一条。
                if (p.payloadKind == PayloadKind::PackedSwitch) {
                    for (ca::u32 t = 0; t < p.payloadCount; ++t) {
                        const ca::u32 target = blockAt(
                            static_cast<ca::u32>(static_cast<ca::i64>(last->address) +
                                                 p.packedSwitchTarget(t)));
                        if (target != 0xFFFFFFFFu) {
                            blk.successors.push_back(target);
                        }
                    }
                } else if (p.payloadKind == PayloadKind::SparseSwitch) {
                    for (ca::u32 t = 0; t < p.payloadCount; ++t) {
                        const ca::u32 target = blockAt(
                            static_cast<ca::u32>(static_cast<ca::i64>(last->address) +
                                                 p.sparseSwitchTarget(t)));
                        if (target != 0xFFFFFFFFu) {
                            blk.successors.push_back(target);
                        }
                    }
                }
            }
            if (nextIdx != 0xFFFFFFFFu) {
                blk.successors.push_back(nextIdx);  // switch 的 default 落点
            } else {
                blk.isExitReachable = true;
            }
        } else if (last->opcode == 0x27 || (last->opcode >= 0x0e && last->opcode <= 0x11)) {
            blk.isExitReachable = true;  // 无流出
        } else {
            if (last->opcode >= 0x38 && last->opcode <= 0x3d && branchIdx != 0xFFFFFFFFu) {
                blk.successors.push_back(branchIdx);  // 条件分支目标
            }
            if (nextIdx != 0xFFFFFFFFu) {
                blk.successors.push_back(nextIdx);  // 线性落点
            } else {
                blk.isExitReachable = true;  // 流出指令区末尾
            }
        }
        // 异常边：块与 try 区间相交 → 该 try 的全部 handler 入口。
        for (const TryBlock& tb : tries) {
            const ca::u32 tbEnd = static_cast<ca::u32>(tb.startAddress) + tb.insnCount;
            if (tb.startAddress >= blk.endAddress || blk.startAddress >= tbEnd) {
                continue;
            }
            if (tb.handlerIndex >= handlers.size()) {
                continue;
            }
            const CatchHandler& h = handlers[tb.handlerIndex];
            for (const TypedCatch& tc : h.typed) {
                const ca::u32 hb = blockAt(tc.address);
                if (hb != 0xFFFFFFFFu) {
                    blk.handlers.push_back(hb);
                }
            }
            if (h.hasCatchAll) {
                const ca::u32 hb = blockAt(h.catchAllAddress);
                if (hb != 0xFFFFFFFFu) {
                    blk.handlers.push_back(hb);
                }
            }
        }
    }
    for (CfgBlock& blk : blocks) {
        std::sort(blk.successors.begin(), blk.successors.end());
        blk.successors.erase(std::unique(blk.successors.begin(), blk.successors.end()),
                             blk.successors.end());
        std::sort(blk.handlers.begin(), blk.handlers.end());
        blk.handlers.erase(std::unique(blk.handlers.begin(), blk.handlers.end()),
                           blk.handlers.end());
    }
    for (ca::u32 b = 0; b < blocks.size(); ++b) {
        for (ca::u32 s : blocks[b].successors) {
            if (s < blocks.size()) {
                blocks[s].predecessors.push_back(b);
            }
        }
    }
    return blocks;
}

// ---- 帧引擎 ----------------------------------------------------------------

namespace {

bool isInvokeFamily(const Insn& i) noexcept
{
    if (i.isPayload()) {
        return false;
    }
    return i.format == InsnFormat::F35c || i.format == InsnFormat::F3rc ||
           i.format == InsnFormat::F45cc || i.format == InsnFormat::F4rcc ||
           i.opcode == 0x24 || i.opcode == 0x25;  // filled-new-array
}

bool isRefish(const RegType& t) noexcept
{
    return t.kind == RegKind::Reference || t.kind == RegKind::Null ||
           t.kind == RegKind::UninitRef || t.kind == RegKind::UninitThis ||
           t.kind == RegKind::Unknown;
}

/// @brief 算术指令的目标族与源宽。
///
/// 宽度必须按操作码区间判定：`neg-long`、`shl-long`、`long-to-int` 这类名字
/// 前缀/子串都不能可靠表达源与目标是否 cat2，且移位的第二源恒为 cat1。
struct ArithShape
{
    RegKind dest = RegKind::IntLike;
    bool destWide = false;
    bool srcWide = false;   ///< unop 的源 / 23x 与 2addr 的第一源
    bool src2Wide = false;  ///< 23x 的第二源
};

bool unopShape(ca::u8 opcode, ArithShape* out) noexcept
{
    switch (opcode) {
        case 0x7b: case 0x7c:  // neg-int / not-int
            *out = ArithShape{RegKind::IntLike, false, false, false};
            return true;
        case 0x7d: case 0x7e:  // neg-long / not-long
            *out = ArithShape{RegKind::Long, true, true, false};
            return true;
        case 0x7f:  // neg-float
            *out = ArithShape{RegKind::Float, false, false, false};
            return true;
        case 0x80:  // neg-double
            *out = ArithShape{RegKind::Double, true, true, false};
            return true;
        case 0x81:  // int-to-long
            *out = ArithShape{RegKind::Long, true, false, false};
            return true;
        case 0x82:  // int-to-float
            *out = ArithShape{RegKind::Float, false, false, false};
            return true;
        case 0x83:  // int-to-double
            *out = ArithShape{RegKind::Double, true, false, false};
            return true;
        case 0x84:  // long-to-int
            *out = ArithShape{RegKind::IntLike, false, true, false};
            return true;
        case 0x85:  // long-to-float
            *out = ArithShape{RegKind::Float, false, true, false};
            return true;
        case 0x86:  // long-to-double
            *out = ArithShape{RegKind::Double, true, true, false};
            return true;
        case 0x87:  // float-to-int
            *out = ArithShape{RegKind::IntLike, false, false, false};
            return true;
        case 0x88:  // float-to-long
            *out = ArithShape{RegKind::Long, true, false, false};
            return true;
        case 0x89:  // float-to-double
            *out = ArithShape{RegKind::Double, true, false, false};
            return true;
        case 0x8a:  // double-to-int
            *out = ArithShape{RegKind::IntLike, false, true, false};
            return true;
        case 0x8b:  // double-to-long
            *out = ArithShape{RegKind::Long, true, true, false};
            return true;
        case 0x8c:  // double-to-float
            *out = ArithShape{RegKind::Float, false, true, false};
            return true;
        case 0x8d: case 0x8e: case 0x8f:  // int-to-byte/char/short
            *out = ArithShape{RegKind::IntLike, false, false, false};
            return true;
        default:
            return false;
    }
}

bool binop23Shape(ca::u8 opcode, ArithShape* out) noexcept
{
    if (opcode >= 0x90 && opcode <= 0x9a) {  // int
        *out = ArithShape{RegKind::IntLike, false, false, false};
        return true;
    }
    if (opcode >= 0x9b && opcode <= 0xa2) {  // long 算术
        *out = ArithShape{RegKind::Long, true, true, true};
        return true;
    }
    if (opcode >= 0xa3 && opcode <= 0xa5) {  // long 移位：第二源是 cat1
        *out = ArithShape{RegKind::Long, true, true, false};
        return true;
    }
    if (opcode >= 0xa6 && opcode <= 0xaa) {  // float
        *out = ArithShape{RegKind::Float, false, false, false};
        return true;
    }
    if (opcode >= 0xab && opcode <= 0xaf) {  // double
        *out = ArithShape{RegKind::Double, true, true, true};
        return true;
    }
    return false;
}

bool binop2addrShape(ca::u8 opcode, ArithShape* out) noexcept
{
    if (opcode >= 0xb0 && opcode <= 0xba) {  // int
        *out = ArithShape{RegKind::IntLike, false, false, false};
        return true;
    }
    if (opcode >= 0xbb && opcode <= 0xc2) {  // long 算术：A/B 都宽
        *out = ArithShape{RegKind::Long, true, true, false};
        return true;
    }
    if (opcode >= 0xc3 && opcode <= 0xc5) {  // long 移位：B 是 cat1
        *out = ArithShape{RegKind::Long, true, false, false};
        return true;
    }
    if (opcode >= 0xc6 && opcode <= 0xca) {  // float
        *out = ArithShape{RegKind::Float, false, false, false};
        return true;
    }
    if (opcode >= 0xcb && opcode <= 0xcf) {  // double：A/B 都宽
        *out = ArithShape{RegKind::Double, true, true, false};
        return true;
    }
    return false;
}

/// @brief move-result 的目标类型：按前驱 invoke 的返回描述符；不可知即顶。
RegType moveResultType(DexFile& dex, const Insn& prev, bool wide)
{
    if (prev.opcode == 0x24 || prev.opcode == 0x25) {
        return RegType::ref(prev.index);  // filled-new-array 的数组类型
    }
    ca::u32 protoIdx = DexFile::kNoIndex;
    if (prev.indexKind == IndexKind::Method) {
        protoIdx = prev.hasProtoIndex ? prev.protoIndex
                                      : (prev.index < dex.methodCount()
                                             ? dex.methodIds[prev.index].protoIdx
                                             : DexFile::kNoIndex);
    }
    if (protoIdx == DexFile::kNoIndex || protoIdx >= dex.protoCount()) {
        return wide ? RegType::ofKind(RegKind::Long) : RegType::top();
    }
    return regTypeOfTypeIdx(dex, dex.protoIds[protoIdx].returnTypeIdx);
}

}   // namespace

Result<MethodAnalysis, ReadError> analyzeFrames(DexFile& dex, const CodeItem& code,
                                                ca::u32 methodIdx, bool isStatic,
                                                bool strict)
{
    MethodAnalysis out;
    out.registersSize = code.registersSize;
    const Result<std::vector<Insn>, InsnError> decoded =
        decodeInsns(subOrEmpty(dex.source(), code.insns.offset, code.insns.length));
    if (decoded.is_err()) {
        return Err(ReadError::BadCodeItem);
    }
    const std::vector<Insn>& insns = decoded.unwrap();
    out.blocks = buildCfg(insns, code.tryBlocks, code.catchHandlers);
    out.entryFrames.assign(insns.size(), {});
    if (insns.empty() || code.registersSize == 0) {
        out.strictClean = out.diagnostics.empty();
        return Ok(std::move(out));
    }

    const std::unordered_map<ca::u32, ca::u32> insIdx = addrIndex(insns);
    const auto diag = [&](ca::u32 addr, FrameDiagnostic::Code c) {
        if (strict) {
            out.diagnostics.push_back(FrameDiagnostic{addr, c});
        }
    };

    // ---- 入口帧：参数类型 ----
    Frame entry;
    entry.regs.assign(code.registersSize, RegType::top());
    if (code.insSize <= code.registersSize && methodIdx < dex.methodCount() &&
        dex.methodIds[methodIdx].protoIdx < dex.protoCount()) {
        const Result<TypeListSpan, ReadError> params =
            dex.protoParameters(dex.methodIds[methodIdx].protoIdx);
        ca::u32 r = code.registersSize - code.insSize;
        if (!isStatic && r < code.registersSize) {
            entry.regs[r++] = RegType::ofKind(RegKind::UninitThis);
        }
        if (params.is_ok()) {
            const TypeListSpan& list = params.unwrap();
            for (ca::u32 p = 0; p < list.size && r < code.registersSize; ++p) {
                const RegType t = regTypeOfTypeIdx(dex, list.at(p));
                entry.regs[r] = t;
                if (t.isWideLow()) {
                    if (r + 1 >= code.registersSize) {
                        break;
                    }
                    entry.regs[r + 1] = t;
                    r += 2;
                } else {
                    ++r;
                }
            }
        }
    }

    // ---- 不动点 ----
    std::vector<Frame> inFrame(insns.size());
    std::vector<char> visited(insns.size(), 0);
    std::vector<ca::u32> work;
    const auto offer = [&](ca::u32 idx, const Frame& f) {
        if (idx >= insns.size()) {
            return;
        }
        if (visited[idx] == 0) {
            inFrame[idx] = f;
            visited[idx] = 1;
            work.push_back(idx);
            return;
        }
        Frame merged = inFrame[idx];
        if (merged.mergeFrom(f)) {
            // 冲突合并静默进帧（Conflicted），诊断推迟到读取点——与 ART
            // 一致：合流冲突只有被后续指令读到才构成 VerifyError。
            inFrame[idx] = merged;
            work.push_back(idx);
        }
    };
    Frame cleared;  // handler 入口：寄存器全清
    cleared.regs.assign(code.registersSize, RegType::top());
    for (const TryBlock& tb : code.tryBlocks) {
        if (tb.handlerIndex >= code.catchHandlers.size()) {
            continue;
        }
        const CatchHandler& h = code.catchHandlers[tb.handlerIndex];
        for (const TypedCatch& tc : h.typed) {
            auto it = insIdx.find(tc.address);
            if (it != insIdx.end()) {
                offer(it->second, cleared);
            }
        }
        if (h.hasCatchAll) {
            auto it = insIdx.find(h.catchAllAddress);
            if (it != insIdx.end()) {
                offer(it->second, cleared);
            }
        }
    }
    offer(0, entry);

    const auto step = [&](ca::u32 i, Frame& cur) {
        const Insn& insn = insns[i];
        const ca::u32 addr = insn.address;
        const auto checkCat1 = [&](ca::u32 reg) -> RegType {
            if (reg >= code.registersSize) {
                diag(addr, FrameDiagnostic::Code::BadOperand);
                return RegType::top();
            }
            if (cur.regs[reg].kind == RegKind::Conflicted) {
                diag(addr, FrameDiagnostic::Code::TypeConflict);
                return RegType::top();
            }
            if (cur.regs[reg].isWideLow()) {
                diag(addr, FrameDiagnostic::Code::WidePairing);
                return RegType::top();
            }
            return cur.regs[reg];
        };
        const auto checkWide = [&](ca::u32 reg) -> RegType {
            if (reg >= code.registersSize || reg + 1 >= code.registersSize) {
                diag(addr, FrameDiagnostic::Code::BadOperand);
                return RegType::top();
            }
            if (cur.regs[reg].kind == RegKind::Conflicted) {
                diag(addr, FrameDiagnostic::Code::TypeConflict);
                return RegType::top();
            }
            if (!cur.regs[reg].isWideLow()) {
                diag(addr, FrameDiagnostic::Code::WidePairing);
                return RegType::top();
            }
            return cur.regs[reg];
        };
        const auto checkRefish = [&](ca::u32 reg) -> RegType {
            const RegType t = checkCat1(reg);
            if (!isRefish(t)) {
                diag(addr, FrameDiagnostic::Code::BadOperand);
            }
            return t;
        };
        const auto writeSingle = [&](ca::u32 reg, RegType t) {
            if (reg >= code.registersSize) {
                diag(addr, FrameDiagnostic::Code::BadOperand);
                return;
            }
            if (cur.regs[reg].isWideLow()) {
                diag(addr, FrameDiagnostic::Code::WidePairing);
                // 只失效低半之后的高半；reg 本身是高半时低半保留宽标记，
                // 残留由读点 checkWide（要求两半同宽）兜底诊断。
                if (reg + 1 < code.registersSize) {
                    cur.regs[reg + 1] = RegType::top();  // 宽对被踩断
                }
            }
            cur.regs[reg] = t;
        };
        const auto writeWide = [&](ca::u32 reg, RegType t) {
            if (reg >= code.registersSize || reg + 1 >= code.registersSize) {
                diag(addr, FrameDiagnostic::Code::BadOperand);
                return;
            }
            cur.regs[reg] = t;
            cur.regs[reg + 1] = t;
        };
        const auto checkValue = [&](ca::u32 reg, const RegType& want) {
            if (want.isWideLow()) {
                checkWide(reg);
            } else if (want.kind == RegKind::Reference) {
                checkRefish(reg);
            } else if (want.kind != RegKind::Unknown) {
                checkCat1(reg);
            }
        };
        const auto argsOf = [&]() -> std::vector<ca::u32> {
            std::vector<ca::u32> regs;
            if (insn.format == InsnFormat::F35c || insn.format == InsnFormat::F45cc) {
                const std::size_t kMax = std::min<std::size_t>(insn.registerCount, 5);
                for (std::size_t k = 0; k < kMax; ++k) {
                    regs.push_back(insn.registers[k]);
                }
            } else {
                for (ca::u32 k = 0; k < insn.registerCount; ++k) {
                    regs.push_back(static_cast<ca::u32>(insn.startRegister) + k);
                }
            }
            return regs;
        };
        const auto protoOfInvoke = [&](const Insn& inv) -> ca::u32 {
            if (inv.hasProtoIndex) {
                return inv.protoIndex;
            }
            if (inv.indexKind == IndexKind::Method && inv.index < dex.methodCount()) {
                return dex.methodIds[inv.index].protoIdx;
            }
            return DexFile::kNoIndex;
        };
        const auto checkInvoke = [&](bool allowInit) {
            const std::vector<ca::u32> args = argsOf();
            const ca::u32 proto = protoOfInvoke(insn);
            // 除 invoke-static/custom 外都带接收者（proto 参数不含 this）。
            const bool hasReceiver = insn.opcode != 0x71 /*invoke-static*/ &&
                                     insn.opcode != 0x78 /*invoke-static/range*/ &&
                                     insn.opcode != 0xfc /*invoke-custom*/ &&
                                     insn.opcode != 0xfd /*invoke-custom/range*/;
            if (proto != DexFile::kNoIndex && proto < dex.protoCount()) {
                const Result<TypeListSpan, ReadError> params = dex.protoParameters(proto);
                if (params.is_ok()) {
                    const TypeListSpan& list = params.unwrap();
                    // 寄存器槽数按宽参数展开成对计数，不能用参数个数对齐。
                    ca::u32 wantSlots = 0;
                    for (ca::u32 p = 0; p < list.size; ++p) {
                        wantSlots += regTypeOfTypeIdx(dex, list.at(p)).isWideLow() ? 2u : 1u;
                    }
                    if (strict &&
                        wantSlots + (hasReceiver ? 1u : 0u) != args.size()) {
                        diag(addr, FrameDiagnostic::Code::BadOperand);
                    }
                    std::size_t argPos = 0;
                    if (hasReceiver && argPos < args.size()) {
                        checkRefish(args[argPos++]);  // 接收者（可为未初始化引用）
                    }
                    for (ca::u32 p = 0; p < list.size && argPos < args.size(); ++p) {
                        const RegType want = regTypeOfTypeIdx(dex, list.at(p));
                        checkValue(args[argPos], want);
                        argPos += want.isWideLow() ? 2u : 1u;
                    }
                }
            }
            if (allowInit && insn.opcode == 0x70 /*invoke-direct*/ &&
                insn.indexKind == IndexKind::Method && insn.index < dex.methodCount()) {
                const auto callee = dex.methodName(insn.index);
                if (callee.is_ok() && callee.unwrap().as_std_view() == "<init>" &&
                    !args.empty()) {
                    // 只初始化接收者与持有同一未初始化引用（同一 new-instance
                    // 地址）的寄存器；其余 UninitRef 属于别的对象。
                    const RegType& receiver = cur.regs[args.front()];
                    const RegType initialized =
                        RegType::ref(dex.methodIds[insn.index].classIdx);
                    for (RegType& slot : cur.regs) {
                        if (slot.kind == receiver.kind &&
                            (slot.kind == RegKind::UninitRef ||
                             slot.kind == RegKind::UninitThis) &&
                            slot.addr == receiver.addr) {
                            slot = initialized;
                        }
                    }
                }
            }
        };

        switch (insn.opcode) {
        case 0x01:  // move
        case 0x02:  // move/from16
        case 0x03:  // move/16
            writeSingle(insn.registers[0], checkCat1(insn.registers[1]));
            break;
        case 0x04:  // move-wide
        case 0x05:  // move-wide/from16
        case 0x06: {  // move-wide/16
            const RegType src = checkWide(insn.registers[1]);
            writeWide(insn.registers[0],
                      src.isWideLow() ? src : RegType::ofKind(RegKind::Long));
            break;
        }
        case 0x07:  // move-object
        case 0x08:  // move-object/from16
        case 0x09:  // move-object/16
            writeSingle(insn.registers[0], checkRefish(insn.registers[1]));
            break;
        case 0x0a:  // move-result
        case 0x0b:  // move-result-wide
        case 0x0c:  // move-result-object
        case 0x0d: {  // move-exception
            if (insn.opcode == 0x0d) {
                RegType t = RegType::ref(DexFile::kNoIndex);
                for (const TryBlock& tb : code.tryBlocks) {
                    if (tb.handlerIndex >= code.catchHandlers.size()) {
                        continue;
                    }
                    const CatchHandler& h = code.catchHandlers[tb.handlerIndex];
                    for (const TypedCatch& tc : h.typed) {
                        if (tc.address == addr) {
                            t = regTypeOfTypeIdx(dex, tc.typeIdx);
                            break;
                        }
                    }
                }
                writeSingle(insn.registers[0], t);
                break;
            }
            const bool paired = i > 0 && isInvokeFamily(insns[i - 1]);
            if (!paired) {
                diag(addr, FrameDiagnostic::Code::MoveResultPair);
            }
            if (insn.opcode == 0x0b) {  // wide
                const RegType t = paired ? moveResultType(dex, insns[i - 1], true)
                                         : RegType::ofKind(RegKind::Long);
                writeWide(insn.registers[0],
                          t.isWideLow() ? t : RegType::ofKind(RegKind::Long));
            } else {  // result / result-object：按返回描述符（引用即 Reference）
                writeSingle(insn.registers[0],
                            paired ? moveResultType(dex, insns[i - 1], false)
                                   : RegType::top());
            }
            break;
        }
        case 0x0e:  // return-void
        case 0x0f:  // return
        case 0x10:  // return-wide
        case 0x11:  // return-object
            if (cur.monitorDepth != 0) {
                diag(addr, FrameDiagnostic::Code::MonitorBalance);
            }
            if (insn.opcode == 0x10) {
                checkWide(insn.registers[0]);
            } else if (insn.opcode == 0x11) {
                checkRefish(insn.registers[0]);
            } else if (insn.opcode == 0x0f) {
                checkCat1(insn.registers[0]);
            }
            break;
        case 0x12:  // const/4
        case 0x13:  // const/16
        case 0x14:  // const
            writeSingle(insn.registers[0],
                        insn.literal == 0 ? RegType::ofKind(RegKind::Null)
                                          : RegType::ofKind(RegKind::IntLike));
            break;
        case 0x15:  // const/high16
            writeSingle(insn.registers[0], RegType::ofKind(RegKind::IntLike));
            break;
        case 0x16:  // const-wide/16
        case 0x17:  // const-wide/32
        case 0x18:  // const-wide
        case 0x19:  // const-wide/high16
            writeWide(insn.registers[0], RegType::ofKind(RegKind::Long));
            break;
        case 0x1a:  // const-string
        case 0x1b:  // const-string/jumbo
            writeSingle(insn.registers[0], RegType::ref(DexFile::kNoIndex));
            break;
        case 0x1c:  // const-class
            writeSingle(insn.registers[0], RegType::ref(insn.index));
            break;
        case 0x1d:  // monitor-enter
            checkRefish(insn.registers[0]);
            ++cur.monitorDepth;
            break;
        case 0x1e:  // monitor-exit
            checkRefish(insn.registers[0]);
            if (cur.monitorDepth == 0) {
                diag(addr, FrameDiagnostic::Code::MonitorBalance);
            } else {
                --cur.monitorDepth;
            }
            break;
        case 0x1f:  // check-cast
            checkRefish(insn.registers[0]);
            writeSingle(insn.registers[0], RegType::ref(insn.index));
            break;
        case 0x20:  // instance-of
        case 0x21:  // array-length
            checkRefish(insn.registers[1]);
            writeSingle(insn.registers[0], RegType::ofKind(RegKind::IntLike));
            break;
        case 0x22:  // new-instance
            writeSingle(insn.registers[0], RegType::uninit(addr));
            break;
        case 0x23:  // new-array
            checkCat1(insn.registers[1]);
            writeSingle(insn.registers[0], RegType::ref(insn.index));
            break;
        case 0x24:  // filled-new-array
        case 0x25:  // filled-new-array/range
        case 0x26:  // fill-array-data
            break;
        case 0x27:  // throw
            checkRefish(insn.registers[0]);
            break;
        case 0x2b:  // packed-switch
        case 0x2c:  // sparse-switch
            checkCat1(insn.registers[0]);
            break;
        case 0x2f:  // cmpl-double
        case 0x30:  // cmpg-double
        case 0x31:  // cmp-long
            checkWide(insn.registers[1]);
            checkWide(insn.registers[2]);
            writeSingle(insn.registers[0], RegType::ofKind(RegKind::IntLike));
            break;
        case 0x2d:  // cmpl-float
        case 0x2e:  // cmpg-float
            checkCat1(insn.registers[1]);
            checkCat1(insn.registers[2]);
            writeSingle(insn.registers[0], RegType::ofKind(RegKind::IntLike));
            break;
        case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72:  // invoke-kind
        case 0x74: case 0x75: case 0x76: case 0x77: case 0x78:  // invoke-kind/range
        case 0xfa: case 0xfb:  // invoke-polymorphic(/range)
        case 0xfc: case 0xfd:  // invoke-custom(/range)
            checkInvoke(/*allowInit=*/true);
            break;
        default: {
            if (insn.opcode >= 0x32 && insn.opcode <= 0x37) {  // if-test
                checkCat1(insn.registers[0]);
                checkCat1(insn.registers[1]);
                break;
            }
            if (insn.opcode >= 0x38 && insn.opcode <= 0x3d) {  // if-testz
                checkCat1(insn.registers[0]);
                break;
            }
            if (insn.opcode >= 0x44 && insn.opcode <= 0x51) {  // aget/aput
                const RegType arr = checkRefish(insn.registers[1]);
                const RegType elem = elemTypeOfArrayDesc(dex, arr);
                if (insn.opcode <= 0x4a) {  // aget 族：A 值
                    if (elem.isWideLow()) {
                        writeWide(insn.registers[0], elem);
                    } else {
                        writeSingle(insn.registers[0], elem);
                    }
                } else {  // aput 族：A 源
                    checkValue(insn.registers[0], elem);
                }
                break;
            }
            if ((insn.opcode >= 0x52 && insn.opcode <= 0x5f) ||  // iget/iput
                (insn.opcode >= 0x60 && insn.opcode <= 0x6d)) {  // sget/sput
                if (insn.indexKind != IndexKind::Field || insn.index >= dex.fieldCount()) {
                    break;
                }
                const RegType ft = regTypeOfTypeIdx(dex, dex.fieldIds[insn.index].typeIdx);
                const bool igetFamily = insn.opcode < 0x60;
                const bool isGet =
                    (insn.opcode >= 0x52 && insn.opcode <= 0x58) ||  // iget
                    (insn.opcode >= 0x60 && insn.opcode <= 0x66);    // sget
                if (isGet) {
                    if (igetFamily) {
                        checkRefish(insn.registers[1]);  // B 对象
                    }
                    if (ft.isWideLow()) {
                        writeWide(insn.registers[0], ft);
                    } else {
                        writeSingle(insn.registers[0], ft);
                    }
                } else {
                    checkValue(insn.registers[0], ft);
                    if (igetFamily) {
                        checkRefish(insn.registers[1]);  // B 对象
                    }
                }
                break;
            }
            if ((insn.opcode >= 0x7b && insn.opcode <= 0x8f) ||   // unop 12x
                (insn.opcode >= 0x90 && insn.opcode <= 0xaf) ||   // binop 23x
                (insn.opcode >= 0xb0 && insn.opcode <= 0xcf) ||   // binop 2addr
                (insn.opcode >= 0xd0 && insn.opcode <= 0xe2)) {   // binop lit
                const auto checkSrc = [&](ca::u32 reg, bool wide) {
                    if (wide) {
                        checkWide(reg);
                    } else {
                        checkCat1(reg);
                    }
                };
                ArithShape shape;
                if (insn.opcode <= 0x8f) {  // unop 12x
                    if (!unopShape(insn.opcode, &shape)) {
                        break;
                    }
                    checkSrc(insn.registers[1], shape.srcWide);
                } else if (insn.opcode <= 0xaf) {  // binop 23x
                    if (!binop23Shape(insn.opcode, &shape)) {
                        break;
                    }
                    checkSrc(insn.registers[1], shape.srcWide);
                    checkSrc(insn.registers[2], shape.src2Wide);
                } else if (insn.opcode <= 0xcf) {  // binop 2addr：A 兼源
                    if (!binop2addrShape(insn.opcode, &shape)) {
                        break;
                    }
                    checkSrc(insn.registers[0], shape.destWide);
                    checkSrc(insn.registers[1], shape.srcWide);
                    break;  // A 就是目标，形状不变
                } else {  // lit16/lit8：源恒 cat1
                    checkCat1(insn.registers[1]);
                    writeSingle(insn.registers[0], RegType::ofKind(RegKind::IntLike));
                    break;
                }
                if (shape.destWide) {
                    writeWide(insn.registers[0], RegType::ofKind(shape.dest));
                } else {
                    writeSingle(insn.registers[0], RegType::ofKind(shape.dest));
                }
                break;
            }
            break;  // 其余（含未定义操作码）：帧不变形状
        }
        }
    };

    for (ca::u64 steps = 0; !work.empty() && steps < 4000000; ++steps) {
        const ca::u32 idx = work.back();
        work.pop_back();
        const Insn& insn = insns[idx];
        if (insn.isPayload()) {
            continue;
        }
        Frame cur = inFrame[idx];
        step(idx, cur);

        const auto offerAddr = [&](ca::i64 target) {
            if (target < 0) {
                return;
            }
            auto it = insIdx.find(static_cast<ca::u32>(target));
            if (it != insIdx.end()) {
                offer(it->second, cur);
            }
        };
        if (insn.opcode >= 0x28 && insn.opcode <= 0x2a) {  // goto
            offerAddr(static_cast<ca::i64>(insn.address) + insn.branchOffset);
        } else if (insn.opcode == 0x2b || insn.opcode == 0x2c) {  // switch
            auto pit = insIdx.find(
                static_cast<ca::u32>(static_cast<ca::i64>(insn.address) + insn.branchOffset));
            if (pit != insIdx.end() && insns[pit->second].isPayload()) {
                const Insn& p = insns[pit->second];
                // 目标偏移相对 switch 指令地址，不是 payload 地址。
                if (p.payloadKind == PayloadKind::PackedSwitch) {
                    for (ca::u32 t = 0; t < p.payloadCount; ++t) {
                        offerAddr(static_cast<ca::i64>(insn.address) +
                                  p.packedSwitchTarget(t));
                    }
                } else if (p.payloadKind == PayloadKind::SparseSwitch) {
                    for (ca::u32 t = 0; t < p.payloadCount; ++t) {
                        offerAddr(static_cast<ca::i64>(insn.address) +
                                  p.sparseSwitchTarget(t));
                    }
                }
            }
            // default 分支线性落到下一条真实指令（payload 不可执行，跳过）。
            for (ca::u32 n = idx + 1; n < insns.size(); ++n) {
                if (!insns[n].isPayload()) {
                    offer(n, cur);
                    break;
                }
            }
        } else if (insn.opcode == 0x27 ||
                   (insn.opcode >= 0x0e && insn.opcode <= 0x11)) {  // return/throw
            // 无流出。
        } else {
            if (insn.opcode >= 0x38 && insn.opcode <= 0x3d) {
                offerAddr(static_cast<ca::i64>(insn.address) + insn.branchOffset);
            }
            for (ca::u32 n = idx + 1; n < insns.size(); ++n) {
                if (!insns[n].isPayload()) {
                    offer(n, cur);
                    break;
                }
            }
        }
    }

    for (ca::u32 i = 0; i < insns.size(); ++i) {
        if (visited[i] != 0) {
            out.entryFrames[i] = std::move(inFrame[i].regs);
        }
    }
    out.strictClean = out.diagnostics.empty();
    return Ok(std::move(out));
}

}   // namespace dex::core
